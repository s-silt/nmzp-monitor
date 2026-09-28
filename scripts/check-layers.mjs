// Layer gate for TARGET §4. dependency-cruiser parses and resolves imports and evaluates the
// per-edge rules. This wrapper owns what depcruise cannot express: first-match layer mapping,
// unmapped files, the layer-level cycle, the core/monitor direction check, and the allowlist.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cruise } from "dependency-cruiser";
import extractTSConfig from "dependency-cruiser/config-utl/extract-ts-config";

export const LAYERS = Object.freeze([
  "contract",
  "domain",
  "adapters",
  "app",
  "infra",
  "cli",
  "ui",
]);

const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  ".git",
  ".pack",
  ".output",
  ".vercel",
  ".nitro",
  "coverage",
]);

function repoOfScript() {
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

export function normalizePosix(rel) {
  return rel.split("\\").join("/");
}

function outOfLayerScope(rel) {
  if (rel.startsWith("scripts/") || rel.startsWith("tests/") || rel.startsWith("bench/")) return true;
  return rel.split("/").some((part) => part.includes(".test."));
}

function walkSources(root, dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (ent.name.startsWith(".") || SKIP_DIRS.has(ent.name)) continue;
    const abs = join(dir, ent.name);
    if (ent.isDirectory()) {
      walkSources(root, abs, out);
      continue;
    }
    if (!/\.(ts|tsx|mjs)$/.test(ent.name) || ent.name.endsWith(".d.ts")) continue;
    const rel = normalizePosix(abs.slice(root.length + 1));
    if (!outOfLayerScope(rel)) out.push(rel);
  }
}

export function listLayerFiles(root) {
  const files = [];
  walkSources(root, root, files);
  files.sort();
  return files;
}

function globToRegExp(glob) {
  let re = "^";
  for (let i = 0; i < glob.length; i += 1) {
    if (glob.startsWith("**/", i)) {
      re += "(?:.*/)?";
      i += 2;
      continue;
    }
    if (glob.startsWith("**", i)) {
      re += ".*";
      i += 1;
      continue;
    }
    const ch = glob[i];
    if (ch === "*") {
      re += "[^/]*";
      continue;
    }
    if ("\\^$+?.()|[]{}".includes(ch)) re += `\\${ch}`;
    else re += ch;
  }
  re += "$";
  return new RegExp(re);
}

function compileLayers(layerRules) {
  if (!Array.isArray(layerRules) || layerRules.length === 0) {
    throw new Error("layers.config.mjs must export a non-empty layers array");
  }
  return layerRules.map((rule, index) => {
    if (!rule || typeof rule.layer !== "string" || !LAYERS.includes(rule.layer)) {
      throw new Error(`layers[${index}] has an unknown layer`);
    }
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      throw new Error(`layers[${index}] needs patterns`);
    }
    return {
      layer: rule.layer,
      tests: rule.patterns.map((pattern) => {
        if (typeof pattern !== "string" || pattern.includes("\\")) {
          throw new Error(`layers[${index}] pattern must be a forward-slash string`);
        }
        return globToRegExp(pattern);
      }),
    };
  });
}

export function layerOf(rel, compiled) {
  for (const rule of compiled) {
    if (rule.tests.some((test) => test.test(rel))) return rule.layer;
  }
  return null;
}

function escapeRegExp(text) {
  return text.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

// Exact file list per layer, so depcruise sees the same first-match result as layerOf.
function exactPath(files) {
  if (files.length === 0) return "^$";
  return `^(?:${files.map(escapeRegExp).join("|")})$`;
}

function layerPaths(layerMap) {
  const byLayer = Object.fromEntries(LAYERS.map((layer) => [layer, []]));
  for (const [rel, layer] of layerMap) if (layer) byLayer[layer].push(rel);
  return Object.fromEntries(LAYERS.map((layer) => [layer, exactPath(byLayer[layer])]));
}

function union(paths, names) {
  return names.map((name) => paths[name]);
}

export function buildRuleSet(layerMap) {
  const p = layerPaths(layerMap);
  const mapped = exactPath([...layerMap].filter(([, layer]) => layer).map(([rel]) => rel));
  const forbidden = [
    { name: "domain-no-node", from: { path: p.domain }, to: { dependencyTypes: ["core"] } },
    {
      name: "domain-no-upper",
      from: { path: p.domain },
      to: { path: union(p, ["app", "infra", "cli", "adapters", "ui"]) },
    },
    {
      name: "adapters-deps",
      from: { path: p.adapters },
      to: { pathNot: union(p, ["domain", "contract", "adapters"]) },
    },
    {
      name: "ui-no-inner",
      from: { path: p.ui },
      to: { path: union(p, ["domain", "app", "infra", "cli", "adapters"]) },
    },
    { name: "app-no-cli-ui", from: { path: p.app }, to: { path: union(p, ["cli", "ui"]) } },
    { name: "infra-no-upper", from: { path: p.infra }, to: { path: union(p, ["app", "cli", "ui"]) } },
    { name: "unresolved-import", from: { path: mapped }, to: { couldNotResolve: true } },
  ];
  for (const layer of LAYERS) {
    forbidden.push({
      name: "cross-layer-cycle",
      from: { path: p[layer] },
      to: { circular: true, path: mapped, pathNot: p[layer] },
    });
  }
  return { forbidden: forbidden.map((rule) => ({ severity: "error", ...rule })) };
}

function tarjan(nodes, edges) {
  const index = new Map();
  const low = new Map();
  const stack = [];
  const onStack = new Set();
  const sccs = [];
  let next = 0;
  const adj = new Map();
  for (const node of nodes) adj.set(node, []);
  for (const edge of edges) {
    if (!adj.has(edge.from)) adj.set(edge.from, []);
    adj.get(edge.from).push(edge.to);
  }
  function strong(node) {
    index.set(node, next);
    low.set(node, next);
    next += 1;
    stack.push(node);
    onStack.add(node);
    for (const to of adj.get(node) ?? []) {
      if (!index.has(to)) {
        strong(to);
        low.set(node, Math.min(low.get(node), low.get(to)));
      } else if (onStack.has(to)) {
        low.set(node, Math.min(low.get(node), index.get(to)));
      }
    }
    if (low.get(node) === index.get(node)) {
      const component = [];
      let top = null;
      do {
        top = stack.pop();
        onStack.delete(top);
        component.push(top);
      } while (top !== node);
      sccs.push(component);
    }
  }
  for (const node of adj.keys()) {
    if (!index.has(node)) strong(node);
  }
  return sccs;
}

function loadAllowlist(root) {
  const path = join(root, "scripts", "layers.allowlist.json");
  if (!existsSync(path)) return [];
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const entries = Array.isArray(parsed) ? parsed : parsed.entries;
  if (!Array.isArray(entries)) throw new Error("layers.allowlist.json needs an entries array");
  return entries.map((entry, index) => {
    for (const key of ["from", "to", "rule", "reason", "wp"]) {
      if (typeof entry?.[key] !== "string" || entry[key].length === 0) {
        throw new Error(`allowlist[${index}] needs ${key}`);
      }
    }
    return {
      from: normalizePosix(entry.from),
      to: entry.to.includes(":") ? entry.to : normalizePosix(entry.to),
      rule: entry.rule,
      reason: entry.reason,
      wp: entry.wp,
    };
  });
}

function keyOf(item) {
  return `${item.rule}\0${item.from}\0${item.to}`;
}

function isCore(types) {
  return types.includes("core");
}

// depcruise reports builtins as "fs" or "node:fs"; the allowlist uses the node: form.
function targetId(to, types) {
  if (!isCore(types)) return to;
  return to.startsWith("node:") ? to : `node:${to}`;
}

// depcruise keeps one dependency per resolved module, typed by its first occurrence.
function edgeKind(types) {
  if (types.includes("dynamic-import")) return "dyn-import";
  if (types.includes("type-import")) return "import-type-query";
  if (types.includes("type-only")) return "import-type";
  if (types.includes("require")) return "require";
  if (types.includes("export")) return "export-from";
  return "import";
}

async function runCruise(root, files, ruleSet) {
  const tsConfigFile = join(root, "tsconfig.json");
  const hasTsConfig = existsSync(tsConfigFile);
  const tsConfig = hasTsConfig ? extractTSConfig(tsConfigFile) : undefined;
  const result = await cruise(
    files,
    {
      baseDir: root,
      validate: true,
      ruleSet,
      tsPreCompilationDeps: true,
      enhancedResolveOptions: {
        exportsFields: ["exports"],
        conditionNames: ["import", "require", "node", "default", "types"],
        mainFields: ["module", "main", "types"],
      },
      doNotFollow: { path: "(^|/)node_modules/" },
      exclude: { path: "(^|/)(?:node_modules|dist|\\.pack|coverage)/|^(?:scripts|tests|bench)/|\\.test\\." },
      ...(hasTsConfig ? { tsConfig: { fileName: tsConfigFile } } : {}),
    },
    undefined,
    tsConfig ? { tsConfig } : undefined,
  );
  if (typeof result.output === "string") throw new Error("dependency-cruiser returned text output");
  return result.output;
}
export async function analyze(root) {
  const normalizedRoot = root.replace(/[\\/]+$/, "");
  const configUrl = pathToFileURL(join(normalizedRoot, "scripts", "layers.config.mjs")).href;
  const config = await import(configUrl);
  const compiled = compileLayers(config.layers);
  const allow = loadAllowlist(normalizedRoot);
  const files = listLayerFiles(normalizedRoot);
  const layers = new Map(files.map((rel) => [rel, layerOf(rel, compiled)]));
  const violations = [];
  for (const [rel, layer] of layers) if (!layer) violations.push({ from: rel, to: "", rule: "unmapped" });

  const output =
    files.length === 0
      ? { modules: [], summary: { violations: [] } }
      : await runCruise(normalizedRoot, files, buildRuleSet(layers));

  const edges = [];
  for (const mod of output.modules) {
    if (!layers.has(mod.source)) continue;
    for (const dep of mod.dependencies) {
      if (dep.couldNotResolve) continue;
      const node = isCore(dep.dependencyTypes);
      if (!node && !layers.has(dep.resolved)) continue;
      edges.push({
        from: mod.source,
        to: targetId(dep.resolved, dep.dependencyTypes),
        kind: edgeKind(dep.dependencyTypes),
        node,
      });
    }
  }

  for (const item of output.summary.violations) {
    if (item.type !== "dependency") continue;
    violations.push({ from: item.from, to: targetId(item.to, item.dependencyTypes ?? []), rule: item.rule.name });
  }

  // Layer-level cycles with no file-level cycle, which depcruise's circular check cannot see.
  const packageEdges = edges.filter((edge) => !edge.node && layers.get(edge.from) !== layers.get(edge.to));
  const layerNodes = [...new Set(packageEdges.flatMap((edge) => [layers.get(edge.from), layers.get(edge.to)]))];
  const layerGraph = packageEdges.map((edge) => ({ from: layers.get(edge.from), to: layers.get(edge.to) }));
  const cyclicLayers = new Set();
  for (const component of tarjan(layerNodes, layerGraph)) {
    if (component.length > 1) for (const layer of component) cyclicLayers.add(layer);
  }
  for (const edge of packageEdges) {
    if (cyclicLayers.has(layers.get(edge.from)) && cyclicLayers.has(layers.get(edge.to))) {
      violations.push({ from: edge.from, to: edge.to, rule: "cross-layer-cycle" });
    }
  }

  let coreToMonitor = false;
  const backEdges = [];
  for (const edge of edges) {
    if (edge.node) continue;
    const fromCore = edge.from.startsWith("core/") && layers.get(edge.from) !== "domain";
    const toCore = edge.to.startsWith("core/") && layers.get(edge.to) !== "domain";
    if (fromCore && edge.to.startsWith("src/lib/monitor/")) coreToMonitor = true;
    if (edge.from.startsWith("src/lib/monitor/") && toCore) backEdges.push(edge);
  }
  if (coreToMonitor) {
    for (const edge of backEdges) violations.push({ from: edge.from, to: edge.to, rule: "core-monitor-bidirectional" });
  }

  const seen = new Set();
  const uniqueViolations = [];
  for (const item of violations) {
    const id = keyOf(item);
    if (seen.has(id)) continue;
    seen.add(id);
    uniqueViolations.push(item);
  }
  uniqueViolations.sort((a, b) => keyOf(a).localeCompare(keyOf(b)));

  const allowKeys = new Map();
  const stale = [];
  for (const entry of allow) {
    const id = keyOf(entry);
    if (allowKeys.has(id)) {
      stale.push({ from: entry.from, to: entry.to, rule: entry.rule, reason: "duplicate allowlist entry" });
      continue;
    }
    allowKeys.set(id, entry);
    if (!seen.has(id)) stale.push({ from: entry.from, to: entry.to, rule: entry.rule, reason: "violation no longer present" });
  }
  const active = uniqueViolations.filter((item) => !allowKeys.has(keyOf(item)));
  stale.sort((a, b) => keyOf(a).localeCompare(keyOf(b)));

  return {
    ok: active.length === 0 && stale.length === 0,
    files: files.length,
    violations: active,
    suppressed: uniqueViolations.length - active.length,
    stale,
    edges,
    layers: Object.fromEntries(layers),
  };
}

function printHuman(result) {
  const lines = [
    `check-layers: ${result.files} files, ${result.violations.length} violations, ${result.stale.length} stale allowlist, ${result.suppressed} suppressed`,
  ];
  for (const item of result.violations) lines.push(`${item.from} -> ${item.to || "(unmapped)"} [${item.rule}]`);
  if (result.stale.length > 0) {
    lines.push("stale allowlist:");
    for (const item of result.stale) lines.push(`${item.from} -> ${item.to} [${item.rule}] ${item.reason}`);
  }
  return `${lines.join("\n")}\n`;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(entry).href);
  } catch {
    return false;
  }
}

export async function main(argv = process.argv.slice(2), stdout = process.stdout) {
  let root = repoOfScript();
  let json = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") json = true;
    else if (arg === "--root") {
      root = argv[i + 1] ?? "";
      i += 1;
    } else if (arg.startsWith("--root=")) root = arg.slice("--root=".length);
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!root) throw new Error("--root needs a directory");
  const result = await analyze(root);
  if (json) {
    const { ok, files, violations, stale, suppressed } = result;
    stdout.write(`${JSON.stringify({ ok, files, violations, stale, suppressed }, null, 2)}\n`);
  } else {
    stdout.write(printHuman(result));
  }
  return result.ok ? 0 : 1;
}

if (invokedDirectly()) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
