import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { analyze } from "./check-layers.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const script = join(repo, "scripts", "check-layers.mjs");

const CONFIG = `export const layers = [
  { layer: "contract", patterns: ["contract/**"] },
  { layer: "domain", patterns: ["domain/**", "src/lib/monitor/**"] },
  { layer: "adapters", patterns: ["adapters/**"] },
  { layer: "app", patterns: ["app/**", "core/**"] },
  { layer: "infra", patterns: ["infra/**"] },
  { layer: "cli", patterns: ["cli/**"] },
  { layer: "ui", patterns: ["ui/**"] },
];
`;

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { cwd: repo, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function fixture(files, allowlist) {
  const root = await mkdtemp(join(tmpdir(), "nmzp-layers-"));
  await mkdir(join(root, "scripts"), { recursive: true });
  await writeFile(join(root, "scripts", "layers.config.mjs"), CONFIG);
  if (allowlist) {
    await writeFile(join(root, "scripts", "layers.allowlist.json"), JSON.stringify({ entries: allowlist }));
  }
  for (const [rel, text] of Object.entries(files)) {
    const path = join(root, rel);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, text);
  }
  return root;
}

function rules(result) {
  return result.violations.map((item) => item.rule);
}

describe("layer rules", () => {
  test("domain may import domain and must not import node:fs", async () => {
    const bad = await fixture({
      "domain/pure.ts": 'import { readFileSync } from "node:fs";\nexport const x = readFileSync;\n',
    });
    const good = await fixture({
      "domain/a.ts": 'export { b } from "./b.ts";\n',
      "domain/b.ts": "export const b = 1;\n",
    });
    try {
      const violated = await analyze(bad);
      assert.equal(violated.ok, false);
      assert.deepEqual(rules(violated), ["domain-no-node"]);
      assert.equal(violated.violations[0].to, "node:fs");
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("a literal dynamic import is an edge and a non-literal one is not", async () => {
    const bad = await fixture({
      "domain/load.ts": 'export function load() { return import("node:fs"); }\n',
    });
    const good = await fixture({
      "domain/load.ts": "export function load(name) { return import(name); }\n",
    });
    try {
      const violated = await analyze(bad);
      assert.ok(rules(violated).includes("domain-no-node"));
      assert.equal(violated.edges.some((edge) => edge.kind === "dyn-import" && edge.to === "node:fs"), true);
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
      assert.equal(clean.edges.some((edge) => edge.kind === "dyn-import"), false);
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("ui may import contract and must not import domain", async () => {
    const bad = await fixture({
      "ui/app.ts": 'import { value } from "../domain/pure.ts";\nexport const n = value;\n',
      "domain/pure.ts": "export const value = 1;\n",
    });
    const good = await fixture({
      "ui/app.ts": 'import { value } from "../contract/api.ts";\nexport const n = value;\n',
      "contract/api.ts": "export const value = 1;\n",
    });
    try {
      const violated = await analyze(bad);
      assert.deepEqual(rules(violated), ["ui-no-inner"]);
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("a cross-layer cycle fails and a one-way domain to contract edge does not", async () => {
    const bad = await fixture({
      "domain/a.ts": 'export { c } from "../contract/c.ts";\n',
      "contract/c.ts": 'export { a } from "../domain/a.ts";\n',
    });
    const good = await fixture({
      "domain/a.ts": 'export { c } from "../contract/c.ts";\n',
      "contract/c.ts": "export const c = 1;\n",
    });
    try {
      const violated = await analyze(bad);
      assert.ok(rules(violated).includes("cross-layer-cycle"));
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("a layer cycle without a file cycle fails and a bare builtin counts as node", async () => {
    const bad = await fixture({
      "domain/a.ts": 'export { c } from "../contract/c.ts";\n',
      "contract/c.ts": "export const c = 1;\n",
      "contract/d.ts": 'export { b } from "../domain/b.ts";\n',
      "domain/b.ts": 'import { join } from "path";\nexport const b = join;\n',
    });
    try {
      const violated = await analyze(bad);
      assert.ok(rules(violated).includes("cross-layer-cycle"));
      const node = violated.violations.find((item) => item.rule === "domain-no-node");
      assert.equal(node?.to, "node:path");
    } finally {
      await rm(bad, { recursive: true, force: true });
    }
  });

  test("an unmapped source file fails and a test file is outside the gate", async () => {
    const bad = await fixture({ "loose/orphan.ts": "export const n = 1;\n" });
    const good = await fixture({
      "domain/a.ts": "export const n = 1;\n",
      "domain/a.test.ts": 'import { readFileSync } from "node:fs";\nexport const x = readFileSync;\n',
    });
    try {
      const violated = await analyze(bad);
      assert.equal(violated.violations[0].rule, "unmapped");
      assert.equal(violated.violations[0].from, "loose/orphan.ts");
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
      assert.equal(clean.files, 1);
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("adapters, app, and infra keep their dependency direction", async () => {
    const bad = await fixture({
      "adapters/host.ts": 'import { readFileSync } from "node:fs";\nexport const x = readFileSync;\n',
      "app/main.ts": 'import { run } from "../cli/main.ts";\nexport const x = run;\n',
      "cli/main.ts": "export const run = 1;\n",
      "infra/db.ts": 'import { main } from "../app/other.ts";\nexport const x = main;\n',
      "app/other.ts": "export const main = 1;\n",
    });
    const good = await fixture({
      "adapters/host.ts": 'import { value } from "../domain/pure.ts";\nexport const x = value;\n',
      "domain/pure.ts": "export const value = 1;\n",
      "app/main.ts": 'import { value } from "../domain/pure.ts";\nexport const x = value;\n',
      "infra/db.ts": 'import { value } from "../domain/pure.ts";\nexport const y = value;\n',
    });
    try {
      const violated = await analyze(bad);
      assert.deepEqual(rules(violated).sort(), ["adapters-deps", "app-no-cli-ui", "infra-no-upper"]);
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("core and monitor are bidirectional only when both directions exist", async () => {
    const bad = await fixture({
      "core/gate.ts": 'import { pure } from "../src/lib/monitor/pure.ts";\nexport const n = pure;\n',
      "src/lib/monitor/pure.ts": 'import { gate } from "../../../core/gate.ts";\nexport const pure = gate;\n',
    });
    const good = await fixture({
      "core/gate.ts": 'import { pure } from "../src/lib/monitor/pure.ts";\nexport const n = pure;\n',
      "src/lib/monitor/pure.ts": "export const pure = 1;\n",
    });
    try {
      const violated = await analyze(bad);
      assert.ok(rules(violated).includes("core-monitor-bidirectional"));
      const clean = await analyze(good);
      assert.equal(clean.ok, true, JSON.stringify(clean.violations));
    } finally {
      await rm(bad, { recursive: true, force: true });
      await rm(good, { recursive: true, force: true });
    }
  });

  test("an allowlist entry suppresses a current violation and a stale entry fails", async () => {
    const files = { "domain/pure.ts": 'import { readFileSync } from "node:fs";\nexport const x = readFileSync;\n' };
    const entry = {
      from: "domain/pure.ts",
      to: "node:fs",
      rule: "domain-no-node",
      reason: "fixture",
      wp: "WP-24",
    };
    const suppressed = await fixture(files, [entry]);
    const stale = await fixture(
      { "domain/pure.ts": "export const x = 1;\n" },
      [entry],
    );
    try {
      const allowed = await analyze(suppressed);
      assert.equal(allowed.ok, true, JSON.stringify(allowed.violations));
      assert.equal(allowed.suppressed, 1);
      const expired = await analyze(stale);
      assert.equal(expired.ok, false);
      assert.equal(expired.violations.length, 0);
      assert.equal(expired.stale.length, 1);
      assert.equal(expired.stale[0].rule, "domain-no-node");
    } finally {
      await rm(suppressed, { recursive: true, force: true });
      await rm(stale, { recursive: true, force: true });
    }
  });
});

describe("repository layer gate", () => {
  test("the real tree has no violations outside the allowlist", async () => {
    const result = await analyze(repo);
    assert.equal(result.ok, true, JSON.stringify({ violations: result.violations, stale: result.stale }));
    assert.equal(result.violations.length, 0);
    assert.equal(result.stale.length, 0);
    const names = [
      "engine.ts",
      "session-window.ts",
      "privacy.ts",
      "rights.ts",
      "ingest.ts",
      "trust.ts",
      "agents.ts",
      "cli.ts",
      "watch.ts",
      "correlate.ts",
      "rules.ts",
      "overrides.ts",
    ];
    // depcruise keeps one edge per module; paths.ts also names these in typeof import() types.
    const targets = new Set(result.edges.filter((edge) => edge.from === "core/paths.ts").map((edge) => edge.to));
    for (const name of names) assert.equal(targets.has(`src/lib/monitor/${name}`), true, name);
  });

  test("the cli reports success as json", async () => {
    const ran = await runCli(["--json"]);
    assert.equal(ran.code, 0, ran.stderr);
    const body = JSON.parse(ran.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.violations.length, 0);
    assert.equal(body.stale.length, 0);
  });
});
