// Candidate corpus runner. `run` is read-only. Expected files are written only by generate --write-expected.
import crypto from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CATEGORIES = [
  "normal",
  "risky",
  "boundaries",
  "protected",
  "exemptions",
  "rewrite",
  "privacy",
  "proposal",
  "historical",
  "host-normalization",
];
export const SEED = 20260927;
export const NOW = 1_790_000_000_000;
export const BASELINE_SHA = "0ea8f6eac4457c5e13b22b7130f64d48e3613927";
export const PRIVACY_CATEGORIES = [
  "rest-id",
  "snowflake",
  "unix-time",
  "uuid",
  "git-sha",
  "ci-build",
  "semver-dateversion",
  "port",
  "ip",
  "digest",
  "order-number",
  "area-extension",
];

const INPUT_KEYS = [
  "nativeTool",
  "command",
  "filePath",
  "url",
  "cwd",
  "dest",
  "contents",
  "agent",
  "sessionModel",
  "sessionId",
  "deviceId",
  "eventId",
  "source",
  "proc",
  "parentProc",
  "hookBlind",
];

export function repoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function stableStringify(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortValue(value[key]);
    return out;
  }
  return value;
}

export function sha256Text(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

export function sha256FileSync(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function assertExternalCorpus(corpus, repo = repoRoot()) {
  const target = path.resolve(corpus);
  const root = path.resolve(repo);
  const rel = path.relative(root, target);
  if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) {
    throw new Error(`corpus root must stay outside the checkout (${root})`);
  }
  return target;
}

export function assertRunReadOnly(argv) {
  if (argv.includes("--write-expected")) {
    throw new Error("run is read-only and cannot rewrite expected");
  }
}

export function projectResult(result) {
  return {
    action: result.action,
    actor: result.actor,
    decision: result.decision,
    dryRunKinds: result.dryRunKinds ?? null,
    exemptionId: result.exemptionId ?? null,
    overrideSource: result.overrideSource ?? null,
    rewritten: result.rewritten,
    risk: result.risk,
    ruleId: result.rule?.id ?? null,
    secretKinds: [...result.secretKinds],
    skipped: result.skipped,
    threat: result.threat ?? null,
    tool: result.tool,
  };
}

export async function loadRuntime(root = repoRoot()) {
  const engineUrl = pathToFileURL(path.join(root, "src/lib/monitor/engine.ts")).href;
  const hookUrl = pathToFileURL(path.join(root, "core/hook-protocol.ts")).href;
  const rulesUrl = pathToFileURL(path.join(root, "src/lib/monitor/rules.ts")).href;
  const overridesUrl = pathToFileURL(path.join(root, "src/lib/monitor/overrides.ts")).href;
  const policyUrl = pathToFileURL(path.join(root, "core/policy-schema.ts")).href;
  const privacyUrl = pathToFileURL(path.join(root, "src/lib/monitor/privacy.ts")).href;
  const agentsUrl = pathToFileURL(path.join(root, "src/lib/monitor/agents.ts")).href;
  const scopeUrl = pathToFileURL(path.join(root, "src/lib/monitor/exemption-scope.ts")).href;
  const [engine, hook, rules, overrides, policy, privacy, agents, scope] = await Promise.all([
    import(engineUrl),
    import(hookUrl),
    import(rulesUrl),
    import(overridesUrl),
    import(policyUrl),
    import(privacyUrl),
    import(agentsUrl),
    import(scopeUrl),
  ]);
  return {
    evaluate: engine.evaluate,
    parseHookEvent: hook.parseHookEvent,
    toolInputToEvalFields: hook.toolInputToEvalFields,
    detectHookAgent: hook.detectHookAgent,
    HOOK_AGENTS: hook.HOOK_AGENTS,
    RULES: rules.RULES,
    protectedRuleIds: overrides.protectedRuleIds,
    protectionLevel: overrides.protectionLevel,
    parsePolicyOverrides: policy.parsePolicyOverrides,
    parseCustomRuleScope: policy.parseCustomRuleScope,
    policyExemptions: policy.policyExemptions,
    compileMatch: privacy.compileMatch,
    sanitizeCustomRules: privacy.sanitizeCustomRules,
    normalizeTool: agents.normalizeTool,
    exemptionSubjects: scope.exemptionSubjects,
  };
}

function fail(code, detail) {
  return { ok: false, code, detail };
}

function enginePayload(input) {
  const payload = {};
  for (const key of INPUT_KEYS) {
    if (input[key] !== undefined) payload[key] = input[key];
  }
  return payload;
}

function hasEngineText(input) {
  return [input.command, input.filePath, input.url, input.contents, input.dest].some(
    (value) => typeof value === "string" && value.length > 0,
  );
}

const ENGINE_INPUT_KEYS = new Set(INPUT_KEYS);
const HOST_INPUT_KEYS = new Set(["raw", "agentFlag"]);
const POLICY_KEYS = new Set(["now", "overrides", "exemptions"]);
const OVERRIDE_KEYS = new Set(["rules", "families"]);
const CONTEXT_KEYS = new Set(["fixtureKind", "intervention", "customRules", "seed", "provenance"]);
const PROVENANCE_KEYS = new Set([
  "status",
  "acceptance",
  "generator",
  "baselineSha",
  "origin",
  "sourceFile",
  "testTitle",
  "note",
  "allowsEarlyReturn",
  "role",
]);
const ORIGINS = new Set(["cited-case", "cited-command-proposed-policy", "synthetic"]);
const EXPECTED_KEYS = new Set(["compare", "redacted", "normalization", "v2Intended"]);
const CUSTOM_RULE_KEYS = new Set(["id", "enabled", "mode", "match", "kind", "replaceWith", "scope", "dryRun"]);

function isPlain(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function unknownField(value, allowed, label) {
  if (!isPlain(value)) return fail("invalid_shape", label);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) return fail("unknown_field", `${label}.${key}`);
  }
  return null;
}

export function validateBundle(bundle) {
  const { input, policy, context } = bundle;
  if (!context || !policy || !input) return fail("invalid_shape", "missing bundle section");
  const inputKeys = context.fixtureKind === "host-normalization" ? HOST_INPUT_KEYS : ENGINE_INPUT_KEYS;
  const unknownInput = unknownField(input, inputKeys, "input");
  if (unknownInput) return unknownInput;
  const unknownPolicy = unknownField(policy, POLICY_KEYS, "policy");
  if (unknownPolicy) return unknownPolicy;
  const unknownContext = unknownField(context, CONTEXT_KEYS, "context");
  if (unknownContext) return unknownContext;
  if (context.fixtureKind !== "engine" && context.fixtureKind !== "host-normalization") {
    return fail("unsupported_kind", String(context.fixtureKind));
  }
  if (!["enforcing", "permissive", "off"].includes(context.intervention)) {
    return fail("invalid_shape", "intervention");
  }
  if (!Array.isArray(context.customRules)) return fail("invalid_shape", "customRules");
  if (context.seed !== SEED) return fail("invalid_shape", "seed");
  const provenance = context.provenance;
  const unknownProvenance = unknownField(provenance, PROVENANCE_KEYS, "provenance");
  if (unknownProvenance) return unknownProvenance;
  if (provenance.status !== "PROPOSED" && provenance.status !== "SOURCE_INDEPENDENT") {
    return fail("invalid_shape", "status");
  }
  if (provenance.acceptance !== "NOT_ACCEPTED" && provenance.acceptance !== "CITED_NOT_CORPUS_ACCEPT") {
    return fail("invalid_shape", "acceptance");
  }
  if (!ORIGINS.has(provenance.origin)) return fail("invalid_shape", "provenance.origin");
  if (provenance.status === "SOURCE_INDEPENDENT" && provenance.acceptance !== "CITED_NOT_CORPUS_ACCEPT") {
    return fail("invalid_shape", "source acceptance");
  }
  if (provenance.status === "PROPOSED" && provenance.acceptance !== "NOT_ACCEPTED") {
    return fail("invalid_shape", "proposed acceptance");
  }
  if (provenance.generator !== "grok-wp02" || provenance.baselineSha !== BASELINE_SHA) {
    return fail("invalid_shape", "provenance identity");
  }
  if (!Number.isSafeInteger(policy.now)) return fail("invalid_shape", "policy.now");
  const unknownOverrides = unknownField(policy.overrides, OVERRIDE_KEYS, "overrides");
  if (unknownOverrides) return unknownOverrides;
  if (!isPlain(policy.overrides.rules)) return fail("invalid_shape", "overrides.rules");
  if (!isPlain(policy.overrides.families)) return fail("invalid_shape", "overrides.families");
  if (!Array.isArray(policy.exemptions)) return fail("invalid_shape", "exemptions");
  const provenanceTypes = [
    optionalStringOrNull(provenance.sourceFile, "provenance.sourceFile"),
    optionalStringOrNull(provenance.testTitle, "provenance.testTitle"),
    optionalString(provenance.note, "provenance.note"),
    optionalBoolean(provenance.allowsEarlyReturn, "provenance.allowsEarlyReturn"),
    optionalString(provenance.role, "provenance.role"),
  ];
  for (const item of provenanceTypes) if (item) return item;
  if (context.fixtureKind === "engine") {
    if (typeof input.nativeTool !== "string" || input.nativeTool.length === 0) {
      return fail("invalid_shape", "nativeTool");
    }
    for (const key of ["command", "filePath", "url", "cwd", "dest", "contents", "agent", "sessionModel", "sessionId", "deviceId", "eventId", "source", "proc", "parentProc"]) {
      const typed = optionalString(input[key], `input.${key}`);
      if (typed) return typed;
    }
    const blind = optionalBoolean(input.hookBlind, "input.hookBlind");
    if (blind) return blind;
    if (!hasEngineText(input)) return fail("empty_input", "engine fixture has no command, path, url, or contents");
  } else {
    if (typeof input.raw !== "string" || input.raw.trim().length < 2) return fail("invalid_shape", "input.raw");
    if (typeof input.agentFlag !== "string" || input.agentFlag.length === 0) {
      return fail("invalid_shape", "agentFlag");
    }
  }
  return { ok: true };
}

function optionalString(value, label) {
  if (value === undefined) return null;
  if (typeof value !== "string") return fail("invalid_shape", label);
  return null;
}

function optionalBoolean(value, label) {
  if (value === undefined) return null;
  if (typeof value !== "boolean") return fail("invalid_shape", label);
  return null;
}

function optionalStringOrNull(value, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return fail("invalid_shape", label);
  return null;
}

export function validateCustomRules(rules, api) {
  if (!Array.isArray(rules)) return fail("invalid_custom_rule", "customRules");
  for (const rule of rules) {
    const unknown = unknownField(rule, CUSTOM_RULE_KEYS, "customRules");
    if (unknown) return unknown;
    if (typeof rule.id !== "string" || rule.id.length === 0) return fail("invalid_custom_rule", "id");
    if (typeof rule.enabled !== "boolean") return fail("invalid_custom_rule", "enabled");
    if (rule.mode !== "block" && rule.mode !== "replace") return fail("invalid_custom_rule", "mode");
    if (typeof rule.match !== "string" || rule.match.length < 2 || !api.compileMatch(rule.match)) return fail("invalid_custom_rule", "match");
    if (typeof rule.kind !== "string" || rule.kind.length === 0) return fail("invalid_custom_rule", "kind");
    if (typeof rule.replaceWith !== "string" || rule.replaceWith.length === 0) return fail("invalid_custom_rule", "replaceWith");
    if (rule.dryRun !== undefined && typeof rule.dryRun !== "boolean") return fail("invalid_custom_rule", "dryRun");
    if (rule.scope !== undefined && !isPlain(rule.scope)) return fail("invalid_shape", "customRules.scope");
    if (rule.scope !== undefined && !api.parseCustomRuleScope(rule.scope).ok) return fail("invalid_custom_rule", "scope");
  }
  const sanitized = api.sanitizeCustomRules(rules);
  if (!sanitized || sanitized.length !== rules.length) {
    return fail("invalid_custom_rule", "sanitizeCustomRules dropped a rule");
  }
  return { ok: true };
}

const LOCAL_FILE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "Read", "Glob", "Grep"]);

function joinSubjects(...parts) {
  const out = [];
  for (const part of parts) if (part && !out.includes(part)) out.push(part);
  return out.join("\n");
}

export function builtinExemptionSubjects(rule, input, api) {
  const tool = api.normalizeTool(input.nativeTool || "");
  const command = input.command ?? "";
  const filePath = input.filePath ?? "";
  const url = input.url ?? "";
  const dest = input.dest ?? "";
  const networkText = LOCAL_FILE_TOOLS.has(tool) ? joinSubjects(url, dest) : joinSubjects(url, dest, command);
  if (rule.field === "file_path" || rule.field === "tool_name" || (rule.field === "url" && tool !== "Bash")) {
    const text = rule.field === "file_path" ? filePath : rule.field === "tool_name" ? input.nativeTool ?? "" : networkText;
    return text ? [text] : [];
  }
  if (rule.field === "url") {
    const re = new RegExp(rule.pattern, "i");
    const literals = [];
    for (const part of [url, dest]) {
      if (!part) continue;
      re.lastIndex = 0;
      if (re.test(part)) literals.push(part);
    }
    if (!command) return literals.length ? literals : networkText ? [networkText] : [];
    const shell = api.exemptionSubjects(command, rule.id);
    if (shell === null) return null;
    return [...literals, ...shell];
  }
  if (!command) return [];
  return api.exemptionSubjects(command, rule.id);
}

export function exemptionAttemptMatches(rule, input, match, api) {
  if (!rule || !api.compileMatch(match)) return false;
  const subjects = builtinExemptionSubjects(rule, input, api);
  if (!subjects?.length) return false;
  const re = api.compileMatch(match);
  return subjects.every((subject) => {
    re.lastIndex = 0;
    return re.test(subject);
  });
}

export function validateExpected(expected) {
  const unknown = unknownField(expected, EXPECTED_KEYS, "expected");
  if (unknown) return unknown;
  if (!("v2Intended" in expected)) return fail("invalid_shape", "expected.v2Intended");
  if (expected.v2Intended !== null && !isPlain(expected.v2Intended)) return fail("invalid_shape", "expected.v2Intended");
  if (!isPlain(expected.compare)) return fail("invalid_shape", "expected.compare");
  if (typeof expected.redacted !== "string") return fail("invalid_shape", "expected.redacted");
  if (!("normalization" in expected)) return fail("invalid_shape", "expected.normalization");
  if (expected.normalization !== null && !isPlain(expected.normalization)) return fail("invalid_shape", "expected.normalization");
  return { ok: true };
}

export function observe(bundle, api) {
  const shape = validateBundle(bundle);
  if (!shape.ok) return shape;
  const custom = validateCustomRules(bundle.context.customRules, api);
  if (!custom.ok) return custom;
  const parsedOverrides = api.parsePolicyOverrides(bundle.policy.overrides);
  if (!parsedOverrides) return fail("invalid_shape", "overrides rejected by policy parser");
  const parsedExemptions = api.policyExemptions(bundle.policy.exemptions);
  if (parsedExemptions.length !== bundle.policy.exemptions.length) {
    return fail("invalid_shape", "one or more exemptions were dropped by the policy parser");
  }
  const policy = {
    now: bundle.policy.now,
    overrides: bundle.policy.overrides,
    exemptions: bundle.policy.exemptions,
  };
  let normalization = null;
  let evalInput;
  if (bundle.context.fixtureKind === "host-normalization") {
    const parsed = api.parseHookEvent(bundle.input.raw);
    if (!parsed) return fail("parse_failure", "parseHookEvent returned null");
    if (!parsed.toolInput || typeof parsed.toolInput !== "object" || Array.isArray(parsed.toolInput)) {
      return fail("parse_failure", "parsed toolInput is not an object");
    }
    const fields = api.toolInputToEvalFields(parsed.toolName, parsed.toolInput);
    const agent = api.detectHookAgent(bundle.input.agentFlag, parsed);
    const parsedCommand =
      typeof parsed.toolInput.command === "string" && parsed.toolInput.command.trim()
        ? parsed.toolInput.command.trim()
        : null;
    if ((fields.command ?? null) !== parsedCommand) {
      return fail("parser_field_divergence", "toolInputToEvalFields command is not parsed.toolInput.command");
    }
    normalization = {
      agent,
      command: fields.command ?? null,
      eventName: parsed.eventName,
      filePath: fields.filePath ?? null,
      nativeTool: fields.nativeTool,
      parsedCommand,
      toolName: parsed.toolName,
      url: fields.url ?? null,
    };
    if (!normalization.command && !normalization.filePath && !normalization.url && !fields.contents) {
      return fail("empty_input", "parser produced no operational field");
    }
    evalInput = {
      nativeTool: fields.nativeTool,
      source: "hook",
      agent: bundle.input.agentFlag,
      cwd: fields.cwd || parsed.cwd || "/home/u/proj",
    };
    if (fields.command) evalInput.command = fields.command;
    if (fields.filePath) evalInput.filePath = fields.filePath;
    if (fields.url) evalInput.url = fields.url;
    if (fields.contents) evalInput.contents = fields.contents;
    if (fields.dest) evalInput.dest = fields.dest;
  } else {
    evalInput = enginePayload(bundle.input);
  }
  const result = api.evaluate(evalInput, bundle.context.intervention, bundle.context.customRules, policy);
  return {
    ok: true,
    observed: {
      compare: projectResult(result),
      redacted: result.redacted,
      normalization,
    },
  };
}

function readJson(file) {
  const text = fsSync.readFileSync(file, "utf8");
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (error) {
    return fail("invalid_json", `${file}: ${error.message}`);
  }
}

export async function loadCase(dir) {
  const names = ["input.json", "policy.json", "context.json", "expected.json"];
  const bundle = {};
  for (const name of names) {
    const loaded = readJson(path.join(dir, name));
    if (!loaded.ok) return loaded;
    bundle[name.replace(".json", "")] = loaded.value;
  }
  return { ok: true, bundle };
}

function caseDirs(root) {
  const found = [];
  function walk(dir) {
    const entries = fsSync.readdirSync(dir, { withFileTypes: true });
    const names = entries.map((entry) => entry.name);
    if (names.includes("input.json")) {
      found.push(dir);
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      walk(path.join(dir, entry.name));
    }
  }
  walk(root);
  return found.sort((a, b) => a.localeCompare(b));
}

function relId(root, dir) {
  return path.relative(root, dir).split(path.sep).join("/");
}

export async function runCorpus(root, api, options = {}) {
  const requireCategories = options.requireCategories !== false;
  const dirs = await caseDirs(root);
  const failures = [];
  const cases = [];
  const byCategory = new Map(CATEGORIES.map((category) => [category, []]));
  for (const dir of dirs) {
    const id = relId(root, dir);
    const category = id.split("/")[0];
    if (!CATEGORIES.includes(category)) {
      failures.push({ id, code: "unsupported_kind", detail: `category ${category}` });
      continue;
    }
    const loaded = await loadCase(dir);
    if (!loaded.ok) {
      failures.push({ id, code: loaded.code, detail: loaded.detail });
      continue;
    }
    for (const name of ["input.json", "policy.json", "context.json", "expected.json"]) {
      const full = path.join(dir, name);
      try {
        fsSync.accessSync(full);
      } catch {
        failures.push({ id, code: "missing_file", detail: name });
      }
    }
    const expected = loaded.bundle.expected;
    const expectedShape = validateExpected(expected);
    if (!expectedShape.ok) {
      failures.push({ id, code: expectedShape.code, detail: expectedShape.detail });
      continue;
    }
    const observed = observe(loaded.bundle, api);
    if (!observed.ok) {
      failures.push({ id, code: observed.code, detail: observed.detail });
      continue;
    }
    const compareMismatch = stableStringify(expected.compare) !== stableStringify(observed.observed.compare);
    const redactedMismatch = expected.redacted !== observed.observed.redacted;
    const normalizationMismatch =
      stableStringify(expected.normalization ?? null) !== stableStringify(observed.observed.normalization);
    if (compareMismatch || redactedMismatch || normalizationMismatch) {
      failures.push({
        id,
        code: "result_mismatch",
        detail: stableStringify({
          compareChanged: compareMismatch,
          expectedDecision: expected.compare.decision ?? null,
          expectedRisk: expected.compare.risk ?? null,
          expectedRuleId: expected.compare.ruleId ?? null,
          normalizationChanged: normalizationMismatch,
          normalizationExpected: expected.normalization?.command ?? null,
          normalizationObserved: observed.observed.normalization?.command ?? null,
          observedDecision: observed.observed.compare.decision,
          observedRisk: observed.observed.compare.risk,
          observedRuleId: observed.observed.compare.ruleId,
          redactedChanged: redactedMismatch,
        }),
      });
    }
    const skipped = observed.observed.compare.skipped === true;
    const allowsEarly = loaded.bundle.context.provenance?.allowsEarlyReturn === true;
    if (skipped && !allowsEarly) {
      failures.push({ id, code: "skipped_unmarked", detail: "engine skipped without allowsEarlyReturn" });
    }
    if (loaded.bundle.context.provenance?.role === "custom" && skipped) {
      failures.push({ id, code: "skipped_unmarked", detail: "custom fixture early-returned" });
    }
    const row = {
      id,
      category,
      status: loaded.bundle.context.provenance.status,
      origin: loaded.bundle.context.provenance.origin,
      sourceFile: loaded.bundle.context.provenance.sourceFile ?? null,
      testTitle: loaded.bundle.context.provenance.testTitle ?? null,
      note: loaded.bundle.context.provenance.note ?? "",
      compare: observed.observed.compare,
      normalization: observed.observed.normalization,
      v2Intended: expected.v2Intended ?? null,
    };
    cases.push(row);
    byCategory.get(category).push(row);
  }
  if (requireCategories) {
    for (const category of CATEGORIES) {
      const rows = byCategory.get(category) ?? [];
      if (rows.length === 0) failures.push({ id: category, code: "missing_category", detail: "no fixtures" });
      else if (rows.every((row) => row.compare.skipped)) {
        failures.push({ id: category, code: "category_all_skipped", detail: "every fixture skipped" });
      }
    }
  }
  const digest = await expectedDigest(root);
  const digestFile = path.join(root, "PROPOSED_DIGEST.txt");
  let digestText = null;
  try {
    digestText = await fs.readFile(digestFile, "utf8");
  } catch {
    if (requireCategories) failures.push({ id: "PROPOSED_DIGEST.txt", code: "missing_file", detail: "digest" });
  }
  if (digestText) {
    const lines = Object.fromEntries(
      digestText
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => {
          const i = line.indexOf("=");
          return [line.slice(0, i), line.slice(i + 1)];
        }),
    );
    if (lines.status !== "PROPOSED" || lines.humanAccept !== "false" || lines.frozen !== "false") {
      failures.push({ id: "PROPOSED_DIGEST.txt", code: "status_mislabel", detail: digestText });
    }
    if (lines.expectedDigest !== digest.digest) {
      failures.push({
        id: "PROPOSED_DIGEST.txt",
        code: "digest_mismatch",
        detail: `file ${lines.expectedDigest} computed ${digest.digest}`,
      });
    }
    if (Number(lines.caseCount) !== digest.count) {
      failures.push({
        id: "PROPOSED_DIGEST.txt",
        code: "digest_mismatch",
        detail: `count file ${lines.caseCount} computed ${digest.count}`,
      });
    }
  }
  return {
    ok: failures.length === 0,
    failures,
    cases,
    digest,
    counts: countCases(cases),
  };
}

export function countCases(cases) {
  const counts = { total: cases.length, byCategory: {}, byStatus: {}, privacyByKind: {} };
  for (const category of CATEGORIES) counts.byCategory[category] = 0;
  for (const row of cases) {
    counts.byCategory[row.category] = (counts.byCategory[row.category] ?? 0) + 1;
    counts.byStatus[row.status] = (counts.byStatus[row.status] ?? 0) + 1;
    if (row.category === "privacy") {
      const kind = row.id.split("/")[1] ?? "unknown";
      counts.privacyByKind[kind] = (counts.privacyByKind[kind] ?? 0) + 1;
    }
  }
  return counts;
}

export async function expectedDigest(root) {
  const dirs = caseDirs(root);
  const parts = [];
  for (const dir of dirs) {
    const rel = `${relId(root, dir)}/expected.json`;
    const text = fsSync.readFileSync(path.join(dir, "expected.json"));
    parts.push(Buffer.from(`${rel}\n`));
    parts.push(text);
  }
  const digest = crypto.createHash("sha256").update(Buffer.concat(parts)).digest("hex");
  return { digest, count: dirs.length, seed: SEED, now: NOW };
}

export function digestDocument(digest) {
  return [
    "status=PROPOSED",
    "humanAccept=false",
    "frozen=false",
    `baselineSha=${BASELINE_SHA}`,
    `seed=${SEED}`,
    `now=${NOW}`,
    `caseCount=${digest.count}`,
    `expectedDigest=${digest.digest}`,
    "",
  ].join("\n");
}

function sliceRule(source, id) {
  const marker = `id: "${id}"`;
  const idx = source.indexOf(marker);
  if (idx < 0 || source.indexOf(marker, idx + marker.length) >= 0) {
    throw new Error(`rule id anchor is not unique: ${id}`);
  }
  const end = source.indexOf("\n  },", idx);
  if (end < 0) throw new Error(`rule block end missing: ${id}`);
  return { idx, end };
}

export function applyRuleMutation(source, id, kind) {
  const { idx, end } = sliceRule(source, id);
  const slice = source.slice(idx, end);
  let next = slice;
  if (kind === "disable-pattern") {
    const match = slice.match(/pattern:\s*"(?:\\.|[^"\\])*"/);
    if (!match) throw new Error(`pattern missing for ${id}`);
    next = slice.replace(match[0], 'pattern: "a^"');
  } else if (kind === "corrupt-risk") {
    const match = slice.match(/risk:\s*"high"/);
    if (!match) throw new Error(`risk missing for ${id}`);
    next = slice.replace(match[0], 'risk: "info"');
  } else {
    throw new Error(`unsupported mutation ${kind}`);
  }
  if (next === slice) throw new Error(`mutation did not change ${id}`);
  return source.slice(0, idx) + next + source.slice(end);
}

const MUTATIONS = [
  { ruleId: "curl_pipe_shell", kind: "disable-pattern", mustMismatch: ["exemptions/pipe-expired"] },
  { ruleId: "scp_rsync_tree", kind: "disable-pattern", mustMismatch: ["risky/a5-scp"] },
  { ruleId: "rclone_cloud_copy", kind: "disable-pattern", mustMismatch: ["risky/a2-rclone"] },
  { ruleId: "dangerous_delete", kind: "corrupt-risk", mustMismatch: ["risky/d1-sudo-rm"] },
  { ruleId: "disk_overwrite", kind: "corrupt-risk", mustMismatch: ["risky/disk-overwrite"] },
];

async function copyTrackedRuntime(dest) {
  const root = repoRoot();
  const filter = (source) => {
    const base = path.basename(source);
    if (base === ".git" || base === "node_modules" || base === ".env" || base.startsWith(".env.")) return false;
    if (base.endsWith(".test.ts") || base.endsWith(".test.mjs")) return false;
    return true;
  };
  await fs.cp(path.join(root, "src", "lib", "monitor"), path.join(dest, "src", "lib", "monitor"), {
    recursive: true,
    filter,
  });
  await fs.cp(path.join(root, "core"), path.join(dest, "core"), { recursive: true, filter });
  await fs.symlink(path.join(root, "node_modules"), path.join(dest, "node_modules"), "junction");
}

async function hashTree(root) {
  const files = [];
  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else files.push(full);
    }
  }
  await walk(root);
  files.sort((a, b) => a.localeCompare(b));
  const hash = crypto.createHash("sha256");
  for (const file of files) {
    hash.update(path.relative(root, file).split(path.sep).join("/"));
    hash.update("\0");
    hash.update(await fs.readFile(file));
    hash.update("\0");
  }
  return hash.digest("hex");
}

export async function mutateBuiltinRules(corpus) {
  if (!corpus) throw new Error("mutateBuiltinRules requires the candidate corpus path");
  const root = repoRoot();
  const corpusRoot = path.resolve(corpus);
  const rulesPath = path.join(root, "src", "lib", "monitor", "rules.ts");
  const enginePath = path.join(root, "src", "lib", "monitor", "engine.ts");
  const parentBefore = {
    corpus: await hashTree(corpusRoot),
    engine: sha256FileSync(await fs.readFile(enginePath)),
    rules: sha256FileSync(await fs.readFile(rulesPath)),
  };
  const work = await fs.mkdtemp(path.join(os.tmpdir(), "nmzp-wp02-mut-"));
  const outside = path.relative(root, work);
  if (!outside.startsWith("..") && !path.isAbsolute(outside)) {
    throw new Error("mutation work directory resolved inside the checkout");
  }
  const results = [];
  let baselineOk = false;
  let baselineFailureCount = 0;
  try {
    const parent = await loadRuntime(root);
    const baseline = await runCorpus(corpusRoot, parent);
    baselineOk = baseline.ok;
    baselineFailureCount = baseline.failures.length;
    if (!baseline.ok) {
      return {
        baselineFailureCount,
        baselineOk: false,
        corpus: corpusRoot,
        failures: baseline.failures.slice(0, 20).map((failure) => ({ id: failure.id, code: failure.code, detail: failure.detail })),
        ok: false,
        parentAfter: parentBefore,
        parentBefore,
        parentUntouched: true,
        results,
        stage: "baseline",
      };
    }
    for (const spec of MUTATIONS) {
      const copy = path.join(work, spec.ruleId);
      await copyTrackedRuntime(copy);
      const copyRules = path.join(copy, "src", "lib", "monitor", "rules.ts");
      const original = await fs.readFile(copyRules, "utf8");
      const hashBefore = sha256Text(original);
      let importError = null;
      let mismatchCaseIds = [];
      let mismatches = [];
      let otherCodes = [];
      try {
        const mutatedText = applyRuleMutation(original, spec.ruleId, spec.kind);
        await fs.writeFile(copyRules, mutatedText);
        const runtime = await loadRuntime(copy);
        const outcome = await runCorpus(corpusRoot, runtime);
        mismatches = outcome.failures.filter((failure) => failure.code === "result_mismatch");
        otherCodes = outcome.failures.filter((failure) => failure.code !== "result_mismatch").map((failure) => `${failure.id}:${failure.code}`);
        mismatchCaseIds = mismatches.map((failure) => failure.id);
      } catch (error) {
        importError = error.message;
      }
      const hashMutated = sha256Text(await fs.readFile(copyRules, "utf8"));
      const detected =
        importError === null &&
        otherCodes.length === 0 &&
        spec.mustMismatch.every((id) => mismatchCaseIds.includes(id)) &&
        hashMutated !== hashBefore;
      results.push({
        assertion: `isolated mutated engine reruns the corpus; ${spec.mustMismatch.join(",")} must result_mismatch. Import errors are not detections. Fixture command strings are not executed.`,
        copyRulesSha256Before: hashBefore,
        copyRulesSha256Mutated: hashMutated,
        detected,
        importError,
        kind: spec.kind,
        mismatchCaseIds,
        mismatches: mismatches.map((failure) => ({ detail: failure.detail, id: failure.id })),
        mustMismatch: spec.mustMismatch,
        otherCodes,
        ruleId: spec.ruleId,
      });
    }
  } finally {
    await fs.rm(work, { recursive: true, force: true });
  }
  const parentAfter = {
    corpus: await hashTree(corpusRoot),
    engine: sha256FileSync(await fs.readFile(enginePath)),
    rules: sha256FileSync(await fs.readFile(rulesPath)),
  };
  const parentUntouched =
    parentBefore.corpus === parentAfter.corpus &&
    parentBefore.engine === parentAfter.engine &&
    parentBefore.rules === parentAfter.rules;
  return {
    baselineFailureCount,
    baselineOk,
    corpus: corpusRoot,
    ok: baselineOk && parentUntouched && results.length === 5 && results.every((row) => row.detected),
    parentAfter,
    parentBefore,
    parentUntouched,
    results,
    stage: "mutants",
    workDeleted: true,
  };
}

function printResult(result) {
  const summary = {
    ok: result.ok,
    counts: result.counts,
    digest: result.digest,
    failureCount: result.failures.length,
    failures: result.failures.map((failure) => ({ id: failure.id, code: failure.code, detail: failure.detail.slice(0, 500) })),
  };
  process.stdout.write(`${stableStringify(summary)}`);
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];
  if (command === "run") {
    assertRunReadOnly(argv);
    const corpus = path.resolve(valueOf(argv, "--corpus"));
    const resultsPath = optionalValue(argv, "--results");
    const started = Date.now();
    const api = await loadRuntime();
    const result = await runCorpus(corpus, api);
    const finished = Date.now();
    printResult(result);
    if (resultsPath) {
      await fs.writeFile(
        resultsPath,
        stableStringify({
          startedUnixMs: started,
          finishedUnixMs: finished,
          elapsedMs: finished - started,
          seed: SEED,
          now: NOW,
          baselineSha: BASELINE_SHA,
          ok: result.ok,
          counts: result.counts,
          digest: result.digest,
          failures: result.failures,
          cases: result.cases,
        }),
      );
    }
    process.exitCode = result.ok ? 0 : 1;
    return;
  }
  if (command === "generate") {
    if (!argv.includes("--write-expected")) throw new Error("generate requires --write-expected");
    const corpus = assertExternalCorpus(path.resolve(valueOf(argv, "--corpus")));
    const mod = await import("./spec-run.generate.mjs");
    const out = await mod.generateCorpus(corpus);
    process.stdout.write(`${stableStringify({ ok: out.ok, counts: out.counts, digest: out.digest, failures: out.failures.length })}`);
    process.exitCode = out.ok ? 0 : 1;
    return;
  }
  if (command === "mutate") {
    const corpus = path.resolve(valueOf(argv, "--corpus"));
    const evidence = path.resolve(valueOf(argv, "--evidence"));
    const result = await mutateBuiltinRules(corpus);
    await fs.writeFile(evidence, stableStringify(result));
    process.stdout.write(`${stableStringify({ ok: result.ok, detected: result.results.map((row) => [row.ruleId, row.detected]) })}`);
    process.exitCode = result.ok ? 0 : 1;
    return;
  }
  if (command === "digest") {
    const corpus = path.resolve(valueOf(argv, "--corpus"));
    process.stdout.write(digestDocument(await expectedDigest(corpus)));
    return;
  }
  process.stderr.write("usage: spec-run.mjs run|generate|mutate|digest\n");
  process.exitCode = 2;
}

function valueOf(argv, flag) {
  const index = argv.indexOf(flag);
  if (index < 0 || !argv[index + 1]) throw new Error(`missing ${flag}`);
  return argv[index + 1];
}

function optionalValue(argv, flag) {
  const index = argv.indexOf(flag);
  if (index < 0) return null;
  return argv[index + 1] ?? null;
}

const entry = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entry && entry === path.resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
