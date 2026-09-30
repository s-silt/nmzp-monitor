import assert from "node:assert/strict";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { pathToFileURL } from "node:url";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import {
  ADAPTER_BODY_LIMIT,
  canonicalToEvalInput,
  d8TrimObservations,
  toCanonicalDecision,
  toCanonicalToolEvent,
  toCanonicalToolEventFromBytes,
  V2_STRICT_INGRESS_DEFAULT,
} from "../../core/protocol/v2-adapter.ts";
import { parseHookEvent, toolInputHasAliasConflict, toolInputToEvalFields } from "../../core/hook-protocol.ts";
import { resolveGoldenStdin } from "../compat/golden-stdin.mjs";
import { loadRuntime, observe, projectResult, repoRoot } from "../../scripts/spec-run.mjs";
import { compileAll, createAjv, loadJson, loadSchemas } from "./protocol-checks.mjs";

import { createRealHookOracle } from "./real-hook-oracle.mjs";

const oracle = await createRealHookOracle();
after(() => oracle.close());
const root = repoRoot();
const HOST_NORM = join(root, "policy-spec", "host-normalization");
const GOLDEN = join(root, "tests", "compat", "fixtures", "hook-bytes-golden.json");

const CTX = {
  eventId: "evt-wp21a",
  occurredAt: "1970-01-01T00:00:00Z",
  deviceId: "UNOBSERVED_DEVICE",
  adapterRevision: 0,
};

async function collectHostCases(dir, acc = []) {
  const entries = await readdir(dir, { withFileTypes: true });
  const names = new Set(entries.map((entry) => entry.name));
  if (names.has("input.json") && names.has("expected.json") && names.has("context.json") && names.has("policy.json")) {
    acc.push(dir);
  }
  for (const entry of entries) {
    if (entry.isDirectory()) await collectHostCases(join(dir, entry.name), acc);
  }
  return acc;
}

function loadBundle(caseDir) {
  return {
    input: loadJson(join(caseDir, "input.json")),
    policy: loadJson(join(caseDir, "policy.json")),
    context: loadJson(join(caseDir, "context.json")),
    expected: loadJson(join(caseDir, "expected.json")),
  };
}

function v2Project(raw, agentFlag, api, policy, context) {
  const parsed = api.parseHookEvent(raw);
  const result = toCanonicalToolEvent(raw, { ...CTX, agentFlag, eventId: parsed?.eventId || CTX.eventId });
  if (!result.ok) return { parse: "failure", failure: result.failure };
  if (result.aliasConflict) {
    return {
      parse: "ok",
      event: result.event,
      compare: {
        action: "block",
        actor: "process",
        decision: "block",
        dryRunKinds: null,
        exemptionId: null,
        overrideSource: null,
        rewritten: false,
        risk: "high",
        ruleId: null,
        secretKinds: [],
        skipped: false,
        threat: null,
        tool: "Bash",
      },
      aliasConflict: true,
      observations: d8TrimObservations(result.event),
    };
  }
  const evalInput = canonicalToEvalInput(result.event);
  const evaluated = api.evaluate(evalInput, context.intervention, context.customRules, {
    now: policy.now,
    overrides: policy.overrides,
    exemptions: policy.exemptions,
  });
  return {
    parse: "ok",
    event: result.event,
    compare: projectResult(evaluated),
    evalInput,
    observations: d8TrimObservations(result.event),
  };
}

describe("v1/v2 decision equivalence", () => {
  const schemas = loadSchemas();
  const validators = compileAll(createAjv(schemas), schemas);
  const eventValidate = validators["canonical-tool-event.schema.json"];

  test("host-normalization cases match projectResult", async () => {
    const api = await loadRuntime(root);
    const cases = await collectHostCases(HOST_NORM);
    assert.ok(cases.length >= 19, `expected host-normalization cases, got ${cases.length}`);
    const mismatches = [];
    const observations = [];
    for (const caseDir of cases) {
      const rel = caseDir.slice(HOST_NORM.length + 1).split("\\").join("/");
      const bundle = loadBundle(caseDir);
      const v1 = observe(bundle, api);
      const v2 = v2Project(bundle.input.raw, bundle.input.agentFlag, api, bundle.policy, bundle.context);
      if (!v1.ok) {
        if (v2.parse !== "failure") mismatches.push({ id: rel, v1: v1.code, v2: "ok" });
        continue;
      }
      if (v2.parse !== "ok") {
        mismatches.push({ id: rel, v1: v1.observed.compare, v2: v2.failure });
        continue;
      }
      if (!eventValidate(v2.event)) {
        mismatches.push({ id: rel, schema: eventValidate.errors });
        continue;
      }
      try {
        assert.deepEqual(v2.compare, v1.observed.compare);
      } catch {
        mismatches.push({ id: rel, v1: v1.observed.compare, v2: v2.compare });
      }
      if (v2.observations?.length) observations.push({ id: rel, observations: v2.observations });
    }
    assert.deepEqual(mismatches, []);
    globalThis.__nmzpD8Observations = observations;
  });

  test("hook-bytes-golden stdin matches projectResult", async () => {
    const api = await loadRuntime(root);
    const golden = loadJson(GOLDEN);
    assert.equal(golden.cases.length, 104);
    const mismatches = [];
    const policy = { now: 1, overrides: { families: {}, rules: {} }, exemptions: [] };
    const context = { intervention: "enforcing", customRules: [] };
    for (const item of golden.cases) {
      const stdin = resolveGoldenStdin(item);
      const parsed = parseHookEvent(stdin);
      const realV1 = await oracle.run(stdin, item.host);
      const v1Eval = realV1.evaluated ? projectResult(realV1.result) : null;
      const v2 = v2Project(stdin, item.host, api, policy, context);
      if (!parsed) {
        if (item.kind === "alias-conflict") {
          if (v2.parse !== "ok" || v2.aliasConflict !== true) {
            mismatches.push({ id: item.id, v1: "parse_failure", v2 });
          }
        } else if (v2.parse !== "failure") {
          mismatches.push({ id: item.id, v1: "parse_failure", v2: "ok" });
        }
        continue;
      }
      if (v2.parse !== "ok") {
        mismatches.push({ id: item.id, v1: v1Eval, v2: v2.failure });
        continue;
      }
      if (!eventValidate(v2.event)) {
        mismatches.push({ id: item.id, schema: eventValidate.errors });
        continue;
      }
      try {
        assert.deepEqual(v2.compare, v1Eval);
      } catch {
        mismatches.push({ id: item.id, v1: v1Eval, v2: v2.compare });
      }
    }
    assert.deepEqual(mismatches, []);
  });

  test("alias conflict is BLOCK conflicting_aliases on both paths", () => {
    const raw = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "echo a", cmd: "echo b" },
      session_id: "sess-alias",
      eventId: "evt-alias",
    });
    const parsed = parseHookEvent(raw);
    const body = JSON.parse(raw);
    const v1Conflict = parsed === null && toolInputHasAliasConflict(body.tool_input);
    assert.equal(v1Conflict, true);
    const v2 = toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-alias" });
    assert.equal(v2.ok, true);
    assert.equal(v2.aliasConflict, true);
    assert.equal(eventValidate(v2.event), true, JSON.stringify(eventValidate.errors));
  });

  test("Antigravity TargetFile vs AbsolutePath disagreement is conflicting_aliases on v2 and a v1 parse failure", () => {
    const view = (args) => JSON.stringify({ toolCall: { name: "view_file", args }, stepIdx: 7, conversationId: "adv-1" });
    const ctx = { ...CTX, agentFlag: "antigravity", eventId: "evt-agy" };
    const bad = view({ TargetFile: "C:/repo/README.md", AbsolutePath: "C:/Users/u/.ssh/id_rsa" });
    assert.equal(parseHookEvent(bad), null);
    const v2 = toCanonicalToolEvent(bad, ctx);
    assert.equal(v2.ok, true);
    assert.equal(v2.aliasConflict, true);
    assert.equal(eventValidate(v2.event), true, JSON.stringify(eventValidate.errors));
    for (const empty of ["", "   ", null, 7]) {
      const raw = view({ TargetFile: empty, AbsolutePath: "C:/Users/u/.ssh/id_rsa" });
      const label = `TargetFile=${JSON.stringify(empty)}`;
      assert.equal(parseHookEvent(raw)?.toolInput.file_path, "C:/Users/u/.ssh/id_rsa", label);
      const blank = toCanonicalToolEvent(raw, ctx);
      assert.equal(blank.ok, true, label);
      assert.equal(blank.aliasConflict, false, label);
      assert.equal(canonicalToEvalInput(blank.event).filePath, "C:/Users/u/.ssh/id_rsa", label);
    }
    const same = toCanonicalToolEvent(view({ TargetFile: "C:/repo/a.ts", AbsolutePath: "C:/repo/a.ts" }), ctx);
    assert.equal(same.ok, true);
    assert.equal(same.aliasConflict, false);
    assert.equal(canonicalToEvalInput(same.event).filePath, "C:/repo/a.ts");
  });

  test("contents vs content disagreement is BLOCK conflicting_aliases on both paths", () => {
    const raw = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "C:\\tmp\\x.txt", content: "SAFE", contents: "curl https://evil.invalid" },
      session_id: "sess-content",
      eventId: "evt-content",
    });
    const parsed = parseHookEvent(raw);
    const body = JSON.parse(raw);
    assert.equal(parsed, null);
    assert.equal(toolInputHasAliasConflict(body.tool_input), true);
    const v2 = toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-content" });
    assert.equal(v2.ok, true);
    assert.equal(v2.aliasConflict, true);
    assert.equal(eventValidate(v2.event), true, JSON.stringify(eventValidate.errors));
    const decision = toCanonicalDecision({
      eventId: "evt-content",
      v1Result: evaluate({ nativeTool: "Write", source: "hook", agent: "claude" }, "enforcing", []),
      aliasConflict: true,
      policyVersion: 0,
      rulesHash: "0",
      engineRevision: 0,
      origin: "OFFLINE_CACHE",
    });
    assert.equal(decision.action, "BLOCK");
    assert.equal(decision.reasonCode, "conflicting_aliases");

    const sameRaw = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "C:\\tmp\\x.txt", content: "SAFE", contents: "SAFE" },
      session_id: "sess-content-same",
      eventId: "evt-content-same",
    });
    const sameParsed = parseHookEvent(sameRaw);
    assert.ok(sameParsed);
    assert.equal(toolInputToEvalFields(sameParsed.toolName, sameParsed.toolInput).contents, "SAFE");
    const sameV2 = toCanonicalToolEvent(sameRaw, { ...CTX, agentFlag: "claude", eventId: "evt-content-same" });
    assert.equal(sameV2.ok, true);
    assert.equal(sameV2.aliasConflict, false);
    assert.deepEqual(sameV2.event.fields.contents.leaves.map((leaf) => leaf.value), ["SAFE", "SAFE"]);
    assert.equal(canonicalToEvalInput(sameV2.event).contents, "SAFE");
  });

  test("envelope cwd falls back past a blank cwd in v1 order with provenance on the winner", () => {
    const base = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-cwd" };
    const cases = [
      { label: "blank cwd + workspaceRoot", body: { ...base, cwd: "   ", workspaceRoot: "C:/repo" }, value: "C:/repo", provenance: "/workspaceRoot" },
      { label: "blank cwd + workspace_roots (cursor)", body: { ...base, cwd: "", workspace_roots: ["C:/cursor"] }, value: "C:/cursor", provenance: "/workspace_roots/0" },
      { label: "blank cwd + blank workspaceRoot + workspace_roots", body: { ...base, cwd: " ", workspaceRoot: "", workspace_roots: ["C:/w"] }, value: "C:/w", provenance: "/workspace_roots/0" },
      { label: "non-blank cwd wins", body: { ...base, cwd: "C:/cwd", workspaceRoot: "C:/repo" }, value: "C:/cwd", provenance: "/cwd" },
    ];
    for (const item of cases) {
      const raw = JSON.stringify(item.body);
      const v1 = parseHookEvent(raw);
      assert.equal(v1?.cwd, item.value, `${item.label} v1`);
      const v2 = toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-cwd" });
      assert.equal(v2.ok, true, item.label);
      assert.deepEqual(v2.event.fields.cwd, { value: item.value, provenance: item.provenance }, item.label);
      assert.equal(canonicalToEvalInput(v2.event).cwd, v1.cwd, `${item.label} bridge`);
      assert.equal(eventValidate(v2.event), true, JSON.stringify(eventValidate.errors));
    }
  });

  test("D8 exact vs trim observations are recorded and do not change decisions", () => {
    const raw = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "  echo padded  " },
      session_id: "sess-d8",
      eventId: "evt-d8",
    });
    const v1Parsed = parseHookEvent(raw);
    const v1Fields = toolInputToEvalFields(v1Parsed.toolName, v1Parsed.toolInput);
    const v2 = toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-d8" });
    assert.equal(v2.ok, true);
    assert.equal(v2.event.fields.command.value, "  echo padded  ");
    const evalInput = canonicalToEvalInput(v2.event);
    assert.equal(evalInput.command, v1Fields.command);
    assert.equal(evalInput.command, "echo padded");
    const observations = d8TrimObservations(v2.event);
    assert.equal(observations.length >= 1, true);
    assert.equal(observations[0].exact, "  echo padded  ");
    assert.equal(observations[0].trimmed, "echo padded");
    const v1Compare = projectResult(evaluate({ nativeTool: "Bash", command: v1Fields.command, source: "hook", agent: "claude" }, "enforcing", []));
    const v2Compare = projectResult(evaluate(evalInput, "enforcing", []));
    assert.deepEqual(v2Compare, v1Compare);
  });

  test("mutation: toolInputHasAliasConflict always false is killed", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "nmzp-wp21a-mut-"));
    try {
      await cp(join(root, "core"), join(tmp, "core"), { recursive: true });
      await cp(join(root, "src", "lib", "monitor"), join(tmp, "src", "lib", "monitor"), { recursive: true });
      const target = join(tmp, "core", "hook-alias-keys.ts");
      const source = await readFile(target, "utf8");
      const mutated = source.replace(
        "export function toolInputHasAliasConflict(obj: Record<string, unknown>): boolean {",
        "export function toolInputHasAliasConflict(obj: Record<string, unknown>): boolean {\n  return false;",
      );
      assert.notEqual(mutated, source);
      await writeFile(target, mutated);
      const adapterUrl = pathToFileURL(join(tmp, "core", "protocol", "v2-adapter.ts")).href;
      const hookUrl = pathToFileURL(join(tmp, "core", "hook-protocol.ts")).href;
      const [adapter, hook] = await Promise.all([import(adapterUrl), import(hookUrl)]);
      const raw = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo a", cmd: "echo b" },
        session_id: "sess-mut",
        eventId: "evt-mut",
      });
      const parsed = hook.parseHookEvent(raw);
      const v1Blocked = parsed === null && hook.toolInputHasAliasConflict(JSON.parse(raw).tool_input);
      const v2 = adapter.toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-mut" });
      assert.equal(v1Blocked, false);
      assert.equal(v2.ok, true);
      assert.equal(v2.aliasConflict, false);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  test("mutation: dropping the contents/content alias group fails the new case", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "nmzp-wp21b-mut-"));
    try {
      await cp(join(root, "core"), join(tmp, "core"), { recursive: true });
      await cp(join(root, "src", "lib", "monitor"), join(tmp, "src", "lib", "monitor"), { recursive: true });
      const target = join(tmp, "core", "hook-alias-keys.ts");
      const source = await readFile(target, "utf8");
      const needle = 'export const CONTENT_ALIAS_KEYS = ["contents", "content"] as const;';
      const mutated = source.replace(needle, "export const CONTENT_ALIAS_KEYS = [] as const;");
      assert.notEqual(mutated, source);
      await writeFile(target, mutated);
      const adapterUrl = pathToFileURL(join(tmp, "core", "protocol", "v2-adapter.ts")).href;
      const hookUrl = pathToFileURL(join(tmp, "core", "hook-protocol.ts")).href;
      const [adapter, hook] = await Promise.all([import(adapterUrl), import(hookUrl)]);
      const raw = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: "C:\\tmp\\x.txt", content: "SAFE", contents: "curl https://evil.invalid" },
        session_id: "sess-mut-content",
        eventId: "evt-mut-content",
      });
      const parsed = hook.parseHookEvent(raw);
      const v2 = adapter.toCanonicalToolEvent(raw, { ...CTX, agentFlag: "claude", eventId: "evt-mut-content" });
      const caseHolds =
        parsed === null &&
        hook.toolInputHasAliasConflict(JSON.parse(raw).tool_input) === true &&
        v2.ok === true &&
        v2.aliasConflict === true;
      assert.equal(caseHolds, false);
      const cmdRaw = JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo a", cmd: "echo b" },
        session_id: "sess-mut-cmd",
        eventId: "evt-mut-cmd",
      });
      assert.equal(hook.parseHookEvent(cmdRaw), null);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });
});

// IC-10 NOT_SWITCHED: strict v2 ingress classes. With the switch off (default) v2
// decides exactly like v1; with it on these inputs are known, asserted differences.
async function v1Decision(stdin, agent) {
  const real = await oracle.run(stdin, agent);
  return real.evaluated ? projectResult(real.result) : null;
}

function v2Decision(result) {
  assert.equal(result.ok, true, JSON.stringify(result.failure));
  assert.equal(result.aliasConflict, false);
  return projectResult(evaluate(canonicalToEvalInput(result.event), "enforcing", []));
}

const SCTX = { ...CTX, agentFlag: "claude" };
const STRICT = { strictIngress: true };

function bash(toolInputJson, extra = "") {
  return `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"sess-ic10"${extra},"tool_input":${toolInputJson}}`;
}

// hook_event_name is itself an unmapped extra, so topExtras(n) yields n + 1 extraFields.
function topExtras(count, value = "v") {
  let out = "";
  for (let i = 0; i < count; i += 1) out += `,"x${i}":"${value}"`;
  return out;
}

function nested(depth) {
  return `${"[".repeat(depth)}${"]".repeat(depth)}`;
}

const DUP = "duplicate_member";
const KNOWN_DIFFERENCES = [
  {
    id: "duplicate top-level member",
    raw: `{"tool_name":"Bash","tool_name":"Bash","tool_input":{"command":"ls"}}`,
    failureClass: DUP,
    detail: { decodedKey: "tool_name" },
  },
  { id: "duplicate nested member (v1 last wins)", raw: bash(`{"command":"ls","command":"rm -rf /"}`), failureClass: DUP, detail: { decodedKey: "command" } },
  { id: "duplicate member inside array object", raw: bash(`{"command":"ls","edits":[{"a":"1","a":"2"}]}`), failureClass: DUP, detail: { decodedKey: "a" } },
  { id: "duplicate after escape decoding", raw: bash(`{"command":"ls","\\u0063ommand":"rm -rf /"}`), failureClass: DUP, detail: { decodedKey: "command" } },
  {
    id: "lone high surrogate in value",
    raw: bash(`{"command":"echo \\ud800"}`),
    failureClass: "unpaired_surrogate",
    detail: { where: "value", surrogate: "lone_high" },
  },
  {
    id: "lone low surrogate in member name",
    raw: bash(`{"command":"ls","\\udc00":"x"}`),
    failureClass: "unpaired_surrogate",
    detail: { where: "member_name", surrogate: "lone_low" },
  },
  { id: "container depth 65", raw: bash(`{"command":"ls"}`, `,"deep":${nested(64)}`), failureClass: "depth_exceeded", detail: { containerDepth: 65 } },
  { id: "257 extra fields", raw: bash(`{"command":"ls"}`, topExtras(256)), failureClass: "extras_exceeded", detail: { extraCount: 257 } },
  { id: "1025-byte pointer", raw: bash(`{"command":"ls"}`, `,"${"k".repeat(1024)}":"v"`), failureClass: "pointer_too_long", detail: { pointerUtf8: 1025 } },
  { id: "129-unit eventId", raw: bash(`{"command":"ls"}`, `,"event_id":"${"e".repeat(129)}"`), failureClass: "event_id_invalid", detail: {} },
  { id: "C0 control in eventId", raw: bash(`{"command":"ls"}`, `,"event_id":"evt\\u0001"`), failureClass: "event_id_invalid", detail: {} },
];

const STRICT_BOUNDARY_OK = [
  { id: "container depth 64", raw: bash(`{"command":"ls"}`, `,"deep":${nested(63)}`) },
  { id: "256 extra fields", raw: bash(`{"command":"ls"}`, topExtras(255)) },
  { id: "1024-byte pointer", raw: bash(`{"command":"ls"}`, `,"${"k".repeat(1023)}":"v"`) },
  { id: "128-unit eventId", raw: bash(`{"command":"ls"}`, `,"event_id":"${"e".repeat(128)}"`) },
  { id: "surrogate pair", raw: bash(`{"command":"echo \\ud83d\\ude00"}`) },
  { id: "same key in sibling objects", raw: bash(`{"command":"ls","edits":[{"a":"1"},{"a":"2"}]}`) },
];

function canonicalOverLimitRaw() {
  // Each extra "xN":"v" grows to {"path":"/xN","value":"v"} in the event; pad the command so
  // the raw body stays under the ceiling while the serialized event exceeds it.
  const extras = topExtras(250);
  const pad = ADAPTER_BODY_LIMIT - Buffer.byteLength(bash(`{"command":"ls","note":""}`, extras)) - 16;
  return bash(`{"command":"ls","note":"${"a".repeat(pad)}"}`, extras);
}

describe("IC-10 strict v2 ingress (NOT_SWITCHED)", () => {
  test("switch defaults off", () => {
    assert.equal(V2_STRICT_INGRESS_DEFAULT, false);
  });

  for (const item of KNOWN_DIFFERENCES) {
    test(`known difference: ${item.id}`, async () => {
      const v1 = await v1Decision(item.raw, "claude");
      assert.notEqual(v1, null, "v1 must evaluate this input");
      assert.deepEqual(v2Decision(toCanonicalToolEvent(item.raw, SCTX)), v1);
      assert.deepEqual(v2Decision(toCanonicalToolEvent(item.raw, SCTX, { strictIngress: false })), v1);
      const strict = toCanonicalToolEvent(item.raw, SCTX, STRICT);
      assert.equal(strict.ok, false);
      assert.equal(strict.failure.failureClass, item.failureClass);
      for (const [key, value] of Object.entries(item.detail)) assert.equal(strict.failure[key], value, key);
    });
  }

  for (const item of STRICT_BOUNDARY_OK) {
    test(`strict boundary accepts: ${item.id}`, async () => {
      const v1 = await v1Decision(item.raw, "claude");
      assert.deepEqual(v2Decision(toCanonicalToolEvent(item.raw, SCTX, STRICT)), v1);
      assert.deepEqual(v2Decision(toCanonicalToolEvent(item.raw, SCTX)), v1);
    });
  }

  test("known difference: canonical_over_limit with raw under the ceiling", async () => {
    const raw = canonicalOverLimitRaw();
    assert.ok(Buffer.byteLength(raw) <= ADAPTER_BODY_LIMIT);
    const off = toCanonicalToolEvent(raw, SCTX);
    assert.ok(Buffer.byteLength(JSON.stringify(off.event)) > ADAPTER_BODY_LIMIT);
    assert.deepEqual(v2Decision(off), await v1Decision(raw, "claude"));
    const strict = toCanonicalToolEvent(raw, SCTX, STRICT);
    assert.equal(strict.ok, false);
    assert.equal(strict.failure.failureClass, "canonical_over_limit");
    assert.equal(strict.failure.channel, "canonical_request");
  });

  test("known difference: invalid UTF-8 needs the raw-byte entry", async () => {
    const head = Buffer.from(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/`);
    const bytes = Buffer.concat([head, Buffer.from([0xff, 0xc3]), Buffer.from(`"}}`)]);
    const v1 = await v1Decision(bytes.toString("utf8"), "claude");
    assert.notEqual(v1, null);
    const off = toCanonicalToolEventFromBytes(bytes, SCTX);
    assert.deepEqual(v2Decision(off), v1);
    assert.equal(off.event.rawPayloadHash, `sha256:${createHash("sha256").update(bytes).digest("hex")}`);
    const strict = toCanonicalToolEventFromBytes(bytes, SCTX, STRICT);
    assert.equal(strict.ok, false);
    assert.equal(strict.failure.failureClass, "invalid_utf8");
  });

  test("raw-byte ceiling counts bytes like v1 readStdin/readLimited", async () => {
    const head = Buffer.from(`{"tool_name":"Bash","tool_input":{"command":"ls","note":"`);
    const tail = Buffer.from(`"}}`);
    const body = (size, fill) => Buffer.concat([head, Buffer.alloc(size - head.length - tail.length, fill), tail]);
    for (const size of [ADAPTER_BODY_LIMIT - 1, ADAPTER_BODY_LIMIT]) {
      const bytes = body(size, 0x61);
      assert.equal(toCanonicalToolEventFromBytes(bytes, SCTX).ok, true, String(size));
      assert.equal(toCanonicalToolEvent(bytes.toString("utf8"), SCTX).ok, true, String(size));
    }
    const over = body(ADAPTER_BODY_LIMIT + 1, 0x61);
    for (const opts of [{}, STRICT]) {
      assert.equal(toCanonicalToolEventFromBytes(over, SCTX, opts).failure.failureClass, "over_limit");
      assert.equal(toCanonicalToolEvent(over.toString("utf8"), SCTX, opts).failure.failureClass, "over_limit");
    }
    // Near-limit invalid UTF-8: each 0xff decodes to U+FFFD (3 bytes). The bytes entry accepts
    // like v1 hookMain; the string entry over-counts the decoded text and rejects.
    const invalid = body(ADAPTER_BODY_LIMIT, 0xff);
    assert.deepEqual(v2Decision(toCanonicalToolEventFromBytes(invalid, SCTX)), await v1Decision(invalid.toString("utf8"), "claude"));
    assert.equal(toCanonicalToolEvent(invalid.toString("utf8"), SCTX).failure.failureClass, "over_limit");
  });

  test("switch off: depth far beyond 64 evaluates like v1 without stack overflow", async () => {
    const raw = bash(`{"command":"rm -rf /tmp/deep"}`, `,"deep":${"[".repeat(100000)}"s"${"]".repeat(100000)}`);
    const off = toCanonicalToolEvent(raw, SCTX);
    assert.deepEqual(v2Decision(off), await v1Decision(raw, "claude"));
    assert.equal(off.event.extraFields.at(-1).path, `/deep${"/0".repeat(100000)}`);
    assert.equal(toCanonicalToolEvent(raw, SCTX, STRICT).failure.failureClass, "depth_exceeded");
  });

  test("strict ingress keeps v2 decisions on every golden and host-normalization input", async () => {
    const golden = loadJson(GOLDEN);
    const inputs = golden.cases.map((item) => ({ id: item.id, raw: resolveGoldenStdin(item), agentFlag: item.host }));
    for (const caseDir of await collectHostCases(HOST_NORM)) {
      const bundle = loadBundle(caseDir);
      inputs.push({ id: caseDir, raw: bundle.input.raw, agentFlag: bundle.input.agentFlag });
    }
    const mismatches = [];
    for (const item of inputs) {
      const ctx = { ...CTX, agentFlag: item.agentFlag };
      const off = toCanonicalToolEvent(item.raw, ctx);
      const on = toCanonicalToolEvent(item.raw, ctx, STRICT);
      if (off.ok !== on.ok) mismatches.push({ id: item.id, on: on.failure });
      else if (off.ok && off.aliasConflict !== on.aliasConflict) mismatches.push({ id: item.id, aliasConflict: on.aliasConflict });
      else if (off.ok) {
        try {
          assert.deepEqual({ ...on.event, eventId: null }, { ...off.event, eventId: null });
        } catch {
          mismatches.push({ id: item.id, event: "differs" });
        }
      } else if (off.failure.failureClass !== on.failure.failureClass) mismatches.push({ id: item.id, off: off.failure, on: on.failure });
    }
    assert.ok(inputs.length >= 123);
    assert.deepEqual(mismatches, []);
  });

  const MUTATIONS = [
    {
      id: "duplicate check removed",
      needle: `    if (frame.keys.has(key)) return adapterFailure("duplicate_member", { decodedKey: key });`,
      expect: "duplicate_member",
      raw: bash(`{"command":"ls","command":"rm -rf /"}`),
    },
    {
      id: "depth limit off by one",
      needle: "export const MAX_CONTAINER_DEPTH = 64;",
      replacement: "export const MAX_CONTAINER_DEPTH = 65;",
      expect: "depth_exceeded",
      raw: bash(`{"command":"ls"}`, `,"deep":${nested(64)}`),
    },
    {
      id: "strict flag ignored by the bytes entry",
      needle: "      text = STRICT_UTF8.decode(raw);",
      replacement: "      text = Buffer.from(raw).toString(\"utf8\");",
      expect: "invalid_utf8",
      bytes: Buffer.concat([Buffer.from(`{"tool_name":"Bash","tool_input":{"command":"ls `), Buffer.from([0xff]), Buffer.from(`"}}`)]),
    },
  ];

  for (const mutation of MUTATIONS) {
    test(`mutation: ${mutation.id} is killed`, async () => {
      const tmp = await mkdtemp(join(tmpdir(), "nmzp-ic10-mut-"));
      try {
        await cp(join(root, "core"), join(tmp, "core"), { recursive: true });
        await cp(join(root, "src", "lib", "monitor"), join(tmp, "src", "lib", "monitor"), { recursive: true });
        const target = join(tmp, "core", "protocol", "v2-adapter.ts");
        const source = await readFile(target, "utf8");
        const mutated = source.replace(mutation.needle, mutation.replacement ?? "");
        assert.notEqual(mutated, source);
        await writeFile(target, mutated);
        const adapter = await import(pathToFileURL(target).href);
        const result = mutation.bytes
          ? adapter.toCanonicalToolEventFromBytes(mutation.bytes, SCTX, STRICT)
          : adapter.toCanonicalToolEvent(mutation.raw, SCTX, STRICT);
        assert.equal(result.ok === false && result.failure.failureClass === mutation.expect, false);
      } finally {
        await rm(tmp, { recursive: true, force: true });
      }
    });
  }
});
