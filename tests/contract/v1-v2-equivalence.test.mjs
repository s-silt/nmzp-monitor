import assert from "node:assert/strict";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import {
  canonicalToEvalInput,
  d8TrimObservations,
  toCanonicalDecision,
  toCanonicalToolEvent,
} from "../../core/protocol/v2-adapter.ts";
import { parseHookEvent, toolInputHasAliasConflict, toolInputToEvalFields } from "../../core/hook-protocol.ts";
import { loadRuntime, observe, projectResult, repoRoot } from "../../scripts/spec-run.mjs";
import { compileAll, createAjv, loadJson, loadSchemas } from "./protocol-checks.mjs";

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
    assert.equal(golden.cases.length, 65);
    const mismatches = [];
    const policy = { now: 1, overrides: { families: {}, rules: {} }, exemptions: [] };
    const context = { intervention: "enforcing", customRules: [] };
    for (const item of golden.cases) {
      const parsed = parseHookEvent(item.stdin);
      const v1Eval = parsed
        ? (() => {
            const fields = toolInputToEvalFields(parsed.toolName, parsed.toolInput);
            const evalInput = {
              nativeTool: fields.nativeTool,
              source: "hook",
              agent: item.host,
            };
            if (fields.command) evalInput.command = fields.command;
            if (fields.filePath) evalInput.filePath = fields.filePath;
            if (fields.url) evalInput.url = fields.url;
            if (fields.contents) evalInput.contents = fields.contents;
            if (fields.dest) evalInput.dest = fields.dest;
            if (fields.cwd) evalInput.cwd = fields.cwd;
            else if (parsed.cwd) evalInput.cwd = parsed.cwd;
            return projectResult(evaluate(evalInput, "enforcing", []));
          })()
        : null;
      const v2 = v2Project(item.stdin, item.host, api, policy, context);
      if (!parsed) {
        if (v2.parse !== "failure") mismatches.push({ id: item.id, v1: "parse_failure", v2: "ok" });
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
    assert.equal(sameV2.event.fields.contents.value, "SAFE");
    assert.equal(canonicalToEvalInput(sameV2.event).contents, "SAFE");
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
      const target = join(tmp, "core", "hook-protocol.ts");
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
      const target = join(tmp, "core", "hook-protocol.ts");
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
