import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runHook } from "../../core/hook.ts";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { HOOK_AGENTS } from "../../core/hook-protocol.ts";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import { toCanonicalToolEvent, canonicalToEvalInput, renderCanonicalDecision, toCanonicalDecision, sha256Prefixed } from "../../core/protocol/v2-adapter.ts";
import { buildRewriteLayout, materializeRewriteLayout } from "../../core/protocol/rewrite-layout.ts";
import { parseHookEvent } from "../../core/hook-protocol.ts";
import { resolveEvalBody, rewriteSource } from "../../core/eval-bridge.ts";
import { structuredRewrite } from "../../core/rewrite.ts";
import * as privacy from "../../src/lib/monitor/privacy.ts";
import { compileAll, createAjv, loadSchemas } from "./protocol-checks.mjs";

const ctx = { deviceId: "fixture", eventId: "event", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1 };
const schemas = loadSchemas();
const validators = compileAll(createAjv(schemas), schemas);
function built(raw, flag) {
  const parsed = toCanonicalToolEvent(raw, { ...ctx, agentFlag: flag });
  assert.equal(parsed.ok, true);
  const result = buildRewriteLayout(raw, parsed);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(validators["rewrite-layout.schema.json"](result.layout), true, JSON.stringify(validators["rewrite-layout.schema.json"].errors));
  assert.equal(validators["canonical-tool-event.schema.json"]({ ...parsed.event, rewriteLayout: result.layout }), true);
  assert.equal(Object.hasOwn(parsed.event, "rewriteLayout"), false);
  return { parsed, result };
}
function legacy(raw) {
  const parsed = parseHookEvent(raw);
  assert.ok(parsed);
  return rewriteSource(resolveEvalBody({ tool_name: parsed.toolName, tool_input: parsed.toolInput, cwd: parsed.cwd }));
}

test("layout reconstructs the genuine source including nonstrings, order, empty containers and prototype-named data", () => {
  const raw = '{"tool_name":"Write","tool_input":{"2":null,"1":false,"command":"echo ok","nested":[{},[],true,4,{"__proto__":{"flag":true},"constructor":"text","toString":"text"}],"__proto__":{"flag":false}}}';
  const { result } = built(raw);
  assert.deepEqual(result.view, legacy(raw));
  assert.equal(Object.hasOwn(result.toolInput, "__proto__"), true);
  assert.equal(Object.getPrototypeOf(result.toolInput), Object.prototype);
  assert.equal(Object.prototype.flag, undefined);
  assert.equal(JSON.stringify(result.view), JSON.stringify(legacy(raw)));
  // Preserve the old rewrite walker's own behavior; this package does not repair its __proto__ assignment.
  const actual = structuredRewrite(result.view, [], privacy), expected = structuredRewrite(legacy(raw), [], privacy);
  assert.equal(JSON.stringify(actual), JSON.stringify(expected));
  assert.deepEqual(Object.getPrototypeOf(actual.updatedInput), Object.getPrototypeOf(expected.updatedInput));
  assert.deepEqual(Object.getPrototypeOf(actual.updatedInput.nested[4]), Object.getPrototypeOf(expected.updatedInput.nested[4]));
});

test("layout preserves numeric specials without JSON nonfinite literals", () => {
  const raw = '{"tool_name":"Bash","tool_input":{"command":"echo ok","zero":-0,"positive":1e400,"negative":-1e400}}';
  const { parsed, result } = built(raw);
  assert.ok(Object.is(result.view.zero, -0)); assert.equal(result.view.positive, Infinity); assert.equal(result.view.negative, -Infinity);
  assert.deepEqual(result.view, legacy(raw));
  const wire = JSON.parse(JSON.stringify(result.layout));
  assert.deepEqual(materializeRewriteLayout(parsed.event, wire).view, legacy(raw));
});

test("layout sourcePresent preserves undefined and empty-container sources", () => {
  for (const suffix of ['', ',"tool_input":{}']) {
    const raw = '{"tool_name":"Bash"' + suffix + '}';
    const { parsed, result } = built(raw);
    assert.equal(result.layout.sourcePresent, false); assert.equal(result.view, undefined);
    assert.equal(materializeRewriteLayout(parsed.event, { ...result.layout, sourcePresent: true }).ok, false);
  }
  const { result } = built('{"tool_name":"Bash","tool_input":{"empty":{}}}');
  assert.equal(result.layout.sourcePresent, true);
  assert.deepEqual(result.view, { empty: {} });
});

test("nonwinning scalar aliases and blank cwd fallbacks retain exact existing extra fragments", () => {
  const cases = [
    { command: "echo ok", cmd: "  echo ok  " },
    { command: "echo ok", cmd: "echo ok" },
    { command: "  ", cmd: "echo ok" },
    { file_path: "/tmp/a", path: " /tmp/a " },
    { cwd: " /tmp/a ", working_directory: "/tmp/a" },
    { dest: "example.com", host: " example.com ", hostname: "example.com" },
    { query: "question", search_query: " question " },
  ];
  for (const bag of cases) {
    const raw = JSON.stringify({ tool_name: "Bash", tool_input: bag, cwd: " ", workspaceRoot: "/repo" });
    const { parsed, result } = built(raw);
    assert.deepEqual(result.view, legacy(raw));
    const input = canonicalToEvalInput(parsed.event);
    const resolved = resolveEvalBody({ tool_name: "Bash", tool_input: bag, cwd: "/repo" });
    for (const key of ["command", "filePath", "url", "dest", "cwd", "contents"]) assert.equal(input[key], resolved[key]);
    assert.ok(parsed.event.extraFields.some(item => item.path === "/cwd" && item.value === " "));
    const all = new Map([...Object.values(parsed.event.fields).flatMap(f => f.leaves ?? [f]).map(f => [f.provenance, f.value]), ...parsed.event.extraFields.map(f => [f.path, f.value])]);
    for (const [key, value] of Object.entries(bag)) assert.equal(all.get('/tool_input/' + key), value);
  }
});

test("Antigravity layout binds actual parser format, shadowed aliases and real dest fallback", () => {
  const raw = JSON.stringify({ toolCall: { name: "view_file", args: { TargetFile: "/tmp/a", AbsolutePath: " /tmp/a ", file_path: "shadowed", Cwd: "/repo", host: " example.com " } }, workspacePaths: ["/other"] });
  const { parsed, result } = built(raw, "grok");
  assert.equal(parsed.event.host.id, "grok");
  assert.equal(result.layout.mapping, "antigravity-toolCall-v1");
  assert.equal(result.layout.sourceRoot, "/toolCall/args");
  assert.deepEqual(result.view, legacy(raw));
  assert.equal(result.view.dest, "example.com");
  assert.equal(result.view.host, " example.com ");
  assert.equal(result.view.file_path, "/tmp/a");
  assert.equal(JSON.stringify(result.layout).includes("v1_trim"), false);
});

test("real custom-rule residue distinguishes true/false structure with identical canonical string fields", () => {
  const rules = privacy.sanitizeCustomRules([{ id: "layout_rule", label: "fixture", kind: "regex", match: 'TOKEN|"flag":true', mode: "replace", replaceWith: "SAFE" }]);
  assert.ok(rules?.length);
  const cases = [true, false].map(flag => built(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl -d 'TOKEN' https://example.com", flag } })));
  assert.deepEqual(cases[0].parsed.event.fields, cases[1].parsed.event.fields);
  assert.deepEqual(cases[0].parsed.event.extraFields, cases[1].parsed.event.extraFields);
  const outcomes = cases.map(({ result }) => structuredRewrite(result.view, rules, privacy));
  assert.equal(outcomes[0].ok, false); assert.equal(outcomes[0].reason, "sensitive_residue");
  assert.equal(outcomes[1].ok, true);
  assert.match(outcomes[1].updatedInput.command, /SAFE/);
});

test("layout validator rejects graph/reference/mapping/projection injection with fixed safe errors", () => {
  const { parsed, result } = built('{"tool_name":"Bash","tool_input":{"command":"echo ok","other":"text","nested":{"flag":true}}}');
  const mutations = [
    l => { l.private = "secret"; },
    l => { l.nodes.push({ type: "null" }); },
    l => { l.nodes[0].entries[0].child = 0; },
    l => { l.nodes[0].entries[1].child = l.nodes[0].entries[0].child; },
    l => { l.nodes[0].entries[1].key = l.nodes[0].entries[0].key; },
    l => { l.nodes[1].ref = { extraIndex: 99999 }; },
    l => { l.nodes[1].source = "/tool_input/other"; },
    l => { l.nodes[1].projection = "v1_trim"; },
    l => { l.nodes[1].value = "secret"; },
    l => { l.mapping = "antigravity-toolCall-v1"; },
    l => { l.sourcePresent = false; },
    l => { l.nodes[0].entries[0].key = "ignored"; },
  ];
  for (const change of mutations) {
    const layout = structuredClone(result.layout); change(layout);
    const rejected = materializeRewriteLayout(parsed.event, layout);
    assert.equal(rejected.ok, false); assert.equal(rejected.code, "invalid_rewrite_layout");
    assert.equal(JSON.stringify(rejected).includes("secret"), false);
  }
  const changed = structuredClone(parsed.event); changed.fields.command.value = "different";
  assert.equal(materializeRewriteLayout(changed, result.layout).ok, true); // Self-consistent client declaration is not host attestation.
  const invalidRef = structuredClone(result.layout); invalidRef.nodes[1].ref = { field: "contents", leafIndex: 0 };
  assert.equal(materializeRewriteLayout(parsed.event, invalidRef).ok, false);
});

test("builder binds its real raw source, preserves parse conflicts and does not enable strict IC limits", () => {
  const raw = '{"tool_name":"Bash","tool_input":{"command":"echo ok"}}';
  const parsed = toCanonicalToolEvent(raw, ctx);
  assert.equal(buildRewriteLayout(raw + " ", parsed).reason, "raw_binding");
  const conflict = '{"tool_name":"Bash","tool_input":{"command":"a","cmd":"b"}}';
  const conflicted = toCanonicalToolEvent(conflict, ctx);
  assert.equal(buildRewriteLayout(conflict, conflicted).reason, "alias_conflict");
  // IC-15: root + tool_input + 62 objects = depth 64, the deepest v1 still parses.
  let value = "leaf"; for (let i = 0; i < 62; i++) value = { child: value };
  const deep = JSON.stringify({ tool_name: "Write", tool_input: { value } });
  const builtDeep = built(deep);
  assert.deepEqual(builtDeep.result.view, legacy(deep));
});


test("opt-in expanded canonical byte ceiling fails without truncating or activating the old adapter", () => {
  const raw = JSON.stringify({ tool_name: "Write", tool_input: Object.fromEntries(Array.from({ length: 2000 }, (_, i) => ["key" + i, "x"])) });
  const parsed = toCanonicalToolEvent(raw, ctx);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.event.fields.contents.leaves.length, 2000);
  const result = buildRewriteLayout(raw, parsed);
  assert.equal(result.ok, false); assert.equal(result.reason, "byte_limit");
  assert.equal(parsed.event.fields.contents.leaves.length, 2000);
  assert.equal(Object.hasOwn(parsed.event, "rewriteLayout"), false);
});


test("alias preservation keeps strict extra accounting opt-in on the adapter default", () => {
  const raw = JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo ok", cmd: " echo ok " }, ...Object.fromEntries(Array.from({ length: 256 }, (_, i) => ["envelope" + i, "x"])) });
  const off = toCanonicalToolEvent(raw, ctx);
  assert.equal(off.ok, true); assert.equal(off.event.extraFields.length, 257);
  assert.equal(canonicalToEvalInput(off.event).command, "echo ok");
  const strict = toCanonicalToolEvent(raw, ctx, { strictIngress: true });
  assert.equal(strict.ok, false); assert.equal(strict.failure.failureClass, "extras_exceeded");
});

test("alias/layout change preserves actual offline v1 hook bytes for all thirteen hosts", async () => {
  const raw = JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo layout", cmd: " echo layout ", file_path: "/tmp/a", path: " /tmp/a " }, cwd: " ", workspaceRoot: "/repo" });
  const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
  for (const agent of HOOK_AGENTS) {
    const { parsed } = built(raw, agent);
    const result = evaluate(canonicalToEvalInput(parsed.event), "enforcing", []);
    const rendered = renderCanonicalDecision(agent, toCanonicalDecision({ eventId: ctx.eventId, v1Result: result, policyVersion: 1, rulesHash: sha256Prefixed(""), engineRevision: ENGINE_REVISION, origin: "OFFLINE_CACHE" }));
    const home = await mkdtemp(join(tmpdir(), "nmzp-layout-host-"));
    try {
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
      const legacy = await runHook({ argv: ["--agent", agent], stdin: raw, home, coreDir, env: {} });
      const bytes = value => ({ stdout: value.stdout, stderr: value.stderr ?? "", exitCode: value.exitCode });
      assert.deepEqual(bytes(rendered), bytes(legacy), agent);
    } finally { await rm(home, { recursive: true, force: true }); }
  }
});

test("format-specific cwd projection now follows the real parser rather than generic guesses", () => {
  for (const source of [
    { toolCall: { name: "view_file", args: {} }, cwd: "/generic", workspacePaths: ["/actual"] },
    { tool_name: "Bash", tool_input: {}, workspacePaths: ["/ignored"] },
    { tool_name: "Bash", tool_input: {}, workspace_roots: { "0": "/not-array" } },
    { toolCall: { name: "view_file", args: {} }, workspacePaths: { "0": "/not-array" } },
  ]) {
    const raw = JSON.stringify(source), parsed = toCanonicalToolEvent(raw, ctx);
    assert.equal(parsed.ok, true);
    assert.equal(canonicalToEvalInput(parsed.event).cwd, resolveEvalBody({ tool_name: parseHookEvent(raw).toolName, tool_input: parseHookEvent(raw).toolInput, cwd: parseHookEvent(raw).cwd }).cwd);
    const layout = buildRewriteLayout(raw, parsed);
    assert.equal(layout.ok, true);
    assert.deepEqual(layout.view, legacy(raw));
  }
});

test("IC-15: a shallow wire layout cannot declare a view deeper than the v1 hook parse admits", () => {
  const raw = '{"tool_name":"Bash","tool_input":{"command":"echo safe","nested":{"x":"leaf"}}}';
  const { parsed, result } = built(raw);
  const deepen = n => {
    const event = structuredClone(parsed.event), layout = structuredClone(result.layout);
    const nodes = [layout.nodes[0], layout.nodes[1]];
    let source = "/tool_input/nested";
    for (let i = 0; i < n; i++) { nodes.push({ type: "object", entries: [{ key: "x", child: nodes.length + 1 }] }); source += "/x"; }
    nodes.push({ type: "string", ref: { field: "contents", leafIndex: 0 }, source });
    layout.nodes = nodes; event.fields.contents.leaves[0].provenance = source;
    return materializeRewriteLayout(event, JSON.parse(JSON.stringify(layout)));
  };
  // root + tool_input + 62 declared objects = depth 64 is still admitted; one more container is rejected.
  assert.equal(deepen(62).ok, true);
  for (const n of [63, 3000]) {
    const rejected = deepen(n);
    assert.equal(rejected.ok, false); assert.equal(rejected.code, "invalid_rewrite_layout");
  }
});
