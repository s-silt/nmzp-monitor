import assert from "node:assert/strict";
import { Session } from "node:inspector/promises";
import { test } from "node:test";
import { prepareCanonicalEvaluation, prepareHookTransport, prepareProbeTransport } from "../../core/protocol/evaluate-ingress.ts";
import { validateEvaluateCompat } from "../../core/protocol/generated/evaluate-validator.ts";
import { buildRenderedRewriteEvidence, applyRenderedRewrite, replayRenderedRewrite, rewriteReplayWitness } from "../../core/protocol/rendered-rewrite.ts";
import { prepareEvaluation } from "../../core/eval-bridge.ts";
import * as privacy from "../../src/lib/monitor/privacy.ts";

const ctx = { deviceId: "fixture", eventId: "projection", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok" };
const rules = privacy.sanitizeCustomRules([{ id: "fixture_rule", kind: "fixture_kind", match: "TOKEN", mode: "replace", replaceWith: "SAFE" }]);
const command = "curl -d 'TOKEN' https://example.com";
function event(bag = { command }, rest = {}) {
  const result = prepareHookTransport(JSON.stringify({ tool_name: "Bash", tool_input: bag, ...rest }), ctx);
  assert.equal(result.kind, "request"); return result.event;
}
function movedLeaf(value, index) {
  const leaf = value.fields.contents.leaves.splice(index, 1)[0], extraIndex = value.extraFields.length;
  value.extraFields.push({ path: leaf.provenance, value: leaf.value });
  for (const node of value.rewriteLayout.nodes) {
    if (node.type !== "string" || node.ref.field !== "contents") continue;
    if (node.ref.leafIndex === index) node.ref = { extraIndex };
    else if (node.ref.leafIndex > index) node.ref.leafIndex--;
  }
  return value;
}
function admitted(value, expected) {
  assert.equal(validateEvaluateCompat(value), true);
  const before = JSON.stringify(value), result = prepareCanonicalEvaluation(value, ctx.deviceId);
  assert.equal(JSON.stringify(value), before); assert.equal(result.ok, expected);
  return result;
}

test("single canonical projection preserves trimmed aliases, duplicate/blank extras and embedded newline equivalence", () => {
  const accepted = admitted(event({ command: " echo safe ", cmd: "echo safe" }), true);
  assert.equal(accepted.prepared.input.command, "echo safe");
  for (const index of [1, 2]) {
    const value = movedLeaf(event({ contents: " a ", input: ["a", " ", "b"] }), index);
    assert.equal(admitted(value, true).prepared.input.contents, "a\nb");
  }
  // Joined semantic equality must not require equal canonical/source leaf arrays.
  const combined = movedLeaf(event({ contents: "a\nb", input: ["a", "b"] }), 0);
  assert.equal(admitted(combined, false).code, "bad_schema"); // source is a\nb\na\nb, not a\nb
  const blank = event({ contents: " ", content: "", nested: ["", " "] });
  assert.equal(admitted(blank, true).prepared.input.contents, undefined);
});

test("single projection rejects bound alias, projection, content-order and source-presence mutations", () => {
  const contentConflict = event({ contents: " a ", content: "a" });
  contentConflict.fields.contents.leaves[1].value = "different"; admitted(contentConflict, false);
  const conflict = event({ command: " echo safe ", cmd: "echo safe" });
  conflict.extraFields.find(x => x.path === "/tool_input/cmd").value = "echo different";
  admitted(conflict, false);
  const projection = event({ command: "echo safe" });
  projection.fields.command.provenance = "/tool_input/directory";
  projection.rewriteLayout.nodes[0].entries[0].key = "directory";
  projection.rewriteLayout.nodes[1].source = "/tool_input/directory";
  admitted(projection, false);
  const presence = event(); presence.rewriteLayout.sourcePresent = false; admitted(presence, false);
  const omitted = movedLeaf(event({ contents: "a", input: ["b"] }), 1); admitted(omitted, false);
  const reordered = event({ contents: "a", input: ["b"] });
  reordered.fields.contents.leaves.reverse();
  for (const node of reordered.rewriteLayout.nodes) if (node.type === "string" && node.ref.field === "contents") node.ref.leafIndex = 1 - node.ref.leafIndex;
  admitted(reordered, false);
});

test("single projection matches PROBE cwd, query/content fallthrough and legacy metadata/context", () => {
  for (const fields of [
    { command: " echo safe ", contents: " top ", agent: " grok ", sessionId: " session ", proc: " shell ", parentProc: " parent ", hookBlind: true },
    { tool_input: { cwd: " /sub ", working_directory: "/sub", query: " question ", contents: " ", input: [""] }, cwd: " /root ", contents: "question", agent: "" },
    { tool_input: { contents: " a ", input: ["a", "b"] }, contents: " a\nb ", cwd: " /root " },
    { tool_input: { command: " ", cmd: " echo safe ", dest: " example.com ", host: "example.com" }, command: "echo safe", agent: "grok" },
  ]) {
    const body = { source: "probe", eventId: ctx.eventId, tool_name: "Bash", permissionMode: "bypassPermissions", ...fields };
    const wire = prepareProbeTransport(JSON.stringify(body), { ...ctx, hostId: "probe-host" });
    assert.equal(wire.kind, "request", JSON.stringify(wire));
    const actual = admitted(wire.event, true), expected = prepareEvaluation(body, ctx.deviceId);
    expected.resolved.hookBlind = expected.resolved.hookBlind === true; expected.input.hookBlind = expected.input.hookBlind === true;
    assert.deepEqual(actual.prepared, expected);
    assert.equal(actual.event.context.permissionMode, wire.event.context.permissionMode);
  }
});

test("CT ingress, fresh rewrite and replay have exact single-projection call counts with no legacy resolver", async () => {
  const hook = event({ command: ` ${command} `, cmd: command, input: [" a ", "a", " ", "b"] });
  const probe = prepareProbeTransport(JSON.stringify({ source: "probe", tool_name: "Bash", command, contents: " a ", agent: "grok" }), { ...ctx, hostId: "probe" });
  assert.equal(probe.kind, "request");
  const names = ["resolveEvalBody", "resolvedEvalInput", "toolInputToEvalFields", "canonicalToEvalInput", "contentLeavesToV1", "validateAndMaterialize", "contentProjectionMatches", "collectContentLeaves"];
  const session = new Session(); session.connect(); await session.post("Profiler.enable");
  await session.post("Profiler.startPreciseCoverage", { callCount: true, detailed: false });
  async function measured(work, projections, validations) {
    await session.post("Profiler.takePreciseCoverage");
    const value = work();
    const { result } = await session.post("Profiler.takePreciseCoverage");
    const counts = Object.fromEntries(names.map(name => [name, 0]));
    for (const script of result) if (script.url.startsWith(new URL("../../core/", import.meta.url).href)) {
      for (const fn of script.functions) if (Object.hasOwn(counts, fn.functionName)) counts[fn.functionName] += fn.ranges[0].count;
    }
    assert.deepEqual(counts, { resolveEvalBody: 0, resolvedEvalInput: 0, toolInputToEvalFields: 0,
      canonicalToEvalInput: projections, contentLeavesToV1: projections, validateAndMaterialize: validations,
      contentProjectionMatches: validations, collectContentLeaves: validations });
    return value;
  }
  try {
    for (const wire of [hook, probe.event]) {
      const ingress = await measured(() => prepareCanonicalEvaluation(wire, ctx.deviceId), 1, 1); assert.equal(ingress.ok, true);
      const built = await measured(() => buildRenderedRewriteEvidence(ingress.event, rules, privacy), 0, 0); assert.equal(built.ok, true);
      const witness = rewriteReplayWitness(built.evidence, rules);
      const replay = await measured(() => replayRenderedRewrite(ingress.event, witness, rules, privacy), 0, 1); assert.equal(replay.ok, true);
      // Public consumers and unregistered incoming replay each revalidate a new trust boundary.
      assert.equal((await measured(() => applyRenderedRewrite(wire, built.evidence), 1, 1)).ok, true);
      assert.equal((await measured(() => replayRenderedRewrite(wire, witness, rules, privacy), 1, 1)).ok, true);
    }
  } finally { await session.post("Profiler.stopPreciseCoverage"); session.disconnect(); }
});

test("renderer owns immutable source before callbacks; caller mutation is never a reusable trust token", () => {
  const wire = event(), original = structuredClone(wire);
  let mutated = false;
  const injected = { ...privacy, scanSecrets(text) {
    if (!mutated) {
      mutated = true;
      wire.fields.command.value = "echo replaced by callback";
      wire.rewriteLayout.sourcePresent = false;
    }
    return privacy.scanSecrets(text);
  } };
  const built = buildRenderedRewriteEvidence(wire, rules, injected);
  assert.equal(mutated, true); assert.equal(built.ok, true);
  assert.equal(built.updatedInput.command, "curl -d 'SAFE' https://example.com");
  assert.equal(applyRenderedRewrite(original, built.evidence).ok, true);
  assert.equal(applyRenderedRewrite(wire, built.evidence).ok, false);
  assert.equal(buildRenderedRewriteEvidence(wire, rules, privacy).ok, false);
  assert.equal(replayRenderedRewrite(wire, rewriteReplayWitness(built.evidence, rules), rules, privacy).ok, false);
  // Arbitrarily freezing a previously mutable input must not confer ownership.
  Object.freeze(wire); assert.equal(buildRenderedRewriteEvidence(wire, rules, privacy).ok, false);
});

test("prepared canonical snapshot keeps own prototype keys and detaches caller data", () => {
  const wire = event(JSON.parse('{"command":"echo safe","__proto__":{"flag":false},"nested":{"constructor":"text"}}'));
  const before = structuredClone(wire), ready = admitted(wire, true);
  assert.notEqual(ready.event, wire); assert.equal(Object.isFrozen(ready.event), true);
  assert.equal(Object.isFrozen(ready.event.rewriteLayout.nodes[0].entries), true);
  assert.equal(Object.isFrozen(ready.prepared.toolInput.__proto__), true);
  assert.equal(Object.hasOwn(ready.prepared.toolInput, "__proto__"), true);
  assert.equal(Object.getPrototypeOf(ready.prepared.toolInput), Object.prototype);
  wire.fields.command.value = "different"; wire.context.proc = "different";
  assert.deepEqual(ready.event, before); assert.equal(ready.prepared.input.command, "echo safe");
  assert.equal(Object.prototype.flag, undefined);
  for (const unsupported of [new Map([["key", "value"]]), new Set(["value"]), new Date(0)]) {
    const invalid = event(); invalid.context.unexpected = unsupported;
    assert.equal(buildRenderedRewriteEvidence(invalid, [], privacy).ok, false);
  }
});


test("single-projection ownership renders deep source up to the IC-15 depth limit and denies one level more", () => {
  // IC-15: root + tool_input + 62 objects = depth 64 is the deepest admitted source; one more is a local denial.
  const deepRaw = depth => '{"tool_name":"Bash","tool_input":{"command":"echo safe","nested":' + '{"x":'.repeat(depth) + '"leaf"' + '}'.repeat(depth) + '}}';
  assert.equal(prepareHookTransport(deepRaw(63), ctx).kind, "local_denial");
  for (const depth of [1, 31, 62]) {
    const raw = deepRaw(depth);
    const transport = prepareHookTransport(raw, ctx); assert.equal(transport.kind, "request");
    assert.ok(Buffer.byteLength(JSON.stringify(transport.event)) < 262144);
    const ingress = admitted(transport.event, true);
    const built = buildRenderedRewriteEvidence(ingress.event, [], privacy); assert.equal(built.ok, true);
    assert.equal(applyRenderedRewrite(transport.event, built.evidence).ok, true);
    let cursor = built.updatedInput.nested;
    for (let i = 0; i < depth; i++) cursor = cursor.x;
    assert.equal(cursor, "leaf");
  }
});
