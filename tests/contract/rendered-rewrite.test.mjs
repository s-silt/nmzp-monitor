import assert from "node:assert/strict";
import { test } from "node:test";
import { toCanonicalToolEvent } from "../../core/protocol/v2-adapter.ts";
import { buildRewriteLayout, materializeRewriteLayout } from "../../core/protocol/rewrite-layout.ts";
import { buildRenderedRewriteEvidence, applyRenderedRewrite, replayRenderedRewrite, rewriteReplayWitness } from "../../core/protocol/rendered-rewrite.ts";
import { structuredRewrite } from "../../core/rewrite.ts";
import { compileAll, createAjv, loadSchemas } from "./protocol-checks.mjs";
import * as privacy from "../../src/lib/monitor/privacy.ts";

const schemas = loadSchemas();
const validators = compileAll(createAjv(schemas), schemas);
const ctx = { deviceId: "fixture", eventId: "d5", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1 };
const rules = match => privacy.sanitizeCustomRules([{ id: "fixture_rule", kind: "fixture_kind", match, mode: "replace", replaceWith: "SAFE" }]);
function eventFor(bag, outer = {}) {
  const raw = JSON.stringify({ tool_name: "Bash", tool_input: bag, ...outer });
  const parsed = toCanonicalToolEvent(raw, ctx); assert.equal(parsed.ok, true);
  const layout = buildRewriteLayout(raw, parsed); assert.equal(layout.ok, true, JSON.stringify(layout));
  return { ...parsed.event, rewriteLayout: layout.layout };
}
function verified(event, custom = rules("TOKEN"), p = privacy) {
  const original = materializeRewriteLayout(event); assert.equal(original.ok, true);
  const plain = structuredRewrite(original.view, custom, p);
  const result = buildRenderedRewriteEvidence(event, custom, p);
  assert.equal(result.ok, plain.ok, JSON.stringify(result));
  if (!result.ok) { assert.equal(result.reason, plain.reason); return result; }
  assert.deepEqual(result.updatedInput, plain.updatedInput);
  const applied = applyRenderedRewrite(event, result.evidence); assert.equal(applied.ok, true, JSON.stringify(applied));
  assert.deepEqual(applied.updatedInput, plain.updatedInput);
  assert.equal(validators["rendered-rewrite-evidence.schema.json"](result.evidence), true, JSON.stringify(validators["rendered-rewrite-evidence.schema.json"].errors));
  assert.equal(result.evidence.rendererRevision, 1);
  assert.equal(result.evidence.completion.residue, "pass");
  assert.ok(!JSON.stringify(result.evidence).includes('"patches"'));
  return result;
}

test("rendered composite edits use real shell/URL output and explicit coordinate stages", () => {
  const event = eventFor({ command: "curl -d 'TOKEN' https://example.com", url: "HTTPS://Example.COM/a%20TOKEN?q=TOKEN&q=%54OKEN#TOKEN", nested: ["TOKEN", "unchanged"] });
  const result = verified(event); assert.equal(result.ok, true);
  assert.ok(result.evidence.edits.length >= 3);
  const stages = result.evidence.observations.filter(o => o.type === "scan").map(o => o.coordinate);
  assert.ok(stages.includes("effective_leaf")); assert.ok(stages.includes("decoded_url_path"));
  assert.ok(stages.includes("prefixed_url_query")); assert.ok(stages.includes("decoded_url_fragment"));
  assert.ok(result.evidence.observations.some(o => o.type === "check" && o.check === "shell_piece" && o.result === "pass"));
  for (const edit of result.evidence.edits) {
    assert.equal(edit.type, "rendered_composite_v1"); assert.equal(edit.span[0], 0);
    assert.match(edit.originalHash, /^sha256:[0-9a-f]{64}$/);
  }
  assert.ok(result.evidence.findings.length > 0);
});

test("same physical source supports distinct identity and fallback view copies", () => {
  const event = eventFor({ command: "curl -d 'TOKEN' https://example.com", host: " X TOKEN " });
  const result = verified(event, rules("TOKEN|^[ ]")); assert.equal(result.ok, true);
  assert.equal(result.updatedInput.host, "SAFEX SAFE "); assert.equal(result.updatedInput.dest, "X SAFE");
  const copies = result.evidence.edits.filter(e => e.sourceRef.field === "dest");
  assert.equal(copies.length, 2); assert.notEqual(copies[0].viewLeafIndex, copies[1].viewLeafIndex);
  assert.equal(copies[0].sourceHash, copies[1].sourceHash); assert.notEqual(copies[0].originalHash, copies[1].originalHash);
  assert.deepEqual(copies.map(e => e.derivation), ["identity", "legacy_fallback"]);
});

test("URL text fallback is reported without pretending successful URL validation", () => {
  const result = verified(eventFor({ command: "curl -d 'TOKEN' https://example.com", url: "not-url-TOKEN" }));
  assert.equal(result.ok, true);
  const leaf = result.evidence.edits.find(e => e.sourceRef.field === "url").viewLeafIndex;
  const checks = result.evidence.observations.filter(o => o.viewLeafIndex === leaf && o.type === "check");
  assert.ok(checks.some(o => o.check === "url_text_fallback" && o.result === "fallback"));
  assert.equal(checks.some(o => o.check === "url_parse" && o.result === "pass"), false);
});

test("observer leaves real outcomes, scan order and short circuits unchanged even when it throws", () => {
  const source = { command: "curl -d 'TOKEN' https://example.com", nested: ["TOKEN"] };
  const custom = rules("TOKEN");
  function tracked(calls) { return { ...privacy, scanSecrets: text => { calls.push(["secret", text]); return privacy.scanSecrets(text); }, scanCustom: (text, r) => { calls.push(["custom", text]); return privacy.scanCustom(text, r); } }; }
  const before = [], after = [];
  const a = structuredRewrite(source, custom, tracked(before));
  const b = structuredRewrite(source, custom, tracked(after), () => { throw new Error("observer-failure"); });
  assert.deepEqual(b, a); assert.deepEqual(after, before);
  const c = structuredRewrite(source, custom, privacy, o => { if (o.type === "scan") o.hits.splice(0); });
  assert.deepEqual(c, a);
  const refused = verified(eventFor({ command: "curl -d 'TOKEN' https://example.com", flag: true }), rules('TOKEN|"flag":true'));
  assert.equal(refused.ok, false); assert.equal(refused.reason, "sensitive_residue");
  assert.ok(refused.observations.some(o => o.type === "check" && o.check === "residue" && o.result === "fail"));
});

test("injected persona transform and real shell refusals retain their original result", () => {
  const p = { ...privacy, shouldCloakPersona: () => true, cloakPersona: text => ({ text: text.replaceAll("PERSONA", "MASK"), changed: text.includes("PERSONA") }) };
  const persona = verified(eventFor({ command: "curl -d 'PERSONA' https://example.com" }), [], p);
  assert.equal(persona.ok, true); assert.ok(persona.evidence.observations.some(o => o.type === "persona" && o.changed));
  assert.equal(persona.evidence.completion.persona, "pass");
  const blocked = verified(eventFor({ command: "curl -d TOKEN https://example.com" }), privacy.sanitizeCustomRules([{ id: "fixture", match: "TOKEN", mode: "replace", replaceWith: "<BAD>" }]));
  assert.equal(blocked.ok, false); assert.equal(blocked.reason, "rewrite_would_break_shell");
});

test("composite edits allow injected actual deletion and preserve UTF-16 surrogate boundaries", () => {
  const p = { ...privacy, shouldCloakPersona: () => true, cloakPersona: text => ({ text: text === "PERSONA" ? "" : text, changed: text === "PERSONA" }) };
  const empty = verified(eventFor({ command: "curl https://example.com", note: "PERSONA" }), [], p);
  assert.equal(empty.ok, true); assert.ok(empty.evidence.edits.some(e => e.replacement === ""));
  const event = eventFor({ command: "curl -d '😀 TOKEN é' https://example.com" });
  const result = verified(event); assert.equal(result.ok, true);
  assert.equal(result.evidence.edits[0].span[1], event.fields.command.value.length);
  const forged = structuredClone(result.evidence); forged.edits[0].span = [1, 2];
  assert.equal(applyRenderedRewrite(event, forged).ok, false);
});

test("source/result/finding/revision tampering is rejected", () => {
  const event = eventFor({ command: "curl -d 'TOKEN' https://example.com" });
  const result = verified(event); assert.equal(result.ok, true);
  const mutations = [
    e => { e.edits[0].originalHash = "sha256:" + "0".repeat(64); },
    e => { e.edits[0].sourceHash = "sha256:" + "0".repeat(64); },
    e => { e.edits[0].viewLeafIndex = 999; },
    e => { e.edits[0].derivation = "legacy_fallback"; },
    e => { e.resultViewHash = "sha256:" + "0".repeat(64); },
    e => { e.resultFieldsHash = "sha256:" + "0".repeat(64); },
    e => { e.rendererRevision = 0; },
    e => { e.findings = []; },
    e => { e.observations = []; },
    e => { e.observations.push({ ...e.observations.find(o => o.type === "check" && o.check === "residue"), result: "fail" }); },
    e => { e.edits[0].replacement = "source-tamper"; },
  ];
  for (const mutate of mutations) { const e = structuredClone(result.evidence); mutate(e); assert.equal(applyRenderedRewrite(event, e).ok, false); }
});

test("metadata-only witness replays historical rewrite without source/replacement/key storage", () => {
  const privateValue = "private-unchanged-source";
  const event = eventFor({ command: `curl -d 'TOKEN ${privateValue}' https://example.com`, privateKeyName: "TOKEN" });
  const custom = rules("TOKEN"), result = verified(event, custom); assert.equal(result.ok, true);
  const witness = rewriteReplayWitness(result.evidence, custom), serialized = JSON.stringify(witness);
  assert.equal(validators["rewrite-replay-witness.schema.json"](witness), true);
  for (const text of [privateValue, "privateKeyName", "TOKEN", "SAFE", "command", "replacement", "sourceRef"]) assert.equal(serialized.includes(text), false);
  assert.throws(() => rewriteReplayWitness({ ...result.evidence, layoutHash: privateValue }, custom), /invalid_rewrite_witness/);
  const replayed = replayRenderedRewrite(event, JSON.parse(serialized), custom, privacy); assert.equal(replayed.ok, true);
  assert.deepEqual(replayed.updatedInput, result.updatedInput);
  assert.deepEqual(replayed.evidence, result.evidence);
  assert.equal(replayRenderedRewrite(event, witness, rules("other"), privacy).ok, false);
  assert.equal(replayRenderedRewrite(event, { ...witness, rendererRevision: 0 }, custom, privacy).ok, false);
});

test("legacy structural projection has separate ownership/prototype parity evidence", () => {
  const raw = '{"tool_name":"Bash","tool_input":{"command":"curl -d \'TOKEN\' https://example.com","__proto__":{"flag":true,"text":"TOKEN"},"nested":{"__proto__":{"count":1}}}}';
  const parsed = toCanonicalToolEvent(raw, ctx), layout = buildRewriteLayout(raw, parsed);
  assert.equal(layout.ok, true); const event = { ...parsed.event, rewriteLayout: layout.layout };
  const plain = structuredRewrite(layout.view, rules("TOKEN"), privacy), result = buildRenderedRewriteEvidence(event, rules("TOKEN"), privacy);
  assert.equal(plain.ok, true); assert.equal(result.ok, true);
  const applied = applyRenderedRewrite(event, result.evidence); assert.equal(applied.ok, true);
  assert.equal(JSON.stringify(applied.updatedInput), JSON.stringify(plain.updatedInput));
  assert.deepEqual(Object.keys(applied.updatedInput), Object.keys(plain.updatedInput));
  assert.deepEqual(Object.getPrototypeOf(applied.updatedInput), Object.getPrototypeOf(plain.updatedInput));
  assert.deepEqual(Object.getPrototypeOf(applied.updatedInput.nested), Object.getPrototypeOf(plain.updatedInput.nested));
  assert.equal(Object.hasOwn(applied.updatedInput, "__proto__"), false);
  assert.equal(Object.prototype.flag, undefined);
});


test("production persona cloak uses genuine outbound checks and transformed text", () => {
  const event = eventFor({ command: `curl --data '{"timezone":"Asia/Tokyo","locale":"ja-JP"}' https://example.test/profile` });
  const result = verified(event, []); assert.equal(result.ok, true);
  assert.match(result.updatedInput.command, /America\/New_York/);
  assert.equal(result.updatedInput.command.includes("Asia/Tokyo"), false);
  assert.ok(result.evidence.observations.some(o => o.type === "check" && o.check === "outbound" && o.result === "true"));
  assert.ok(result.evidence.observations.some(o => o.type === "persona" && o.changed && o.coordinate === "post_redaction_leaf"));
});

test("real detector overlap/touching priority stays inside the existing transform", () => {
  const event = eventFor({ command: "curl -d 'ABCDEF' https://example.com" });
  for (const match of ["CDEF", "DEF"]) {
    const custom = privacy.sanitizeCustomRules([{ id: "first", match: "ABC", mode: "replace", replaceWith: "ONE" }, { id: "second", match, mode: "replace", replaceWith: "TWO" }]);
    const result = verified(event, custom); assert.equal(result.ok, true);
    assert.match(result.updatedInput.command, /<标签>/);
    assert.equal(result.evidence.edits[0].span[0], 0); // Composite edit is not falsely called a merged detector span.
  }
  const id = "110101199001011237";
  const secret = verified(eventFor({ command: `curl -d '${id}' https://example.com` }), rules(id));
  assert.equal(secret.ok, true); assert.match(secret.updatedInput.command, /<标签>/);
  assert.ok(secret.evidence.observations.some(o => o.type === "scan" && o.scanner === "secrets" && o.hits.length));
});

test("residue short-circuit does not invent later custom scans or successful checks", () => {
  const id = "110101199001011237";
  const result = verified(eventFor({ command: `curl -d '${id}' https://example.com`, file_path: `/tmp/${id}` }), []);
  assert.equal(result.ok, false); assert.equal(result.reason, "sensitive_residue");
  const scans = result.observations.filter(o => o.phase === "residue" && o.type === "scan");
  assert.equal(scans.length, 1); assert.equal(scans[0].scanner, "secrets"); assert.ok(scans[0].hits.length);
  assert.equal(result.observations.some(o => o.type === "check" && o.check === "residue" && o.result === "pass"), false);
});

test("repeated leaves and query sharing retain physical and effective identities", () => {
  const event = eventFor({ command: "curl -d 'TOKEN' https://example.com", contents: "TOKEN", nested: { note: "TOKEN" }, query: "TOKEN" });
  const result = verified(event); assert.equal(result.ok, true);
  const bindings = result.evidence.edits.map(e => e.sourceBindingHash);
  assert.equal(new Set(bindings).size, bindings.length);
  assert.equal(result.updatedInput.contents, "SAFE"); assert.equal(result.updatedInput.nested.note, "SAFE"); assert.equal(result.updatedInput.query, "SAFE");
  assert.notEqual(result.evidence.baseFieldsHash, result.evidence.resultFieldsHash);
});
