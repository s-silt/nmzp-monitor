import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { canonicalRequestHash } from "../../core/evaluation-application.ts";
import { stableJson } from "../../core/hook-alias-keys.ts";
import { prepareCanonicalEvaluation, prepareHookTransport, prepareProbeTransport } from "../../core/protocol/evaluate-ingress.ts";
import { canonicalEvaluateResponse, compactRenderedRewrite } from "../../core/protocol/evaluate-response.ts";
import { validateEvaluateCompat, validateEvaluateStrict, validateEvaluateResponse } from "../../core/protocol/generated/evaluate-validator.ts";
import { buildRenderedRewriteEvidence, rewriteReplayWitness } from "../../core/protocol/rendered-rewrite.ts";
import * as privacy from "../../src/lib/monitor/privacy.ts";
import { compileAll, createAjv, loadSchemas, repoRoot } from "./protocol-checks.mjs";

// Pure synthetic protocol inputs. Only the regeneration/isolation test creates
// a test-owned temporary module and child process; no live server or host is used.
const schemas = loadSchemas(), validators = compileAll(createAjv(schemas), schemas);
const ctx = { deviceId: "schema-device", eventId: "schema-event", occurredAt: "2026-09-30T12:00:00Z", adapterRevision: 1 };
const digest = value => `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
const hash = `sha256:${"a".repeat(64)}`;
const wire = value => JSON.parse(JSON.stringify(value));
const request = () => {
  const result = prepareHookTransport(JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo safe" } }), ctx);
  assert.equal(result.kind, "request", JSON.stringify(result));
  return wire(result.event);
};
function pair(name, generated, value, expected = true) {
  const before = wire(value);
  assert.equal(validators[name](value), expected, `${name}: ${JSON.stringify(validators[name].errors)}`);
  assert.equal(generated(value), expected, `generated ${name}: ${JSON.stringify(generated.errors)}`);
  assert.deepEqual(value, before, "validation must not strip, coerce, or mutate input");
}
function response(decision = "allow", changes = {}) {
  const event = request();
  let rewrite;
  if (decision === "rewrite") {
    const prepared = prepareHookTransport(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl -d 'TOKEN' https://example.com", nested: ["TOKEN", "unchanged"] } }), ctx);
    assert.equal(prepared.kind, "request");
    Object.assign(event, wire(prepared.event));
    const rules = privacy.sanitizeCustomRules([{ id: "schema_rule", kind: "schema_kind", match: "TOKEN", mode: "replace", replaceWith: "SAFE" }]);
    const rendered = buildRenderedRewriteEvidence(event, rules, privacy);
    assert.equal(rendered.ok, true, JSON.stringify(rendered));
    rewrite = rendered.evidence;
  }
  const record = { id: event.eventId, requestHash: canonicalRequestHash(event), policyVersion: 7, binding: { rulesHash: hash },
    outcome: { decision, reason: decision, ruleIndex: null, risk: "info", threat: null,
      rewriteStatus: decision === "rewrite" ? "APPLIED" : "NONE", secretKindIndices: [], enforcement: "delivered", ...changes },
    ...(rewrite ? { rewrite: rewriteReplayWitness(rewrite, []) } : {}) };
  const projected = canonicalEvaluateResponse({ record, catalog: { rules: ["schema_rule"], kinds: ["schema_kind"], exemptions: [] }, rewrite, duplicate: false });
  return { event, record, evidence: rewrite, response: wire(projected) };
}
const requestPair = (value, expected = true) => pair("canonical-evaluate-request-v2.schema.json", validateEvaluateCompat, value, expected);
const responsePair = (value, expected = true) => pair("canonical-evaluate-response-v2.schema.json", validateEvaluateResponse, value, expected);

test("generated evaluate validators reproduce schemas and load without runtime AJV or contract files", () => {
  execFileSync(process.execPath, ["scripts/generate-evaluate-validator.mjs", "--check"], { cwd: repoRoot, encoding: "utf8" });
  const source = readFileSync(join(repoRoot, "core/protocol/generated/evaluate-validator.ts"), "utf8");
  assert.doesNotMatch(source, /\brequire\s*\(|\bimport\s/);
  const dir = mkdtempSync(join(tmpdir(), "nmzp-validator-isolation-"));
  try {
    const target = join(dir, "evaluate-validator.mjs");
    writeFileSync(target, source);
    const code = `const module = await import(${JSON.stringify(pathToFileURL(target).href)}); for (const name of ["validateEvaluateCompat", "validateEvaluateStrict", "validateEvaluateResponse"]) { if (typeof module[name] !== "function" || module[name](null) !== false) throw new Error(name); }`;
    execFileSync(process.execPath, ["--input-type=module", "--eval", code], { cwd: dir, encoding: "utf8" });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("genuine HOOK and PROBE producers satisfy the closed compatibility wire", () => {
  const hooks = [
    { tool_name: "Bash", tool_input: { command: "echo safe" } },
    { toolCall: { name: "run_command", args: { CommandLine: "echo safe", Cwd: "/repo" } } },
  ];
  for (const raw of hooks) {
    const prepared = prepareHookTransport(JSON.stringify(raw), ctx);
    assert.equal(prepared.kind, "request", JSON.stringify(prepared));
    requestPair(prepared.event);
    assert.equal(prepareCanonicalEvaluation(prepared.event, ctx.deviceId).ok, true);
  }
  for (const extra of [{}, { agent: "" }, { agent: "  " }, { agent: "codex", hookBlind: true }, { toolInput: { cmd: " echo safe " }, contents: " direct text " }]) {
    const raw = { source: "probe", tool: "Bash", command: "echo safe", ...extra };
    const prepared = prepareProbeTransport(JSON.stringify(raw), { ...ctx, hostId: "probe-host" });
    assert.equal(prepared.kind, "request", JSON.stringify(prepared));
    requestPair(prepared.event);
    assert.equal(prepared.event.rewriteLayout.mapping, "probe-eval-v1");
    assert.equal(prepared.event.context.agentPresent, typeof extra.agent === "string" && extra.agent.trim().length > 0);
    assert.equal(prepareCanonicalEvaluation(prepared.event, ctx.deviceId).ok, true);
  }
});

test("strict evaluate schema is opt-in and preserves the actual evaluate envelope", () => {
  for (const eventId of ["x".repeat(128), "😀".repeat(64)]) {
    const value = { ...request(), eventId };
    requestPair(value);
    pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, value);
  }
  for (const eventId of ["x".repeat(129), "😀".repeat(65), "id\u0000text", "id\u0080text"]) {
    const value = { ...request(), eventId };
    requestPair(value);
    pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, value, false);
  }
  const many = request();
  many.extraFields = Array.from({ length: 257 }, (_, i) => ({ path: `/extra${i}`, value: "x" }));
  requestPair(many);
  pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, many, false);
  many.extraFields.pop();
  pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, many);
  for (const mutate of [value => { delete value.rewriteLayout; }, value => { value.origin = "BACKFILL"; value.context.hookBlind = true; }]) {
    const value = request(); mutate(value);
    requestPair(value, false);
    pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, value, false);
  }
});

test("compatibility schemas do not silently activate strict pointer/depth parser limits", () => {
  const value = request(), path = `/${"😀".repeat(260)}`;
  value.extraFields.push({ path, value: "retained" });
  assert.ok(Buffer.byteLength(path) > 1024);
  requestPair(value);
  // These are schema-only checks; raw parser byte/depth checks remain separate.
  pair("canonical-evaluate-request-v2-strict.schema.json", validateEvaluateStrict, value);
});

test("evaluate request rejects unknown fields, truncation flags and invalid source mappings without mutation", () => {
  const paths = [[], ["device"], ["host"], ["session"], ["tool"], ["fields"], ["fields", "command"], ["context"], ["rewriteLayout"], ["rewriteLayout", "nodes", 0], ["rewriteLayout", "nodes", 0, "entries", 0], ["rewriteLayout", "nodes", 1], ["rewriteLayout", "nodes", 1, "ref"]];
  for (const path of paths) {
    const value = request();
    let target = value; for (const key of path) target = target[key];
    target.injected = "synthetic";
    requestPair(value, false);
  }
  for (const mutate of [
    value => { value.truncated = true; },
    value => { value.context.agentPresent = "true"; },
    value => { value.context.hookBlind = true; },
    value => { value.rewriteLayout.probe = { agent: null, topLevel: {} }; },
    value => { value.origin = "PROBE"; },
    value => { value.rewriteLayout.sourceRoot = "/invented"; },
    value => { value.fields.command.provenance = "/bad~escape"; },
  ]) { const value = request(); mutate(value); requestPair(value, false); }
  for (const value of [null, true, 17, "request", []]) requestPair(value, false);
});

test("PROBE fallback references and nested metadata remain closed", () => {
  const prepared = prepareProbeTransport(JSON.stringify({ source: "probe", tool: "Bash", command: "echo safe", agent: "codex" }), { ...ctx, hostId: "probe-host" });
  assert.equal(prepared.kind, "request");
  for (const mutate of [
    value => { delete value.rewriteLayout.probe; },
    value => { value.rewriteLayout.probe.extra = true; },
    value => { value.rewriteLayout.probe.topLevel.cwd = { extraIndex: 0 }; },
    value => { value.rewriteLayout.probe.agent.unknown = 0; },
    value => { value.rewriteLayout.sourceRoot = "/input"; },
  ]) { const value = wire(prepared.event); mutate(value); requestPair(value, false); }
});

test("actual projection for every action passes both validators and preserves immutable egress observations", () => {
  const egress = { observationOnly: true, operation: "upload", interaction: "noninteractive_reported", authorization: "risk_blocked", basis: "large_archive",
    uploadSize: { status: "observed", bytes: 40000000, checkedAt: 1, source: "local_hook_stat", reason: "explicit_archive" },
    archivePolicy: { thresholdMiB: 20, action: "block" }, github: "target_unknown" };
  for (const decision of ["allow", "log", "confirm", "block", "rewrite"]) {
    const value = response(decision, { egress }).response;
    responsePair(value);
    assert.deepEqual(value.egress, egress);
    assert.equal(value.v, 2); assert.equal(value.kind, "canonical_evaluate_response");
    assert.equal(validators["canonical-decision.schema.json"](value), false, "legacy placeholder must remain distinct");
  }
  for (const [decision, rewriteStatus] of [["log", "NOOP_NO_SPAN"], ["block", "REFUSED"]]) responsePair(response(decision, { rewriteStatus }).response);
});

test("compact rewrite retains complete actual edits and labels the full detector trace as omitted", () => {
  const { evidence, response: value } = response("rewrite");
  responsePair(value);
  const compact = compactRenderedRewrite(evidence);
  assert.equal(validators["compact-rendered-rewrite.schema.json"](compact), true);
  assert.deepEqual(compact.edits, evidence.edits);
  assert.deepEqual(compact.completion, evidence.completion);
  assert.equal(compact.trace.observationCount, evidence.observations.length);
  assert.equal(compact.trace.findingCount, evidence.findings.length);
  assert.equal(compact.trace.hash, digest({ observations: evidence.observations, findings: evidence.findings, completion: evidence.completion }));
  assert.equal(compact.trace.availability, "omitted");
  assert.equal(Object.hasOwn(compact, "findings"), false); assert.equal(Object.hasOwn(compact, "observations"), false);
  assert.deepEqual(value.privacy.renderedSummary, { availability: "full_trace_omitted", observationCount: compact.trace.observationCount, findingCount: compact.trace.findingCount, hash: compact.trace.hash });
});

test("response rejects missing request binding, fake full traces and nested injected payload", () => {
  const original = response("rewrite").response;
  for (const mutate of [
    value => { delete value.requestHash; },
    value => { value.requestHash = "unbound"; },
    value => { value.v = 1; },
    value => { value.kind = "canonical_decision"; },
    value => { value.origin = "OFFLINE_CACHE"; },
    value => { value.privacy.findings = []; },
    value => { value.privacy.engineSummary.coverage = "all_findings"; },
    value => { value.privacy.engineSummary.kinds = ["same", "same"]; },
    value => { value.privacy.renderedSummary = { availability: "not_retained" }; },
    value => { value.rewrite.kind = "rendered_rewrite_evidence"; },
    value => { value.rewrite.observations = []; },
    value => { value.rewrite.findings = []; },
    value => { value.rewrite.trace.availability = "complete"; },
    value => { value.rewrite.trace.observationCount = -1; },
    value => { value.rewrite.trace.findingCount = Number.MAX_SAFE_INTEGER + 1; },
    value => { value.rewrite.edits[0].sourceRef.raw = "secret"; },
    value => { value.rewrite.edits[0].span = [0, 1, 2]; },
    value => { value.rewrite.completion.extra = true; },
    value => { value.explain[0].matchedText = "secret"; },
    value => { value.userMessage = "echo private-input"; },
    value => { value.explain[0].result = "allow"; },
  ]) { const value = wire(original); mutate(value); responsePair(value, false); }
});

test("every action keeps its rewrite presence/status/message/summary contract", () => {
  const statuses = { allow: ["NONE"], log: ["NONE", "NOOP_NO_SPAN"], confirm: ["NONE"], block: ["NONE", "REFUSED"], rewrite: ["APPLIED"] };
  for (const [decision, allowed] of Object.entries(statuses)) {
    const original = response(decision).response;
    for (const status of ["NONE", "APPLIED", "NOOP_NO_SPAN", "REFUSED"]) {
      const value = wire(original); value.privacy.rewriteStatus = status;
      responsePair(value, allowed.includes(status));
    }
    const value = wire(original);
    if (decision === "rewrite") delete value.rewrite;
    else value.rewrite = response("rewrite").response.rewrite;
    responsePair(value, false);
  }
});

test("egress observations and upload-size variants reject unknown or incompatible fields", () => {
  const egress = { observationOnly: true, operation: "upload", interaction: "unknown", authorization: "not_observed", basis: "existing_policy",
    uploadSize: { status: "unknown", checkedAt: 0, source: "local_hook_stat", reason: "unresolved_source" }, archivePolicy: { thresholdMiB: 1, action: "warn" } };
  const original = response("log", { egress }).response;
  responsePair(original);
  for (const mutate of [
    value => { value.egress.rawCommand = "private"; },
    value => { value.egress.observationOnly = false; },
    value => { value.egress.uploadSize.bytes = 1; },
    value => { value.egress.uploadSize.checkedAt = -1; },
    value => { value.egress.archivePolicy.extra = true; },
    value => { value.egress.archivePolicy.thresholdMiB = 0; },
  ]) { const value = wire(original); mutate(value); responsePair(value, false); }
});
