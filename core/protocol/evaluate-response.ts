/** Real compact V2 wire projection. Full edits are transmitted; the full detector trace is explicitly omitted. */
import { createHash } from "node:crypto";
import { stableJson } from "../hook-alias-keys.ts";
import { ENGINE_REVISION } from "../policy/engine-revision.ts";
import { canonicalRequestHash, EvaluationApplicationError, type DecisionProjection } from "../evaluation-application.ts";
import { applyCompactRenderedRewrite } from "./rendered-rewrite.ts";
import type { CanonicalToolEvent } from "./v2-adapter.ts";
import { validateEvaluateResponse } from "./generated/evaluate-validator.ts";
import type { RenderedRewriteEvidence } from "./rendered-rewrite.ts";

export type CompactRenderedRewrite = Omit<RenderedRewriteEvidence, "kind" | "observations" | "findings"> & {
  kind: "rendered_composite_payload";
  trace: { availability: "omitted"; observationCount: number; findingCount: number; hash: string };
};
const digest = (value: unknown) => `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;

export function compactRenderedRewrite(evidence: RenderedRewriteEvidence): CompactRenderedRewrite {
  const { kind: _kind, observations, findings, ...complete } = evidence;
  return { ...complete, kind: "rendered_composite_payload", trace: { availability: "omitted", observationCount: observations.length,
    findingCount: findings.length, hash: digest({ observations, findings, completion: evidence.completion }) } };
}
const actions = { allow: "ALLOW", log: "LOG", confirm: "ASK", block: "BLOCK", rewrite: "REWRITE" } as const;
const messages = { ALLOW: "NMZP allowed this call.", LOG: "NMZP recorded this call.", ASK: "NMZP requires confirmation for this call.", BLOCK: "NMZP blocked this call.", REWRITE: "NMZP rewrote this call according to its privacy policy." } as const;

export function canonicalEvaluateResponse({ record, catalog, rewrite, duplicate }: DecisionProjection) {
  const o = record.outcome, action = actions[o.decision];
  const ruleIds = o.ruleIndex === null ? [] : [catalog.rules[o.ruleIndex]];
  const originalReason = o.reason === "rule" ? ruleIds[0] : o.reason;
  const reasonCode = /^[a-z][a-z0-9_:]{0,127}$/.test(originalReason) ? originalReason : "rule_hit";
  if ((action === "REWRITE") !== Boolean(rewrite)) throw new EvaluationApplicationError("evaluation_replay_unavailable");
  const compact = rewrite ? compactRenderedRewrite(rewrite) : undefined;
  if (compact && compact.trace.hash !== record.rewrite?.observationHash) throw new EvaluationApplicationError("evaluation_replay_unavailable");
  return {
    v: 2 as const, kind: "canonical_evaluate_response" as const, eventId: record.id, requestHash: record.requestHash, action, reasonCode, ruleIds,
    risk: o.risk === "info" ? "none" : o.risk, family: o.threat,
    policy: { version: record.policyVersion, rulesHash: record.binding.rulesHash }, engineRevision: ENGINE_REVISION, origin: "SERVER" as const,
    privacy: { rewriteStatus: o.rewriteStatus, engineSummary: { coverage: "unique_kinds_only" as const, kinds: o.secretKindIndices.map(index => catalog.kinds[index]) },
      renderedSummary: compact ? { availability: "full_trace_omitted" as const, findingCount: compact.trace.findingCount, observationCount: compact.trace.observationCount, hash: compact.trace.hash } : { availability: "not_retained" as const } },
    explain: [{ layer: "application", result: o.decision, reasonCode, ruleIds }], userMessage: messages[action],
    enforcement: o.enforcement, duplicate, ...(o.egress ? { egress: o.egress } : {}), ...(compact ? { rewrite: compact } : {}),
  };
}
export type CanonicalEvaluateResponseV2 = ReturnType<typeof canonicalEvaluateResponse>;

/** Opt-in consumer boundary. Call with the exact event retained by the trusted local producer.
 * This validates wire shape and request/source/result bindings, not the omitted detector trace.
 * It does not activate the hook transport or substitute display text for executable input.
 */
export function applyCanonicalEvaluateResponse(event: CanonicalToolEvent, raw: unknown):
  { ok: true; decision: "allow" | "deny"; reason: string; updatedInput?: Record<string, unknown> } | { ok: false; code: "evaluation_response_invalid" } {
  const bad = { ok: false as const, code: "evaluation_response_invalid" as const };
  if (!validateEvaluateResponse(raw)) return bad;
  const response = raw as CanonicalEvaluateResponseV2;
  if (response.eventId !== event.eventId || response.requestHash !== canonicalRequestHash(event)) return bad;
  const explanation = response.explain[0];
  if (explanation.reasonCode !== response.reasonCode || stableJson(explanation.ruleIds) !== stableJson(response.ruleIds)) return bad;
  if (response.rewrite) {
    const summary = response.privacy.renderedSummary, trace = response.rewrite.trace;
    if (summary.availability !== "full_trace_omitted" || summary.hash !== trace.hash || summary.findingCount !== trace.findingCount || summary.observationCount !== trace.observationCount) return bad;
  }
  const reason = response.reasonCode === "unstructured_rewrite" ? "tool_input is not a structured object; refusing unsafe rewrite"
    : response.reasonCode === "rule_hit" && response.ruleIds.length ? response.ruleIds[0] : response.reasonCode;
  if (response.action === "REWRITE") {
    const applied = applyCompactRenderedRewrite(event, response.rewrite);
    if (!applied.ok) return bad;
    return { ok: true, decision: "allow", reason, updatedInput: applied.updatedInput };
  }
  return { ok: true, decision: response.action === "BLOCK" || response.action === "ASK" ? "deny" : "allow", reason };
}
