/** Durable V2 application boundary. HTTP activation and canonical ingress live in the route package. */
import { createHash } from "node:crypto";
import { BODY_LIMIT, NMZP_VERSION } from "./constants.ts";
import { applyPreparedEvaluation, privacyFrom, type EvalResponse, type PreparedEvaluation } from "./eval-bridge.ts";
import { stableJson } from "./hook-protocol.ts";
import type { MonitorMods } from "./paths.ts";
import type { NmzpStore } from "./persist.ts";
import { ENGINE_REVISION } from "./policy/engine-revision.ts";
import { policyRulesHash, REWRITE_SEMANTICS_REVISION } from "./policy/nmzp-service.ts";
import type { PolicyState, StoredEvent } from "./schema.ts";
import { ownedEvaluationRecord, V2_HASH_SCHEME, type EvaluationBinding, type EvaluationRecord, type ImmutableOutcome } from "./audit/evaluation-record.ts";
import { buildRenderedRewriteEvidence, replayRenderedRewrite, rewriteReplayWitness, RENDERED_REWRITE_REVISION, type RenderedRewriteEvidence } from "./protocol/rendered-rewrite.ts";
import type { CanonicalToolEvent } from "./protocol/v2-adapter.ts";

const digest = (value: unknown) => `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
/** Explicit replay implementation contract. Bump the relevant entry when those semantics change.
 * Historical executable versions are not retained: a mismatch refuses replay.
 */
export const EVALUATION_IMPLEMENTATIONS = Object.freeze({ application: 2, adapter: 2, layout: 2,
  rewrite: REWRITE_SEMANTICS_REVISION, observation: 1, rendered: RENDERED_REWRITE_REVISION,
  projection: "legacy_object_assignment_v1", privateCodec: 1, responseTemplate: 2, engine: ENGINE_REVISION, package: NMZP_VERSION });

export function evaluationBinding(policyHash: string, monitor: MonitorMods): EvaluationBinding {
  return { version: 1, policyHash: `sha256:${policyHash}`, rulesHash: `sha256:${policyRulesHash(monitor)}`, implementationHash: digest(EVALUATION_IMPLEMENTATIONS) };
}
export function canonicalRequestHash(event: CanonicalToolEvent): string {
  const context = { ...event.context };
  delete context.uploadSize;
  return digest({ scheme: V2_HASH_SCHEME, event: { ...event, context } });
}
export class EvaluationApplicationError extends Error {
  readonly code: "unauthorized" | "storage_not_enabled" | "event_protocol_incompatible" | "event_conflict" | "event_expired" | "evaluation_replay_unavailable" | "evaluation_result_too_large" | "audit_storage_unavailable";
  constructor(code: EvaluationApplicationError["code"]) { super(code); this.code = code; }
}
function fail(code: EvaluationApplicationError["code"]): never { throw new EvaluationApplicationError(code); }
function fence(store: NmzpStore, deviceId: string): void {
  store.capturePolicy();
  const device = store.getDevice(deviceId);
  if (!device || typeof device.revokedAt === "number") fail("unauthorized");
  if (store.auditHealth() !== "ready") fail("audit_storage_unavailable");
}
export function evaluationCatalog(monitor: MonitorMods, policy: PolicyState) {
  const kinds = [...new Set([...monitor.privacy.CRED_KINDS, ...monitor.privacy.PII_KINDS, ...policy.customRules.map(rule => rule.kind), "pii"])];
  // engine.privacyRule uses this fixed template for built-in PII and policy-bound custom kinds.
  return { rules: [...monitor.RULES.map(rule => rule.id), ...kinds.map(kind => `privacy:${kind}`)], kinds,
    exemptions: (policy.exemptions ?? []).map(exemption => exemption.id) };
}
function ordinal(value: string | undefined, list: string[]): number | null {
  if (value === undefined) return null;
  const at = list.indexOf(value);
  if (at < 0) fail("evaluation_replay_unavailable");
  return at;
}
function outcomeOf(response: EvalResponse, event: StoredEvent | null, catalog: ReturnType<typeof evaluationCatalog>): ImmutableOutcome {
  const ruleIndex = ordinal(response.ruleIds[0], catalog.rules);
  const reason = response.reason === response.ruleIds[0] ? "rule"
    : response.reason === "tool_input is not a structured object; refusing unsafe rewrite" ? "unstructured_rewrite" : response.reason;
  return {
    decision: response.decision as ImmutableOutcome["decision"], reason: reason as ImmutableOutcome["reason"], ruleIndex,
    risk: event?.risk ?? "info", threat: event?.threat as ImmutableOutcome["threat"] ?? null,
    scope: (event?.workdirScope ?? "unknown") as ImmutableOutcome["scope"],
    rewriteStatus: response.decision === "rewrite" ? "APPLIED" : response.reason === "rewrite_noop" ? "NOOP_NO_SPAN"
      : ["rewrite_would_break_shell", "sensitive_residue", "persona_residue", "unstructured_rewrite"].includes(reason) ? "REFUSED" : "NONE",
    enforcement: response.enforcement, overrideSource: response.overrideSource ?? null,
    exemptionIndex: ordinal(response.exemptionId, catalog.exemptions),
    secretKindIndices: [...new Set((event?.secretKinds ?? []).map(kind => ordinal(kind, catalog.kinds)!))],
    correlateHit: event?.correlateHit === true, ...(response.egress ? { egress: JSON.parse(JSON.stringify(response.egress)) } : {}),
  };
}
function checkIndices(record: EvaluationRecord, catalog: ReturnType<typeof evaluationCatalog>): void {
  const o = record.outcome;
  if (o.ruleIndex !== null && o.ruleIndex >= catalog.rules.length || o.exemptionIndex !== null && o.exemptionIndex >= catalog.exemptions.length ||
    o.secretKindIndices.some(index => index >= catalog.kinds.length)) fail("evaluation_replay_unavailable");
}

export interface DecisionProjection {
  record: EvaluationRecord;
  catalog: ReturnType<typeof evaluationCatalog>;
  rewrite?: RenderedRewriteEvidence;
  duplicate: boolean;
}
/** Trusted server serializer: package 2 supplies the closed compact HTTP schema projection.
 * The callback receives immutable metadata and transient rewrite evidence; neither its output nor the evidence is persisted.
 */
export interface DurableEvaluationOptions {
  store: NmzpStore;
  monitor: MonitorMods;
  windows: InstanceType<MonitorMods["SessionWindows"]>;
  event: CanonicalToolEvent;
  prepared: PreparedEvaluation;
  /** Trusted server capture taken after authentication and before awaiting request bytes. Never read from the wire. */
  snapshot: ReturnType<NmzpStore["capturePolicy"]>;
  deviceId: string;
  project: (decision: DecisionProjection) => unknown;
}

/** One mutex spans identity, history, staged evaluation, budget and durable write.
 * A published session stage and SQLite are deliberately NOT called one atomic transaction.
 * After append is attempted every failure is unknown; retries resolve the durable identity first.
 */
export async function evaluateDurably(opts: DurableEvaluationOptions): Promise<{ json: string; record: EvaluationRecord; duplicate: boolean }> {
  const { store, monitor, event, deviceId, windows } = opts;
  if (store.getStorageMode() !== "sqlite") fail("storage_not_enabled");
  if (event.device.id !== deviceId || opts.prepared.input.deviceId !== deviceId) fail("unauthorized");
  if (event.origin === "BACKFILL" || opts.prepared.input.source !== (event.origin === "PROBE" ? "probe" : "hook") || opts.prepared.input.eventId !== event.eventId) fail("event_protocol_incompatible");
  const requestHash = canonicalRequestHash(event);
  const snapshot = { hash: opts.snapshot.hash, policy: structuredClone(opts.snapshot.policy) as PolicyState };
  const prepared = structuredClone(opts.prepared);
  return store.withMutex(async () => {
    fence(store, deviceId);
    const previous = await store.lookupEvaluationIdentityUnlocked(deviceId, event.eventId);
    fence(store, deviceId);
    if (previous) {
      if (previous.originProtocol !== "v2") fail("event_protocol_incompatible");
      if (previous.kind === "tombstone") {
        if (previous.requestHash !== requestHash) fail("event_conflict");
        fail("event_expired");
      }
      const record = previous.record;
      if (record.requestHash !== requestHash) fail("event_conflict");
      const historical = store.getHistoricalPolicy(record.policyVersion);
      if (!historical || historical.hash !== record.binding.policyHash.slice(7) || historical.rulesHash !== policyRulesHash(monitor) || historical.engineVersion !== NMZP_VERSION ||
        stableJson(record.binding) !== stableJson(evaluationBinding(historical.hash, monitor))) fail("evaluation_replay_unavailable");
      const policy = structuredClone(historical.policy) as PolicyState;
      const catalog = evaluationCatalog(monitor, policy);
      checkIndices(record, catalog);
      let rewrite: RenderedRewriteEvidence | undefined;
      if (record.rewrite) {
        // No evaluate, session apply, current-policy egress or client-supplied privacy functions on replay.
        const replay = replayRenderedRewrite(event, record.rewrite, policy.customRules, privacyFrom(monitor));
        if (!replay.ok) fail("evaluation_replay_unavailable");
        rewrite = replay.evidence;
      }
      const json = JSON.stringify(opts.project({ record: structuredClone(record), catalog, rewrite, duplicate: true }));
      if (typeof json !== "string" || Buffer.byteLength(json) > BODY_LIMIT) fail("evaluation_replay_unavailable");
      fence(store, deviceId);
      return { json, record, duplicate: true };
    }
    const policy = snapshot.policy;
    // Runtime replacement never rewrites history implicitly. Until an explicit policy
    // publish/restore binds the new catalog, do not create an unreplayable V2 decision.
    const historical = store.getHistoricalPolicyForFreshEvaluation(policy.version);
    if (!historical || historical.hash !== snapshot.hash || historical.rulesHash !== policyRulesHash(monitor) || historical.engineVersion !== NMZP_VERSION) {
      fail("evaluation_replay_unavailable");
    }
    const device = store.getDevice(deviceId)!;
    const stage = windows.stage();
    let rewrite: RenderedRewriteEvidence | undefined;
    const evaluated = policy.stopped ? { event: null, response: { eventId: event.eventId, decision: "allow", reason: "processing_stopped", ruleIds: [], policyVersion: policy.version, summary: "", enforcement: "delivered" } as EvalResponse }
      : applyPreparedEvaluation({ monitor, windows: stage.windows, policy, device, body: { permissionMode: event.context.permissionMode, uploadSize: event.context.uploadSize }, eventId: event.eventId }, prepared, (_view, rules, privacy) => {
        const result = buildRenderedRewriteEvidence(event, rules, privacy);
        if (!result.ok) {
          if (result.code === "rewrite_refused") return { ok: false, reason: result.reason };
          fail("evaluation_replay_unavailable");
        }
        rewrite = result.evidence;
        return { ok: true, updatedInput: result.updatedInput };
      });
    const binding = evaluationBinding(snapshot.hash, monitor), catalog = evaluationCatalog(monitor, policy);
    const publicEvent = evaluated.event ? { ...evaluated.event, policyHash: snapshot.hash } : undefined;
    const record = ownedEvaluationRecord({ kind: "v2_evaluation", version: 1, originProtocol: "v2", hashScheme: V2_HASH_SCHEME, requestHash,
      id: event.eventId, machineId: deviceId, ts: publicEvent?.ts ?? Date.now(), policyVersion: policy.version, internalOnly: !publicEvent, binding,
      outcome: outcomeOf(evaluated.response, evaluated.event, catalog), ...(publicEvent ? { publicEvent } : {}),
      ...(evaluated.response.decision === "rewrite" && rewrite ? { rewrite: rewriteReplayWitness(rewrite, policy.customRules) } : {}) });
    const json = JSON.stringify(opts.project({ record: structuredClone(record), catalog, rewrite: record.rewrite ? rewrite : undefined, duplicate: false }));
    if (typeof json !== "string" || Buffer.byteLength(json) > BODY_LIMIT) fail("evaluation_result_too_large");
    fence(store, deviceId);
    // All refusal/size/codec checks precede session publication. A failed/uncertain append does not roll back the published session.
    stage.publish();
    try { await store.appendEvaluationUnlocked(record); }
    catch { fail("audit_storage_unavailable"); }
    try { fence(store, deviceId); } catch { fail("audit_storage_unavailable"); }
    return { json, record, duplicate: false };
  });
}
