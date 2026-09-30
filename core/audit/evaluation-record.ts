/** Private immutable V2 replay metadata. Never contains source/layout/edits or arbitrary explanatory text. */
import { stableJson } from "../hook-alias-keys.ts";
import type { EgressEvidence } from "../egress-schema.ts";
import type { Enforcement, StoredEvent } from "../schema.ts";


export interface RewriteReplayWitness {
  version: 1;
  rendererRevision: 1;
  structuralProjection: "legacy_object_assignment_v1";
  customRulesHash: string;
  layoutHash: string;
  baseFieldsHash: string;
  resultFieldsHash: string;
  baseViewHash: string;
  resultViewHash: string;
  editCount: number;
  observationHash: string;
}

export const V2_HASH_SCHEME = "canonical_event_v1_without_upload_size" as const;
export interface EvaluationBinding {
  policyHash: string;
  rulesHash: string;
  implementationHash: string;
  /** Fixed metadata codec/template version, independent of package version. */
  version: 1;
}
export interface ImmutableOutcome {
  decision: "allow" | "log" | "confirm" | "block" | "rewrite";
  reason: "rule" | "allow" | "log" | "confirm" | "block" | "rewrite" | "processing_stopped" | "out_of_scope" |
    "conflicting_aliases" | "rewrite_noop" | "rewrite_would_break_shell" | "sensitive_residue" | "persona_residue" | "unstructured_rewrite";
  /** Index into the bound server catalog; never a caller-controlled rule name. */
  ruleIndex: number | null;
  risk: "info" | "low" | "medium" | "high";
  threat: "exfil" | "secret" | "tamper" | "destructive" | "recon" | "isolate" | "poison" | null;
  scope: "project" | "home" | "system" | "other" | "unknown";
  rewriteStatus: "NONE" | "APPLIED" | "NOOP_NO_SPAN" | "REFUSED";
  enforcement: Enforcement;
  overrideSource: "rule" | "family" | null;
  exemptionIndex: number | null;
  /** Catalog-relative finding indices, bound by policy/catalog hashes. No arbitrary kind or field names. */
  secretKindIndices: number[];
  correlateHit: boolean;
  egress?: EgressEvidence;
}
export interface EvaluationRecord {
  kind: "v2_evaluation";
  version: 1;
  originProtocol: "v2";
  hashScheme: typeof V2_HASH_SCHEME;
  requestHash: string;
  id: string;
  machineId: string;
  ts: number;
  policyVersion: number;
  internalOnly: boolean;
  binding: EvaluationBinding;
  outcome: ImmutableOutcome;
  rewrite?: RewriteReplayWitness;
  /** Existing sanitized public audit projection only; never exposed by spreading this envelope. */
  publicEvent?: StoredEvent;
}
export type EvaluationIdentity =
  | { kind: "event"; originProtocol: "v1"; event: StoredEvent }
  | { kind: "event"; originProtocol: "v2"; record: EvaluationRecord }
  | { kind: "tombstone"; originProtocol: "v1" | "v2"; requestHash?: string; hashScheme?: typeof V2_HASH_SCHEME;
      policyVersion: number; policyHash?: string; internalOnly: boolean; reason: string };

const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, required: string[], optional: string[] = []) =>
  required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const hash = (v: unknown) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const index = (v: unknown) => v === null || integer(v);
const member = (v: unknown, values: readonly unknown[]) => values.includes(v);
// Identity values are protocol identifiers, not a channel for free-form replay metadata.
const identifier = (v: unknown) => typeof v === "string" && v.length > 0 && Buffer.byteLength(v) <= 262144;
const enforcement = ["blocked", "pending_verify", "delivered", "returned_deny", "offline", "timeout", "failed", "degraded"];

function validEgress(v: unknown): boolean {
  if (!object(v) || !keys(v, ["observationOnly", "operation", "interaction", "authorization", "basis"], ["uploadSize", "archivePolicy", "github"]) || v.observationOnly !== true ||
    !member(v.operation, ["git_push", "upload", "local_archive", "storage_access"]) ||
    !member(v.interaction, ["host_prompt_available", "noninteractive_reported", "background_reported", "unknown"]) ||
    !member(v.authorization, ["risk_blocked", "not_required", "policy_inactive", "not_observed"]) ||
    !member(v.basis, ["storage_endpoint", "correlation", "local_only", "existing_policy", "large_archive", "github_agent"])) return false;
  if (v.github !== undefined && !member(v.github, ["unlimited", "agent_allowed", "agent_denied", "target_unknown"])) return false;
  if (v.archivePolicy !== undefined) {
    const p = v.archivePolicy;
    if (!object(p) || !keys(p, ["thresholdMiB", "action"]) || !integer(p.thresholdMiB) || p.thresholdMiB < 1 || p.thresholdMiB > 1048576 || !member(p.action, ["warn", "block"])) return false;
  }
  if (v.uploadSize !== undefined) {
    const s = v.uploadSize;
    if (!object(s) || !keys(s, ["status", "checkedAt", "source", "reason"], ["bytes"]) || !integer(s.checkedAt) || s.source !== "local_hook_stat") return false;
    if (s.status === "observed") { if (s.reason !== "explicit_archive" || !integer(s.bytes)) return false; }
    else if (s.status !== "unknown" || s.reason !== "unresolved_source" || s.bytes !== undefined) return false;
    // No freshness recomputation: this is the first committed observation.
  }
  return true;
}
function validWitness(v: unknown): boolean {
  const hashes = ["customRulesHash", "layoutHash", "baseFieldsHash", "resultFieldsHash", "baseViewHash", "resultViewHash", "observationHash"];
  return object(v) && keys(v, ["version", "rendererRevision", "structuralProjection", "editCount", ...hashes]) &&
    v.version === 1 && v.rendererRevision === 1 && v.structuralProjection === "legacy_object_assignment_v1" && integer(v.editCount) && hashes.every(k => hash(v[k]));
}
const publicKeys = ["egress", "response", "id", "ts", "machineId", "agent", "sessionId", "layer", "tool", "nativeTool", "input", "risk", "decision", "ruleId", "category", "workdirScope", "dest", "endpoints", "redacted", "threat", "secretKinds", "detectedModel", "source", "hookBlind", "correlateHit", "actor", "proc", "rewritten", "policyVersion", "evaluation", "enforcement", "degraded", "duplicate", "requestHash", "policyHash", "relatedEventId", "overrideSource", "exemptionId", "dryRunKinds"];

/** Reject unknown metadata, including nested source hidden in reasons, findings or traces. */
export function validateEvaluationRecord(value: unknown): asserts value is EvaluationRecord {
  const fail = () => { throw new Error("audit_evaluation_invalid"); };
  if (!object(value) || !keys(value, ["kind", "version", "originProtocol", "hashScheme", "requestHash", "id", "machineId", "ts", "policyVersion", "internalOnly", "binding", "outcome"], ["rewrite", "publicEvent"])) return fail();
  if (value.kind !== "v2_evaluation" || value.version !== 1 || value.originProtocol !== "v2" || value.hashScheme !== V2_HASH_SCHEME || !hash(value.requestHash) ||
    !identifier(value.id) || !identifier(value.machineId) || !integer(value.ts) || !integer(value.policyVersion) || typeof value.internalOnly !== "boolean") return fail();
  const b = value.binding;
  if (!object(b) || !keys(b, ["version", "policyHash", "rulesHash", "implementationHash"]) || b.version !== 1 || ![b.policyHash, b.rulesHash, b.implementationHash].every(hash)) return fail();
  const o = value.outcome;
  if (!object(o) || !keys(o, ["decision", "reason", "ruleIndex", "risk", "threat", "scope", "rewriteStatus", "enforcement", "overrideSource", "exemptionIndex", "secretKindIndices", "correlateHit"], ["egress"]) ||
    !member(o.decision, ["allow", "log", "confirm", "block", "rewrite"]) ||
    !member(o.reason, ["rule", "allow", "log", "confirm", "block", "rewrite", "processing_stopped", "out_of_scope", "conflicting_aliases", "rewrite_noop", "rewrite_would_break_shell", "sensitive_residue", "persona_residue", "unstructured_rewrite"]) ||
    !index(o.ruleIndex) || (o.reason === "rule" && o.ruleIndex === null) || !member(o.risk, ["info", "low", "medium", "high"]) ||
    !member(o.threat, [null, "exfil", "secret", "tamper", "destructive", "recon", "isolate", "poison"]) || !member(o.scope, ["project", "home", "system", "other", "unknown"]) ||
    !member(o.rewriteStatus, ["NONE", "APPLIED", "NOOP_NO_SPAN", "REFUSED"]) || !member(o.enforcement, enforcement) ||
    !member(o.overrideSource, [null, "rule", "family"]) || !index(o.exemptionIndex) || typeof o.correlateHit !== "boolean" ||
    !Array.isArray(o.secretKindIndices) || o.secretKindIndices.length > 1024 || !o.secretKindIndices.every(integer) || new Set(o.secretKindIndices).size !== o.secretKindIndices.length ||
    (o.egress !== undefined && !validEgress(o.egress))) return fail();
  if ((o.decision === "rewrite") !== (o.rewriteStatus === "APPLIED") || (o.decision === "rewrite") !== (value.rewrite !== undefined) || (value.rewrite !== undefined && !validWitness(value.rewrite))) return fail();
  if (value.internalOnly) {
    if (value.publicEvent !== undefined || !member(o.reason, ["processing_stopped", "out_of_scope"]) || o.decision !== "allow" || o.ruleIndex !== null || o.rewriteStatus !== "NONE" || o.egress !== undefined) return fail();
  } else {
    const e = value.publicEvent;
    if (!object(e) || Object.keys(e).some(k => !publicKeys.includes(k)) || e.id !== value.id || e.machineId !== value.machineId || e.ts !== value.ts || e.policyVersion !== value.policyVersion ||
      e.risk !== o.risk || (e.threat ?? null) !== o.threat || e.workdirScope !== o.scope || (e.correlateHit === true) !== o.correlateHit ||
      e.decision !== o.decision || e.evaluation !== o.decision || e.enforcement !== o.enforcement || e.policyHash !== (b.policyHash as string).slice(7) || e.requestHash !== undefined ||
      stableJson(e.egress) !== stableJson(o.egress) || !member(e.layer, ["app_pre", "kernel_exec"])) return fail();
  }
}

export function ownedEvaluationRecord(value: unknown): EvaluationRecord {
  validateEvaluationRecord(value);
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new Error("audit_event_too_large");
  const copy: unknown = JSON.parse(encoded);
  validateEvaluationRecord(copy);
  return copy;
}
