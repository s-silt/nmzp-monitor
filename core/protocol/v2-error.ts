/**
 * v2 error envelope and policy ETag. Pure functions; they do not read contract files.
 * Code is the generated ErrorCode union. retryable and outcome come only from ERROR_DISPOSITION.
 * ETag bytes, including the quotes: "p<version>.<64 lowercase hex>.e<engineRevision>".
 * If-None-Match hits when the header, or one comma-separated segment, is byte-equal to that ETag.
 * Segments are not trimmed. A segment that is "*" or starts with "W/" does not hit.
 */
import type { components } from "./generated/openapi.ts";

export type ErrorCode = components["schemas"]["ErrorCode"];
export type ErrorOutcome = "not_committed" | "unknown" | "rejected";

export interface ErrorDisposition {
  readonly retryable: boolean;
  readonly outcome: ErrorOutcome;
}

/**
 * Constructor table. rejected: this call was refused. not_committed: the write did not land.
 * unknown: do not treat the call as committed. retryable is true only when a later attempt of the same call can succeed.
 */
export const ERROR_DISPOSITION = {
  payload_too_large: { retryable: false, outcome: "rejected" },
  bad_json: { retryable: false, outcome: "rejected" },
  bad_schema: { retryable: false, outcome: "rejected" },
  unauthorized: { retryable: false, outcome: "rejected" },
  forbidden: { retryable: false, outcome: "rejected" },
  not_found: { retryable: false, outcome: "rejected" },
  conflict: { retryable: false, outcome: "rejected" },
  event_conflict: { retryable: false, outcome: "rejected" },
  event_expired: { retryable: false, outcome: "rejected" },
  evaluation_immutable: { retryable: false, outcome: "rejected" },
  bad_receipt: { retryable: false, outcome: "rejected" },
  bad_backfill: { retryable: false, outcome: "rejected" },
  bad_heartbeat: { retryable: false, outcome: "rejected" },
  storage_not_enabled: { retryable: false, outcome: "rejected" },
  processing_stopped: { retryable: true, outcome: "rejected" },
  policy_conflict: { retryable: false, outcome: "not_committed" },
  cas_conflict: { retryable: false, outcome: "not_committed" },
  policy_recovery_required: { retryable: false, outcome: "not_committed" },
  policy_not_committed: { retryable: false, outcome: "not_committed" },
  policy_queue_full: { retryable: true, outcome: "not_committed" },
  audit_storage_unavailable: { retryable: false, outcome: "unknown" },
  probe_proof_required: { retryable: false, outcome: "rejected" },
  internal_error: { retryable: false, outcome: "unknown" },
  input_truncated: { retryable: false, outcome: "rejected" },
  invalid_utf8: { retryable: false, outcome: "rejected" },
  lone_surrogate: { retryable: false, outcome: "rejected" },
  duplicate_member: { retryable: false, outcome: "rejected" },
  depth_exceeded: { retryable: false, outcome: "rejected" },
  extras_exceeded: { retryable: false, outcome: "rejected" },
  pointer_too_long: { retryable: false, outcome: "rejected" },
  event_id_invalid: { retryable: false, outcome: "rejected" },
} as const satisfies Record<ErrorCode, ErrorDisposition>;

export interface PolicyConflictData {
  currentVersion: number;
  currentRulesHash: string;
}

export interface CasConflictData {
  currentVersion: number;
}

export interface V2ErrorBody {
  code: ErrorCode;
  message: string;
  retryable: boolean;
  outcome: ErrorOutcome;
  requestId: string;
  data?: PolicyConflictData | CasConflictData;
}

export interface V2ErrorEnvelope {
  error: V2ErrorBody;
}

interface V2ErrorOptions {
  message: string;
  requestId: string;
  data?: PolicyConflictData | CasConflictData;
}

const SHA256_PREFIXED = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const PREFIXED_HASH = /^sha256:([0-9a-f]{64})$/;

export function v2Error(code: "policy_conflict", opts: { message: string; requestId: string; data: PolicyConflictData }): V2ErrorEnvelope;
export function v2Error(code: "cas_conflict", opts: { message: string; requestId: string; data: CasConflictData }): V2ErrorEnvelope;
export function v2Error(
  code: Exclude<ErrorCode, "policy_conflict" | "cas_conflict">,
  opts: { message: string; requestId: string; data?: never },
): V2ErrorEnvelope;
export function v2Error(code: ErrorCode, opts: V2ErrorOptions): V2ErrorEnvelope {
  if (typeof code !== "string" || !Object.prototype.hasOwnProperty.call(ERROR_DISPOSITION, code)) {
    throw new Error(`v2Error: unknown code ${String(code)}`);
  }
  if (!opts || typeof opts !== "object") throw new Error("v2Error: opts are required");
  const message = requiredText(opts.message, "message");
  const requestId = requiredText(opts.requestId, "requestId");
  const disposition = ERROR_DISPOSITION[code];
  const error: V2ErrorBody = {
    code,
    message,
    retryable: disposition.retryable,
    outcome: disposition.outcome,
    requestId,
  };
  if (code === "policy_conflict") {
    error.data = policyConflictData(opts.data);
  } else if (code === "cas_conflict") {
    error.data = casConflictData(opts.data);
  } else if (opts.data !== undefined) {
    throw new Error(`v2Error: data is forbidden for ${code}`);
  }
  return { error };
}

export function policyETag(input: { version: number; rulesHash: string; engineRevision: number }): string {
  if (!input || typeof input !== "object") throw new Error("policyETag: input is required");
  const version = nonNegativeInt(input.version, "version");
  const engineRevision = nonNegativeInt(input.engineRevision, "engineRevision");
  const hex = rulesHashHex(input.rulesHash);
  return `"p${version}.${hex}.e${engineRevision}"`;
}

export function ifNoneMatchHits(header: string | null | undefined, etag: string): boolean {
  if (typeof header !== "string" || header.length === 0) return false;
  if (typeof etag !== "string" || etag.length === 0) return false;
  for (const part of header.split(",")) {
    if (part.length === 0 || part === "*" || part.startsWith("W/")) continue;
    if (part === etag) return true;
  }
  return false;
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`v2Error: ${label} must be a non-empty string`);
  }
  return value;
}

function nonNegativeInt(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`policyETag: ${label} must be a non-negative safe integer`);
  }
  return value;
}

function rulesHashHex(rulesHash: unknown): string {
  if (typeof rulesHash !== "string") throw new Error("policyETag: rulesHash must be a string");
  if (HEX64.test(rulesHash)) return rulesHash;
  const prefixed = PREFIXED_HASH.exec(rulesHash);
  if (prefixed) return prefixed[1];
  throw new Error("policyETag: rulesHash must be 64 lowercase hex or sha256: plus that hex");
}

function versionOf(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error("v2Error: currentVersion must be an integer >= 0");
  }
  return value;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  const got = Object.keys(value);
  return got.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function policyConflictData(data: unknown): PolicyConflictData {
  if (!data || typeof data !== "object" || Array.isArray(data) || !exactKeys(data, ["currentVersion", "currentRulesHash"])) {
    throw new Error("v2Error: policy_conflict data must be { currentVersion, currentRulesHash }");
  }
  const record = data as PolicyConflictData;
  const currentRulesHash = record.currentRulesHash;
  if (typeof currentRulesHash !== "string" || !SHA256_PREFIXED.test(currentRulesHash)) {
    throw new Error("v2Error: currentRulesHash must be sha256: and 64 lowercase hex");
  }
  return { currentVersion: versionOf(record.currentVersion), currentRulesHash };
}

function casConflictData(data: unknown): CasConflictData {
  if (!data || typeof data !== "object" || Array.isArray(data) || !exactKeys(data, ["currentVersion"])) {
    throw new Error("v2Error: cas_conflict data must be { currentVersion }");
  }
  return { currentVersion: versionOf((data as CasConflictData).currentVersion) };
}

/** Fixed privacy-safe messages for the existing authentication/ownership/not-found meanings. */
export function v2AccessError(code: "unauthorized" | "forbidden" | "not_found", requestId: string) {
  if (code === "unauthorized") {
    return { status: 401 as const, body: v2Error("unauthorized", { message: "Device authentication failed.", requestId }) };
  }
  if (code === "forbidden") {
    return { status: 403 as const, body: v2Error("forbidden", { message: "This device cannot update the event.", requestId }) };
  }
  return { status: 404 as const, body: v2Error("not_found", { message: "The event was not found.", requestId }) };
}
