import type { Enforcement } from "./schema.ts";

const ENFORCEMENT = new Set<Enforcement>([
  "blocked", "returned_deny", "pending_verify", "timeout", "failed", "delivered", "offline", "degraded",
]);

export interface ReceiptBody {
  eventId: string;
  evaluation?: unknown;
  enforcement: Enforcement;
}

/** Exact legacy JSON predicate: null throws; truthy non-string ids are not newly rejected. */
export function parseLegacyReceiptBody(raw: unknown): ReceiptBody | null {
  // The cast deliberately preserves the old HTTP handler's runtime behavior.
  const body = raw as ReceiptBody;
  if (!body.eventId || !body.enforcement || !ENFORCEMENT.has(body.enforcement)) return null;
  return { eventId: body.eventId, evaluation: body.evaluation, enforcement: body.enforcement };
}

/** Candidate v2 shape: object + nonempty string id; unknown fields are not retained. */
export function parseReceiptBody(raw: unknown): ReceiptBody | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const body = raw as Record<string, unknown>;
  if (typeof body.eventId !== "string") return null;
  return parseLegacyReceiptBody(raw);
}

/** A falsy evaluation never requests a change in v1. Do not coerce or add an enum. */
export function receiptEvaluationChanges(body: ReceiptBody, evaluation: unknown): boolean {
  return Boolean(body.evaluation) && body.evaluation !== evaluation;
}
