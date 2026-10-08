import { validateEvaluateStrict } from "./generated/evaluate-validator.ts";
import {
  eventIdProblem,
  longestPointerUtf8,
  MAX_EXTRA_FIELDS,
  MAX_POINTER_UTF8,
  strictJsonScan,
  v1JsonText,
  type AdapterErrorCode,
  type CanonicalContents,
  type CanonicalField,
  type CanonicalToolEvent,
} from "./v2-adapter.ts";

/** IC-10 SWITCHED（2026-10-08，路由层）。v1 永不严格。 */
export const V2_ROUTE_STRICT_INGRESS: boolean = true;

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function parseStrictV2Json(
  bytes: Uint8Array,
): { ok: true; value: unknown } | { ok: false; code: AdapterErrorCode } {
  let text: string;
  try {
    text = STRICT_UTF8.decode(bytes);
  } catch {
    return { ok: false, code: "invalid_utf8" };
  }
  const normalized = v1JsonText(text);
  const scanned = strictJsonScan(normalized);
  if (scanned) return { ok: false, code: scanned.errorCode };
  try {
    return { ok: true, value: JSON.parse(normalized) };
  } catch {
    return { ok: false, code: "bad_json" };
  }
}

/** Compat schema has already passed. Limit codes stay distinct from bad_schema. */
export function strictEvaluateProblem(event: CanonicalToolEvent): AdapterErrorCode | "bad_schema" | null {
  if (eventIdProblem(event.eventId)) return "event_id_invalid";
  if (event.extraFields.length > MAX_EXTRA_FIELDS) return "extras_exceeded";
  const pointerUtf8 = longestPointerUtf8([
    ...Object.entries(event.fields).flatMap(([name, field]) => name === "contents"
      ? (field as CanonicalContents).leaves.map((leaf) => leaf.provenance)
      : [(field as CanonicalField).provenance]),
    ...event.extraFields.map((item) => item.path),
  ]);
  if (pointerUtf8 > MAX_POINTER_UTF8) return "pointer_too_long";
  if (!validateEvaluateStrict(event)) return "bad_schema";
  return null;
}
