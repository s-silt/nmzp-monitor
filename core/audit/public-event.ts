import { sanitizeAuditText, sanitizeStoredEvent } from "../network-evidence.ts";
import type { StoredEvent } from "../schema.ts";

/** One server-side projection for recent state, history pages and downloads. */
export function publicStoredEvent(event: StoredEvent) {
  const cleaned = sanitizeStoredEvent(event);
  const { evaluation: _evaluation, ...rest } = cleaned;
  return {
    ...rest,
    input: sanitizeAuditText(typeof rest.input === "string" ? rest.input : ""),
    redacted: sanitizeAuditText(typeof rest.redacted === "string" ? rest.redacted : ""),
    dest: rest.dest,
    endpoints: rest.endpoints,
    requestHash: rest.requestHash,
  };
}
