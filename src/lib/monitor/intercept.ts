/**
 * Intercept is only real when it happens before bytes leave, or the dest is never dialed.
 * We do not decrypt TLS. A kill after the process started is a race.
 */
import { isTelemetryUrl } from "./cloak.ts";
import type { Decision, EventSource } from "./types.ts";

export type Seal = "pre_exec" | "dest_drop" | "race" | "opaque";

export function sealOf(input: {
  source?: EventSource;
  decision: Decision;
  dest?: string;
  url?: string;
  command?: string;
}): Seal {
  const destish = `${input.dest ?? ""} ${input.url ?? ""} ${input.command ?? ""}`;
  if (input.decision === "rewrite" && (input.source === "hook" || !input.source)) return "pre_exec";
  if (input.decision === "block") {
    if (isTelemetryUrl(destish) || /\b(curl|wget|scp)\b/i.test(input.command ?? "")) {
      if (input.source === "probe") return "race";
      return input.source === "hook" || !input.source ? "pre_exec" : "dest_drop";
    }
    if (input.source === "probe") return "race";
    return "pre_exec";
  }
  return "opaque";
}

export function readsCiphertext() {
  return false;
}
