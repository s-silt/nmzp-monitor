/** Pure hook response wrappers shared by the runtime and canonical adapter. No I/O. */
import { formatHookResponse, type HookAgent } from "./hook-protocol.ts";

export function deny(
  agent: HookAgent | "unknown",
  reason: string,
  argMap?: Record<string, string>,
) {
  return formatHookResponse(
    agent === "unknown" ? "grok" : agent,
    { decision: "deny", reason },
    argMap ? { argMap } : undefined,
  );
}

/** Pass / rewrite: protocol formats empty success or updatedInput-only (no forced allow). */
export function pass(
  agent: HookAgent | "unknown",
  reason: string,
  updatedInput?: Record<string, unknown>,
  argMap?: Record<string, string>,
) {
  return formatHookResponse(
    agent === "unknown" ? "grok" : agent,
    {
      decision: "allow",
      reason,
      updatedInput,
    },
    argMap ? { argMap } : undefined,
  );
}
