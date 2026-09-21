import { ZCODE_HOOK_EVENTS } from "../src/lib/monitor/zcode-hook-config.ts";
import type { HookResult } from "./hook.ts";

export function zcodeEventEnvelope(
  raw: string,
  expected?: string,
): { event?: string; error?: string } {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return { error: "bad_hook_json" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    return { error: "bad_hook_json" };
  const o = value as Record<string, unknown>;
  const aliases = [o.hook_event_name, o.hookEventName, o.event].filter((v) => v !== undefined);
  if (aliases.some((v) => typeof v !== "string" || !v.trim() || v !== aliases[0]))
    return { error: "event_alias_conflict" };
  const event = (aliases[0] as string | undefined) ?? expected ?? "PreToolUse";
  if (expected && event !== expected) return { event: expected, error: "event_mismatch" };
  if (
    !(ZCODE_HOOK_EVENTS as readonly string[]).includes(event) &&
    !["PostToolUse", "PostToolUseFailure"].includes(event)
  )
    return { error: "unsupported_event" };
  return { event };
}

export function zcodePermissionResponse(result: HookResult): HookResult {
  const statusRecord = result.statusRecord
    ? { ...result.statusRecord, eventName: "PermissionRequest" }
    : undefined;
  if (!result.stdout) return { ...result, statusRecord };
  const output = JSON.parse(result.stdout);
  const specific = output.hookSpecificOutput;
  // PermissionRequest 的 allow+updatedInput 会代替宿主批准；不能为改写悄悄绕过审批。
  const reason = specific?.updatedInput
    ? "rewrite_requires_pretooluse"
    : (specific?.permissionDecisionReason ?? "policy");
  return {
    ...result,
    statusRecord,
    stdout:
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PermissionRequest",
          decision: { behavior: "deny", message: reason },
        },
      }) + "\n",
    pendingReceipt: result.pendingReceipt
      ? { ...result.pendingReceipt, enforcement: "returned_deny" }
      : undefined,
  };
}
