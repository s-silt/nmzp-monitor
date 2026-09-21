/** Shared by the real installer and UI examples; no Node or browser side effects. */
export const ZCODE_HOOK_EVENTS = [
  "PreToolUse",
  "PermissionRequest",
  "SessionStart",
  "UserPromptSubmit",
  "Stop",
] as const;
export type ZcodeHookEvent = (typeof ZCODE_HOOK_EVENTS)[number];
export const ZCODE_HOOK_MARKER = "NMZP PreToolUse v1";

export function makeZcodeHookGroup(nodePath: string, entry: string): Record<string, unknown> {
  return {
    hooks: [
      {
        type: "process",
        command: nodePath,
        args: [
          "--experimental-strip-types",
          entry,
          "hook",
          "--agent",
          "zcode",
          "--event",
          "PreToolUse",
        ],
        timeoutMs: 8000,
        statusMessage: ZCODE_HOOK_MARKER,
      },
    ],
  };
}

export function zcodeHookEvents(
  group: Record<string, unknown>,
): Record<string, Record<string, unknown>> {
  return Object.fromEntries(
    ZCODE_HOOK_EVENTS.map((event) => [
      event,
      {
        ...group,
        hooks: (group.hooks as Record<string, unknown>[]).map((hook) => {
          const args = [...(hook.args as string[])];
          const index = args.indexOf("--event");
          if (index >= 0) args.splice(index, 2);
          return { ...hook, args: [...args, "--event", event] };
        }),
      },
    ]),
  );
}
