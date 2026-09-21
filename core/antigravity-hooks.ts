import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { hookCommand, isNmzpOwnedHook } from "./install-hooks.ts";

export const ANTIGRAVITY_HOOK_NAME = "nmzp";

function object(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function namedHookHasOwned(v: unknown): boolean {
  if (!object(v)) return false;
  for (const val of Object.values(v)) {
    if (!Array.isArray(val)) continue;
    for (const row of val) {
      if (!object(row) || !Array.isArray(row.hooks)) continue;
      if (row.hooks.some((h) => isNmzpOwnedHook(h))) return true;
    }
  }
  return false;
}

function preToolUseHasOwned(v: unknown): boolean {
  if (!object(v) || !Array.isArray(v.PreToolUse)) return false;
  return v.PreToolUse.some(
    (row) => object(row) && Array.isArray(row.hooks) && row.hooks.some((h) => isNmzpOwnedHook(h)),
  );
}

export function antigravityHooksPath(home: string): string {
  return join(home, ".gemini", "config", "hooks.json");
}

export function antigravityHookDoc(nodePath: string, entry: string, os?: string): Record<string, unknown> {
  return {
    enabled: true,
    PreToolUse: [
      {
        matcher: "*",
        hooks: [
          {
            type: "command",
            command: hookCommand(nodePath, entry, "antigravity", os),
            timeout: 8,
          },
        ],
      },
    ],
  };
}

export function mergeAntigravityHooks(raw: string | null, doc?: Record<string, unknown>): string {
  let parsed: Record<string, unknown>;
  if (raw === null) {
    parsed = {};
  } else {
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      throw Error("antigravity_hooks_corrupt");
    }
    if (!object(value)) throw Error("antigravity_hooks_corrupt");
    parsed = value;
  }
  if (parsed[ANTIGRAVITY_HOOK_NAME] !== undefined && !object(parsed[ANTIGRAVITY_HOOK_NAME])) {
    throw Error("antigravity_hooks_corrupt");
  }
  for (const name of Object.keys(parsed)) {
    if (namedHookHasOwned(parsed[name])) delete parsed[name];
  }
  if (doc) parsed[ANTIGRAVITY_HOOK_NAME] = doc;
  return JSON.stringify(parsed, null, 2) + "\n";
}

export function antigravityHookConfiguredRaw(raw: string): { configured: boolean; enabled: boolean } {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!object(parsed)) return { configured: false, enabled: false };
    for (const value of Object.values(parsed)) {
      if (!preToolUseHasOwned(value) || !object(value)) continue;
      return { configured: true, enabled: value.enabled !== false };
    }
    return { configured: false, enabled: false };
  } catch {
    return { configured: false, enabled: false };
  }
}

export function antigravityHookState(home: string): { present: boolean; configured: boolean; enabled: boolean } {
  const path = antigravityHooksPath(home);
  if (!existsSync(path)) return { present: false, configured: false, enabled: false };
  try {
    const flags = antigravityHookConfiguredRaw(readFileSync(path, "utf8"));
    return { present: true, ...flags };
  } catch {
    return { present: true, configured: false, enabled: false };
  }
}

export function antigravityHookGateError(state: { configured: boolean; enabled: boolean }): string | undefined {
  if (state.configured && !state.enabled) return "hook_disabled";
  return undefined;
}
