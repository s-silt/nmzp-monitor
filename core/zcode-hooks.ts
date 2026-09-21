import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { decodeWindowsEncodedCommand } from "./install-hooks.ts";

const MARKER = "NMZP PreToolUse v1";

function object(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function argsHaveZcodeHook(args: unknown): boolean {
  if (!Array.isArray(args)) return false;
  for (let i = 0; i < args.length - 2; i++) {
    if (args[i] === "hook" && args[i + 1] === "--agent" && args[i + 2] === "zcode") return true;
  }
  return false;
}

function own(v: unknown): boolean {
  if (!object(v) || v.statusMessage !== MARKER) return false;
  if (v.type === "process" && argsHaveZcodeHook(v.args)) return true;
  if (v.type === "command" && typeof v.command === "string") {
    return /hook --agent zcode(?:;|\s|$)/.test(decodeWindowsEncodedCommand(v.command) ?? v.command);
  }
  return false;
}

export function zcodeConfigPath(home: string): string {
  return join(home, ".zcode", "cli", "config.json");
}

export function zcodeHookGroup(nodePath: string, entry: string): Record<string, unknown> {
  return {
    hooks: [
      {
        type: "process",
        command: nodePath,
        args: ["--experimental-strip-types", entry, "hook", "--agent", "zcode"],
        timeoutMs: 8000,
        statusMessage: MARKER,
      },
    ],
  };
}

export function mergeZcodeConfig(raw: string | null, group?: Record<string, unknown>): string {
  let doc: Record<string, unknown>;
  if (raw === null) {
    doc = {};
  } else {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw Error("zcode_config_corrupt");
    }
    if (!object(parsed)) throw Error("zcode_config_corrupt");
    doc = parsed;
  }
  if (doc.hooks !== undefined && !object(doc.hooks)) throw Error("zcode_config_corrupt");
  const hooks = object(doc.hooks) ? doc.hooks : {};
  if (hooks.events !== undefined && !object(hooks.events)) throw Error("zcode_config_corrupt");
  const events = object(hooks.events) ? hooks.events : {};
  if (events.PreToolUse !== undefined && !Array.isArray(events.PreToolUse)) throw Error("zcode_config_corrupt");
  const pre = (Array.isArray(events.PreToolUse) ? events.PreToolUse : []).flatMap((row) => {
    if (!object(row) || !Array.isArray(row.hooks)) return [row];
    const kept = row.hooks.filter((h) => !own(h));
    if (kept.length === row.hooks.length) return [row];
    return kept.length ? [{ ...row, hooks: kept }] : [];
  });
  if (group) {
    hooks.enabled = true;
    pre.push(group);
  }
  events.PreToolUse = pre;
  hooks.events = events;
  doc.hooks = hooks;
  return JSON.stringify(doc, null, 2) + "\n";
}

export function zcodeHookConfiguredRaw(raw: string): { configured: boolean; enabled: boolean } {
  try {
    const doc = JSON.parse(raw) as unknown;
    if (!object(doc) || !object(doc.hooks)) return { configured: false, enabled: false };
    const pre = object(doc.hooks.events) ? doc.hooks.events.PreToolUse : undefined;
    const configured =
      Array.isArray(pre) &&
      pre.some((row) => object(row) && Array.isArray(row.hooks) && row.hooks.some(own));
    return { configured, enabled: doc.hooks.enabled === true };
  } catch {
    return { configured: false, enabled: false };
  }
}

export function zcodeHookState(home: string): { present: boolean; configured: boolean; enabled: boolean } {
  const path = zcodeConfigPath(home);
  if (!existsSync(path)) return { present: false, configured: false, enabled: false };
  try {
    const flags = zcodeHookConfiguredRaw(readFileSync(path, "utf8"));
    return { present: true, ...flags };
  } catch {
    return { present: true, configured: false, enabled: false };
  }
}

export function zcodeHookGateError(state: { configured: boolean; enabled: boolean }): string | undefined {
  if (state.configured && !state.enabled) return "hooks_disabled";
  return undefined;
}
