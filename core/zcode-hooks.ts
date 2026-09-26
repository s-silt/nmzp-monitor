import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isNmzpOwnedHook } from "./install-hooks.ts";
import {
  makeZcodeHookGroup,
  zcodeHookEvents,
  ZCODE_HOOK_EVENTS,
  ZCODE_HOOK_MARKER,
} from "../src/lib/monitor/zcode-hook-config.ts";

const MARKER = ZCODE_HOOK_MARKER;

function object(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function nodeExecutable(exe: string): boolean {
  const cut = Math.max(exe.lastIndexOf("/"), exe.lastIndexOf("\\"));
  const base = cut >= 0 ? exe.slice(cut + 1) : exe;
  const name = base.toLowerCase();
  return name === "node" || name === "node.exe";
}

function nmzpEntry(entry: string): boolean {
  if (!entry || entry.endsWith("/") || entry.endsWith("\\")) return false;
  const parts = entry.split(/[/\\]/);
  return parts[parts.length - 1] === "nmzp.mjs";
}

/** Process argv from makeZcodeHookGroup / zcodeHookEvents. Echo text in args is not this shape. */
function zcodeProcessOwned(exe: unknown, args: unknown): boolean {
  if (typeof exe !== "string" || !nodeExecutable(exe) || !Array.isArray(args) || args.some((part) => typeof part !== "string")) {
    return false;
  }
  const list = args as string[];
  let index = 0;
  if (list[index] === "--experimental-strip-types") index += 1;
  const entry = list[index];
  if (entry === undefined || !nmzpEntry(entry)) return false;
  if (list[index + 1] !== "hook" || list[index + 2] !== "--agent" || list[index + 3] !== "zcode") return false;
  if (list.length === index + 4) return true;
  return list.length === index + 6 && list[index + 4] === "--event" && list[index + 5]!.length > 0;
}

function own(v: unknown): boolean {
  if (!object(v) || v.statusMessage !== MARKER) return false;
  if (v.type === "process") return zcodeProcessOwned(v.command, v.args);
  if (v.type === "command" && typeof v.command === "string") return isNmzpOwnedHook(v);
  return false;
}

export function zcodeConfigPath(home: string): string {
  return join(home, ".zcode", "cli", "config.json");
}

export function zcodeHookGroup(nodePath: string, entry: string): Record<string, unknown> {
  return makeZcodeHookGroup(nodePath, entry);
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
  const additions = group ? zcodeHookEvents(group) : undefined;
  for (const event of ZCODE_HOOK_EVENTS) {
    if (events[event] !== undefined && !Array.isArray(events[event]))
      throw Error("zcode_config_corrupt");
    const pre = (Array.isArray(events[event]) ? events[event] : []).flatMap((row) => {
      if (!object(row) || !Array.isArray(row.hooks)) return [row];
      const kept = row.hooks.filter((h) => !own(h));
      if (kept.length === row.hooks.length) return [row];
      return kept.length ? [{ ...row, hooks: kept }] : [];
    });
    if (additions) {
      hooks.enabled = true;
      pre.push(additions[event]);
    }
    if (pre.length || events[event] !== undefined || event === "PreToolUse") events[event] = pre;
  }
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

export function zcodeHookState(home: string): {
  present: boolean;
  configured: boolean;
  enabled: boolean;
} {
  const path = zcodeConfigPath(home);
  if (!existsSync(path)) return { present: false, configured: false, enabled: false };
  try {
    const flags = zcodeHookConfiguredRaw(readFileSync(path, "utf8"));
    return { present: true, ...flags };
  } catch {
    return { present: true, configured: false, enabled: false };
  }
}

export function zcodeHookGateError(state: {
  configured: boolean;
  enabled: boolean;
}): string | undefined {
  if (state.configured && !state.enabled) return "hooks_disabled";
  return undefined;
}
