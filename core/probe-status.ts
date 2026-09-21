import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFile } from "./install-fs.ts";
import type { Capability } from "./schema.ts";

export const HOOK_STATUS_FILENAME = "hook-status.json";
export const HOOK_STATUS_SCHEMA_VERSION = 1;
export const HOOK_EVIDENCE_TTL_MS = 24 * 60 * 60 * 1000;

/** Contract for the hook worker: write this file only after official stdout success. */
export const HOOK_STATUS_CONTRACT = {
  relativePath: ".nmzp/hook-status.json",
  version: HOOK_STATUS_SCHEMA_VERSION as 1,
  writeWhen: "after official hook stdout has been written successfully",
  agents: [
    "grok",
    "claude",
    "codex",
    "zcode",
    "antigravity",
    "kimi",
    "trae",
    "qwen",
    "qoder",
    "lingma",
    "codebuddy",
    "gemini",
    "cursor",
  ] as const,
  ttlMs: HOOK_EVIDENCE_TTL_MS,
  fields: {
    version: "number, must be 1",
    updatedAt: "number epoch ms",
    hooks: {
      grok: {
        ok: "boolean, true only after stdout success",
        lastSuccessAt: "number epoch ms when ok",
        eventId: "optional string",
        tool: "optional tool name, never raw input",
        error: "optional short code: timeout|exception|deny_failed|...",
      },
      claude: "same shape as grok",
      codex: "same shape; stdout delivery only, not proof host prevented execution",
    },
  },
  heartbeat: {
    success: "capability.active=true",
    offline: "capability.error=offline (missing, stale, or no lastSuccessAt)",
    exception: "capability.error=exception (ok=false or error code)",
  },
  eventReceipts: "events[agent][eventName] records lifecycle/permission delivery only; hooks[agent] remains tool-check coverage",
} as const;

export interface HookAgentStatus {
  ok?: boolean;
  lastSuccessAt?: number;
  eventId?: string;
  tool?: string;
  error?: string;
}

export interface HookStatusFile {
  version: number;
  updatedAt?: number;
  hooks?: Record<string, HookAgentStatus>;
  /** Separate receipts: lifecycle / permission events never prove PreToolUse coverage. */
  events?: Record<string, Record<string, HookAgentStatus>>;
}

export function hookStatusPath(home: string): string {
  return join(home, ".nmzp", HOOK_STATUS_FILENAME);
}

export function emptyHookStatus(): HookStatusFile {
  return { version: HOOK_STATUS_SCHEMA_VERSION, updatedAt: 0, hooks: {} };
}

export function readHookStatus(home: string): HookStatusFile | null {
  const path = hookStatusPath(home);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as HookStatusFile;
    if (!parsed || typeof parsed !== "object" || parsed.version !== HOOK_STATUS_SCHEMA_VERSION) return null;
    return parsed;
  } catch {
    return null;
  }
}

function safeErrorCode(raw?: string): string {
  if (!raw || typeof raw !== "string") return "exception";
  if (!/^[a-z0-9_-]{1,64}$/i.test(raw)) return "exception";
  return raw.toLowerCase();
}

/** Hook worker: record stdout success or a short error code. Never write tool bodies. */
export function recordHookOutcome(
  home: string,
  agent: string,
  outcome: { ok: boolean; eventId?: string; tool?: string; error?: string; at?: number; eventName?: string },
): void {
  const now = outcome.at ?? Date.now();
  const prev = readHookStatus(home) ?? emptyHookStatus();
  const hooks = { ...(prev.hooks ?? {}) };
  const separate = outcome.eventName && outcome.eventName !== "PreToolUse";
  if (separate && !["SessionStart", "UserPromptSubmit", "Stop", "PermissionRequest"].includes(outcome.eventName!)) return;
  const cur: HookAgentStatus = { ...(separate ? prev.events?.[agent]?.[outcome.eventName!] : hooks[agent]) };
  if (outcome.ok) {
    cur.ok = true;
    cur.lastSuccessAt = now;
    cur.error = undefined;
    if (outcome.eventId) cur.eventId = outcome.eventId;
    if (outcome.tool) cur.tool = outcome.tool;
  } else {
    cur.ok = false;
    cur.error = safeErrorCode(outcome.error);
  }
  if (!separate) hooks[agent] = cur;
  const events = { ...prev.events };
  if (separate) events[agent] = { ...events[agent], [outcome.eventName!]: cur };
  const next: HookStatusFile = { version: HOOK_STATUS_SCHEMA_VERSION, updatedAt: now, hooks, ...(Object.keys(events).length ? { events } : {}) };
  atomicWriteFile(hookStatusPath(home), JSON.stringify(next), 0o600);
}

export function hookCapability(
  id: string,
  configured: boolean,
  agent: string,
  status: HookStatusFile | null,
  now: number,
  opts?: { supported?: boolean; unsupportedError?: string; gateError?: string },
): Capability {
  if (opts?.supported === false) {
    return { id, supported: false, active: false, error: opts.unsupportedError ?? "not_implemented" };
  }
  if (!configured) return { id, supported: true, active: false, error: "hook_not_installed" };
  const ev = status?.hooks?.[agent];
  /** Host will not run the hook (e.g. Codex trust): never active, even with a fresh receipt. */
  if (opts?.gateError) {
    const last = ev?.ok === true && typeof ev.lastSuccessAt === "number" ? ev.lastSuccessAt : undefined;
    return { id, supported: true, active: false, error: safeErrorCode(opts.gateError), ...(last ? { lastSuccess: last } : {}) };
  }
  if (!ev) return { id, supported: true, active: false, error: "offline" };
  if (ev.ok === false) return { id, supported: true, active: false, error: safeErrorCode(ev.error) };
  const fresh =
    ev.ok === true &&
    typeof ev.lastSuccessAt === "number" &&
    Number.isFinite(ev.lastSuccessAt) && ev.lastSuccessAt > 0 && ev.lastSuccessAt <= now &&
    now - ev.lastSuccessAt <= HOOK_EVIDENCE_TTL_MS;
  if (fresh) return { id, supported: true, active: true, lastSuccess: ev.lastSuccessAt };
  return { id, supported: true, active: false, lastSuccess: ev.lastSuccessAt, error: "offline" };
}
