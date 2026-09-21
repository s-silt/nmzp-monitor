/**
 * Persist session correlate marks only (no original command/tool body).
 * Cross-process, file-locked, bounded, expired. Used by offline hook.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { withFileLock } from "./persist.ts";
import type { MonitorMods } from "./paths.ts";

const MAX_SESSION_KEYS = 64;
const MAX_SEEN_EVENT_IDS = 128;
const MAX_HITS = 48;
const WINDOW_MS = 120_000;

export interface StoredHit {
  ts: number;
  mark: string;
}

export interface WindowState {
  keys: Record<string, { hits: StoredHit[]; seen: string[]; lastTs: number }>;
}

function windowKey(input: { deviceId?: string; agent?: string; sessionId?: string }): string {
  const device = typeof input.deviceId === "string" ? input.deviceId.trim().slice(0, 256) : "";
  const agent = input.agent ?? "";
  const session = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
  return `${device}\0${agent}\0${session}`;
}

export function emptyWindowState(): WindowState {
  return { keys: {} };
}

export function loadWindowState(path: string): WindowState {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as WindowState;
    if (!raw || typeof raw !== "object" || !raw.keys) return emptyWindowState();
    return raw;
  } catch {
    return emptyWindowState();
  }
}

export function saveWindowState(path: string, state: WindowState): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(state), { mode: 0o600 });
}

function pruneState(state: WindowState, now: number): void {
  for (const [k, v] of Object.entries(state.keys)) {
    v.hits = v.hits.filter((h) => now - h.ts <= WINDOW_MS).slice(-MAX_HITS);
    if (!v.hits.length && now - v.lastTs > WINDOW_MS) delete state.keys[k];
  }
  const ids = Object.keys(state.keys);
  if (ids.length <= MAX_SESSION_KEYS) return;
  const ordered = ids.sort((a, b) => (state.keys[a]!.lastTs ?? 0) - (state.keys[b]!.lastTs ?? 0));
  for (const k of ordered.slice(0, ids.length - MAX_SESSION_KEYS)) delete state.keys[k];
}

export function applyStoredWindow(
  mods: MonitorMods,
  state: WindowState,
  input: Record<string, unknown>,
  result: {
    skipped?: boolean;
    tool?: string;
    decision: string;
    rewritten?: boolean;
    threat?: string;
    risk?: string;
    action?: string;
    correlateHit?: boolean;
  },
  intervention: string,
  ts: number,
): typeof result {
  if (result.skipped) return result;
  if (
    !mods.isWatchedProcess({
      proc: typeof input.proc === "string" ? input.proc : undefined,
      parentProc: typeof input.parentProc === "string" ? input.parentProc : undefined,
      source: input.source === "probe" ? "probe" : "hook",
      agent: typeof input.agent === "string" ? input.agent : undefined,
    })
  ) {
    return result;
  }
  const sessionId = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
  if (!sessionId) return result;
  const mark = mods.markFrom({
    command: typeof input.command === "string" ? input.command : "",
    filePath: typeof input.filePath === "string" ? input.filePath : "",
    tool: String(result.tool || input.nativeTool || ""),
    dest: typeof input.dest === "string" ? input.dest : typeof input.url === "string" ? input.url : undefined,
  });
  if (!mark) return result;
  const key = windowKey({
    deviceId: typeof input.deviceId === "string" ? input.deviceId : undefined,
    agent: typeof input.agent === "string" ? input.agent : undefined,
    sessionId,
  });
  pruneState(state, ts);
  const slot = state.keys[key] ?? { hits: [], seen: [], lastTs: ts };
  const eventId = typeof input.eventId === "string" ? input.eventId.trim().slice(0, 256) : "";
  const linked = mods.correlate(slot.hits, mark, ts);
  const duplicate = eventId !== "" && slot.seen.includes(eventId);
  if (!duplicate) {
    if (eventId) {
      slot.seen.push(eventId);
      if (slot.seen.length > MAX_SEEN_EVENT_IDS) slot.seen.splice(0, slot.seen.length - MAX_SEEN_EVENT_IDS);
    }
    slot.hits = mods.pushHit(slot.hits, { ts, mark });
    slot.lastTs = ts;
    state.keys[key] = slot;
  } else {
    state.keys[key] = slot;
  }
  pruneState(state, ts);
  if (linked) {
    result.correlateHit = true;
    result.threat = linked;
    result.risk = "high";
    result.action = "block";
    if (intervention === "enforcing" && result.decision !== "block") {
      result.decision = "block";
      result.rewritten = false;
    }
  }
  return result;
}

export class FileSessionWindows {
  private readonly path: string;
  private readonly mods: MonitorMods;
  constructor(path: string, mods: MonitorMods) {
    this.path = path;
    this.mods = mods;
  }

  apply(input: unknown, result: unknown, intervention: unknown, ts: number = Date.now()): unknown {
    const state = loadWindowState(this.path);
    const next = applyStoredWindow(
      this.mods,
      state,
      (input ?? {}) as Record<string, unknown>,
      result as Parameters<typeof applyStoredWindow>[3],
      String(intervention ?? ""),
      ts,
    );
    saveWindowState(this.path, state);
    return next;
  }

  async transact<T>(fn: (w: FileSessionWindows) => T | Promise<T>, timeoutMs = 400): Promise<T> {
    return withFileLock(dirname(this.path), async () => fn(this), { timeoutMs });
  }
}
