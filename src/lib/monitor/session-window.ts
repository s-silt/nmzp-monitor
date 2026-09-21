import { correlate, markFrom, pushHit, type WindowHit } from "./correlate.ts";
import type { EvalInput, EvalResult } from "./engine.ts";
import type { Intervention } from "./types.ts";
import { isWatchedProcess } from "./watch.ts";

/** Cap session keys so CT memory cannot grow without bound. Drop oldest first. */
export const MAX_SESSION_KEYS = 64;
/** Per-window eventId ring. Dedup is scoped to the window key, never global. */
export const MAX_SEEN_EVENT_IDS = 128;

function windowKey(input: EvalInput): string {
  const device = typeof input.deviceId === "string" ? input.deviceId.trim().slice(0, 256) : "";
  const agent = input.agent ?? "";
  const session = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
  return `${device}\0${agent}\0${session}`;
}

/**
 * CT-path correlate windows keyed by deviceId+agent+sessionId.
 * Missing/blank sessionId never stitches — single-event evaluate still applies.
 * Old callers without deviceId share the empty-device bucket (compat).
 */
export class SessionWindows {
  private readonly sessions = new Map<string, WindowHit[]>();
  private readonly seen = new Map<string, string[]>();

  apply(
    input: EvalInput,
    result: EvalResult,
    intervention: Intervention,
    ts: number = Date.now(),
  ): EvalResult {
    if (result.skipped) return result;
    if (!isWatchedProcess({ proc: input.proc, parentProc: input.parentProc, source: input.source, agent: input.agent })) {
      return result;
    }

    const sessionId = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
    if (!sessionId) return result;

    const mark = markFrom({
      command: input.command ?? "",
      filePath: input.filePath ?? "",
      tool: result.tool || input.nativeTool,
      dest: input.dest ?? input.url,
    });
    if (!mark) return result;

    const key = windowKey(input);
    const eventId = typeof input.eventId === "string" ? input.eventId.trim().slice(0, 256) : "";
    const prev = this.sessions.get(key);
    const linked = correlate(prev ?? [], mark, ts);
    const duplicate = eventId !== "" && (this.seen.get(key) ?? []).includes(eventId);
    if (!duplicate) {
      if (eventId) this.remember(key, eventId);
      this.sessions.delete(key);
      this.sessions.set(key, pushHit(prev, { ts, mark }));
      this.prune();
    } else {
      this.sessions.delete(key);
      this.sessions.set(key, prev ?? []);
    }

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

  clear(): void {
    this.sessions.clear();
    this.seen.clear();
  }

  get size(): number {
    return this.sessions.size;
  }

  private remember(key: string, eventId: string): void {
    const list = this.seen.get(key) ?? [];
    list.push(eventId);
    if (list.length > MAX_SEEN_EVENT_IDS) list.splice(0, list.length - MAX_SEEN_EVENT_IDS);
    this.seen.set(key, list);
  }

  private prune(): void {
    while (this.sessions.size > MAX_SESSION_KEYS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
      this.seen.delete(oldest);
    }
  }
}

export const liveWindows = new SessionWindows();

export function applySessionCorrelate(
  input: EvalInput,
  result: EvalResult,
  intervention: Intervention,
  ts?: number,
): EvalResult {
  return liveWindows.apply(input, result, intervention, ts ?? Date.now());
}
