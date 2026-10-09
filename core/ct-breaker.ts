import { closeSync, fstatSync, mkdirSync, openSync, readSync } from "node:fs";
import { dirname, join } from "node:path";
import { atomicReplaceSync } from "./atomic-file.ts";
import { CT_BREAKER_OPEN_MS, CT_BREAKER_THRESHOLD } from "./constants.ts";

/** Derived breaker file. Missing or illegal contents are a closed breaker. */
export const CT_BREAKER_FILE = "ct-breaker.json";
const MAX_BREAKER_BYTES = 4096;

export interface CtBreakerState {
  consecutiveFailures: number;
  /** Epoch ms when the open window ends. 0 means closed and not half-open. */
  openUntil: number;
}

export const CLOSED_BREAKER: CtBreakerState = { consecutiveFailures: 0, openUntil: 0 };

export type HttpBreakerEffect = "reset" | "connect-failure" | "ignore";
export type CtErrorEffect = "failure" | "reset" | "neutral";

export function breakerPath(home: string): string {
  return join(home, ".nmzp", "run", CT_BREAKER_FILE);
}

function isPlain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseBreaker(value: unknown, now: number): CtBreakerState | undefined {
  if (!isPlain(value) || !Number.isFinite(now)) return undefined;
  const failures = value.consecutiveFailures;
  const openUntil = value.openUntil;
  if (
    typeof failures !== "number" ||
    !Number.isSafeInteger(failures) ||
    failures < 0 ||
    failures > CT_BREAKER_THRESHOLD
  ) {
    return undefined;
  }
  if (typeof openUntil !== "number" || !Number.isSafeInteger(openUntil) || openUntil < 0)
    return undefined;
  if (openUntil > now + CT_BREAKER_OPEN_MS) return undefined;
  return { consecutiveFailures: failures, openUntil };
}

function connectFailuresOpen(failures: number): boolean {
  return failures >= CT_BREAKER_THRESHOLD;
}

function openedAt(now: number): CtBreakerState {
  return { consecutiveFailures: CT_BREAKER_THRESHOLD, openUntil: now + CT_BREAKER_OPEN_MS };
}

/** True only while a legal open window is still in the future. */
export function shouldSkipCt(state: CtBreakerState, now: number): boolean {
  const parsed = parseBreaker(state, now);
  if (!parsed) return false;
  return parsed.openUntil > now;
}

/**
 * Closed: count this failure and open at the threshold.
 * Half-open (cooldown elapsed after a real open): one failure opens another full window.
 * Already open: unchanged. Illegal input counts as the first failure of a closed breaker.
 */
export function nextAfterConnectFailure(state: CtBreakerState, now: number): CtBreakerState {
  if (!Number.isFinite(now)) return CLOSED_BREAKER;
  const current = parseBreaker(state, now) ?? CLOSED_BREAKER;
  if (current.openUntil > now) return current;
  if (connectFailuresOpen(current.consecutiveFailures)) return openedAt(now);
  const failures = current.consecutiveFailures + 1;
  if (connectFailuresOpen(failures)) return openedAt(now);
  return { consecutiveFailures: failures, openUntil: 0 };
}

export function nextAfterReachable(): CtBreakerState {
  return CLOSED_BREAKER;
}

export function effectOfHttpStatus(status: number): HttpBreakerEffect {
  if (!Number.isInteger(status) || status < 100 || status > 599) return "ignore";
  // WP-13b: 4xx and 5xx still prove the TCP/TLS connection reached CT.
  return "reset";
}

export function applyHttpStatus(
  state: CtBreakerState,
  status: number,
  now: number,
): CtBreakerState {
  const effect = effectOfHttpStatus(status);
  if (effect === "reset") return nextAfterReachable();
  if (effect === "connect-failure") return nextAfterConnectFailure(state, now);
  return parseBreaker(state, now) ?? CLOSED_BREAKER;
}

/** Pin mismatch and a response-phase timeout are neutral. Headers already received reset. */
export function ctErrorEffect(error: unknown): CtErrorEffect {
  if (!error || typeof error !== "object") return "neutral";
  const row = error as { phase?: unknown; httpReceived?: unknown };
  if (row.httpReceived === true) return "reset";
  if (row.phase === "connect" || row.phase === "tls") return "failure";
  return "neutral";
}

export function nextStateForCtError(
  state: CtBreakerState,
  error: unknown,
  now: number,
): CtBreakerState {
  const effect = ctErrorEffect(error);
  if (effect === "failure") return nextAfterConnectFailure(state, now);
  if (effect === "reset") return nextAfterReachable();
  return parseBreaker(state, now) ?? CLOSED_BREAKER;
}

export function readBreaker(home: string, now: number): CtBreakerState {
  let fd: number | undefined;
  try {
    fd = openSync(breakerPath(home), "r");
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_BREAKER_BYTES) return CLOSED_BREAKER;
    const buf = Buffer.alloc(stat.size);
    const n = readSync(fd, buf, 0, stat.size, 0);
    if (n !== stat.size) return CLOSED_BREAKER;
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString("utf8"));
    } catch (error) {
      if (error instanceof SyntaxError) return CLOSED_BREAKER;
      throw error;
    }
    return parseBreaker(parsed, now) ?? CLOSED_BREAKER;
  } catch {
    return CLOSED_BREAKER;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // The decision uses the value already chosen above.
      }
    }
  }
}

function sameState(a: CtBreakerState, b: CtBreakerState): boolean {
  return a.consecutiveFailures === b.consecutiveFailures && a.openUntil === b.openUntil;
}

function writeBreaker(home: string, state: CtBreakerState): void {
  try {
    const path = breakerPath(home);
    mkdirSync(dirname(path), { recursive: true });
    atomicReplaceSync(path, JSON.stringify(state));
  } catch {
    // Derived runtime state. A failed write must not change the hook decision.
  }
}

export function recordConnectFailure(home: string, now: number): CtBreakerState {
  let next = CLOSED_BREAKER;
  try {
    next = nextAfterConnectFailure(readBreaker(home, now), now);
  } catch {
    next = nextAfterConnectFailure(CLOSED_BREAKER, now);
  }
  writeBreaker(home, next);
  return next;
}

export function recordCtReachable(home: string): void {
  try {
    const now = Date.now();
    const current = readBreaker(home, now);
    const next = nextAfterReachable();
    if (sameState(current, next)) return;
    writeBreaker(home, next);
  } catch {
    // The caller already has its decision. Closing the breaker is best-effort.
  }
}

export function recordHttpResponse(home: string, status: number, now = Date.now()): void {
  const effect = effectOfHttpStatus(status);
  if (effect === "reset") recordCtReachable(home);
  else if (effect === "connect-failure") recordConnectFailure(home, now);
}
