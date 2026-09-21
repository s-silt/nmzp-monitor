/**
 * Inbound traffic is observation, never instruction.
 * The core computes decisions. Payloads cannot change rules, mode, or run code.
 */
import { parseHookPayload } from "./ingest.ts";
import type { EvalInput } from "./engine.ts";

/** Keys that would mean "tell the core what to do". Presence = drop. */
const CONTROL_KEYS = [
  "decision",
  "intervention",
  "customRules",
  "rules",
  "eval",
  "script",
  "exec",
  "spawn",
  "join",
  "token",
  "paused",
] as const;

const JOIN_PIPE_RE = /\bcurl\b[\s\S]{0,80}\|\s*(sh|bash|zsh)\b/i;
const REMOTE_INSTALL_RE =
  /\b(docker\s+pull|npm\s+i(nstall)?|npx\b|pip3?\s+install|curl\b|wget\b|ghcr\.io|docker\.io\/|github\.com\/)/i;

export function joinIsPipeToShell(cmd: string) {
  return JOIN_PIPE_RE.test(cmd);
}

export function installTalksToRegistry(cmd: string) {
  return REMOTE_INSTALL_RE.test(cmd);
}

export function hasControlKeys(raw: string): boolean {
  if (typeof raw !== "string") return false;
  try {
    const v = JSON.parse(raw.trim()) as unknown;
    if (!v || typeof v !== "object" || Array.isArray(v)) return false;
    return CONTROL_KEYS.some((k) => Object.prototype.hasOwnProperty.call(v, k));
  } catch {
    return false;
  }
}

/** The only ingest door. Observation or nothing. Never a command to this process. */
export function ingestObservation(raw: string): EvalInput | null {
  if (hasControlKeys(raw)) return null;
  return parseHookPayload(raw);
}
