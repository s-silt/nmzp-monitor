/**
 * Minimal process snapshot for the probe.
 * Lists ONLY watch-allowlist agent binaries — never browsers, terminals, or user shells.
 */
import { agentFromBin, basename, isNeverBin, isWatchedBin } from "./watch.ts";
import type { AgentId } from "./types.ts";

export interface WatchedProc {
  proc: string;
  agent: AgentId;
}

/** Classify a raw process name against the agent allowlist. */
export function classifyWatchedProc(name: string | undefined): AgentId | undefined {
  const b = basename(name);
  if (!b) return undefined;
  if (isNeverBin(b)) return undefined;
  if (!isWatchedBin(b)) return undefined;
  return agentFromBin(b);
}

/** Filter a process-name list down to allowlisted agent binaries only. */
export function filterWatchedProcs(names: string[]): WatchedProc[] {
  const out: WatchedProc[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    const agent = classifyWatchedProc(name);
    if (!agent) continue;
    const proc = basename(name);
    const key = `${agent}:${proc}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ proc, agent });
  }
  return out;
}

/** Observation body for POST /ingest with source=probe (snapshot). */
export function buildProbeSnapshotObservation(proc: string, agent: AgentId) {
  return {
    source: "probe" as const,
    tool: "snapshot",
    nativeTool: "snapshot",
    agent,
    proc,
    command: `process-snapshot ${proc}`,
    hookBlind: true,
  };
}
