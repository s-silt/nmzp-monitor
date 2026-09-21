import { classifyRelay } from "./relay.ts";
import { classifySnapshot } from "./snapshot.ts";
import type { Actor, AgentId, EventSource } from "./types";

/**
 * Process = the agent binary itself (silent snapshot, telemetry, no tool call).
 * Model  = a tool the model asked to run (PreToolUse / PostToolUse).
 * Relay  = the call went through a 中转站, not the vendor's model API.
 */
export function classifyActor(input: {
  source?: EventSource;
  nativeTool?: string;
  command?: string;
  dest?: string;
  url?: string;
  agent?: AgentId;
  hookBlind?: boolean;
}): Actor {
  const relay = classifyRelay({ dest: input.dest, url: input.url, command: input.command });
  if (relay === "relay" || relay === "poison") return "relay";

  const snap = classifySnapshot({
    agent: input.agent,
    nativeTool: input.nativeTool,
    command: input.command,
    dest: input.dest,
    url: input.url,
    source: input.source,
  });
  if (snap) return "process";

  // hookBlind/probe → attribute as process; caller must still evaluate (never treat as allow).
  if (input.hookBlind || input.source === "probe") {
    if (input.nativeTool === "snapshot") return "process";
    return "process";
  }
  return "model";
}
