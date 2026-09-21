import type { AgentId, AuditEvent } from "./types";

/** Live board: authenticated devices + the event's own agent. Do not require the process to still be present. */
export function filterLiveEvents(
  events: AuditEvent[],
  opts: { agentFilter: AgentId | "all"; machineFilter: string | "all"; deviceIds: Set<string> },
): AuditEvent[] {
  let rows = events.filter((e) => !e.machineId || opts.deviceIds.has(e.machineId) || opts.deviceIds.size === 0);
  if (opts.machineFilter !== "all") rows = rows.filter((e) => e.machineId === opts.machineFilter);
  if (opts.agentFilter !== "all") rows = rows.filter((e) => e.agent === opts.agentFilter);
  return rows;
}
