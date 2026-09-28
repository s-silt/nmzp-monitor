import {
  readHookObservation,
  readListeners,
  readRole,
  readServiceState,
  resolveDataDir,
  resolveHome,
  type HookObservation,
  type InspectContext,
} from "./inspect.ts";
import { HOOK_OBSERVED_WINDOW_MS, type DoctorRole } from "./report.ts";

export interface StatusExtras {
  role: DoctorRole;
  service: "running" | "stopped" | null;
  listeners: Array<{ name: "ct"; host: string; port: number }>;
  lastHookObserved: Record<string, string | null> | null;
}

export async function readStatusExtras(
  input: {
    home?: string;
    dataDir?: string;
    env?: NodeJS.ProcessEnv;
    nowMs?: number;
    events?: unknown;
    service?: "running" | "stopped" | null;
  } = {},
): Promise<StatusExtras> {
  const env = input.env ?? process.env;
  const home = resolveHome(env, input.home);
  const dataDir = resolveDataDir(env, input.dataDir);
  const nowMs = input.nowMs ?? Date.now();
  const role = await readRole(home, dataDir);
  const ctx: InspectContext = { home, dataDir, env, nowMs, role, extraEvents: input.events };
  const service = input.service !== undefined ? input.service : await readServiceState(home, dataDir);
  const listeners = await readListeners(dataDir);
  const observed = await readHookObservation(ctx);
  return { role, service, listeners, lastHookObserved: hookMap(observed, nowMs) };
}

function hookMap(observed: HookObservation, nowMs: number): Record<string, string | null> | null {
  const hosts = [...new Set([...observed.configured, ...observed.observed])].sort();
  if (hosts.length === 0) return null;
  const out: Record<string, string | null> = {};
  for (const host of hosts) {
    const ts = observed.latest.get(host);
    out[host] =
      typeof ts === "number" && ts >= nowMs - HOOK_OBSERVED_WINDOW_MS && ts <= nowMs + 60_000
        ? new Date(ts).toISOString()
        : null;
  }
  return out;
}
