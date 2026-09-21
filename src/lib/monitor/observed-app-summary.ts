import { adapterById, discoveryStale, type DiscoveredAgent } from "./agent-discovery.ts";
import { formatDateTime } from "./format.ts";
import type { Machine } from "./types.ts";

export type ObservedAppProcess = {
  pid: number;
  startedAt: number;
  startedAtText: string;
};

export type ObservedAppInstall = {
  instanceId: string;
  adapterId: string;
  product: string;
  form: "cli" | "desktop" | "extension";
  candidate: boolean;
  runningLabel: string;
  processes: ObservedAppProcess[];
};

export type ObservedAppSummary = {
  status: "unknown" | "observed" | "none";
  count: number;
  headline: string;
  note: string;
  apps: ObservedAppInstall[];
};

const OBSERVED_NOTE =
  "来自本机自动发现的应用进程，不等于正在执行 Agent 任务，也不表示已保护。";
const UNKNOWN_NOTE =
  "过期、无报告、连接中断或部分扫描没有观测时，不能判断应用进程是否在运行。";

function scopedMachines(machines: readonly Machine[], host: string): Machine[] {
  if (host === "all") return [...machines];
  return machines.filter((m) => m.id === host);
}

export function observedRunningLabel(item: {
  running: string;
  installation?: string;
  identity?: string;
}): string {
  if (item.running !== "observed") return "";
  return item.installation === "candidate" || item.identity === "candidate"
    ? "候选应用进程"
    : "观察到应用进程";
}

function liveProcesses(item: DiscoveredAgent): Array<{ pid: number; startedAt: number }> {
  if (item.running !== "observed") return [];
  const seen = new Set<string>();
  const out: Array<{ pid: number; startedAt: number }> = [];
  for (const p of item.processes) {
    if (!Number.isSafeInteger(p.pid) || p.pid <= 0) continue;
    const key = `${p.pid}:${p.startedAt}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ pid: p.pid, startedAt: p.startedAt });
  }
  return out;
}

export function summarizeObservedAppProcesses(
  machines: readonly Machine[],
  input: { host: string; now: number; disconnected: boolean },
): ObservedAppSummary {
  const unknown = (): ObservedAppSummary => ({
    status: "unknown",
    count: 0,
    headline: "未知",
    note: UNKNOWN_NOTE,
    apps: [],
  });
  if (input.disconnected) return unknown();
  const scoped = scopedMachines(machines, input.host);
  if (!scoped.length) return unknown();
  const usable = scoped.filter((m) => m.discovery && !discoveryStale(m.discovery, input.now));
  if (!usable.length) return unknown();

  const apps: ObservedAppInstall[] = [];
  let completeWithoutObservation = false;
  let incompleteWithoutObservation = false;
  for (const m of usable) {
    const snapshot = m.discovery!;
    const rows: ObservedAppInstall[] = [];
    for (const it of snapshot.items) {
      const processes = liveProcesses(it);
      if (!processes.length) continue;
      const a = adapterById(it.adapterId);
      if (!a) continue;
      const candidate = it.installation === "candidate" || it.identity === "candidate";
      rows.push({
        instanceId: it.instanceId,
        adapterId: it.adapterId,
        product: a.product,
        form: a.form,
        candidate,
        runningLabel: observedRunningLabel(it),
        processes: processes.map((p) => ({
          pid: p.pid,
          startedAt: p.startedAt,
          startedAtText: `${formatDateTime(p.startedAt, "zh")} UTC+8`,
        })),
      });
    }
    if (rows.length) apps.push(...rows);
    else if (snapshot.status === "ok") completeWithoutObservation = true;
    else incompleteWithoutObservation = true;
  }
  if (apps.length) {
    return {
      status: "observed",
      count: apps.length,
      headline: `已观察到应用进程 (${apps.length})`,
      note: OBSERVED_NOTE,
      apps,
    };
  }
  if (incompleteWithoutObservation) return unknown();
  if (completeWithoutObservation) {
    return {
      status: "none",
      count: 0,
      headline: "本次检查未观察到应用进程",
      note: OBSERVED_NOTE,
      apps: [],
    };
  }
  return unknown();
}

export function legacyAuditIdentityTitle(opts: {
  collectedCount: number;
  identityLabel: string;
}): string {
  if (opts.collectedCount <= 0) return "审计进程归属记录";
  return `${opts.identityLabel} · 审计进程归属记录 (${opts.collectedCount})`;
}
