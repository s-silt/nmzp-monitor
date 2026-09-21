import { AGENT_ORDER } from "./agents.ts";
import type { AgentId, AuditEvent, DeviceCapability, Machine, MachineStatus, ProbeIdentity, Session } from "./types.ts";

export function filterSessions(sessions: Session[], agentFilter: string, machineId: string = "all") {
  let rows = sessions;
  if (machineId !== "all") rows = rows.filter((s) => s.machineId === machineId);
  if (agentFilter === "all") return rows;
  return rows.filter((s) => s.agent === agentFilter);
}

export function filterEvents(events: AuditEvent[], agentFilter: AgentId | "all", machineId: string, present: AgentId[]) {
  let rows = events;
  if (machineId !== "all") rows = rows.filter((e) => e.machineId === machineId);
  const effective = agentFilter !== "all" && present.includes(agentFilter) ? agentFilter : "all";
  if (effective === "all") return rows.filter((e) => present.includes(e.agent));
  return rows.filter((e) => e.agent === effective);
}

/** Agents this machine actually has — running session or live probe. Never the catalog. */
export function presentAgents(sessions: Session[], identities: ProbeIdentity[], machineId: string = "all"): AgentId[] {
  const sess = machineId === "all" ? sessions : sessions.filter((s) => s.machineId === machineId);
  const ident = machineId === "all" ? identities : identities.filter((i) => i.machineId === machineId);
  const seen = new Set<AgentId>();
  const out: AgentId[] = [];
  const add = (id: AgentId) => {
    if (seen.has(id)) return;
    seen.add(id);
    out.push(id);
  };
  for (const id of AGENT_ORDER) {
    if (sess.some((s) => s.agent === id && s.status === "running") || ident.some((i) => i.agent === id)) add(id);
  }
  return out;
}

export function presentModels(sessions: Session[], agentFilter: string, machineId: string = "all"): string[] {
  const rows = filterSessions(sessions, agentFilter, machineId).filter((s) => s.status === "running");
  const out: string[] = [];
  for (const s of rows) {
    const m = s.detectedModel || s.model;
    if (m && !out.includes(m)) out.push(m);
  }
  return out;
}

export interface MachineView extends Machine {
  high: number;
  isolate: number;
  poison: number;
  blocked: number;
}

export const HEARTBEAT_MS = 90_000;
export const ARCHIVE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

export function deriveMachineStatus(machine: Machine, _events: AuditEvent[] = [], now = Date.now()): MachineStatus {
  if (now - machine.lastSeen >= ARCHIVE_AFTER_MS) return "archived";
  if (now - machine.lastSeen > HEARTBEAT_MS) return "dark";
  return "online";
}

export function machineRollup(machines: Machine[], events: AuditEvent[], now = Date.now()): MachineView[] {
  return machines.map((m) => {
    const mine = events.filter((e) => e.machineId === m.id);
    return {
      ...m,
      status: deriveMachineStatus(m, events, now),
      high: mine.filter((e) => e.risk === "high" && (e.decision === "block" || e.decision === "rewrite")).length,
      isolate: mine.filter((e) => e.threat === "isolate").length,
      poison: mine.filter((e) => e.threat === "poison").length,
      blocked: mine.filter((e) => e.enforcement === "blocked").length,
    };
  });
}

/** A host is in scope only after it has joined (attachedAt set). */
export function isJoinedHost(machine: { attachedAt: number }): boolean {
  return machine.attachedAt > 0;
}

/** Overview: joined hosts that have not been dark for 7 days. Never-joined are out of scope. */
export function overviewMachines(views: MachineView[]): MachineView[] {
  return views.filter((m) => isJoinedHost(m) && m.status !== "archived");
}

export function effectiveMachineFilter(filter: string, views: MachineView[]): string {
  if (filter === "all") return "all";
  return overviewMachines(views).some((m) => m.id === filter) ? filter : "all";
}

export function isPersistedHostFilter(v: string): boolean {
  return v === "all" || /^(m_|dev_)[A-Za-z0-9_-]+$/.test(v);
}

export function scopedCapabilities(
  machines: Array<{ id: string; capabilities?: Record<string, DeviceCapability> }>,
  host: string,
): Record<string, DeviceCapability> {
  if (host !== "all") {
    const m = machines.find((x) => x.id === host);
    return m?.capabilities ? { ...m.capabilities } : {};
  }
  const out: Record<string, DeviceCapability> = {};
  for (const m of machines) {
    const caps = m.capabilities;
    if (!caps) continue;
    for (const [id, cap] of Object.entries(caps)) {
      const prev = out[id];
      if (!prev) {
        out[id] = { ...cap };
        continue;
      }
      out[id] = {
        supported: prev.supported || cap.supported,
        active: prev.active || cap.active,
        lastSuccess:
          prev.lastSuccess != null && cap.lastSuccess != null
            ? Math.max(prev.lastSuccess, cap.lastSuccess)
            : (cap.lastSuccess ?? prev.lastSuccess),
        error: prev.active || cap.active ? undefined : (prev.error ?? cap.error),
      };
    }
  }
  return out;
}

export interface HookCoverage {
  active: number;
  reporting: number;
  perMachine: Array<{ machineId: string; hostname: string; cap?: DeviceCapability }>;
}

export function hookCoverage(
  machines: Array<{ id: string; hostname: string; capabilities?: Record<string, DeviceCapability> }>,
  host: string,
  agents: readonly string[],
): Record<string, HookCoverage> {
  const out: Record<string, HookCoverage> = {};

  if (host !== "all") {
    const target = machines.find((x) => x.id === host);
    if (!target) {
      for (const agent of agents) {
        out[agent] = { active: 0, reporting: 0, perMachine: [] };
      }
      return out;
    }
    for (const agent of agents) {
      const key = `hook_${agent}`;
      const cap = target.capabilities?.[key];
      const reporting = cap !== undefined ? 1 : 0;
      const active = cap?.active === true ? 1 : 0;
      out[agent] = {
        active,
        reporting,
        perMachine: [{ machineId: target.id, hostname: target.hostname, cap }],
      };
    }
    return out;
  }

  for (const agent of agents) {
    const key = `hook_${agent}`;
    let active = 0;
    let reporting = 0;
    const perMachine = machines.map((m) => {
      const cap = m.capabilities?.[key];
      if (cap !== undefined) {
        reporting++;
        if (cap.active === true) active++;
      }
      return { machineId: m.id, hostname: m.hostname, cap };
    });
    out[agent] = { active, reporting, perMachine };
  }

  return out;
}

/** Pick one host → only that host's rows. "all" → joined, not-yet-archived hosts only. */
export function scopedByHost<T extends { machineId: string }>(
  rows: T[],
  host: string,
  allowed: ReadonlySet<string>,
): T[] {
  if (host !== "all") return rows.filter((r) => r.machineId === host);
  return rows.filter((r) => allowed.has(r.machineId));
}

export function statsFrom(events: AuditEvent[]) {
  const appPre = events.filter((e) => e.layer === "app_pre");
  const count = (pred: (e: AuditEvent) => boolean) => events.filter(pred).length;
  const cat = (c: AuditEvent["category"]) => count((e) => e.category === c);
  return {
    total: events.length,
    blocked: count((e) => e.enforcement === "blocked"),
    returnedDeny: count((e) => e.enforcement === "returned_deny"),
    confirm: count((e) => e.decision === "confirm"),
    rewrite: count((e) => e.decision === "rewrite" || Boolean(e.rewritten)),
    toolCalls: appPre.length,
    mcp: cat("mcp"),
    skill: cat("skill"),
    subagent: cat("subagent"),
    reads: cat("file_read"),
    writes: cat("file_write"),
    edits: cat("file_edit"),
    deletes: cat("file_delete"),
    pip: cat("install_pip"),
    sys: cat("install_sys"),
    npm: cat("install_npm"),
    otherInstall: cat("install_other"),
    git: cat("git"),
    ssh: cat("ssh"),
    download: cat("download"),
    docker: cat("docker"),
    archive: cat("archive"),
    process: cat("process"),
    sensitive: cat("sensitive"),
    screenshot: cat("screenshot"),
    exfil: count((e) => e.threat === "exfil" || e.category === "exfil"),
    secrets: count((e) => e.threat === "secret" || (e.secretKinds?.length ?? 0) > 0),
    tamper: count((e) => e.threat === "tamper"),
    isolate: count((e) => e.threat === "isolate"),
    poison: count((e) => e.threat === "poison"),
    relay: count((e) => e.actor === "relay"),
    processActor: count((e) => e.actor === "process"),
    modelActor: count((e) => e.actor === "model"),
    bypass: count((e) => Boolean(e.hookBlind)),
    snapshots: count((e) => (e.ruleId ?? "").startsWith("zcode_")),
    layers: {
      app_pre: count((e) => e.layer === "app_pre"),
      app_post: count((e) => e.layer === "app_post"),
      kernel_exec: count((e) => e.layer === "kernel_exec"),
      kernel_net: count((e) => e.layer === "kernel_net"),
    },
    risks: {
      high: count((e) => e.risk === "high"),
      medium: count((e) => e.risk === "medium"),
      low: count((e) => e.risk === "low"),
      info: count((e) => e.risk === "info"),
    },
  };
}
