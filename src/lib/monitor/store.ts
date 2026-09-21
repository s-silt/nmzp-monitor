import {archivePolicy,type ArchiveUploadPolicy,githubPolicy,type GithubUploadPolicy} from "./egress-evidence.ts";
import {parseProbeProtection} from "./probe-protection";
import {parseDiscovery} from "./agent-discovery";
import {parseEvidenceWindow,type EvidenceWindow} from "./evidence-window";
import { create } from "zustand";
import { AGENT_ORDER, isAgentId } from "./agents";
import { agentsFromDiscovery } from "./agent-catalog";
import { SETTINGS_KEY, SETTINGS_MAX_BYTES } from "./caps";
import { t, type Locale, type Msg } from "./i18n";
import { compilePrivacyDraft, MAX_CUSTOM_RULES, sanitizeCustomRules } from "./privacy";
import { exportBundle } from "./rights";
import { effectiveMachineFilter, isPersistedHostFilter, machineRollup, overviewMachines, scopedByHost, scopedCapabilities } from "./stats";
import { canMutateState, mapEvent, maskCustomRules, parseViewerCustomRules } from "./map-event";
import { parseSnapshotGuard } from "./snapshot-guard";
import { publicNetworkHistory, publicNetworkSample } from "./network-evidence";
import type {
  AgentId,
  Approval,
  AuditEvent,
  CustomPrivacyRule,
  DeviceCapability,
  Intervention,
  Machine,
  NetworkHistoryRow,
  NetworkHop,
  ProbeIdentity,
  QuotaBlock,
  Session,
  TranscriptTurn,
} from "./types";
import { clearDemoResidue, clearEventsApi, exportApi, fetchState, putPolicy, type ApiDevice, type ApiCapability, type AccessRole } from "./api";
import { filterLiveEvents } from "./live-filter";
import {
  THREAT_KINDS,
  type FamilyOverride,
  type PolicyExemption,
  type PolicyOverrides,
  type RuleOverride,
  type CustomRuleScope,
} from "./policy-schema.ts";

export { filterLiveEvents } from "./live-filter";
export { canMutateState } from "./map-event";

export function deviceCapabilityMap(raw: unknown): Record<string, DeviceCapability> {
  if (!Array.isArray(raw)) return {};
  const out: Record<string, DeviceCapability> = {};
  for (const row of raw) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const c = row as Record<string, unknown>;
    if (typeof c.id !== "string" || !c.id.trim()) continue;
    if (typeof c.supported !== "boolean") continue;
    const cap: DeviceCapability = {
      supported: c.supported,
      active: c.active === true,
    };
    if (typeof c.lastSuccess === "number" && Number.isFinite(c.lastSuccess)) cap.lastSuccess = c.lastSuccess;
    if (typeof c.error === "string" && c.error) cap.error = c.error;
    out[c.id.trim()] = cap;
  }
  return out;
}

function mapDevice(d: ApiDevice): Machine {
  const agents = Array.isArray(d.agents) ? d.agents.filter((a): a is AgentId => isAgentId(a)) : [];
  const m: Machine = {
    id: d.id,
    hostname: d.hostname,
    ip: d.ip,
    user: d.user,
    os: d.os,
    lastSeen: d.lastSeen,
    attachedAt: d.attachedAt,
    status: d.status,
    agents,
    capabilities: deviceCapabilityMap(d.capabilities),
    discovery:parseDiscovery(d.discovery),
    probeProtection:parseProbeProtection(d.probeProtection),
    snapshotGuard: parseSnapshotGuard(d.snapshotGuard),
    network: publicNetworkSample(d.network),
  };
  (m as Machine & { networkOwnerCount?: number; lastPolicyVersion?: number }).networkOwnerCount =
    typeof d.networkOwnerCount === "number" ? d.networkOwnerCount : 0;
  (m as Machine & { networkOwnerCount?: number; lastPolicyVersion?: number }).lastPolicyVersion =
    typeof d.lastPolicyVersion === "number" ? d.lastPolicyVersion : 0;
  return m;
}

function lookupCap(caps: Record<string, DeviceCapability | ApiCapability>, ...ids: string[]) {
  for (const id of ids) {
    const cap = caps[id];
    if (cap) return cap;
  }
  return undefined;
}

function mapIdentities(devices: ApiDevice[]): ProbeIdentity[] {
  const out: ProbeIdentity[] = [];
  for (const d of devices) {
    for (const p of d.agentProcs ?? []) {
      if (!isAgentId(p.agent)) continue;
      if (typeof p.pid !== "number" || !Number.isInteger(p.pid) || p.pid <= 0) continue;
      const bin = typeof p.bin === "string" ? p.bin : "";
      if (!bin || bin.includes("/") || bin.includes("\\")) continue;
      out.push({
        agent: p.agent,
        machineId: d.id,
        pid: p.pid,
        user: "unknown",
        cwd: "",
        proc: bin,
      });
    }
  }
  return out;
}

/** Display-only: map collected session/process evidence. Does not invent status. */
export function agentCardDisplay(
  agent: AgentId,
  sessions: Session[],
  procs: ProbeIdentity[],
  capabilities: Record<string, { supported: boolean; active: boolean; error?: string }> = {},
): {
  running: Session | undefined;
  session: Session | undefined;
  proc: ProbeIdentity | undefined;
  statusMsg: Msg;
  noHookAdapter: boolean;
} {
  const running = sessions.find((x) => x.agent === agent && x.status === "running");
  const session = running ?? sessions.find((x) => x.agent === agent);
  const proc = procs.find((p) => p.agent === agent && typeof p.pid === "number" && p.pid > 0);
  let statusMsg: Msg = "sessionNotCollected";
  if (session?.status === "running") statusMsg = "running";
  else if (session?.status === "idle") statusMsg = "idle";
  else if (session?.status === "ended") statusMsg = "ended";
  const cap = lookupCap(
    capabilities,
    `hook_${agent}`,
    `hook${agent.slice(0, 1).toUpperCase()}${agent.slice(1)}`,
  );
  const noHookAdapter = cap ? cap.supported === false : true;
  return { running, session, proc, statusMsg, noHookAdapter };
}

export interface MonitorState {
  evidenceWindow?: EvidenceWindow;
  locale: Locale;
  theme: "dark" | "light";
  disconnected: boolean;
  loginNeeded: boolean;
  synced: boolean;
  access: AccessRole;
  policyVersion: number;
  archiveUpload:ArchiveUploadPolicy;
  githubUpload:GithubUploadPolicy;
  capabilities: Record<string, { supported: boolean; active: boolean; error?: string }>;
  intervention: Intervention;
  paused: boolean;
  agentFilter: AgentId | "all";
  machineFilter: string | "all";
  sessions: Session[];
  machines: Machine[];
  events: AuditEvent[];
  approvals: Approval[];
  hops: NetworkHop[];
  networkHistory: NetworkHistoryRow[];
  transcripts: Record<string, TranscriptTurn[]>;
  identities: ProbeIdentity[];
  quotas: QuotaBlock[];
  customRules: CustomPrivacyRule[];
  overrides: PolicyOverrides;
  exemptions: PolicyExemption[];
  hydrated: boolean;
  setLocale: (locale: Locale) => void;
  setTheme: (theme: "dark" | "light") => void;
  setGithubUpload:(v:GithubUploadPolicy)=>Promise<boolean>;
  setArchiveUpload:(v:ArchiveUploadPolicy)=>Promise<boolean>;
  setIntervention: (v: Intervention) => Promise<boolean>;
  setAgentFilter: (v: AgentId | "all") => void;
  setMachineFilter: (v: string | "all") => void;
  setRuleOverride: (ruleId: string, value: RuleOverride | null) => Promise<boolean>;
  setFamilyOverride: (family: string, value: FamilyOverride | null) => Promise<boolean>;
  setCustomRuleState: (id: string, state: "on" | "dry_run" | "off") => Promise<boolean>;
  setCustomRuleScope: (id: string, scope: CustomRuleScope | undefined) => Promise<boolean>;
  addExemption: (ex: PolicyExemption) => Promise<boolean>;
  removeExemption: (id: string) => Promise<boolean>;
  applyProposal: (next: {
    overrides?: PolicyOverrides;
    customRules?: CustomPrivacyRule[];
    exemptions?: PolicyExemption[];
  }) => Promise<boolean>;
  addPrivacyDraft: (text: string) => Promise<number>;
  removePrivacyRule: (id: string) => Promise<boolean>;
  togglePrivacyRule: (id: string) => Promise<boolean>;
  clearEvents: () => Promise<boolean>;
  wipeLocal: () => Promise<boolean>;
  stopProcessing: () => Promise<boolean>;
  resumeProcessing: () => Promise<boolean>;
  exportLocal: () => Promise<string>;
  hydrate: () => void;
  syncFromServer: () => Promise<void>;
  setLoginNeeded: (v: boolean) => void;
}

function readSettings(): Partial<Pick<MonitorState, "locale" | "theme" | "agentFilter" | "machineFilter">> {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw || raw.length > SETTINGS_MAX_BYTES) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const locale = parsed.locale === "en" ? "en" : parsed.locale === "zh" ? "zh" : undefined;
    const theme = parsed.theme === "light" ? "light" : parsed.theme === "dark" ? "dark" : undefined;
    const agentFilter =
      parsed.agentFilter === "all" || (typeof parsed.agentFilter === "string" && isAgentId(parsed.agentFilter))
        ? parsed.agentFilter
        : undefined;
    const machineFilter =
      typeof parsed.machineFilter === "string" && isPersistedHostFilter(parsed.machineFilter)
        ? parsed.machineFilter
        : undefined;
    return {
      ...(locale ? { locale } : {}),
      ...(theme ? { theme } : {}),
      ...(agentFilter ? { agentFilter } : {}),
      ...(machineFilter ? { machineFilter } : {}),
    };
  } catch {
    return {};
  }
}

function writeSettings(s: MonitorState) {
  if (typeof window === "undefined") return;
  const payload = JSON.stringify({
    locale: s.locale,
    theme: s.theme,
    agentFilter: s.agentFilter,
    machineFilter: s.machineFilter,
  });
  if (payload.length > SETTINGS_MAX_BYTES) return;
  localStorage.setItem(SETTINGS_KEY, payload);
}

function gate(): boolean {
  return canMutateState(useMonitor.getState());
}

export const useMonitor = create<MonitorState>((set, get) => ({
  locale: "zh",
  theme: "dark",
  disconnected: false,
  loginNeeded: false,
  synced: false,
  access: "viewer",
  policyVersion: 0,
  capabilities: {},
  intervention: "enforcing",
  paused: false,
  agentFilter: "all",
  machineFilter: "all",
  sessions: [],
  machines: [],
  events: [],
  approvals: [],
  hops: [],
  networkHistory: [],
  transcripts: {},
  identities: [],
  quotas: [],
  customRules: [],
  overrides: { rules: {}, families: {} },
  exemptions: [],
  archiveUpload:archivePolicy(undefined),
  githubUpload:githubPolicy(undefined),
  hydrated: false,
  hydrate: () => {
    clearDemoResidue();
    const s = readSettings();
    set({
      ...s,
      hydrated: true,
      evidenceWindow: undefined,
      synced: false,
      access: "viewer",
      disconnected: false,
      loginNeeded: false,
      sessions: [],
      machines: [],
      events: [],
      hops: [],
      networkHistory: [],
      transcripts: {},
      identities: [],
      quotas: [],
      customRules: [],
      overrides: { rules: {}, families: {} },
      exemptions: [],
      approvals: [],
    });
    void get().syncFromServer();
  },
  setLoginNeeded: (loginNeeded) => set({ loginNeeded }),
  syncFromServer: async () => {
    try {
      const r = await fetchState();
      if (!r.ok) {
        set({ disconnected: true, loginNeeded: r.status === 401 });
        return;
      }
      const st = r.state;
      const access: AccessRole = st.access;
      set({
        disconnected: false,
        loginNeeded: false,
        synced: true,
        access,
        intervention: st.stopped ? "off" : st.mode,
        paused: st.stopped,
        policyVersion: st.policyVersion,
        overrides: st.overrides ?? { rules: {}, families: {} },
        exemptions: st.exemptions ?? [],
        evidenceWindow:parseEvidenceWindow(st.evidenceWindow),
        archiveUpload:archivePolicy(st.archiveUpload),
        githubUpload:githubPolicy(st.githubUpload),
        customRules:
          access === "viewer"
            ? parseViewerCustomRules(st.customRules)
            : (sanitizeCustomRules(st.customRules) ?? []),
        machines: (st.devices ?? []).map((d) => {
          const m = mapDevice(d);
          if (!m.network && st.deviceNetwork?.[d.id]) m.network = publicNetworkSample(st.deviceNetwork[d.id]);
          return m;
        }),
        events: (st.events ?? [])
          .map((row) => {
            if (!row || typeof row !== "object" || Array.isArray(row)) return mapEvent(row);
            const r = row as Record<string, unknown>;
            const id = typeof r.id === "string" ? r.id : "";
            const sidecar = id && st.eventEndpoints ? st.eventEndpoints[id] : undefined;
            return mapEvent({ ...r, endpoints: r.endpoints ?? sidecar });
          })
          .filter((e): e is AuditEvent => !!e),
        capabilities: st.capabilities ?? {},
        identities: mapIdentities(st.devices ?? []),
        sessions: [],
        quotas: [],
        hops: [],
        networkHistory: publicNetworkHistory(st.networkHistory ?? []),
        transcripts: {},
      });
    } catch {
      set({ disconnected: true });
    }
  },
  setLocale: (locale) => {
    set({ locale });
    writeSettings(get());
  },
  setTheme: (theme) => {
    set({ theme });
    writeSettings(get());
  },
  setGithubUpload:async(v)=>{if(get().access!=="admin"||!get().synced||get().disconnected)return false;const r=await putPolicy({expectedVersion:get().policyVersion,githubUpload:v});if(!r.ok){await get().syncFromServer();return false;}set({githubUpload:v,policyVersion:r.version});return true;},
  setArchiveUpload:async(v)=>{if(get().access!=="admin"||!get().synced||get().disconnected)return false;const r=await putPolicy({expectedVersion:get().policyVersion,archiveUpload:v});if(!r.ok){await get().syncFromServer();return false;}set({archiveUpload:v,policyVersion:r.version});return true;},
  setIntervention: async (intervention) => {
    if (!gate()) return false;
    const r = await putPolicy({ expectedVersion: get().policyVersion, mode: intervention });
    if (!r.ok) return false;
    set({ intervention: r.mode, policyVersion: r.version, paused: r.stopped });
    void get().syncFromServer();
    return true;
  },
  setAgentFilter: (agentFilter) => {
    set({ agentFilter });
    writeSettings(get());
  },
  setMachineFilter: (machineFilter) => {
    set({ machineFilter, agentFilter: "all" });
    writeSettings(get());
  },
  setRuleOverride: async (ruleId, value) => {
    if (!gate()) return false;
    const nextRules = { ...(get().overrides.rules ?? {}) };
    if (value === null) {
      delete nextRules[ruleId];
    } else {
      nextRules[ruleId] = value;
    }
    const nextOverrides: PolicyOverrides = {
      ...get().overrides,
      rules: nextRules,
    };
    const r = await putPolicy({ expectedVersion: get().policyVersion, overrides: nextOverrides });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({
      overrides: r.overrides ?? nextOverrides,
      policyVersion: r.version,
    });
    return true;
  },
  setFamilyOverride: async (family, value) => {
    if (!gate()) return false;
    const nextFamilies = { ...(get().overrides.families ?? {}) };
    if (value === null) {
      delete nextFamilies[family as (typeof THREAT_KINDS)[number]];
    } else {
      nextFamilies[family as (typeof THREAT_KINDS)[number]] = value;
    }
    const nextOverrides: PolicyOverrides = {
      ...get().overrides,
      families: nextFamilies,
    };
    const r = await putPolicy({ expectedVersion: get().policyVersion, overrides: nextOverrides });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({
      overrides: r.overrides ?? nextOverrides,
      policyVersion: r.version,
    });
    return true;
  },
  setCustomRuleState: async (id, state) => {
    if (!gate()) return false;
    const merged = get().customRules.map((r) => {
      if (r.id !== id) return r;
      if (state === "on") return { ...r, enabled: true, dryRun: false };
      if (state === "dry_run") return { ...r, enabled: false, dryRun: true };
      return { ...r, enabled: false, dryRun: false };
    });
    const r = await putPolicy({ expectedVersion: get().policyVersion, customRules: merged });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({ customRules: r.customRules, policyVersion: r.version });
    return true;
  },
  setCustomRuleScope: async (id, scope) => {
    if (!gate()) return false;
    const merged = get().customRules.map((r) => {
      if (r.id !== id) return r;
      return { ...r, scope };
    });
    const r = await putPolicy({ expectedVersion: get().policyVersion, customRules: merged });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({ customRules: r.customRules, policyVersion: r.version });
    return true;
  },
  addExemption: async (ex) => {
    if (!gate()) return false;
    const nextExemptions = [...get().exemptions, ex];
    const r = await putPolicy({ expectedVersion: get().policyVersion, exemptions: nextExemptions });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({ exemptions: r.exemptions ?? nextExemptions, policyVersion: r.version });
    return true;
  },
  removeExemption: async (id) => {
    if (!gate()) return false;
    const nextExemptions = get().exemptions.filter((e) => e.id !== id);
    const r = await putPolicy({ expectedVersion: get().policyVersion, exemptions: nextExemptions });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({ exemptions: r.exemptions ?? nextExemptions, policyVersion: r.version });
    return true;
  },
  applyProposal: async (next) => {
    if (!gate()) return false;
    const r = await putPolicy({
      expectedVersion: get().policyVersion,
      overrides: next.overrides,
      customRules: next.customRules,
      exemptions: next.exemptions,
    });
    if (!r.ok) {
      await get().syncFromServer();
      return false;
    }
    set({
      overrides: r.overrides ?? next.overrides ?? get().overrides,
      customRules: r.customRules,
      exemptions: r.exemptions ?? next.exemptions ?? get().exemptions,
      policyVersion: r.version,
    });
    return true;
  },
  addPrivacyDraft: async (text) => {
    if (!gate()) return 0;
    const drafted = compilePrivacyDraft(text);
    if (!drafted.length) return 0;
    const have = new Set(get().customRules.map((r) => r.match.toLowerCase()));
    const merged = [...get().customRules];
    let added = 0;
    for (const row of drafted) {
      if (have.has(row.match.toLowerCase())) continue;
      if (merged.length >= MAX_CUSTOM_RULES) break;
      merged.push(row);
      have.add(row.match.toLowerCase());
      added += 1;
    }
    if (!added) return 0;
    const r = await putPolicy({ expectedVersion: get().policyVersion, customRules: merged });
    if (!r.ok) return 0;
    set({ customRules: r.customRules, policyVersion: r.version });
    return added;
  },
  removePrivacyRule: async (id) => {
    if (!gate()) return false;
    const merged = get().customRules.filter((r) => r.id !== id);
    const r = await putPolicy({ expectedVersion: get().policyVersion, customRules: merged });
    if (!r.ok) return false;
    set({ customRules: r.customRules, policyVersion: r.version });
    return true;
  },
  togglePrivacyRule: async (id) => {
    if (!gate()) return false;
    const merged = get().customRules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r));
    const r = await putPolicy({ expectedVersion: get().policyVersion, customRules: merged });
    if (!r.ok) return false;
    set({ customRules: r.customRules, policyVersion: r.version });
    return true;
  },
  clearEvents: async () => {
    if (!gate()) return false;
    const ok = await clearEventsApi();
    if (ok) set({ events: [], approvals: [] });
    return ok;
  },
  wipeLocal: async () => {
    if (!gate()) return false;
    const ok = await clearEventsApi();
    if (ok) set({ events: [], approvals: [], hops: [], transcripts: {}, evidenceWindow: undefined });
    return ok;
  },
  stopProcessing: async () => {
    if (!gate()) return false;
    const r = await putPolicy({ expectedVersion: get().policyVersion, stopped: true });
    if (!r.ok) return false;
    set({ intervention: "off", paused: true, policyVersion: r.version });
    return true;
  },
  resumeProcessing: async () => {
    if (!gate()) return false;
    const r = await putPolicy({ expectedVersion: get().policyVersion, stopped: false });
    if (!r.ok) return false;
    set({ intervention: r.mode, paused: false, policyVersion: r.version });
    void get().syncFromServer();
    return true;
  },
  exportLocal: async () => {
    const s = get();
    if (s.synced && !s.disconnected) {
      try {
        return await exportApi();
      } catch {
        return "";
      }
    }
    return JSON.stringify(
      exportBundle({
        events: s.events,
        hops: s.hops,
        machines: s.machines,
        customRules: s.access === "viewer" ? maskCustomRules(s.customRules, "viewer") : s.customRules,
      }),
    );
  },
}));

export function useT() {
  const locale = useMonitor((s) => s.locale);
  return (key: Msg) => t(locale, key);
}

export function useCanMutate() {
  const synced = useMonitor((s) => s.synced);
  const disconnected = useMonitor((s) => s.disconnected);
  const access = useMonitor((s) => s.access);
  const loginNeeded = useMonitor((s) => s.loginNeeded);
  return canMutateState({ synced, disconnected, access, loginNeeded });
}

function useFleetScope() {
  const machineFilter = useMonitor((s) => s.machineFilter);
  const machines = useMonitor((s) => s.machines);
  const events = useMonitor((s) => s.events);
  const views = machineRollup(machines, events);
  const visible = overviewMachines(views);
  const host = effectiveMachineFilter(machineFilter, views);
  const allowed = new Set(visible.map((m) => m.id));
  return { host, allowed, views, visible };
}

export function useFilteredEvents() {
  const events = useMonitor((s) => s.events);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const machines = useMonitor((s) => s.machines);
  const { host } = useFleetScope();
  return filterLiveEvents(events, {
    agentFilter,
    machineFilter: host,
    deviceIds: new Set(machines.filter((m) => m.attachedAt > 0).map((m) => m.id)),
  });
}

export function useFilteredSessions() {
  const sessions = useMonitor((s) => s.sessions);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const { host, allowed } = useFleetScope();
  const present = usePresentAgents();
  const rows = scopedByHost(sessions, host, allowed);
  const effective = agentFilter !== "all" && present.includes(agentFilter) ? agentFilter : "all";
  if (effective === "all") return rows;
  return rows.filter((s) => s.agent === effective);
}

export function useFilteredHops() {
  const hops = useMonitor((s) => s.hops);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const { host, allowed } = useFleetScope();
  const rows = scopedByHost(hops, host, allowed);
  if (agentFilter === "all") return rows;
  return rows.filter((h) => h.agent === agentFilter);
}

export function usePresentAgents() {
  const events = useMonitor((s) => s.events);
  const machines = useMonitor((s) => s.machines);
  const identities = useMonitor((s) => s.identities);
  const { host } = useFleetScope();
  const seen = new Set<AgentId>();
  const add = (id: string) => {
    if (!isAgentId(id) || seen.has(id)) return;
    seen.add(id);
  };
  const inHost = (machineId: string) => host === "all" || machineId === host;
  for (const m of machines) {
    if (!inHost(m.id)) continue;
    for (const a of m.agents ?? []) add(a);
    for (const a of agentsFromDiscovery(m.discovery?.items ?? [])) add(a);
  }
  for (const i of identities) {
    if (!inHost(i.machineId)) continue;
    if (typeof i.pid === "number" && i.pid > 0) add(i.agent);
  }
  for (const e of events) {
    if (inHost(e.machineId)) add(e.agent);
  }
  return AGENT_ORDER.filter((id) => seen.has(id));
}

export function useMachineViews() {
  const machines = useMonitor((s) => s.machines);
  const events = useMonitor((s) => s.events);
  return machineRollup(machines, events);
}

export function useOverviewMachines() {
  return overviewMachines(useMachineViews());
}

export function useScopedCapabilities() {
  const { host, visible } = useFleetScope();
  return scopedCapabilities(visible, host);
}
