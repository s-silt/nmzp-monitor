import {collectOwnedAgentTcp,type NetworkOwnerDeps} from "./network-owner.ts";
import {agentsFromDiscovery} from "./agent-catalog.ts";
import {refreshDiscovery} from "./agent-discovery.ts";
import type {DiscoverySnapshot} from "./agent-discovery-schema.ts";
import { antigravityHookGateError, antigravityHookState } from "./antigravity-hooks.ts";
import { codexHookConfiguredRaw, codexHookGateError, codexHookTrust } from "./codex-hooks.ts";
import { EXTRA_HOOK_AGENTS, hostHookState } from "./host-adapters.ts";
import { zcodeHookGateError, zcodeHookState } from "./zcode-hooks.ts";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir, hostname as osHostname, userInfo } from "node:os";
import { platform } from "node:os";
import { join } from "node:path";
import { GROK_HOOK_FILE, HEARTBEAT_INTERVAL_MS } from "./constants.ts";
import { pinnedHttps } from "./https-client.ts";
import { loadCreds } from "./hook.ts";
import { drainOutbox, outboxStatus } from "./audit/outbox.ts";
import { readPolicyCache, writePolicyCache } from "./policy-cache.ts";
import {
  WINDOWS_CANDIDATE_IDENTITY_SCRIPT,
  WINDOWS_PROCESS_INDEX_SCRIPT,
  binOf,
  classifyAgentProc,
  isCandidateProcessName,
  type ProcRow,
} from "./probe-classify.ts";
import { announceProbeReady } from "./install-autostart.ts";
import { isNmzpOwnedHook } from "./install-hooks.ts";
import { hookCapability, readHookStatus, type HookStatusFile } from "./probe-status.ts";
import type { Capability, NetworkSampleReport, PolicyState, SnapshotGuardReport } from "./schema.ts";
import { adaptSnapshotGuardLibraryStatus } from "./schema.ts";
import { collectAgentTcp, networkCapabilityFrom, type NetworkCollectDeps } from "./network-collect.ts";
import {
  SNAPSHOT_GUARD_PROBE_MS,
  collectSnapshotGuardStatus,
  snapshotGuardPlatformSupported,
  snapshotStatusHomeKey,
} from "./snapshot-status-collector.ts";

export type { ProcRow };
export {
  WINDOWS_CANDIDATE_IDENTITY_SCRIPT,
  WINDOWS_PROCESS_INDEX_SCRIPT,
  classifyAgentProc,
};
export {
  HOOK_EVIDENCE_TTL_MS,
  HOOK_STATUS_CONTRACT,
  HOOK_STATUS_FILENAME,
  HOOK_STATUS_SCHEMA_VERSION,
  hookStatusPath,
  readHookStatus,
  recordHookOutcome,
} from "./probe-status.ts";

export interface ProbeReport {
  agents: string[];
  capabilities: Capability[];
  agentProcs: Array<{ agent: string; pid: number; ppid: number; bin: string }>;
}

export type SnapshotGuardCollector = (opts: { home: string }) => Promise<unknown>;

export { SNAPSHOT_GUARD_PROBE_MS } from "./snapshot-status-collector.ts";

function failedSnapshotGuard(error: string): SnapshotGuardReport {
  return {
    supported: snapshotGuardPlatformSupported(),
    active: false,
    managed: false,
    targetPresent: false,
    writeBlocked: false,
    existingArchiveCoverage: "unknown",
    error,
    lastVerified: 0,
  };
}

export function snapshotGuardReportFromCollector(raw: unknown): SnapshotGuardReport {
  const adapted = adaptSnapshotGuardLibraryStatus(raw);
  if (adapted) return adapted;
  const err =
    raw && typeof raw === "object" && !Array.isArray(raw) && typeof (raw as { error?: unknown }).error === "string"
      ? String((raw as { error: string }).error).toLowerCase()
      : "status_failed";
  const code = /^[a-z0-9_-]{1,64}$/.test(err) ? err : "status_failed";
  return failedSnapshotGuard(code);
}

const injectInFlight = new Map<string, Promise<SnapshotGuardReport>>();

/**
 * Bounded read-only status. Production default is an async child (killable).
 * Stopped ticks skip collection. Failures are lastVerified=0, never old active.
 */
export async function snapshotGuardForHeartbeat(opts: {
  home: string;
  stopped: boolean;
  collect?: SnapshotGuardCollector;
  timeoutMs?: number;
}): Promise<SnapshotGuardReport | undefined> {
  if (opts.stopped) return undefined;
  const timeoutMs = opts.timeoutMs ?? SNAPSHOT_GUARD_PROBE_MS;
  if (!opts.collect) {
    const raw = await collectSnapshotGuardStatus({ home: opts.home, timeoutMs });
    return snapshotGuardReportFromCollector(raw);
  }
  const key = snapshotStatusHomeKey(opts.home);
  const existing = injectInFlight.get(key);
  if (existing) return existing;
  const collect = opts.collect;
  const pending = (async () => {
    try {
      const raw = await collect({ home: opts.home });
      return snapshotGuardReportFromCollector(raw);
    } catch {
      return failedSnapshotGuard("status_failed");
    }
  })();
  injectInFlight.set(key, pending);
  const timer = new Promise<SnapshotGuardReport>((resolve) => {
    setTimeout(() => resolve(failedSnapshotGuard("timeout")), timeoutMs);
  });
  try {
    return await Promise.race([pending, timer]);
  } finally {
    if (injectInFlight.get(key) === pending) injectInFlight.delete(key);
  }
}

function parseCimJson(buf: string): Array<Record<string, unknown>> {
  const trimmed = buf.trim();
  if (!trimmed) return [];
  const parsed = JSON.parse(trimmed) as unknown;
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows.filter((r) => r && typeof r === "object") as Array<Record<string, unknown>>;
}

function spawnPs(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { windowsHide: true });
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      buf += c;
      if (buf.length > 8_000_000) buf = buf.slice(0, 8_000_000);
    });
    child.on("error", (e) => reject(e));
    child.on("close", (code) => {
      if (code !== 0) reject(new Error("process_list_failed"));
      else resolve(buf);
    });
  });
}

export async function listProcesses(): Promise<ProcRow[]> {
  if (platform() === "win32") return listWindows();
  return listPosix();
}

async function listWindows(): Promise<ProcRow[]> {
  const raw = await spawnPs(WINDOWS_PROCESS_INDEX_SCRIPT);
  let records: Array<Record<string, unknown>>;
  try {
    records = parseCimJson(raw);
  } catch {
    throw new Error("process_list_failed");
  }
  const rows: ProcRow[] = [];
  for (const o of records) {
    rows.push({
      pid: Number(o.ProcessId) || 0,
      ppid: Number(o.ParentProcessId) || 0,
      name: String(o.Name ?? ""),
    });
  }
  const candidates = rows.filter((r) => isCandidateProcessName(r.name));
  if (!candidates.length) return rows;
  try {
    const idRaw = await spawnPs(WINDOWS_CANDIDATE_IDENTITY_SCRIPT(candidates.map((c) => c.pid)));
    const idRows = parseCimJson(idRaw);
    const exeByPid = new Map<number, string>();
    for (const o of idRows) {
      const pid = Number(o.ProcessId) || 0;
      if (pid && typeof o.ExecutablePath === "string") exeByPid.set(pid, o.ExecutablePath);
    }
    for (const row of rows) {
      const exe = exeByPid.get(row.pid);
      if (exe) row.exe = exe;
    }
  } catch {
    /* named agents still classifiable; node without exe stays unknown */
  }
  return rows;
}

function listPosix(): Promise<ProcRow[]> {
  return new Promise((resolve, reject) => {
    const child = spawn("ps", ["-axo", "pid=,ppid=,comm="], { windowsHide: true });
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      buf += c;
    });
    child.on("error", (e) => reject(e));
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error("process_list_failed"));
        return;
      }
      const out: ProcRow[] = [];
      for (const line of buf.split("\n")) {
        const m = /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);
        if (!m) continue;
        out.push({ pid: Number(m[1]), ppid: Number(m[2]), name: m[3]!.trim() });
      }
      resolve(out);
    });
  });
}

function preToolUseHasOwnedHook(doc: unknown): boolean {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return false;
  const hooks = (doc as Record<string, unknown>).hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return false;
  const pre = (hooks as Record<string, unknown>).PreToolUse;
  if (!Array.isArray(pre)) return false;
  for (const row of pre) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const list = (row as Record<string, unknown>).hooks;
    if (!Array.isArray(list)) continue;
    if (list.some((h) => isNmzpOwnedHook(h))) return true;
  }
  return false;
}

function jsonFileHasOwnedPreToolUse(path: string): boolean {
  if (!existsSync(path)) return false;
  try {
    return preToolUseHasOwnedHook(JSON.parse(readFileSync(path, "utf8")) as unknown);
  } catch {
    return false;
  }
}

export function grokHookConfigured(home: string): boolean {
  return jsonFileHasOwnedPreToolUse(join(home, ".grok", "hooks", GROK_HOOK_FILE));
}

export function claudeHookConfigured(home: string): boolean {
  return jsonFileHasOwnedPreToolUse(join(home, ".claude", "settings.json"));
}

export function codexHookConfigured(home: string): boolean {
  try { return codexHookConfiguredRaw(readFileSync(join(home,".codex","hooks.json"),"utf8")); } catch { return false; }
}

export function assembleProbeReport(opts: {
  home: string;
  procs: ProcRow[];
  listOk: boolean;
  now?: number;
  hookStatus?: HookStatusFile | null;
  network?: NetworkSampleReport;
}): ProbeReport {
  const now = opts.now ?? Date.now();
  const status = opts.hookStatus === undefined ? readHookStatus(opts.home) : opts.hookStatus;
  const grokCfg = grokHookConfigured(opts.home);
  const claudeCfg = claudeHookConfigured(opts.home);
  /** Codex skips hooks it has not trusted; report that instead of a misleading "offline". */
  const codexTrust = codexHookTrust(opts.home);
  const zcodeState = zcodeHookState(opts.home);
  const antigravityState = antigravityHookState(opts.home);
  const capabilities: Capability[] = [
    { id: "heartbeat", supported: true, active: true, lastSuccess: now },
    opts.listOk
      ? { id: "process_snapshot", supported: true, active: true, lastSuccess: now }
      : { id: "process_snapshot", supported: true, active: false, error: "unknown" },
    hookCapability("hook_grok", grokCfg, "grok", status, now),
    hookCapability("hook_claude", claudeCfg, "claude", status, now),
    hookCapability("hook_codex", codexTrust.configured, "codex", status, now, {
      gateError: codexHookGateError(codexTrust),
    }),
    hookCapability("hook_zcode", zcodeState.configured, "zcode", status, now, {
      gateError: zcodeHookGateError(zcodeState),
    }),
    hookCapability("hook_antigravity", antigravityState.configured, "antigravity", status, now, {
      gateError: antigravityHookGateError(antigravityState),
    }),
    ...EXTRA_HOOK_AGENTS.map((agent) =>
      hookCapability(`hook_${agent}`, hostHookState(agent, opts.home).configured, agent, status, now),
    ),
    { id: "quota", supported: false, active: false, error: "not_collected" },
    { id: "transcript", supported: false, active: false, error: "not_collected" },
    networkCapabilityFrom(opts.network, now),
  ];
  if (!opts.listOk) {
    return { agents: ["unknown"], agentProcs: [], capabilities };
  }
  const agents: string[] = [];
  const seen = new Set<string>();
  const agentProcs: ProbeReport["agentProcs"] = [];
  for (const row of opts.procs) {
    const a = classifyAgentProc(row, opts.procs);
    if (!a) continue;
    if (!seen.has(a)) {
      seen.add(a);
      agents.push(a);
    }
    if (a !== "unknown") {
      agentProcs.push({ agent: a, pid: row.pid, ppid: row.ppid, bin: binOf(row) });
    }
  }
  return { agents, agentProcs, capabilities };
}

export type NetworkCollector = (opts: { stopped: boolean }) => Promise<NetworkSampleReport>;

export async function probeTick(opts: {
  home: string;
  coreDir?: string;
  listProcesses?: () => Promise<ProcRow[]>;
  collectSnapshotGuard?: SnapshotGuardCollector;
  collectNetwork?: NetworkCollector;
  networkDeps?: NetworkCollectDeps;
  networkOwnerDeps?: NetworkOwnerDeps;
  collectDiscovery?: () => Promise<DiscoverySnapshot>;
  heartbeat?: (body:string)=>ReturnType<typeof pinnedHttps>;
}): Promise<{ ok: boolean; error?: string; pollOnly?: boolean }> {
  const creds = await loadCreds(opts.home);
  if (!creds) return { ok: false, error: "not_joined" };
  const pin = {
    caPem: creds.caPem,
    fingerprintSha256: creds.fingerprintSha256,
  };
  const auth = { authorization: `Bearer ${creds.token}`, "content-type": "application/json" };
  const heartbeat=(body:string)=>opts.heartbeat?opts.heartbeat(body):pinnedHttps({url:`${creds.url}/api/v1/heartbeat`,method:"POST",body,headers:auth,...pin});
  try {
    const pol = await pinnedHttps({
      url: `${creds.url}/api/v1/policy`,
      method: "GET",
      headers: { authorization: `Bearer ${creds.token}` },
      ...pin,
    });
    let policy: PolicyState | null = null;
    if (pol.status === 200) {
      policy = JSON.parse(pol.body) as PolicyState;
      await writePolicyCache(join(opts.home, ".nmzp", "policy-cache.json"), policy);
    } else {
      policy = await readPolicyCache(join(opts.home, ".nmzp", "policy-cache.json"));
    }
    if (policy?.stopped) {
      const hb = await heartbeat(JSON.stringify({
          pollOnly: true,
          stoppedAck: true,
          policyVersion: policy.version,
          hostname: osHostname(),
          os: platform(),
        }));
      if (hb.status !== 200) return { ok: false, error: `http_${hb.status}`, pollOnly: true };
      return { ok: true, pollOnly: true };
    }
    let listOk = true;
    let procs: ProcRow[] = [];
    try {
      procs = opts.listProcesses ? await opts.listProcesses() : [];
    } catch {
      listOk = false;
      procs = [];
    }
    const discoveryP = (opts.collectDiscovery ?? (()=>refreshDiscovery(opts.home)))();
    const snapshotGuardP = snapshotGuardForHeartbeat({
      home: opts.home,
      stopped: false,
      collect: opts.collectSnapshotGuard,
    });
    const networkP = opts.collectNetwork
      ? opts.collectNetwork({ stopped: false })
      : opts.networkDeps ? collectAgentTcp({ stopped: false, homeKey: opts.home, deps: opts.networkDeps })
        : collectOwnedAgentTcp({home:opts.home,creds,deps:opts.networkOwnerDeps});
    const [snapshotGuard, network, discovery] = await Promise.all([snapshotGuardP, networkP, discoveryP]);
    const report = assembleProbeReport({ home: opts.home, procs, listOk, network });
    const res = await heartbeat(JSON.stringify({
        hostname: osHostname(),
        user: userInfo().username,
        agents: agentsFromDiscovery(discovery.items),
        agentProcs: [], // Discovery never authorizes process ownership.
        discovery,
        capabilities: report.capabilities,
        os: platform(),
        policyVersion: policy?.version,
        stoppedAck: false,
        snapshotGuard,
        network,
      }));
    if (res.status !== 200) return { ok: false, error: `http_${res.status}` };
    // Heartbeat and policy polling remain the authority for whether upload is active.
    // Backfill never replays a tool; it sends at most two persisted metadata items.
    try {
      if ((await outboxStatus(opts.home)).pending > 0) {
        await drainOutbox(opts.home,creds,{allowEvents:true,maxItems:2,timeoutMs:800});
      }
    } catch { /* delivery state remains local for the next tick */ }
    return { ok: true, pollOnly: false };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "probe_error" };
  }
}

export async function probeLoop(coreDir: string): Promise<void> {
  const home = process.env.NMZP_HOME || homedir();
  const claimed = await announceProbeReady(home, coreDir);
  if (!claimed.tookLock) return;
  let ticking = false;
  const tick = async () => {
    if(ticking)return;ticking=true;
    try {await probeTick({home,coreDir});} finally {ticking=false;}
  };
  tick();
  setInterval(tick, HEARTBEAT_INTERVAL_MS);
}
