import {join} from "node:path";
/**
 * Windows non-admin TCP metadata collector for confirmed Agent process trees.
 * CIM ExecutablePath + CreationDate before and after Get-NetTCPConnection.
 * Never reads CommandLine. No reverse DNS. Bound/Listen/zero-remote are not egress.
 */

import { spawn } from "node:child_process";
import { HEARTBEAT_INTERVAL_MS } from "./constants.ts";
import { binOf } from "./probe-classify.ts";
import {
  NETWORK_SAMPLE_MAX_CONNECTIONS,
  NETWORK_STDOUT_MAX,
  isEgressTcp,
  parseIp,
  parseNetworkSampleReport,
} from "./network-evidence.ts";
import type { NetworkConnection, NetworkSampleReport } from "./schema.ts";

export const NETWORK_COLLECT_MS = Math.min(8_000, Math.max(1_000, HEARTBEAT_INTERVAL_MS - 22_000));

export const WINDOWS_NETWORK_PROCESS_SCRIPT =
  "Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,@{N='StartedAtMs';E={ if ($null -eq $_.CreationDate) { 0 } else { try { [int64]([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } catch { 0 } } }} | ConvertTo-Json -Compress";

export function WINDOWS_NETWORK_IDENTITY_SCRIPT(pids: number[]): string {
  const list = pids.filter((n) => Number.isInteger(n) && n > 0).join(",");
  return `Get-CimInstance Win32_Process -Filter '${pids.filter(n=>Number.isInteger(n)&&n>0).map(n=>"ProcessId="+n).join(" OR ") || "ProcessId=0"}' -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,@{N='StartedAtMs';E={ if ($null -eq $_.CreationDate) { 0 } else { try { [int64]([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } catch { 0 } } }} | ConvertTo-Json -Compress`;
}

export function WINDOWS_NETWORK_TCP_SCRIPT(pids: number[]): string {
  const list = pids.filter((n) => Number.isInteger(n) && n > 0);
  if (!list.length) return "Write-Output '[]'";
  return `$pids = @(${list.join(",")}); Get-NetTCPConnection -ErrorAction Stop | Where-Object { $pids -contains ([int]$_.OwningProcess) } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='State';E={[string]$_.State}},OwningProcess | ConvertTo-Json -Compress`;
}

export interface IdentifiedProc {
  pid: number;
  ppid: number;
  name: string;
  exe: string;
  startedAt: number;
}

export type NetworkScriptKind = "cim" | "tcp" | "cim_after";

export interface NetworkRunResult {
  stdout: string;
  truncated?: boolean;
  timedOut?: boolean;
  error?: string;
}

export interface NetworkCollectDeps {
  run?: (kind: NetworkScriptKind, script: string) => Promise<NetworkRunResult>;
  platform?: NodeJS.Platform;
  now?: () => number;
}

const BROWSER_NAMES = new Set([
  "chrome",
  "msedge",
  "msedgewebview2",
  "firefox",
  "iexplore",
  "brave",
  "opera",
  "safari",
]);

function basenameOf(path: string): string {
  return path.replace(/\\/g, "/").split("/").pop() || path;
}

function nameKey(name: string): string {
  return (name || "").toLowerCase().replace(/\.exe$/, "");
}

export function isBrowserProcessName(name: string): boolean {
  return BROWSER_NAMES.has(nameKey(name));
}

export function identityKey(row: IdentifiedProc): string {
  return `${row.pid}|${row.exe.toLowerCase()}|${row.startedAt}|${row.ppid}`;
}

/**
 * Network roots require a known install layout + matching basename.
 * Arbitrary grok.exe / any file under .grok or .codex is not a root.
 */
export function confirmedAgentRoot(row: IdentifiedProc): string | null {
  if (!row.exe || !row.pid || row.startedAt <= 0) return null;
  if (isBrowserProcessName(row.name) || isBrowserProcessName(basenameOf(row.exe))) return null;
  const n = row.exe.replace(/\\/g, "/").toLowerCase();
  const base = basenameOf(n).replace(/\.exe$/, "");
  if (n.includes("/node_modules/")) return null;
  if (base === "grok" || base === "grok-cli" || base === "grok-build") {
    if (/(^|\/)\.grok\/bin\/grok(\.exe)?$/.test(n)) return "grok";
    if (/\/programs\/grok\/[^/]+\/grok(\.exe)?$/.test(n)) return "grok";
    if (/\/grok-cli\/[^/]+\/grok(\.exe)?$/.test(n)) return "grok";
    return null;
  }
  if (base === "claude" || base === "claude-code") {
    if (/(^|\/)\.claude\/.*(claude)(\.exe)?$/.test(n)) return "claude";
    if (/\/programs\/claude\/.*claude(\.exe)?$/.test(n)) return "claude";
    return null;
  }
  if (base === "codex" || base === "codex-cli") {
    if (/(^|\/)\.codex\/bin\/codex(\.exe)?$/.test(n)) return "codex";
    if (/\/codex\/bin\/codex(\.exe)?$/.test(n)) return "codex";
    return null;
  }
  if (base === "zcode" || base === "zcode-cli") {
    if (/\/zcode\/.*\/zcode(\.exe)?$/.test(n)) return "zcode";
    return null;
  }
  return null;
}

export function ancestryStable(
  startPid: number,
  beforeTree: Map<number, { agent: string; row: IdentifiedProc }>,
  afterByPid: Map<number, IdentifiedProc>,
): boolean {
  let node = beforeTree.get(startPid);
  if (!node) return false;
  const seen = new Set<number>();
  while (node) {
    if (seen.has(node.row.pid)) return false;
    seen.add(node.row.pid);
    const after = afterByPid.get(node.row.pid);
    if (!after || identityKey(after) !== identityKey(node.row)) return false;
    if (confirmedAgentRoot(node.row)) return true;
    node = beforeTree.get(node.row.ppid);
  }
  return false;
}

export function parseIdentifiedProcs(raw: unknown): IdentifiedProc[] {
  const rows = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? [raw] : [];
  const out: IdentifiedProc[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const o = row as Record<string, unknown>;
    const pid = Number(o.ProcessId ?? o.pid);
    const ppid = Number(o.ParentProcessId ?? o.ppid);
    const name = String(o.Name ?? o.name ?? "");
    const exe = typeof o.ExecutablePath === "string" ? o.ExecutablePath : typeof o.exe === "string" ? o.exe : "";
    let startedAt = Number(o.StartedAtMs ?? o.startedAt);
    if (!Number.isFinite(startedAt) || startedAt <= 0) {
      const cd = o.CreationDate;
      if (typeof cd === "string") {
        const m = /\/Date\((\d+)\)\//.exec(cd);
        startedAt = m ? Number(m[1]) : Date.parse(cd);
      }
    }
    if (!Number.isInteger(pid) || pid <= 0 || pid > 4_000_000_000) continue;
    if (!Number.isInteger(ppid) || ppid < 0 || ppid > 4_000_000_000) continue;
    if (!exe || exe.includes("\0") || exe.length > 512) continue;
    if (!Number.isFinite(startedAt) || startedAt <= 0) continue;
    out.push({ pid, ppid, name, exe, startedAt });
  }
  return out;
}

export function agentTree(rows: IdentifiedProc[]): Map<number, { agent: string; row: IdentifiedProc }> {
  const out = new Map<number, { agent: string; row: IdentifiedProc }>();
  for (const r of rows) {
    const agent = confirmedAgentRoot(r);
    if (agent) out.set(r.pid, { agent, row: r });
  }
  let grew = true;
  while (grew) {
    grew = false;
    for (const r of rows) {
      if (out.has(r.pid)) continue;
      if (isBrowserProcessName(r.name) || isBrowserProcessName(basenameOf(r.exe))) continue;
      const parent = out.get(r.ppid);
      if (!parent) continue;
      if (r.startedAt < parent.row.startedAt) continue;
      out.set(r.pid, { agent: parent.agent, row: r });
      grew = true;
    }
  }
  return out;
}

function parseJsonRecords(buf: string): unknown {
  const trimmed = buf.trim();
  if (!trimmed) return [];
  return JSON.parse(trimmed) as unknown;
}

export const TCP_STATE_BY_CODE: Record<string, string> = {
  "1": "Closed",
  "2": "Listen",
  "3": "SynSent",
  "4": "SynReceived",
  "5": "Established",
  "6": "FinWait1",
  "7": "FinWait2",
  "8": "CloseWait",
  "9": "Closing",
  "10": "LastAck",
  "11": "TimeWait",
  "12": "DeleteTcb",
  "100": "Bound",
};

function tcpStateName(raw: unknown): string {
  if (typeof raw === "number" && Number.isInteger(raw)) return TCP_STATE_BY_CODE[String(raw)] ?? "";
  if (typeof raw === "string") {
    const t = raw.trim();
    if (TCP_STATE_BY_CODE[t]) return TCP_STATE_BY_CODE[t]!;
    return Object.values(TCP_STATE_BY_CODE).find(v => v.toLowerCase() === t.toLowerCase()) ?? "";
  }
  return "";
}

export function parseTcpRows(raw: unknown): Array<{
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  pid: number;
}> {
  const rows = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? [raw] : [];
  const out: Array<{ localIp: string; localPort: number; remoteIp: string; remotePort: number; state: string; pid: number }> = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const o = row as Record<string, unknown>;
    const pid = Number(o.OwningProcess ?? o.pid);
    const localPort = Number(o.LocalPort ?? o.localPort);
    const remotePort = Number(o.RemotePort ?? o.remotePort);
    const state = tcpStateName(o.State ?? o.state);
    const localIp = parseIp(String(o.LocalAddress ?? o.localIp ?? ""));
    const remoteIp = parseIp(String(o.RemoteAddress ?? o.remoteIp ?? ""));
    if (!Number.isInteger(pid) || pid <= 0) continue;
    if (!localIp || !remoteIp || !state) continue;
    if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) continue;
    if (!Number.isInteger(remotePort) || remotePort < 0 || remotePort > 65535) continue;
    out.push({ localIp, localPort, remoteIp, remotePort, state, pid });
  }
  return out;
}

function classifyError(err: string | undefined): NetworkSampleReport["status"] {
  const e = (err || "").toLowerCase();
  if (e.includes("timeout")) return "timeout";
  if (e.includes("truncated")) return "truncated";
  if (e.includes("access") || e.includes("denied") || e.includes("permission")) return "permission";
  if (e.includes("not_supported") || e.includes("unsupported") || e.includes("notfound") || e.includes("commandnotfound")) {
    return "unsupported";
  }
  return "error";
}

export function runPowershell(script: string, timeoutMs: number, maxStdout = NETWORK_STDOUT_MAX): Promise<NetworkRunResult> {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let truncated = false;
    const child = spawn(join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-Command", script], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const finish = (value: NetworkRunResult, kill: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (kill && child.exitCode === null && child.signalCode === null) {
        try {
          child.kill();
        } catch {
          /* already gone */
        }
      }
      child.stdout?.destroy();
      child.stderr?.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => finish({ stdout, timedOut: true, error: "timeout", truncated }, true), timeoutMs);
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (c: string) => {
      stdout += c;
      if (stdout.length > maxStdout) {
        stdout = stdout.slice(0, maxStdout);
        truncated = true;
        finish({ stdout, truncated: true, error: "truncated" }, true);
      }
    });
    child.stderr?.resume();
    child.on("error", () => finish({ stdout, error: "error" }, false));
    child.on("close", (code) => {
      if (settled) return;
      if (code !== 0) {
        finish({ stdout, error: code === null ? "timeout" : "error" }, false);
        return;
      }
      finish({ stdout, truncated }, false);
    });
  });
}

const inFlight = new Map<string, Promise<NetworkSampleReport>>();

function defaultRun(kind: NetworkScriptKind, script: string, timeoutMs: number): Promise<NetworkRunResult> {
  void kind;
  return runPowershell(script, timeoutMs);
}

export async function collectAgentTcp(opts: {
  stopped: boolean;
  timeoutMs?: number;
  deps?: NetworkCollectDeps;
  homeKey?: string;
  /** Exact identities supplied only by a trusted local owner; discovery metadata is never sufficient. */
  verifiedRoots?: ReadonlyArray<{pid:number;startedAt:number;exe:string;agent?:string}>;
}): Promise<NetworkSampleReport> {
  const clock = opts.deps?.now ?? Date.now;
  const started = clock();
  const platform = opts.deps?.platform ?? process.platform;
  if (opts.stopped) {
    return { status: "not_sampled", observedAt: started, connections: [], error: "not_sampled" };
  }
  if (platform !== "win32" && !opts.deps?.run) {
    return { status: "unsupported", observedAt: started, connections: [], error: "unsupported" };
  }
  if (!opts.deps?.run && !opts.verifiedRoots?.length) {
    return { status: "not_sampled", observedAt: started, connections: [], error: "no_confirmed_agent" };
  }
  const key = (opts.homeKey ?? "default") + "|" + JSON.stringify(opts.verifiedRoots ?? []);
  const existing = inFlight.get(key);
  if (existing) return existing;
  const timeoutMs = opts.timeoutMs ?? NETWORK_COLLECT_MS;
  const remaining = () => Math.max(0, timeoutMs - (clock() - started));
  const runStep = async (kind: NetworkScriptKind, script: string): Promise<NetworkRunResult> => {
    const left = remaining();
    if (left < 50) return { stdout: "", timedOut: true, error: "timeout" };
    try {
      if (opts.deps?.run) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          return await Promise.race([
            opts.deps.run(kind, script),
            new Promise<NetworkRunResult>((resolve) => {
              timer = setTimeout(() => resolve({ stdout: "", timedOut: true, error: "timeout" }), left);
            }),
          ]);
        } finally { if (timer) clearTimeout(timer); }
      }
      return await defaultRun(kind, script, left);
    } catch {
      return { stdout: "", error: "error" };
    }
  };

  const pending = (async (): Promise<NetworkSampleReport> => {
    const fail = (status: NetworkSampleReport["status"], extra?: Partial<NetworkSampleReport>): NetworkSampleReport => ({
      status,
      observedAt: clock(),
      connections: [],
      error: extra?.error ?? status,
      ...extra,
    });
    const before = await runStep("cim", opts.verifiedRoots ? WINDOWS_NETWORK_IDENTITY_SCRIPT(opts.verifiedRoots.map(r=>r.pid)) : WINDOWS_NETWORK_PROCESS_SCRIPT);
    if (before.timedOut) return fail("timeout");
    if (before.truncated) return fail("truncated", { truncated: true });
    if (before.error) return fail(classifyError(before.error));
    let records: unknown;
    try {
      records = parseJsonRecords(before.stdout);
    } catch {
      return fail("partial");
    }
    if (!Array.isArray(records) && (!records || typeof records !== "object")) return fail("partial");
    const rawRows = Array.isArray(records) ? records : [records];
    const identified = parseIdentifiedProcs(records);
    const invalidCandidate = rawRows.some((row: any) => !row || typeof row !== "object" || Array.isArray(row) ||
      (/^(grok|claude|codex)(\.exe)?$/i.test(String(row.Name ?? row.name ?? "")) && parseIdentifiedProcs(row).length === 0));
    // Exact approved roots only. A plugin/IDE or arbitrary child cannot inherit this authority.
    const tree = opts.verifiedRoots ? new Map<number,{agent:string;row:IdentifiedProc}>() : agentTree(identified);
    if(opts.verifiedRoots) for(const row of identified){
      const root=opts.verifiedRoots.find(p=>p.pid===row.pid&&p.startedAt===row.startedAt&&p.exe.toLowerCase()===row.exe.toLowerCase());
      const agent=root?.agent ?? (root ? confirmedAgentRoot(row) : null);
      if(agent)tree.set(row.pid,{agent,row});
    }
    const pids = [...tree.keys()];
    const observedAt = clock();
    if (!pids.length) {
      if (invalidCandidate) return fail("partial");
      return { status: "not_sampled", observedAt, connections: [], error: "no_confirmed_agent" };
    }

    const tcpRes = await runStep("tcp", WINDOWS_NETWORK_TCP_SCRIPT(pids));
    if (tcpRes.timedOut) return fail("timeout");
    if (tcpRes.truncated) return fail("truncated", { truncated: true });
    if (tcpRes.error) return fail(classifyError(tcpRes.error));
    let tcpRaw: unknown = [];
    try {
      tcpRaw = parseJsonRecords(tcpRes.stdout);
    } catch {
      return fail("partial");
    }
    if (!Array.isArray(tcpRaw) && (!tcpRaw || typeof tcpRaw !== "object")) return fail("partial");
    const tcpRows = parseTcpRows(tcpRaw);
    const tcpInvalid = (Array.isArray(tcpRaw) ? tcpRaw.length : 1) - tcpRows.length;

    const after = await runStep("cim_after", WINDOWS_NETWORK_IDENTITY_SCRIPT(pids));
    if (after.timedOut) return fail("timeout");
    if (after.truncated) return fail("truncated", { truncated: true });
    if (after.error) return fail(classifyError(after.error));
    let afterRecords: unknown = [];
    try {
      afterRecords = parseJsonRecords(after.stdout);
    } catch {
      return fail("partial");
    }
    if (!Array.isArray(afterRecords) && (!afterRecords || typeof afterRecords !== "object")) return fail("partial");
    const afterIdent = parseIdentifiedProcs(afterRecords);
    const afterByPid = new Map(afterIdent.map((r) => [r.pid, r]));

    const stable=(pid:number)=>opts.verifiedRoots ? !!tree.get(pid)&&!!afterByPid.get(pid)&&identityKey(tree.get(pid)!.row)===identityKey(afterByPid.get(pid)!) : ancestryStable(pid,tree,afterByPid);
    const connections: NetworkConnection[] = [];
    let dropped = tcpInvalid + (invalidCandidate ? 1 : 0) + pids.filter(pid => !stable(pid)).length;
    const sampleAt = clock();
    for (const row of tcpRows) {
      const beforeRow = tree.get(row.pid);
      if (!beforeRow) continue;
      if (!stable(row.pid)) {
        dropped += 1;
        continue;
      }
      const peer = isEgressTcp(row.state, row.remoteIp, row.remotePort);
      if (!peer) continue;
      const direction = row.state.trim().toLowerCase() === "synsent" ? "attempted" : "unknown";
      connections.push({
        remoteIp: row.remoteIp,
        remotePort: row.remotePort,
        localIp: row.localIp,
        localPort: row.localPort,
        state: row.state,
        role: "egress",
        direction,
        observedAt: sampleAt,
        pid: row.pid,
        ppid: beforeRow.row.ppid,
        processStartedAt: beforeRow.row.startedAt,
        bin: binOf({ pid: row.pid, ppid: beforeRow.row.ppid, name: beforeRow.row.name, exe: beforeRow.row.exe }),
        agent: beforeRow.agent,
      });
    }

    let status: NetworkSampleReport["status"] = "ok";
    if (connections.length > NETWORK_SAMPLE_MAX_CONNECTIONS) status = "truncated";
    else if (dropped > 0) status = "partial";
    const report: NetworkSampleReport = {
      status,
      observedAt: sampleAt,
      connections: connections.slice(0, NETWORK_SAMPLE_MAX_CONNECTIONS),
    };
    if (status !== "ok") report.error = status;
    if (status === "truncated") report.truncated = true;
    const parsed = parseNetworkSampleReport(report, { now: sampleAt, relaxTime: true });
    return parsed ?? fail("partial");
  })();

  inFlight.set(key, pending);
  try {
    return await pending;
  } finally {
    if (inFlight.get(key) === pending) inFlight.delete(key);
  }
}

export function networkCapabilityFrom(
  sample: NetworkSampleReport | undefined,
  now: number,
  platform: NodeJS.Platform = process.platform,
): { id: string; supported: boolean; active: boolean; lastSuccess?: number; error?: string } {
  const win = platform === "win32";
  if (!sample) {
    return { id: "network_sample", supported: win, active: false, error: win ? "not_sampled" : "unsupported" };
  }
  if (sample.status === "unsupported") {
    return { id: "network_sample", supported: false, active: false, error: "unsupported" };
  }
  if (sample.status === "ok") {
    return { id: "network_sample", supported: true, active: true, lastSuccess: sample.observedAt || now };
  }
  return { id: "network_sample", supported: win, active: false, error: sample.status };
}
