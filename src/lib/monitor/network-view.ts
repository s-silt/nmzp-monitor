import type { Msg } from "./i18n.ts";
import { ossHostShape } from "./network-evidence.ts";
import { HEARTBEAT_MS } from "./stats.ts";
import type { AuditEvent, EndpointEvidence, Machine, NetworkConnection, NetworkHistoryRow } from "./types.ts";

export const NETWORK_STALE_MS = HEARTBEAT_MS;
export const EXPORT_TIMEZONE = "Asia/Shanghai" as const;
export const EXPORT_UTC_OFFSET = "+08:00" as const;

export type NetworkViewStatus =
  | "ok"
  | "sampled_zero"
  | "missing"
  | "unsupported"
  | "permission"
  | "timeout"
  | "partial"
  | "truncated"
  | "not_sampled"
  | "stale"
  | "offline"
  | "error";

export type SampleQuality =
  | "ok"
  | "partial"
  | "truncated"
  | "timeout"
  | "unsupported"
  | "permission"
  | "not_sampled"
  | "missing"
  | "error";

export type TcpRow = NetworkConnection & { machineId: string; hostname: string; live: boolean };

export type DestinationKind = "endpoints" | "dest" | "empty" | "missing";

export interface SampleView {
  status: NetworkViewStatus;
  quality: SampleQuality;
  live: boolean;
  ageMs: number | null;
  observedAt: number | null;
  receivedAt: number | null;
  connections: NetworkConnection[];
  truncated: boolean;
}

export const CLOCK_TICK_MS = 15_000;

export interface EvidenceExport<T> {
  timezone: typeof EXPORT_TIMEZONE;
  utcOffset: typeof EXPORT_UTC_OFFSET;
  exportedAt: number;
  records: T[];
}



export function connectionKey(c: {
  pid: number;
  processStartedAt: number;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  machineId?: string;
}): string {
  return `${c.machineId ?? ""}:${c.pid}:${c.processStartedAt}:${c.localIp}:${c.localPort}:${c.remoteIp}:${c.remotePort}`;
}

export function formatSocket(ip: string, port: number): string {
  if (!ip) return "—";
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return Number.isInteger(port) && port > 0 ? `${host}:${port}` : host;
}

export function tcpStateLabel(state: string): string {
  const s = state.trim().toLowerCase().replace(/[_-\s]/g, "");
  if (s === "established") return "Established";
  if (s === "synsent") return "SynSent";
  return state.trim() || "—";
}

export function hostLike(value: string | undefined): value is string {
  if (!value) return false;
  const h = value.trim();
  if (!h || h.length > 253) return false;
  if (h.includes("/") || h.includes("?") || h.includes("#") || h.includes("@")) return false;
  return true;
}

export function formatDeclaredHost(ep: EndpointEvidence): string {
  const host = ep.host.includes(":") && ep.scheme ? `[${ep.host}]` : ep.host;
  const port = typeof ep.port === "number" && ep.port > 0 ? `:${ep.port}` : "";
  return ep.scheme ? `${ep.scheme}://${host}${port}` : `${host}${port}`;
}

export function ossShapeOf(host: string): boolean {
  return ossHostShape(host);
}

/** Freshness uses collector observedAt, never receivedAt (replayed heartbeat). */
function sampleAgeMs(observedAt: number | undefined, now: number): number | null {
  if (typeof observedAt !== "number" || !Number.isFinite(observedAt) || observedAt <= 0 || observedAt > now) return null;
  return now - observedAt;
}

function lastSeenAged(machine: Machine, now: number): boolean {
  const seen = machine.lastSeen;
  if (typeof seen !== "number" || !Number.isFinite(seen) || seen <= 0) return false;
  return now - seen > NETWORK_STALE_MS;
}

function isPeerObservation(c: NetworkConnection): boolean {
  if (c.role === "local") return false;
  return true;
}

function qualityOf(status: string, truncated: boolean): SampleQuality {
  if (truncated || status === "truncated") return "truncated";
  if (status === "partial") return "partial";
  if (status === "timeout" || status === "unsupported" || status === "permission" || status === "not_sampled") {
    return status;
  }
  if (status === "ok") return "ok";
  return "error";
}

export function sampleView(machine: Machine, now: number): SampleView {
  const offline = machine.status === "dark" || machine.status === "archived" || lastSeenAged(machine, now);
  const empty: SampleView = {
    status: offline ? "offline" : "missing",
    quality: "missing",
    live: false,
    ageMs: null,
    observedAt: null,
    receivedAt: null,
    connections: [],
    truncated: false,
  };
  const report = machine.network;
  if (!report) return empty;

  const ageMs = sampleAgeMs(report.observedAt, now);
  const truncated = report.truncated === true || report.status === "truncated";
  const quality = qualityOf(report.status, truncated);
  const failed = quality === "timeout" || quality === "unsupported" || quality === "permission" || quality === "not_sampled";
  const connections = failed ? [] : report.connections.filter(isPeerObservation);
  const receivedAt =
    typeof report.receivedAt === "number" && Number.isFinite(report.receivedAt) ? report.receivedAt : null;
  const base: SampleView = {
    status: "missing",
    quality,
    live: false,
    ageMs,
    observedAt: Number.isFinite(report.observedAt) ? report.observedAt : null,
    receivedAt,
    connections,
    truncated,
  };

  if (offline) return { ...base, status: "offline" };
  if (ageMs === null || ageMs > NETWORK_STALE_MS) return { ...base, status: "stale" };
  if (failed) return { ...base, status: quality };
  if (quality === "error") return { ...base, status: "error" };
  if (quality === "partial") return { ...base, status: "partial", live: true };
  if (quality === "truncated") return { ...base, status: "truncated", live: true };
  if (connections.length === 0) return { ...base, status: "sampled_zero", live: true };
  return { ...base, status: "ok", live: true };
}

export function sampleStatusKey(status: NetworkViewStatus): Msg {
  if (status === "ok") return "netOk";
  if (status === "sampled_zero") return "netSampledZero";
  if (status === "unsupported") return "netUnsupported";
  if (status === "permission") return "netPermission";
  if (status === "timeout") return "netTimeout";
  if (status === "partial") return "netPartial";
  if (status === "truncated") return "netTruncated";
  if (status === "not_sampled") return "netNotSampled";
  if (status === "stale") return "netStale";
  if (status === "offline") return "netOffline";
  if (status === "error") return "netSampleError";
  return "notCollected";
}

export function isLiveSample(status: NetworkViewStatus): boolean {
  return status === "ok" || status === "sampled_zero" || status === "partial" || status === "truncated";
}

export function dedupConnections<T extends NetworkConnection & { machineId?: string }>(rows: T[]): T[] {
  const map = new Map<string, T>();
  for (const row of rows) {
    const key = connectionKey(row);
    const prev = map.get(key);
    if (!prev || row.observedAt > prev.observedAt) map.set(key, row);
  }
  return [...map.values()].sort((a, b) => b.observedAt - a.observedAt);
}

export function scopedConnections<T extends NetworkConnection>(rows: T[], agent: string | "all"): T[] {
  if (agent === "all") return rows;
  return rows.filter((c) => c.agent === agent);
}

export function matchesTcpQuery(row: TcpRow, q: string): boolean {
  if (!q) return true;
  return `${row.machineId} ${row.hostname} ${row.agent} ${row.bin} ${row.pid} ${row.processStartedAt} ${row.remoteIp} ${row.remotePort} ${row.localIp} ${row.localPort} ${row.state}`
    .toLowerCase()
    .includes(q);
}

export function collectTcpRows(
  samples: Array<{ machine: Machine; view: SampleView }>,
  opts: { agent: string | "all"; query?: string },
): TcpRow[] {
  const q = opts.query?.trim().toLowerCase() ?? "";
  const rows: TcpRow[] = [];
  for (const { machine, view } of samples) {
    for (const c of scopedConnections(view.connections, opts.agent)) {
      rows.push({ ...c, machineId: machine.id, hostname: machine.hostname, live: view.live });
    }
  }
  return dedupConnections(rows).filter((c) => matchesTcpQuery(c, q));
}

export function networkExportPayload(input: {
  exportedAt: number;
  filters: { machineId: string; agent: string; query: string; ossHigh: boolean };
  samples: Array<{
    machineId: string;
    hostname: string;
    status: NetworkViewStatus;
    quality: SampleQuality;
    live: boolean;
    ageMs: number | null;
    observedAt: number | null;
    receivedAt: number | null;
    truncated: boolean;
  }>;
  tcp: TcpRow[];
  history: NetworkHistoryRow[];
  declared: AuditEvent[];
}) {
  return {
    timezone: EXPORT_TIMEZONE,
    utcOffset: EXPORT_UTC_OFFSET,
    exportedAt: input.exportedAt,
    filters: input.filters,
    samples: input.samples,
    tcp: input.tcp,
    history: input.history,
    declared: input.declared,
  };
}

export function isSynSent(state: string): boolean {
  return tcpStateLabel(state) === "SynSent";
}

export function scopedHistory(
  rows: NetworkHistoryRow[],
  opts: { machineId: string | "all"; agent: string | "all"; query?: string },
): NetworkHistoryRow[] {
  const q = opts.query?.trim().toLowerCase() ?? "";
  return rows
    .filter((row) => {
      if (opts.machineId !== "all" && row.machineId !== opts.machineId) return false;
      if (opts.agent !== "all" && row.agent !== opts.agent) return false;
      if (!q) return true;
      return historySearchText(row).includes(q);
    })
    .sort((a, b) => b.lastSeen - a.lastSeen);
}

export function historySearchText(row: NetworkHistoryRow): string {
  return [
    row.id,
    row.machineId,
    row.agent,
    row.bin,
    String(row.pid),
    String(row.processStartedAt),
    row.remoteIp,
    String(row.remotePort),
    row.localIp,
    String(row.localPort),
    row.state,
  ]
    .join(" ")
    .toLowerCase();
}

export function declaredTargets(event: AuditEvent): {
  collected: boolean;
  endpoints: EndpointEvidence[];
  dest?: string;
} {
  const dest = hostLike(event.dest) ? event.dest.trim() : undefined;
  if (event.endpoints === undefined) {
    return { collected: false, endpoints: [], dest };
  }
  return { collected: true, endpoints: event.endpoints, dest };
}

export function visibleDestinations(event: AuditEvent): { kind: DestinationKind; hosts: string[] } {
  const t = declaredTargets(event);
  if (t.endpoints.length > 0) {
    return { kind: "endpoints", hosts: t.endpoints.map(formatDeclaredHost) };
  }
  if (t.collected) return { kind: "empty", hosts: [] };
  if (t.dest) return { kind: "dest", hosts: [t.dest] };
  return { kind: "missing", hosts: [] };
}

export function eventOssHosts(event: AuditEvent): string[] {
  const out: string[] = [];
  for (const ep of event.endpoints ?? []) {
    if (ossShapeOf(ep.host) && !out.includes(ep.host)) out.push(ep.host);
  }
  if (hostLike(event.dest) && ossShapeOf(event.dest) && !out.includes(event.dest)) out.push(event.dest);
  return out;
}

export function isHighRiskOss(event: AuditEvent): boolean {
  if (event.layer === "model_response") return false;
  return event.risk === "high" && eventOssHosts(event).length > 0;
}

export function eventSearchText(event: AuditEvent): string {
  const hosts = (event.endpoints ?? []).map((ep) => `${ep.host} ${ep.port ?? ""} ${ep.scheme ?? ""} ${ep.source}`).join(" ");
  return [
    event.id,
    event.machineId,
    event.sessionId,
    event.proc,
    event.dest,
    event.requestHash,
    event.input,
    event.redacted,
    event.tool,
    event.nativeTool,
    event.ruleId,
    hosts,
  ]
    .filter((x) => typeof x === "string" && x)
    .join(" ")
    .toLowerCase();
}

export function eventMatchesQuery(event: AuditEvent, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return eventSearchText(event).includes(q);
}

const NETWORK_CATEGORIES = new Set(["network", "exfil", "download"]);

/** Explicit outbound/exfil rules. Self-tamper and file Read/Edit are not in this set. */
const OUTBOUND_RULE_IDS = new Set([
  "telemetry_drop",
  "clipboard_pipe_upload",
  "screenshot_then_upload",
  "screenshot_file_upload",
  "zcode_snapshot_host",
  "zcode_oss_form",
  "pack_pipe_upload",
  "curl_upload_archive",
  "anonymous_drop_host",
  "scp_rsync_tree",
  "rclone_cloud_copy",
  "git_archive_exfil",
  "env_piped_outbound",
  "curl_post_local_file",
  "wget_post_file",
  "nc_redirect_file",
  "anonymous_drop_url",
  "curl_pipe_shell",
  "reverse_shell_pattern",
  "curl_download_then_exec",
  "ssh_tunnel_reverse_proxy",
  "download_operation",
  "network_diag",
  "ssh_operation",
]);

function hasSafeDeclaredHost(event: AuditEvent): boolean {
  if ((event.endpoints ?? []).some((ep) => hostLike(ep.host))) return true;
  return hostLike(event.dest);
}

export function isNetworkRelevantEvent(event: AuditEvent): boolean {
  if (event.layer === "model_response") return false;
  if (hasSafeDeclaredHost(event)) return true;
  if (NETWORK_CATEGORIES.has(event.category)) return true;
  if (event.threat === "exfil") return true;
  if (event.ruleId && OUTBOUND_RULE_IDS.has(event.ruleId)) return true;
  return false;
}

export function filterDeclaredEvents(
  events: AuditEvent[],
  opts: { query?: string; ossHigh?: boolean },
): AuditEvent[] {
  return events
    .filter((e) => isNetworkRelevantEvent(e))
    .filter((e) => (opts.ossHigh ? isHighRiskOss(e) : true))
    .filter((e) => eventMatchesQuery(e, opts.query ?? ""))
    .sort((a, b) => b.ts - a.ts);
}

export function tcpEmptyKind(
  samples: Array<{ view: SampleView }>,
  tcpCount: number,
  opts: { query?: string; agent?: string | "all" },
): "sampled_zero" | "none_visible" {
  if (tcpCount > 0) return "none_visible";
  const q = opts.query?.trim() ?? "";
  const agent = opts.agent ?? "all";
  if (q || agent !== "all") return "none_visible";
  if (!samples.length) return "none_visible";
  if (samples.every((s) => s.view.status === "sampled_zero")) return "sampled_zero";
  return "none_visible";
}

export function shortEvidenceId(id: string): string {
  const t = id.trim();
  return t.length <= 12 ? t : t.slice(0, 10);
}

export function decisionMsg(decision: AuditEvent["decision"]): Msg {
  if (decision === "block") return "block";
  if (decision === "rewrite") return "rewrite";
  if (decision === "allow") return "allow";
  if (decision === "log") return "log";
  if (decision === "confirm") return "confirm";
  return "unknown";
}

export function enforcementMsg(enforcement: AuditEvent["enforcement"]): Msg {
  if (enforcement === "blocked") return "blocked";
  if (enforcement === "returned_deny") return "returnedDeny";
  if (enforcement === "pending_verify") return "netEnforcementPending";
  if (enforcement === "timeout") return "netEnforcementTimeout";
  if (enforcement === "failed") return "netEnforcementFailed";
  if (enforcement === "delivered") return "netEnforcementDelivered";
  if (enforcement === "offline") return "disconnected";
  if (enforcement === "degraded") return "netEnforcementDegraded";
  return "unknown";
}

export function evidenceExport<T>(records: T[], exportedAt: number): EvidenceExport<T> {
  return {
    timezone: EXPORT_TIMEZONE,
    utcOffset: EXPORT_UTC_OFFSET,
    exportedAt,
    records,
  };
}

/** Declared URL targets are never a proven DNS mapping of observed TCP. */
export function sameHostNotProvenDns(declaredHost: string, remoteIp: string): boolean {
  void declaredHost;
  void remoteIp;
  return false;
}

/** Public fixed text only; never display arbitrary collector error bodies. */
export function networkOwnerMessage(error: string | undefined, locale: string): string | null {
  const messages: Record<string,[string,string]> = {
    no_confirmed_agent:["没有当前有效的进程采样授权","No active process sampling approval"],
    owner_authority_unavailable:["采样授权服务不可用，未采样","Sampling authority unavailable; no sample"],
    owner_hash_mismatch:["文件或登记路径与授权不符，未采样","File or path differs from approval; no sample"],
    owner_identity_changed:["进程已退出或身份改变，未采样","Process exited or identity changed; no sample"],
    owner_identity_unavailable:["无法复核进程身份，未采样","Process identity unavailable; no sample"],
    owner_revoked:["采样期间授权失效，本次结果已丢弃","Approval invalidated during sampling; result discarded"],
    owner_expired:["进程采样授权已过期","Process sampling approval expired"],
    owner_hash_timeout:["文件身份校验超时，未采样","File verification timed out; no sample"],
    owner_file_changed:["校验期间文件变化，未采样","File changed during verification; no sample"],
    owner_file_invalid:["文件身份不能确认，未采样","File identity unconfirmed; no sample"],
    owner_path_invalid:["本机登记路径无效，未采样","Local path registration invalid; no sample"],
  };
  return error && messages[error] ? messages[error][locale==="zh"?0:1] : null;
}
