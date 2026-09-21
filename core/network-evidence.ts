import {parseEgressEvidence} from "./egress-schema.ts";
import {parseResponseEvidence} from "./response-evidence.ts";
/**
 * Declared URL targets and TCP sample parsing.
 * Evaluate original tool input first; this module only projects safe audit fields.
 * Never persist userinfo, path, query, fragment, or reverse-DNS names.
 */

import type { CustomPrivacyRule } from "./schema.ts";
import type {
  EndpointEvidence,
  EndpointSource,
  NetworkConnection,
  NetworkHistoryRow,
  NetworkRole,
  NetworkSampleReport,
  NetworkSampleStatus,
} from "./schema.ts";

export const NETWORK_EVIDENCE_MAX_ENDPOINTS = 8;
export const MAX_NETWORK_HISTORY = 2000;
export const NETWORK_SAMPLE_MAX_CONNECTIONS = 256;
export const NETWORK_STDOUT_MAX = 256_000;
export const NETWORK_CLOCK_SKEW_MS = 10 * 60 * 1000;
export const NETWORK_MIN_TS = Date.UTC(2000, 0, 1);
export const HOST_MAX = 253;

const HTTP_URL_RE = /https?:\/\/[^\s<>"'\\]+/gi;

const HOST_SECRET_RES: RegExp[] = [
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/i,
  /\bsk-[A-Za-z0-9_-]{20,}\b/i,
  /\bxai-[A-Za-z0-9_-]{20,}\b/i,
  /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/i,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bnpm_[A-Za-z0-9]{20,}\b/i,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/i,
  /\beyJ[A-Za-z0-9_-]{18,}\.[A-Za-z0-9_-]{8,}\./,
];

const EGRESS_STATES = new Set(["established", "synsent"]);
const ZERO_REMOTE = new Set(["", "*", "0.0.0.0", "::", "::0", "0000:0000:0000:0000:0000:0000:0000:0000"]);

export interface EndpointScanFns {
  scanSecrets?: (text: string) => Array<{ index?: number; length?: number }>;
  scanCustom?: (text: string, rules: CustomPrivacyRule[]) => Array<{ index?: number; length?: number }>;
  customRules?: CustomPrivacyRule[];
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function peelUrlToken(raw: string): string {
  const t = raw.trim();
  // Do not strip ']' from bracketed IPv6 literals.
  if (t.includes("[")) return t.replace(/[),.;}>]+$/g, "");
  return t.replace(/[),.;\]}>]+$/g, "");
}

export function hostHasSecret(host: string, scan?: EndpointScanFns): boolean {
  const h = host.trim();
  if (!h) return true;
  for (const re of HOST_SECRET_RES) {
    re.lastIndex = 0;
    if (re.test(h)) return true;
  }
  if (scan?.scanSecrets && scan.scanSecrets(h).length) return true;
  if (scan?.scanCustom && scan.customRules?.length && scan.scanCustom(h, scan.customRules).length) return true;
  return false;
}

export function ossHostShape(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (!h || h.length > HOST_MAX) return false;
  if (/(^|\.)oss[-.][a-z0-9-]+\.aliyuncs\.com$/.test(h)) return true;
  if (/^oss-[a-z0-9-]+\.aliyuncs\.com$/.test(h)) return true;
  if (/(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$/.test(h)) return true;
  if (/(^|\.)cos\.[a-z0-9-]+\.myqcloud\.com$/.test(h)) return true;
  if (/(^|\.)tos-cn-[a-z0-9-]+\.volces\.com$/.test(h)) return true;
  if (/(^|\.)r2\.cloudflarestorage\.com$/.test(h)) return true;
  if (/(^|\.)blob\.core\.windows\.net$/.test(h)) return true;
  if (h === "storage.googleapis.com" || /(^|\.)storage\.googleapis\.com$/.test(h)) return true;
  return false;
}

function isIPv4(host: string): boolean {
  const p = host.split(".");
  if (p.length !== 4) return false;
  return p.every((x) => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255);
}

/** Portable RFC 4291 IPv6. Rejects ::::, 1:2:3, 1::2::3. No node:net. */
export function parseIpv6(raw: string): string | undefined {
  const s = raw.trim().toLowerCase();
  if (!s || s.length > 45 || s.includes("%")) return undefined;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped) return isIPv4(mapped[1]!) ? mapped[1] : undefined;
  if (s.includes(".")) return undefined;
  if ((s.match(/::/g) ?? []).length > 1) return undefined;
  const compressed = s.includes("::");
  const hex = (p: string) => p === "" || /^[0-9a-f]{1,4}$/.test(p);
  if (!compressed) {
    const parts = s.split(":");
    if (parts.length !== 8 || parts.some((p) => !p || !hex(p))) return undefined;
    return s;
  }
  const [left, right] = s.split("::");
  const leftParts = left === "" ? [] : left.split(":");
  const rightParts = right === "" ? [] : right.split(":");
  if (leftParts.some((p) => !hex(p)) || rightParts.some((p) => !hex(p))) return undefined;
  if (leftParts.some((p) => p === "") || rightParts.some((p) => p === "")) return undefined;
  if (leftParts.length + rightParts.length > 7) return undefined;
  return s;
}

function isIPv6(host: string): boolean {
  return parseIpv6(host) !== undefined;
}

function isDnsHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (!h || h.length > HOST_MAX) return false;
  if (h === "localhost") return true;
  if (!/^[a-z0-9.-]+$/.test(h)) return false;
  if (h.startsWith("-") || h.endsWith("-") || h.includes("..")) return false;
  const labels = h.split(".");
  if (!labels.length || labels.some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) return false;
  return true;
}

export function isValidHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (!h || h.length > HOST_MAX) return false;
  if (/[/\\?#@\s\0]/.test(h)) return false;
  if (isIPv4(h) || isIPv6(h) || isDnsHost(h)) return true;
  return false;
}

export function parseIp(raw: string): string | undefined {
  let t = raw.trim().toLowerCase();
  if (t.startsWith("[") && t.endsWith("]") && t.includes(":")) t = t.slice(1, -1);
  const noZone = t.replace(/%[a-z0-9._-]+$/i, "");
  if (isIPv4(noZone)) return noZone;
  return parseIpv6(noZone);
}

function isZeroRemote(ip: string): boolean {
  const n = ip.trim().toLowerCase();
  return ZERO_REMOTE.has(n) || n === "0:0:0:0:0:0:0:0";
}

export function isEgressTcp(state: string, remoteIp: string, remotePort: number): boolean {
  if (!EGRESS_STATES.has(state.trim().toLowerCase())) return false;
  if (!Number.isInteger(remotePort) || remotePort < 1 || remotePort > 65535) return false;
  if (isZeroRemote(remoteIp)) return false;
  return parseIp(remoteIp) !== undefined;
}

function parsePort(raw: unknown): number | undefined {
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 1 && raw <= 65535) return raw;
  if (typeof raw === "string" && /^\d{1,5}$/.test(raw)) {
    const n = Number(raw);
    if (n >= 1 && n <= 65535) return n;
  }
  return undefined;
}

export function parseHttpUrl(
  raw: string,
  scan?: EndpointScanFns,
): { host: string; port?: number; scheme: "http" | "https" } | undefined {
  const peeled = peelUrlToken(raw);
  if (!/^https?:\/\//i.test(peeled)) return undefined;
  let u: URL;
  try {
    u = new URL(peeled);
  } catch {
    return undefined;
  }
  const scheme = u.protocol === "http:" ? "http" : u.protocol === "https:" ? "https" : undefined;
  if (!scheme) return undefined;
  let host = (u.hostname || "").trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (!host || host.length > HOST_MAX || /[/\\?#@\s\0]/.test(host)) return undefined;
  if (!isValidHost(host)) return undefined;
  if (hostHasSecret(host, scan)) return undefined;
  const port = u.port ? parsePort(u.port) : undefined;
  if (u.port && port === undefined) return undefined;
  return port ? { host, port, scheme } : { host, scheme };
}

function parseBareHostPort(raw: string, scan?: EndpointScanFns): { host: string; port?: number } | undefined {
  const t = raw.trim();
  if (!t || /^https?:\/\//i.test(t)) return undefined;
  if (/[/\\?#@\s\0]/.test(t)) return undefined;
  let host = t;
  let port: number | undefined;
  if (t.startsWith("[")) {
    const end = t.indexOf("]");
    if (end < 2) return undefined;
    host = t.slice(1, end);
    const rest = t.slice(end + 1);
    if (rest.startsWith(":")) port = parsePort(rest.slice(1));
    else if (rest) return undefined;
  } else if (/^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/.test(t) || (/^[a-z0-9.-]+:\d{1,5}$/i.test(t) && t.split(":").length === 2)) {
    const i = t.lastIndexOf(":");
    host = t.slice(0, i);
    port = parsePort(t.slice(i + 1));
    if (port === undefined) return undefined;
  }
  host = host.trim().toLowerCase();
  if (!isValidHost(host) || hostHasSecret(host, scan)) return undefined;
  return port ? { host, port } : { host };
}

function originFromParsed(p: { host: string; port?: number; scheme: "http" | "https" }): string {
  const host = p.host.includes(":") ? `[${p.host}]` : p.host;
  return p.port ? `${p.scheme}://${host}:${p.port}` : `${p.scheme}://${host}`;
}

/** Replace explicit URLs with scheme://host[:port] or [url]. Never keep query/userinfo/path. */
export function sanitizeAuditText(text: string, scan?: EndpointScanFns): string {
  if (!text) return text;
  HTTP_URL_RE.lastIndex = 0;
  return text.replace(HTTP_URL_RE, (raw) => {
    const parsed = parseHttpUrl(raw, scan);
    if (!parsed) return "[url]";
    return originFromParsed(parsed);
  });
}

function pushEndpoint(out: EndpointEvidence[], ep: EndpointEvidence): void {
  if (out.length >= NETWORK_EVIDENCE_MAX_ENDPOINTS) return;
  const any = `${ep.scheme ?? ""}|${ep.host}|${ep.port ?? ""}`;
  if (out.some((e) => `${e.scheme ?? ""}|${e.host}|${e.port ?? ""}` === any)) return;
  out.push(ep);
}

function endpointFromParsed(
  parsed: { host: string; port?: number; scheme?: "http" | "https" },
  source: EndpointSource,
): EndpointEvidence {
  const ep: EndpointEvidence = { host: parsed.host, source, observation: "declared" };
  if (parsed.port) ep.port = parsed.port;
  if (parsed.scheme) ep.scheme = parsed.scheme;
  return ep;
}

export function extractDeclaredEndpoints(
  opts: { url?: string; dest?: string; command?: string } & EndpointScanFns,
): EndpointEvidence[] {
  const scan: EndpointScanFns = {
    scanSecrets: opts.scanSecrets,
    scanCustom: opts.scanCustom,
    customRules: opts.customRules,
  };
  const out: EndpointEvidence[] = [];
  const consider = (raw: string | undefined, source: EndpointSource) => {
    if (!raw || out.length >= NETWORK_EVIDENCE_MAX_ENDPOINTS) return;
    if (/^https?:\/\//i.test(raw.trim())) {
      const parsed = parseHttpUrl(raw, scan);
      if (parsed) pushEndpoint(out, endpointFromParsed(parsed, source));
      return;
    }
    if (source === "tool_url") {
      const bare = parseBareHostPort(raw, scan);
      if (bare) pushEndpoint(out, endpointFromParsed(bare, source));
    }
  };

  consider(opts.url, "tool_url");
  consider(opts.dest, "tool_url");

  const command = opts.command ?? "";
  if (command) {
    HTTP_URL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = HTTP_URL_RE.exec(command))) {
      const parsed = parseHttpUrl(m[0], scan);
      if (parsed) pushEndpoint(out, endpointFromParsed(parsed, "tool_command"));
      if (HTTP_URL_RE.lastIndex === m.index) HTTP_URL_RE.lastIndex += 1;
    }
  }
  return out.slice(0, NETWORK_EVIDENCE_MAX_ENDPOINTS);
}

export function parseEndpointEvidence(raw: unknown): EndpointEvidence | undefined {
  if (!isPlain(raw)) return undefined;
  const host = typeof raw.host === "string" ? raw.host.trim().toLowerCase() : "";
  if (!isValidHost(host) || hostHasSecret(host)) return undefined;
  const source = raw.source === "tool_url" || raw.source === "tool_command" ? raw.source : undefined;
  if (!source) return undefined;
  if (raw.observation !== "declared") return undefined;
  const ep: EndpointEvidence = { host, source, observation: "declared" };
  if (raw.scheme !== undefined) {
    if (raw.scheme !== "http" && raw.scheme !== "https") return undefined;
    ep.scheme = raw.scheme;
  }
  if (raw.port !== undefined) {
    const port = parsePort(raw.port);
    if (port === undefined) return undefined;
    ep.port = port;
  }
  return ep;
}

/** undefined = field missing (未采集). Array (maybe empty) = collected this event. */
export function parseEndpointList(raw: unknown): EndpointEvidence[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) return undefined;
  const out: EndpointEvidence[] = [];
  for (const row of raw) {
    const ep = parseEndpointEvidence(row);
    if (ep) pushEndpoint(out, ep);
    if (out.length >= NETWORK_EVIDENCE_MAX_ENDPOINTS) break;
  }
  return out;
}

const SAMPLE_STATUSES = new Set<NetworkSampleStatus>([
  "ok",
  "timeout",
  "unsupported",
  "permission",
  "partial",
  "truncated",
  "not_sampled",
  "error",
]);

function boundedBin(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const bin = raw.trim().slice(0, 64);
  if (!bin || bin.includes("/") || bin.includes("\\") || bin.includes("\0") || bin.includes("..")) return undefined;
  return bin;
}

function boundedAgent(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const a = raw.trim().slice(0, 32);
  return a || undefined;
}

function boundedPid(raw: unknown, allowZeroPpid = false): number | undefined {
  if (typeof raw !== "number" || !Number.isInteger(raw)) return undefined;
  if (allowZeroPpid) {
    if (raw < 0 || raw > 4_000_000_000) return undefined;
    return raw;
  }
  if (raw <= 0 || raw > 4_000_000_000) return undefined;
  return raw;
}

function validTs(n: unknown, opts?: { now?: number; relaxTime?: boolean }): number | undefined {
  if (typeof n !== "number" || !Number.isFinite(n) || n < NETWORK_MIN_TS) return undefined;
  const now = opts?.now ?? Date.now();
  const skew = opts?.relaxTime ? NETWORK_CLOCK_SKEW_MS * 24 : NETWORK_CLOCK_SKEW_MS;
  if (n > now + skew) return undefined;
  return n;
}

export function parseNetworkConnection(raw: unknown, opts?: { now?: number; relaxTime?: boolean }): NetworkConnection | undefined {
  if (!isPlain(raw)) return undefined;
  const remoteIp = typeof raw.remoteIp === "string" ? parseIp(raw.remoteIp) : undefined;
  const localIp = typeof raw.localIp === "string" ? parseIp(raw.localIp) : undefined;
  const remotePort = parsePort(raw.remotePort);
  const localPort = parsePort(raw.localPort);
  const state = typeof raw.state === "string" ? raw.state.trim().slice(0, 32) : "";
  const role: NetworkRole = raw.role === "egress" || raw.role === "local" ? raw.role : "local";
  const observedAt = validTs(raw.observedAt, opts);
  const pid = boundedPid(raw.pid);
  const ppid = boundedPid(raw.ppid, true);
  const processStartedAt = validTs(raw.processStartedAt, opts);
  const bin = boundedBin(raw.bin);
  const agent = boundedAgent(raw.agent);
  if (!remoteIp || !localIp || !remotePort || !localPort || !state || !observedAt || !pid || ppid === undefined || !processStartedAt || !bin || !agent) {
    return undefined;
  }
  if (processStartedAt > observedAt + NETWORK_CLOCK_SKEW_MS) return undefined;
  const peer = isEgressTcp(state, remoteIp, remotePort);
  if (role === "egress" && !peer) return undefined;
  const st = state.trim().toLowerCase();
  const direction: NetworkConnection["direction"] = st === "synsent" ? "attempted" : "unknown";
  const parsedDirection =
    raw.direction === "unknown" || raw.direction === "attempted" ? raw.direction : direction;
  const out: NetworkConnection = {
    remoteIp,
    remotePort,
    localIp,
    localPort,
    state,
    role: peer ? "egress" : "local",
    direction: parsedDirection,
    observedAt,
    pid,
    ppid,
    processStartedAt,
    bin,
    agent,
  };
  return out;
}

export function parseNetworkSampleReport(raw: unknown, opts?: { now?: number; relaxTime?: boolean }): NetworkSampleReport | undefined {
  if (!isPlain(raw)) return undefined;
  const status = typeof raw.status === "string" && SAMPLE_STATUSES.has(raw.status as NetworkSampleStatus) ? (raw.status as NetworkSampleStatus) : undefined;
  if (!status) return undefined;
  const observedAt = validTs(raw.observedAt, opts);
  if (!observedAt) return undefined;
  if (Object.prototype.hasOwnProperty.call(raw, "error") && raw.error !== undefined) {
    if (typeof raw.error !== "string" || !/^[a-z0-9_-]{1,64}$/i.test(raw.error)) return undefined;
  }
  if (status === "ok" && (raw.connections === undefined || raw.truncated === true || raw.error !== undefined)) return undefined;
  if (raw.connections !== undefined && !Array.isArray(raw.connections)) return undefined;
  const connections: NetworkConnection[] = [];
  let invalid = 0;
  const rows = Array.isArray(raw.connections) ? raw.connections : [];
  for (const row of rows) {
    const c = parseNetworkConnection(row, opts);
    if (!c) {
      invalid += 1;
      continue;
    }
    if (c.role !== "egress") continue;
    connections.push(c);
  }
  const failed =
    status === "timeout" ||
    status === "unsupported" ||
    status === "permission" ||
    status === "not_sampled" ||
    status === "error";
  let nextStatus = status;
  if (!failed && status === "ok") {
    if (invalid > 0) nextStatus = "partial";
    if (rows.length > NETWORK_SAMPLE_MAX_CONNECTIONS || connections.length > NETWORK_SAMPLE_MAX_CONNECTIONS) {
      nextStatus = "truncated";
    }
  }
  const out: NetworkSampleReport = {
    status: nextStatus,
    observedAt,
    connections: failed ? [] : connections.slice(0, NETWORK_SAMPLE_MAX_CONNECTIONS),
  };
  if (typeof raw.error === "string") out.error = raw.error.toLowerCase();
  else if (nextStatus !== "ok" && nextStatus !== "not_sampled") out.error = nextStatus;
  if (raw.truncated === true || nextStatus === "truncated") out.truncated = true;
  if (Object.prototype.hasOwnProperty.call(raw, "receivedAt") && raw.receivedAt !== undefined) {
    const receivedAt = validTs(raw.receivedAt, opts);
    if (receivedAt) out.receivedAt = receivedAt;
  }
  return out;
}

export function parseNetworkHistoryRow(raw: unknown, opts?: { now?: number; relaxTime?: boolean }): NetworkHistoryRow | undefined {
  if (!isPlain(raw)) return undefined;
  const id = typeof raw.id === "string" && /^[a-z0-9_-]{6,80}$/i.test(raw.id) ? raw.id : undefined;
  const machineId = typeof raw.machineId === "string" && raw.machineId.trim() ? raw.machineId.trim().slice(0, 80) : undefined;
  if (!id || !machineId) return undefined;
  const conn = parseNetworkConnection(
    {
      remoteIp: raw.remoteIp,
      remotePort: raw.remotePort,
      localIp: raw.localIp,
      localPort: raw.localPort,
      state: raw.state,
      role: "egress",
      observedAt: raw.lastSeen ?? raw.firstSeen,
      pid: raw.pid,
      ppid: raw.ppid,
      processStartedAt: raw.processStartedAt,
      bin: raw.bin,
      agent: raw.agent,
    },
    opts,
  );
  if (!conn || conn.role !== "egress") return undefined;
  const firstSeen = validTs(raw.firstSeen, opts);
  const lastSeen = validTs(raw.lastSeen, opts);
  if (!firstSeen || !lastSeen || lastSeen < firstSeen) return undefined;
  return {
    id,
    machineId,
    agent: conn.agent,
    pid: conn.pid,
    ppid: conn.ppid,
    processStartedAt: conn.processStartedAt,
    bin: conn.bin,
    remoteIp: conn.remoteIp,
    remotePort: conn.remotePort,
    localIp: conn.localIp,
    localPort: conn.localPort,
    state: conn.state,
    direction: conn.direction,
    role: "egress",
    firstSeen,
    lastSeen,
  };
}

export function networkHistoryKey(machineId: string, c: Pick<NetworkConnection, "pid" | "processStartedAt" | "remoteIp" | "remotePort" | "localIp" | "localPort">): string {
  return `${machineId}|${c.pid}|${c.processStartedAt}|${c.remoteIp}|${c.remotePort}|${c.localIp}|${c.localPort}`;
}

export function upsertNetworkHistory(
  rows: NetworkHistoryRow[],
  machineId: string,
  sample: NetworkSampleReport,
  newId: () => string,
  max = MAX_NETWORK_HISTORY,
): NetworkHistoryRow[] {
  if (sample.status !== "ok" && sample.status !== "partial" && sample.status !== "truncated") return rows;
  const map = new Map<string, NetworkHistoryRow>();
  for (const row of rows) map.set(networkHistoryKey(row.machineId, row), row);
  for (const c of sample.connections) {
    if (c.role !== "egress") continue;
    const key = networkHistoryKey(machineId, c);
    const prev = map.get(key);
    if (prev) {
      map.set(key, { ...prev, lastSeen: Math.max(prev.lastSeen, c.observedAt), state: c.state, bin: c.bin, agent: c.agent, ppid: c.ppid });
    } else {
      map.set(key, {
        id: newId(),
        machineId,
        agent: c.agent,
        pid: c.pid,
        ppid: c.ppid,
        processStartedAt: c.processStartedAt,
        bin: c.bin,
        remoteIp: c.remoteIp,
        remotePort: c.remotePort,
        localIp: c.localIp,
        localPort: c.localPort,
        state: c.state,
        role: "egress",
        direction: c.direction,
        firstSeen: c.observedAt,
        lastSeen: c.observedAt,
      });
    }
  }
  const next = [...map.values()].sort((a, b) => a.firstSeen - b.firstSeen);
  if (next.length <= max) return next;
  return next.slice(next.length - max);
}

export function mergeHeartbeatNetwork(
  prev: NetworkSampleReport | undefined,
  incoming: unknown,
  pollOnly: boolean,
  now = Date.now(),
): NetworkSampleReport | undefined {
  if (pollOnly) return prev ? parseNetworkSampleReport(prev, { now, relaxTime: true }) : undefined;
  const withoutClientTime =
    isPlain(incoming) ? { ...incoming, receivedAt: undefined } : incoming;
  const parsed = parseNetworkSampleReport(withoutClientTime, { now });
  if (!parsed) return undefined;
  return { ...parsed, receivedAt: now };
}

const EVENT_STRING_KEYS = [
  "input",
  "redacted",
  "dest",
  "proc",
  "nativeTool",
  "sessionId",
  "detectedModel",
  "threat",
  "tool",
  "category",
  "workdirScope",
  "layer",
  "actor",
  "source",
] as const;

/** Sanitize URL-bearing strings on a persisted/public event. Does not invent endpoints. */
export function sanitizeEventStrings<T extends Record<string, unknown>>(e: T, scan?: EndpointScanFns): T {
  const out: Record<string, unknown> = { ...e };
  for (const k of EVENT_STRING_KEYS) {
    if (typeof out[k] === "string") out[k] = sanitizeAuditText(out[k] as string, scan);
  }
  if (typeof out.dest === "string") {
    const d = out.dest as string;
    if (/^https?:\/\//i.test(d)) {
      out.dest = parseHttpUrl(d, scan)?.host;
    } else if (hostHasSecret(d, scan) || !isValidHost(d)) {
      const cleaned = sanitizeAuditText(d, scan);
      out.dest = isValidHost(cleaned) ? cleaned : undefined;
    }
  }
  return out as T;
}

export function sanitizeStoredEvent(e: import("./schema.ts").StoredEvent, scan?: EndpointScanFns): import("./schema.ts").StoredEvent {
  const cleaned = sanitizeEventStrings(e as unknown as Record<string, unknown>, scan);
  delete cleaned.egress;const egress=parseEgressEvidence(e.egress);if(egress)cleaned.egress=egress;
  delete cleaned.response;
  const response = parseResponseEvidence(e.response);
  if (response) cleaned.response = response;
  return cleaned as unknown as import("./schema.ts").StoredEvent;
}

export function publicNetworkSample(raw: unknown): NetworkSampleReport | undefined {
  return parseNetworkSampleReport(raw, { relaxTime: true });
}

export function publicNetworkHistory(raw: unknown): NetworkHistoryRow[] {
  if (!Array.isArray(raw)) return [];
  const out: NetworkHistoryRow[] = [];
  for (const row of raw) {
    const p = parseNetworkHistoryRow(row, { relaxTime: true });
    if (p) out.push(p);
    if (out.length >= MAX_NETWORK_HISTORY) break;
  }
  return out;
}
