import {archivePolicy,githubPolicy} from "./egress-schema.ts";
import {parseEgressEvidence} from "./egress-schema.ts";
import {parseProbeProtection} from "./probe-protection.ts";
import {createHash} from "node:crypto";
import {parseDiscovery} from "./agent-discovery-schema.ts";
import {parseResponseEvidence} from "./response-evidence.ts";
import {parseEvidenceWindow} from "./evidence-window.ts";
/**
 * LAN read-only HTTP viewer. Binds a private IPv4, allowlists source CIDRs,
 * and projects a public subset of the pinned core state. Admin credentials and
 * tool originals stay on the server; this port never accepts writes.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createReadStream, existsSync, realpathSync, statSync } from "node:fs";
import { extname, join, normalize, sep } from "node:path";
import { ADMIN_BODY_LIMIT, NMZP_VERSION } from "./constants.ts";
import { pinnedHttps } from "./https-client.ts";
import { mimeForPath, STATIC_MIME } from "./http-util.ts";
import { parseSnapshotGuardReport } from "./schema.ts";
import { parseEndpointList, publicNetworkHistory, publicNetworkSample } from "./network-evidence.ts";
import { parseCustomRuleScope, parsePolicyExemptions, parsePolicyOverrides } from "./policy-schema.ts";

export const VIEWER_HIDDEN_RULE = "<仅管理员可见>";

const API_GET = new Set(["/health", "/api/v1/state", "/api/v1/export"]);
const MODES = new Set(["enforcing", "permissive", "off"]);

const EVENT_KEYS = [
  "id",
  "ts",
  "machineId",
  "agent",
  "sessionId",
  "layer",
  "tool",
  "nativeTool",
  "risk",
  "decision",
  "ruleId",
  "category",
  "workdirScope",
  "dest",
  "redacted",
  "threat",
  "secretKinds",
  "detectedModel",
  "source",
  "hookBlind",
  "correlateHit",
  "actor",
  "proc",
  "rewritten",
  "policyVersion",
  "enforcement",
  "degraded",
  "duplicate",
  "requestHash",
  "overrideSource",
  "exemptionId",
  "dryRunKinds",
] as const;

const DEVICE_KEYS = [
  "id",
  "hostname",
  "ip",
  "user",
  "os",
  "lastSeen",
  "attachedAt",
  "status",
  "stopState",
  "agents",
  "lastPolicyVersion",
  "networkOwnerCount",
] as const;

const CAP_FIELD_KEYS = ["id", "supported", "active", "lastSuccess", "error"] as const;
const PROC_KEYS = ["agent", "pid", "ppid", "bin"] as const;
/** Device/state capability names: short id, not a hook-name allowlist. */
const SHORT_ID = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;
const EXPORT_EVENT_KEYS = [
  "layer", "source", "category", "workdirScope",
  "sessionId",
  "nativeTool",
  "policyVersion",
  "proc",
  "id",
  "ts",
  "machineId",
  "agent",
  "tool",
  "redacted",
  "risk",
  "decision",
  "ruleId",
  "dest",
  "actor",
  "threat",
  "enforcement",
  "requestHash",
  "overrideSource",
  "exemptionId",
  "dryRunKinds",
] as const;
const MACHINE_KEYS = ["id", "hostname", "ip", "os", "status"] as const;

const RFC1918: Array<{ net: number; prefix: number }> = [
  { net: ipv4ToInt("10.0.0.0")!, prefix: 8 },
  { net: ipv4ToInt("172.16.0.0")!, prefix: 12 },
  { net: ipv4ToInt("192.168.0.0")!, prefix: 16 },
];
const LOOPBACK = { net: ipv4ToInt("127.0.0.0")!, prefix: 8 };

export interface LanViewerOpts {
  host: string;
  allowedCidrs: string[];
  port?: number;
  uiDir?: string | null;
  ctUrl: string;
  caPem: string;
  fingerprintSha256: string;
  adminToken: string;
  timeoutMs?: number;
}

export interface RunningLanViewer {
  host: string;
  port: number;
  url: string;
  close: () => Promise<void>;
}

export function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = [m[1]!, m[2]!, m[3]!, m[4]!];
  if (parts.some((p) => (p.length > 1 && p.startsWith("0")) || Number(p) > 255)) return null;
  return ((Number(parts[0]) << 24) | (Number(parts[1]) << 16) | (Number(parts[2]) << 8) | Number(parts[3])) >>> 0;
}

function maskFor(prefix: number): number {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xffffffff >>> 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function inCidr(addr: number, net: number, prefix: number): boolean {
  const mask = maskFor(prefix);
  return ((addr & mask) >>> 0) === ((net & mask) >>> 0);
}

export function parseCidr(cidr: string): { net: number; prefix: number } | null {
  const raw = cidr.trim();
  const slash = raw.indexOf("/");
  if (slash <= 0) return null;
  const ip = raw.slice(0, slash);
  const p = raw.slice(slash + 1);
  if (!/^\d{1,2}$/.test(p)) return null;
  const prefix = Number(p);
  if (prefix < 1 || prefix > 32) return null;
  const addr = ipv4ToInt(ip);
  if (addr === null) return null;
  const mask = maskFor(prefix);
  if (((addr & mask) >>> 0) !== addr) return null;
  return { net: addr >>> 0, prefix };
}

function cidrInsidePrivateOrLoopback(parsed: { net: number; prefix: number }): boolean {
  const outer = [...RFC1918, LOOPBACK];
  return outer.some((o) => parsed.prefix >= o.prefix && inCidr(parsed.net, o.net, o.prefix));
}

export function isPrivateOrLoopbackIpv4(ip: string): boolean {
  const addr = ipv4ToInt(ip);
  if (addr === null) return false;
  if (inCidr(addr, LOOPBACK.net, LOOPBACK.prefix)) return true;
  return RFC1918.some((o) => inCidr(addr, o.net, o.prefix));
}

export function isPrivateOrLoopbackCidr(cidr: string): boolean {
  const parsed = parseCidr(cidr);
  if (!parsed) return false;
  return cidrInsidePrivateOrLoopback(parsed);
}

export function assertLanViewerBind(host: string, allowedCidrs: string[]): void {
  if (host === "0.0.0.0" || host === "::" || host.includes(":")) {
    throw new Error("viewer host must be a private IPv4 address (RFC1918 or loopback), not 0.0.0.0 or public");
  }
  if (!isPrivateOrLoopbackIpv4(host)) {
    throw new Error("viewer host must be a private IPv4 address (RFC1918 or loopback), not 0.0.0.0 or public");
  }
  if (!allowedCidrs.length) throw new Error("viewer allowedCidrs required");
  for (const c of allowedCidrs) {
    if (!isPrivateOrLoopbackCidr(c)) {
      throw new Error("viewer allowedCidrs must be RFC1918 or loopback CIDR (not 0.0.0.0/0 or public)");
    }
  }
}

export function sourceIpv4(remoteAddress: string | undefined): string | null {
  let a = (remoteAddress ?? "").trim().toLowerCase();
  if (a.startsWith("::ffff:")) a = a.slice(7);
  if (ipv4ToInt(a) === null) return null;
  return a;
}

export function ipInAllowedCidrs(ip: string, cidrs: string[]): boolean {
  const addr = ipv4ToInt(ip);
  if (addr === null) return false;
  for (const c of cidrs) {
    const parsed = parseCidr(c);
    if (!parsed) continue;
    if (inCidr(addr, parsed.net, parsed.prefix)) return true;
  }
  return false;
}

export function viewerHostHeaderOk(hostHeader: string | undefined, bindIp: string, port: number): boolean {
  const h = (hostHeader ?? "").trim().toLowerCase();
  if (!h) return false;
  const expected = port === 80 ? bindIp.toLowerCase() : `${bindIp.toLowerCase()}:${port}`;
  return h === expected;
}

export function viewerOriginOk(origin: string | undefined, bindIp: string, port: number): boolean {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    if (u.protocol !== "http:") return false;
    const expectedHost = port === 80 ? bindIp : `${bindIp}:${port}`;
    return u.host.toLowerCase() === expectedHost.toLowerCase() && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}

/** Fetch Metadata: cross-site is rejected even when Origin is absent. */
export function viewerFetchSiteOk(secFetchSite: string | string[] | undefined): boolean {
  const raw = Array.isArray(secFetchSite) ? secFetchSite[0] : secFetchSite;
  if (!raw) return true;
  return raw.trim().toLowerCase() !== "cross-site";
}

export function parseViewerFlags(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
): { host: string; port: number; allowedCidrs: string[] } {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    if (i < 0) return undefined;
    const v = argv[i + 1];
    return v && !v.startsWith("-") ? v : undefined;
  };
  const flagAll = (name: string): string[] => {
    const out: string[] = [];
    for (let i = 0; i < argv.length; i++) {
      if (argv[i] === name) {
        const v = argv[i + 1];
        if (v && !v.startsWith("-")) {
          out.push(v);
          i += 1;
        }
      }
    }
    return out;
  };
  const host = flag("--host") || env.NMZP_VIEWER_HOST || "";
  const portRaw = flag("--port") || env.NMZP_VIEWER_PORT || "8789";
  const port = Number(portRaw);
  const fromFlags = flagAll("--allow-cidr");
  const fromEnv = (env.NMZP_VIEWER_ALLOW_CIDR ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allowedCidrs = fromFlags.length ? fromFlags : fromEnv;
  if (!host || !allowedCidrs.length) {
    throw new Error("usage: nmzp viewer --host <private-ip> --port 8789 --allow-cidr <CIDR>");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("viewer port invalid");
  assertLanViewerBind(host, allowedCidrs);
  return { host, port, allowedCidrs };
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function extraNested(obj: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allow = new Set(allowed);
  for (const [k, v] of Object.entries(obj)) {
    if (allow.has(k)) continue;
    if (v !== null && typeof v === "object") return true;
  }
  return false;
}

function asStr(v: unknown): { ok: true; value?: string } | { ok: false } {
  if (v === undefined) return { ok: true };
  if (typeof v === "string") return { ok: true, value: v };
  return { ok: false };
}

function asNum(v: unknown): { ok: true; value?: number } | { ok: false } {
  if (v === undefined) return { ok: true };
  if (typeof v === "number" && Number.isFinite(v)) return { ok: true, value: v };
  return { ok: false };
}

function asBool(v: unknown): { ok: true; value?: boolean } | { ok: false } {
  if (v === undefined) return { ok: true };
  if (typeof v === "boolean") return { ok: true, value: v };
  return { ok: false };
}

function asStrArr(v: unknown): { ok: true; value?: string[] } | { ok: false } {
  if (v === undefined) return { ok: true };
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) return { ok: false };
  return { ok: true, value: v };
}

function asInt(v: unknown): { ok: true; value?: number } | { ok: false } {
  if (v === undefined) return { ok: true };
  if (typeof v === "number" && Number.isFinite(v) && Number.isInteger(v)) return { ok: true, value: v };
  return { ok: false };
}

const EVENT_TYPES: Record<(typeof EVENT_KEYS)[number], "str" | "num" | "bool" | "str[]"> = {
  id: "str",
  ts: "num",
  machineId: "str",
  agent: "str",
  sessionId: "str",
  layer: "str",
  tool: "str",
  nativeTool: "str",
  risk: "str",
  decision: "str",
  ruleId: "str",
  category: "str",
  workdirScope: "str",
  dest: "str",
  redacted: "str",
  threat: "str",
  secretKinds: "str[]",
  detectedModel: "str",
  source: "str",
  hookBlind: "bool",
  correlateHit: "bool",
  actor: "str",
  proc: "str",
  rewritten: "bool",
  policyVersion: "num",
  enforcement: "str",
  degraded: "bool",
  duplicate: "bool",
  requestHash: "str",
  overrideSource: "str",
  exemptionId: "str",
  dryRunKinds: "str[]",
};

const DEVICE_TYPES: Record<(typeof DEVICE_KEYS)[number], "str" | "num" | "str[]"> = {
  id: "str",
  hostname: "str",
  ip: "str",
  user: "str",
  os: "str",
  lastSeen: "num",
  attachedAt: "num",
  status: "str",
  stopState: "str",
  agents: "str[]",
  lastPolicyVersion: "num",
  networkOwnerCount: "num",
};

const MACHINE_TYPES: Record<(typeof MACHINE_KEYS)[number], "str"> = {
  id: "str",
  hostname: "str",
  ip: "str",
  os: "str",
  status: "str",
};

function typedPick(
  obj: Record<string, unknown>,
  keys: readonly string[],
  types: Record<string, "str" | "num" | "bool" | "str[]" | "int">,
  extraAllowed: readonly string[] = [],
): Record<string, unknown> | null {
  if (extraNested(obj, [...keys, ...extraAllowed])) return null;
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(obj, k) || obj[k] === undefined) continue;
    const kind = types[k];
    const v = obj[k];
    if (kind === "str") {
      const t = asStr(v);
      if (!t.ok) return null;
      if (t.value !== undefined) out[k] = t.value;
    } else if (kind === "num") {
      const t = asNum(v);
      if (!t.ok) return null;
      if (t.value !== undefined) out[k] = t.value;
    } else if (kind === "int") {
      const t = asInt(v);
      if (!t.ok) return null;
      if (t.value !== undefined) out[k] = t.value;
    } else if (kind === "bool") {
      const t = asBool(v);
      if (!t.ok) return null;
      if (t.value !== undefined) out[k] = t.value;
    } else if (kind === "str[]") {
      const t = asStrArr(v);
      if (!t.ok) return null;
      if (t.value !== undefined) out[k] = t.value;
    }
  }
  return out;
}

function projectCapFields(raw: unknown, requireId: boolean): Record<string, unknown> | null {
  const r = asRecord(raw);
  if (!r || extraNested(r, CAP_FIELD_KEYS)) return null;
  const id = asStr(r.id);
  if (!id.ok) return null;
  if (requireId) {
    if (typeof id.value !== "string" || !SHORT_ID.test(id.value)) return null;
  } else if (id.value !== undefined && !SHORT_ID.test(id.value)) return null;
  const supported = asBool(r.supported);
  const active = asBool(r.active);
  const lastSuccess = asNum(r.lastSuccess);
  const error = asStr(r.error);
  if (!supported.ok || !active.ok || !lastSuccess.ok || !error.ok) return null;
  const out: Record<string, unknown> = {};
  if (id.value !== undefined) out.id = id.value;
  if (supported.value !== undefined) out.supported = supported.value;
  if (active.value !== undefined) out.active = active.value;
  if (lastSuccess.value !== undefined) out.lastSuccess = lastSuccess.value;
  if (error.value !== undefined) out.error = error.value;
  if (requireId && typeof out.id !== "string") return null;
  return out;
}

function projectCaps(raw: unknown): Array<Record<string, unknown>> | null {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) return null;
  const out: Array<Record<string, unknown>> = [];
  for (const row of raw) {
    const p = projectCapFields(row, true);
    if (!p) return null;
    out.push(p);
  }
  return out;
}

function projectProcs(raw: unknown): Array<Record<string, unknown>> | null {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) return null;
  const out: Array<Record<string, unknown>> = [];
  for (const row of raw) {
    const r = asRecord(row);
    if (!r || extraNested(r, PROC_KEYS)) return null;
    const agent = asStr(r.agent);
    const pid = asInt(r.pid);
    const ppid = asInt(r.ppid);
    const bin = asStr(r.bin);
    if (!agent.ok || !pid.ok || !ppid.ok || !bin.ok) return null;
    const item: Record<string, unknown> = {};
    if (agent.value !== undefined) item.agent = agent.value;
    if (pid.value !== undefined) item.pid = pid.value;
    if (ppid.value !== undefined) item.ppid = ppid.value;
    if (bin.value !== undefined) item.bin = bin.value;
    out.push(item);
  }
  return out;
}

export function projectCustomRule(raw: unknown): Record<string, unknown> | null {
  const r = asRecord(raw);
  if (!r || extraNested(r, ["id", "enabled", "mode", "kind", "match", "replaceWith", "scope", "dryRun"])) return null;
  const id = asStr(r.id);
  if (!id.ok || typeof id.value !== "string" || !id.value) return null;
  const mode = r.mode === "block" || r.mode === "replace" ? r.mode : null;
  if (!mode) return null;
  const enabled = asBool(r.enabled);
  const kind = asStr(r.kind);
  if (!enabled.ok || !kind.ok) return null;
  if (r.match !== undefined && typeof r.match !== "string") return null;
  if (r.replaceWith !== undefined && typeof r.replaceWith !== "string") return null;
  if (r.dryRun !== undefined && typeof r.dryRun !== "boolean") return null;
  const scoped = parseCustomRuleScope(r.scope);
  if (r.scope !== undefined && !scoped.ok) return null;
  const out: Record<string, unknown> = {
    id: id.value,
    enabled: enabled.value === true,
    mode,
    kind: kind.value ?? "",
    match: VIEWER_HIDDEN_RULE,
    replaceWith: VIEWER_HIDDEN_RULE,
  };
  if (typeof r.dryRun === "boolean") out.dryRun = r.dryRun;
  if (scoped.ok && scoped.scope) out.scope = scoped.scope;
  return out;
}

function projectEvent(raw: unknown, keys: readonly string[]): Record<string, unknown> | null {
  const r = asRecord(raw);
  if (!r) return null;
  const types: Record<string, "str" | "num" | "bool" | "str[]"> = {};
  for (const k of keys) {
    const t = EVENT_TYPES[k as (typeof EVENT_KEYS)[number]];
    if (t) types[k] = t;
  }
  const out = typedPick(r, keys, types, ["endpoints", "response", "egress"]);
  if (!out || typeof out.id !== "string") return null;
  if(r.egress!==undefined){const e=parseEgressEvidence(r.egress);if(!e)return null;out.egress={...e,review:undefined};}
  if (r.response !== undefined) { const response = parseResponseEvidence(r.response); if (!response) return null; out.response = response; }
  if (Object.prototype.hasOwnProperty.call(r, "endpoints") && r.endpoints !== undefined) {
    const eps = parseEndpointList(r.endpoints);
    if (eps === undefined) return null;
    out.endpoints = eps;
  }
  return out;
}

function projectDevice(raw: unknown): Record<string, unknown> | null {
  const r = asRecord(raw);
  if (!r) return null;
  const out = typedPick(r, DEVICE_KEYS, DEVICE_TYPES, ["capabilities", "agentProcs", "snapshotGuard", "network", "discovery", "probeProtection"]);
  if (!out || typeof out.id !== "string") return null;
  if (Object.prototype.hasOwnProperty.call(r, "capabilities")) {
    const caps = projectCaps(r.capabilities);
    if (!caps) return null;
    out.capabilities = caps;
  }
  if (Object.prototype.hasOwnProperty.call(r, "agentProcs")) {
    const procs = projectProcs(r.agentProcs);
    if (!procs) return null;
    out.agentProcs = procs;
  }
  if (r.discovery !== undefined) {const d=parseDiscovery(r.discovery);if(!d)return null;out.discovery=d;}
  if(r.probeProtection!==undefined){const p=parseProbeProtection(r.probeProtection);if(!p)return null;out.probeProtection=p;}
  // LAN inventory must not disclose a Windows account name.
  out.user="unknown";
  out.hostname="device-"+createHash("sha256").update(out.id).digest("hex").slice(0,10);
  if (Object.prototype.hasOwnProperty.call(r, "snapshotGuard") && r.snapshotGuard !== undefined) {
    const sg = parseSnapshotGuardReport(r.snapshotGuard);
    if (!sg) return null;
    out.snapshotGuard = sg;
  }
  if (Object.prototype.hasOwnProperty.call(r, "network") && r.network !== undefined) {
    const network = publicNetworkSample(r.network);
    if (!network) return null;
    out.network = network;
  }
  return out;
}

function projectStateCaps(raw: unknown): Record<string, Record<string, unknown>> | null {
  if (raw === undefined) return {};
  const r = asRecord(raw);
  if (!r) return null;
  const out: Record<string, Record<string, unknown>> = {};
  for (const [name, val] of Object.entries(r)) {
    if (!SHORT_ID.test(name)) return null;
    const cap = projectCapFields(val, false);
    if (!cap) return null;
    out[name] = cap;
  }
  return out;
}

export function projectViewerState(raw: unknown): { ok: true; state: Record<string, unknown> } | { ok: false } {
  const s = asRecord(raw);
  if (!s) return { ok: false };
  if (typeof s.policyVersion !== "number" || !Number.isFinite(s.policyVersion)) return { ok: false };
  if (typeof s.stopped !== "boolean") return { ok: false };
  if (typeof s.mode !== "string" || !MODES.has(s.mode)) return { ok: false };
  const serverTime = asNum(s.serverTime);
  if (!serverTime.ok || serverTime.value === undefined) return { ok: false };
  if (!Array.isArray(s.devices) || !Array.isArray(s.events)) return { ok: false };
  const customIn = s.customRules === undefined ? [] : s.customRules;
  if (!Array.isArray(customIn)) return { ok: false };
  const customRules: Array<Record<string, unknown>> = [];
  for (const row of customIn) {
    const p = projectCustomRule(row);
    if (!p) return { ok: false };
    customRules.push(p);
  }
  const devices: Array<Record<string, unknown>> = [];
  for (const row of s.devices) {
    const p = projectDevice(row);
    if (!p) return { ok: false };
    devices.push(p);
  }
  const events: Array<Record<string, unknown>> = [];
  for (const row of s.events) {
    const p = projectEvent(row, EVENT_KEYS);
    if (!p) return { ok: false };
    events.push(p);
  }
  const overrides = parsePolicyOverrides(s.overrides === undefined ? {} : s.overrides);
  if (!overrides) return { ok: false };
  const exemptionsRaw = parsePolicyExemptions(s.exemptions === undefined ? [] : s.exemptions);
  if (!exemptionsRaw) return { ok: false };
  const exemptions = exemptionsRaw.map((ex) => {
    const row: Record<string, unknown> = {
      id: ex.id,
      ruleId: ex.ruleId,
      match: VIEWER_HIDDEN_RULE,
      createdAt: ex.createdAt,
    };
    if (ex.tools) row.tools = ex.tools;
    if (ex.expiresAt !== undefined) row.expiresAt = ex.expiresAt;
    if (ex.sourceEventId !== undefined) row.sourceEventId = ex.sourceEventId;
    return row;
  });
  const capabilities = projectStateCaps(s.capabilities);
  if (!capabilities) return { ok: false };
  if (s.networkHistory !== undefined && !Array.isArray(s.networkHistory)) return { ok: false };
  const networkHistory = publicNetworkHistory(s.networkHistory);
  const eventEndpoints = projectEndpointIndex(s.eventEndpoints);
  if (s.eventEndpoints !== undefined && !eventEndpoints) return { ok: false };
  const deviceNetwork = projectDeviceNetworkIndex(s.deviceNetwork);
  if (s.deviceNetwork !== undefined && !deviceNetwork) return { ok: false };
  return {
    ok: true,
    state: {
      access: "viewer",
      ...(parseEvidenceWindow(s.evidenceWindow) ? {evidenceWindow:parseEvidenceWindow(s.evidenceWindow)} : {}),
      serverTime: serverTime.value,
      policyVersion: s.policyVersion,
        archiveUpload:archivePolicy(s.archiveUpload),
      githubUpload:githubPolicy(s.githubUpload),
      mode: s.mode,
      stopped: s.stopped,
      customRules,
      overrides,
      exemptions,
      devices,
      events,
      capabilities,
      networkHistory,
      ...(eventEndpoints ? { eventEndpoints } : {}),
      ...(deviceNetwork ? { deviceNetwork } : {}),
      ...(typeof s.timestampOffset === "string" ? { timestampOffset: s.timestampOffset.slice(0, 16) } : {}),
      ...(typeof s.timezone === "string" ? { timezone: s.timezone.slice(0, 64) } : {}),
    },
  };
}

function projectEndpointIndex(raw: unknown): Record<string, NonNullable<ReturnType<typeof parseEndpointList>>> | null {
  if (raw === undefined) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out: Record<string, NonNullable<ReturnType<typeof parseEndpointList>>> = {};
  for (const [id, val] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof id !== "string" || id.length > 80) return null;
    const eps = parseEndpointList(val);
    if (eps === undefined) return null;
    out[id] = eps;
  }
  return out;
}

function projectDeviceNetworkIndex(raw: unknown): Record<string, NonNullable<ReturnType<typeof publicNetworkSample>>> | null {
  if (raw === undefined) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out: Record<string, NonNullable<ReturnType<typeof publicNetworkSample>>> = {};
  for (const [id, val] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof id !== "string" || id.length > 80) return null;
    const n = publicNetworkSample(val);
    if (!n) return null;
    out[id] = n;
  }
  return out;
}

export function projectViewerExport(raw: unknown): { ok: true; bundle: Record<string, unknown> } | { ok: false } {
  const s = asRecord(raw);
  if (!s) return { ok: false };
  if (typeof s.version !== "number" || !Number.isFinite(s.version)) return { ok: false };
  const exportedAt = asNum(s.exportedAt);
  if (!exportedAt.ok || exportedAt.value === undefined) return { ok: false };
  const crossBorder = asBool(s.crossBorder);
  if (!crossBorder.ok || crossBorder.value === undefined) return { ok: false };
  if (!Array.isArray(s.events) || !Array.isArray(s.machines)) return { ok: false };
  const rulesIn = s.rules === undefined ? [] : s.rules;
  if (!Array.isArray(rulesIn)) return { ok: false };
  const events: Array<Record<string, unknown>> = [];
  for (const row of s.events) {
    const p = projectEvent(row, EXPORT_EVENT_KEYS);
    if (!p) return { ok: false };
    events.push(p);
  }
  const machines: Array<Record<string, unknown>> = [];
  for (const row of s.machines) {
    const r = asRecord(row);
    if (!r) return { ok: false };
    const m = typedPick(r, MACHINE_KEYS, MACHINE_TYPES, ["snapshotGuard", "network", "discovery", "probeProtection"]);
    if (!m || typeof m.id !== "string") return { ok: false };
    m.hostname="device-"+createHash("sha256").update(m.id).digest("hex").slice(0,10);
    if(r.probeProtection!==undefined){const p=parseProbeProtection(r.probeProtection);if(!p)return {ok:false};m.probeProtection=p;}
    if (r.discovery !== undefined) {const d=parseDiscovery(r.discovery);if(!d)return {ok:false};m.discovery=d;}
    if (Object.prototype.hasOwnProperty.call(r, "snapshotGuard") && r.snapshotGuard !== undefined) {
      const sg = parseSnapshotGuardReport(r.snapshotGuard);
      if (!sg) return { ok: false };
      m.snapshotGuard = sg;
    }
    if (Object.prototype.hasOwnProperty.call(r, "network") && r.network !== undefined) {
      const network = publicNetworkSample(r.network);
      if (!network) return { ok: false };
      m.network = network;
    }
    machines.push(m);
  }
  const rules: Array<Record<string, unknown>> = [];
  for (const row of rulesIn) {
    const p = projectCustomRule(row);
    if (!p) return { ok: false };
    rules.push(p);
  }
  const hopsIn = s.hops === undefined ? [] : s.hops;
  if (!Array.isArray(hopsIn)) return { ok: false };
  const hops: Array<Record<string, unknown>> = [];
  for (const row of hopsIn) {
    const r = asRecord(row);
    if (!r || extraNested(r, ["ts", "dest"])) return { ok: false };
    const ts = asNum(r.ts);
    const dest = asStr(r.dest);
    if (!ts.ok || !dest.ok) return { ok: false };
    const hop: Record<string, unknown> = {};
    if (ts.value !== undefined) hop.ts = ts.value;
    if (dest.value !== undefined) hop.dest = dest.value;
    hops.push(hop);
  }
  if (s.categories !== undefined) {
    if (!Array.isArray(s.categories) || s.categories.some((c) => typeof c !== "string")) return { ok: false };
  }
  const categories = Array.isArray(s.categories) ? (s.categories as string[]) : [];
  if (s.networkHistory !== undefined && !Array.isArray(s.networkHistory)) return { ok: false };
  const eventEndpoints = projectEndpointIndex(s.eventEndpoints);
  if (s.eventEndpoints !== undefined && !eventEndpoints) return { ok: false };
  const deviceNetwork = projectDeviceNetworkIndex(s.deviceNetwork);
  if (s.deviceNetwork !== undefined && !deviceNetwork) return { ok: false };
  let policy: Record<string, unknown> | undefined;
  if (s.policy !== undefined) {
    const pol = asRecord(s.policy);
    if (!pol) return { ok: false };
    const ovr = parsePolicyOverrides(pol.overrides === undefined ? {} : pol.overrides);
    if (!ovr) return { ok: false };
    const ex = parsePolicyExemptions(pol.exemptions === undefined ? [] : pol.exemptions);
    if (!ex) return { ok: false };
    policy = {
      version: pol.version,
      mode: pol.mode,
      overrides: ovr,
      exemptions: ex.map((e) => {
        const row: Record<string, unknown> = {
          id: e.id,
          ruleId: e.ruleId,
          match: VIEWER_HIDDEN_RULE,
          createdAt: e.createdAt,
        };
        if (e.tools) row.tools = e.tools;
        if (e.expiresAt !== undefined) row.expiresAt = e.expiresAt;
        if (e.sourceEventId !== undefined) row.sourceEventId = e.sourceEventId;
        return row;
      }),
    };
  }
  return {
    ok: true,
    bundle: {
      access: "viewer",
      ...(policy ? { policy } : {}),
      ...(parseEvidenceWindow(s.evidenceWindow) ? {evidenceWindow:parseEvidenceWindow(s.evidenceWindow)} : {}),
      version: s.version,
      exportedAt: exportedAt.value,
      crossBorder: crossBorder.value,
      categories,
      events,
      hops,
      machines,
      rules,
      networkHistory: publicNetworkHistory(s.networkHistory),
      ...(eventEndpoints ? { eventEndpoints } : {}),
      ...(deviceNetwork ? { deviceNetwork } : {}),
      ...(typeof s.timestampOffset === "string" ? { timestampOffset: s.timestampOffset.slice(0, 16) } : {}),
      ...(typeof s.timezone === "string" ? { timezone: s.timezone.slice(0, 64) } : {}),
    },
  };
}

const SEC_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "content-security-policy": "frame-ancestors 'none'",
};

function consume(req: IncomingMessage): Promise<void> {
  if (req.readableEnded || req.complete) return Promise.resolve();
  return new Promise((resolve) => {
    req.resume();
    req.on("end", resolve);
    req.on("error", () => resolve());
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, method: string): void {
  if (res.headersSent || res.writableEnded) return;
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(raw),
    ...SEC_HEADERS,
  });
  if (method === "HEAD") res.end();
  else res.end(raw);
}

async function sendJsonAfter(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  body: unknown,
  method: string,
): Promise<void> {
  if (method !== "GET" && method !== "HEAD") await consume(req);
  sendJson(res, status, body, method);
}

function sendFile(res: ServerResponse, file: string, type: string, method: string): void {
  const st = statSync(file);
  res.writeHead(200, {
    "content-type": type,
    "content-length": st.size,
    ...SEC_HEADERS,
  });
  if (method === "HEAD") {
    res.end();
    return;
  }
  const stream = createReadStream(file);
  stream.on("error", () => {
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: "internal_error" }, method);
    else res.destroy();
  });
  stream.pipe(res);
}

function safeRelPath(urlPath: string): { ok: true; rel: string } | { ok: false } {
  let decoded: string;
  try {
    decoded = decodeURIComponent(urlPath.split("?")[0] ?? "/");
  } catch {
    return { ok: false };
  }
  if (decoded.includes("\0") || decoded.includes("\\")) return { ok: false };
  const parts = decoded.split("/").filter((p) => p.length > 0 && p !== ".");
  if (parts.some((p) => p === "..")) return { ok: false };
  return { ok: true, rel: parts.length ? parts.join("/") : "index.html" };
}

function canonPath(p: string): string {
  const n = normalize(p);
  return process.platform === "win32" ? n.toLowerCase() : n;
}

function insideRoot(rootReal: string, candidate: string): boolean {
  const a = canonPath(rootReal);
  const b = canonPath(candidate);
  const prefix = a.endsWith(sep) ? a : a + sep;
  return b === a || b.startsWith(prefix);
}

function resolveUiFile(
  uiDir: string,
  rel: string,
): { kind: "file"; file: string } | { kind: "spa" } | { kind: "deny" } | { kind: "missing" } {
  let rootReal: string;
  try {
    if (!existsSync(uiDir) || !statSync(uiDir).isDirectory()) return { kind: "missing" };
    rootReal = realpathSync(uiDir);
  } catch {
    return { kind: "deny" };
  }
  const abs = normalize(join(uiDir, rel));
  if (!insideRoot(uiDir, abs) && canonPath(abs) !== canonPath(uiDir)) return { kind: "deny" };
  const parts = rel.split(/[/\\]/).filter(Boolean);
  let cur = uiDir;
  for (const part of parts) {
    cur = join(cur, part);
    if (!existsSync(cur)) break;
    try {
      const real = realpathSync(cur);
      if (!insideRoot(rootReal, real)) return { kind: "deny" };
    } catch {
      return { kind: "deny" };
    }
  }
  if (!existsSync(abs)) {
    const ext = extname(rel).toLowerCase();
    if (ext && STATIC_MIME[ext]) return { kind: "missing" };
    return { kind: "spa" };
  }
  let real: string;
  try {
    real = realpathSync(abs);
  } catch {
    return { kind: "deny" };
  }
  if (!insideRoot(rootReal, real)) return { kind: "deny" };
  if (!statSync(real).isFile()) {
    const ext = extname(rel).toLowerCase();
    if (ext && STATIC_MIME[ext]) return { kind: "missing" };
    return { kind: "spa" };
  }
  return { kind: "file", file: real };
}

function serveViewerStatic(res: ServerResponse, uiDir: string, urlPath: string, method: string): void {
  const rel = safeRelPath(urlPath);
  if (!rel.ok) {
    sendJson(res, 400, { ok: false, error: "bad_path" }, method);
    return;
  }
  const resolved = resolveUiFile(uiDir, rel.rel);
  if (resolved.kind === "deny") {
    sendJson(res, 403, { ok: false, error: "bad_path" }, method);
    return;
  }
  if (resolved.kind === "file") {
    sendFile(res, resolved.file, mimeForPath(resolved.file), method);
    return;
  }
  if (resolved.kind === "missing") {
    sendJson(res, 404, { ok: false, error: "not_found" }, method);
    return;
  }
  const index = resolveUiFile(uiDir, "index.html");
  if (index.kind === "file") {
    sendFile(res, index.file, "text/html; charset=utf-8", method);
    return;
  }
  if (index.kind === "deny") {
    sendJson(res, 403, { ok: false, error: "bad_path" }, method);
    return;
  }
  sendJson(res, 404, { ok: false, error: "not_found" }, method);
}

export async function startLanViewer(opts: LanViewerOpts): Promise<RunningLanViewer> {
  assertLanViewerBind(opts.host, opts.allowedCidrs);
  if (!opts.adminToken) throw new Error("viewer admin token required");
  if (!opts.caPem) throw new Error("tls pin required");
  let ct: URL;
  try {
    ct = new URL(opts.ctUrl);
  } catch {
    throw new Error("viewer core url invalid");
  }
  if (ct.protocol !== "https:") throw new Error("viewer core must be https");
  const pin = (opts.fingerprintSha256 ?? "").toLowerCase().replace(/:/g, "");
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new Error("tls pin required");
  const ctBase = opts.ctUrl.replace(/\/$/, "");
  const uiDir = opts.uiDir ?? null;
  const timeoutMs = opts.timeoutMs ?? 4000;
  const listen = { port: opts.port ?? 8789 };

  const coreGet = async (path: "/api/v1/state" | "/api/v1/export") => {
    try {
      const fwd = await pinnedHttps({
        url: `${ctBase}${path}`,
        method: "GET",
        headers: { authorization: `Bearer ${opts.adminToken}` },
        caPem: opts.caPem,
        fingerprintSha256: pin,
        timeoutMs,
        maxBodyBytes: ADMIN_BODY_LIMIT,
      });
      if (fwd.status !== 200) return { kind: "bad" as const };
      let parsed: unknown;
      try {
        parsed = JSON.parse(fwd.body || "");
      } catch {
        return { kind: "bad" as const };
      }
      return { kind: "ok" as const, parsed };
    } catch {
      return { kind: "down" as const };
    }
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const method = (req.method ?? "GET").toUpperCase();
    const reply = (status: number, body: unknown) => sendJsonAfter(req, res, status, body, method);
    const src = sourceIpv4(req.socket.remoteAddress);
    if (!src || !ipInAllowedCidrs(src, opts.allowedCidrs)) {
      await reply(403, { ok: false, error: "forbidden_src" });
      return;
    }
    if (!viewerHostHeaderOk(req.headers.host, opts.host, listen.port)) {
      await reply(403, { ok: false, error: "bad_host" });
      return;
    }
    if (!viewerFetchSiteOk(req.headers["sec-fetch-site"])) {
      await reply(403, { ok: false, error: "cross_site" });
      return;
    }
    if (!viewerOriginOk(typeof req.headers.origin === "string" ? req.headers.origin : undefined, opts.host, listen.port)) {
      await reply(403, { ok: false, error: "origin" });
      return;
    }

    let pathname = "/";
    try {
      pathname = new URL(req.url ?? "/", "http://lan.invalid").pathname;
    } catch {
      await reply(400, { ok: false, error: "bad_path" });
      return;
    }

    if (method !== "GET" && method !== "HEAD") {
      await reply(405, { ok: false, error: "method_not_allowed" });
      return;
    }

    if (pathname.startsWith("/api/") || pathname === "/health") {
      if (!API_GET.has(pathname)) {
        await reply(404, { ok: false, error: "not_found" });
        return;
      }
      if (pathname === "/health") {
        await reply(200, { ok: true, name: "nmzp-viewer", version: NMZP_VERSION });
        return;
      }
      const path = pathname as "/api/v1/state" | "/api/v1/export";
      const got = await coreGet(path);
      if (got.kind === "down") {
        await reply(503, { ok: false, error: "ct_unreachable" });
        return;
      }
      if (got.kind === "bad") {
        await reply(502, { ok: false, error: "ct_bad_response" });
        return;
      }
      if (path === "/api/v1/state") {
        const projected = projectViewerState(got.parsed);
        if (!projected.ok) {
          await reply(502, { ok: false, error: "ct_bad_response" });
          return;
        }
        await reply(200, projected.state);
        return;
      }
      const projected = projectViewerExport(got.parsed);
      if (!projected.ok) {
        await reply(502, { ok: false, error: "ct_bad_response" });
        return;
      }
      await reply(200, projected.bundle);
      return;
    }

    if (uiDir) {
      serveViewerStatic(res, uiDir, pathname, method);
      return;
    }
    await reply(404, { ok: false, error: "not_found" });
  };

  const server: Server = createServer((req, res) => {
    void handler(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { ok: false, error: "internal_error" }, req.method ?? "GET");
    });
  });
  const port = opts.port ?? 8789;
  await new Promise<void>((resolve, reject) => {
    server.listen(port, opts.host, () => resolve());
    server.on("error", reject);
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("listen failed");
  listen.port = addr.port;
  return {
    host: opts.host,
    port: addr.port,
    url: `http://${opts.host}:${addr.port}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
