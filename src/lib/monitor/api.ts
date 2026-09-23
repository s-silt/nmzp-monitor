import {archivePolicy,type ArchiveUploadPolicy,githubPolicy,type GithubUploadPolicy} from "./egress-evidence.ts";
import type { AuditEvent, CustomPrivacyRule, Intervention } from "./types";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import { mapEvent } from "./map-event.ts";
import { streamAuditDownload } from "./audit-download.ts";

export interface ApiCapability {
  supported: boolean;
  active: boolean;
  lastSuccess?: number;
  error?: string;
}

export interface ApiAgentProc {
  agent: string;
  pid: number;
  ppid: number;
  bin: string;
}

export interface ApiDevice {
  id: string;
  hostname: string;
  ip: string;
  user: string;
  os: "linux" | "darwin" | "win32";
  lastSeen: number;
  attachedAt: number;
  status: "online" | "dark" | "archived";
  capabilities: Array<{ id: string } & ApiCapability>;
  agents: string[];
  agentProcs?: ApiAgentProc[];
  discovery?: unknown;
  probeProtection?: unknown;
  snapshotGuard?: unknown;
  network?: unknown;
  lastPolicyVersion?: number;
  networkOwnerCount?: number;
}

export type AccessRole = "viewer" | "admin";

export interface ApiState {
  archiveUpload?:ArchiveUploadPolicy;
  githubUpload?:GithubUploadPolicy;
  /** Server window metadata; missing on old releases, never assumed complete. */
  evidenceWindow?: unknown;
  serverTime: number;
  policyVersion: number;
  mode: Intervention;
  stopped: boolean;
  customRules: CustomPrivacyRule[];
  devices: ApiDevice[];
  events: unknown[];
  networkHistory?: unknown[];
  eventEndpoints?: Record<string, unknown>;
  deviceNetwork?: Record<string, unknown>;
  capabilities: Record<string, ApiCapability>;
  /** Old authenticated 200 payloads without this field are treated as admin. */
  access: AccessRole;
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
}

const TOKEN_KEY = "nmzp-admin-token";

export function getAdminToken(): string {
  if (typeof sessionStorage === "undefined") return "";
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

export function setAdminToken(token: string) {
  if (typeof sessionStorage === "undefined") return;
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

function headers(extra?: Record<string, string>): HeadersInit {
  const h: Record<string, string> = { ...(extra ?? {}) };
  const t = getAdminToken();
  if (t) h.authorization = `Bearer ${t}`;
  return h;
}

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { ok: false, error: "bad_json", status: res.status };
  }
}

export async function login(token: string): Promise<boolean> {
  const res = await fetch("/api/v1/session", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) return false;
  setAdminToken(token);
  if (typeof localStorage !== "undefined") {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      /* ignore */
    }
  }
  return true;
}

const MODES = new Set(["enforcing", "permissive", "off"]);

export function parseApiState(raw: unknown): ApiState | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const s = raw as Record<string, unknown>;
  if (typeof s.policyVersion !== "number" || !Number.isFinite(s.policyVersion)) return null;
  if (typeof s.stopped !== "boolean") return null;
  if (typeof s.mode !== "string" || !MODES.has(s.mode)) return null;
  if (!Array.isArray(s.devices) || !Array.isArray(s.events)) return null;
  if (s.customRules !== undefined && !Array.isArray(s.customRules)) return null;
  return {
    evidenceWindow: s.evidenceWindow,
    serverTime: typeof s.serverTime === "number" && Number.isFinite(s.serverTime) ? s.serverTime : 0,
    policyVersion: s.policyVersion,
    mode: s.mode as ApiState["mode"],
    archiveUpload:archivePolicy(s.archiveUpload),
    githubUpload:githubPolicy(s.githubUpload),
    stopped: s.stopped,
    customRules: (s.customRules as ApiState["customRules"]) ?? [],
    devices: s.devices as ApiState["devices"],
    events: s.events,
    networkHistory: Array.isArray(s.networkHistory) ? s.networkHistory : [],
    eventEndpoints:
      s.eventEndpoints && typeof s.eventEndpoints === "object" && !Array.isArray(s.eventEndpoints)
        ? (s.eventEndpoints as Record<string, unknown>)
        : undefined,
    deviceNetwork:
      s.deviceNetwork && typeof s.deviceNetwork === "object" && !Array.isArray(s.deviceNetwork)
        ? (s.deviceNetwork as Record<string, unknown>)
        : undefined,
    capabilities: s.capabilities && typeof s.capabilities === "object" && !Array.isArray(s.capabilities) ? (s.capabilities as ApiState["capabilities"]) : {},
    access: parseAccess(s.access),
    overrides: (s.overrides as ApiState["overrides"]) ?? undefined,
    exemptions: Array.isArray(s.exemptions) ? (s.exemptions as ApiState["exemptions"]) : undefined,
  };
}

/** Legacy authenticated 200 with no access → admin. Unknown nonempty values never become admin. */
export function parseAccess(v: unknown): AccessRole {
  if (v === undefined || v === null || v === "") return "admin";
  if (v === "admin") return "admin";
  return "viewer";
}

export async function fetchState(): Promise<{ ok: true; state: ApiState } | { ok: false; status: number }> {
  const res = await fetch("/api/v1/state", { credentials: "include", headers: headers() });
  if (!res.ok) return { ok: false, status: res.status };
  const parsed = parseApiState(await parse(res));
  if (!parsed) return { ok: false, status: res.status || 200 };
  return { ok: true, state: parsed };
}

export async function putPolicy(body: {
  githubUpload?:GithubUploadPolicy;
  archiveUpload?:ArchiveUploadPolicy;
  expectedVersion: number;
  mode?: Intervention;
  customRules?: CustomPrivacyRule[];
  stopped?: boolean;
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
}): Promise<{
  ok: true;
  version: number;
  mode: Intervention;
  stopped: boolean;
  customRules: CustomPrivacyRule[];
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
} | { ok: false; status: number; error?: string }> {
  const res = await fetch("/api/v1/policy", {
    method: "PUT",
    credentials: "include",
    headers: headers({ "content-type": "application/json" }),
    body: JSON.stringify(body),
  });
  const data = (await parse(res)) as {
    version?: number;
    mode?: Intervention;
    stopped?: boolean;
    customRules?: CustomPrivacyRule[];
    overrides?: PolicyOverrides;
    exemptions?: PolicyExemption[];
    error?: string;
  };
  if (!res.ok) return { ok: false, status: res.status, error: data.error };
  return {
    ok: true,
    version: data.version!,
    mode: data.mode!,
    stopped: data.stopped!,
    customRules: data.customRules ?? [],
    overrides: data.overrides,
    exemptions: data.exemptions,
  };
}

export async function clearEventsApi(): Promise<boolean> {
  const res = await fetch("/api/v1/events", { method: "DELETE", credentials: "include", headers: headers() });
  return res.ok;
}

export async function exportApi(): Promise<string> {
  const res = await fetch("/api/v1/export", { credentials: "include", headers: headers() });
  if (!res.ok) throw new Error("export_failed");
  return JSON.stringify(await parse(res));
}

/** Drop leftover demo switches so they cannot revive seed data. */
export function clearDemoResidue() {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem("nmzp-demo");
  } catch {
    /* ignore */
  }
  try {
    const url = new URL(window.location.href);
    if (url.searchParams.has("demo")) {
      url.searchParams.delete("demo");
      const next = `${url.pathname}${url.search}${url.hash}`;
      window.history.replaceState({}, "", next);
    }
  } catch {
    /* ignore */
  }
}

export interface AuditStorageLimits {
  maxRecords: number;
  maxAgeMs: number;
  maxDbBytes: number;
  minFreeBytes: number;
  tombstoneMs: number;
}

export interface AuditStorageStatus {
  retained: number;
  deleted: number;
  tombstones: number;
  retentionPending: number;
  dbBytes: number;
  reusableBytes: number;
  limits: AuditStorageLimits;
  physicalShrink: "vacuum_not_needed" | "manual_vacuum_required";
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function natural(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function revision(value: unknown): value is PolicyRevision {
  return record(value) && natural(value.version) && value.version > 0 && natural(value.publishedAt)
    && typeof value.hash === "string" && /^[a-f0-9]{64}$/.test(value.hash)
    && typeof value.rulesHash === "string" && /^[a-f0-9]{64}$/.test(value.rulesHash)
    && typeof value.engineVersion === "string";
}
const invalidHistoryResponse = () => ({ ok: false as const, status: 502, error: "invalid_history_response" });

export interface AuditEventsQuery {
  limit?: number;
  highWatermark?: number;
  beforeSeq?: number;
  machineId?: string;
  agent?: string;
  decision?: string;
  risk?: string;
  ruleId?: string;
  fromTs?: number;
  toTs?: number;
}

export interface AuditEventsResponse {
  events: AuditEvent[];
  highWatermark: number;
  nextBeforeSeq: number | null;
  historyCompleteness: "unknown";
}

export async function fetchAuditEvents(
  query: AuditEventsQuery,
  signal?: AbortSignal,
): Promise<
  | { ok: true; data: AuditEventsResponse }
  | { ok: false; status: number; error: string }
> {
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.highWatermark !== undefined) params.set("highWatermark", String(query.highWatermark));
  if (query.beforeSeq !== undefined) params.set("beforeSeq", String(query.beforeSeq));
  if (query.machineId) params.set("machineId", query.machineId);
  if (query.agent) params.set("agent", query.agent);
  if (query.decision) params.set("decision", query.decision);
  if (query.risk) params.set("risk", query.risk);
  if (query.ruleId) params.set("ruleId", query.ruleId);
  if (query.fromTs !== undefined) params.set("fromTs", String(query.fromTs));
  if (query.toTs !== undefined) params.set("toTs", String(query.toTs));

  const url = `/api/v1/audit/events${params.toString() ? `?${params.toString()}` : ""}`;
  const res = await fetch(url, { credentials: "include", headers: headers(), signal });
  const body = (await parse(res)) as Record<string, unknown>;
  if (!res.ok) {
    return { ok: false, status: res.status, error: typeof body?.error === "string" ? body.error : `http_${res.status}` };
  }
  if (!record(body) || !Array.isArray(body.events) || body.events.length > 25 || !natural(body.highWatermark)
    || !(body.nextBeforeSeq === null || (natural(body.nextBeforeSeq) && body.nextBeforeSeq > 0))
    || body.historyCompleteness !== "unknown") return invalidHistoryResponse();
  const events = body.events.map(mapEvent);
  if (events.some((event) => event === null)) return invalidHistoryResponse();
  return {
    ok: true,
    data: {
      events: events as AuditEvent[],
      highWatermark: typeof body.highWatermark === "number" ? body.highWatermark : 0,
      nextBeforeSeq: typeof body.nextBeforeSeq === "number" ? body.nextBeforeSeq : null,
      historyCompleteness: "unknown",
    },
  };
}

export async function fetchAuditStorage(signal?: AbortSignal): Promise<
  | { ok: true; data: AuditStorageStatus }
  | { ok: false; status: number; error: string }
> {
  const res = await fetch("/api/v1/audit/storage", { credentials: "include", headers: headers(), signal });
  const body = (await parse(res)) as Record<string, unknown>;
  if (!res.ok) {
    return { ok: false, status: res.status, error: typeof body?.error === "string" ? body.error : `http_${res.status}` };
  }
  if (!record(body) || !["retained", "deleted", "tombstones", "retentionPending", "dbBytes", "reusableBytes"].every((key) => natural(body[key]))
    || !record(body.limits) || !["maxRecords", "maxAgeMs", "maxDbBytes", "minFreeBytes", "tombstoneMs"].every((key) => natural((body.limits as Record<string, unknown>)[key]))
    || !["vacuum_not_needed", "manual_vacuum_required"].includes(String(body.physicalShrink))) return invalidHistoryResponse();
  return { ok: true, data: body as unknown as AuditStorageStatus };
}

export { type AuditExportStreamOptions, type AuditExportDownloadResult } from "./audit-download.ts";
export async function downloadAuditExportStream(options: import("./audit-download.ts").AuditExportStreamOptions) {
  return streamAuditDownload(options, headers());
}

export interface PolicyRevision {
  version: number;
  hash: string;
  publishedAt: number;
  rulesHash: string;
  engineVersion: string;
}

export interface PolicyHistoryResponse {
  revisions: PolicyRevision[];
  nextBeforeVersion: number | null;
}

export async function fetchPolicyHistory(
  query: { limit?: number; beforeVersion?: number } = {},
  signal?: AbortSignal,
): Promise<
  | { ok: true; data: PolicyHistoryResponse }
  | { ok: false; status: number; error: string }
> {
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.beforeVersion !== undefined) params.set("beforeVersion", String(query.beforeVersion));

  const url = `/api/v1/policy/history${params.toString() ? `?${params.toString()}` : ""}`;
  const res = await fetch(url, { credentials: "include", headers: headers(), signal });
  const body = (await parse(res)) as Record<string, unknown>;
  if (!res.ok) {
    return { ok: false, status: res.status, error: typeof body?.error === "string" ? body.error : `http_${res.status}` };
  }
  if (!record(body) || !Array.isArray(body.revisions) || body.revisions.length > 100 || !body.revisions.every(revision)
    || !(body.nextBeforeVersion === null || (natural(body.nextBeforeVersion) && body.nextBeforeVersion > 0))) return invalidHistoryResponse();
  const revisions = body.revisions;
  return {
    ok: true,
    data: {
      revisions,
      nextBeforeVersion: typeof body.nextBeforeVersion === "number" ? body.nextBeforeVersion : null,
    },
  };
}

export interface HistoricalPolicyDetail {
  version: number;
  formatVersion: number;
  hash: string;
  publishedAt: number;
  rulesHash: string;
  engineVersion: string;
  policy: unknown;
}

export async function fetchPolicyRevisionDetail(
  version: number,
  signal?: AbortSignal,
): Promise<
  | { ok: true; data: HistoricalPolicyDetail }
  | { ok: false; status: number; error: string }
> {
  const res = await fetch(`/api/v1/policy/history/${version}`, {
    credentials: "include",
    headers: headers(),
    signal,
  });
  const body = (await parse(res)) as Record<string, unknown>;
  if (!res.ok) {
    return { ok: false, status: res.status, error: typeof body?.error === "string" ? body.error : `http_${res.status}` };
  }
  if (!revision(body) || !record(body) || body.formatVersion !== 1 || !record(body.policy)) return invalidHistoryResponse();
  return { ok: true, data: body as unknown as HistoricalPolicyDetail };
}

export interface PolicyRestoreResult {
  ok: boolean;
  version?: number;
  mode?: Intervention;
  stopped?: boolean;
  status?: number;
  error?: string;
}

export async function restorePolicyRevision(params: {
  expectedVersion: number;
  sourceVersion: number;
}): Promise<PolicyRestoreResult> {
  const res = await fetch("/api/v1/policy/restore", {
    method: "POST",
    credentials: "include",
    headers: headers({ "content-type": "application/json" }),
    body: JSON.stringify(params),
  });
  const data = (await parse(res)) as {
    ok?: boolean;
    version?: number;
    mode?: Intervention;
    stopped?: boolean;
    error?: string;
  };
  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      error: data?.error ?? `http_${res.status}`,
      version: data?.version,
    };
  }
  if (data?.ok !== true || !natural(data.version) || data.version < 1 || !MODES.has(String(data.mode)) || typeof data.stopped !== "boolean") return invalidHistoryResponse();
  return {
    ok: true,
    version: data?.version,
    mode: data.mode,
    stopped: data.stopped,
  };
}
