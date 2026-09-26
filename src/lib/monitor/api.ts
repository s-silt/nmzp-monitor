import {archivePolicy,type ArchiveUploadPolicy,githubPolicy,type GithubUploadPolicy} from "./egress-evidence.ts";
import type { AuditEvent, CustomPrivacyRule, Intervention } from "./types";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import type { PolicyProposal } from "./policy-proposal.ts";
import {
  buildApplyEnvelope,
  isReviewCurrent,
  proposalBindingIssue,
  type ProposalCandidate,
  type ProposalReview,
} from "./proposal-review.ts";
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
  revoked?: boolean;
  revokedAt?: number | null;
}

/** Public revocation stamp. Non-positive or non-integer values count as absent. */
export function readDeviceRevocation(raw: { revoked?: unknown; revokedAt?: unknown } | null | undefined): { revoked: boolean; revokedAt: number | null } {
  const revokedAt = raw && typeof raw.revokedAt === "number" && Number.isSafeInteger(raw.revokedAt) && raw.revokedAt > 0 ? raw.revokedAt : null;
  return { revoked: raw?.revoked === true || revokedAt !== null, revokedAt };
}

function projectApiDevice(row: unknown): ApiDevice {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row as ApiDevice;
  const copy = { ...(row as Record<string, unknown>) };
  delete copy.tokenHash;
  delete copy.probeBinding;
  delete copy.networkOwners;
  return copy as unknown as ApiDevice;
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

function clearLegacyAdminToken(): void {
  setAdminToken("");
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
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
  try {
    const res = await fetch("/api/v1/session", {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    return res.ok;
  } finally {
    clearLegacyAdminToken();
  }
}

export async function logout(): Promise<boolean> {
  try {
    const res = await fetch("/api/v1/session", {
      method: "DELETE",
      credentials: "include",
    });
    return res.ok;
  } finally {
    clearLegacyAdminToken();
  }
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
    devices: s.devices.map((row) => projectApiDevice(row)),
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

export type MutationOutcomeName = "conflict" | "rejected" | "unknown";

export function classifyMutationFailure(status: number, error?: string): MutationOutcomeName {
  void error;
  if (status === 409) return "conflict";
  if (status === 0 || status === 502 || status === 504) return "unknown";
  return "rejected";
}

function failMutation<T extends { ok: false; status: number; error?: string }>(body: T): T & { outcome: MutationOutcomeName } {
  return { ...body, outcome: classifyMutationFailure(body.status, body.error) };
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
} | { ok: false; status: number; error?: string; outcome: MutationOutcomeName }> {
  let res: Response;
  try {
    res = await fetch("/api/v1/policy", {
      method: "PUT",
      credentials: "include",
      headers: headers({ "content-type": "application/json" }),
      body: JSON.stringify(body),
    });
  } catch {
    return failMutation({ ok: false, status: 0, error: "network" });
  }
  const data = (await parse(res)) as {
    version?: number;
    mode?: Intervention;
    stopped?: boolean;
    customRules?: CustomPrivacyRule[];
    overrides?: PolicyOverrides;
    exemptions?: PolicyExemption[];
    error?: string;
  };
  if (!res.ok) return failMutation({ ok: false, status: res.status, error: data.error });
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

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function readError(data: unknown): string | undefined {
  return isJsonRecord(data) && typeof data.error === "string" ? data.error : undefined;
}

function isProposalCandidate(value: unknown): value is ProposalCandidate {
  return isJsonRecord(value) && isJsonRecord(value.overrides) && Array.isArray(value.customRules) && Array.isArray(value.exemptions);
}

function isCandidateTotals(value: unknown): value is ProposalReview["candidateTotals"] {
  return isJsonRecord(value)
    && typeof value.overrideRules === "number"
    && typeof value.customRules === "number"
    && typeof value.exemptions === "number";
}

export type ProposalValidationResult =
  | ({ ok: true } & Omit<ProposalReview, "proposal">)
  | { ok: false; status: number; error?: string; outcome?: MutationOutcomeName };

export async function validateProposalApi(proposal: PolicyProposal, forceDryRun: boolean): Promise<ProposalValidationResult> {
  if (proposalBindingIssue(proposal) !== null) {
    // Not sent. status 0 stays rejected; failMutation would classify 0 as unknown.
    return { ok: false, status: 0, error: "proposal_base_required", outcome: "rejected" };
  }
  const res = await fetch("/api/v1/policy/proposals/validate", {
    method: "POST",
    credentials: "include",
    headers: headers({ "content-type": "application/json" }),
    body: JSON.stringify({ envelopeVersion: 1, proposal, forceDryRun }),
  });
  const data = await parse(res);
  if (!res.ok || !isJsonRecord(data) || data.ok !== true || typeof data.policyVersion !== "number" || typeof data.rulesHash !== "string"
    || typeof data.validatedAt !== "number" || data.forceDryRun !== forceDryRun || typeof data.engineVersion !== "string"
    || typeof data.candidateDigest !== "string" || typeof data.reviewExpiresAt !== "number"
    || !isProposalCandidate(data.candidate) || !isCandidateTotals(data.candidateTotals) || data.newCustomRulesDefaultDryRun !== true) {
    return { ok: false, status: res.status, error: readError(data) };
  }
  return {
    ok: true,
    policyVersion: data.policyVersion,
    rulesHash: data.rulesHash,
    candidateTotals: data.candidateTotals,
    newCustomRulesDefaultDryRun: true,
    validatedAt: data.validatedAt,
    forceDryRun,
    engineVersion: data.engineVersion,
    candidate: data.candidate,
    candidateDigest: data.candidateDigest,
    reviewExpiresAt: data.reviewExpiresAt,
  };
}

export async function applyProposalApi(review: ProposalReview): Promise<
  { ok: true; version: number; rulesHash?: string; newCustomRulesDefaultDryRun?: boolean } | { ok: false; status: number; error?: string; outcome: MutationOutcomeName }
> {
  if (proposalBindingIssue(review.proposal) !== null) {
    // Not sent. status 0 stays rejected; failMutation would classify 0 as unknown.
    return { ok: false, status: 0, error: "proposal_base_required", outcome: "rejected" };
  }
  let res: Response;
  try {
    res = await fetch("/api/v1/policy/proposals/apply", {
      method: "POST",
      credentials: "include",
      headers: headers({ "content-type": "application/json" }),
      body: JSON.stringify(buildApplyEnvelope(review)),
    });
  } catch {
    return failMutation({ ok: false, status: 0, error: "network" });
  }
  const data = await parse(res);
  if (!res.ok || !isJsonRecord(data) || data.ok !== true || typeof data.version !== "number") {
    return failMutation({ ok: false, status: res.status, error: readError(data) });
  }
  return {
    ok: true,
    version: data.version,
    ...(typeof data.rulesHash === "string" ? { rulesHash: data.rulesHash } : {}),
    ...(typeof data.newCustomRulesDefaultDryRun === "boolean" ? { newCustomRulesDefaultDryRun: data.newCustomRulesDefaultDryRun } : {}),
  };
}

/** Store-free gate: a stale review never reaches applyProposalApi. */
export async function applyCurrentReview(
  review: ProposalReview,
  proposal: PolicyProposal,
  forceDryRun: boolean,
): Promise<{ ok: true; version: number; rulesHash?: string; newCustomRulesDefaultDryRun?: boolean } | { ok: false; status: number; error?: string; outcome: MutationOutcomeName }> {
  if (!isReviewCurrent(review, proposal, forceDryRun)) {
    return failMutation({ ok: false, status: 409, error: "proposal_preview_mismatch" });
  }
  return applyProposalApi(review);
}

export async function revokeDeviceApi(deviceId: string): Promise<{ ok: true; alreadyRevoked: boolean } | { ok: false; status: number }> {
  const res = await fetch("/api/v1/devices/revoke", {
    method: "POST",
    credentials: "include",
    headers: headers({ "content-type": "application/json" }),
    body: JSON.stringify({ deviceId }),
  });
  const data = (await parse(res)) as { alreadyRevoked?: boolean };
  if (!res.ok) return { ok: false, status: res.status };
  return { ok: true, alreadyRevoked: data.alreadyRevoked === true };
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

export interface AuditCorruptRef {
  seq: number;
  machineId: string;
  id: string;
}

export interface AuditEventsResponse {
  events: AuditEvent[];
  highWatermark: number;
  nextBeforeSeq: number | null;
  historyCompleteness: "unknown";
  corrupt: AuditCorruptRef[];
  corruptCount: number;
}

function corruptRef(value: unknown): AuditCorruptRef | null {
  if (!record(value) || !natural(value.seq) || typeof value.machineId !== "string" || value.machineId.length === 0
    || typeof value.id !== "string" || value.id.length === 0) return null;
  return { seq: value.seq, machineId: value.machineId, id: value.id };
}

function corruptList(value: unknown): AuditCorruptRef[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 25) return null;
  const out: AuditCorruptRef[] = [];
  for (const item of value) {
    const ref = corruptRef(item);
    if (!ref) return null;
    out.push(ref);
  }
  return out;
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
  const corrupt = corruptList(body.corrupt);
  const corruptCount = body.corruptCount === undefined ? corrupt?.length : body.corruptCount;
  if (!corrupt || !natural(corruptCount) || corruptCount !== corrupt.length) return invalidHistoryResponse();
  const events = body.events.map(mapEvent);
  if (events.some((event) => event === null)) return invalidHistoryResponse();
  return {
    ok: true,
    data: {
      events: events as AuditEvent[],
      highWatermark: typeof body.highWatermark === "number" ? body.highWatermark : 0,
      nextBeforeSeq: typeof body.nextBeforeSeq === "number" ? body.nextBeforeSeq : null,
      historyCompleteness: "unknown",
      corrupt,
      corruptCount,
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
  outcome?: MutationOutcomeName;
}

export async function restorePolicyRevision(params: {
  expectedVersion: number;
  sourceVersion: number;
}): Promise<PolicyRestoreResult> {
  let res: Response;
  try {
    res = await fetch("/api/v1/policy/restore", {
      method: "POST",
      credentials: "include",
      headers: headers({ "content-type": "application/json" }),
      body: JSON.stringify(params),
    });
  } catch {
    return failMutation({ ok: false, status: 0, error: "network" });
  }
  const data = (await parse(res)) as {
    ok?: boolean;
    version?: number;
    mode?: Intervention;
    stopped?: boolean;
    error?: string;
  };
  if (!res.ok) {
    return failMutation({
      ok: false,
      status: res.status,
      error: data?.error ?? `http_${res.status}`,
      version: data?.version,
    });
  }
  if (data?.ok !== true || !natural(data.version) || data.version < 1 || !MODES.has(String(data.mode)) || typeof data.stopped !== "boolean") return failMutation(invalidHistoryResponse());
  return {
    ok: true,
    version: data?.version,
    mode: data.mode,
    stopped: data.stopped,
  };
}
