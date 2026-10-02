import type { PolicyFileOperations } from "./policy/file-store.ts";
import { ENGINE_REVISION } from "./policy/engine-revision.ts";
import { policyRulesHash } from "./policy/nmzp-service.ts";
import { PolicyDomainError } from "./policy/nmzp-domain.ts";
import {archivePolicy,parseArchivePolicy,githubPolicy,parseGithubPolicy} from "./egress-schema.ts";
import {ProbeChallenges,newProbeBinding,publicProbeProtection} from "./probe-auth.ts";
import {parseProbeProtection} from "./probe-protection.ts";
import {activeOwnerGrants, parseOwnerGrant} from "./network-owner-schema.ts";
import {randomUUID as ownerUuid} from "node:crypto";
import {parseDiscovery} from "./agent-discovery-schema.ts";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { NMZP_NAME, NMZP_VERSION, JOIN_TICKET_TTL_MS } from "./constants.ts";
import { newDeviceId, newEventId, newSecret, parseBearer, parseCookie, sha256Hex, safeEqualHex } from "./auth.ts";
import {
  bootstrapAdmin,
  NmzpStore,
  deriveDeviceStatus,
  deriveStopState,
  mergeHeartbeatSnapshotGuard,
  writeServePointer,
  removeServePointer,
} from "./persist.ts";
import { publicNetworkHistory, publicNetworkSample } from "./network-evidence.ts";
import { loadOrCreateTls, type TlsMaterial } from "./tls.ts";
import { loadMonitor, loadPolicyProposal, resolveUiDir, type MonitorMods } from "./paths.ts";
import { failJson, json, originOk, readLimited, serveStatic } from "./http-util.ts";
import { beginRouteLatency, observeRequestOutcome } from "./metrics.ts";
import {
  applyEvaluate,
  privacyFrom,
  reconstructRewrite,
  requestFingerprint,
  type EvalRequestBody,
} from "./eval-bridge.ts";
import { jsonDepthExceeds } from "./hook-alias-keys.ts";
import { exportBundleShape } from "./export.ts";
import { projectViewerExport, projectViewerState } from "./lan-viewer.ts";
import { viewerTokenMatches } from "./viewer-credential.ts";
import { handleAuditHttp } from "./audit/http.ts";
import { publicStoredEvent } from "./audit/public-event.ts";
import { handlePolicyHistoryHttp } from "./policy/http-history.ts";
import { handlePolicyProposalHttp } from "./policy/http-proposal.ts";
import { parseBackfill } from "./audit/backfill.ts";
import type { AuditWorkerSpawn } from "./audit/runtime.ts";
import type { AuditRetention } from "./audit/store.ts";
import { evaluateDurably, EvaluationApplicationError } from "./evaluation-application.ts";
import { bindBodyDevice } from "./protocol/device-binding.ts";
import { prepareCanonicalEvaluation } from "./protocol/evaluate-ingress.ts";
import { canonicalEvaluateResponse } from "./protocol/evaluate-response.ts";
import { v2DeviceError } from "./protocol/v2-device-error.ts";
import { policyETag, ifNoneMatchHits } from "./protocol/v2-error.ts";
import { parseHeartbeatBody } from "./heartbeat-schema.ts";
import { parseLegacyReceiptBody, parseReceiptBody, receiptEvaluationChanges } from "./receipt-schema.ts";
import { parseAgentProcs, parseSnapshotGuardReport, type CustomPrivacyRule } from "./schema.ts";
import { parsePolicyExemptions, parsePolicyOverrides } from "./policy-schema.ts";

const ADMIN_COOKIE = "nmzp_admin";
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const ADMIN_SESSION_CAP = 64;

/** Private scheduler signal; hidden row counts never become API counts. */
export function auditMaintenanceDelay(removed: number, needsFollowup: boolean): number {
  return removed === 100 || needsFollowup ? 50 : 60_000;
}

export interface ServeOpts {
  dataDir: string;
  host?: string;
  port?: number;
  uiDir?: string | null;
  coreDir?: string;
  extraHosts?: string[];
  adminToken?: string;
  /** Test-only session TTL. Omitted means 12 hours. Never read from HTTP. */
  adminSessionTtlMs?: number;
  /** Test-only session clock. Omitted means Date.now. Never read from HTTP. */
  adminSessionNow?: () => number;
  /** Trusted fault-injection port; never populated from HTTP or policy JSON. */
  policyFileOperations?: PolicyFileOperations;
  storageMode?: "window" | "sqlite";
  auditRetention?: AuditRetention;
  /** Test-only audit worker factory. Never read from HTTP, environment, or CLI. */
  auditWorkerSpawn?: AuditWorkerSpawn;
  /** Test-only audit recovery delays. Never read from HTTP, environment, or CLI. */
  auditRecoveryDelaysMs?: number[];
}

export interface RunningServer {
  host: string;
  port: number;
  url: string;
  tls: TlsMaterial;
  adminToken: string;
  store: NmzpStore;
  close: () => Promise<void>;
  /** Resolves after recovery exhaustion has stopped the server and released the writer lease. */
  fatal: Promise<void>;
  /** Invoked after `fatal` settles. */
  onFatal: (listener: () => void) => void;
}

function coreDirDefault(): string {
  return dirname(fileURLToPath(import.meta.url));
}

function publicSnapshotGuard(raw: unknown) {
  return parseSnapshotGuardReport(raw);
}

function publicStateDevice(d: ReturnType<NmzpStore["listDevices"]>[number]) {
  const snapshotGuard = publicSnapshotGuard(d.snapshotGuard);
  const network = publicNetworkSample(d.network);
  return {
    id: d.id,
    hostname: d.hostname,
    ip: d.ip,
    user: d.user,
    os: d.os,
    lastSeen: d.lastSeen,
    attachedAt: d.attachedAt,
    status: d.status,
    stopState: d.stopState,
    capabilities: d.capabilities,
    probeProtection:publicProbeProtection(d.probeBinding),
    agents: d.agents,
    agentProcs: d.agentProcs ?? [],
    lastPolicyVersion: d.lastPolicyVersion,
    ...(snapshotGuard ? { snapshotGuard } : {}),
    ...(network ? { network } : {}),
    discovery: parseDiscovery(d.discovery),
    networkOwnerCount: activeOwnerGrants(d.networkOwners).length,
    revoked: typeof d.revokedAt === "number",
    revokedAt: typeof d.revokedAt === "number" ? d.revokedAt : null,
  };
}

function parseDeviceRevokeId(text: string): string | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text || "{}");
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const deviceId = (raw as { deviceId?: unknown }).deviceId;
  if (typeof deviceId !== "string" || deviceId.length < 1 || deviceId.length > 128 || deviceId !== deviceId.trim()) return null;
  return deviceId;
}

function clearDeviceChallenges(challenges: ProbeChallenges, deviceId: string): void {
  const rows = (challenges as unknown as { rows: Map<string, { deviceId: string }> }).rows;
  for (const [nonce, row] of rows) {
    if (row.deviceId === deviceId) rows.delete(nonce);
  }
}

function eventEndpointsIndex(events: import("./schema.ts").StoredEvent[]) {
  const out: Record<string, NonNullable<import("./schema.ts").StoredEvent["endpoints"]>> = {};
  for (const e of events) {
    if (e.endpoints !== undefined) out[e.id] = e.endpoints;
  }
  return out;
}

function deviceNetworkIndex(devices: ReturnType<NmzpStore["listDevices"]>) {
  const out: Record<string, NonNullable<ReturnType<typeof publicNetworkSample>>> = {};
  for (const d of devices) {
    const network = publicNetworkSample(d.network);
    if (network) out[d.id] = network;
  }
  return out;
}

function publicExportMachine(d: {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  status: string;
  probeProtection?: unknown;
  discovery?: unknown;
  snapshotGuard?: unknown;
  network?: unknown;
}) {
  const snapshotGuard = publicSnapshotGuard(d.snapshotGuard);
  return {
    id: d.id,
    hostname: d.hostname,
    ip: d.ip,
    os: d.os,
    status: d.status,
    ...(snapshotGuard ? { snapshotGuard } : {}),
    ...(d.network ? { network: publicNetworkSample(d.network) } : {}),
    discovery:parseDiscovery(d.discovery),
    probeProtection:parseProbeProtection(d.probeProtection),
  };
}

function pathOf(req: IncomingMessage): { pathname: string; search: URLSearchParams } {
  const u = new URL(req.url ?? "/", "https://nmzp.local");
  return { pathname: u.pathname, search: u.searchParams };
}

/** Wildcard bind is not a connectable/cert host. IPv6 literals need brackets in the URL. */
function connectableUrl(listenHost: string, port: number): string {
  const host = listenHost === "0.0.0.0" ? "127.0.0.1" : listenHost;
  const hostPart = host.includes(":") ? `[${host}]` : host;
  return `https://${hostPart}:${port}`;
}

/** Wrap eval-bridge fingerprint with fields it still omits (url/dest/path/cwd/proc/source). */
export function evaluateRequestHash(body: EvalRequestBody): string {
  const base = requestFingerprint(body);
  return sha256Hex(
    JSON.stringify({
      base,
      url: body.url ?? "",
      dest: body.dest ?? "",
      file_path: body.file_path ?? "",
      cwd: body.cwd ?? "",
      proc: body.proc ?? "",
      parentProc: body.parentProc ?? "",
      hookBlind: body.hookBlind === true,
      source: body.source ?? "",
    }),
  );
}

type JoinOs = "darwin" | "linux" | "win32";

type JoinBody =
  | { ok: true; ticket: string; hostname: string; user: string; ip: string; os: JoinOs }
  | { ok: false; status: 400 | 401; error: "bad_json" | "join_ticket_invalid" };

/** Absent and null keep the historical defaults. Any other non-string is rejected before consumeTicket. */
function joinProvidedString(value: unknown): { ok: true; value: string | undefined } | { ok: false } {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  if (typeof value !== "string") return { ok: false };
  return { ok: true, value };
}

function joinOs(value: unknown): JoinOs {
  if (value === "darwin" || value === "linux" || value === "win32") return value;
  return "win32";
}

function validateJoinRequest(parsed: unknown): JoinBody {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: "bad_json" };
  }
  const body = parsed as Record<string, unknown>;
  const hostname = joinProvidedString(body.hostname);
  const user = joinProvidedString(body.user);
  const ip = joinProvidedString(body.ip);
  if (!hostname.ok || !user.ok || !ip.ok) return { ok: false, status: 400, error: "bad_json" };
  const osValue = body.os;
  if (osValue !== undefined && osValue !== null && typeof osValue !== "string") {
    return { ok: false, status: 400, error: "bad_json" };
  }
  const ticket = body.ticket;
  if (typeof ticket !== "string") {
    if (ticket === undefined || ticket === null) {
      return { ok: false, status: 401, error: "join_ticket_invalid" };
    }
    return { ok: false, status: 400, error: "bad_json" };
  }
  if (ticket.length === 0) return { ok: false, status: 401, error: "join_ticket_invalid" };
  const os = joinOs(osValue);
  return {
    ok: true,
    ticket,
    hostname: (hostname.value ?? "host").slice(0, 80),
    user: (user.value ?? "").slice(0, 64),
    ip: (ip.value ?? "").slice(0, 64),
    os,
  };
}

export async function startServer(opts: ServeOpts): Promise<RunningServer> {
  const coreDir = opts.coreDir ?? coreDirDefault();
  const monitor: MonitorMods = await loadMonitor(coreDir);
  const proposalParser = await loadPolicyProposal(coreDir);
  const suggested = Array.isArray(monitor.privacy.SUGGESTED_PRIVACY)
    ? (monitor.privacy.SUGGESTED_PRIVACY as CustomPrivacyRule[])
    : [];
  const store = new NmzpStore(opts.dataDir);
  await store.load({ defaultRules: suggested, defaultOverrides: monitor.SUGGESTED_OVERRIDES, policySource: monitor, policyFileOperations: opts.policyFileOperations, storageMode: opts.storageMode, auditRetention:opts.auditRetention, auditWorkerSpawn: opts.auditWorkerSpawn, auditRecoveryDelaysMs: opts.auditRecoveryDelaysMs });
  let startingServer: HttpsServer | undefined;
  let maintenanceTimer:ReturnType<typeof setTimeout>|undefined;
  let maintenanceClosed=false;
  let closePromise: Promise<void> | undefined;
  const closeServer = (): Promise<void> => closePromise ??= (async () => {
    maintenanceClosed = true;
    if (maintenanceTimer) clearTimeout(maintenanceTimer);
    let closeError: Error | undefined;
    if (startingServer?.listening) {
      closeError = await new Promise((resolve) => {
        startingServer!.close((error) => resolve(error ?? undefined));
      });
    }
    removeServePointer(opts.dataDir);
    await store.close();
    if (closeError) throw closeError;
  })();
  let resolveFatal: () => void = () => undefined;
  const fatal = new Promise<void>((resolve) => { resolveFatal = resolve; });
  store.onAuditWorkerFatal(() => {
    process.stderr.write("audit_worker_unrecoverable\n");
    void closeServer().catch(() => {
      process.stderr.write("serve_shutdown_failed\n");
    }).finally(() => resolveFatal());
  });
  const scheduleMaintenance=(delay:number):void=>{
    if(maintenanceClosed || store.getStorageMode()!=="sqlite")return;
    maintenanceTimer=setTimeout(()=>{
      void (async()=>{
        let removed=0,needsFollowup=false;
        try{removed=await store.maintainAuditRetentionStep(value=>{needsFollowup=value;});}
        catch{process.stderr.write("audit_retention_failed\n");}
        scheduleMaintenance(auditMaintenanceDelay(removed,needsFollowup));
      })();
    },delay);
    maintenanceTimer.unref();
  };
  try {
  const admin = await bootstrapAdmin(store, opts.adminToken);
  const hosts = ["127.0.0.1", "localhost", ...(opts.extraHosts ?? [])];
  const tls = await loadOrCreateTls(opts.dataDir, hosts);
  const challenges=new ProbeChallenges();
  const windows = new monitor.SessionWindows();
  const uiDir = opts.uiDir === undefined ? resolveUiDir(coreDir) : opts.uiDir;
  const sessions: { hash: string; expiresAt: number; createdAt: number }[] = [];

  const sessionNow = (): number => {
    const custom = opts.adminSessionNow?.();
    if (typeof custom === "number" && Number.isFinite(custom)) return custom;
    return Date.now();
  };

  const sessionTtlMs = (): number => {
    const custom = opts.adminSessionTtlMs;
    if (typeof custom === "number" && Number.isFinite(custom) && custom > 0) return Math.floor(custom);
    return ADMIN_SESSION_TTL_MS;
  };

  const sessionMaxAge = (): number => Math.ceil(sessionTtlMs() / 1000);

  const purgeExpired = (now: number): void => {
    for (let i = sessions.length - 1; i >= 0; i--) {
      const session = sessions[i];
      if (session && session.expiresAt <= now) sessions.splice(i, 1);
    }
  };

  const evictOldest = (): void => {
    let oldest = 0;
    for (let i = 1; i < sessions.length; i++) {
      const session = sessions[i];
      const current = sessions[oldest];
      if (session && current && session.createdAt < current.createdAt) oldest = i;
    }
    sessions.splice(oldest, 1);
  };

  const issueAdminSession = (now: number): string => {
    purgeExpired(now);
    while (sessions.length >= ADMIN_SESSION_CAP) evictOldest();
    const id = newSecret(32);
    sessions.push({ hash: sha256Hex(id), expiresAt: now + sessionTtlMs(), createdAt: now });
    return id;
  };

  const acceptAdminSession = (id: string, now: number): boolean => {
    purgeExpired(now);
    const hash = sha256Hex(id);
    let ok = false;
    for (const session of sessions) {
      if (safeEqualHex(session.hash, hash)) ok = true;
    }
    return ok;
  };

  const revokeAdminSession = (id: string): void => {
    const hash = sha256Hex(id);
    for (let i = sessions.length - 1; i >= 0; i--) {
      const session = sessions[i];
      if (session && safeEqualHex(session.hash, hash)) sessions.splice(i, 1);
    }
  };

  const adminSetCookie = (value: string, maxAge: number): string =>
    `${ADMIN_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${maxAge}`;

  const adminOk = (req: IncomingMessage): boolean => {
    const bearer = parseBearer(req.headers.authorization);
    if (bearer !== null) return safeEqualHex(sha256Hex(bearer), store.adminHash());
    const cookie = parseCookie(req.headers.cookie, ADMIN_COOKIE);
    if (!cookie) return false;
    return acceptAdminSession(cookie, sessionNow());
  };

  const requireAdmin = (req: IncomingMessage, res: ServerResponse): boolean => {
    if (!originOk(req)) {
      json(res, 403, { ok: false, error: "origin" });
      return false;
    }
    if (!adminOk(req)) {
      json(res, 401, { ok: false, error: "unauthorized" });
      return false;
    }
    return true;
  };

  const deviceReply = (res: ServerResponse, status: number, body: unknown, requestId?: string) => {
    if (requestId && status >= 400) {
      const code = body && typeof body === "object" && "error" in body && typeof body.error === "string"
        ? body.error : "internal_error";
      json(res, status, v2DeviceError(code, requestId));
    } else {
      json(res, status, body);
    }
  };

  const requireDevice = (req: IncomingMessage, res: ServerResponse, requestId?: string) => {
    const token = parseBearer(req.headers.authorization);
    if (!token) {
      deviceReply(res, 401, { ok: false, error: "unauthorized" }, requestId);
      return null;
    }
    const d = store.findDeviceByToken(token);
    if (!d) {
      deviceReply(res, 401, { ok: false, error: "unauthorized" }, requestId);
      return null;
    }
    return d;
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const { pathname, search } = pathOf(req);
    const method = req.method ?? "GET";
    const v2RequestId = pathname.startsWith("/api/v2/") ? ownerUuid() : undefined;
    const reply = (status: number, body: unknown) => deviceReply(res, status, body, v2RequestId);

    try {
      if (method === "GET" && pathname === "/health") {
        const audit = store.auditHealth();
        const up = audit === "window" || audit === "ready";
        json(res, up ? 200 : 503, { ok: up, name: NMZP_NAME, version: NMZP_VERSION, audit });
        return;
      }

      if (method === "POST" && pathname === "/api/v1/session") {
        if (!originOk(req)) {
          json(res, 403, { ok: false, error: "origin" });
          return;
        }
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: { token?: string } = {};
        try {
          parsed = JSON.parse(body.text || "{}") as { token?: string };
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        if (!parsed.token || !safeEqualHex(sha256Hex(parsed.token), store.adminHash())) {
          json(res, 401, { ok: false, error: "unauthorized" });
          return;
        }
        const sid = issueAdminSession(sessionNow());
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": adminSetCookie(sid, sessionMaxAge()),
          "cache-control": "no-store",
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      if (method === "DELETE" && pathname === "/api/v1/session") {
        if (!originOk(req)) {
          json(res, 403, { ok: false, error: "origin" });
          return;
        }
        const cookie = parseCookie(req.headers.cookie, ADMIN_COOKIE);
        if (cookie) revokeAdminSession(cookie);
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": adminSetCookie("", 0),
          "cache-control": "no-store",
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      if (method === "GET" && pathname === "/api/v1/state") {
        const finishState = beginRouteLatency("state");
        try {
        const asAdmin = adminOk(req);
        if (asAdmin && !originOk(req)) {
          json(res, 403, { ok: false, error: "origin" });
          return;
        }
        const viewerBearer = parseBearer(req.headers.authorization);
        const asViewer =
          !asAdmin && originOk(req) && viewerBearer !== null && viewerTokenMatches(opts.dataDir, viewerBearer);
        if (!asAdmin && !asViewer) {
          requireAdmin(req, res);
          return;
        }
        const now = Date.now();
        const policy = store.getPolicy();
        const devices = store.listDevices(now).map((d) => publicStateDevice(d));
        const events = store.listEvents().map((e) => publicStoredEvent(e));
        const hookActive = (id: string) =>
          devices.some((d) => (d.capabilities ?? []).some((c) => c.id === id && c.active));
        const full = {
          access: "admin",
          serverTime: now,
          policyVersion: policy.version,
          mode: policy.stopped ? "off" : policy.mode,
          stopped: policy.stopped,
          customRules: policy.customRules,
          archiveUpload:archivePolicy(policy.archiveUpload),
          githubUpload:githubPolicy(policy.githubUpload),
          overrides: policy.overrides,
          exemptions: policy.exemptions,
          devices,
          events,
          eventEndpoints: eventEndpointsIndex(store.listEvents()),
          deviceNetwork: deviceNetworkIndex(store.listDevices()),
          networkHistory: publicNetworkHistory(store.listNetworkHistory()),
          evidenceWindow: store.evidenceWindow(),
          timestampOffset: "+08:00",
          timezone: "Asia/Shanghai",
          capabilities: {
            https: { supported: true, active: true, lastSuccess: now },
            persist: { supported: true, active: true, lastSuccess: now },
            hookGrok: { supported: true, active: hookActive("hook_grok") },
            hookClaude: { supported: true, active: hookActive("hook_claude") },
            hookCodex: { supported: true, active: hookActive("hook_codex") },
          },
        };
        if (asViewer) {
          let projected: ReturnType<typeof projectViewerState>;
          try {
            projected = projectViewerState(full);
          } catch {
            json(res, 500, { ok: false, error: "viewer_projection_failed" });
            return;
          }
          if (!projected.ok) {
            json(res, 500, { ok: false, error: "viewer_projection_failed" });
            return;
          }
          json(res, 200, projected.state);
          return;
        }
        json(res, 200, full);
        return;
        } finally {
          finishState();
        }
      }

      if (await handlePolicyHistoryHttp(req, res, pathname, search, {store, requireAdmin})) return;
      if (await handlePolicyProposalHttp(req, res, pathname, {store, monitor, proposalParser, requireAdmin})) return;
      if (await handleAuditHttp(req, res, pathname, search, {store, requireAdmin})) return;

      if (method === "PUT" && pathname === "/api/v1/policy") {
        if (!requireAdmin(req, res)) return;
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: {
          expectedVersion?: number;
          mode?: string;
          customRules?: CustomPrivacyRule[];
          archiveUpload?: unknown;
          githubUpload?: unknown;
          stopped?: boolean;
          overrides?: unknown;
          exemptions?: unknown;
        };
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        if (typeof parsed.expectedVersion !== "number") {
          json(res, 400, { ok: false, error: "expectedVersion required" });
          return;
        }
        if(parsed.githubUpload!==undefined&&!parseGithubPolicy(parsed.githubUpload)){failJson(res,400,"invalid_github_policy");return;}
        if(parsed.archiveUpload!==undefined&&!parseArchivePolicy(parsed.archiveUpload)){failJson(res,400,"invalid_archive_policy");return;}
        let overridesPatch: ReturnType<typeof parsePolicyOverrides> | undefined;
        if (parsed.overrides !== undefined) {
          overridesPatch = parsePolicyOverrides(parsed.overrides);
          if (!overridesPatch) {
            failJson(res, 400, "invalid_policy_overrides");
            return;
          }
          const unknown = monitor.unknownRuleIds(overridesPatch, monitor.RULES);
          if (unknown.length) {
            failJson(res, 400, "unknown_rule_override", { ruleIds: unknown });
            return;
          }
          const protectedIds = monitor.protectedDowngrades(overridesPatch, monitor.RULES);
          if (protectedIds.length) {
            failJson(res, 400, "protected_rule_override", { ruleIds: protectedIds });
            return;
          }
        }
        let exemptionsPatch: ReturnType<typeof parsePolicyExemptions> | undefined;
        if (parsed.exemptions !== undefined) {
          exemptionsPatch = parsePolicyExemptions(parsed.exemptions);
          if (!exemptionsPatch) {
            failJson(res, 400, "invalid_policy_exemptions");
            return;
          }
          for (const ex of exemptionsPatch) {
            if (!monitor.privacy.compileMatch(ex.match)) {
              failJson(res, 400, "invalid_policy_exemptions");
              return;
            }
          }
          const bad = exemptionsPatch
            .filter((ex) => {
              const rule = monitor.RULE_BY_ID[ex.ruleId];
              return rule && monitor.isProtectedRule(rule);
            })
            .map((ex) => ex.ruleId);
          if (bad.length) {
            failJson(res, 400, "protected_rule_exemption", { ruleIds: [...new Set(bad)] });
            return;
          }
        }
        let customRules = parsed.customRules;
        if (parsed.customRules !== undefined) {
          const n = monitor.privacy.sanitizeCustomRules(parsed.customRules);
          if (!n || n.length !== parsed.customRules.length || n.length > monitor.privacy.MAX_CUSTOM_RULES) {
            failJson(res, 400, "invalid_custom_rules");
            return;
          }
          customRules = n;
        }
        const mode =
          parsed.mode === "enforcing" || parsed.mode === "permissive" || parsed.mode === "off" ? parsed.mode : undefined;
        // v1 accepted any numeric version and reported non-integral/old values as CAS conflicts.
        if (!Number.isSafeInteger(parsed.expectedVersion) || parsed.expectedVersion < 1) {
          json(res, 409, { ok: false, error: "cas_conflict", version: store.getPolicy().version });
          return;
        }
        const result = await store.casPolicy(parsed.expectedVersion, {
          mode,
          customRules,
          stopped: typeof parsed.stopped === "boolean" ? parsed.stopped : undefined,
          archiveUpload:parseArchivePolicy(parsed.archiveUpload),
          githubUpload:parseGithubPolicy(parsed.githubUpload),
          overrides: overridesPatch,
          exemptions: exemptionsPatch,
        });
        if ("conflict" in result) {
          json(res, 409, { ok: false, error: "cas_conflict", version: result.version });
          return;
        }
        json(res, 200, { ok: true, version: result.version, mode: result.mode, stopped: result.stopped, customRules: result.customRules, archiveUpload:archivePolicy(result.archiveUpload),githubUpload:githubPolicy(result.githubUpload), overrides: result.overrides, exemptions: result.exemptions });
        return;
      }

      if (method === "GET" && pathname === "/api/v1/export") {
        const asAdmin = adminOk(req);
        if (asAdmin && !originOk(req)) {
          json(res, 403, { ok: false, error: "origin" });
          return;
        }
        const viewerBearer = parseBearer(req.headers.authorization);
        const asViewer =
          !asAdmin && originOk(req) && viewerBearer !== null && viewerTokenMatches(opts.dataDir, viewerBearer);
        if (!asAdmin && !asViewer) {
          requireAdmin(req, res);
          return;
        }
        const bundle = exportBundleShape(store);
        const full = { ...bundle, machines: store.listDevices().map((d) => publicExportMachine({...d,probeProtection:publicProbeProtection(d.probeBinding)})) };
        if (asViewer) {
          let projected: ReturnType<typeof projectViewerExport>;
          try {
            projected = projectViewerExport(full);
          } catch {
            json(res, 500, { ok: false, error: "viewer_projection_failed" });
            return;
          }
          if (!projected.ok) {
            json(res, 500, { ok: false, error: "viewer_projection_failed" });
            return;
          }
          json(res, 200, projected.bundle);
          return;
        }
        json(res, 200, full);
        return;
      }

      if (method === "DELETE" && pathname === "/api/v1/events") {
        if (!requireAdmin(req, res)) return;
        await store.clearEvents();
        json(res, 200, { ok: true });
        return;
      }

      if (method === "POST" && pathname === "/api/v1/join") {
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        const join = validateJoinRequest(parsed);
        if (!join.ok) {
          json(res, join.status, { ok: false, error: join.error });
          return;
        }
        if (!(await store.consumeTicket(join.ticket))) {
          json(res, 401, { ok: false, error: "join_ticket_invalid" });
          return;
        }
        const id = newDeviceId();
        const token = newSecret(32);
        const now = Date.now();
        await store.putDevice({
          id,
          tokenHash: sha256Hex(token),
          hostname: join.hostname,
          ip: join.ip,
          user: join.user,
          os: join.os,
          attachedAt: now,
          lastSeen: now,
          lastPolicyVersion: 0,
          capabilities: [],
          agents: [],
        });
        json(res, 200, {
          deviceId: id,
          deviceToken: token,
          caPem: tls.certPem,
          fingerprintSha256: tls.fingerprintSha256,
        });
        return;
      }

      if (method === "POST" && pathname === "/api/v1/devices/revoke") {
        if (!requireAdmin(req, res)) return;
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        const deviceId = parseDeviceRevokeId(body.text);
        if (!deviceId) {
          json(res, 400, { ok: false, error: "bad_body" });
          return;
        }
        const result = await store.revokeDevice(deviceId, Date.now());
        if (!result.ok) {
          json(res, 404, { ok: false, error: "device_not_found" });
          return;
        }
        clearDeviceChallenges(challenges, deviceId);
        json(res, 200, { ok: true, alreadyRevoked: result.alreadyRevoked });
        return;
      }

      if (pathname === "/api/v1/network-owners") {
        if (method === "GET") {
          const d=requireDevice(req,res);if(!d)return;
          json(res,200,{grants:store.getPolicy().stopped?[]:activeOwnerGrants(d.networkOwners)});return;
        }
        if (method !== "POST") {failJson(res,405,"method");return;}
        if (!requireAdmin(req,res)) return;
        const body=await readLimited(req);if(!body.ok){failJson(res,413,"too_large");return;}
        let raw;try{raw=JSON.parse(body.text);}catch{failJson(res,400,"invalid_owner");return;}
        if(!raw || typeof raw!=="object" || Array.isArray(raw)){failJson(res,400,"invalid_owner");return;}
        if(typeof raw.deviceId!=="string" || !["approve","revoke"].includes(raw.action)) {failJson(res,400,"invalid_owner");return;}
        let grant;
        if(raw.action==="approve") {
          const now=Date.now();
          grant=parseOwnerGrant({...raw.claim,id:ownerUuid(),approvedAt:now});
          if(!grant || grant.expiresAt<=now || store.getPolicy().stopped) {failJson(res,400,"invalid_owner");return;}
        } else if(typeof raw.id!=="string" || !/^[a-f0-9-]{36}$/.test(raw.id)) {failJson(res,400,"invalid_owner");return;}
        if(!await store.updateNetworkOwner(raw.deviceId,grant,raw.action==="revoke"?raw.id:undefined)) {failJson(res,409,"owner_device_or_limit");return;}
        json(res,200,{ok:true,...(grant?{grant}:{})});return;
      }
      if(method==="POST"&&pathname==="/api/v1/probe/binding") {
        if(!requireAdmin(req,res))return;
        const b=await readLimited(req);if(!b.ok){failJson(res,413,"too_large");return;}
        let raw,binding;try{raw=JSON.parse(b.text);if(!raw||typeof raw.deviceId!=="string")throw Error();binding=raw.action==="revoke"?"revoke" as const:raw.action==="enroll"&&typeof raw.publicKey==="string"?newProbeBinding(raw.publicKey):null;if(!binding)throw Error();}catch{failJson(res,400,"invalid_probe_binding");return;}
        if(!await store.bindProbe(raw.deviceId,binding)){failJson(res,409,"probe_device_or_binding_missing");return;}
        json(res,200,{ok:true,probeProtection:publicProbeProtection(store.getDevice(raw.deviceId)?.probeBinding)});return;
      }
      if(method==="GET"&&pathname==="/api/v1/probe/challenge") {
        const d=requireDevice(req,res);if(!d)return;
        if(!d.probeBinding||d.probeBinding.revoked){failJson(res,403,"probe_binding_required");return;}
        const c=challenges.issue(d.id,d.probeBinding);
        if(c){json(res,200,c);return;}
        failJson(res,429,"challenge_limit");return;
      }
      if (method === "POST" && (pathname === "/api/v1/heartbeat" || pathname === "/api/v2/heartbeat")) {
        const d = requireDevice(req, res, v2RequestId);
        if (!d) return;
        const body = await readLimited(req);
        if (!body.ok) {
          reply(413, { ok: false, error: "payload_too_large" });
          return;
        }
        const expectedProbeKey=d.probeBinding?d.probeBinding.keyId+":"+d.probeBinding.registeredAt:null;
        if(d.probeBinding&&!challenges.consume(d.id,d.probeBinding,body.text,req.headers)){
          if(v2RequestId)reply(401,{ok:false,error:"probe_proof_required"});
          else failJson(res,401,"probe_proof_required");
          return;
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          reply(400, { ok: false, error: "bad_json" });
          return;
        }
        if (v2RequestId && !bindBodyDevice(parsed, d.id)) {
          reply(401, { ok: false, error: "unauthorized" });
          return;
        }
        const heartbeat = parseHeartbeatBody(parsed);
        if (!heartbeat.ok) {
          reply(400, { ok: false, error: "bad_heartbeat" });
          return;
        }
        const fields = heartbeat.fields;
        const raw = parsed as Record<string, unknown>;
        const policy = store.getPolicy();
        const pollOnly = fields.pollOnly === true;
        const stoppedAck = fields.stoppedAck === true;
        const reportedVersion = typeof fields.policyVersion === "number" ? fields.policyVersion : -1;
        const versionAccepted =
          Number.isSafeInteger(reportedVersion) && reportedVersion >= 0 && reportedVersion <= policy.version;
        const recordedVersion = versionAccepted ? reportedVersion : d.lastPolicyVersion;
        const applied = policy.stopped && stoppedAck && reportedVersion === policy.version;
        const now = Date.now();
        const incomingDiscovery = parseDiscovery(raw.discovery, now);
        const discovery = incomingDiscovery && incomingDiscovery.completedAt >= (d.discovery?.completedAt ?? 0) ? {...incomingDiscovery,receivedAt:now} : d.discovery;
        const snapshotGuard = mergeHeartbeatSnapshotGuard(d.snapshotGuard, raw.snapshotGuard, pollOnly);
        const touched = await store.touchDevice(d.id, pollOnly ? {
          lastSeen: now,
          lastPolicyVersion: recordedVersion,
          agentProcs: [],
          stoppedAck: applied,
          stopAckVersion: applied ? policy.version : policy.stopped ? (d.stopAckVersion ?? 0) : 0,
          snapshotGuard,
        } : {
          lastSeen: now,
          hostname: fields.hostname ?? d.hostname,
          ip: fields.ip ?? d.ip,
          user: fields.user ?? d.user,
          lastPolicyVersion: recordedVersion,
          discovery,
          capabilities: fields.capabilities ?? d.capabilities,
          agents: fields.agents ?? d.agents,
          agentProcs: parseAgentProcs(raw.agentProcs),
          stoppedAck: applied,
          stopAckVersion: applied ? policy.version : policy.stopped ? (d.stopAckVersion ?? 0) : 0,
          snapshotGuard,
        }, expectedProbeKey);
        if (!touched || typeof touched.revokedAt === "number") {
          reply(401, { ok: false, error: "unauthorized" });
          return;
        }
        await store.applyNetworkSample(d.id, raw.network, pollOnly, now, expectedProbeKey);
        const updated = store.getDevice(d.id);
        if (!updated || typeof updated.revokedAt === "number") {
          reply(401, { ok: false, error: "unauthorized" });
          return;
        }
        reply(200, {
          mode: policy.stopped ? "off" : policy.mode,
          policyVersion: policy.version,
          stopped: policy.stopped,
          status: deriveDeviceStatus(updated.lastSeen, now),
          stopState: deriveStopState(policy, updated, now),
          engineRevision: ENGINE_REVISION,
        });
        return;
      }

      if (method === "GET" && (pathname === "/api/v1/policy" || pathname === "/api/v2/policy")) {
        const d = requireDevice(req, res, v2RequestId);
        if (!d) return;
        const policy = store.getPolicy();
        const rulesHash = v2RequestId ? `sha256:${policyRulesHash(monitor)}` : undefined;
        if (v2RequestId) {
          const etag = policyETag({ version: policy.version, rulesHash: rulesHash!, engineRevision: ENGINE_REVISION });
          res.setHeader("ETag", etag);
          if (ifNoneMatchHits(req.headers["if-none-match"], etag)) {
            res.writeHead(304);
            res.end();
            return;
          }
        }
        reply(200, {
          version: policy.version,
          mode: policy.stopped ? "off" : policy.mode,
          stopped: policy.stopped,
          customRules: policy.customRules,
          archiveUpload:archivePolicy(policy.archiveUpload),
          githubUpload:githubPolicy(policy.githubUpload),
          overrides: policy.overrides,
          exemptions: policy.exemptions,
          engineRevision: ENGINE_REVISION,
          ...(rulesHash === undefined ? {} : { rulesHash }),
        });
        return;
      }

      if (method === "POST" && pathname === "/api/v2/evaluate") {
        const finishEvaluate = beginRouteLatency("evaluate");
        try {
          const d = requireDevice(req, res, v2RequestId);
          if (!d) return;
          // Capture before any body/queue wait; later fences retain this policy snapshot.
          const snapshot = store.capturePolicy();
          const body = await readLimited(req);
          if (!body.ok) { reply(413, { ok: false, error: "payload_too_large" }); return; }
          let parsed: unknown;
          try { parsed = JSON.parse(body.text); }
          catch { reply(400, { ok: false, error: "bad_json" }); return; }
          // IC-15: reject deep nesting before prepare walks it synchronously on the event loop.
          if (jsonDepthExceeds(parsed)) { reply(400, { ok: false, error: "bad_schema" }); return; }
          store.capturePolicy(); // Fence recovery after the body wait without changing snapshot.
          const ingress = prepareCanonicalEvaluation(parsed, d.id);
          if (!ingress.ok) { reply(ingress.code === "unauthorized" ? 401 : 400, { ok: false, error: ingress.code }); return; }
          const result = await evaluateDurably({ store, monitor, windows, snapshot, deviceId: d.id,
            event: ingress.event, prepared: ingress.prepared, project: canonicalEvaluateResponse });
          // The trusted application serialized and bounded this complete projection before effects.
          observeRequestOutcome(200);
          res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
            "x-content-type-options": "nosniff", "content-length": Buffer.byteLength(result.json) });
          res.end(result.json);
        } catch (error) {
          if (!(error instanceof EvaluationApplicationError)) throw error;
          const status = error.code === "unauthorized" ? 401 : error.code === "audit_storage_unavailable" ? 503
            : error.code === "evaluation_result_too_large" ? 413 : 409;
          reply(status, { ok: false, error: error.code });
        } finally { finishEvaluate(); }
        return;
      }

      if (method === "POST" && pathname === "/api/v1/evaluate") {
        const finishEvaluate = beginRouteLatency("evaluate");
        try {
        const d = requireDevice(req, res);
        if (!d) return;
        const snapshot = store.capturePolicy();
        const policy = structuredClone(snapshot.policy) as import("./schema.ts").PolicyState;
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: EvalRequestBody;
        try {
          parsed = JSON.parse(body.text || "{}") as EvalRequestBody;
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        // IC-15: reject deep nesting before the fingerprint walks it synchronously on the event loop.
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || jsonDepthExceeds(parsed)) {
          json(res, 400, { ok: false, error: "bad_schema" });
          return;
        }
        const eventId = typeof parsed.eventId === "string" && parsed.eventId ? parsed.eventId : newEventId();
        store.capturePolicy(); // Request-body waits must not bypass a newly entered recovery state.
        if (policy.stopped && store.getStorageMode() === "sqlite") {
          // Intentional migration exception: stopped V1 must not overwrite the meaning of a V2 identity.
          // This prefilter can report storage unavailability before the legacy stopped ALLOW.
          const incompatible = await store.withMutex(async () => {
            const identity = await store.lookupEvaluationIdentityUnlocked(d.id, eventId);
            store.capturePolicy();
            const current = store.getDevice(d.id);
            if (!current || typeof current.revokedAt === "number") return "unauthorized";
            return identity?.originProtocol === "v2" ? "event_protocol_incompatible" : undefined;
          });
          if (incompatible) { json(res, incompatible === "unauthorized" ? 401 : 409, { ok: false, error: incompatible }); return; }
        }
        if (policy.stopped) {
          json(res, 200, {
            eventId,
            decision: "allow",
            reason: "processing_stopped",
            stopped: true,
            ruleIds: [],
            policyVersion: policy.version,
            summary: "",
            enforcement: "delivered",
          });
          return;
        }
        const hash = evaluateRequestHash(parsed);
        const packed = await store.withMutex(async () => {
          const current = store.getDevice(d.id);
          if (!current || typeof current.revokedAt === "number") {
            return { status: 401 as const, body: { ok: false, error: "unauthorized" } };
          }
          store.capturePolicy(); // Fence recovery after request-body/queue waits; keep this call's snapshot.
          const identity = await store.lookupEvaluationIdentityUnlocked(d.id, eventId);
          store.capturePolicy();
          const afterLookup = store.getDevice(d.id);
          if (!afterLookup || typeof afterLookup.revokedAt === "number") return { status: 401, body: { ok: false, error: "unauthorized" } };
          if (identity?.originProtocol === "v2") return { status: 409, body: { ok: false, error: "event_protocol_incompatible" } };
          const prev = identity?.kind === "event" ? identity.event : undefined;
          if (prev) {
            if (prev.requestHash && prev.requestHash !== hash) {
              return { status: 409 as const, body: { ok: false, error: "event_conflict" } };
            }
            let updatedInput: Record<string, unknown> | undefined;
            if (prev.decision === "rewrite") {
              const historical = store.getHistoricalPolicy(prev.policyVersion);
              // A row without a binding, or one created under a different trusted
              // rule catalog/engine, cannot safely recreate its updatedInput.
              if (!historical || prev.policyHash !== historical.hash || !prev.requestHash
                || historical.rulesHash !== policyRulesHash(monitor) || historical.engineVersion !== NMZP_VERSION) {
                return { status: 200 as const, body: {
                  eventId, decision: "block", reason: "historical_policy_unavailable",
                  policyVersion: prev.policyVersion, ruleIds: prev.ruleId ? [prev.ruleId] : [],
                  summary: prev.redacted, enforcement: "pending_verify", duplicate: true,
                } };
              }
              const rw = reconstructRewrite(parsed, structuredClone(historical.policy.customRules) as CustomPrivacyRule[], privacyFrom(monitor));
              if (!rw.ok) {
                return {
                  status: 200 as const,
                  body: {
                    eventId,
                    decision: "block",
                    reason: rw.reason,
                    ruleIds: prev.ruleId ? [prev.ruleId] : [],
                    policyVersion: prev.policyVersion,
                    summary: prev.redacted,
                    enforcement: "pending_verify",
                    duplicate: true,
                  },
                };
              }
              updatedInput = rw.updatedInput;
            }
            return {
              status: 200 as const,
              body: {
                eventId,
                decision: prev.decision,
                egress: prev.egress,
                reason: prev.ruleId ?? prev.decision,
                ruleIds: prev.ruleId ? [prev.ruleId] : [],
                policyVersion: prev.policyVersion,
                summary: prev.redacted,
                updatedInput,
                enforcement: prev.enforcement,
                duplicate: true,
              },
            };
          }
          const tombstone=await store.getAuditTombstone(d.id,eventId);
          if(tombstone){
            if(tombstone.requestHash && tombstone.requestHash!==hash){
              return {status:409 as const,body:{ok:false,error:"event_conflict"}};
            }
            return {status:200 as const,body:{eventId,decision:"block",reason:"historical_event_pruned",
              ruleIds:[],policyVersion:tombstone.policyVersion,summary:"",enforcement:"pending_verify",duplicate:true}};
          }
          const out = applyEvaluate({
            monitor,
            windows,
            policy,
            device: d,
            body: parsed,
            eventId,
          });
          if (out.event) {
            out.event.requestHash = hash;
            out.event.policyHash = snapshot.hash;
            await store.appendEventUnlocked(out.event);
          }
          return { status: 200 as const, body: out.response };
        });
        json(res, packed.status, packed.body);
        return;
        } finally {
          finishEvaluate();
        }
      }

      if (method === "POST" && (pathname === "/api/v1/receipt" || pathname === "/api/v2/receipts")) {
        const d = requireDevice(req, res, v2RequestId);
        if (!d) return;
        const body = await readLimited(req);
        if (!body.ok) {
          reply(413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: { eventId?: string; evaluation?: string; enforcement?: string };
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          reply(400, { ok: false, error: "bad_json" });
          return;
        }
        if (v2RequestId && !bindBodyDevice(parsed, d.id)) {
          reply(401, { ok: false, error: "unauthorized" });
          return;
        }
        const receipt = v2RequestId ? parseReceiptBody(parsed) : parseLegacyReceiptBody(parsed);
        if (!receipt) {
          reply(400, { ok: false, error: "bad_receipt" });
          return;
        }
        const ev = await store.getEvent(d.id, receipt.eventId);
        if (ev && receiptEvaluationChanges(receipt, ev.evaluation)) {
          reply(409, { ok: false, error: "evaluation_immutable" });
          return;
        }
        const updated = await store.updateReceipt(d.id, receipt.eventId, receipt.enforcement);
        if ("error" in updated) {
          const status = updated.error === "unauthorized" ? 401 : updated.error === "forbidden" ? 403 : 404;
          reply(status, { ok: false, error: updated.error });
          return;
        }
        reply(200, { ok: true, eventId: updated.id, enforcement: updated.enforcement, evaluation: updated.evaluation });
        return;
      }

      if (method === "POST" && (pathname === "/api/v1/audit/backfill" || pathname === "/api/v2/backfill")) {
        const d=requireDevice(req,res,v2RequestId);
        if(!d)return;
        if(store.getStorageMode()!=="sqlite"){reply(404,{ok:false,error:"storage_not_enabled"});return;}
        const body=await readLimited(req);
        if(!body.ok){reply(413,{ok:false,error:"payload_too_large"});return;}
        let raw:unknown;
        try{raw=JSON.parse(body.text||"{}");}catch{raw=undefined;}
        if(raw!==undefined && v2RequestId && !bindBodyDevice(raw,d.id)){reply(401,{ok:false,error:"unauthorized"});return;}
        let parsed:ReturnType<typeof parseBackfill>=null;
        try{if(raw!==undefined)parsed=parseBackfill(raw);}catch{parsed=null;}
        if(!parsed){reply(400,{ok:false,error:"bad_backfill"});return;}
        if(parsed.kind==="receipt"){
          const result=await store.confirmBackfillReceipt(d.id,parsed.eventId,parsed.payload.evaluation,parsed.payload.enforcement);
          if("error" in result){const code=result.error;
            reply(code==="unauthorized"?401:code==="forbidden"?403:code==="not_found"?404:409,{ok:false,error:code});return;}
          reply(200,{ok:true,eventId:parsed.eventId,duplicate:result.duplicate,enforcement:result.event.enforcement});return;
        }
        const outcome=await store.withMutex(async()=>{
          const current=store.getDevice(d.id);
          if(!current || typeof current.revokedAt==="number") return {status:401 as const,body:{ok:false,error:"unauthorized"}};
          const policy=store.getPolicy();
          if(policy.stopped)return {status:503 as const,body:{ok:false,error:"processing_stopped"}};
          const identity=await store.lookupEvaluationIdentityUnlocked(d.id,parsed.eventId);
          store.capturePolicy();
          const afterLookup=store.getDevice(d.id);
          if(!afterLookup || typeof afterLookup.revokedAt==="number") return {status:401 as const,body:{ok:false,error:"unauthorized"}};
          if(identity?.originProtocol==="v2") return {status:409 as const,body:{ok:false,error:"event_protocol_incompatible"}};
          const prior=identity?.kind==="event"?identity.event:undefined;
          if(prior){
            const same=prior.source==="offline_backfill" && prior.ts===parsed.payload.ts && prior.agent===parsed.payload.agent
              && prior.tool===parsed.payload.tool && prior.decision===parsed.payload.decision && prior.risk===parsed.payload.risk
              && prior.policyVersion===parsed.payload.policyVersion && prior.ruleId===parsed.payload.ruleId
              && prior.relatedEventId===parsed.payload.relatedEventId;
            return same?{status:200 as const,body:{ok:true,eventId:parsed.eventId,duplicate:true}}
              :{status:409 as const,body:{ok:false,error:"event_conflict"}};
          }
          if(await store.getAuditTombstone(d.id,parsed.eventId))return {status:409 as const,body:{ok:false,error:"event_expired"}};
          const p=parsed.payload;
          await store.appendEventUnlocked({id:parsed.eventId,ts:p.ts,machineId:d.id,agent:p.agent,sessionId:"",layer:"app_pre",
            tool:p.tool,nativeTool:p.tool,input:"",risk:p.risk,decision:p.decision,ruleId:p.ruleId,category:"other",
            workdirScope:"unknown",redacted:"",policyVersion:p.policyVersion,evaluation:p.decision,enforcement:"offline",
            source:"offline_backfill",degraded:true,hookBlind:true,relatedEventId:p.relatedEventId});
          return {status:200 as const,body:{ok:true,eventId:parsed.eventId,duplicate:false}};
        });
        reply(outcome.status,outcome.body);return;
      }

      if (method === "POST" && pathname === "/api/v1/ticket") {
        if (!requireAdmin(req, res)) return;
        const ticket = newSecret(24);
        await store.addTicket(sha256Hex(ticket), JOIN_TICKET_TTL_MS);
        json(res, 200, {
          ticket,
          expiresInMs: JOIN_TICKET_TTL_MS,
          fingerprintSha256: tls.fingerprintSha256,
          caPem: tls.certPem,
        });
        return;
      }

      if (method === "GET" && uiDir) {
        if (pathname.startsWith("/api/")) {
          reply(404, { ok: false, error: "not_found" });
          return;
        }
        if (serveStatic(res, uiDir, pathname)) return;
      }

      reply(404, { ok: false, error: "not_found" });
    } catch (error) {
      const code = error instanceof Error ? error.message : "";
      if (["policy_recovery_required", "policy_not_committed", "policy_queue_full"].includes(code)) {
        reply(503, { ok: false, error: code });
      } else if (code === "audit_event_protocol_incompatible") {
        reply(409,{ok:false,error:"event_protocol_incompatible"});
      } else if (code === "audit_event_conflict") {
        reply(409,{ok:false,error:"event_conflict"});
      } else if (code.startsWith("audit_") || code.includes("SQLITE_FULL") || (error as NodeJS.ErrnoException)?.code === "ENOSPC") {
        reply(503,{ok:false,error:"audit_storage_unavailable"});
      } else if (error instanceof PolicyDomainError) {
        if (v2RequestId) reply(500, { ok: false, error: "internal_error" });
        else failJson(res, 400, error.code, error.ruleIds ? { ruleIds: [...error.ruleIds] } : undefined);
      } else {
        reply(500, { ok: false, error: "internal_error" });
      }
    }
  };

  const server: HttpsServer = startingServer = createHttpsServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
    void handler(req, res).catch(() => {
      if (!res.headersSent) deviceReply(res, 500, { ok: false, error: "internal_error" }, req.url?.startsWith("/api/v2/") ? ownerUuid() : undefined);
    });
  });

  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 0;
  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => resolve());
    server.on("error", reject);
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("listen failed");
  const bound = addr.port;
  const url = connectableUrl(host, bound);
  await writeServePointer(opts.dataDir, {
    pid: process.pid,
    host,
    port: bound,
    url,
    fingerprintSha256: tls.fingerprintSha256,
    startedAt: Date.now(),
  });
  scheduleMaintenance(1000);
  return {
    host,
    port: bound,
    url,
    tls,
    adminToken: admin.token,
    store,
    close: closeServer,
    fatal,
    onFatal: (listener: () => void) => { void fatal.then(listener); },
  };
  } catch (error) {
    try { await closeServer(); } catch { /* the original startup error is the one callers see */ }
    throw error;
  }
}

export async function issueJoinTicket(store: NmzpStore): Promise<string> {
  const ticket = newSecret(24);
  await store.addTicket(sha256Hex(ticket), JOIN_TICKET_TTL_MS);
  return ticket;
}
