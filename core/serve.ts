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
import { publicNetworkHistory, publicNetworkSample, sanitizeAuditText, sanitizeStoredEvent } from "./network-evidence.ts";
import { loadOrCreateTls, type TlsMaterial } from "./tls.ts";
import { loadMonitor, resolveUiDir, type MonitorMods } from "./paths.ts";
import { json, originOk, readLimited, serveStatic } from "./http-util.ts";
import {
  applyEvaluate,
  privacyFrom,
  reconstructRewrite,
  requestFingerprint,
  type EvalRequestBody,
} from "./eval-bridge.ts";
import { exportBundleShape } from "./export.ts";
import { parseAgentProcs, parseSnapshotGuardReport, type CustomPrivacyRule, type Enforcement } from "./schema.ts";
import { parsePolicyExemptions, parsePolicyOverrides } from "./policy-schema.ts";

const ADMIN_COOKIE = "nmzp_admin";

export interface ServeOpts {
  dataDir: string;
  host?: string;
  port?: number;
  uiDir?: string | null;
  coreDir?: string;
  extraHosts?: string[];
  adminToken?: string;
}

export interface RunningServer {
  host: string;
  port: number;
  url: string;
  tls: TlsMaterial;
  adminToken: string;
  store: NmzpStore;
  close: () => Promise<void>;
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
  };
}

function publicStoredEvent(e: import("./schema.ts").StoredEvent) {
  const cleaned = sanitizeStoredEvent(e);
  const { evaluation: _ev, ...rest } = cleaned;
  return {
    ...rest,
    input: sanitizeAuditText(typeof rest.input === "string" ? rest.input : ""),
    redacted: sanitizeAuditText(typeof rest.redacted === "string" ? rest.redacted : ""),
    dest: rest.dest,
    endpoints: rest.endpoints,
    requestHash: rest.requestHash,
  };
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

const ENFORCEMENT = new Set<Enforcement>([
  "blocked",
  "returned_deny",
  "pending_verify",
  "timeout",
  "failed",
  "delivered",
  "offline",
  "degraded",
]);

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

export async function startServer(opts: ServeOpts): Promise<RunningServer> {
  const coreDir = opts.coreDir ?? coreDirDefault();
  const monitor: MonitorMods = await loadMonitor(coreDir);
  const suggested = Array.isArray(monitor.privacy.SUGGESTED_PRIVACY)
    ? (monitor.privacy.SUGGESTED_PRIVACY as CustomPrivacyRule[])
    : [];
  const store = new NmzpStore(opts.dataDir);
  await store.load({ defaultRules: suggested, defaultOverrides: monitor.SUGGESTED_OVERRIDES });
  const admin = await bootstrapAdmin(store, opts.adminToken);
  const hosts = ["127.0.0.1", "localhost", ...(opts.extraHosts ?? [])];
  const tls = await loadOrCreateTls(opts.dataDir, hosts);
  const challenges=new ProbeChallenges();
  const windows = new monitor.SessionWindows();
  const uiDir = opts.uiDir === undefined ? resolveUiDir(coreDir) : opts.uiDir;

  const adminOk = (req: IncomingMessage): boolean => {
    const bearer = parseBearer(req.headers.authorization);
    const cookie = parseCookie(req.headers.cookie, ADMIN_COOKIE);
    const token = bearer ?? cookie;
    if (!token) return false;
    return safeEqualHex(sha256Hex(token), store.adminHash());
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

  const requireDevice = (req: IncomingMessage, res: ServerResponse) => {
    const token = parseBearer(req.headers.authorization);
    if (!token) {
      json(res, 401, { ok: false, error: "unauthorized" });
      return null;
    }
    const d = store.findDeviceByToken(token);
    if (!d) {
      json(res, 401, { ok: false, error: "unauthorized" });
      return null;
    }
    return d;
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const { pathname } = pathOf(req);
    const method = req.method ?? "GET";

    try {
      if (method === "GET" && pathname === "/health") {
        json(res, 200, { ok: true, name: NMZP_NAME, version: NMZP_VERSION });
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
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "set-cookie": `${ADMIN_COOKIE}=${encodeURIComponent(parsed.token)}; Path=/; HttpOnly; SameSite=Strict; Secure`,
          "cache-control": "no-store",
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      if (method === "GET" && pathname === "/api/v1/state") {
        if (!requireAdmin(req, res)) return;
        const now = Date.now();
        const policy = store.getPolicy();
        const devices = store.listDevices(now).map((d) => publicStateDevice(d));
        const events = store.listEvents().map((e) => publicStoredEvent(e));
        const hookActive = (id: string) =>
          devices.some((d) => (d.capabilities ?? []).some((c) => c.id === id && c.active));
        json(res, 200, {
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
        });
        return;
      }

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
        if(parsed.githubUpload!==undefined&&!parseGithubPolicy(parsed.githubUpload)){json(res,400,{error:"invalid_github_policy"});return;}
        if(parsed.archiveUpload!==undefined&&!parseArchivePolicy(parsed.archiveUpload)){json(res,400,{error:"invalid_archive_policy"});return;}
        let overridesPatch: ReturnType<typeof parsePolicyOverrides> | undefined;
        if (parsed.overrides !== undefined) {
          overridesPatch = parsePolicyOverrides(parsed.overrides);
          if (!overridesPatch) {
            json(res, 400, { error: "invalid_policy_overrides" });
            return;
          }
          const unknown = monitor.unknownRuleIds(overridesPatch, monitor.RULES);
          if (unknown.length) {
            json(res, 400, { error: "unknown_rule_override", ruleIds: unknown });
            return;
          }
          const protectedIds = monitor.protectedDowngrades(overridesPatch, monitor.RULES);
          if (protectedIds.length) {
            json(res, 400, { error: "protected_rule_override", ruleIds: protectedIds });
            return;
          }
        }
        let exemptionsPatch: ReturnType<typeof parsePolicyExemptions> | undefined;
        if (parsed.exemptions !== undefined) {
          exemptionsPatch = parsePolicyExemptions(parsed.exemptions);
          if (!exemptionsPatch) {
            json(res, 400, { error: "invalid_policy_exemptions" });
            return;
          }
          for (const ex of exemptionsPatch) {
            if (!monitor.privacy.compileMatch(ex.match)) {
              json(res, 400, { error: "invalid_policy_exemptions" });
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
            json(res, 400, { error: "protected_rule_exemption", ruleIds: [...new Set(bad)] });
            return;
          }
        }
        let customRules = parsed.customRules;
        if (parsed.customRules !== undefined) {
          const n = monitor.privacy.sanitizeCustomRules(parsed.customRules);
          if (!n || n.length !== parsed.customRules.length || n.length > monitor.privacy.MAX_CUSTOM_RULES) {
            json(res, 400, { error: "invalid_custom_rules" });
            return;
          }
          customRules = n;
        }
        const mode =
          parsed.mode === "enforcing" || parsed.mode === "permissive" || parsed.mode === "off" ? parsed.mode : undefined;
        const result = await store.casPolicy(parsed.expectedVersion, {
          mode,
          customRules,
          stopped: parsed.stopped,
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
        if (!requireAdmin(req, res)) return;
        const bundle = exportBundleShape(store);
        json(res, 200, { ...bundle, machines: store.listDevices().map((d) => publicExportMachine({...d,probeProtection:publicProbeProtection(d.probeBinding)})) });
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
        let parsed: { ticket?: string; hostname?: string; os?: string; user?: string; ip?: string };
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        if (!parsed.ticket || !(await store.consumeTicket(parsed.ticket))) {
          json(res, 401, { ok: false, error: "join_ticket_invalid" });
          return;
        }
        const os = parsed.os === "darwin" || parsed.os === "linux" || parsed.os === "win32" ? parsed.os : "win32";
        const id = newDeviceId();
        const token = newSecret(32);
        const now = Date.now();
        await store.putDevice({
          id,
          tokenHash: sha256Hex(token),
          hostname: (parsed.hostname ?? "host").slice(0, 80),
          ip: (parsed.ip ?? "").slice(0, 64),
          user: (parsed.user ?? "").slice(0, 64),
          os,
          attachedAt: now,
          lastSeen: now,
          lastPolicyVersion: store.getPolicy().version,
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

      if (pathname === "/api/v1/network-owners") {
        if (method === "GET") {
          const d=requireDevice(req,res);if(!d)return;
          json(res,200,{grants:store.getPolicy().stopped?[]:activeOwnerGrants(d.networkOwners)});return;
        }
        if (method !== "POST") {json(res,405,{error:"method"});return;}
        if (!requireAdmin(req,res)) return;
        const body=await readLimited(req);if(!body.ok){json(res,413,{error:"too_large"});return;}
        let raw;try{raw=JSON.parse(body.text);}catch{json(res,400,{error:"invalid_owner"});return;}
        if(!raw || typeof raw!=="object" || Array.isArray(raw)){json(res,400,{error:"invalid_owner"});return;}
        if(typeof raw.deviceId!=="string" || !["approve","revoke"].includes(raw.action)) {json(res,400,{error:"invalid_owner"});return;}
        let grant;
        if(raw.action==="approve") {
          const now=Date.now();
          grant=parseOwnerGrant({...raw.claim,id:ownerUuid(),approvedAt:now});
          if(!grant || grant.expiresAt<=now || store.getPolicy().stopped) {json(res,400,{error:"invalid_owner"});return;}
        } else if(typeof raw.id!=="string" || !/^[a-f0-9-]{36}$/.test(raw.id)) {json(res,400,{error:"invalid_owner"});return;}
        if(!await store.updateNetworkOwner(raw.deviceId,grant,raw.action==="revoke"?raw.id:undefined)) {json(res,409,{error:"owner_device_or_limit"});return;}
        json(res,200,{ok:true,...(grant?{grant}:{})});return;
      }
      if(method==="POST"&&pathname==="/api/v1/probe/binding") {
        if(!requireAdmin(req,res))return;
        const b=await readLimited(req);if(!b.ok){json(res,413,{error:"too_large"});return;}
        let raw,binding;try{raw=JSON.parse(b.text);if(!raw||typeof raw.deviceId!=="string")throw Error();binding=raw.action==="revoke"?"revoke" as const:raw.action==="enroll"&&typeof raw.publicKey==="string"?newProbeBinding(raw.publicKey):null;if(!binding)throw Error();}catch{json(res,400,{error:"invalid_probe_binding"});return;}
        if(!await store.bindProbe(raw.deviceId,binding)){json(res,409,{error:"probe_device_or_binding_missing"});return;}
        json(res,200,{ok:true,probeProtection:publicProbeProtection(store.getDevice(raw.deviceId)?.probeBinding)});return;
      }
      if(method==="GET"&&pathname==="/api/v1/probe/challenge") {
        const d=requireDevice(req,res);if(!d)return;
        if(!d.probeBinding||d.probeBinding.revoked){json(res,403,{error:"probe_binding_required"});return;}
        const c=challenges.issue(d.id,d.probeBinding);json(res,c?200:429,c??{error:"challenge_limit"});return;
      }
      if (method === "POST" && pathname === "/api/v1/heartbeat") {
        const d = requireDevice(req, res);
        if (!d) return;
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        const expectedProbeKey=d.probeBinding?d.probeBinding.keyId+":"+d.probeBinding.registeredAt:null;
        if(d.probeBinding&&!challenges.consume(d.id,d.probeBinding,body.text,req.headers)){json(res,401,{error:"probe_proof_required"});return;}
        let parsed: {
          hostname?: string;
          agents?: string[];
          agentProcs?: unknown;
          capabilities?: DeviceRecordCap[];
          policyVersion?: number;
          ip?: string;
          user?: string;
          pollOnly?: boolean;
          stoppedAck?: boolean;
          snapshotGuard?: unknown;
          discovery?: unknown;
          network?: unknown;
        } = {};
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        const policy = store.getPolicy();
        const pollOnly = parsed.pollOnly === true;
        const stoppedAck = parsed.stoppedAck === true;
        const reportedVersion = typeof parsed.policyVersion === "number" ? parsed.policyVersion : -1;
        const applied = policy.stopped && stoppedAck && reportedVersion === policy.version;
        const now = Date.now();
        const incomingDiscovery = parseDiscovery(parsed.discovery, now);
        const discovery = incomingDiscovery && incomingDiscovery.completedAt >= (d.discovery?.completedAt ?? 0) ? {...incomingDiscovery,receivedAt:now} : d.discovery;
        const snapshotGuard = mergeHeartbeatSnapshotGuard(d.snapshotGuard, parsed.snapshotGuard, pollOnly);
        if (pollOnly) {
          await store.touchDevice(d.id, {
            lastSeen: now,
            lastPolicyVersion: reportedVersion >= 0 ? reportedVersion : d.lastPolicyVersion,
            agentProcs: [],
            stoppedAck: applied,
            stopAckVersion: applied ? policy.version : policy.stopped ? (d.stopAckVersion ?? 0) : 0,
            snapshotGuard,
          },expectedProbeKey);
          await store.applyNetworkSample(d.id, parsed.network, true, now,expectedProbeKey);
        } else {
          await store.touchDevice(d.id, {
            lastSeen: now,
            hostname: parsed.hostname ?? d.hostname,
            ip: parsed.ip ?? d.ip,
            user: parsed.user ?? d.user,
            lastPolicyVersion: reportedVersion >= 0 ? reportedVersion : d.lastPolicyVersion,
            discovery,
            capabilities: Array.isArray(parsed.capabilities) ? parsed.capabilities : d.capabilities,
            agents: Array.isArray(parsed.agents) ? parsed.agents.map(String) : d.agents,
            agentProcs: parseAgentProcs(parsed.agentProcs),
            stoppedAck: applied,
            stopAckVersion: applied ? policy.version : policy.stopped ? (d.stopAckVersion ?? 0) : 0,
            snapshotGuard,
          },expectedProbeKey);
          await store.applyNetworkSample(d.id, parsed.network, false, now,expectedProbeKey);
        }
        const updated = store.getDevice(d.id) ?? d;
        json(res, 200, {
          mode: policy.stopped ? "off" : policy.mode,
          policyVersion: policy.version,
          stopped: policy.stopped,
          status: deriveDeviceStatus(updated.lastSeen, now),
          stopState: deriveStopState(policy, updated, now),
        });
        return;
      }

      if (method === "GET" && pathname === "/api/v1/policy") {
        const d = requireDevice(req, res);
        if (!d) return;
        const policy = store.getPolicy();
        json(res, 200, {
          version: policy.version,
          mode: policy.stopped ? "off" : policy.mode,
          stopped: policy.stopped,
          customRules: policy.customRules,
          archiveUpload:archivePolicy(policy.archiveUpload),
          githubUpload:githubPolicy(policy.githubUpload),
          overrides: policy.overrides,
          exemptions: policy.exemptions,
        });
        return;
      }

      if (method === "POST" && pathname === "/api/v1/evaluate") {
        const d = requireDevice(req, res);
        if (!d) return;
        const policy = store.getPolicy();
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
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          json(res, 400, { ok: false, error: "bad_schema" });
          return;
        }
        const eventId = typeof parsed.eventId === "string" && parsed.eventId ? parsed.eventId : newEventId();
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
          const prev = store.getEventUnlocked(d.id, eventId);
          if (prev) {
            if (prev.requestHash && prev.requestHash !== hash) {
              return { status: 409 as const, body: { ok: false, error: "event_conflict" } };
            }
            let updatedInput: Record<string, unknown> | undefined;
            if (prev.decision === "rewrite") {
              const rw = reconstructRewrite(parsed, policy.customRules, privacyFrom(monitor));
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
            store.appendEventUnlocked(out.event);
          }
          return { status: 200 as const, body: out.response };
        });
        json(res, packed.status, packed.body);
        return;
      }

      if (method === "POST" && pathname === "/api/v1/receipt") {
        const d = requireDevice(req, res);
        if (!d) return;
        const body = await readLimited(req);
        if (!body.ok) {
          json(res, 413, { ok: false, error: "payload_too_large" });
          return;
        }
        let parsed: { eventId?: string; evaluation?: string; enforcement?: string };
        try {
          parsed = JSON.parse(body.text || "{}");
        } catch {
          json(res, 400, { ok: false, error: "bad_json" });
          return;
        }
        if (!parsed.eventId || !parsed.enforcement || !ENFORCEMENT.has(parsed.enforcement as Enforcement)) {
          json(res, 400, { ok: false, error: "bad_receipt" });
          return;
        }
        const ev = store.getEvent(d.id, parsed.eventId);
        if (ev && parsed.evaluation && parsed.evaluation !== ev.evaluation) {
          json(res, 409, { ok: false, error: "evaluation_immutable" });
          return;
        }
        const updated = await store.updateReceipt(d.id, parsed.eventId, parsed.enforcement as Enforcement);
        if ("error" in updated) {
          json(res, updated.error === "forbidden" ? 403 : 404, { ok: false, error: updated.error });
          return;
        }
        json(res, 200, { ok: true, eventId: updated.id, enforcement: updated.enforcement, evaluation: updated.evaluation });
        return;
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
          json(res, 404, { ok: false, error: "not_found" });
          return;
        }
        if (serveStatic(res, uiDir, pathname)) return;
      }

      json(res, 404, { ok: false, error: "not_found" });
    } catch {
      json(res, 500, { ok: false, error: "internal_error" });
    }
  };

  const server: HttpsServer = createHttpsServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
    void handler(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { ok: false, error: "internal_error" });
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
  return {
    host,
    port: bound,
    url,
    tls,
    adminToken: admin.token,
    store,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((e) => {
          removeServePointer(opts.dataDir);
          if (e) reject(e);
          else resolve();
        });
      }),
  };
}

type DeviceRecordCap = import("./schema.ts").Capability;

export async function issueJoinTicket(store: NmzpStore): Promise<string> {
  const ticket = newSecret(24);
  await store.addTicket(sha256Hex(ticket), JOIN_TICKET_TTL_MS);
  return ticket;
}
