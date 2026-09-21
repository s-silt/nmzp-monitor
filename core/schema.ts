import type {EgressEvidence} from "./egress-schema.ts";
import type {ProbeBinding} from "./probe-auth.ts";
import type {NetworkOwnerGrant} from "./network-owner-schema.ts";
import type {DiscoverySnapshot} from "./agent-discovery-schema.ts";
import type {ResponseEvidence} from "./response-evidence.ts";
export type Intervention = "enforcing" | "permissive" | "off";
export type Decision = "block" | "confirm" | "allow" | "log" | "rewrite";
export type Risk = "high" | "medium" | "low" | "info";

export interface CustomPrivacyRule {
  id: string;
  enabled: boolean;
  mode: "block" | "replace";
  match: string;
  kind: string;
  replaceWith: string;
  scope?: import("./policy-schema.ts").CustomRuleScope;
  dryRun?: boolean;
}

export interface Capability {
  id: string;
  supported: boolean;
  active: boolean;
  lastSuccess?: number;
  error?: string;
}

/** Confirmed agent process from probe. bin is a basename; pid is never 0. */
export interface AgentProc {
  agent: string;
  pid: number;
  ppid: number;
  bin: string;
}

export function parseAgentProcs(raw: unknown): AgentProc[] {
  if (!Array.isArray(raw)) return [];
  const out: AgentProc[] = [];
  for (const row of raw) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const a = row as Record<string, unknown>;
    const agent = typeof a.agent === "string" ? a.agent.trim().slice(0, 32) : "";
    const pid =
      typeof a.pid === "number" && Number.isInteger(a.pid) && a.pid > 0 && a.pid <= 4_000_000_000 ? a.pid : 0;
    const ppid =
      typeof a.ppid === "number" && Number.isInteger(a.ppid) && a.ppid >= 0 && a.ppid <= 4_000_000_000 ? a.ppid : -1;
    const bin = typeof a.bin === "string" ? a.bin.trim().slice(0, 64) : "";
    if (!agent || pid <= 0 || ppid < 0 || !bin) continue;
    if (bin.includes("/") || bin.includes("\\") || bin.includes("\0") || bin.includes("..")) continue;
    out.push({ agent, pid, ppid, bin });
  }
  return out;
}

export type Enforcement =
  | "blocked"
  | "returned_deny"
  | "pending_verify"
  | "timeout"
  | "failed"
  | "delivered"
  | "offline"
  | "degraded";

export interface StoredEvent {
  egress?: EgressEvidence;
  response?: ResponseEvidence;
  id: string;
  ts: number;
  machineId: string;
  agent: string;
  sessionId: string;
  layer: string;
  tool: string;
  nativeTool: string;
  input: string;
  risk: Risk;
  decision: Decision;
  ruleId?: string;
  category: string;
  workdirScope: string;
  dest?: string;
  /**
   * Declared HTTP(S) targets for this event. Missing = 未采集 (historic).
   * Empty array = collected, none declared. Never backfilled on old rows.
   */
  endpoints?: EndpointEvidence[];
  redacted: string;
  threat?: string;
  secretKinds?: string[];
  detectedModel?: string;
  source?: string;
  hookBlind?: boolean;
  correlateHit?: boolean;
  actor?: string;
  proc?: string;
  rewritten?: boolean;
  policyVersion: number;
  evaluation: Decision;
  enforcement: Enforcement;
  degraded?: boolean;
  duplicate?: boolean;
  /** SHA-256 of canonical request; never the raw tool body. */
  requestHash?: string;
  overrideSource?: "rule" | "family";
  exemptionId?: string;
  dryRunKinds?: string[];
}

export type EndpointSource = "tool_url" | "tool_command";
export type EndpointObservation = "declared";

/** Host/port/scheme only. No userinfo, path, query, fragment, or reverse-DNS. */
export interface EndpointEvidence {
  host: string;
  port?: number;
  scheme?: "http" | "https";
  source: EndpointSource;
  observation: EndpointObservation;
}

export type NetworkSampleStatus =
  | "ok"
  | "timeout"
  | "unsupported"
  | "permission"
  | "partial"
  | "truncated"
  | "not_sampled"
  | "error";

export type NetworkRole = "egress" | "local";
/** Established = observed peer, initiation unknown. SynSent = attempted. */
export type NetworkDirection = "unknown" | "attempted";

/** Observed TCP metadata. No bytes, no reverse-DNS hostname, no command line. */
export interface NetworkConnection {
  remoteIp: string;
  remotePort: number;
  localIp: string;
  localPort: number;
  state: string;
  role: NetworkRole;
  direction?: NetworkDirection;
  observedAt: number;
  pid: number;
  ppid: number;
  processStartedAt: number;
  bin: string;
  agent: string;
}

/**
 * Latest sample on a device (`network` public field).
 * status ok + connections [] = sampled zero egress sockets.
 * timeout/unsupported/permission/not_sampled never mean successful zero.
 * Bound/Listen/zero-remote are not egress and are not listed.
 */
export interface NetworkSampleReport {
  status: NetworkSampleStatus;
  observedAt: number;
  receivedAt?: number;
  connections: NetworkConnection[];
  truncated?: boolean;
  error?: string;
}

export interface NetworkHistoryRow {
  id: string;
  machineId: string;
  agent: string;
  pid: number;
  ppid: number;
  processStartedAt: number;
  bin: string;
  remoteIp: string;
  remotePort: number;
  localIp: string;
  localPort: number;
  state: string;
  role: "egress";
  direction?: NetworkDirection;
  firstSeen: number;
  lastSeen: number;
}

export type StopState = "running" | "stop_pending" | "stop_confirmed" | "offline";

export interface PolicyState {
  githubUpload?: import("./egress-schema.ts").GithubUploadPolicy;
  archiveUpload?: import("./egress-schema.ts").ArchiveUploadPolicy;
  version: number;
  mode: Intervention;
  customRules: CustomPrivacyRule[];
  stopped: boolean;
  previousMode?: Intervention;
  updatedAt: number;
  overrides?: import("./policy-schema.ts").PolicyOverrides;
  exemptions?: import("./policy-schema.ts").PolicyExemption[];
}

export const SNAPSHOT_GUARD_COVERAGE = ["none", "protected", "partial", "unknown"] as const;
export type SnapshotGuardCoverage = (typeof SNAPSHOT_GUARD_COVERAGE)[number];

/** Public per-device snapshot protection. No paths, ACL/SDDL, or file contents. */
export interface SnapshotGuardReport {
  supported: boolean;
  active: boolean;
  managed: boolean;
  targetPresent: boolean;
  writeBlocked: boolean;
  existingArchiveCoverage: SnapshotGuardCoverage;
  error?: string;
  lastVerified: number;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function asPublicBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

function asPublicCoverage(v: unknown): SnapshotGuardCoverage | undefined {
  return v === "none" || v === "protected" || v === "partial" || v === "unknown" ? v : undefined;
}

function asPublicLastVerified(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > Number.MAX_SAFE_INTEGER) return undefined;
  return v;
}

function asPublicError(v: unknown): string | undefined {
  if (typeof v !== "string" || !/^[a-z0-9_-]{1,64}$/i.test(v)) return undefined;
  return v.toLowerCase();
}

/**
 * Strict public snapshot-guard projection. Unknown keys are dropped.
 * Wrong types on known fields → undefined. partial/unknown cannot be active.
 */
export function parseSnapshotGuardReport(raw: unknown): SnapshotGuardReport | undefined {
  if (!isPlainObject(raw)) return undefined;
  const supported = asPublicBool(raw.supported);
  const active = asPublicBool(raw.active);
  const managed = asPublicBool(raw.managed);
  const targetPresent = asPublicBool(raw.targetPresent);
  const writeBlocked = asPublicBool(raw.writeBlocked);
  const existingArchiveCoverage = asPublicCoverage(raw.existingArchiveCoverage);
  const lastVerified = asPublicLastVerified(raw.lastVerified);
  if (
    supported === undefined ||
    active === undefined ||
    managed === undefined ||
    targetPresent === undefined ||
    writeBlocked === undefined ||
    existingArchiveCoverage === undefined ||
    lastVerified === undefined
  ) {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(raw, "error") && raw.error !== undefined) {
    if (asPublicError(raw.error) === undefined) return undefined;
  }
  const err = asPublicError(raw.error);
  if (
    active &&
    (!supported ||
      !managed ||
      !targetPresent ||
      !writeBlocked ||
      (existingArchiveCoverage !== "none" && existingArchiveCoverage !== "protected") ||
      lastVerified <= 0 ||
      err)
  ) {
    return undefined;
  }
  const out: SnapshotGuardReport = {
    supported,
    active,
    managed,
    targetPresent,
    writeBlocked,
    existingArchiveCoverage,
    lastVerified,
  };
  if (err) out.error = err;
  return out;
}

/** Map library-only keys/coverage onto the public shape, then parse. Never copies ACL/SDDL/paths. */
export function adaptSnapshotGuardLibraryStatus(raw: unknown): SnapshotGuardReport | undefined {
  if (!isPlainObject(raw)) return undefined;
  const coverage = raw.existingArchiveCoverage === "unprotected" ? "partial" : raw.existingArchiveCoverage;
  const lastVerified = asPublicLastVerified(raw.lastVerified) ?? 0;
  const existingError = asPublicError(raw.error);
  const error = existingError ?? (lastVerified <= 0 ? "not_verified" : undefined);
  let active = raw.active === true;
  if (coverage === "partial" || coverage === "unknown" || lastVerified <= 0 || error) active = false;
  return parseSnapshotGuardReport({
    supported: raw.supported,
    active,
    managed: raw.managed,
    targetPresent: raw.targetPresent,
    writeBlocked: raw.writeBlocked,
    existingArchiveCoverage: coverage,
    lastVerified,
    ...(error ? { error } : {}),
  });
}

export interface DeviceRecord {
  probeBinding?: ProbeBinding;
  /** Internal admin authority. Never projected to state/export. */
  networkOwners?: NetworkOwnerGrant[];
  discovery?: DiscoverySnapshot;
  id: string;
  tokenHash: string;
  hostname: string;
  ip: string;
  user: string;
  os: "linux" | "darwin" | "win32";
  attachedAt: number;
  lastSeen: number;
  lastPolicyVersion: number;
  capabilities: Capability[];
  agents: string[];
  agentProcs?: AgentProc[];
  stoppedAck?: boolean;
  stopAckVersion?: number;
  snapshotGuard?: SnapshotGuardReport;
  /** Latest TCP sample. Strict-parsed. Missing = 未采集. */
  network?: NetworkSampleReport;
}
