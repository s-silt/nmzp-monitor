import type {EgressEvidence} from "./egress-schema.ts";
import type {ProbeBinding} from "./probe-binding.ts";
import type {NetworkOwnerGrant} from "./network-owner-schema.ts";
import type {DiscoverySnapshot} from "./agent-discovery-schema.ts";
import type {ResponseEvidence} from "./response-evidence.ts";
import { RULE_ID_RE, customRuleState } from "./policy-schema.ts";
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
  setId?: string;
}

/** Local sets are writable. A subscription source parses, and 26d is what may store it. */
export interface CustomRuleSet {
  id: string;
  name: string;
  enabled: boolean;
  source: "local" | { subscriptionId: string };
}

export const MAX_CUSTOM_SETS = 64;

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
  /** Exact policy content used for this decision; absent on historical rows. */
  policyHash?: string;
  /** Fallback correlation to the online event id. JSON body only; no SQLite column. */
  relatedEventId?: string;
  overrideSource?: "rule" | "family";
  exemptionId?: string;
  dryRunKinds?: string[];
  /** Set only when per-client log-only changed this decision. */
  clientMode?: "log_only";
  wouldHave?: "block" | "confirm" | "rewrite";
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
  /** Absent on pre-26c documents. Readers treat that as one enabled local "default" set. */
  customSets?: CustomRuleSet[];
  stopped: boolean;
  previousMode?: Intervention;
  updatedAt: number;
  overrides?: import("./policy-schema.ts").PolicyOverrides;
  exemptions?: import("./policy-schema.ts").PolicyExemption[];
  clients?: import("./policy-schema.ts").ClientMode[];
}

export function defaultCustomSet(): CustomRuleSet {
  return { id: "default", name: "default", enabled: true, source: "local" };
}

/** Missing customSets is the implicit default set. An explicit empty array is no sets. */
export function resolvedCustomSets(sets: readonly CustomRuleSet[] | undefined): readonly CustomRuleSet[] {
  return sets ?? [defaultCustomSet()];
}

/** View only. Same reference when customSets is already present, so stored bytes stay untouched. */
export function migratePolicyRead<T extends { customSets?: CustomRuleSet[] }>(policy: T): T {
  if (policy.customSets !== undefined) return policy;
  return { ...policy, customSets: [defaultCustomSet()] };
}

function setNameHasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c === 127) return true;
  }
  return false;
}

function parseSetSource(raw: unknown): CustomRuleSet["source"] | undefined {
  if (raw === "local") return "local";
  if (!isPlainObject(raw)) return undefined;
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "subscriptionId") return undefined;
  const id = raw.subscriptionId;
  if (typeof id !== "string" || id.length < 1 || id.length > 128 || setNameHasControl(id)) return undefined;
  return { subscriptionId: id };
}

const CUSTOM_SET_KEYS = new Set(["id", "name", "enabled", "source"]);

/** Undefined on any bad element. Accepts a subscription source; writers reject that separately. */
export function parseCustomSets(raw: unknown): CustomRuleSet[] | undefined {
  if (!Array.isArray(raw) || raw.length > MAX_CUSTOM_SETS) return undefined;
  const out: CustomRuleSet[] = [];
  const seen = new Set<string>();
  for (const row of raw) {
    if (!isPlainObject(row)) return undefined;
    for (const key of Object.keys(row)) if (!CUSTOM_SET_KEYS.has(key)) return undefined;
    if (typeof row.id !== "string" || !RULE_ID_RE.test(row.id) || seen.has(row.id)) return undefined;
    if (typeof row.name !== "string" || row.name.length < 1 || row.name.length > 80 || setNameHasControl(row.name)) return undefined;
    if (typeof row.enabled !== "boolean") return undefined;
    const source = parseSetSource(row.source);
    if (!source) return undefined;
    seen.add(row.id);
    out.push({ id: row.id, name: row.name, enabled: row.enabled, source });
  }
  return out;
}

export function customSetsAreLocal(sets: readonly CustomRuleSet[]): boolean {
  return sets.every((set) => set.source === "local");
}

function ruleSetId(setId: string | undefined): string {
  return setId && setId.length > 0 ? setId : "default";
}

/** Unknown setId is not enabled. Missing sets are the implicit default set. */
export function customRuleSetEnabled(
  setId: string | undefined,
  sets: readonly { id: string; enabled: boolean }[] | undefined,
): boolean {
  const id = ruleSetId(setId);
  const list = sets ?? [defaultCustomSet()];
  for (const set of list) if (set.id === id) return set.enabled;
  return false;
}

/**
 * Compiled and evaluated custom rules: enabled set, and not plain-off.
 * Dry-run stays (stored enabled:false + dryRun). A dangling setId matches nothing.
 * The engine keeps a twin in src/lib/monitor/privacy.ts and cannot import this one: the
 * policy-compat guard pairs the live engine with an older core tree. custom-sets.test pins both.
 */
export function effectiveCustomRules<R extends { setId?: string; enabled?: boolean; dryRun?: boolean }>(
  rules: readonly R[],
  sets: readonly { id: string; enabled: boolean }[] | undefined,
): R[] {
  return rules.filter((rule) => customRuleSetEnabled(rule.setId, sets) && customRuleState(rule) !== "off");
}

/** A setId that names no resolved set, including "default" when that set was not stored. */
export function danglingCustomRuleSet(
  rules: readonly { setId?: string }[] | undefined,
  sets: readonly { id: string }[] | undefined,
): boolean {
  const ids = new Set((sets ?? [defaultCustomSet()]).map((set) => set.id));
  for (const rule of rules ?? []) if (!ids.has(ruleSetId(rule.setId))) return true;
  return false;
}

/** Device GET projection: enabled-set membership only. setId is stripped. Rule on/off/dry-run stays on the rule. */
export function projectDeviceCustomRules<R extends { setId?: string }>(
  rules: readonly R[],
  sets: readonly { id: string; enabled: boolean }[] | undefined,
): Array<Omit<R, "setId">> {
  return rules.filter((rule) => customRuleSetEnabled(rule.setId, sets)).map((rule) => {
    const { setId: _setId, ...rest } = rule;
    return rest;
  });
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
  /** Admin revocation time. The stored tokenHash is then an unissued replacement. */
  revokedAt?: number;
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
