import type {EgressEvidence} from "./egress-evidence.ts";
import type {ProbeProtection} from "./probe-protection";
import type {DiscoverySnapshot} from "./agent-discovery";
import type {ResponseEvidence} from "./response-evidence";
export type AgentId =
  | "zcode"
  | "codex"
  | "grok"
  | "claude"
  | "antigravity"
  | "kimi"
  | "qoder"
  | "lingma"
  | "codebuddy"
  | "cursor"
  | "copilot"
  | "windsurf"
  | "gemini"
  | "aider"
  | "qwen"
  | "cline"
  | "trae";

export type Risk = "high" | "medium" | "low" | "info";

export type Action = "block" | "confirm" | "log" | "rewrite";

export type Decision = "block" | "confirm" | "allow" | "log" | "rewrite";

export type Intervention = "enforcing" | "permissive" | "off";

export type Layer = "model_response" | "app_pre" | "app_post" | "kernel_exec" | "kernel_net";

export type EventSource = "hook" | "probe" | "trusted_gateway_response";

/** Who actually did it — never the human at the keyboard. */
export type Actor = "model" | "process" | "relay";

export type MachineStatus = "online" | "dark" | "archived";

export type SessionStatus = "running" | "idle" | "ended";

export interface DeviceCapability {
  supported: boolean;
  active: boolean;
  lastSuccess?: number;
  error?: string;
}

export interface Machine {
  discovery?: DiscoverySnapshot;
  probeProtection?: ProbeProtection;
  id: string;
  hostname: string;
  ip: string;
  user: string;
  os: "linux" | "darwin" | "win32";
  lastSeen: number;
  attachedAt: number;
  status: MachineStatus;
  /** Agent ids reported by the device. Absent means not collected. */
  agents?: AgentId[];
  /** Probe-reported caps for this device only. Missing id means not collected. */
  capabilities?: Record<string, DeviceCapability>;
  snapshotGuard?: SnapshotGuardState;
  network?: NetworkSampleReport;
}

export type ArchiveCoverage = "none" | "protected" | "partial" | "unknown";

export interface SnapshotGuard {
  supported: boolean;
  active: boolean;
  managed: boolean;
  targetPresent: boolean;
  writeBlocked: boolean;
  existingArchiveCoverage: ArchiveCoverage;
  error?: string;
  lastVerified: number;
}

export type SnapshotGuardState =
  | { status: "missing" }
  | { status: "invalid" }
  | { status: "ok"; guard: SnapshotGuard };

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export type ThreatKind = "exfil" | "secret" | "tamper" | "destructive" | "recon" | "isolate" | "poison";

export type Category =
  | "file_read"
  | "file_write"
  | "file_edit"
  | "file_delete"
  | "shell"
  | "network"
  | "mcp"
  | "install_pip"
  | "install_sys"
  | "install_npm"
  | "install_other"
  | "git"
  | "ssh"
  | "download"
  | "docker"
  | "archive"
  | "process"
  | "sensitive"
  | "screenshot"
  | "subagent"
  | "skill"
  | "search"
  | "exfil"
  | "other";

export type CanonicalTool =
  | "Bash"
  | "Read"
  | "Write"
  | "Edit"
  | "MultiEdit"
  | "Glob"
  | "Grep"
  | "WebFetch"
  | "WebSearch"
  | "Task"
  | "Skill"
  | "MCP";

/** Display-only: unmapped native tool. Never coerced to Bash. */
export type ObservedTool = CanonicalTool | "unknown" | "ModelResponse";

export interface AgentDef {
  id: AgentId;
  name: string;
  vendor: string;
  process: string;
  hookPath: string;
  projectHookPath: string;
  models: string[];
  transcriptHint: string;
  letter: string;
}

export interface Session {
  id: string;
  machineId: string;
  shortId: string;
  agent: AgentId;
  cwd: string;
  folder: string;
  model: string;
  pid: number;
  user: string;
  startedAt: number;
  lastAt: number;
  status: SessionStatus;
  gitBranch: string;
  tokensIn: number;
  tokensOut: number;
  cacheRead: number;
  contextPct: number;
  compaction: number;
  prompt: string;
  detectedModel: string;
  modelSource: "session" | "host" | "tool" | "payload";
}

export interface AuditEvent {
  egress?: EgressEvidence;
  response?: ResponseEvidence;
  id: string;
  ts: number;
  machineId: string;
  agent: AgentId;
  sessionId: string;
  layer: Layer;
  tool: ObservedTool;
  nativeTool: string;
  input: string;
  risk: Risk;
  decision: Decision;
  ruleId?: string;
  category: Category;
  workdirScope: "project" | "home" | "system" | "other";
  bytes?: number;
  dest?: string;
  /** Missing = 未采集. Empty = collected, no declared HTTP(S) target. */
  endpoints?: EndpointEvidence[];
  redacted: string;
  threat?: ThreatKind;
  secretKinds?: string[];
  detectedModel?: string;
  source?: EventSource;
  hookBlind?: boolean;
  /** True when session correlate stitched this row to a prior mark. */
  correlateHit?: boolean;
  actor?: Actor;
  proc?: string;
  rewritten?: boolean;
  /** Live CT receipts. Absent when the host never confirmed. */
  enforcement?: "blocked" | "returned_deny" | "pending_verify" | "timeout" | "failed" | "delivered" | "offline" | "degraded";
  requestHash?: string;
  policyVersion?: number;
  overrideSource?: "rule" | "family";
  exemptionId?: string;
  dryRunKinds?: string[];
}

export type EndpointSource = "tool_url" | "tool_command";

export interface EndpointEvidence {
  host: string;
  port?: number;
  scheme?: "http" | "https";
  source: EndpointSource;
  observation: "declared";
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

export interface NetworkConnection {
  remoteIp: string;
  remotePort: number;
  localIp: string;
  localPort: number;
  state: string;
  role: "egress" | "local";
  direction?: "unknown" | "attempted";
  observedAt: number;
  pid: number;
  ppid: number;
  processStartedAt: number;
  bin: string;
  agent: string;
}

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
  direction?: "unknown" | "attempted";
  firstSeen: number;
  lastSeen: number;
}

export interface Approval {
  id: string;
  eventId: string;
  sessionId: string;
  agent: AgentId;
  tool: ObservedTool;
  input: string;
  ruleId: string;
  risk: Risk;
  status: ApprovalStatus;
  requestedAt: number;
  resolvedAt?: number;
  resolveSource?: "web" | "auto";
}

export interface TranscriptTurn {
  id: string;
  ts: number;
  role: "user" | "assistant" | "thinking" | "tool" | "result";
  text: string;
  tool?: CanonicalTool;
  nativeTool?: string;
  tokens?: number;
}

export interface NetworkHop {
  id: string;
  ts: number;
  machineId: string;
  agent: AgentId;
  sessionId: string;
  pid: number;
  hostname: string;
  ip: string;
  port: number;
  city: string;
  country: string;
  lat: number;
  lng: number;
  bytes: number;
  inferred: boolean;
}

export interface RuleDef {
  id: string;
  risk: Risk;
  action: Action;
  title: string;
  titleEn: string;
  desc: string;
  descEn: string;
  tools: Array<CanonicalTool | "*">;
  field: "command" | "file_path" | "url" | "tool_name";
  pattern: string;
  family?: ThreatKind;
}

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

export type { PolicyOverrides, PolicyExemption, CustomRuleScope } from "./policy-schema.ts";

export interface QuotaBlock {
  agent: AgentId;
  plan: string;
  org: string;
  sessionUsedPct: number;
  weeklyUsedPct: number;
  weeklyModelPct: number;
  sessionResetIn: string;
  weeklyResetIn: string;
  extraCredits: boolean;
}

export interface ProbeIdentity {
  agent: AgentId;
  machineId: string;
  pid?: number;
  user: string;
  cwd: string;
  proc: string;
  matchesUiUser?: boolean;
}
