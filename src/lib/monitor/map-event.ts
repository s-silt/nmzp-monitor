import {parseEgressEvidence} from "./egress-evidence.ts";
import {parseResponseEvidence} from "./response-evidence.ts";
import { isAgentId } from "./agents.ts";
import { parseEndpointList } from "./network-evidence.ts";
import type {
  Actor,
  AuditEvent,
  CanonicalTool,
  Category,
  CustomPrivacyRule,
  Decision,
  EventSource,
  Layer,
  ObservedTool,
  Risk,
  ThreatKind,
} from "./types.ts";

export const ADMIN_HIDDEN = "<仅管理员可见>";

const CANONICAL_TOOLS: ReadonlySet<string> = new Set([
  "Bash",
  "Read",
  "Write",
  "Edit",
  "MultiEdit",
  "Glob",
  "Grep",
  "WebFetch",
  "WebSearch",
  "Task",
  "Skill",
  "MCP",
]);

/** Native names that map without guessing. Missing/unknown stays unknown — never Bash. */
const NATIVE_TOOL_MAP: Record<string, CanonicalTool> = {
  bash: "Bash",
  shell: "Bash",
  shell_command: "Bash",
  exec_command: "Bash",
  run_terminal_command: "Bash",
  read: "Read",
  read_file: "Read",
  write: "Write",
  write_file: "Write",
  edit: "Edit",
  edit_file: "Edit",
  apply_patch: "Edit",
  strreplace: "Edit",
  str_replace: "Edit",
  search_replace: "Edit",
  multiedit: "MultiEdit",
  glob: "Glob",
  grep: "Grep",
  webfetch: "WebFetch",
  websearch: "WebSearch",
  search_web: "WebSearch",
  search_x: "WebSearch",
  web_search: "WebSearch",
  task: "Task",
  agent: "Task",
  delegate: "Task",
  spawn_subagent: "Task",
  skill: "Skill",
};

const LAYERS: ReadonlySet<string> = new Set(["app_pre", "app_post", "kernel_exec", "kernel_net", "model_response"]);
const RISKS: ReadonlySet<string> = new Set(["high", "medium", "low", "info"]);
const DECISIONS: ReadonlySet<string> = new Set(["block", "confirm", "allow", "log", "rewrite"]);
const THREATS: ReadonlySet<string> = new Set(["exfil", "secret", "tamper", "destructive", "recon", "isolate", "poison"]);
const ACTORS: ReadonlySet<string> = new Set(["model", "process", "relay"]);
const ENFORCEMENTS: ReadonlySet<string> = new Set([
  "blocked",
  "returned_deny",
  "pending_verify",
  "timeout",
  "failed",
  "delivered",
  "offline",
  "degraded",
]);
const SCOPES: ReadonlySet<string> = new Set(["project", "home", "system", "other"]);
const CATEGORIES: ReadonlySet<string> = new Set([
  "file_read",
  "file_write",
  "file_edit",
  "file_delete",
  "shell",
  "network",
  "mcp",
  "install_pip",
  "install_sys",
  "install_npm",
  "install_other",
  "git",
  "ssh",
  "download",
  "docker",
  "archive",
  "process",
  "sensitive",
  "screenshot",
  "subagent",
  "skill",
  "search",
  "exfil",
  "other",
]);

export function parseObservedTool(tool: unknown, nativeTool: string): ObservedTool {
  if (tool === "ModelResponse") return "ModelResponse";
  if (typeof tool === "string" && CANONICAL_TOOLS.has(tool)) return tool as CanonicalTool;
  const key = nativeTool.trim().toLowerCase();
  if (!key) return "unknown";
  if (key.startsWith("mcp__")) return "MCP";
  return NATIVE_TOOL_MAP[key] ?? "unknown";
}

export function parseCategory(v: unknown): Category | undefined {
  if (typeof v === "string" && CATEGORIES.has(v)) return v as Category;
  return undefined;
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export function mapEvent(row: unknown): AuditEvent | null {
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  const e = row as Record<string, unknown>;
  if (typeof e.id !== "string" || !e.id) return null;
  if (typeof e.redacted !== "string") return null;
  if (typeof e.ts !== "number" || !Number.isFinite(e.ts) || e.ts <= 0) return null;
  if (typeof e.agent !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(e.agent)) return null;
  const agent=isAgentId(e.agent)?e.agent:"unknown";
  if (typeof e.layer !== "string" || !LAYERS.has(e.layer)) return null;
  if (typeof e.risk !== "string" || !RISKS.has(e.risk)) return null;
  if (typeof e.decision !== "string" || !DECISIONS.has(e.decision)) return null;

  const nativeTool = asString(e.nativeTool) || (typeof e.tool === "string" && !CANONICAL_TOOLS.has(e.tool) ? e.tool : "");
  const tool = parseObservedTool(e.tool, nativeTool);
  const input = typeof e.input === "string" ? e.input : e.redacted;
  const category = parseCategory(e.category) ?? "other";

  const workdirScope =
    typeof e.workdirScope === "string" && SCOPES.has(e.workdirScope)
      ? (e.workdirScope as AuditEvent["workdirScope"])
      : "other";

  const enforcement =
    typeof e.enforcement === "string" && ENFORCEMENTS.has(e.enforcement)
      ? (e.enforcement as AuditEvent["enforcement"])
      : undefined;

  const threat = typeof e.threat === "string" && THREATS.has(e.threat) ? (e.threat as ThreatKind) : undefined;
  const actor = typeof e.actor === "string" && ACTORS.has(e.actor) ? (e.actor as Actor) : undefined;
  const source = e.source === "probe" || e.source === "hook" || e.source === "trusted_gateway_response" || e.source === "offline_backfill" ? (e.source as EventSource) : undefined;
  const endpoints = parseEndpointList(e.endpoints);
  const requestHash =
    typeof e.requestHash === "string" && /^[a-f0-9]{64}$/i.test(e.requestHash) ? e.requestHash.toLowerCase() : undefined;
  const policyVersion =
    typeof e.policyVersion === "number" && Number.isInteger(e.policyVersion) && e.policyVersion > 0
      ? e.policyVersion
      : undefined;

  return {
    response:parseResponseEvidence(e.response),
    egress:parseEgressEvidence(e.egress),
    id: e.id,
    ts: e.ts,
    machineId: asString(e.machineId),
    agent,
    rawAgent: agent === "unknown" && e.agent !== "unknown" ? e.agent : undefined,
    sessionId: asString(e.sessionId),
    layer: e.layer as Layer,
    tool,
    nativeTool,
    input,
    risk: e.risk as Risk,
    decision: e.decision as Decision,
    ruleId: typeof e.ruleId === "string" ? e.ruleId : undefined,
    category,
    workdirScope,
    dest: typeof e.dest === "string" ? e.dest : undefined,
    endpoints,
    redacted: e.redacted,
    threat,
    secretKinds: Array.isArray(e.secretKinds) ? e.secretKinds.filter((x): x is string => typeof x === "string") : undefined,
    detectedModel: typeof e.detectedModel === "string" ? e.detectedModel : undefined,
    source,
    hookBlind: e.hookBlind === true,
    correlateHit: e.correlateHit === true,
    actor,
    proc: typeof e.proc === "string" ? e.proc : undefined,
    rewritten: e.rewritten === true,
    enforcement,
    requestHash,
    policyVersion,
    overrideSource: e.overrideSource === "rule" || e.overrideSource === "family" ? e.overrideSource : undefined,
    exemptionId: typeof e.exemptionId === "string" ? e.exemptionId : undefined,
    dryRunKinds: Array.isArray(e.dryRunKinds) ? e.dryRunKinds.filter((x): x is string => typeof x === "string") : undefined,
  };
}

export function maskCustomRules(rules: CustomPrivacyRule[], access: "viewer" | "admin"): CustomPrivacyRule[] {
  if (access !== "viewer") return rules;
  return rules.map((r) => ({
    ...r,
    match: ADMIN_HIDDEN,
    replaceWith: r.mode === "replace" ? ADMIN_HIDDEN : "",
  }));
}

/** Viewer ingest: keep count/order/id. Never compile or dedupe by masked match. */
export function parseViewerCustomRules(raw: unknown): CustomPrivacyRule[] {
  if (!Array.isArray(raw)) return [];
  const out: CustomPrivacyRule[] = [];
  for (let i = 0; i < raw.length; i++) {
    const row = raw[i];
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const r = row as Record<string, unknown>;
    const id = typeof r.id === "string" && r.id.trim() ? r.id.trim().slice(0, 40) : `v_${i}`;
    const mode = r.mode === "replace" ? "replace" : "block";
    const rowOut: CustomPrivacyRule = {
      id,
      enabled: r.enabled !== false,
      mode,
      match: ADMIN_HIDDEN,
      kind: typeof r.kind === "string" && r.kind.trim() ? r.kind.trim().slice(0, 32) : "privacy",
      replaceWith: mode === "replace" ? ADMIN_HIDDEN : "",
    };
    if (typeof r.dryRun === "boolean") rowOut.dryRun = r.dryRun;
    if (r.scope && typeof r.scope === "object" && !Array.isArray(r.scope)) rowOut.scope = r.scope as CustomPrivacyRule["scope"];
    out.push(rowOut);
  }
  return out;
}

export function canMutateState(s: {
  synced: boolean;
  disconnected: boolean;
  access: "viewer" | "admin";
  loginNeeded: boolean;
}): boolean {
  return s.synced && !s.disconnected && s.access === "admin" && !s.loginNeeded;
}

export function displayHostUser(user: string | undefined): "unknown" | string {
  if (!user || user === "unknown") return "unknown";
  return user;
}
