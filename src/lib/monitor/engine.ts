import {storageTarget} from "./storage-target.ts";
import { RULES, RULE_BY_ID } from "./rules.ts";
import {
  applyPolicyDecision,
  composeAction,
  isGuarded,
  ruleDisabled,
  activeExemption,
} from "./overrides.ts";
import { policyExemptions, policyOverrides } from "./policy-schema.ts";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import { dryRunCustomRules, liveCustomRules } from "./privacy.ts";
import { cloakPersona, isTelemetryUrl, shouldCloakPersona } from "./cloak.ts";
import { detectSelfProtection, SELF_PROTECTION_RULE_IDS } from "./self-protection.ts";
import { detectHookConfigGuard, HOOK_GUARD_RULE } from "./hook-config-guard.ts";
import { hasSourceUpload } from "./upload-operands.ts";
import { classifyActor } from "./actor.ts";
import { normalizeTool } from "./agents.ts";
import { guessModel } from "./fingerprint.ts";
import { sealOf, type Seal } from "./intercept.ts";
import {
  CRED_KINDS,
  hasPrivacyKeyword,
  looksOutbound,
  redactAll,
  scanCustom,
  scanSecrets,
  uniqueKinds,
} from "./privacy.ts";
import { classifyRelay } from "./relay.ts";
import { classifySnapshot, classifyZcodeContext, SNAPSHOT_RULE, ZCODE_CONTEXT_RULE } from "./snapshot.ts";
import { isWatchedProcess } from "./watch.ts";
import type {
  Action,
  Actor,
  AgentId,
  AuditEvent,
  CanonicalTool,
  Category,
  CustomPrivacyRule,
  Decision,
  EventSource,
  Intervention,
  RuleDef,
  ThreatKind,
} from "./types";

export interface EvalInput {
  nativeTool: string;
  command?: string;
  filePath?: string;
  url?: string;
  cwd?: string;
  dest?: string;
  /** Write/Edit body. Inspected separately from the log summary. */
  contents?: string;
  agent?: AgentId;
  sessionModel?: string;
  sessionId?: string;
  /** Set by authenticated backend; do not take this from hook JSON. */
  deviceId?: string;
  eventId?: string;
  source?: EventSource;
  proc?: string;
  parentProc?: string;
  /** Probe saw what the hook missed. Never means allow — still evaluate. */
  hookBlind?: boolean;
}

export interface EvalResult {
  rule?: RuleDef;
  risk: AuditEvent["risk"];
  action: Action;
  decision: Decision;
  tool: CanonicalTool;
  category: Category;
  workdirScope: AuditEvent["workdirScope"];
  input: string;
  redacted: string;
  threat?: ThreatKind;
  secretKinds: string[];
  detectedModel?: string;
  actor: Actor;
  rewritten: boolean;
  skipped: boolean;
  seal: Seal;
  /** Set when session-window correlate linked this event to a prior mark. */
  correlateHit?: boolean;
  /** Observation only; does not change intervention or trusted process scope. */
  storageAccess?: boolean;
  overrideSource?: "rule" | "family";
  exemptionId?: string;
  dryRunKinds?: string[];
}

export interface EnginePolicy {
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
  now?: number;
}

interface Compiled {
  rule: RuleDef;
  re: RegExp;
}

const COMPILED: Compiled[] = RULES.map((rule) => ({
  rule,
  re: new RegExp(rule.pattern, "i"),
}));

/** Linear stand-in for curl_download_then_exec — the catalog pattern uses leading `(?=.*)` lookaheads that ReDoS on a 256 KiB line. */
const DOWNLOAD_CURL_OUT = /\b(?:curl|wget2?)\b[^\n]{0,800}(?:-o\b|-O\b|--output\b)/i;
const DOWNLOAD_SCRIPT_EXT = /\.(?:sh|py|pl|rb)\b/i;
const DOWNLOAD_THEN_RUN = /\b(?:bash|sh|zsh|python3?|chmod\s+\+x)\b|\.\//i;

function fieldMatches(rule: RuleDef, re: RegExp, fieldValue: string): boolean {
  if (rule.id === "curl_download_then_exec") {
    return DOWNLOAD_CURL_OUT.test(fieldValue) && DOWNLOAD_SCRIPT_EXT.test(fieldValue) && DOWNLOAD_THEN_RUN.test(fieldValue);
  }
  re.lastIndex = 0;
  return re.test(fieldValue);
}

function firstMatch(
  tool: CanonicalTool,
  fieldValue: string,
  field: RuleDef["field"],
  skip?: (id: string) => boolean,
) {
  for (const { rule, re } of COMPILED) {
    if (Object.values(ZCODE_CONTEXT_RULE).some((id) => id === rule.id)) continue;
    if (Object.values(HOOK_GUARD_RULE).some((id) => id === rule.id)) continue;
    if (rule.id === "source_file_upload") continue;
    if (SELF_PROTECTION_RULE_IDS.has(rule.id)) continue;
    if (skip?.(rule.id)) continue;
    if (rule.field !== field) continue;
    if (!(rule.tools.includes("*") || rule.tools.includes(tool))) continue;
    if (fieldMatches(rule, re, fieldValue)) return rule;
  }
  return undefined;
}

function joinFields(...parts: Array<string | undefined>): string {
  const out: string[] = [];
  for (const p of parts) {
    if (p && !out.includes(p)) out.push(p);
  }
  return out.join("\n");
}

type InspectSeg = { field: string; start: number; end: number };

function buildInspect(input: {
  command: string;
  filePath: string;
  url: string;
  dest: string;
  contents: string;
  nativeTool: string;
}): { inspect: string; segs: InspectSeg[] } {
  const parts: Array<{ field: string; text: string }> = [];
  const seen = new Set<string>();
  const add = (field: string, text: string) => {
    if (!text || seen.has(text)) return;
    seen.add(text);
    parts.push({ field, text });
  };
  add("command", input.command);
  add("file_path", input.filePath);
  add("url", input.url);
  add("url", input.dest);
  add("contents", input.contents);
  add("nativeTool", input.nativeTool);
  let inspect = "";
  const segs: InspectSeg[] = [];
  for (const p of parts) {
    if (inspect) inspect += "\n";
    const start = inspect.length;
    inspect += p.text;
    segs.push({ field: p.field, start, end: inspect.length });
  }
  return { inspect, segs };
}

function hitInScope(
  index: number,
  length: number,
  segs: InspectSeg[],
  fields: string[] | undefined,
): boolean {
  if (!fields?.length) return true;
  const end = index + length;
  for (const s of segs) {
    if (s.field === "nativeTool") continue;
    if (!fields.includes(s.field)) continue;
    if (index >= s.start && end <= s.end) return true;
  }
  return false;
}

function scopedCustomHits(
  inspect: string,
  segs: InspectSeg[],
  tool: CanonicalTool,
  rules: CustomPrivacyRule[],
  requireEnabled: boolean,
) {
  const hits = scanCustom(
    inspect,
    requireEnabled ? rules : rules.map((r) => ({ ...r, enabled: true })),
  );
  return hits.filter((h) => {
    const rule = rules.find((r) => r.id === h.ruleId);
    if (!rule) return false;
    if (rule.scope?.tools?.length && !rule.scope.tools.includes(tool)) return false;
    if (!hitInScope(h.index, h.length, segs, rule.scope?.fields)) return false;
    return true;
  });
}

/** Local file tools: body URLs are document text, not a network request. */
function isLocalFileTool(tool: CanonicalTool): boolean {
  return tool === "Write" || tool === "Edit" || tool === "MultiEdit" || tool === "Read" || tool === "Glob" || tool === "Grep";
}

export function workdirScope(path: string | undefined, cwd: string | undefined): AuditEvent["workdirScope"] {
  if (!path) return "project";
  const p = path.replace(/^~/, "/home/max");
  if (cwd && (p.startsWith(cwd) || p.startsWith("./") || !p.startsWith("/"))) return "project";
  if (p.startsWith("/etc") || p.startsWith("/usr") || p.startsWith("/var") || p.startsWith("/opt"))
    return "system";
  if (p.startsWith("/home") || p.startsWith("/Users")) return "home";
  if (p.startsWith("/")) return "other";
  return "project";
}

const INSTALL_PIP_RULES = new Set(["sudo_pip_install", "pip_install_no_venv", "uv_project_install"]);

export function categorize(tool: CanonicalTool, input: string, rule?: RuleDef): Category {
  if (rule?.family === "exfil") return "exfil";
  if (rule) {
    if (rule.id.includes("npm") || rule.id.includes("js_package")) return "install_npm";
    if (INSTALL_PIP_RULES.has(rule.id)) return "install_pip";
    if (rule.id.includes("system_package")) return "install_sys";
    if (rule.id.includes("git")) return "git";
    if (rule.id.includes("ssh")) return "ssh";
    if (rule.id.includes("download") || rule.id.includes("curl")) return "download";
    if (rule.id.includes("docker")) return "docker";
    if (rule.id.includes("archive") || rule.id.includes("pack_")) return "archive";
    if (rule.id.includes("process") || rule.id.includes("kill")) return "process";
    if (rule.id.includes("sensitive") || rule.id.includes("env") || rule.id.includes("credential") || rule.family === "secret")
      return "sensitive";
    if (rule.id.includes("screenshot") || rule.id.includes("screen_capture")) return "screenshot";
    if (rule.id.includes("mcp")) return "mcp";
  }
  if (tool === "Read") {
    if (/\.(png|jpe?g|webp|gif)$/i.test(input)) return "screenshot";
    return "file_read";
  }
  if (tool === "Write") return "file_write";
  if (tool === "Edit" || tool === "MultiEdit") return "file_edit";
  if (tool === "Task") return "subagent";
  if (tool === "Skill") return "skill";
  if (tool === "MCP") return "mcp";
  if (tool === "WebFetch" || tool === "WebSearch") return "network";
  if (tool === "Grep" || tool === "Glob") return "search";
  if (/\b(Set-Content|Add-Content|Out-File)\b/i.test(input)) return "file_write";
  if (/\b(pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+pip\s+install)\b/i.test(input)) return "install_pip";
  if (/\brm\s+/.test(input)) return "file_delete";
  return tool === "Bash" ? "shell" : "other";
}

const CUT: ThreatKind[] = ["exfil", "tamper", "isolate", "poison"];

/**
 * Quiet policy. Never confirm, never popup.
 *   cut families (exfil / tamper / isolate / poison) → block
 *   secret leaving the box → block
 *   PII rewrite → rewrite
 *   remaining high → block
 *   medium / low → log
 */
export function applyIntervention(
  action: Action,
  intervention: Intervention,
  family?: ThreatKind,
  risk: AuditEvent["risk"] = "info",
): Decision {
  if (intervention === "off") return "allow";
  if (intervention === "permissive") return "log";
  if (action === "rewrite") return "rewrite";
  if (family && CUT.includes(family)) return "block";
  if (family === "secret" && action === "block") return "block";
  if (risk === "high") return "block";
  return "log";
}

function privacyRule(kind: string, action: Action): RuleDef {
  return {
    id: `privacy:${kind}`,
    risk: "high",
    action,
    family: "secret",
    title: `隐私词 · ${kind}`,
    titleEn: `Privacy · ${kind}`,
    desc: "自定义隐私规则命中，外连已拦或已替换。",
    descEn: "Custom privacy rule hit; outbound blocked or rewritten.",
    tools: ["*"],
    field: "command",
    pattern: "",
  };
}

const EMPTY: EvalResult = {
  risk: "info",
  action: "log",
  decision: "allow",
  tool: "Bash",
  category: "other",
  workdirScope: "project",
  input: "",
  redacted: "",
  secretKinds: [],
  actor: "process",
  rewritten: false,
  skipped: true,
  seal: "opaque",
};

export function evaluate(
  input: EvalInput,
  intervention: Intervention,
  customRules: CustomPrivacyRule[] = [],
  policy: EnginePolicy = {},
): EvalResult {
  if (!isWatchedProcess({ proc: input.proc, parentProc: input.parentProc, source: input.source, agent: input.agent })) {
    return {
      ...EMPTY,
      tool: normalizeTool(input.nativeTool),
      input: input.command || input.filePath || input.nativeTool,
      redacted: input.command || input.filePath || input.nativeTool,
    };
  }

  const tool = normalizeTool(input.nativeTool);
  const command = input.command ?? "";
  const filePath = input.filePath ?? "";
  const url = input.url ?? "";
  const dest = input.dest ?? "";
  const contents = input.contents ?? "";
  const overrides = policyOverrides(policy.overrides);
  const exemptions = policyExemptions(policy.exemptions);
  const now = policy.now ?? Date.now();
  const skipDisabled = (id: string) =>
    intervention === "enforcing" && ruleDisabled(id, overrides, RULE_BY_ID);
  const built = buildInspect({ command, filePath, url, dest, contents, nativeTool: input.nativeTool });
  const inspect = built.inspect;
  const commandish = joinFields(command, contents);
  const hits = scanSecrets(inspect);
  const liveRules = liveCustomRules(customRules);
  const dryRules = dryRunCustomRules(customRules);
  let customHits = scopedCustomHits(inspect, built.segs, tool, liveRules, true);
  let dryHits = scopedCustomHits(inspect, built.segs, tool, dryRules, false);
  let exemptionId: string | undefined;
  const suppressedCustomHits: typeof customHits = [];
  customHits = customHits.filter((h) => {
    const ex = activeExemption(h.ruleId, inspect, tool, exemptions, now);
    if (!ex) return true;
    suppressedCustomHits.push(h);
    exemptionId = exemptionId ?? ex.id;
    return false;
  });
  dryHits = dryHits.filter((h) => {
    const ex = activeExemption(h.ruleId, inspect, tool, exemptions, now);
    if (!ex) return true;
    suppressedCustomHits.push(h);
    exemptionId = exemptionId ?? ex.id;
    return false;
  });
  let redacted = redactAll(inspect, hits, [...customHits, ...suppressedCustomHits, ...dryHits]);

  const networkText = isLocalFileTool(tool) ? joinFields(url, dest) : joinFields(url, dest, command);

  let rule =
    (commandish ? firstMatch(tool, commandish, "command", skipDisabled) : undefined) ??
    (filePath ? firstMatch(tool, filePath, "file_path", skipDisabled) : undefined) ??
    (networkText ? firstMatch(tool, networkText, "url", skipDisabled) : undefined) ??
    firstMatch(tool, input.nativeTool, "tool_name", skipDisabled);

  let family = rule?.family;
  let action: Action = rule?.action ?? "log";
  let risk = rule?.risk ?? "info";

  const selfHit = detectSelfProtection({
    tool,
    nativeTool: input.nativeTool,
    command,
    filePath,
    cwd: input.cwd,
  });
  if (selfHit) {
    rule = RULES.find((r) => r.id === selfHit.ruleId) ?? rule;
    action = "block";
    risk = "high";
    family = selfHit.family;
  }

  const snapId = classifySnapshot({
    agent: input.agent,
    nativeTool: input.nativeTool,
    command,
    filePath,
    url,
    dest,
    source: input.source,
  });
  const hookGuard = detectHookConfigGuard({ tool, nativeTool: input.nativeTool, command, filePath, cwd: input.cwd, contents });
  if (tool === "Bash" && hasSourceUpload(command) && !isGuarded(action, family)) {
    rule = RULE_BY_ID.source_file_upload;
    action = "block";
    risk = "high";
    family = "exfil";
  }
  if (hookGuard) {
    rule = RULES.find((r) => r.id === hookGuard);
    action = "block";
    risk = "high";
    family = rule?.family;
  }
  if (snapId) {
    rule = RULES.find((r) => r.id === snapId) ?? rule;
    action = "block";
    risk = "high";
    family = "exfil";
  } else if (Object.values(SNAPSHOT_RULE).some((id) => id === rule?.id)) {
    rule = undefined;
    action = "log";
    risk = "info";
    family = undefined;
  }

  // 反馈默认阻断独立于普通命令的记账设置；上下文项不能遮住受保护的外传/投毒规则。
  const contextId = classifyZcodeContext({ ...input, command, filePath, url, dest });
  const feedbackGate = contextId === ZCODE_CONTEXT_RULE.feedback && !isGuarded(action, family);
  if (feedbackGate || !rule || (rule.action === "log" && !rule.family && rule.risk !== "high" && !overrides.rules[rule.id])) {
    if (contextId && !skipDisabled(contextId)) {
      rule = RULES.find((r) => r.id === contextId);
      action = rule?.action ?? "log";
      risk = rule?.risk ?? "info";
      family = rule?.family;
    }
  }

  const storageAccess=Boolean(storageTarget({tool,command,url,dest}));
  const relayKind = classifyRelay({ dest, url, command });
  if ((rule?.id === "relay_poison" || rule?.id === "poison_instruction_file") && relayKind !== "poison") {
    if (!(rule.id === "poison_instruction_file" && (tool === "Write" || tool === "Edit"))) {
      rule = undefined;
      action = "log";
      risk = "info";
      family = undefined;
    }
  }
  if (relayKind === "poison") {
    rule = RULES.find((r) => r.id === "poison_relay_payload") ?? RULES.find((r) => r.id === "relay_poison") ?? rule;
    action = "block";
    risk = "high";
    family = "poison";
  }

  if ((isTelemetryUrl(networkText) || isTelemetryUrl(dest)) && !skipDisabled("telemetry_drop")) {
    rule = RULES.find((r) => r.id === "telemetry_drop") ?? rule;
    action = "block";
    risk = "high";
    family = "recon";
  }

  const persona = shouldCloakPersona({ agent: input.agent, tool, command, url, dest });
  if (rule?.id === "persona_cloak" && !persona) {
    rule = undefined;
    action = "log";
    risk = "info";
    family = undefined;
  }

  const outbound =
    Boolean(url) ||
    Boolean(dest) ||
    Boolean(snapId) ||
    tool === "WebFetch" ||
    tool === "WebSearch" ||
    (!isLocalFileTool(tool) && looksOutbound(command));
  const credHits = hits.filter((h) => CRED_KINDS.has(h.kind));
  const keywordLeak = hasPrivacyKeyword(inspect) && outbound;
  const secretLeak = credHits.length > 0 && outbound;
  const customBlock = customHits.some((h) => h.mode === "block") && outbound;
  const customReplace = customHits.some((h) => h.mode === "replace") && outbound;
  const piiOutbound = hits.some((h) => !CRED_KINDS.has(h.kind)) && outbound;

  let rewritten = false;

  if (secretLeak) {
    action = "block";
    risk = "high";
    family = "secret";
    if (!rule || (rule.family !== "secret" && rule.family !== "exfil")) {
      rule = RULES.find((r) => r.id === "env_piped_outbound") ?? rule;
    }
  } else if (customBlock && !snapId) {
    action = "block";
    risk = "high";
    family = "secret";
    const hit = customHits.find((h) => h.mode === "block")!;
    if (!rule || rule.action === "log" || rule.risk === "info" || rule.risk === "low") {
      rule = privacyRule(hit.kind, "block");
    }
  } else if ((piiOutbound || keywordLeak || customReplace) && !snapId && action !== "block") {
    action = "rewrite";
    risk = "high";
    family = family ?? "secret";
    rewritten = redacted !== inspect;
    const hit = customHits.find((h) => h.mode === "replace");
    if (!rule || rule.action === "log" || rule.risk === "info" || rule.risk === "low") {
      rule = privacyRule(hit?.kind ?? "pii", "rewrite");
    }
  }

  if (persona && action !== "block" && !skipDisabled("persona_cloak")) {
    const cloakCompose =
      intervention === "enforcing"
        ? composeAction({ ruleId: "persona_cloak", family: "recon", action: "rewrite" }, overrides)
        : { action: "rewrite" as const };
    if (cloakCompose.action !== "off") {
      if (cloakCompose.action === "rewrite") {
        const cloakedFull = cloakPersona(inspect);
        if (cloakedFull.changed) {
          const view = cloakPersona(redacted);
          if (view.changed) redacted = view.text;
          rewritten = true;
        }
      }
      if (rewritten || cloakCompose.action !== "rewrite" || rule?.id === "persona_cloak") {
        action = "rewrite";
        risk = "high";
        family = family ?? "recon";
        if (!rule || rule.action === "log") rule = RULES.find((r) => r.id === "persona_cloak") ?? rule;
      }
    }
  }

  if (hits.length && action !== "block" && action !== "rewrite" && (!rule || (rule.action === "log" && risk === "info"))) {
    action = "log";
    risk = "medium";
    if (outbound) family = family ?? "secret";
  }

  // Audit `redacted` may be truncated. That is not a structured tool rewrite.
  if (action !== "rewrite") rewritten = false;

  const kinds = [...uniqueKinds(hits), ...[...new Set(customHits.map((h) => h.kind))]];
  const dryRunKinds = dryHits.length ? [...new Set(dryHits.map((h) => h.kind))] : undefined;

  const guess = input.agent
    ? guessModel({
        agent: input.agent,
        nativeTool: input.nativeTool,
        command,
        dest: dest || url,
        sessionModel: input.sessionModel,
        proc: input.proc,
        parentProc: input.parentProc,
      })
    : undefined;

  // hookBlind labels actor=process; it must never short-circuit to allow.
  const actor = classifyActor({
    source: input.source,
    nativeTool: input.nativeTool,
    command,
    dest,
    url,
    agent: input.agent,
    hookBlind: input.hookBlind === true || (input.source === "probe" && input.nativeTool === "snapshot"),
  });

  let overrideSource: "rule" | "family" | undefined;
  let overridden = false;
  if (intervention === "enforcing") {
    const guarded = isGuarded(action, family);
    if (rule && !guarded) {
      const ex = activeExemption(rule.id, inspect, tool, exemptions, now);
      if (ex) {
        exemptionId = ex.id;
        action = "log";
        rewritten = false;
        overridden = true;
      } else {
        const c = composeAction({ ruleId: rule.id, family, action }, overrides);
        if (c.action === "off") {
          rule = undefined;
          action = "log";
          risk = "info";
          family = undefined;
        } else if (c.source) {
          action = c.action;
          overrideSource = c.source;
          overridden = true;
          if (action !== "rewrite") rewritten = false;
        }
      }
    }
  }
  const decided = overridden
    ? applyPolicyDecision(action, intervention, family, risk, true)
    : applyIntervention(action, intervention, family, risk);
  const decision: Decision = decided === "confirm" ? (risk === "high" ? "block" : "log") : decided;
  return {
    rule,
    storageAccess,
    risk,
    action,
    decision,
    tool,
    category: categorize(tool, inspect, rule),
    workdirScope: workdirScope(filePath || command, input.cwd),
    input: inspect,
    redacted,
    threat: family,
    secretKinds: kinds,
    detectedModel: guess?.model,
    actor: relayKind === "relay" || relayKind === "poison" ? "relay" : actor,
    rewritten,
    skipped: false,
    seal: sealOf({ source: input.source, decision, dest, url, command }),
    overrideSource,
    exemptionId,
    dryRunKinds,
  };
}
