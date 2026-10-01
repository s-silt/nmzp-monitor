import type { Action, CanonicalTool, Decision, Intervention, Risk, RuleDef, ThreatKind } from "./types.ts";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import { exemptionSubjects } from "./exemption-scope.ts";
import { compileMatch } from "./privacy.ts";
import { RULES, RULE_BY_ID } from "./rules.ts";

/** Subjects already limited to the text a rule matched. null means an ambiguous shell command. */
export interface ExemptionScopeInput {
  subjects: string[] | null;
}

export const PROTECTED_FAMILIES: ReadonlySet<ThreatKind> = new Set(["exfil", "tamper", "isolate", "poison", "secret"]);
const CUT: ThreatKind[] = ["exfil", "tamper", "isolate", "poison"];

/** First-create seed: persist / privilege / credential-theft rules that should stop a silent agent. */
export const SUGGESTED_OVERRIDES: PolicyOverrides = {
  rules: {
    ssh_authorized_keys_bash_write: "block",
    disable_security_controls: "block",
    user_account_management: "block",
    c2_framework_execution: "block",
    browser_credential_read: "block",
    fork_bomb: "block",
    chmod_world_writable_recursive: "block",
    setuid_setgid_bit: "block",
  },
  families: {},
};

export function isGuarded(action: Action, family: ThreatKind | undefined): boolean {
  return action === "block" && !!family && PROTECTED_FAMILIES.has(family);
}

/**
 * Builtin ids that ignore every rule and family override. Frozen; not loaded
 * from policy or a subscription. The other protected builtins are adjustable.
 */
export const LOCKED_RULE_IDS: readonly string[] = Object.freeze([
  "isolate_cut_board",
  "isolate_delete_binary",
  "isolate_kill_monitor",
  "isolate_stop_container",
  "agent_hook_disable",
  "kill_monitor_process",
  "monitor_self_tamper",
  "monitor_self_tamper_cmd",
  "zcode_trust_store_tamper",
  "agent_hook_poison",
  "credential_file_upload",
  "env_piped_outbound",
]);

const LOCKED_RULE_ID_SET: ReadonlySet<string> = new Set(LOCKED_RULE_IDS);

export type ProtectionLevel = "locked" | "adjustable" | "none";

export function protectionLevel(rule: Pick<RuleDef, "id" | "action" | "family">): ProtectionLevel {
  if (LOCKED_RULE_ID_SET.has(rule.id)) return "locked";
  if (isProtectedRule(rule)) return "adjustable";
  return "none";
}

export function isProtectedRule(rule: Pick<RuleDef, "action" | "family">): boolean {
  return rule.action === "block" && !!rule.family && PROTECTED_FAMILIES.has(rule.family);
}

export function protectedRuleIds(rules: readonly RuleDef[]): string[] {
  return rules.filter((r) => isProtectedRule(r)).map((r) => r.id);
}

function familyOverrideValue(overrides: PolicyOverrides, family: ThreatKind | undefined): "block" | "log" | "off" | undefined {
  if (!family) return undefined;
  const value = (overrides.families as Partial<Record<string, string>>)[family];
  if (value === "block" || value === "log" || value === "off") return value;
  return undefined;
}

export function composeAction(
  base: { ruleId?: string; family?: ThreatKind; action: Action },
  overrides: PolicyOverrides,
): { action: Action | "off"; source?: "rule" | "family" } {
  const { action } = base;
  const catalog = base.ruleId ? RULE_BY_ID[base.ruleId] : undefined;
  // Level comes from the catalog id. A guarded action with no catalog rule
  // (privacy block, synthetic elevation) still ignores overrides via isGuarded.
  const level: ProtectionLevel = catalog ? protectionLevel(catalog) : "none";
  if (level === "locked") return { action };
  if (level !== "adjustable" && isGuarded(action, base.family)) return { action };

  let ruleOvr = base.ruleId ? overrides.rules[base.ruleId] : undefined;
  let famOvr = familyOverrideValue(overrides, base.family);
  if (level === "adjustable") {
    // Rule override accepts only block/log. Family off does not apply.
    // The schema still rejects family off at parse time; ignore it if present.
    if (ruleOvr === "off") ruleOvr = undefined;
    if (famOvr === "off") famOvr = undefined;
  }
  if (ruleOvr !== undefined) {
    if (ruleOvr === action && (famOvr === undefined || famOvr === action)) return { action };
    return { action: ruleOvr, source: "rule" };
  }
  if (famOvr !== undefined) {
    if (famOvr === action) return { action };
    return { action: famOvr, source: "family" };
  }
  return { action };
}

export function applyPolicyDecision(
  action: Action,
  intervention: Intervention,
  family: ThreatKind | undefined,
  risk: Risk,
  overridden: boolean,
): Decision {
  if (intervention === "off") return "allow";
  if (intervention === "permissive") return "log";
  if (overridden) {
    if (action === "block") return "block";
    if (action === "rewrite") return "rewrite";
    return "log";
  }
  if (action === "rewrite") return "rewrite";
  if (family && CUT.includes(family)) return "block";
  if (family === "secret" && action === "block") return "block";
  if (risk === "high") return "block";
  return "log";
}

export function ruleDisabled(
  ruleId: string,
  overrides: PolicyOverrides,
  rules: Record<string, RuleDef>,
): boolean {
  const rule = rules[ruleId];
  if (!rule || isProtectedRule(rule)) return false;
  return overrides.rules[ruleId] === "off";
}

export function protectedDowngrades(overrides: PolicyOverrides, rules: readonly RuleDef[]): string[] {
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));
  const out: string[] = [];
  for (const [id, v] of Object.entries(overrides.rules)) {
    const rule = byId[id];
    if (!rule) continue;
    const level = protectionLevel(rule);
    // Locked: log and off are disallowed. block is the same action, not a downgrade.
    // Adjustable: only off is disallowed. log is accepted.
    if (level === "locked" && v !== "block") out.push(id);
    else if (level === "adjustable" && v === "off") out.push(id);
  }
  // Family log/off writes are accepted and are not reported. Such a write would
  // be a disallowed downgrade only if it changed a locked rule's action. Locked
  // rules ignore family overrides, so the action does not change. Adjustable
  // rules may follow family log and ignore family off. Family off is not a
  // schema value; parse rejects it before this check.
  return out.sort();
}

function assertProtectionPartition(rules: readonly RuleDef[]): void {
  const protectedIds = protectedRuleIds(rules);
  const protectedSet = new Set(protectedIds);
  const missing = LOCKED_RULE_IDS.filter((id) => !protectedSet.has(id));
  const adjustable = protectedIds.filter((id) => !LOCKED_RULE_ID_SET.has(id));
  if (
    new Set(LOCKED_RULE_IDS).size !== LOCKED_RULE_IDS.length
    || missing.length > 0
    || LOCKED_RULE_IDS.length !== 12
    || adjustable.length !== 17
    || protectedIds.length !== LOCKED_RULE_IDS.length + adjustable.length
  ) {
    throw new Error(
      `protection partition drifted: protected=${protectedIds.length} locked=${LOCKED_RULE_IDS.length} adjustable=${adjustable.length} missing=${missing.join(",")}`,
    );
  }
}

assertProtectionPartition(RULES);

export function unknownRuleIds(overrides: PolicyOverrides, rules: readonly RuleDef[]): string[] {
  const known = new Set(rules.map((r) => r.id));
  return Object.keys(overrides.rules)
    .filter((id) => !known.has(id))
    .sort();
}

export function activeExemption(
  ruleId: string | undefined,
  inspect: string,
  tool: CanonicalTool,
  exemptions: PolicyExemption[],
  now: number,
  scope?: ExemptionScopeInput,
): PolicyExemption | undefined {
  if (!ruleId || exemptions.length === 0) return undefined;
  const builtin = RULE_BY_ID[ruleId];
  if (builtin && isProtectedRule(builtin)) return undefined;
  // Callers that only have a redacted summary (policy replay) still shell-scope that string.
  const subjects = scope !== undefined ? scope.subjects : exemptionSubjects(inspect, ruleId);
  if (!subjects?.length) return undefined;
  // Triggering operands only. Testing `inspect` here would borrow another segment.
  const haystack = subjects;
  for (const ex of exemptions) {
    if (ex.ruleId !== ruleId) continue;
    if (ex.expiresAt !== undefined && ex.expiresAt <= now) continue;
    if (ex.tools && ex.tools.length && !ex.tools.includes(tool)) continue;
    const re = compileMatch(ex.match);
    if (!re) continue;
    const matched = haystack.every((subject) => {
      re.lastIndex = 0;
      return re.test(subject);
    });
    if (matched) return ex;
  }
  return undefined;
}
