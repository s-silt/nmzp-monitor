import type { Action, CanonicalTool, Decision, Intervention, Risk, RuleDef, ThreatKind } from "./types.ts";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import { compileMatch } from "./privacy.ts";

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

export function isProtectedRule(rule: Pick<RuleDef, "action" | "family">): boolean {
  return rule.action === "block" && !!rule.family && PROTECTED_FAMILIES.has(rule.family);
}

export function protectedRuleIds(rules: RuleDef[]): string[] {
  return rules.filter((r) => isProtectedRule(r)).map((r) => r.id);
}

export function composeAction(
  base: { ruleId?: string; family?: ThreatKind; action: Action },
  overrides: PolicyOverrides,
): { action: Action | "off"; source?: "rule" | "family" } {
  const { action } = base;
  if (isGuarded(action, base.family)) return { action };
  const ruleOvr = base.ruleId ? overrides.rules[base.ruleId] : undefined;
  const famOvr = base.family ? overrides.families[base.family] : undefined;
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

export function protectedDowngrades(overrides: PolicyOverrides, rules: RuleDef[]): string[] {
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));
  const out: string[] = [];
  for (const [id, v] of Object.entries(overrides.rules)) {
    if (v !== "log" && v !== "off") continue;
    const rule = byId[id];
    if (rule && isProtectedRule(rule)) out.push(id);
  }
  for (const [f, v] of Object.entries(overrides.families)) {
    if (v === "log" && PROTECTED_FAMILIES.has(f as ThreatKind)) out.push(`family:${f}`);
  }
  return out.sort();
}

export function unknownRuleIds(overrides: PolicyOverrides, rules: RuleDef[]): string[] {
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
): PolicyExemption | undefined {
  if (!ruleId) return undefined;
  for (const ex of exemptions) {
    if (ex.ruleId !== ruleId) continue;
    if (ex.expiresAt !== undefined && ex.expiresAt <= now) continue;
    if (ex.tools && ex.tools.length && !ex.tools.includes(tool)) continue;
    const re = compileMatch(ex.match);
    if (!re) continue;
    re.lastIndex = 0;
    if (re.test(inspect)) return ex;
  }
  return undefined;
}
