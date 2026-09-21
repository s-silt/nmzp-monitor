import { applyPolicyDecision, composeAction, PROTECTED_FAMILIES, activeExemption } from "./overrides.ts";
import { policyExemptions, policyOverrides } from "./policy-schema.ts";
import { compileMatch } from "./privacy.ts";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import type {
  Action,
  AuditEvent,
  CanonicalTool,
  CustomPrivacyRule,
  Decision,
  Intervention,
  RuleDef,
  ThreatKind,
} from "./types.ts";

export interface PolicyView {
  mode: Intervention;
  overrides: PolicyOverrides;
  customRules: CustomPrivacyRule[];
  exemptions: PolicyExemption[];
}

export interface ReplayRow {
  eventId: string;
  ruleId?: string;
  before: Decision;
  after: Decision;
  source: "rule" | "family" | "exemption" | "custom";
  approximate: boolean;
}

export interface ReplayResult {
  rows: ReplayRow[];
  summary: {
    block: number;
    log: number;
    exempt: number;
    customHits: number;
    approximate: number;
    unchanged: number;
  };
}

export function replayPolicy(
  events: AuditEvent[],
  next: PolicyView,
  current: PolicyView,
  rules: RuleDef[],
  now: number,
): ReplayResult {
  const byId = Object.fromEntries(rules.map((r) => [r.id, r]));
  const overrides = policyOverrides(next.overrides);
  const exemptions = policyExemptions(next.exemptions);
  const currentMatch = new Set((current.customRules ?? []).map((r) => r.match.toLowerCase()));
  const added = (next.customRules ?? []).filter((r) => !currentMatch.has(r.match.toLowerCase()));
  const rows: ReplayRow[] = [];
  const summary = { block: 0, log: 0, exempt: 0, customHits: 0, approximate: 0, unchanged: 0 };

  for (const e of events) {
    if (e.decision === "block" && e.threat && PROTECTED_FAMILIES.has(e.threat)) continue;

    let after: Decision = e.decision;
    let source: ReplayRow["source"] | undefined;
    let approximate = false;
    const rule = e.ruleId ? byId[e.ruleId] : undefined;

    if (rule) {
      const family = (e.threat ?? rule.family) as ThreatKind | undefined;
      const composed = composeAction({ ruleId: rule.id, family, action: rule.action }, overrides);
      if (composed.action === "off") approximate = true;
      const act: Action = composed.action === "off" ? "log" : composed.action;
      after = applyPolicyDecision(act, next.mode, family, rule.risk, Boolean(composed.source) || composed.action === "off");
      if (composed.source) source = composed.source;
    }

    const tool = (typeof e.tool === "string" ? e.tool : "Bash") as CanonicalTool;
    if (e.ruleId) {
      const ex = activeExemption(e.ruleId, e.redacted, tool, exemptions, now);
      if (ex) {
        after = applyPolicyDecision("log", next.mode, rule?.family, rule?.risk ?? e.risk, true);
        source = "exemption";
        approximate = true;
      }
    }

    for (const cr of added) {
      const re = compileMatch(cr.match);
      if (!re) continue;
      re.lastIndex = 0;
      if (!re.test(e.redacted)) continue;
      const act: Action = cr.mode === "block" ? "block" : "rewrite";
      after = applyPolicyDecision(act, next.mode, undefined, "high", true);
      source = "custom";
      approximate = true;
    }

    if (after === e.decision || !source) continue;
    const row: ReplayRow = {
      eventId: e.id,
      ruleId: e.ruleId,
      before: e.decision,
      after,
      source,
      approximate,
    };
    rows.push(row);
    if (after === "block") summary.block += 1;
    else if (after === "log") summary.log += 1;
    if (source === "exemption") summary.exempt += 1;
    if (source === "custom") summary.customHits += 1;
    if (approximate) summary.approximate += 1;
  }

  summary.unchanged = events.length - rows.length;
  return { rows, summary };
}
