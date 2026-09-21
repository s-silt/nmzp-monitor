import { ADMIN_HIDDEN } from "./map-event.ts";
import {
  isProtectedRule,
  protectedDowngrades,
  protectedRuleIds,
  unknownRuleIds,
} from "./overrides.ts";
import {
  MATCH_MAX,
  MAX_CUSTOM_RULES,
  REDACT_TAG,
  compileMatch,
  draftRuleId,
  exemptionId,
} from "./privacy.ts";
import {
  MAX_EXEMPTIONS,
  MAX_RULE_OVERRIDES,
  RULE_ID_RE,
  parseCustomRuleScope,
  parsePolicyOverrides,
} from "./policy-schema.ts";
import type { CustomRuleScope, PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import type { CustomPrivacyRule, Intervention, RuleDef } from "./types.ts";

export const PROPOSAL_SCHEMA = "nmzp-policy-proposal/1";
export const CONTEXT_SCHEMA = "nmzp-policy-context/1";

const ALLOWED_KEYS = new Set([
  "schema",
  "basePolicyVersion",
  "overrides",
  "customRules",
  "exemptions",
  "remove",
  "rationale",
]);

const REMOVE_KEYS = new Set(["customRuleIds", "exemptionIds", "overrideRuleIds", "overrideFamilies"]);
const DAY = 24 * 60 * 60 * 1000;

export interface ProposalCustomRule {
  match: string;
  mode: "block" | "replace";
  kind?: string;
  scope?: CustomRuleScope;
  dryRun?: boolean;
}

export interface ProposalExemption {
  ruleId: string;
  match: string;
  tools?: string[];
  note?: string;
  expiresAt?: number;
}

export interface PolicyProposal {
  schema: typeof PROPOSAL_SCHEMA;
  basePolicyVersion?: number;
  overrides?: PolicyOverrides;
  customRules?: ProposalCustomRule[];
  exemptions?: ProposalExemption[];
  remove?: {
    customRuleIds?: string[];
    exemptionIds?: string[];
    overrideRuleIds?: string[];
    overrideFamilies?: string[];
  };
  rationale?: string;
}

export interface PolicyView {
  mode: Intervention;
  overrides: PolicyOverrides;
  customRules: CustomPrivacyRule[];
  exemptions: PolicyExemption[];
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) < 32) return true;
  return false;
}

function slugKind(match: string): string {
  if (/emp/i.test(match)) return "emp_id";
  if (/internal|内网|主机/.test(match)) return "internal_host";
  if (/合同/.test(match)) return "contract_no";
  if (/姓名|客户/.test(match)) return "name";
  const ascii = match
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 24);
  return ascii || "privacy";
}

function stringList(v: unknown): string[] | undefined {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) return undefined;
  return v as string[];
}

export function parsePolicyProposal(
  raw: unknown,
  ctx: { rules: RuleDef[] },
): { ok: true; proposal: PolicyProposal } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  if (!isPlain(raw)) return { ok: false, errors: ["bad_schema"] };
  if (raw.schema !== PROPOSAL_SCHEMA) errors.push("bad_schema");
  for (const k of Object.keys(raw)) {
    if (!ALLOWED_KEYS.has(k)) errors.push(`forbidden_field:${k}`);
  }

  const proposal: PolicyProposal = { schema: PROPOSAL_SCHEMA };
  if (typeof raw.basePolicyVersion === "number" && Number.isFinite(raw.basePolicyVersion)) {
    proposal.basePolicyVersion = raw.basePolicyVersion;
  }

  if (raw.overrides !== undefined) {
    const parsed = parsePolicyOverrides(raw.overrides);
    if (!parsed) errors.push("invalid_overrides");
    else {
      for (const id of unknownRuleIds(parsed, ctx.rules)) errors.push(`unknown_rule:${id}`);
      for (const id of protectedDowngrades(parsed, ctx.rules)) {
        if (id.startsWith("family:")) errors.push(`protected_family_override:${id.slice(7)}`);
        else errors.push(`protected_rule_override:${id}`);
      }
      proposal.overrides = parsed;
    }
  }

  if (raw.customRules !== undefined) {
    if (!Array.isArray(raw.customRules)) errors.push("invalid_custom_rule:0");
    else {
      if (raw.customRules.length > MAX_CUSTOM_RULES) errors.push("too_many_custom_rules");
      const rows: ProposalCustomRule[] = [];
      for (let i = 0; i < raw.customRules.length; i++) {
        const row = raw.customRules[i];
        if (!isPlain(row)) {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        if (typeof row.match !== "string" || !compileMatch(row.match)) {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        if (row.mode !== undefined && row.mode !== "block" && row.mode !== "replace") {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        const scoped = parseCustomRuleScope(row.scope);
        if (!scoped.ok) {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        if (row.dryRun !== undefined && row.dryRun !== true && row.dryRun !== false) {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        if (row.kind !== undefined && typeof row.kind !== "string") {
          errors.push(`invalid_custom_rule:${i}`);
          continue;
        }
        const item: ProposalCustomRule = {
          match: row.match,
          mode: row.mode === "replace" ? "replace" : "block",
          dryRun: row.dryRun === false ? false : true,
        };
        if (typeof row.kind === "string") item.kind = row.kind;
        if (scoped.scope) item.scope = scoped.scope;
        rows.push(item);
      }
      proposal.customRules = rows;
    }
  }

  if (raw.exemptions !== undefined) {
    if (!Array.isArray(raw.exemptions)) errors.push("invalid_exemption:0");
    else {
      if (raw.exemptions.length > MAX_EXEMPTIONS) errors.push("too_many_exemptions");
      const byId = Object.fromEntries(ctx.rules.map((r) => [r.id, r]));
      const rows: ProposalExemption[] = [];
      for (let i = 0; i < raw.exemptions.length; i++) {
        const row = raw.exemptions[i];
        if (!isPlain(row)) {
          errors.push(`invalid_exemption:${i}`);
          continue;
        }
        if (typeof row.ruleId !== "string" || !RULE_ID_RE.test(row.ruleId)) {
          errors.push(`invalid_exemption:${i}`);
          continue;
        }
        if (
          typeof row.match !== "string" ||
          row.match.length < 4 ||
          row.match.length > MATCH_MAX ||
          hasControl(row.match) ||
          !compileMatch(row.match)
        ) {
          errors.push(`invalid_exemption:${i}`);
          continue;
        }
        const builtin = byId[row.ruleId];
        if (builtin && isProtectedRule(builtin)) {
          errors.push(`protected_rule_exemption:${row.ruleId}`);
          continue;
        }
        if (row.tools !== undefined) {
          const scoped = parseCustomRuleScope({ tools: row.tools });
          if (!scoped.ok || !scoped.scope?.tools) {
            errors.push(`invalid_exemption:${i}`);
            continue;
          }
        }
        if (row.note !== undefined && (typeof row.note !== "string" || row.note.length > 120)) {
          errors.push(`invalid_exemption:${i}`);
          continue;
        }
        if (row.expiresAt !== undefined && !Number.isSafeInteger(row.expiresAt)) {
          errors.push(`invalid_exemption:${i}`);
          continue;
        }
        const item: ProposalExemption = { ruleId: row.ruleId, match: row.match };
        if (row.tools !== undefined) {
          const scoped = parseCustomRuleScope({ tools: row.tools });
          item.tools = scoped.ok && scoped.scope?.tools ? scoped.scope.tools : undefined;
        }
        if (typeof row.note === "string") item.note = row.note;
        if (typeof row.expiresAt === "number") item.expiresAt = row.expiresAt;
        rows.push(item);
      }
      proposal.exemptions = rows;
    }
  }

  if (raw.remove !== undefined) {
    if (!isPlain(raw.remove)) errors.push("invalid_remove");
    else {
      const remove: NonNullable<PolicyProposal["remove"]> = {};
      for (const k of Object.keys(raw.remove)) {
        const list = stringList(raw.remove[k]);
        if (!list) {
          errors.push(`invalid_remove:${k}`);
          continue;
        }
        if (!REMOVE_KEYS.has(k)) continue;
        if (k === "customRuleIds") remove.customRuleIds = list;
        else if (k === "exemptionIds") remove.exemptionIds = list;
        else if (k === "overrideRuleIds") remove.overrideRuleIds = list;
        else if (k === "overrideFamilies") remove.overrideFamilies = list;
      }
      proposal.remove = remove;
    }
  }

  if (raw.rationale !== undefined) {
    if (typeof raw.rationale !== "string" || raw.rationale.length > 2000) errors.push("rationale_too_long");
    else proposal.rationale = raw.rationale;
  }

  if (errors.length) return { ok: false, errors };
  return { ok: true, proposal };
}

export function mergeProposal(
  current: { overrides: PolicyOverrides; customRules: CustomPrivacyRule[]; exemptions: PolicyExemption[] },
  proposal: PolicyProposal,
  opts: { now: number; forceDryRun: boolean },
): { ok: true; next: { overrides: PolicyOverrides; customRules: CustomPrivacyRule[]; exemptions: PolicyExemption[] } } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const rules = { ...current.overrides.rules, ...(proposal.overrides?.rules ?? {}) };
  const families = { ...current.overrides.families, ...(proposal.overrides?.families ?? {}) };
  for (const id of proposal.remove?.overrideRuleIds ?? []) delete rules[id];
  for (const f of proposal.remove?.overrideFamilies ?? []) delete families[f as keyof typeof families];
  const overrides: PolicyOverrides = { rules, families };

  const dropCustom = new Set(proposal.remove?.customRuleIds ?? []);
  const customRules = current.customRules.filter((r) => !dropCustom.has(r.id)).map((r) => ({ ...r }));
  const seenMatch = new Set(customRules.map((r) => r.match.toLowerCase()));
  for (const p of proposal.customRules ?? []) {
    const key = p.match.toLowerCase();
    if (seenMatch.has(key)) continue;
    seenMatch.add(key);
    const dryRun = opts.forceDryRun || p.dryRun !== false;
    const item: CustomPrivacyRule = {
      id: draftRuleId(p.match),
      enabled: !dryRun,
      mode: p.mode,
      match: p.match,
      kind: p.kind ? p.kind : slugKind(p.match),
      replaceWith: REDACT_TAG,
    };
    if (dryRun) item.dryRun = true;
    if (p.scope) {
      item.scope = {
        ...(p.scope.tools ? { tools: [...p.scope.tools] } : {}),
        ...(p.scope.fields ? { fields: [...p.scope.fields] } : {}),
      };
    }
    customRules.push(item);
  }
  if (customRules.length > MAX_CUSTOM_RULES) errors.push("too_many_custom_rules");

  const dropEx = new Set(proposal.remove?.exemptionIds ?? []);
  const exemptions: PolicyExemption[] = current.exemptions
    .filter((e) => !dropEx.has(e.id))
    .map((e) => {
      const copy: PolicyExemption = { ...e };
      if (e.tools) copy.tools = [...e.tools];
      return copy;
    });
  const seenEx = new Set(exemptions.map((e) => `${e.ruleId}\0${e.match.toLowerCase()}`));
  for (const p of proposal.exemptions ?? []) {
    const key = `${p.ruleId}\0${p.match.toLowerCase()}`;
    if (seenEx.has(key)) continue;
    seenEx.add(key);
    const item: PolicyExemption = {
      id: exemptionId(p.ruleId, p.match),
      ruleId: p.ruleId,
      match: p.match,
      createdAt: opts.now,
      expiresAt: p.expiresAt ?? opts.now + 30 * DAY,
    };
    if (p.tools) item.tools = [...p.tools];
    if (p.note !== undefined) item.note = p.note;
    exemptions.push(item);
  }
  if (exemptions.length > MAX_EXEMPTIONS) errors.push("too_many_exemptions");

  if (errors.length) return { ok: false, errors };
  return { ok: true, next: { overrides, customRules, exemptions } };
}

export function buildPolicyContext(
  input: {
    policyVersion: number;
    mode: Intervention;
    overrides: PolicyOverrides;
    exemptions: PolicyExemption[];
    customRules: CustomPrivacyRule[];
    rules: RuleDef[];
  },
  access: "admin" | "viewer",
) {
  const mask = access === "viewer";
  return {
    schema: CONTEXT_SCHEMA,
    proposalSchema: PROPOSAL_SCHEMA,
    policyVersion: input.policyVersion,
    mode: input.mode,
    overrides: { rules: { ...input.overrides.rules }, families: { ...input.overrides.families } },
    exemptions: input.exemptions.map((e) => ({
      ...e,
      tools: e.tools ? [...e.tools] : undefined,
      match: mask ? ADMIN_HIDDEN : e.match,
    })),
    customRules: input.customRules.map((r) => ({
      ...r,
      match: mask ? ADMIN_HIDDEN : r.match,
      replaceWith: mask && r.mode === "replace" ? ADMIN_HIDDEN : r.replaceWith,
    })),
    catalog: input.rules.map((r) => ({
      id: r.id,
      family: r.family,
      action: r.action,
      risk: r.risk,
      tools: r.tools,
      field: r.field,
      pattern: r.pattern,
      title: r.title,
      titleEn: r.titleEn,
    })),
    protectedRuleIds: protectedRuleIds(input.rules),
    limits: {
      maxCustomRules: MAX_CUSTOM_RULES,
      maxExemptions: MAX_EXEMPTIONS,
      maxRuleOverrides: MAX_RULE_OVERRIDES,
      matchMax: MATCH_MAX,
    },
  };
}
