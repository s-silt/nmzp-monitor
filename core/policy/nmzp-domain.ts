import { parseArchivePolicy, parseGithubPolicy } from "../egress-schema.ts";
import {
  parsePolicyExemptions,
  parsePolicyOverrides,
  RULE_ID_RE,
  THREAT_KINDS,
  type PolicyOverrides,
} from "../policy-schema.ts";
import type { CustomPrivacyRule, PolicyState } from "../schema.ts";
import {
  capturePolicyData,
  createPolicySnapshot,
  type PolicySnapshot,
  type SnapshotLimits,
} from "./snapshot.ts";

export type NmzpPolicyPatch = Partial<Pick<PolicyState,
  "mode" | "stopped" | "customRules" | "overrides" | "exemptions" | "archiveUpload" | "githubUpload"
>>;

/** Trusted application modules, e.g. loadMonitor(coreDir). Never supplied by policy JSON. */
export interface NmzpPolicySource<Rule extends { id: string }> {
  RULES: readonly Rule[];
  isProtectedRule: (rule: Rule) => boolean;
  protectedDowngrades: (overrides: PolicyOverrides, rules: Rule[]) => string[];
  privacy: {
    MAX_CUSTOM_RULES: number;
    sanitizeCustomRules: (raw: unknown) => CustomPrivacyRule[] | undefined;
    compileMatch: (match: string) => RegExp | null;
  };
}

export type PolicyDomainErrorCode =
  | "policy_domain_options"
  | "invalid_policy_schema"
  | "invalid_policy_patch"
  | "invalid_policy_mode"
  | "invalid_policy_stopped"
  | "invalid_previous_mode"
  | "invalid_custom_rules"
  | "invalid_policy_overrides"
  | "unknown_rule_override"
  | "protected_rule_override"
  | "invalid_policy_exemptions"
  | "protected_rule_exemption"
  | "invalid_archive_policy"
  | "invalid_github_policy";

export class PolicyDomainError extends Error {
  readonly code: PolicyDomainErrorCode;
  readonly ruleIds?: readonly string[];

  constructor(code: PolicyDomainErrorCode, ruleIds?: readonly string[]) {
    super(code);
    this.name = "PolicyDomainError";
    this.code = code;
    // Only bounded catalog/override identifiers, never match text or filesystem paths.
    if (ruleIds) this.ruleIds = Object.freeze([...ruleIds].sort());
  }
}

export interface NmzpPolicyDomain {
  /** Input normalization follows the existing HTTP validators; revisions are not editable. */
  normalizePatch: (raw: unknown) => NmzpPolicyPatch;
  /** Full durable documents must already be canonical. Never silently repair on open/restore. */
  prepare: (snapshot: PolicySnapshot<PolicyState>) => void;
}

const EDITABLE = new Set([
  "mode", "stopped", "customRules", "overrides", "exemptions", "archiveUpload", "githubUpload",
]);
const DOCUMENT_KEYS = new Set([...EDITABLE, "version", "updatedAt", "previousMode"]);
const MODES = new Set(["enforcing", "permissive", "off"]);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Bind trusted rule facts once, and reuse NMZP's parsers/compiler, not a second regex engine.
 * This is validation/normalization, not HTTP authorization or a compiled evaluation engine.
 * The application must authorize the caller before invoking a policy service.
 */
export function createNmzpPolicyDomain<Rule extends { id: string }>(
  source: NmzpPolicySource<Rule>,
  limits: SnapshotLimits = {},
): NmzpPolicyDomain {
  if (!source || !Array.isArray(source.RULES) || source.RULES.length === 0 || source.RULES.length > 4096
    || typeof source.isProtectedRule !== "function" || typeof source.protectedDowngrades !== "function"
    || typeof source.privacy?.sanitizeCustomRules !== "function" || typeof source.privacy?.compileMatch !== "function") {
    throw new PolicyDomainError("policy_domain_options");
  }
  const maxRules = source.privacy.MAX_CUSTOM_RULES;
  if (!Number.isSafeInteger(maxRules) || maxRules < 1 || maxRules > 1024) {
    throw new PolicyDomainError("policy_domain_options");
  }
  const ownedLimits = Object.freeze({ ...limits });
  const known = new Set<string>();
  const protectedRules = new Set<string>();
  for (const rule of source.RULES) {
    if (!rule || typeof rule.id !== "string" || !RULE_ID_RE.test(rule.id) || known.has(rule.id)) {
      throw new PolicyDomainError("policy_domain_options");
    }
    known.add(rule.id);
    if (source.isProtectedRule(rule)) protectedRules.add(rule.id);
  }
  const protectedFamilies = new Set<string>(THREAT_KINDS.filter((family) =>
    source.protectedDowngrades({ rules: {}, families: { [family]: "log" } }, [...source.RULES]).length > 0,
  ));
  const sanitize = source.privacy.sanitizeCustomRules;
  const compile = source.privacy.compileMatch;

  function normalizeEditable(raw: Record<string, unknown>): NmzpPolicyPatch {
    const out: NmzpPolicyPatch = {};
    if (raw.mode !== undefined) {
      if (typeof raw.mode !== "string" || !MODES.has(raw.mode)) throw new PolicyDomainError("invalid_policy_mode");
      out.mode = raw.mode as PolicyState["mode"];
    }
    if (raw.stopped !== undefined) {
      if (typeof raw.stopped !== "boolean") throw new PolicyDomainError("invalid_policy_stopped");
      out.stopped = raw.stopped;
    }
    if (raw.githubUpload !== undefined) {
      const value = parseGithubPolicy(raw.githubUpload);
      if (!value) throw new PolicyDomainError("invalid_github_policy");
      out.githubUpload = value;
    }
    if (raw.archiveUpload !== undefined) {
      const value = parseArchivePolicy(raw.archiveUpload);
      if (!value) throw new PolicyDomainError("invalid_archive_policy");
      out.archiveUpload = value;
    }
    if (raw.overrides !== undefined) {
      const value = parsePolicyOverrides(raw.overrides);
      if (!value) throw new PolicyDomainError("invalid_policy_overrides");
      const unknown = Object.keys(value.rules).filter((id) => !known.has(id));
      if (unknown.length) throw new PolicyDomainError("unknown_rule_override", unknown);
      const forbidden = Object.entries(value.rules)
        .filter(([id, action]) => protectedRules.has(id) && action !== "block")
        .map(([id]) => id);
      for (const [family, action] of Object.entries(value.families)) {
        if (protectedFamilies.has(family) && action === "log") forbidden.push(`family:${family}`);
      }
      if (forbidden.length) throw new PolicyDomainError("protected_rule_override", forbidden);
      out.overrides = value;
    }
    if (raw.exemptions !== undefined) {
      const value = parsePolicyExemptions(raw.exemptions);
      if (!value) throw new PolicyDomainError("invalid_policy_exemptions");
      for (const exemption of value) {
        let valid: boolean;
        try { valid = !!compile(exemption.match); }
        catch { valid = false; }
        if (!valid) throw new PolicyDomainError("invalid_policy_exemptions");
      }
      const forbidden = [...new Set(value.filter((entry) => protectedRules.has(entry.ruleId)).map((entry) => entry.ruleId))];
      if (forbidden.length) throw new PolicyDomainError("protected_rule_exemption", forbidden);
      // Unknown/custom-rule targets retain the current server validator's behavior.
      out.exemptions = value;
    }
    if (raw.customRules !== undefined) {
      if (!Array.isArray(raw.customRules) || raw.customRules.length > maxRules) {
        throw new PolicyDomainError("invalid_custom_rules");
      }
      let value: CustomPrivacyRule[] | undefined;
      try { value = sanitize(raw.customRules); }
      catch { throw new PolicyDomainError("invalid_custom_rules"); }
      if (!value || value.length !== raw.customRules.length || value.length > maxRules) {
        throw new PolicyDomainError("invalid_custom_rules");
      }
      out.customRules = value;
    }
    return out;
  }

  const normalizePatch = (raw: unknown): NmzpPolicyPatch => {
    // Capture before calling any domain helper. Accessors/non-JSON objects are rejected.
    const owned = capturePolicyData(raw, ownedLimits);
    if (!record(owned) || Object.keys(owned).some((key) => !EDITABLE.has(key))) {
      throw new PolicyDomainError("invalid_policy_patch");
    }
    return normalizeEditable(owned);
  };

  const prepare = (snapshot: PolicySnapshot<PolicyState>): void => {
    const checked = createPolicySnapshot(snapshot.policy as PolicyState, ownedLimits);
    if (checked.hash !== snapshot.hash) throw new PolicyDomainError("invalid_policy_schema");
    const policy = checked.policy;
    if (Object.keys(policy).some((key) => !DOCUMENT_KEYS.has(key))
      || !Object.hasOwn(policy, "mode") || !Object.hasOwn(policy, "stopped") || !Array.isArray(policy.customRules)) {
      throw new PolicyDomainError("invalid_policy_schema");
    }
    if (policy.previousMode !== undefined && !MODES.has(policy.previousMode)) {
      throw new PolicyDomainError("invalid_previous_mode");
    }
    const editable = Object.fromEntries(Object.entries(policy).filter(([key]) => EDITABLE.has(key)));
    const normalized = normalizeEditable(editable);
    // Existing policy files must not be changed silently by normalization at startup/restore.
    for (const key of Object.keys(editable)) {
      const before = capturePolicyData(editable[key], ownedLimits);
      const after = capturePolicyData(normalized[key as keyof NmzpPolicyPatch], ownedLimits);
      if (JSON.stringify(before) !== JSON.stringify(after)) {
        const codes: Record<string, PolicyDomainErrorCode> = {
          customRules: "invalid_custom_rules", overrides: "invalid_policy_overrides",
          exemptions: "invalid_policy_exemptions", archiveUpload: "invalid_archive_policy",
          githubUpload: "invalid_github_policy",
        };
        throw new PolicyDomainError(codes[key] ?? "invalid_policy_schema");
      }
    }
  };
  return Object.freeze({ normalizePatch, prepare });
}
