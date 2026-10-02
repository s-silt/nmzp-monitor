export const THREAT_KINDS = ["exfil", "secret", "tamper", "destructive", "recon", "isolate", "poison"] as const;
export const CANONICAL_TOOL_NAMES = [
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
] as const;
export const CUSTOM_RULE_FIELDS = ["command", "file_path", "url", "contents"] as const;
export const RULE_ID_RE = /^[a-z][a-z0-9_]{0,63}$/;
export const MAX_RULE_OVERRIDES = 128;
export const MAX_EXEMPTIONS = 32;
export const EXEMPTION_MAX_TTL_MS = 365 * 24 * 60 * 60 * 1000;
export const EXEMPTION_ID_RE = /^x_[a-z0-9]{1,24}$/;
export type RuleOverride = "block" | "log" | "off";
export type FamilyOverride = "block" | "log";
export type ThreatKindName = (typeof THREAT_KINDS)[number];
export interface PolicyOverrides {
  rules: Record<string, RuleOverride>;
  families: Partial<Record<ThreatKindName, FamilyOverride>>;
}
export interface PolicyExemption {
  id: string;
  ruleId: string;
  match: string;
  tools?: string[];
  note?: string;
  createdAt: number;
  expiresAt?: number;
  sourceEventId?: string;
}
export interface CustomRuleScope {
  tools?: string[];
  fields?: string[];
}

const TOOL_SET = new Set<string>(CANONICAL_TOOL_NAMES);
const FIELD_SET = new Set<string>(CUSTOM_RULE_FIELDS);
const THREAT_SET = new Set<string>(THREAT_KINDS);
const RULE_OVR = new Set(["block", "log", "off"]);
const FAM_OVR = new Set(["block", "log"]);

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32) return true;
  }
  return false;
}

function uniq(xs: string[]): string[] {
  const out: string[] = [];
  for (const x of xs) if (!out.includes(x)) out.push(x);
  return out;
}

export function parsePolicyOverrides(raw: unknown): PolicyOverrides | undefined {
  if (!isPlain(raw)) return undefined;
  const keys = Object.keys(raw);
  for (const k of keys) if (k !== "rules" && k !== "families") return undefined;
  const rulesRaw = raw.rules === undefined ? {} : raw.rules;
  const familiesRaw = raw.families === undefined ? {} : raw.families;
  if (!isPlain(rulesRaw) || !isPlain(familiesRaw)) return undefined;
  const rules: Record<string, RuleOverride> = {};
  const ruleKeys = Object.keys(rulesRaw);
  if (ruleKeys.length > MAX_RULE_OVERRIDES) return undefined;
  for (const k of ruleKeys) {
    if (!RULE_ID_RE.test(k)) return undefined;
    const v = rulesRaw[k];
    if (typeof v !== "string" || !RULE_OVR.has(v)) return undefined;
    rules[k] = v as RuleOverride;
  }
  const families: PolicyOverrides["families"] = {};
  for (const k of Object.keys(familiesRaw)) {
    if (!THREAT_SET.has(k)) return undefined;
    const v = familiesRaw[k];
    if (typeof v !== "string" || !FAM_OVR.has(v)) return undefined;
    families[k as ThreatKindName] = v as FamilyOverride;
  }
  return { rules: { ...rules }, families: { ...families } };
}

export function policyOverrides(raw: unknown): PolicyOverrides {
  return parsePolicyOverrides(raw) ?? { rules: {}, families: {} };
}

export function parsePolicyExemptions(raw: unknown): PolicyExemption[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  if (raw.length > MAX_EXEMPTIONS) return undefined;
  const out: PolicyExemption[] = [];
  const seen = new Set<string>();
  for (const row of raw) {
    if (!isPlain(row)) return undefined;
    for (const k of Object.keys(row)) {
      if (!["id", "ruleId", "match", "tools", "note", "createdAt", "expiresAt", "sourceEventId"].includes(k)) return undefined;
    }
    if (typeof row.id !== "string" || !EXEMPTION_ID_RE.test(row.id)) return undefined;
    if (seen.has(row.id)) return undefined;
    seen.add(row.id);
    if (typeof row.ruleId !== "string" || !RULE_ID_RE.test(row.ruleId)) return undefined;
    if (typeof row.match !== "string" || row.match.length < 4 || row.match.length > 80 || hasControl(row.match)) return undefined;
    if (!Number.isSafeInteger(row.createdAt) || (row.createdAt as number) < 0) return undefined;
    const item: PolicyExemption = {
      id: row.id,
      ruleId: row.ruleId,
      match: row.match,
      createdAt: row.createdAt as number,
    };
    if (row.tools !== undefined) {
      if (!Array.isArray(row.tools) || row.tools.length === 0) return undefined;
      const tools: string[] = [];
      for (const t of row.tools) {
        if (typeof t !== "string" || !TOOL_SET.has(t)) return undefined;
        if (!tools.includes(t)) tools.push(t);
      }
      item.tools = tools;
    }
    if (row.note !== undefined) {
      if (typeof row.note !== "string" || row.note.length > 120) return undefined;
      item.note = row.note;
    }
    if (row.expiresAt !== undefined) {
      if (!Number.isSafeInteger(row.expiresAt)) return undefined;
      const exp = row.expiresAt as number;
      if (exp <= item.createdAt || exp > item.createdAt + EXEMPTION_MAX_TTL_MS) return undefined;
      item.expiresAt = exp;
    }
    if (row.sourceEventId !== undefined) {
      if (typeof row.sourceEventId !== "string" || row.sourceEventId.length > 64) return undefined;
      item.sourceEventId = row.sourceEventId;
    }
    out.push(item);
  }
  return out;
}

export function policyExemptions(raw: unknown): PolicyExemption[] {
  const parsed = parsePolicyExemptions(raw);
  return parsed ? parsed.map((e) => ({ ...e, tools: e.tools ? [...e.tools] : undefined })) : [];
}

export const MAX_CLIENT_MODES = 256;
export const CLIENT_LABEL_MAX = 128;
export interface ClientMode {
  deviceId: string;
  agent?: string;
  mode: "log_only";
}

function clientLabel(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  if (value.length < 1 || value.length > CLIENT_LABEL_MAX) return undefined;
  if (value !== value.trim() || hasControl(value) || /\s/u.test(value)) return undefined;
  for (let i = 0; i < value.length; i++) if (value.charCodeAt(i) === 127) return undefined;
  return value;
}

export function parsePolicyClients(raw: unknown): ClientMode[] | undefined {
  if (!Array.isArray(raw) || raw.length > MAX_CLIENT_MODES) return undefined;
  const out: ClientMode[] = [];
  const seen = new Set<string>();
  for (const row of raw) {
    if (!isPlain(row)) return undefined;
    for (const key of Object.keys(row)) {
      if (key !== "deviceId" && key !== "agent" && key !== "mode") return undefined;
    }
    const deviceId = clientLabel(row.deviceId);
    if (!deviceId || row.mode !== "log_only") return undefined;
    let agent: string | undefined;
    if (row.agent !== undefined) {
      agent = clientLabel(row.agent);
      if (!agent) return undefined;
    }
    const key = `${deviceId}\0${agent ?? ""}`;
    if (seen.has(key)) return undefined;
    seen.add(key);
    out.push(agent === undefined ? { deviceId, mode: "log_only" } : { deviceId, agent, mode: "log_only" });
  }
  return out;
}

export function policyClients(raw: unknown): ClientMode[] {
  const parsed = parsePolicyClients(raw);
  if (!parsed) return [];
  return parsed.map((row) => (row.agent === undefined
    ? { deviceId: row.deviceId, mode: row.mode }
    : { deviceId: row.deviceId, agent: row.agent, mode: row.mode }));
}

/** Exact deviceId+agent wins over a device-wide row. Absent or unknown mode does not match. */
export function selectClientMode(raw: unknown, deviceId: string, agent: string): ClientMode | undefined {
  if (!Array.isArray(raw)) return undefined;
  let deviceWide: ClientMode | undefined;
  for (const row of raw) {
    if (!isPlain(row) || row.deviceId !== deviceId || row.mode !== "log_only") continue;
    if (row.agent === agent && typeof row.agent === "string") {
      return { deviceId, agent, mode: "log_only" };
    }
    if (row.agent === undefined && !deviceWide) deviceWide = { deviceId, mode: "log_only" };
  }
  return deviceWide;
}

export function parseCustomRuleScope(raw: unknown): { ok: true; scope?: CustomRuleScope } | { ok: false } {
  if (raw === undefined) return { ok: true };
  if (!isPlain(raw)) return { ok: false };
  for (const k of Object.keys(raw)) if (k !== "tools" && k !== "fields") return { ok: false };
  const scope: CustomRuleScope = {};
  if (raw.tools !== undefined) {
    if (!Array.isArray(raw.tools) || raw.tools.length === 0) return { ok: false };
    const tools: string[] = [];
    for (const t of raw.tools) {
      if (typeof t !== "string" || !TOOL_SET.has(t)) return { ok: false };
      if (!tools.includes(t)) tools.push(t);
    }
    scope.tools = tools;
  }
  if (raw.fields !== undefined) {
    if (!Array.isArray(raw.fields) || raw.fields.length === 0) return { ok: false };
    const fields: string[] = [];
    for (const f of raw.fields) {
      if (typeof f !== "string" || !FIELD_SET.has(f)) return { ok: false };
      if (!fields.includes(f)) fields.push(f);
    }
    scope.fields = fields;
  }
  if (!scope.tools && !scope.fields) return { ok: true };
  return { ok: true, scope };
}

export function customRuleState(rule: { enabled?: unknown; dryRun?: unknown }): "on" | "dry_run" | "off" {
  if (rule.dryRun === true) return "dry_run";
  if (rule.enabled === false) return "off";
  return "on";
}

export { uniq, TOOL_SET, FIELD_SET };
