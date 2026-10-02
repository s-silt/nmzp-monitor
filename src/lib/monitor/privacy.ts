/** Scan tool input as data only. Never evaluate it. */

import type { CustomPrivacyRule } from "./types";
import { CANONICAL_TOOL_NAMES, CUSTOM_RULE_FIELDS, customRuleState, parseCustomRuleScope, RULE_ID_RE } from "./policy-schema.ts";

/** Product copy: privacy words become this exact token. */
export const REDACT_TAG = "<标签>";

export interface SecretHit {
  kind: string;
  index: number;
  length: number;
}

export interface CustomHit {
  kind: string;
  index: number;
  length: number;
  mode: "block" | "replace";
  ruleId: string;
  replaceWith?: string;
}

const PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: "aws_key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "github_token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { kind: "github_pat", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { kind: "openai_key", re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "xai_key", re: /\bxai-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "npm_token", re: /\bnpm_[A-Za-z0-9]{20,}\b/g },
  { kind: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{18,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: "bearer", re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  { kind: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { kind: "secret_kv", re: /\b(api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*\S{8,}/gi },
  { kind: "cn_id", re: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g },
  { kind: "bank_card", re: /\b[1-9]\d{15,18}\b/g },
];

export const CRED_KINDS = new Set([
  "aws_key",
  "github_token",
  "github_pat",
  "openai_key",
  "anthropic_key",
  "xai_key",
  "npm_token",
  "slack_token",
  "jwt",
  "bearer",
  "private_key",
  "secret_kv",
]);

export const PII_KINDS = new Set(["cn_id", "bank_card", "phone"]);

/**
 * JSON phone values only. Keys: phone, mobile, tel, telephone, phoneNumber,
 * mobilePhone, phone_number, mobile_number, mobile_phone, tel_number,
 * 手机, 手机号, 电话. Value is a JSON string or number: optional +86/86 prefix,
 * then 1[3-9] and 9 digits. Not general international recognition.
 */
const PHONE_KEYS = new Set([
  "phone", "mobile", "tel", "telephone", "phonenumber", "mobilephone",
  "phone_number", "mobile_number", "mobile_phone", "tel_number",
  "手机", "手机号", "电话",
]);
const PHONE_SCAN_MAX = 65_536;
const PHONE_HITS_MAX = 32;
const PHONE_VALUE_MAX = 24;
const KEY_LOOKBACK = 80;
const URL_LOOKBACK = 2_048;
const URL_TOKEN_MAX = 4_096;

const CARD_KEYS = new Set([
  "card", "bank", "bank_card", "bankcard", "pan", "credit_card", "creditcard",
  "debit", "debit_card", "iban", "cvv", "cvc",
  "卡号", "银行卡", "收款账号", "银行账号",
]);
const CRED_KEYS = new Set([
  "password", "passwd", "secret", "token", "api_key", "apikey", "access_token",
  "authorization", "auth", "pwd",
]);
const TIMESTAMP_KEYS = new Set([
  "timestamp", "timestamps", "ts", "time", "created_at", "updated_at", "createdat",
  "updatedat", "nanos", "nanoseconds", "nanosecond", "nano", "unix", "unix_ns",
  "unix_ms", "unix_time", "epoch", "epoch_ns", "epoch_ms", "date", "occurred_at",
  "event_time", "created", "updated",
]);
const OPAQUE_ID_KEYS = new Set([
  "id", "order", "order_id", "orderid", "user_id", "userid", "snowflake",
  "channel_id", "channelid", "message_id", "messageid", "resource_id", "resourceid",
  "trace", "trace_id", "traceid", "span", "span_id", "spanid", "request_id",
  "requestid", "session_id", "sessionid", "guild_id", "role_id", "object_id",
  "objectid", "pk", "uid", "uuid", "guid",
]);

function normKey(key: string): string {
  for (let i = 0; i < key.length; i += 1) {
    if (key.charCodeAt(i) > 127) return key;
  }
  return key.toLowerCase();
}

function isCnMobile(value: string): boolean {
  return /^(?:\+?86[-\s]?)?1[3-9]\d{9}$/.test(value);
}

function precedingKey(text: string, index: number): string | null {
  let i = index;
  const min = Math.max(0, index - KEY_LOOKBACK);
  while (i > min && (text[i - 1] === " " || text[i - 1] === "\t" || text[i - 1] === "\n" || text[i - 1] === "\r")) i -= 1;
  if (i > min && (text[i - 1] === '"' || text[i - 1] === "'")) i -= 1;
  while (i > min && (text[i - 1] === " " || text[i - 1] === "\t")) i -= 1;
  if (i <= min) return null;
  const sep = text[i - 1];
  if (sep !== "=" && sep !== ":") return null;
  i -= 1;
  while (i > min && (text[i - 1] === " " || text[i - 1] === "\t")) i -= 1;
  if (i > min && (text[i - 1] === '"' || text[i - 1] === "'")) i -= 1;
  const end = i;
  while (i > min) {
    const c = text[i - 1]!;
    if (c === "=" || c === ":" || c === '"' || c === "'" || c === " " || c === "\n" || c === "\r" || c === "\t" || c === "?" || c === "&" || c === "/" || c === "{" || c === "}" || c === "," || c === "[" || c === "]" || c === "\\") break;
    i -= 1;
    if (end - i > 64) break;
  }
  const key = text.slice(i, end);
  return key ? normKey(key) : null;
}

function urlPart(text: string, index: number, length: number): "path" | "userinfo" | "query" | "other" {
  const min = Math.max(0, index - URL_LOOKBACK);
  let start = index;
  while (start > min) {
    const c = text[start - 1]!;
    if (/[\s'"|&;<>()]/.test(c)) break;
    start -= 1;
  }
  let end = index + length;
  const endMax = Math.min(text.length, start + URL_TOKEN_MAX);
  while (end < endMax) {
    const c = text[end]!;
    if (/[\s'"|&;<>()]/.test(c)) break;
    end += 1;
  }
  const token = text.slice(start, end);
  if (!/^https?:\/\//i.test(token)) return "other";
  const rel = index - start;
  const relEnd = rel + length;
  if (rel < 0 || relEnd > token.length) return "other";
  const scheme = token.toLowerCase().startsWith("https://") ? 8 : 7;
  let at = -1;
  let path = -1;
  let query = -1;
  let hash = -1;
  for (let j = scheme; j < token.length; j += 1) {
    const c = token[j]!;
    if (c === "@" && path < 0 && query < 0 && hash < 0) at = j;
    else if (c === "/" && path < 0 && query < 0 && hash < 0) path = j;
    else if (c === "?" && query < 0 && hash < 0) query = j;
    else if (c === "#" && hash < 0) {
      hash = j;
      break;
    }
  }
  if (at >= 0 && rel >= scheme && relEnd <= at) return "userinfo";
  if (path >= 0 && rel >= path && (query < 0 || rel < query) && (hash < 0 || rel < hash)) {
    const before = token[rel - 1] ?? "";
    const after = token[relEnd] ?? "";
    if (before === "/" && (after === "" || after === "/" || after === "?" || after === "#")) return "path";
  }
  if (query >= 0 && rel > query && (hash < 0 || rel < hash)) return "query";
  return "other";
}

/** bank_card stays for explicit card/credential keys, userinfo, and unlabeled numbers. Path segments and explicit ids/timestamps do not. */
function keepBankCard(text: string, index: number, length: number): boolean {
  const key = precedingKey(text, index);
  if (key && (CARD_KEYS.has(key) || CRED_KEYS.has(key))) return true;
  if (key && (TIMESTAMP_KEYS.has(key) || OPAQUE_ID_KEYS.has(key))) return false;
  const part = urlPart(text, index, length);
  if (part === "path") return false;
  return true;
}

function collectPhones(text: string, hits: SecretHit[]): void {
  const limit = Math.min(text.length, PHONE_SCAN_MAX);
  let found = 0;
  let i = 0;
  while (i < limit && found < PHONE_HITS_MAX) {
    const q = text.indexOf('"', i);
    if (q < 0 || q >= limit) break;
    let j = q + 1;
    let key = "";
    let broken = false;
    while (j < limit && text[j] !== '"') {
      if (text[j] === "\\") {
        broken = true;
        break;
      }
      key += text[j];
      j += 1;
      if (key.length > 32) {
        broken = true;
        break;
      }
    }
    if (broken || j >= limit || text[j] !== '"') {
      i = q + 1;
      continue;
    }
    const norm = normKey(key);
    let k = j + 1;
    while (k < limit && (text[k] === " " || text[k] === "\t" || text[k] === "\n" || text[k] === "\r")) k += 1;
    if (k >= limit || text[k] !== ":") {
      i = j + 1;
      continue;
    }
    k += 1;
    while (k < limit && (text[k] === " " || text[k] === "\t" || text[k] === "\n" || text[k] === "\r")) k += 1;
    if (!PHONE_KEYS.has(norm)) {
      i = j + 1;
      continue;
    }
    if (k < limit && text[k] === '"') {
      const vStart = k + 1;
      let value = "";
      let p = vStart;
      let badValue = false;
      while (p < limit && text[p] !== '"') {
        if (text[p] === "\\") {
          badValue = true;
          break;
        }
        value += text[p];
        p += 1;
        if (value.length > PHONE_VALUE_MAX) {
          badValue = true;
          break;
        }
      }
      if (!badValue && p < limit && text[p] === '"' && isCnMobile(value)) {
        hits.push({ kind: "phone", index: vStart, length: value.length });
        found += 1;
        i = p + 1;
        continue;
      }
      i = j + 1;
      continue;
    }
    if (k < limit && text[k]! >= "0" && text[k]! <= "9") {
      const vStart = k;
      let value = "";
      while (k < limit && text[k]! >= "0" && text[k]! <= "9" && value.length <= PHONE_VALUE_MAX) {
        value += text[k];
        k += 1;
      }
      if (isCnMobile(value)) {
        hits.push({ kind: "phone", index: vStart, length: value.length });
        found += 1;
      }
      i = k;
      continue;
    }
    i = j + 1;
  }
}

const KEYWORD_RE =
  /(身份证|银行卡|验证码|家庭住址|社保号|护照号|手机号|password|passwd|api[_-]?key|secret_key|private[_-]?key|authorization)/i;

const OUTBOUND_RE =
  /\b(curl|wget|scp|rsync|rclone|nc|ncat|ftp|sftp|httpie|aria2c)\b|https?:\/\//i;

export const MAX_CUSTOM_RULES = 64;
export const MATCH_MAX = 80;
/** Per-rule scan ceiling. Must stay above typical PII counts so rewrite cannot miss. */
export const CUSTOM_SCAN_MAX = 4096;

export const SUGGESTED_PRIVACY: CustomPrivacyRule[] = [
  { id: "p_emp", enabled: true, mode: "replace", match: "EMP-\\d{4}", kind: "emp_id", replaceWith: REDACT_TAG },
  {
    id: "p_db",
    enabled: true,
    mode: "block",
    match: "db\\.prod\\.internal",
    kind: "internal_host",
    replaceWith: REDACT_TAG,
  },
  { id: "p_ht", enabled: true, mode: "block", match: "合同编号", kind: "contract_no", replaceWith: REDACT_TAG },
  {
    id: "p_pem_hdr",
    enabled: true,
    mode: "replace",
    match: "-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
    kind: "pem_header",
    replaceWith: REDACT_TAG,
  },
  { id: "p_aws_key", enabled: true, mode: "replace", match: "AKIA[0-9A-Z]{16}", kind: "aws_key_id", replaceWith: REDACT_TAG },
  {
    id: "p_conn",
    enabled: true,
    mode: "replace",
    match: "(postgres|mysql|mongodb)://[^\\s]+",
    kind: "db_url",
    replaceWith: REDACT_TAG,
  },
  { id: "p_salary", enabled: true, mode: "replace", match: "工资明细|薪酬表|salary", kind: "hr_pay", replaceWith: REDACT_TAG },
  { id: "p_bank", enabled: true, mode: "replace", match: "收款账号|银行账号|iban", kind: "bank", replaceWith: REDACT_TAG },
  {
    id: "p_conf",
    enabled: true,
    mode: "replace",
    match: "商业秘密|strictly confidential|internal only",
    kind: "confidential",
    replaceWith: REDACT_TAG,
  },
];

export function isCredentialKind(kind: string) {
  return CRED_KINDS.has(kind);
}

export function scanSecrets(text: string): SecretHit[] {
  if (!text) return [];
  const hits: SecretHit[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text))) {
      if (p.kind === "bank_card" && !keepBankCard(text, m.index, m[0].length)) {
        if (p.re.lastIndex === m.index) p.re.lastIndex += 1;
        continue;
      }
      hits.push({ kind: p.kind, index: m.index, length: m[0].length });
      if (p.re.lastIndex === m.index) p.re.lastIndex += 1;
    }
  }
  collectPhones(text, hits);
  return hits;
}

export function redact(text: string, hits = scanSecrets(text)): string {
  if (!hits.length) return text;
  return paint(text, hits.map((h) => ({ index: h.index, length: h.length, label: h.kind })));
}

export function hasPrivacyKeyword(text: string): boolean {
  return KEYWORD_RE.test(text);
}

export function looksOutbound(text: string): boolean {
  return OUTBOUND_RE.test(text);
}

export function uniqueKinds(hits: SecretHit[]): string[] {
  return [...new Set(hits.map((h) => h.kind))];
}

export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const MATCH_CACHE = new Map<string, RegExp | null>();

function skipClass(s: string, i: number): number {
  i += 1;
  if (s[i] === "^") i += 1;
  if (s[i] === "]") i += 1;
  while (i < s.length && s[i] !== "]") {
    if (s[i] === "\\" && i + 1 < s.length) i += 2;
    else i += 1;
  }
  return i < s.length ? i + 1 : i;
}

function isQuantifierAt(s: string, i: number): boolean {
  const c = s[i];
  if (c === "+" || c === "*" || c === "{") return true;
  if (c !== "?") return false;
  if (i > 0 && s[i - 1] === "(") return false;
  if (i > 0 && "+*?}".includes(s[i - 1]!)) return false;
  return true;
}

function bodyHasQuantifier(s: string, start: number, end: number): boolean {
  let i = start;
  while (i < end) {
    if (s[i] === "\\" && i + 1 < end) {
      i += 2;
      continue;
    }
    if (s[i] === "[") {
      i = skipClass(s, i);
      continue;
    }
    if (isQuantifierAt(s, i)) return true;
    i += 1;
  }
  return false;
}

function matchingParen(s: string, open: number): number {
  let depth = 1;
  let i = open + 1;
  while (i < s.length && depth > 0) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (s[i] === "[") {
      i = skipClass(s, i);
      continue;
    }
    if (s[i] === "(") depth += 1;
    else if (s[i] === ")") depth -= 1;
    if (depth > 0) i += 1;
  }
  return depth === 0 ? i : -1;
}

function isCatastrophic(pattern: string): boolean {
  if (/\\[1-9]/.test(pattern)) return true;
  let i = 0;
  while (i < pattern.length) {
    if (pattern[i] === "\\" && i + 1 < pattern.length) {
      i += 2;
      continue;
    }
    if (pattern[i] === "[") {
      i = skipClass(pattern, i);
      continue;
    }
    if (pattern[i] === "(") {
      const close = matchingParen(pattern, i);
      if (close < 0) break;
      let bodyStart = i + 1;
      if (pattern[bodyStart] === "?") bodyStart += 1;
      if (pattern[bodyStart] === ":") bodyStart += 1;
      const after = close + 1;
      if (after < pattern.length && isQuantifierAt(pattern, after) && bodyHasQuantifier(pattern, bodyStart, close)) return true;
      i = close + 1;
      continue;
    }
    i += 1;
  }
  return false;
}

function compileMatchUncached(match: string): RegExp | null {
  const m = match.trim();
  if (m.length < 2 || m.length > MATCH_MAX) return null;
  if (/^(\.\*?|\s+)$/.test(m)) return null;
  if (isCatastrophic(m)) return null;
  try {
    const re = new RegExp(m, "gi");
    if (re.test("") && m.replace(/\\[dwsWDS]/g, "x").length < 4) return null;
    re.lastIndex = 0;
    return re;
  } catch {
    try {
      const re = new RegExp(escapeRegExp(m), "gi");
      re.lastIndex = 0;
      return re;
    } catch {
      return null;
    }
  }
}

export function compileMatch(match: string): RegExp | null {
  if (MATCH_CACHE.has(match)) {
    const cached = MATCH_CACHE.get(match) ?? null;
    if (cached) cached.lastIndex = 0;
    return cached;
  }
  const compiled = compileMatchUncached(match);
  if (MATCH_CACHE.size >= 256) MATCH_CACHE.clear();
  MATCH_CACHE.set(match, compiled);
  if (compiled) compiled.lastIndex = 0;
  return compiled;
}

export function scanCustom(text: string, rules: CustomPrivacyRule[]): CustomHit[] {
  if (!text || !rules.length) return [];
  const hits: CustomHit[] = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const re = compileMatch(rule.match);
    if (!re) continue;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = re.exec(text)) && n < CUSTOM_SCAN_MAX) {
      if (!m[0]) {
        re.lastIndex += 1;
        continue;
      }
      hits.push({
        kind: rule.kind || "privacy",
        index: m.index,
        length: m[0].length,
        mode: rule.mode,
        ruleId: rule.id,
        replaceWith: rule.mode === "replace" && rule.replaceWith ? rule.replaceWith : REDACT_TAG,
      });
      n += 1;
    }
  }
  return hits;
}

export function redactAll(text: string, secretHits: SecretHit[], customHits: CustomHit[]): string {
  const marks = [
    ...secretHits.map((h) => ({ index: h.index, length: h.length, label: h.kind })),
    ...customHits.map((h) => ({ index: h.index, length: h.length, label: h.kind })),
  ];
  if (!marks.length) return text;
  return paint(text, marks);
}

function mergeSpans(marks: Array<{ index: number; length: number }>): Array<{ index: number; length: number }> {
  const valid = marks.filter((h) => Number.isFinite(h.index) && h.index >= 0 && h.length > 0);
  valid.sort((a, b) => a.index - b.index || b.length - a.length);
  const out: Array<{ index: number; length: number }> = [];
  for (const h of valid) {
    const last = out[out.length - 1];
    const end = h.index + h.length;
    if (last && h.index <= last.index + last.length) {
      last.length = Math.max(last.index + last.length, end) - last.index;
    } else {
      out.push({ index: h.index, length: h.length });
    }
  }
  return out;
}

function paint(text: string, marks: Array<{ index: number; length: number; label: string }>): string {
  const merged = mergeSpans(marks);
  let out = text;
  for (let i = merged.length - 1; i >= 0; i -= 1) {
    const h = merged[i]!;
    if (h.index + h.length > out.length) continue;
    out = `${out.slice(0, h.index)}${REDACT_TAG}${out.slice(h.index + h.length)}`;
  }
  return out.length > 240 ? `${out.slice(0, 239)}…` : out;
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

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

const TOOL_NAME_SET = new Set<string>(CANONICAL_TOOL_NAMES);
const FIELD_NAME_SET = new Set<string>(CUSTOM_RULE_FIELDS);

function parseDraftScope(line: string): { rest: string; scope?: CustomPrivacyRule["scope"] } | null {
  const colon = line.indexOf(":");
  if (colon <= 0) return { rest: line };
  const prefix = line.slice(0, colon).trim();
  const rest = line.slice(colon + 1).trim();
  if (!prefix || !rest) return { rest: line };
  const toks = prefix.split(",").map((t) => t.trim()).filter(Boolean);
  if (!toks.length) return { rest: line };
  const tools: string[] = [];
  const fields: string[] = [];
  let known = 0;
  let unknown = 0;
  for (const t of toks) {
    if (TOOL_NAME_SET.has(t)) {
      if (!tools.includes(t)) tools.push(t);
      known += 1;
    } else if (FIELD_NAME_SET.has(t)) {
      if (!fields.includes(t)) fields.push(t);
      known += 1;
    } else unknown += 1;
  }
  if (unknown && known) return null;
  if (unknown && !known) return { rest: line };
  const scope: CustomPrivacyRule["scope"] = {};
  if (tools.length) scope.tools = tools;
  if (fields.length) scope.fields = fields;
  return { rest, scope: tools.length || fields.length ? scope : undefined };
}

export function draftRuleId(match: string): string {
  return `p_${Math.abs(hash(match)).toString(36)}`;
}

export function exemptionId(ruleId: string, match: string): string {
  return `x_${Math.abs(hash(`${ruleId}\0${match.toLowerCase()}`)).toString(36)}`;
}

export function liveCustomRules(rules: CustomPrivacyRule[]): CustomPrivacyRule[] {
  return rules.filter((r) => customRuleState(r) === "on");
}

export function dryRunCustomRules(rules: CustomPrivacyRule[]): CustomPrivacyRule[] {
  return rules.filter((r) => customRuleState(r) === "dry_run");
}

export function compilePrivacyDraft(text: string): CustomPrivacyRule[] {
  const parts = text
    .split(/\r?\n|;|；/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  const out: CustomPrivacyRule[] = [];
  const seen = new Set<string>();
  for (const rawLine of parts) {
    if (out.length >= MAX_CUSTOM_RULES) break;
    const scoped = parseDraftScope(rawLine);
    if (scoped === null) continue;
    const line = scoped.rest;
    let match = line;
    let mode: "block" | "replace" = "block";
    let kind = "privacy";
    const arrow = line.split(/\s*=>\s*/);
    if (arrow.length >= 2) {
      match = arrow[0]!.trim();
      kind = arrow[1]!.replace(/[‹›<>]/g, "").trim() || "privacy";
      mode = "replace";
    } else {
      const pipe = line.split(/\s*\|\s*/);
      if (pipe.length >= 2) {
        match = pipe[0]!.trim();
        const flag = pipe[1]!.trim().toLowerCase();
        const label = (pipe[2] ?? "").replace(/[‹›<>]/g, "").trim();
        if (flag === "replace" || flag === "替换") {
          mode = "replace";
          kind = label || slugKind(match);
        } else if (flag === "block" || flag === "拦截") {
          mode = "block";
          kind = label || slugKind(match);
        }
      }
    }
    match = match.trim();
    if (match.length < 2 || match.length > MATCH_MAX) continue;
    if (!compileMatch(match)) continue;
    const key = match.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (kind === "privacy") kind = slugKind(match);
    const row: CustomPrivacyRule = {
      id: draftRuleId(match),
      enabled: true,
      mode,
      match,
      kind,
      replaceWith: REDACT_TAG,
    };
    if (scoped.scope) row.scope = scoped.scope;
    out.push(row);
  }
  return out;
}

export function sanitizeCustomRules(v: unknown): CustomPrivacyRule[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: CustomPrivacyRule[] = [];
  const seen = new Set<string>();
  for (const row of v) {
    if (!row || typeof row !== "object") continue;
    const r = row as Record<string, unknown>;
    if (typeof r.match !== "string" || r.match.length < 2 || r.match.length > MATCH_MAX) continue;
    if (!compileMatch(r.match)) continue;
    if (r.setId !== undefined && (typeof r.setId !== "string" || !RULE_ID_RE.test(r.setId))) continue;
    const scoped = parseCustomRuleScope(r.scope);
    if (!scoped.ok) continue;
    const key = r.match.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const dryRun = r.dryRun === true;
    const item: CustomPrivacyRule = {
      id: typeof r.id === "string" && r.id ? r.id.slice(0, 40) : `p_${out.length}`,
      enabled: dryRun ? false : r.enabled !== false,
      mode: r.mode === "replace" ? "replace" : "block",
      match: r.match,
      kind: typeof r.kind === "string" && r.kind ? r.kind.slice(0, 32) : "privacy",
      replaceWith: typeof r.replaceWith === "string" && r.replaceWith ? r.replaceWith.slice(0, 40) : REDACT_TAG,
    };
    if (dryRun) item.dryRun = true;
    if (typeof r.setId === "string") item.setId = r.setId;
    if (scoped.scope) item.scope = scoped.scope;
    out.push(item);
    if (out.length >= MAX_CUSTOM_RULES) break;
  }
  return out;
}

export { cloakPersona, shouldCloakPersona } from "./cloak.ts";

/**
 * Same filter as core/schema.ts effectiveCustomRules (custom-sets.test pins the two together).
 * Kept here so the engine imports no core export newer than the policy-compat admission tree.
 * Missing sets mean the implicit enabled "default" set; an unknown setId is not enabled.
 */
export function effectiveCustomRules<R extends { setId?: string; enabled?: boolean; dryRun?: boolean }>(
  rules: readonly R[],
  sets: readonly { id: string; enabled: boolean }[] | undefined,
): R[] {
  const list = sets ?? [{ id: "default", enabled: true }];
  return rules.filter((rule) => {
    const id = rule.setId && rule.setId.length > 0 ? rule.setId : "default";
    return list.find((set) => set.id === id)?.enabled === true && customRuleState(rule) !== "off";
  });
}
