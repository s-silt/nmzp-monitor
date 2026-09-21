/**
 * Model-gateway payload inspection. Patterns follow src/lib/monitor/privacy.ts
 * as a reference. Replacement is full-string (not the 240-char audit paint).
 * This module does not detect prompt-injection / model poisoning and does not
 * claim to close every encoding covert channel.
 */

export const REDACT_TAG = "<标签>";

export const MODEL_GATEWAY_ROUTES = ["/v1/chat/completions", "/v1/responses", "/v1/messages"] as const;
export type ModelGatewayRoute = (typeof MODEL_GATEWAY_ROUTES)[number];

export const IMPLEMENTED_MODEL_ROUTES: ReadonlySet<string> = new Set(["/v1/chat/completions"]);

export const GATEWAY_MAX_DEPTH = 24;
export const GATEWAY_MAX_NODES = 4096;
export const GATEWAY_MAX_STRING = 262_144;
export const GATEWAY_MAX_MESSAGES = 256;
export const GATEWAY_MAX_TOOLS = 64;
export const GATEWAY_MAX_PARTS = 64;
export const GATEWAY_MAX_TOOL_CALLS = 32;
export const GATEWAY_B64_MIN = 256;

const PII_KINDS = new Set(["cn_id", "bank_card"]);

const SECRET_PATTERNS: Array<{ kind: string; source: string; flags: string }> = [
  { kind: "aws_key", source: String.raw`\bAKIA[0-9A-Z]{16}\b`, flags: "g" },
  { kind: "github_token", source: String.raw`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`, flags: "g" },
  { kind: "github_pat", source: String.raw`\bgithub_pat_[A-Za-z0-9_]{20,}\b`, flags: "g" },
  { kind: "openai_key", source: String.raw`\bsk-[A-Za-z0-9_-]{20,}\b`, flags: "g" },
  { kind: "anthropic_key", source: String.raw`\bsk-ant-[A-Za-z0-9_-]{20,}\b`, flags: "g" },
  { kind: "xai_key", source: String.raw`\bxai-[A-Za-z0-9_-]{20,}\b`, flags: "g" },
  { kind: "npm_token", source: String.raw`\bnpm_[A-Za-z0-9]{20,}\b`, flags: "g" },
  { kind: "slack_token", source: String.raw`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`, flags: "g" },
  { kind: "jwt", source: String.raw`\beyJ[A-Za-z0-9_-]{18,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, flags: "g" },
  { kind: "bearer", source: String.raw`\bBearer\s+[A-Za-z0-9\-._~+/]{24,}={0,2}`, flags: "gi" },
  { kind: "private_key", source: String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----`, flags: "g" },
  { kind: "secret_kv", source: String.raw`\b(api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*\S{8,}`, flags: "gi" },
  { kind: "cn_id", source: String.raw`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`, flags: "g" },
  { kind: "bank_card", source: String.raw`\b[1-9]\d{15,18}\b`, flags: "g" },
];

const ROLES = new Set(["system", "user", "assistant", "tool", "developer"]);
const MESSAGE_KEYS = new Set(["role", "content", "name", "tool_calls", "tool_call_id"]);
const TOP_KEYS = new Set([
  "model",
  "messages",
  "tools",
  "tool_choice",
  "parallel_tool_calls",
  "stream",
  "stream_options",
  "temperature",
  "top_p",
  "n",
  "max_tokens",
  "max_completion_tokens",
  "stop",
  "presence_penalty",
  "frequency_penalty",
  "user",
  "seed",
  "response_format",
  "stream_tool_calls",
  "reasoning_effort",
  "logprobs",
  "top_logprobs",
  "store",
  "prompt_cache_key",
  "logit_bias",
]);
/** Production event/log field names. Not exported — callers cannot enlarge it. */
const KNOWN_PROTOCOL_FIELDS: ReadonlySet<string> = new Set([
  ...TOP_KEYS,
  ...MESSAGE_KEYS,
  "type",
  "text",
  "id",
  "function",
  "arguments",
  "description",
  "parameters",
  "strict",
  "include_usage",
  "required",
  "properties",
  "items",
  "enum",
  "additionalProperties",
  "default",
  "title",
  "pattern",
  "format",
  "minimum",
  "maximum",
  "minLength",
  "maxLength",
  "minItems",
  "maxItems",
  "anyOf",
  "oneOf",
  "allOf",
  "not",
  "const",
  "unknown_field",
]);

export function publicProtocolField(name: string | undefined): string | undefined {
  if (!name) return undefined;
  return KNOWN_PROTOCOL_FIELDS.has(name) ? name : "unknown_field";
}

const BLOCKED_KEYS = new Set([
  "image",
  "images",
  "image_url",
  "audio",
  "input_audio",
  "file",
  "files",
  "file_ids",
  "attachments",
  "documents",
  "media",
  "video",
  "functions",
  "function_call",
  "base_url",
  "api_key",
  "apiKey",
  "access_token",
  "extra_headers",
  "extra_body",
  "http_client",
  "modalities",
]);

class Deny extends Error {
  code: string;
  field: string | undefined;
  constructor(code: string, field?: string) {
    super(code);
    this.name = "ModelGatewayDeny";
    this.code = code;
    this.field = field;
  }
}

function deny(code: string, field?: string): never {
  throw new Deny(code, field === undefined ? undefined : publicProtocolField(field));
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

export interface SecretHit {
  kind: string;
  index: number;
  length: number;
}

export function scanGatewaySecrets(text: string): SecretHit[] {
  if (!text) return [];
  const hits: SecretHit[] = [];
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.source, p.flags);
    for (const m of text.matchAll(re)) {
      if (m.index === undefined || !m[0]) continue;
      hits.push({ kind: p.kind, index: m.index, length: m[0].length });
    }
  }
  return hits;
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

/** Full-payload paint. Never the 240-char audit summary. */
export function paintGateway(text: string, hits: Array<{ index: number; length: number }>, tag = REDACT_TAG): string {
  const merged = mergeSpans(hits);
  let out = text;
  for (let i = merged.length - 1; i >= 0; i -= 1) {
    const h = merged[i]!;
    if (h.index + h.length > out.length) continue;
    out = `${out.slice(0, h.index)}${tag}${out.slice(h.index + h.length)}`;
  }
  return out;
}

const MAGIC_B64 = [
  "H4sI",
  "UEsDB",
  "iVBORw0KGgo",
  "/9j/",
  "R0lGOD",
  "JVBERi0",
  "AAAAIGZ0eX",
  "T2dnUw",
  "SUQz",
  "Qk1G",
];

export function encodedKind(s: string): string {
  if (/data:[^,\s]+;base64,/i.test(s)) return "data_uri";
  if (/H4sI/.test(s)) return "gzip_b64";
  if (/UEsDB/.test(s)) return "zip_b64";
  if (/iVBORw0KGgo/.test(s) || /\/9j\//.test(s)) return "image_b64";
  if (/-----BEGIN/.test(s)) return "pem";
  if (/[A-Za-z0-9+/]{256,}={0,2}/.test(s)) return "b64_run";
  if (/[0-9a-fA-F]{256,}/.test(s)) return "hex_run";
  return "encoded";
}

export function looksEncodedPayload(s: string): boolean {
  if (!s) return false;
  const t = s.trim();
  const dataUri = /data:(image|audio|video|application)\/[a-z0-9.+-]*;base64,([A-Za-z0-9+/]+=*)/i.exec(s);
  if (dataUri) {
    const b64 = dataUri[2] ?? "";
    if (b64.length >= GATEWAY_B64_MIN) return true;
    if (MAGIC_B64.some((p) => b64.startsWith(p) && b64.length >= p.length + 24)) return true;
  }
  if (/-----BEGIN PGP (MESSAGE|PRIVATE KEY)-----/.test(s)) return true;
  if (/-----BEGIN ENCRYPTED/.test(s)) return true;
  if (s.includes("Salted__")) return true;
  if (s.includes("\u001f\u008b") || s.includes("PK\u0003\u0004") || s.includes("\u0089PNG") || s.includes("%PDF-")) {
    return true;
  }
  for (const p of MAGIC_B64) {
    const re = new RegExp(`(?:^|[^A-Za-z0-9+/])${p}[A-Za-z0-9+/]{24,}`);
    if (re.test(s)) return true;
  }
  const b64Run = /[A-Za-z0-9+/]{256,}={0,2}/g;
  let bm: RegExpExecArray | null;
  while ((bm = b64Run.exec(s))) {
    if (isMixedB64(bm[0])) return true;
  }
  const hexRun = /[0-9a-fA-F]{256,}/g;
  let hm: RegExpExecArray | null;
  while ((hm = hexRun.exec(s))) {
    if (hm[0].length % 2 !== 0) continue;
    if (/^(.)\1+$/.test(hm[0])) continue;
    if (/\d/.test(hm[0]) && /[a-fA-F]/.test(hm[0])) return true;
  }
  const compact = t.replace(/\s+/g, "");
  if (compact.length >= GATEWAY_B64_MIN && isMixedB64(compact)) return true;
  if (compact.length >= GATEWAY_B64_MIN && /^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && !/^(.)\1+$/.test(compact)) {
    return /\d/.test(compact) && /[a-fA-F]/.test(compact);
  }
  return false;
}

function isMixedB64(run: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(run)) return false;
  const body = run.replace(/=+$/, "");
  if (body.length < GATEWAY_B64_MIN) return false;
  if (/^(.)\1+$/.test(body)) return false;
  return /\d/.test(body) || /[+/]/.test(body) || (/[A-Z]/.test(body) && /[a-z]/.test(body));
}

export function looksBinaryString(s: string): boolean {
  let ctrl = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c === 0) return true;
    if (c < 32 && c !== 9 && c !== 10 && c !== 13) {
      ctrl += 1;
      if (ctrl >= 8) return true;
    }
  }
  return false;
}

export type InspectTapNote = {
  path: string;
  reason: string;
  kind?: string;
  sampleLen?: number;
  ident?: string;
};

export type InspectTap = (note: InspectTapNote) => void;

interface WalkState {
  nodes: number;
  redacted: boolean;
  piiKinds: string[];
  tap?: InspectTap;
  path: string;
}

function tap(state: WalkState, reason: string, extra?: { kind?: string; sampleLen?: number; ident?: string }): void {
  state.tap?.({
    path: state.path || "root",
    reason,
    kind: extra?.kind,
    sampleLen: extra?.sampleLen,
    ident: extra?.ident,
  });
}

function identForTap(k: string): string | undefined {
  if (!KNOWN_PROTOCOL_FIELDS.has(k)) return undefined;
  if (scanGatewaySecrets(k).length) return undefined;
  if (!/^[A-Za-z][A-Za-z0-9_]{0,40}$/.test(k)) return undefined;
  return k;
}

function withPath<T>(state: WalkState, path: string, fn: () => T): T {
  const prev = state.path;
  state.path = path;
  try {
    return fn();
  } finally {
    state.path = prev;
  }
}

function bump(state: WalkState): void {
  state.nodes += 1;
  if (state.nodes > GATEWAY_MAX_NODES) deny("nested_too_deep");
}

function inspectKey(k: string, state: WalkState): void {
  if (typeof k !== "string" || k.length > 256) deny("protocol_unsupported", "unknown_field");
  if (looksBinaryString(k)) deny("binary_denied");
  if (scanGatewaySecrets(k).length) {
    tap(state, "secret_blocked", { kind: "key", sampleLen: k.length });
    deny("secret_blocked");
  }
  if (looksEncodedPayload(k)) {
    tap(state, "encoded_payload", { kind: encodedKind(k), sampleLen: k.length });
    deny("encoded_payload");
  }
}

function walkString(s: string, state: WalkState): string {
  if (s.length > GATEWAY_MAX_STRING) deny("body_too_large");
  if (looksBinaryString(s)) deny("binary_denied");
  const hits = scanGatewaySecrets(s);
  const cred = hits.filter((h) => !PII_KINDS.has(h.kind));
  if (cred.length) {
    tap(state, "secret_blocked", { kind: cred[0]?.kind, sampleLen: s.length });
    deny("secret_blocked");
  }
  if (looksEncodedPayload(s)) {
    tap(state, "encoded_payload", { kind: encodedKind(s), sampleLen: s.length });
    deny("encoded_payload");
  }
  const pii = hits.filter((h) => PII_KINDS.has(h.kind));
  if (!pii.length) return s;
  state.redacted = true;
  for (const h of pii) {
    if (!state.piiKinds.includes(h.kind)) state.piiKinds.push(h.kind);
  }
  return paintGateway(s, pii, REDACT_TAG);
}

function walkJson(val: unknown, depth: number, state: WalkState): unknown {
  if (depth > GATEWAY_MAX_DEPTH) deny("nested_too_deep");
  bump(state);
  if (val === null || typeof val === "boolean") return val;
  if (typeof val === "number") {
    if (!Number.isFinite(val)) deny("malformed");
    const asText = String(val);
    const hits = scanGatewaySecrets(asText);
    if (hits.some((h) => !PII_KINDS.has(h.kind))) deny("secret_blocked");
    if (hits.some((h) => PII_KINDS.has(h.kind))) deny("secret_blocked");
    return val;
  }
  if (typeof val === "string") return walkString(val, state);
  if (Array.isArray(val)) {
    if (val.length > GATEWAY_MAX_NODES) deny("nested_too_deep");
    const parentPath = state.path;
    return val.map((item, i) => withPath(state, `${parentPath}[${i}]`, () => walkJson(item, depth + 1, state)));
  }
  if (!isPlain(val)) deny("protocol_unsupported");
  if (val.type === "Buffer" && Array.isArray(val.data)) deny("binary_denied");
  for (const k of Object.keys(val)) {
    if (k === "__proto__" || k === "prototype" || k === "constructor") deny("protocol_unsupported");
  }
  const out: Record<string, unknown> = {};
  const parentPath = state.path;
  for (const [k, v] of Object.entries(val)) {
    out[k] = withPath(state, `${parentPath}.${publicProtocolField(k)}`, () => {
      inspectKey(k, state);
      return walkJson(v, depth + 1, state);
    });
  }
  return out;
}

function inspectFunctionArguments(raw: string, state: WalkState): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    deny("protocol_unsupported");
  }
  const parentPath = state.path;
  const walked = withPath(state, `${parentPath}.arguments`, () => walkJson(parsed, 0, state));
  return JSON.stringify(walked);
}

function expectFiniteNumber(v: unknown, key: string): number {
  if (typeof v !== "number" || !Number.isFinite(v)) deny("protocol_unsupported");
  void key;
  return v;
}

function inspectContent(content: unknown, role: string, state: WalkState): unknown {
  if (content === null) {
    if (role !== "assistant") deny("protocol_unsupported");
    return null;
  }
  if (typeof content === "string") return walkString(content, state);
  if (!Array.isArray(content)) deny("protocol_unsupported");
  if (content.length > GATEWAY_MAX_PARTS) deny("nested_too_deep");
  return content.map((part) => {
    if (!isPlain(part)) deny("protocol_unsupported");
    const keys = Object.keys(part);
    for (const k of keys) {
      if (k !== "type" && k !== "text") deny("protocol_unsupported");
    }
    if (part.type !== "text" || typeof part.text !== "string") deny("protocol_unsupported");
    return { type: "text", text: walkString(part.text, state) };
  });
}

function inspectToolCalls(raw: unknown, state: WalkState): unknown {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > GATEWAY_MAX_TOOL_CALLS) deny("protocol_unsupported");
  return raw.map((item) => {
    if (!isPlain(item)) deny("protocol_unsupported");
    for (const k of Object.keys(item)) {
      if (k !== "id" && k !== "type" && k !== "function") deny("protocol_unsupported");
    }
    if (typeof item.id !== "string" || item.type !== "function" || !isPlain(item.function)) {
      deny("protocol_unsupported");
    }
    const fn = item.function;
    for (const k of Object.keys(fn)) {
      if (k !== "name" && k !== "arguments") deny("protocol_unsupported");
    }
    if (typeof fn.name !== "string" || typeof fn.arguments !== "string") deny("protocol_unsupported");
    if (!fn.name || fn.name.length > 128) deny("protocol_unsupported");
    return {
      id: walkString(item.id, state),
      type: "function",
      function: {
        name: walkString(fn.name, state),
        arguments: inspectFunctionArguments(fn.arguments, state),
      },
    };
  });
}

function inspectMessage(raw: unknown, state: WalkState): Record<string, unknown> {
  if (!isPlain(raw)) deny("protocol_unsupported");
  for (const k of Object.keys(raw)) {
    if (!MESSAGE_KEYS.has(k) || BLOCKED_KEYS.has(k)) {
      tap(state, "protocol_unsupported", { kind: "unknown_field", ident: identForTap(k) });
      deny("protocol_unsupported", "unknown_field");
    }
  }
  if (typeof raw.role !== "string" || !ROLES.has(raw.role)) deny("protocol_unsupported");
  const role = raw.role;
  const out: Record<string, unknown> = { role };
  if (role === "tool") {
    if (typeof raw.tool_call_id !== "string" || !raw.tool_call_id) deny("protocol_unsupported");
    if (typeof raw.content !== "string") deny("protocol_unsupported");
    out.tool_call_id = walkString(raw.tool_call_id, state);
    out.content = walkString(raw.content, state);
    if (raw.name !== undefined) {
      if (typeof raw.name !== "string") deny("protocol_unsupported");
      out.name = walkString(raw.name, state);
    }
    if (raw.tool_calls !== undefined) deny("protocol_unsupported");
    return out;
  }
  if (raw.tool_call_id !== undefined) deny("protocol_unsupported");
  if (role === "assistant") {
    if (raw.tool_calls !== undefined) out.tool_calls = inspectToolCalls(raw.tool_calls, state);
    if (raw.content !== undefined) out.content = inspectContent(raw.content, role, state);
    else if (!raw.tool_calls) deny("protocol_unsupported");
  } else {
    if (raw.tool_calls !== undefined) deny("protocol_unsupported");
    if (raw.content === undefined) deny("protocol_unsupported");
    out.content = inspectContent(raw.content, role, state);
  }
  if (raw.name !== undefined) {
    if (typeof raw.name !== "string") deny("protocol_unsupported");
    out.name = walkString(raw.name, state);
  }
  return out;
}

function inspectTools(raw: unknown, state: WalkState): unknown {
  if (!Array.isArray(raw) || raw.length > GATEWAY_MAX_TOOLS) deny("protocol_unsupported");
  const parentPath = state.path;
  return raw.map((item, i) =>
    withPath(state, `${parentPath}[${i}]`, () => {
      if (!isPlain(item)) deny("protocol_unsupported");
      for (const k of Object.keys(item)) {
        if (k !== "type" && k !== "function") deny("protocol_unsupported");
      }
      if (item.type !== "function" || !isPlain(item.function)) deny("protocol_unsupported");
      const fn = item.function;
      for (const k of Object.keys(fn)) {
        if (k !== "name" && k !== "description" && k !== "parameters" && k !== "strict") {
          deny("protocol_unsupported");
        }
      }
      if (typeof fn.name !== "string" || !fn.name || fn.name.length > 128) deny("protocol_unsupported");
      const fnName = fn.name;
      const itemPath = state.path;
      const outFn: Record<string, unknown> = {
        name: withPath(state, `${itemPath}.function.name`, () => walkString(fnName, state)),
      };
      if (fn.description !== undefined) {
        if (typeof fn.description !== "string") deny("protocol_unsupported");
        const fnDesc = fn.description;
        outFn.description = withPath(state, `${itemPath}.function.description`, () => walkString(fnDesc, state));
      }
      if (fn.parameters !== undefined) {
        if (!isPlain(fn.parameters) && !Array.isArray(fn.parameters)) deny("protocol_unsupported");
        outFn.parameters = withPath(state, `${itemPath}.function.parameters`, () => walkJson(fn.parameters, 0, state));
      }
      if (fn.strict !== undefined) {
        if (typeof fn.strict !== "boolean") deny("protocol_unsupported");
        outFn.strict = fn.strict;
      }
      return { type: "function", function: outFn };
    }),
  );
}

function inspectToolChoice(raw: unknown, state: WalkState): unknown {
  if (typeof raw === "string") {
    if (raw !== "none" && raw !== "auto" && raw !== "required") deny("protocol_unsupported");
    return raw;
  }
  if (!isPlain(raw)) deny("protocol_unsupported");
  for (const k of Object.keys(raw)) {
    if (k !== "type" && k !== "function") deny("protocol_unsupported");
  }
  if (raw.type !== "function" || !isPlain(raw.function)) deny("protocol_unsupported");
  if (typeof raw.function.name !== "string") deny("protocol_unsupported");
  for (const k of Object.keys(raw.function)) {
    if (k !== "name") deny("protocol_unsupported");
  }
  return { type: "function", function: { name: walkString(raw.function.name, state) } };
}

function inspectChatObject(root: Record<string, unknown>, state: WalkState): Record<string, unknown> {
  for (const k of Object.keys(root)) {
    if (!TOP_KEYS.has(k) || BLOCKED_KEYS.has(k)) {
      tap(state, "protocol_unsupported", { kind: "unknown_field", ident: identForTap(k) });
      deny("protocol_unsupported", "unknown_field");
    }
  }
  if (typeof root.model !== "string" || !root.model || root.model.length > 256) deny("protocol_unsupported");
  const modelName = root.model;
  if (!Array.isArray(root.messages) || root.messages.length === 0 || root.messages.length > GATEWAY_MAX_MESSAGES) {
    deny("protocol_unsupported");
  }
  const out: Record<string, unknown> = {
    model: withPath(state, "model", () => walkString(modelName, state)),
    messages: root.messages.map((m, i) => withPath(state, `messages[${i}]`, () => inspectMessage(m, state))),
  };
  if (root.tools !== undefined) out.tools = withPath(state, "tools", () => inspectTools(root.tools, state));
  if (root.tool_choice !== undefined) out.tool_choice = inspectToolChoice(root.tool_choice, state);
  if (root.parallel_tool_calls !== undefined) {
    if (typeof root.parallel_tool_calls !== "boolean") deny("protocol_unsupported");
    out.parallel_tool_calls = root.parallel_tool_calls;
  }
  if (root.stream !== undefined) {
    if (typeof root.stream !== "boolean") deny("protocol_unsupported");
    out.stream = root.stream;
  }
  if (root.stream_options !== undefined) {
    if (!isPlain(root.stream_options)) deny("protocol_unsupported");
    for (const k of Object.keys(root.stream_options)) {
      if (k !== "include_usage") deny("protocol_unsupported");
    }
    if (root.stream_options.include_usage !== undefined && typeof root.stream_options.include_usage !== "boolean") {
      deny("protocol_unsupported");
    }
    out.stream_options = { ...root.stream_options };
  }
  for (const k of ["temperature", "top_p", "n", "max_tokens", "max_completion_tokens", "presence_penalty", "frequency_penalty", "seed"] as const) {
    if (root[k] !== undefined) out[k] = expectFiniteNumber(root[k], k);
  }
  if (root.stop !== undefined) {
    if (typeof root.stop === "string") out.stop = walkString(root.stop, state);
    else if (Array.isArray(root.stop) && root.stop.length <= 8 && root.stop.every((x) => typeof x === "string")) {
      out.stop = root.stop.map((s) => walkString(s, state));
    } else deny("protocol_unsupported");
  }
  if (root.user !== undefined) {
    if (typeof root.user !== "string") deny("protocol_unsupported");
    out.user = walkString(root.user, state);
  }
  if (root.response_format !== undefined) {
    if (!isPlain(root.response_format)) deny("protocol_unsupported");
    const keys = Object.keys(root.response_format);
    if (keys.length !== 1 || keys[0] !== "type") deny("protocol_unsupported");
    const t = root.response_format.type;
    if (t !== "text" && t !== "json_object") deny("protocol_unsupported");
    out.response_format = { type: t };
  }
  if (root.stream_tool_calls !== undefined) {
    if (typeof root.stream_tool_calls !== "boolean") deny("protocol_unsupported", "stream_tool_calls");
    out.stream_tool_calls = root.stream_tool_calls;
  }
  if (root.reasoning_effort !== undefined) {
    if (typeof root.reasoning_effort === "string") {
      if (!root.reasoning_effort || root.reasoning_effort.length > 32) deny("protocol_unsupported", "reasoning_effort");
      out.reasoning_effort = walkString(root.reasoning_effort, state);
    } else if (typeof root.reasoning_effort === "number" && Number.isFinite(root.reasoning_effort)) {
      out.reasoning_effort = root.reasoning_effort;
    } else deny("protocol_unsupported", "reasoning_effort");
  }
  if (root.logprobs !== undefined) {
    if (typeof root.logprobs !== "boolean") deny("protocol_unsupported", "logprobs");
    out.logprobs = root.logprobs;
  }
  if (root.top_logprobs !== undefined) out.top_logprobs = expectFiniteNumber(root.top_logprobs, "top_logprobs");
  if (root.store !== undefined) {
    if (typeof root.store !== "boolean") deny("protocol_unsupported", "store");
    out.store = root.store;
  }
  if (root.prompt_cache_key !== undefined) {
    if (typeof root.prompt_cache_key !== "string") deny("protocol_unsupported", "prompt_cache_key");
    out.prompt_cache_key = walkString(root.prompt_cache_key, state);
  }
  if (root.logit_bias !== undefined) {
    if (!isPlain(root.logit_bias)) deny("protocol_unsupported", "logit_bias");
    const bias: Record<string, number> = {};
    for (const [k, v] of Object.entries(root.logit_bias)) {
      withPath(state, "logit_bias", () => inspectKey(k, state));
      bias[k] = expectFiniteNumber(v, "logit_bias");
    }
    out.logit_bias = bias;
  }
  return out;
}

export type InspectOk = {
  ok: true;
  payload: Record<string, unknown>;
  stream: boolean;
  redacted: boolean;
  piiKinds: string[];
};

export type InspectDeny = {
  ok: false;
  code: string;
  field?: string;
};

export type InspectResult = InspectOk | InspectDeny;

export function inspectModelPayload(route: string, raw: string, tapFn?: InspectTap): InspectResult {
  if (!IMPLEMENTED_MODEL_ROUTES.has(route)) return { ok: false, code: "protocol_unsupported" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, code: "malformed" };
  }
  if (!isPlain(parsed)) return { ok: false, code: "malformed" };
  const state: WalkState = { nodes: 0, redacted: false, piiKinds: [], tap: tapFn, path: "root" };
  try {
    const payload = inspectChatObject(parsed, state);
    const blob = JSON.stringify(payload);
    if (scanGatewaySecrets(blob).length) return { ok: false, code: "secret_blocked" };
    return {
      ok: true,
      payload,
      stream: payload.stream === true,
      redacted: state.redacted,
      piiKinds: state.piiKinds,
    };
  } catch (e) {
    if (e instanceof Deny) return { ok: false, code: e.code, field: publicProtocolField(e.field) };
    return { ok: false, code: "malformed" };
  }
}

export function isModelGatewayRoute(path: string): path is ModelGatewayRoute {
  return (MODEL_GATEWAY_ROUTES as readonly string[]).includes(path);
}
