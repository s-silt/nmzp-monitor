/**
 * Canonical Protocol v1 adapter (WP-21a). Pure functions, no I/O.
 *
 * D8 (coordinator): CanonicalToolEvent stores the host's exact field strings
 * (no trim). The v2→engine bridge applies v1 `str()` semantics (trim; whitespace
 * is missing) when building EvalInput, so v1 and v2 decisions match. Samples
 * where the exact string differs from the trimmed result are recorded in tests
 * as IC observations and do not change decisions.
 */
import { createHash } from "node:crypto";
import { BODY_LIMIT } from "../constants.ts";
import { deny, pass } from "../hook.ts";
import {
  ALIAS_CONFLICT,
  COMMAND_KEYS,
  CONTENT_KEYS,
  CWD_KEYS,
  DEST_KEYS,
  detectHookAgent,
  FILE_PATH_KEYS,
  formatHookResponse,
  objectsConflict,
  parseHookEvent,
  pickDefinedSame,
  remapAntigravityArgs,
  toolInputHasAliasConflict,
  toolInputToEvalFields,
  URL_KEYS,
  type HookAgent,
  type ParsedHook,
} from "../hook-protocol.ts";
import type { EvalInput, EvalResult } from "../../src/lib/monitor/engine.ts";

export const ADAPTER_BODY_LIMIT = BODY_LIMIT;
export const MAX_CONTAINER_DEPTH = 64;
export const MAX_EXTRA_FIELDS = 256;
export const MAX_POINTER_UTF8 = 1024;
export const MAX_EVENT_ID_UTF16 = 128;

/** v2 canonical field only. hook-protocol does not score `query` as an eval alias. */
const QUERY_KEYS = ["query"] as const;

/**
 * Copied from contract/protocol/native-kind-map.json canonicalKind.
 * Stays in core/: the hook fast path copies only core/ and must not read contract/ at runtime.
 */
export const CANONICAL_KIND = {
  Bash: "SHELL",
  Read: "FILE_READ",
  Glob: "FILE_READ",
  Grep: "FILE_READ",
  Write: "FILE_WRITE",
  Edit: "FILE_EDIT",
  MultiEdit: "FILE_EDIT",
  WebFetch: "WEB_FETCH",
  WebSearch: "WEB_SEARCH",
  Task: "UNKNOWN",
  Skill: "UNKNOWN",
  MCP: "MCP",
} as const;

/** Copied from native-kind-map.json nativeCanonical (source: agents.ts NATIVE_TOOL_MAP). Same in-core constraint. */
export const NATIVE_CANONICAL: Record<string, keyof typeof CANONICAL_KIND> = {
  bash: "Bash",
  shell: "Bash",
  shell_command: "Bash",
  exec_command: "Bash",
  run_terminal_command: "Bash",
  run_command: "Bash",
  read: "Read",
  view_file: "Read",
  list_dir: "Glob",
  find_by_name: "Glob",
  read_file: "Read",
  write: "Write",
  write_file: "Write",
  write_to_file: "Write",
  edit: "Edit",
  edit_file: "Edit",
  replace_file_content: "Edit",
  multi_replace_file_content: "MultiEdit",
  apply_patch: "Edit",
  strreplace: "Edit",
  str_replace: "Edit",
  search_replace: "Edit",
  multiedit: "MultiEdit",
  glob: "Glob",
  grep: "Grep",
  grep_search: "Grep",
  webfetch: "WebFetch",
  read_url_content: "WebFetch",
  websearch: "WebSearch",
  search_web: "WebSearch",
  search_x: "WebSearch",
  web_search: "WebSearch",
  task: "Task",
  agent: "Task",
  delegate: "Task",
  spawn_subagent: "Task",
  invoke_subagent: "Task",
  skill: "Skill",
  runcommand: "Bash",
  run_shell_command: "Bash",
  run_in_terminal: "Bash",
  create_file: "Write",
  replace: "Edit",
  delete: "Bash",
  fetchurl: "WebFetch",
  web_fetch: "WebFetch",
  google_web_search: "WebSearch",
  list_directory: "Glob",
  read_many_files: "Read",
  invoke_agent: "Task",
};

const FAILURE_CLASS_ERROR = {
  over_limit: "payload_too_large",
  canonical_over_limit: "payload_too_large",
  invalid_utf8: "invalid_utf8",
  json_syntax: "bad_json",
  unpaired_surrogate: "lone_surrogate",
  duplicate_member: "duplicate_member",
  incoming_truncation: "input_truncated",
  depth_exceeded: "depth_exceeded",
  extras_exceeded: "extras_exceeded",
  pointer_too_long: "pointer_too_long",
  event_id_invalid: "event_id_invalid",
} as const;

export type FailureClass = keyof typeof FAILURE_CLASS_ERROR;
export type AdapterErrorCode = (typeof FAILURE_CLASS_ERROR)[FailureClass];

export type CanonicalFieldName = "command" | "cwd" | "filePath" | "url" | "dest" | "contents" | "query";
export type ToolKind = (typeof CANONICAL_KIND)[keyof typeof CANONICAL_KIND];

export interface CanonicalField {
  value: string;
  provenance: string;
}

export interface CanonicalToolEvent {
  v: 1;
  eventId: string;
  occurredAt: string;
  device: { id: string };
  host: { id: string; version: string | null; adapterRevision: number };
  session: { id: string | null; model: string | null };
  tool: { kind: ToolKind; nativeName: string };
  fields: Partial<Record<CanonicalFieldName, CanonicalField>>;
  extraFields: Array<{ path: string; value: string }>;
  rawPayloadHash: string;
  context: { proc: string | null; parentProc: string | null; hookBlind: boolean };
  origin: "HOOK" | "PROBE" | "BACKFILL";
}

export interface AdapterParseFailure {
  kind: "adapter_parse_failure";
  localAction: "DENY";
  errorCode: AdapterErrorCode;
  failureClass: FailureClass;
  completenessProven: false;
  channel?: "raw_stdin" | "canonical_request";
  incomingFlags?: Array<"toolInputTruncated" | "tool_input_truncated">;
  where?: "member_name" | "value";
  surrogate?: "lone_high" | "lone_low";
  decodedKey?: string;
  containerDepth?: number;
  pointerUtf8?: number;
  extraCount?: number;
}

export interface AdapterContext {
  agentFlag?: string;
  eventId: string;
  occurredAt: string;
  deviceId: string;
  adapterRevision: number;
}

export interface AdapterHostMeta {
  agent: HookAgent | "unknown";
  argMap?: Record<string, string>;
  toolInput: Record<string, unknown>;
  parsed: ParsedHook;
}

export type ParseEventResult =
  | { ok: true; event: CanonicalToolEvent; aliasConflict: boolean; host: AdapterHostMeta }
  | { ok: false; failure: AdapterParseFailure };

export type CanonicalAction = "ALLOW" | "LOG" | "ASK" | "BLOCK" | "REWRITE";
export type RewriteStatus = "NONE" | "APPLIED" | "NOOP_NO_SPAN" | "REFUSED";

export interface CanonicalRewrite {
  patches: Array<{
    field: CanonicalFieldName;
    span: [number, number];
    kind: string;
    replacement: string;
    originalHash: string;
  }>;
  rendererRevision: number;
  baseInputHash: string;
  resultInputHash: string;
  validation: { residueScan: "PASS"; shellStructure: "PASS" | "N_A"; urlParse: "PASS" | "N_A" };
  updatedFields: Partial<Record<CanonicalFieldName, string>>;
}

export interface CanonicalDecision {
  v: 1;
  eventId: string;
  action: CanonicalAction;
  reasonCode: string;
  ruleIds: string[];
  risk: "none" | "low" | "medium" | "high" | "critical";
  family: string | null;
  policy: { version: number; rulesHash: string };
  engineRevision: number;
  origin: "SERVER" | "OFFLINE_CACHE" | "FAIL_CLOSED";
  privacy: {
    findings: Array<{ category: string; kind: string; field: string; action: string }>;
    rewriteStatus: RewriteStatus;
  };
  rewrite?: CanonicalRewrite;
  explain: Array<{ layer: string; result: string; reasonCode?: string; ruleIds?: string[] }>;
  userMessage: string;
}

export type RewriteBridge =
  | { status: "APPLIED"; updatedInput: Record<string, unknown>; updatedFields: Partial<Record<CanonicalFieldName, string>> }
  | { status: "NOOP_NO_SPAN" }
  | { status: "REFUSED"; reason: string };

const REASON_CODE = /^[a-z][a-z0-9_:]{0,127}$/;

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** v1 `str()`: trim, and treat whitespace as missing. */
export function v1Str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function utf8Bytes(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

export function sha256Prefixed(text: string): string {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

export function encodePointerToken(token: string): string {
  return token.replaceAll("~", "~0").replaceAll("/", "~1");
}

export function encodePointer(tokens: string[]): string {
  return tokens.map((token) => `/${encodePointerToken(token)}`).join("");
}

function pointerTokens(pointer: string): string[] {
  if (!pointer.startsWith("/")) return [];
  return pointer.split("/").slice(1).map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
}

export function kindForNativeName(nativeName: string): ToolKind {
  const key = nativeName.toLowerCase();
  if (key.startsWith("mcp__")) return "MCP";
  const canonical = NATIVE_CANONICAL[key];
  if (!canonical) return "UNKNOWN";
  return CANONICAL_KIND[canonical];
}

export function adapterFailure(failureClass: FailureClass, extra: Partial<AdapterParseFailure> = {}): AdapterParseFailure {
  return {
    kind: "adapter_parse_failure",
    localAction: "DENY",
    errorCode: FAILURE_CLASS_ERROR[failureClass],
    failureClass,
    completenessProven: false,
    channel: "raw_stdin",
    ...extra,
  };
}

function unpairedKind(text: string): "lone_high" | "lone_low" | null {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return "lone_high";
      i += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return "lone_low";
  }
  return null;
}

function rejectUnpaired(value: unknown): AdapterParseFailure | null {
  if (typeof value === "string") {
    const kind = unpairedKind(value);
    if (kind) return adapterFailure("unpaired_surrogate", { where: "value", surrogate: kind });
    return null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = rejectUnpaired(item);
      if (hit) return hit;
    }
    return null;
  }
  if (isPlain(value)) {
    for (const [key, child] of Object.entries(value)) {
      const keyKind = unpairedKind(key);
      if (keyKind) return adapterFailure("unpaired_surrogate", { where: "member_name", surrogate: keyKind });
      const hit = rejectUnpaired(child);
      if (hit) return hit;
    }
  }
  return null;
}

export function containerDepth(value: unknown): number {
  if (isPlain(value)) {
    let nested = 0;
    for (const child of Object.values(value)) nested = Math.max(nested, containerDepth(child));
    return 1 + nested;
  }
  if (Array.isArray(value)) {
    let nested = 0;
    for (const child of value) nested = Math.max(nested, containerDepth(child));
    return 1 + nested;
  }
  return 0;
}

function eventIdProblem(text: string): boolean {
  if (text.length === 0 || text.length > MAX_EVENT_ID_UTF16) return true;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code <= 0x1f || (code >= 0x80 && code <= 0x9f)) return true;
  }
  return false;
}

function truncationFlags(value: Record<string, unknown>): Array<"toolInputTruncated" | "tool_input_truncated"> {
  const fired: Array<"toolInputTruncated" | "tool_input_truncated"> = [];
  if (value.toolInputTruncated === true || value.toolInputTruncated === "true") fired.push("toolInputTruncated");
  if (value.tool_input_truncated === true || value.tool_input_truncated === "true") fired.push("tool_input_truncated");
  return fired;
}

function parseObject(raw: string): Record<string, unknown> | null {
  if (typeof raw !== "string") return null;
  const t = raw.replace(/^\uFEFF+/, "").trim();
  if (!t || t[0] !== "{") return null;
  try {
    const parsed: unknown = JSON.parse(t);
    return isPlain(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function envelopeAliasConflict(obj: Record<string, unknown>): boolean {
  if (isPlain(obj.toolCall)) {
    const args = isPlain(obj.toolCall.args) ? obj.toolCall.args : {};
    const { toolInput, conflict } = remapAntigravityArgs(args);
    return conflict || toolInputHasAliasConflict(toolInput);
  }
  const toolName = pickDefinedSame([v1Str(obj.tool_name), v1Str(obj.toolName), v1Str(obj.tool)]);
  if (toolName === ALIAS_CONFLICT) return true;
  const sessionId = pickDefinedSame([v1Str(obj.session_id), v1Str(obj.sessionId), v1Str(obj.conversation_id)]);
  if (sessionId === ALIAS_CONFLICT) return true;
  const bags = [obj.tool_input, obj.toolInput, obj.input];
  if (objectsConflict(bags)) return true;
  const toolInput = bags.find(isPlain) ?? {};
  if (toolInputHasAliasConflict(toolInput)) return true;
  const eventIdAlias = pickDefinedSame([v1Str(obj.eventId), v1Str(obj.event_id)]);
  if (eventIdAlias === ALIAS_CONFLICT) return true;
  const toolUseId = pickDefinedSame([v1Str(obj.toolUseId), v1Str(obj.tool_use_id), v1Str(obj.tool_call_id)]);
  if (toolUseId === ALIAS_CONFLICT) return true;
  const nestedTool = v1Str(toolInput.tool);
  if (nestedTool && typeof toolName === "string" && nestedTool !== toolName) return false;
  return false;
}

function bagPath(obj: Record<string, unknown>): { bag: Record<string, unknown>; path: string } | null {
  if (isPlain(obj.toolCall) && isPlain(obj.toolCall.args)) return { bag: obj.toolCall.args, path: "/toolCall/args" };
  if (isPlain(obj.tool_input)) return { bag: obj.tool_input, path: "/tool_input" };
  if (isPlain(obj.toolInput)) return { bag: obj.toolInput, path: "/toolInput" };
  if (isPlain(obj.input)) return { bag: obj.input, path: "/input" };
  return { bag: {}, path: "/tool_input" };
}

function firstExactWinner(
  obj: Record<string, unknown>,
  keys: readonly string[],
): { key: string; exact: string } | undefined {
  const trimmed = keys.map((key) => v1Str(obj[key]));
  const picked = pickDefinedSame(trimmed);
  if (picked === ALIAS_CONFLICT || picked === undefined) return undefined;
  for (const key of keys) {
    if (v1Str(obj[key]) === picked && typeof obj[key] === "string") return { key, exact: obj[key] };
  }
  return undefined;
}

function pointerFor(bagPathName: string, key: string, hostArgMap?: Record<string, string>): string {
  const hostKey = hostArgMap?.[key] ?? key;
  return `${bagPathName}${encodePointer([hostKey])}`;
}

function walkStringPaths(
  value: unknown,
  tokens: string[],
  out: Array<{ path: string; value: string }>,
): void {
  if (typeof value === "string") {
    if (tokens.length === 0) return;
    out.push({ path: encodePointer(tokens), value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => walkStringPaths(child, [...tokens, String(index)], out));
    return;
  }
  if (isPlain(value)) {
    for (const [key, child] of Object.entries(value)) walkStringPaths(child, [...tokens, key], out);
  }
}

function longestPointerUtf8(paths: string[]): number {
  let best = 0;
  for (const path of paths) best = Math.max(best, utf8Bytes(path));
  return best;
}

function reasonCodeOf(text: string, fallback: string): string {
  if (REASON_CODE.test(text) && text.length <= 128) return text;
  return fallback;
}

function userMessageFor(action: CanonicalAction, reasonCode: string, rewriteStatus: RewriteStatus): string {
  if (action === "REWRITE") {
    return "NMZP rewrote this call: matched text was replaced with an NMZP_REDACTED placeholder. Do not restore the original.";
  }
  if (action === "BLOCK") {
    return `NMZP blocked this call: ${reasonCode}. This action is not allowed by policy; do not retry it in another form.`;
  }
  if (action === "ASK") {
    return `NMZP requires a decision: ${reasonCode}. This action is not allowed until reviewed.`;
  }
  if (action === "LOG" && rewriteStatus === "NOOP_NO_SPAN") {
    return "NMZP logged this call: a rewrite was requested but no span was applied.";
  }
  if (action === "LOG") return `NMZP logged this call: ${reasonCode}.`;
  return `NMZP allowed this call: ${reasonCode}.`;
}

function mapRisk(risk: EvalResult["risk"]): CanonicalDecision["risk"] {
  if (risk === "info") return "none";
  if (risk === "high" || risk === "medium" || risk === "low") return risk;
  return "none";
}

function dummyHash(): string {
  return sha256Prefixed("");
}

/**
 * Parse a host stdin string into CanonicalToolEvent. Alias conflicts are not
 * merged: they yield a successful event plus `aliasConflict: true` (BLOCK
 * conflicting_aliases), matching eval-bridge rather than collapsing values.
 */
export function toCanonicalToolEvent(raw: string, ctx: AdapterContext): ParseEventResult {
  if (typeof raw !== "string") return { ok: false, failure: adapterFailure("json_syntax") };
  if (utf8Bytes(raw) > ADAPTER_BODY_LIMIT) return { ok: false, failure: adapterFailure("over_limit") };

  const obj = parseObject(raw);
  if (!obj) return { ok: false, failure: adapterFailure("json_syntax") };

  const unpaired = rejectUnpaired(obj);
  if (unpaired) return { ok: false, failure: unpaired };

  const depth = containerDepth(obj);
  if (depth > MAX_CONTAINER_DEPTH) return { ok: false, failure: adapterFailure("depth_exceeded", { containerDepth: depth }) };

  const flags = truncationFlags(obj);
  if (flags.length) {
    return { ok: false, failure: adapterFailure("incoming_truncation", { incomingFlags: flags }) };
  }

  const parsed = parseHookEvent(raw);
  const conflict = envelopeAliasConflict(obj);
  if (!parsed && !conflict) return { ok: false, failure: adapterFailure("json_syntax") };

  let toolName: string;
  let toolInput: Record<string, unknown>;
  let hostArgMap: Record<string, string> | undefined;
  let sessionId: string | undefined;
  let eventId: string;
  let agent: HookAgent | "unknown";
  let parsedHook: ParsedHook;

  if (parsed) {
    toolName = parsed.toolName;
    toolInput = parsed.toolInput;
    hostArgMap = parsed.hostArgMap;
    sessionId = parsed.sessionId;
    eventId = parsed.eventId || ctx.eventId;
    agent = detectHookAgent(ctx.agentFlag, parsed);
    parsedHook = parsed;
  } else {
    if (isPlain(obj.toolCall)) {
      const name = v1Str(obj.toolCall.name);
      if (!name) return { ok: false, failure: adapterFailure("json_syntax") };
      const args = isPlain(obj.toolCall.args) ? obj.toolCall.args : {};
      const remapped = remapAntigravityArgs(args);
      toolName = name;
      toolInput = remapped.toolInput;
      hostArgMap = remapped.hostArgMap;
      const conversationId = v1Str(obj.conversationId);
      sessionId = conversationId;
      eventId =
        conversationId && typeof obj.stepIdx === "number" ? `${conversationId}:${obj.stepIdx}` : ctx.eventId;
    } else {
      const name = pickDefinedSame([v1Str(obj.tool_name), v1Str(obj.toolName), v1Str(obj.tool)]);
      if (name === ALIAS_CONFLICT || !name) {
        const bags = [obj.tool_input, obj.toolInput, obj.input];
        toolInput = bags.find(isPlain) ?? {};
        toolName = typeof obj.tool_name === "string" ? obj.tool_name : typeof obj.toolName === "string" ? obj.toolName : "unknown";
      } else {
        toolName = name;
        const bags = [obj.tool_input, obj.toolInput, obj.input];
        toolInput = bags.find(isPlain) ?? {};
      }
      const sid = pickDefinedSame([v1Str(obj.session_id), v1Str(obj.sessionId), v1Str(obj.conversation_id)]);
      sessionId = sid === ALIAS_CONFLICT ? undefined : sid;
      const eventIdAlias = pickDefinedSame([v1Str(obj.eventId), v1Str(obj.event_id)]);
      const toolUseId = pickDefinedSame([v1Str(obj.toolUseId), v1Str(obj.tool_use_id), v1Str(obj.tool_call_id)]);
      eventId =
        (eventIdAlias !== ALIAS_CONFLICT ? eventIdAlias : undefined) ??
        (toolUseId !== ALIAS_CONFLICT ? toolUseId : undefined) ??
        ctx.eventId;
    }
    const stub: ParsedHook = {
      agentHint: undefined,
      eventName: v1Str(obj.hook_event_name) ?? v1Str(obj.hookEventName) ?? v1Str(obj.event) ?? "PreToolUse",
      toolName,
      toolInput,
      sessionId,
      eventId,
      rawKeys: Object.keys(obj),
      hostArgMap,
    };
    parsedHook = stub;
    agent = detectHookAgent(ctx.agentFlag, stub);
  }

  if (eventIdProblem(eventId) || eventIdProblem(ctx.eventId)) {
    return { ok: false, failure: adapterFailure("event_id_invalid") };
  }

  const bag = bagPath(obj);
  const bagPathName = bag?.path ?? "/tool_input";
  const fields: CanonicalToolEvent["fields"] = {};
  const mapped = new Set<string>();

  const take = (name: CanonicalFieldName, keys: readonly string[], exactBag: Record<string, unknown>, pathPrefix: string) => {
    const winner = firstExactWinner(exactBag, keys);
    if (!winner) return;
    const provenance = pointerFor(pathPrefix === bagPathName && hostArgMap ? bagPathName : pathPrefix, winner.key, hostArgMap);
    fields[name] = { value: winner.exact, provenance };
    mapped.add(provenance);
    for (const key of keys) {
      if (typeof exactBag[key] === "string") mapped.add(pointerFor(pathPrefix, key, hostArgMap));
    }
  };

  take("command", COMMAND_KEYS, toolInput, bagPathName);
  take("filePath", FILE_PATH_KEYS, toolInput, bagPathName);
  take("url", URL_KEYS, toolInput, bagPathName);
  take("dest", DEST_KEYS, toolInput, bagPathName);
  take("query", QUERY_KEYS, toolInput, bagPathName);

  const toolCwd = firstExactWinner(toolInput, CWD_KEYS);
  if (toolCwd) {
    const provenance = pointerFor(bagPathName, toolCwd.key, hostArgMap);
    fields.cwd = { value: toolCwd.exact, provenance };
    mapped.add(provenance);
    for (const key of CWD_KEYS) {
      if (typeof toolInput[key] === "string") mapped.add(pointerFor(bagPathName, key, hostArgMap));
    }
  } else {
    // v1 order: str(cwd) ?? str(workspaceRoot) ?? str(workspace_roots[0]); first non-blank wins.
    const candidates: Array<{ value: unknown; provenance: string }> = [
      { value: obj.cwd, provenance: "/cwd" },
      { value: obj.workspaceRoot, provenance: "/workspaceRoot" },
      { value: Array.isArray(obj.workspace_roots) ? obj.workspace_roots[0] : undefined, provenance: "/workspace_roots/0" },
      { value: Array.isArray(obj.workspacePaths) ? obj.workspacePaths[0] : undefined, provenance: "/workspacePaths/0" },
      {
        value: isPlain(obj.toolCall) && isPlain(obj.toolCall.args) ? obj.toolCall.args.Cwd : undefined,
        provenance: "/toolCall/args/Cwd",
      },
    ];
    for (const candidate of candidates) {
      if (typeof candidate.value !== "string") continue;
      mapped.add(candidate.provenance);
      if (v1Str(candidate.value)) {
        fields.cwd = { value: candidate.value, provenance: candidate.provenance };
        break;
      }
    }
  }

  const v1Fields = toolInputToEvalFields(toolName, toolInput);
  if (v1Fields.contents) {
    const bagTokens = pointerTokens(bagPathName);
    const scanLeaves: Array<{ path: string; value: string }> = [];
    walkStringPaths(toolInput, bagTokens, scanLeaves);
    for (const key of CONTENT_KEYS) {
      if (typeof toolInput[key] === "string") mapped.add(pointerFor(bagPathName, key, hostArgMap));
    }
    if (Array.isArray(toolInput.edits)) {
      toolInput.edits.forEach((row, index) => {
        if (!isPlain(row)) return;
        for (const key of CONTENT_KEYS) {
          if (typeof row[key] === "string") mapped.add(`${bagPathName}/edits/${index}${encodePointer([key])}`);
        }
      });
    }
    const contributor = scanLeaves.find((leaf) => {
      const trimmed = v1Str(leaf.value);
      return trimmed !== undefined && v1Fields.contents!.includes(trimmed);
    });
    if (contributor) mapped.add(contributor.path);
    fields.contents = { value: v1Fields.contents, provenance: contributor?.path ?? `${bagPathName}/contents` };
    mapped.add(fields.contents.provenance);
  }

  if (typeof toolName === "string") {
    if (isPlain(obj.toolCall) && typeof obj.toolCall.name === "string") mapped.add("/toolCall/name");
    else if (typeof obj.tool_name === "string") mapped.add("/tool_name");
    else if (typeof obj.toolName === "string") mapped.add("/toolName");
    else if (typeof obj.tool === "string") mapped.add("/tool");
  }
  if (sessionId) {
    if (typeof obj.conversationId === "string") mapped.add("/conversationId");
    else if (typeof obj.session_id === "string") mapped.add("/session_id");
    else if (typeof obj.sessionId === "string") mapped.add("/sessionId");
    else if (typeof obj.conversation_id === "string") mapped.add("/conversation_id");
  }
  if (typeof obj.event_id === "string") mapped.add("/event_id");
  if (typeof obj.eventId === "string") mapped.add("/eventId");
  if (typeof obj.tool_use_id === "string") mapped.add("/tool_use_id");
  if (typeof obj.toolUseId === "string") mapped.add("/toolUseId");
  if (typeof obj.tool_call_id === "string") mapped.add("/tool_call_id");

  const leaves: Array<{ path: string; value: string }> = [];
  walkStringPaths(obj, [], leaves);
  const extraFields: Array<{ path: string; value: string }> = [];
  const extraSeen = new Set<string>();
  for (const leaf of leaves) {
    if (mapped.has(leaf.path) || extraSeen.has(leaf.path)) continue;
    extraSeen.add(leaf.path);
    extraFields.push(leaf);
  }
  if (extraFields.length > MAX_EXTRA_FIELDS) {
    return { ok: false, failure: adapterFailure("extras_exceeded", { extraCount: extraFields.length }) };
  }
  const pointerUtf8 = longestPointerUtf8([
    ...Object.values(fields).map((field) => field.provenance),
    ...extraFields.map((item) => item.path),
  ]);
  if (pointerUtf8 > MAX_POINTER_UTF8) {
    return { ok: false, failure: adapterFailure("pointer_too_long", { pointerUtf8 }) };
  }

  const hostId = ctx.agentFlag && ctx.agentFlag.length > 0 ? ctx.agentFlag : agent;
  const event: CanonicalToolEvent = {
    v: 1,
    eventId,
    occurredAt: ctx.occurredAt,
    device: { id: ctx.deviceId },
    host: { id: hostId, version: null, adapterRevision: ctx.adapterRevision },
    session: { id: sessionId ?? null, model: null },
    tool: { kind: kindForNativeName(toolName), nativeName: toolName },
    fields,
    extraFields,
    rawPayloadHash: sha256Prefixed(raw),
    context: { proc: null, parentProc: null, hookBlind: false },
    origin: "HOOK",
  };

  return {
    ok: true,
    event,
    aliasConflict: conflict,
    host: { agent, argMap: hostArgMap, toolInput, parsed: parsedHook },
  };
}

/** Bridge: exact CanonicalToolEvent field strings → v1 `str()` EvalInput. */
export function canonicalToEvalInput(event: CanonicalToolEvent): EvalInput {
  const input: EvalInput = {
    nativeTool: event.tool.nativeName,
    source: event.origin === "PROBE" ? "probe" : event.origin === "BACKFILL" ? "offline_backfill" : "hook",
  };
  const agent = event.host.id;
  if (agent) input.agent = agent as EvalInput["agent"];
  const command = v1Str(event.fields.command?.value);
  if (command) input.command = command;
  const filePath = v1Str(event.fields.filePath?.value);
  if (filePath) input.filePath = filePath;
  const url = v1Str(event.fields.url?.value);
  if (url) input.url = url;
  const dest = v1Str(event.fields.dest?.value);
  if (dest) input.dest = dest;
  const contents = v1Str(event.fields.contents?.value);
  if (contents) input.contents = contents;
  const cwd = v1Str(event.fields.cwd?.value);
  if (cwd) input.cwd = cwd;
  if (event.session.id) input.sessionId = event.session.id;
  if (event.session.model) input.sessionModel = event.session.model;
  if (event.device.id) input.deviceId = event.device.id;
  if (event.eventId) input.eventId = event.eventId;
  if (event.context.proc) input.proc = event.context.proc;
  if (event.context.parentProc) input.parentProc = event.context.parentProc;
  if (event.context.hookBlind) input.hookBlind = true;
  return input;
}

export function d8TrimObservations(event: CanonicalToolEvent): Array<{ field: CanonicalFieldName; exact: string; trimmed: string | undefined }> {
  const out: Array<{ field: CanonicalFieldName; exact: string; trimmed: string | undefined }> = [];
  for (const name of Object.keys(event.fields) as CanonicalFieldName[]) {
    const spec = event.fields[name];
    if (!spec) continue;
    const trimmed = v1Str(spec.value);
    if (trimmed !== spec.value) out.push({ field: name, exact: spec.value, trimmed });
  }
  return out;
}

export function toCanonicalDecision(opts: {
  eventId: string;
  v1Result: EvalResult;
  rewrite?: RewriteBridge;
  aliasConflict?: boolean;
  policyVersion: number;
  rulesHash: string;
  engineRevision: number;
  origin: CanonicalDecision["origin"];
}): CanonicalDecision {
  const { v1Result } = opts;
  let action: CanonicalAction;
  let rewriteStatus: RewriteStatus = "NONE";
  let reasonCode: string;
  let rewrite: CanonicalRewrite | undefined;

  if (opts.aliasConflict) {
    action = "BLOCK";
    rewriteStatus = "NONE";
    reasonCode = "conflicting_aliases";
  } else if (opts.rewrite?.status === "REFUSED") {
    action = "BLOCK";
    rewriteStatus = "REFUSED";
    reasonCode = reasonCodeOf(opts.rewrite.reason, "sensitive_residue");
  } else if (opts.rewrite?.status === "NOOP_NO_SPAN") {
    action = "LOG";
    rewriteStatus = "NOOP_NO_SPAN";
    reasonCode = "rewrite_noop";
  } else if (opts.rewrite?.status === "APPLIED") {
    action = "REWRITE";
    rewriteStatus = "APPLIED";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "rewrite", "rewrite");
    rewrite = {
      patches: [],
      rendererRevision: 0,
      baseInputHash: dummyHash(),
      resultInputHash: dummyHash(),
      validation: { residueScan: "PASS", shellStructure: "N_A", urlParse: "N_A" },
      updatedFields: opts.rewrite.updatedFields,
    };
  } else if (v1Result.skipped) {
    action = "ALLOW";
    reasonCode = "out_of_scope";
  } else if (v1Result.decision === "block") {
    action = "BLOCK";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "block", "block");
  } else if (v1Result.decision === "confirm") {
    action = "ASK";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "confirm", "confirm");
  } else if (v1Result.decision === "rewrite") {
    action = "REWRITE";
    rewriteStatus = "APPLIED";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "rewrite", "rewrite");
    rewrite = {
      patches: [],
      rendererRevision: 0,
      baseInputHash: dummyHash(),
      resultInputHash: dummyHash(),
      validation: { residueScan: "PASS", shellStructure: "N_A", urlParse: "N_A" },
      updatedFields: {},
    };
  } else if (v1Result.decision === "log") {
    action = "LOG";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "log", "log");
  } else {
    action = "ALLOW";
    reasonCode = reasonCodeOf(v1Result.rule?.id ?? "allow", "allow");
  }

  const ruleIds = v1Result.rule?.id ? [v1Result.rule.id] : [];
  const family = v1Result.threat ?? v1Result.rule?.family ?? null;
  const decision: CanonicalDecision = {
    v: 1,
    eventId: opts.eventId,
    action,
    reasonCode,
    ruleIds,
    risk: mapRisk(v1Result.risk),
    family,
    policy: { version: opts.policyVersion, rulesHash: opts.rulesHash },
    engineRevision: opts.engineRevision,
    origin: opts.aliasConflict ? "FAIL_CLOSED" : opts.origin,
    privacy: { findings: [], rewriteStatus },
    explain: [
      {
        layer: "protected",
        result: v1Result.rule ? "match" : "no_match",
        ...(v1Result.rule?.id ? { reasonCode, ruleIds } : {}),
      },
    ],
    userMessage: userMessageFor(action, reasonCode, rewriteStatus),
  };
  if (rewrite) decision.rewrite = rewrite;
  return decision;
}

export function renderCanonicalDecision(
  agent: HookAgent | "unknown",
  decision: CanonicalDecision,
  host?: { argMap?: Record<string, string>; updatedInput?: Record<string, unknown> },
): { stdout: string; exitCode: number; stderr?: string } {
  const reason = decision.reasonCode;
  if (decision.action === "BLOCK" || decision.action === "ASK") {
    return deny(agent, reason, host?.argMap);
  }
  if (decision.action === "REWRITE") {
    const updatedInput = host?.updatedInput;
    if (!updatedInput) return deny(agent, "rewrite_missing_updated_input", host?.argMap);
    return pass(agent, reason, updatedInput, host?.argMap);
  }
  return pass(agent, reason, undefined, host?.argMap);
}

export { formatHookResponse };
