/**
 * Shared alias tables and pure field helpers. Order is part of the contract
 * (first non-blank wins; conflict compares the set).
 *
 * 原文（msg979 B2）要求别名字面量数组只允许出现在 hook-protocol.ts。
 * ingest.ts 是 domain，hook-protocol.ts 是 app（auth/newEventId），domain 不能 import app。
 * 键表与 toolInputHasAliasConflict / toolInputToEvalFields 放在本文件（无 I/O），
 * 由 hook-protocol re-export，core 仍自包含。不把认证/随机 ID 拉进 domain。
 *
 * eval-bridge 顶层别名是窄集合（无 path/target_file、无 conversation_id、多 nativeTool），
 * 用 EVAL_BRIDGE_* 命名，不切片、不扩充。
 */

export const COMMAND_KEYS = ["command", "cmd"] as const;

/** Top-level operational path aliases, including Grok `target_file`. Nested `path` is not an op target. */
export const FILE_PATH_KEYS = ["file_path", "filePath", "path", "target_file"] as const;

export const DEST_KEYS = ["dest", "host", "hostname"] as const;
export const URL_KEYS = ["url"] as const;

/** Winner order matches toolInputToEvalFields. Conflict detection compares the set. */
export const CWD_KEYS = ["working_directory", "workingDirectory", "cwd"] as const;

export const CONTENT_KEYS = [
  "contents",
  "content",
  "new_string",
  "old_string",
  "newString",
  "oldString",
  "body",
  "patch",
  "new_source",
  "replacement",
  "file_text",
  "prompt",
] as const;

/** Top-level semantic aliases. Parallel edit operands (new_string, old_string, body, patch) are not aliases. */
export const CONTENT_ALIAS_KEYS = ["contents", "content"] as const;

export const TOOL_NAME_KEYS = ["tool_name", "toolName", "tool"] as const;
export const EVAL_BRIDGE_TOOL_NAME_KEYS = ["tool_name", "toolName", "tool", "nativeTool"] as const;

export const SESSION_ID_KEYS = ["session_id", "sessionId", "conversation_id"] as const;
export const EVAL_BRIDGE_SESSION_ID_KEYS = ["sessionId", "session_id"] as const;

export const EVENT_ID_KEYS = ["eventId", "event_id"] as const;
export const TOOL_USE_ID_KEYS = ["toolUseId", "tool_use_id", "tool_call_id"] as const;

/** eval-bridge envelope filePath aliases. No path/target_file. */
export const EVAL_BRIDGE_FILE_PATH_KEYS = ["file_path", "filePath"] as const;

export const TOOL_INPUT_BAG_KEYS = ["tool_input", "toolInput", "input"] as const;

export const ALIAS_CONFLICT = Symbol("alias_conflict");

export function aliasStr(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function firstTrimmed(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = aliasStr(obj[key]);
    if (value) return value;
  }
  return undefined;
}

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(",")}}`;
}

export function pickDefinedSame(values: Array<string | undefined>): string | undefined | typeof ALIAS_CONFLICT {
  const defined = values.filter((v): v is string => typeof v === "string" && v.length > 0);
  if (!defined.length) return undefined;
  const first = defined[0]!;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i] !== first) return ALIAS_CONFLICT;
  }
  return first;
}

export function objectsConflict(values: Array<unknown>): boolean {
  const defined = values.filter(isPlainObject);
  if (defined.length <= 1) return false;
  const first = stableJson(defined[0]);
  return defined.some((v) => stableJson(v) !== first);
}

/** Top-level operational fields. Nested payload keys with the same names are still scanned. */
const OP_KEYS = new Set<string>([
  ...COMMAND_KEYS,
  ...FILE_PATH_KEYS,
  ...CWD_KEYS,
  "directory",
  ...URL_KEYS,
  ...DEST_KEYS,
  ...TOOL_NAME_KEYS,
]);

export function toolInputHasAliasConflict(obj: Record<string, unknown>): boolean {
  const command = pickDefinedSame(COMMAND_KEYS.map((k) => aliasStr(obj[k])));
  const filePath = pickDefinedSame(FILE_PATH_KEYS.map((k) => aliasStr(obj[k])));
  const dest = pickDefinedSame(DEST_KEYS.map((k) => aliasStr(obj[k])));
  const cwd = pickDefinedSame(CWD_KEYS.map((k) => aliasStr(obj[k])));
  const contentAlias = pickDefinedSame(CONTENT_ALIAS_KEYS.map((k) => aliasStr(obj[k])));
  const editRows = Array.isArray(obj.edits) ? obj.edits.filter(isPlainObject) : [];
  const editAlias = editRows.some(
    (row) => pickDefinedSame(CONTENT_ALIAS_KEYS.map((k) => aliasStr(row[k]))) === ALIAS_CONFLICT,
  );
  return (
    command === ALIAS_CONFLICT ||
    filePath === ALIAS_CONFLICT ||
    dest === ALIAS_CONFLICT ||
    cwd === ALIAS_CONFLICT ||
    contentAlias === ALIAS_CONFLICT ||
    editAlias
  );
}

function collectContentParts(obj: Record<string, unknown>): string[] {
  const parts: string[] = [];
  const push = (v: string | undefined) => {
    if (v && !parts.includes(v)) parts.push(v);
  };
  for (const key of CONTENT_KEYS) push(aliasStr(obj[key]));
  const edits = obj.edits;
  if (Array.isArray(edits)) {
    for (const row of edits) {
      if (!isPlainObject(row)) continue;
      for (const key of CONTENT_KEYS) push(aliasStr(row[key]));
    }
  }
  const seen = new WeakSet<object>();
  for (const [k, v] of Object.entries(obj)) {
    if (OP_KEYS.has(k)) continue;
    if (k === "edits") continue;
    if ((CONTENT_KEYS as readonly string[]).includes(k) && typeof v === "string") continue;
    walkScanLeaves(v, push, seen);
  }
  return parts;
}

function walkScanLeaves(val: unknown, push: (v: string | undefined) => void, seen: WeakSet<object>): void {
  if (typeof val === "string") {
    push(aliasStr(val));
    return;
  }
  if (!val || typeof val !== "object") return;
  if (seen.has(val)) return;
  seen.add(val);
  if (Array.isArray(val)) {
    for (const item of val) walkScanLeaves(item, push, seen);
    return;
  }
  if (!isPlainObject(val)) return;
  for (const v of Object.values(val)) walkScanLeaves(v, push, seen);
}

export function toolInputToEvalFields(toolName: string, toolInput: Record<string, unknown>) {
  const parts = collectContentParts(toolInput);
  return {
    nativeTool: toolName,
    command: firstTrimmed(toolInput, COMMAND_KEYS),
    filePath: firstTrimmed(toolInput, FILE_PATH_KEYS),
    url: firstTrimmed(toolInput, URL_KEYS),
    contents: parts.length ? parts.join("\n") : undefined,
    dest: firstTrimmed(toolInput, DEST_KEYS),
    cwd: firstTrimmed(toolInput, CWD_KEYS),
  };
}
