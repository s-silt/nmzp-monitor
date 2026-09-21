import { isAgentId } from "./agents.ts";
import type { EvalInput } from "./engine.ts";
import type { AgentId } from "./types.ts";

/** Hard ceiling so a pasted hook payload cannot balloon memory. */
export const INGEST_MAX_RAW = 65536;
/** Identifiers only. Command/contents/url are judged in full up to INGEST_MAX_RAW. */
const META_MAX = 256;

const CONTENT_KEYS = [
  "contents",
  "content",
  "new_string",
  "old_string",
  "newString",
  "oldString",
  "body",
  "patch",
  "new_source",
] as const;

function asText(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t || undefined;
}

function clipMeta(v: unknown): string | undefined {
  const t = asText(v);
  if (!t) return undefined;
  return t.length > META_MAX ? t.slice(0, META_MAX) : t;
}

/** Only explicit booleans (or "true"/"false" strings). Missing → undefined. */
function asBool(v: unknown): boolean | undefined {
  if (v === true || v === false) return v;
  if (v === "true") return true;
  if (v === "false") return false;
  return undefined;
}

function isPlain(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function own(obj: Record<string, unknown>, key: string) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function nested(obj: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const v = obj[key];
  return isPlain(v) ? v : undefined;
}

function collectContentParts(obj: Record<string, unknown> | undefined): string[] {
  if (!obj) return [];
  const parts: string[] = [];
  const push = (v: string | undefined) => {
    if (v && !parts.includes(v)) parts.push(v);
  };
  for (const key of CONTENT_KEYS) push(asText(obj[key]));
  const edits = obj.edits;
  if (Array.isArray(edits)) {
    for (const row of edits) {
      if (!isPlain(row)) continue;
      for (const key of CONTENT_KEYS) push(asText(row[key]));
    }
  }
  return parts;
}

const CONFLICT = Symbol("conflict");
const BAG_KEYS = ["tool_input", "toolInput", "arguments", "params", "input", "event"] as const;

function pickSame(values: Array<string | undefined>): string | undefined | typeof CONFLICT {
  const defined = values.filter((v): v is string => Boolean(v));
  if (!defined.length) return undefined;
  const first = defined[0]!;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i] !== first) return CONFLICT;
  }
  return first;
}

function pickSameBool(values: Array<boolean | undefined>): boolean | undefined | typeof CONFLICT {
  const defined = values.filter((v): v is boolean => v !== undefined);
  if (!defined.length) return undefined;
  const first = defined[0]!;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i] !== first) return CONFLICT;
  }
  return first;
}

function bagHasToolFields(bag: Record<string, unknown>): boolean {
  if (asText(bag.command) || asText(bag.cmd)) return true;
  if (asText(bag.file_path) || asText(bag.filePath) || asText(bag.path) || asText(bag.target_file)) return true;
  if (asText(bag.url) || asText(bag.dest) || asText(bag.host) || asText(bag.hostname)) return true;
  for (const key of CONTENT_KEYS) {
    if (asText(bag[key])) return true;
  }
  return Array.isArray(bag.edits) && bag.edits.length > 0;
}

interface FieldSlice {
  command?: string;
  filePath?: string;
  url?: string;
  dest?: string;
  contents?: string;
}

function sliceFrom(obj: Record<string, unknown>): FieldSlice | typeof CONFLICT {
  const command = pickSame([asText(obj.command), asText(obj.cmd)]);
  const filePath = pickSame([asText(obj.file_path), asText(obj.filePath), asText(obj.path), asText(obj.target_file)]);
  const dest = pickSame([asText(obj.dest), asText(obj.host), asText(obj.hostname)]);
  if (command === CONFLICT || filePath === CONFLICT || dest === CONFLICT) return CONFLICT;
  const parts = collectContentParts(obj);
  return {
    command,
    filePath,
    url: asText(obj.url),
    dest,
    contents: parts.length ? parts.join("\n") : undefined,
  };
}

function mergeSlices(slices: FieldSlice[]): FieldSlice | typeof CONFLICT {
  const command = pickSame(slices.map((s) => s.command));
  const filePath = pickSame(slices.map((s) => s.filePath));
  const url = pickSame(slices.map((s) => s.url));
  const dest = pickSame(slices.map((s) => s.dest));
  const contents = pickSame(slices.map((s) => s.contents));
  if (
    command === CONFLICT ||
    filePath === CONFLICT ||
    url === CONFLICT ||
    dest === CONFLICT ||
    contents === CONFLICT
  ) {
    return CONFLICT;
  }
  return { command, filePath, url, dest, contents };
}

/**
 * The only door inbound hook JSON walks through.
 * JSON.parse as data, then pick known string fields. Never eval, Function, or
 * copy unknown keys onto our objects (so __proto__ / constructor stay inert).
 */
export function parseHookPayload(raw: string): EvalInput | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > INGEST_MAX_RAW || trimmed[0] !== "{") return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (!isPlain(parsed)) return null;
  if (own(parsed, "__proto__") || own(parsed, "prototype")) return null;

  const bags: Record<string, unknown>[] = [];
  for (const key of BAG_KEYS) {
    const bag = nested(parsed, key);
    if (bag && bagHasToolFields(bag)) bags.push(bag);
  }

  const slices: FieldSlice[] = [];
  const top = sliceFrom(parsed);
  if (top === CONFLICT) return null;
  slices.push(top);
  for (const bag of bags) {
    const slice = sliceFrom(bag);
    if (slice === CONFLICT) return null;
    slices.push(slice);
  }
  const merged = mergeSlices(slices);
  if (merged === CONFLICT) return null;

  const toolNames: Array<string | undefined> = [
    clipMeta(parsed.tool_name),
    clipMeta(parsed.toolName),
    clipMeta(parsed.tool),
    clipMeta(parsed.nativeTool),
  ];
  for (const bag of bags) {
    toolNames.push(clipMeta(bag.tool_name), clipMeta(bag.toolName), clipMeta(bag.tool));
  }
  const nativePicked = pickSame(toolNames);
  if (nativePicked === CONFLICT) return null;
  const nativeTool = nativePicked ?? clipMeta(parsed.name);

  const command = merged.command;
  const filePath = merged.filePath;
  const url = merged.url;
  const dest = merged.dest;
  const contents = merged.contents;

  const cwdPicked = pickSame([
    asText(parsed.cwd),
    asText(parsed.workdir),
    asText(parsed.workingDirectory),
    ...bags.flatMap((b) => [asText(b.cwd), asText(b.workdir), asText(b.workingDirectory)]),
  ]);
  if (cwdPicked === CONFLICT) return null;
  const cwd = cwdPicked;

  const agentRaw = clipMeta(parsed.agent);
  const agent = agentRaw && isAgentId(agentRaw) ? (agentRaw as AgentId) : undefined;
  const sessionModel = clipMeta(parsed.model) ?? clipMeta(parsed.sessionModel);
  const sourceRaw = clipMeta(parsed.source);
  const source = sourceRaw === "probe" || sourceRaw === "hook" ? sourceRaw : undefined;
  const proc = clipMeta(parsed.proc) ?? clipMeta(parsed.process) ?? clipMeta(parsed.comm);
  const parentProc = clipMeta(parsed.parent) ?? clipMeta(parsed.parentProc) ?? clipMeta(parsed.ppid_comm);

  const sessionPicked = pickSame([
    clipMeta(parsed.sessionId),
    clipMeta(parsed.session_id),
    clipMeta(parsed.session),
    ...bags.flatMap((b) => [clipMeta(b.sessionId), clipMeta(b.session_id), clipMeta(b.session)]),
  ]);
  if (sessionPicked === CONFLICT) return null;
  const sessionId = sessionPicked;

  const eventPicked = pickSame([
    clipMeta(parsed.eventId),
    clipMeta(parsed.event_id),
    clipMeta(parsed.tool_use_id),
    clipMeta(parsed.toolUseId),
    ...bags.flatMap((b) => [clipMeta(b.eventId), clipMeta(b.event_id), clipMeta(b.tool_use_id), clipMeta(b.toolUseId)]),
  ]);
  if (eventPicked === CONFLICT) return null;
  const eventId = eventPicked;

  const hookPicked = pickSameBool([
    asBool(parsed.hookBlind),
    asBool(parsed.hook_blind),
    ...bags.flatMap((b) => [asBool(b.hookBlind), asBool(b.hook_blind)]),
  ]);
  if (hookPicked === CONFLICT) return null;
  const hookBlind = hookPicked;

  const tool =
    nativeTool ??
    (command ? "Bash" : contents ? "Write" : url ? "WebFetch" : filePath ? "Read" : dest ? "snapshot" : undefined);
  if (!tool) return null;

  return {
    nativeTool: tool,
    command,
    filePath,
    url,
    cwd,
    dest,
    contents,
    agent,
    sessionModel,
    sessionId,
    eventId,
    source,
    proc,
    parentProc,
    hookBlind,
  };
}
