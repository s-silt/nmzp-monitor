import {
  ALIAS_CONFLICT,
  COMMAND_KEYS,
  CONTENT_KEYS,
  CWD_KEYS,
  DEST_KEYS,
  EVAL_BRIDGE_TOOL_NAME_KEYS,
  EVENT_ID_KEYS,
  FILE_PATH_KEYS,
  SESSION_ID_KEYS,
  TOOL_INPUT_BAG_KEYS,
  TOOL_NAME_KEYS,
  TOOL_USE_ID_KEYS,
  URL_KEYS,
  aliasStr,
  pickDefinedSame,
  toolInputHasAliasConflict,
  toolInputToEvalFields,
} from "../../../core/hook-alias-keys.ts";
import { isAgentId } from "./agents.ts";
import type { EvalInput } from "./engine.ts";
import type { AgentId } from "./types.ts";

/** Hard ceiling so a pasted hook payload cannot balloon memory. */
export const INGEST_MAX_RAW = 65536;
/** Identifiers only. Command/contents/url are judged in full up to INGEST_MAX_RAW. */
const META_MAX = 256;

/** Extra observation carriers besides TOOL_INPUT_BAG_KEYS. Not an alias group. */
const INGEST_EXTRA_BAG_KEYS = ["arguments", "params", "event"] as const;
/** Observation envelope/extra-bag cwd key. Canonical tool bags keep workdir as a content leaf. */
const INGEST_WORKDIR_KEY = "workdir";
/** Extra-bag envelope metadata. Old ingest read these as ids, not contents. */
const INGEST_BAG_META_KEYS = [
  ...SESSION_ID_KEYS,
  "session",
  ...EVENT_ID_KEYS,
  ...TOOL_USE_ID_KEYS,
  "hookBlind",
  "hook_blind",
] as const;

function clipMeta(v: unknown): string | undefined {
  const t = aliasStr(v);
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

function pickSameBool(values: Array<boolean | undefined>): boolean | undefined | typeof ALIAS_CONFLICT {
  const defined = values.filter((v): v is boolean => v !== undefined);
  if (!defined.length) return undefined;
  const first = defined[0]!;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i] !== first) return ALIAS_CONFLICT;
  }
  return first;
}

function firstKnown(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = aliasStr(obj[key]);
    if (value) return value;
  }
  return undefined;
}

function hasText(obj: Record<string, unknown>, keys: readonly string[]): boolean {
  for (const key of keys) {
    if (aliasStr(obj[key])) return true;
  }
  return false;
}

function bagHasToolFields(bag: Record<string, unknown>): boolean {
  if (hasText(bag, COMMAND_KEYS)) return true;
  if (hasText(bag, FILE_PATH_KEYS)) return true;
  if (hasText(bag, URL_KEYS)) return true;
  if (hasText(bag, DEST_KEYS)) return true;
  if (hasText(bag, CONTENT_KEYS)) return true;
  if (Array.isArray(bag.edits) && bag.edits.length > 0) return true;
  if (aliasStr(bag[INGEST_WORKDIR_KEY])) return true;
  if (Array.isArray(bag.patch) && bag.patch.length > 0) return true;
  return false;
}

interface FieldSlice {
  command?: string;
  filePath?: string;
  url?: string;
  dest?: string;
  contents?: string;
  cwd?: string;
}

/** Envelope/top: known operational keys only. Do not walk agent/session/nested bags as contents. */
function envelopeSlice(obj: Record<string, unknown>): FieldSlice | typeof ALIAS_CONFLICT {
  if (toolInputHasAliasConflict(obj)) return ALIAS_CONFLICT;
  const parts: string[] = [];
  const push = (v: string | undefined) => {
    if (v && !parts.includes(v)) parts.push(v);
  };
  for (const key of CONTENT_KEYS) push(aliasStr(obj[key]));
  const edits = obj.edits;
  if (Array.isArray(edits)) {
    for (const row of edits) {
      if (!isPlain(row)) continue;
      for (const key of CONTENT_KEYS) push(aliasStr(row[key]));
    }
  }
  const cwd = pickDefinedSame([...CWD_KEYS.map((key) => aliasStr(obj[key])), aliasStr(obj[INGEST_WORKDIR_KEY])]);
  if (cwd === ALIAS_CONFLICT) return ALIAS_CONFLICT;
  return {
    command: firstKnown(obj, COMMAND_KEYS),
    filePath: firstKnown(obj, FILE_PATH_KEYS),
    url: firstKnown(obj, URL_KEYS),
    dest: firstKnown(obj, DEST_KEYS),
    cwd,
    contents: parts.length ? parts.join("\n") : undefined,
  };
}

function bagSlice(bag: Record<string, unknown>): FieldSlice | typeof ALIAS_CONFLICT {
  if (toolInputHasAliasConflict(bag)) return ALIAS_CONFLICT;
  const fields = toolInputToEvalFields("unknown", bag);
  return {
    command: fields.command,
    filePath: fields.filePath,
    url: fields.url,
    dest: fields.dest,
    cwd: fields.cwd,
    contents: fields.contents,
  };
}

function observationBagSlice(bag: Record<string, unknown>): FieldSlice | typeof ALIAS_CONFLICT {
  if (toolInputHasAliasConflict(bag)) return ALIAS_CONFLICT;
  const cleaned: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(bag)) {
    if (key === INGEST_WORKDIR_KEY) continue;
    if ((INGEST_BAG_META_KEYS as readonly string[]).includes(key)) continue;
    cleaned[key] = value;
  }
  const fields = toolInputToEvalFields("unknown", cleaned);
  const cwd = pickDefinedSame([fields.cwd, aliasStr(bag[INGEST_WORKDIR_KEY])]);
  if (cwd === ALIAS_CONFLICT) return ALIAS_CONFLICT;
  return {
    command: fields.command,
    filePath: fields.filePath,
    url: fields.url,
    dest: fields.dest,
    cwd,
    contents: fields.contents,
  };
}

function mergeSlices(slices: FieldSlice[]): FieldSlice | typeof ALIAS_CONFLICT {
  const command = pickDefinedSame(slices.map((s) => s.command));
  const filePath = pickDefinedSame(slices.map((s) => s.filePath));
  const url = pickDefinedSame(slices.map((s) => s.url));
  const dest = pickDefinedSame(slices.map((s) => s.dest));
  const contents = pickDefinedSame(slices.map((s) => s.contents));
  const cwd = pickDefinedSame(slices.map((s) => s.cwd));
  if (
    command === ALIAS_CONFLICT ||
    filePath === ALIAS_CONFLICT ||
    url === ALIAS_CONFLICT ||
    dest === ALIAS_CONFLICT ||
    contents === ALIAS_CONFLICT ||
    cwd === ALIAS_CONFLICT
  ) {
    return ALIAS_CONFLICT;
  }
  return { command, filePath, url, dest, contents, cwd };
}

/**
 * The only door inbound hook JSON walks through.
 * JSON.parse as data, then pick known string fields. Never eval, Function, or
 * copy unknown keys onto our objects (so __proto__ / constructor stay inert).
 *
 * ingest.ts has no runtime caller (trust.ingestObservation is probe/observation
 * plus tests); aligning listed hook extraction rules does not change v1 decisions.
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

  const canonicalBags: Record<string, unknown>[] = [];
  // Hook carriers always go through toolInputToEvalFields, including nested-only,
  // workdir-only, and patch-array-only bags. Do not require known top-level keys.
  for (const key of TOOL_INPUT_BAG_KEYS) {
    const bag = nested(parsed, key);
    if (bag) canonicalBags.push(bag);
  }
  const extraBags: Record<string, unknown>[] = [];
  // Observation extras keep compatibility, but skip meta-only session/agent bags.
  for (const key of INGEST_EXTRA_BAG_KEYS) {
    const bag = nested(parsed, key);
    if (bag && bagHasToolFields(bag)) extraBags.push(bag);
  }
  const bags = [...canonicalBags, ...extraBags];

  const top = envelopeSlice(parsed);
  if (top === ALIAS_CONFLICT) return null;
  const slices: FieldSlice[] = [top];
  for (const bag of canonicalBags) {
    const slice = bagSlice(bag);
    if (slice === ALIAS_CONFLICT) return null;
    slices.push(slice);
  }
  for (const bag of extraBags) {
    const slice = observationBagSlice(bag);
    if (slice === ALIAS_CONFLICT) return null;
    slices.push(slice);
  }
  const merged = mergeSlices(slices);
  if (merged === ALIAS_CONFLICT) return null;

  const toolNames: Array<string | undefined> = EVAL_BRIDGE_TOOL_NAME_KEYS.map((key) => clipMeta(parsed[key]));
  for (const bag of bags) {
    for (const key of TOOL_NAME_KEYS) toolNames.push(clipMeta(bag[key]));
  }
  const nativePicked = pickDefinedSame(toolNames);
  if (nativePicked === ALIAS_CONFLICT) return null;
  const nativeToolHint = nativePicked ?? clipMeta(parsed.name);

  const command = merged.command;
  const filePath = merged.filePath;
  const url = merged.url;
  const dest = merged.dest;
  const contents = merged.contents;
  const cwd = merged.cwd;

  const agentRaw = clipMeta(parsed.agent);
  const agent = agentRaw && isAgentId(agentRaw) ? (agentRaw as AgentId) : undefined;
  const sessionModel = clipMeta(parsed.model) ?? clipMeta(parsed.sessionModel);
  const sourceRaw = clipMeta(parsed.source);
  const source = sourceRaw === "probe" || sourceRaw === "hook" ? sourceRaw : undefined;
  const proc = clipMeta(parsed.proc) ?? clipMeta(parsed.process) ?? clipMeta(parsed.comm);
  const parentProc = clipMeta(parsed.parent) ?? clipMeta(parsed.parentProc) ?? clipMeta(parsed.ppid_comm);

  const sessionPicked = pickDefinedSame([
    ...SESSION_ID_KEYS.map((key) => clipMeta(parsed[key])),
    clipMeta(parsed.session),
    ...bags.flatMap((b) => [...SESSION_ID_KEYS.map((key) => clipMeta(b[key])), clipMeta(b.session)]),
  ]);
  if (sessionPicked === ALIAS_CONFLICT) return null;
  const sessionId = sessionPicked;

  const eventIdAlias = pickDefinedSame([
    ...EVENT_ID_KEYS.map((key) => clipMeta(parsed[key])),
    ...bags.flatMap((b) => EVENT_ID_KEYS.map((key) => clipMeta(b[key]))),
  ]);
  if (eventIdAlias === ALIAS_CONFLICT) return null;
  const toolUseId = pickDefinedSame([
    ...TOOL_USE_ID_KEYS.map((key) => clipMeta(parsed[key])),
    ...bags.flatMap((b) => TOOL_USE_ID_KEYS.map((key) => clipMeta(b[key]))),
  ]);
  if (toolUseId === ALIAS_CONFLICT) return null;
  const eventId = pickDefinedSame([eventIdAlias, toolUseId]);
  if (eventId === ALIAS_CONFLICT) return null;

  const hookPicked = pickSameBool([
    asBool(parsed.hookBlind),
    asBool(parsed.hook_blind),
    ...bags.flatMap((b) => [asBool(b.hookBlind), asBool(b.hook_blind)]),
  ]);
  if (hookPicked === ALIAS_CONFLICT) return null;
  const hookBlind = hookPicked;

  const tool =
    nativeToolHint ??
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
