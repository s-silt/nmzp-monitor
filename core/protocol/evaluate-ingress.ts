/** Real producer/source boundaries. These helpers do not activate runToolHook or transmit anything. */
import { createHash } from "node:crypto";
import { BODY_LIMIT } from "../constants.ts";
import { resolveEvalBody, rewriteSource, type EvalRequestBody, type PreparedEvaluation } from "../eval-bridge.ts";
import { COMMAND_KEYS, FILE_PATH_KEYS, EVAL_BRIDGE_FILE_PATH_KEYS, URL_KEYS, DEST_KEYS, CWD_KEYS, collectContentLeaves, toolInputToEvalFields } from "../hook-protocol.ts";
import { legacyCanonicalContext } from "./v2-context.ts";
import { adapterFailure, encodePointer, kindForNativeName, toCanonicalToolEventFromBytes, v1Str,
  type AdapterContext, type AdapterParseFailure, type CanonicalToolEvent, type ScalarFieldName } from "./v2-adapter.ts";
import { buildRewriteLayout, buildDeclaredRewriteLayout, layoutFragments, ownRewriteLayout, type RewriteLayout } from "./rewrite-layout.ts";
import { validateEvaluateCompat } from "./generated/evaluate-validator.ts";

export type PreparedTransport = { kind: "request"; event: CanonicalToolEvent } | { kind: "local_denial"; failure: AdapterParseFailure | { aliasConflict: true } };
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const deny = (kind: "json_syntax" | "over_limit" | "canonical_over_limit"): PreparedTransport => ({ kind: "local_denial", failure: adapterFailure(kind) });
const bytes = (raw: string | Uint8Array) => typeof raw === "string" ? Buffer.from(raw, "utf8") : Buffer.from(raw);
function complete(event: CanonicalToolEvent): PreparedTransport {
  return Buffer.byteLength(JSON.stringify(event)) > BODY_LIMIT ? deny("canonical_over_limit") : { kind: "request", event };
}

/** Full raw envelope conflicts remain a local denial; no spoofable conflict bit is sent as evidence. */
export function prepareHookTransport(raw: string | Uint8Array, context: AdapterContext, observation: { uploadSize?: unknown } = {}): PreparedTransport {
  const data = bytes(raw), parsed = toCanonicalToolEventFromBytes(data, context);
  if (!parsed.ok) return { kind: "local_denial", failure: parsed.failure };
  if (parsed.aliasConflict) return { kind: "local_denial", failure: { aliasConflict: true } };
  const agent = context.agentFlag ?? (parsed.host.agent === "unknown" ? undefined : parsed.host.agent);
  const event: CanonicalToolEvent = { ...parsed.event, context: { ...legacyCanonicalContext("HOOK", { permissionMode: parsed.host.parsed.permissionMode, uploadSize: observation.uploadSize }), agentPresent: v1Str(agent) !== undefined } };
  const layout = buildRewriteLayout(data, { ...parsed, event });
  if (!layout.ok) return deny("json_syntax");
  return complete({ ...event, rewriteLayout: layout.layout });
}

function strings(value: unknown): Array<{ path: string; value: string }> {
  const result: Array<{ path: string; value: string }> = [], todo = [{ value, tokens: [] as string[] }];
  while (todo.length) {
    const next = todo.pop()!;
    if (typeof next.value === "string") result.push({ path: encodePointer(next.tokens), value: next.value });
    else if (Array.isArray(next.value)) for (let i = next.value.length - 1; i >= 0; i--) todo.push({ value: next.value[i], tokens: [...next.tokens, String(i)] });
    else if (object(next.value)) for (const [key, value] of Object.entries(next.value).reverse()) todo.push({ value, tokens: [...next.tokens, key] });
  }
  return result;
}

/** Direct PROBE evaluate-body semantics. Never runs a hook parser on a manufactured envelope. */
export function prepareProbeTransport(raw: string | Uint8Array, context: AdapterContext & { hostId: string }): PreparedTransport {
  const data = bytes(raw);
  if (data.length > BODY_LIMIT) return deny("over_limit");
  let source: unknown;
  try { source = JSON.parse(data.toString("utf8")); } catch { return deny("json_syntax"); }
  if (!object(source) || source.source !== "probe" || !context.hostId) return deny("json_syntax");
  const body = source as EvalRequestBody, resolved = resolveEvalBody(body);
  if (resolved.conflict) return { kind: "local_denial", failure: { aliasConflict: true } };
  const sourceRoot = object(source.tool_input) ? "/tool_input" : object(source.toolInput) ? "/toolInput" : null;
  const bag = resolved.toolInput, fields: CanonicalToolEvent["fields"] = {}, mapped = new Set<string>();
  const take = (name: ScalarFieldName, bagKeys: readonly string[], topKeys: readonly string[]) => {
    for (const [value, prefix, keys] of [[bag, sourceRoot, bagKeys], [source, "", topKeys]] as const) {
      for (const key of keys) if (v1Str(value[key]) !== undefined) {
        const provenance = `${prefix}${encodePointer([key])}`;
        fields[name] = { value: value[key] as string, provenance }; mapped.add(provenance); return;
      }
    }
  };
  take("command", COMMAND_KEYS, ["command"]); take("filePath", FILE_PATH_KEYS, EVAL_BRIDGE_FILE_PATH_KEYS);
  take("url", URL_KEYS, ["url"]); take("dest", DEST_KEYS, ["dest"]); take("cwd", CWD_KEYS, ["cwd"]); take("query", ["query"], []);
  const content = collectContentLeaves(bag).map(leaf => ({ value: leaf.value, provenance: `${sourceRoot}${encodePointer(leaf.tokens)}` }));
  if (toolInputToEvalFields(resolved.nativeTool, bag).contents === undefined && v1Str(source.contents) !== undefined) content.push({ value: source.contents as string, provenance: "/contents" });
  if (content.length) { fields.contents = { leaves: content }; for (const leaf of content) mapped.add(leaf.provenance); }
  const event: CanonicalToolEvent = { v: 1, eventId: typeof source.eventId === "string" && source.eventId ? source.eventId : context.eventId,
    occurredAt: context.occurredAt, device: { id: context.deviceId }, host: { id: context.hostId, version: null, adapterRevision: context.adapterRevision },
    session: { id: resolved.sessionId ?? null, model: null }, tool: { kind: kindForNativeName(resolved.nativeTool), nativeName: resolved.nativeTool },
    fields, extraFields: strings(source).filter(leaf => !mapped.has(leaf.path)), rawPayloadHash: `sha256:${createHash("sha256").update(data).digest("hex")}`,
    context: { ...legacyCanonicalContext("PROBE", body), agentPresent: resolved.agent !== undefined }, origin: "PROBE" };
  const fragments = layoutFragments(event); if (!fragments) return deny("json_syntax");
  const topLevel: NonNullable<RewriteLayout["probe"]>["topLevel"] = {};
  for (const name of ["command", "url", "dest", "contents"] as const) if (typeof source[name] === "string") topLevel[name] = fragments.get(`/${name}`)!.ref;
  for (const key of EVAL_BRIDGE_FILE_PATH_KEYS) if (v1Str(source[key]) !== undefined) { topLevel.file_path = fragments.get(`/${key}`)!.ref; break; }
  const layout = buildDeclaredRewriteLayout(event, bag, { version: 1, mapping: "probe-eval-v1", sourceRoot, sourcePresent: rewriteSource(resolved) !== undefined,
    ...(typeof source.cwd === "string" ? { envelopeCwd: fragments.get("/cwd")!.ref } : {}),
    probe: { agent: typeof source.agent === "string" ? fragments.get("/agent")!.ref : null, topLevel } });
  if (!layout.ok) return deny("json_syntax");
  return complete({ ...event, rewriteLayout: layout.layout });
}

/** Schema plus real alias/projection checks. Declared layout consistency is not proof of untransmitted stdin. */
export function prepareCanonicalEvaluation(raw: unknown, deviceId: string): { ok: true; event: CanonicalToolEvent; prepared: PreparedEvaluation } | { ok: false; code: "bad_schema" | "unauthorized" } {
  if (!validateEvaluateCompat(raw)) return { ok: false, code: "bad_schema" };
  let event = raw as CanonicalToolEvent;
  if (event.device.id !== deviceId) return { ok: false, code: "unauthorized" };
  if (event.origin === "BACKFILL" || event.tool.kind !== kindForNativeName(event.tool.nativeName)) return { ok: false, code: "bad_schema" };
  const owned = ownRewriteLayout(event);
  if (!owned.ok) return { ok: false, code: "bad_schema" };
  event = owned.event;
  const { materialized } = owned;
  if ((event.origin === "PROBE") !== (materialized.layout.mapping === "probe-eval-v1")) return { ok: false, code: "bad_schema" };
  const agent = event.origin === "PROBE" ? materialized.resolved.agent : event.context.agentPresent === false ? undefined : v1Str(event.host.id);
  if (event.context.agentPresent !== undefined && event.context.agentPresent !== (agent !== undefined)) return { ok: false, code: "bad_schema" };
  const resolved = { ...materialized.resolved, source: event.origin === "PROBE" ? "probe" as const : "hook" as const, agent,
    sessionId: v1Str(event.session.id), proc: v1Str(event.context.proc), parentProc: v1Str(event.context.parentProc), hookBlind: event.context.hookBlind };
  // Engine fields come only from the one canonical projection. Keep legacy
  // metadata/defaults and its explicit undefined keys without a second resolver.
  const input = { ...materialized.input, nativeTool: resolved.nativeTool, command: materialized.input.command,
    filePath: materialized.input.filePath, url: materialized.input.url, cwd: materialized.input.cwd, dest: materialized.input.dest,
    contents: materialized.input.contents, agent: agent as PreparedEvaluation["input"]["agent"], sessionId: resolved.sessionId,
    source: resolved.source, proc: resolved.proc, parentProc: resolved.parentProc, hookBlind: resolved.hookBlind, deviceId, eventId: event.eventId };
  // The established CT bridge does not forward model metadata to legacy evaluation.
  delete input.sessionModel;
  return { ok: true, event, prepared: { resolved, input, toolInput: materialized.view } };
}
