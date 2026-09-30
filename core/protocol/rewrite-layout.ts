/** Opt-in transient parameter reconstruction, not proof of original stdin or a D5 implementation. */
import { createHash } from "node:crypto";
import { BODY_LIMIT } from "../constants.ts";
import { resolveEvalBody, rewriteSource } from "../eval-bridge.ts";
import { remapAntigravityArgs, TOOL_INPUT_BAG_KEYS } from "../hook-protocol.ts";
import { canonicalToEvalInput, encodePointer, v1Str } from "./v2-adapter.ts";
import type { CanonicalToolEvent, ParseEventResult, ScalarFieldName } from "./v2-adapter.ts";

export type LayoutStringRef = { field: ScalarFieldName } | { field: "contents"; leafIndex: number } | { extraIndex: number };
export type RewriteLayoutNode =
  | { type: "object"; entries: Array<{ key: string; child: number }> }
  | { type: "array"; items: number[] }
  | { type: "string"; ref: LayoutStringRef; source: string }
  | { type: "null" }
  | { type: "boolean"; value: boolean }
  | { type: "number"; value: number }
  | { type: "numberSpecial"; value: "negative_zero" | "positive_infinity" | "negative_infinity" };
export interface RewriteLayout {
  version: 1;
  mapping: "generic-hook-v1" | "antigravity-toolCall-v1";
  sourceRoot: "/tool_input" | "/toolInput" | "/input" | "/toolCall/args" | null;
  /** Whether the genuine rewriteSource helper yields an object, not whether a raw bag existed. */
  sourcePresent: boolean;
  envelopeCwd?: LayoutStringRef;
  nodes: RewriteLayoutNode[];
}
export type LayoutReason = "shape" | "graph" | "reference" | "mapping" | "projection" | "source_presence" | "byte_limit" | "alias_conflict" | "raw_binding";
export type LayoutFailure = { ok: false; code: "invalid_rewrite_layout"; reason: LayoutReason };
export type LayoutResult = { ok: true; layout: RewriteLayout; toolInput: Record<string, unknown>; view: Record<string, unknown> | undefined } | LayoutFailure;
const bad = (reason: LayoutReason): LayoutFailure => ({ ok: false, code: "invalid_rewrite_layout", reason });
const scalarNames = ["command", "cwd", "filePath", "url", "dest", "query"] as const;
const own = (value: object, key: PropertyKey) => Object.prototype.hasOwnProperty.call(value, key);
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: Record<string, unknown>, names: string[]) => Object.keys(value).length === names.length && names.every(name => own(value, name));
const dense = (value: unknown): value is unknown[] => Array.isArray(value) && Object.keys(value).length === value.length;
const index = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

interface Fragment { value: string; source: string; ref: LayoutStringRef }
function fragments(event: CanonicalToolEvent): Map<string, Fragment> | undefined {
  if (!record(event.fields) || !Array.isArray(event.extraFields)) return;
  const out = new Map<string, Fragment>();
  const add = (source: unknown, value: unknown, ref: LayoutStringRef, extra = false) => {
    if (typeof source !== "string" || !source.startsWith("/") || /~(?![01])/.test(source) || typeof value !== "string") return false;
    const previous = out.get(source);
    if (previous && (extra || previous.value !== value)) return false;
    if (!previous) out.set(source, { source, value, ref });
    return true;
  };
  for (const [name, field] of Object.entries(event.fields)) {
    if (name === "contents") {
      if (!record(field) || !exact(field, ["leaves"]) || !dense(field.leaves) || field.leaves.length === 0) return;
      const seen = new Set<string>();
      for (const [leafIndex, leaf] of field.leaves.entries()) {
        if (!record(leaf) || !exact(leaf, ["value", "provenance"]) || seen.has(leaf.provenance as string)
          || !add(leaf.provenance, leaf.value, { field: "contents", leafIndex })) return;
        seen.add(leaf.provenance as string);
      }
    } else {
      if (!(scalarNames as readonly string[]).includes(name) || !record(field) || !exact(field, ["value", "provenance"])
        || !add(field.provenance, field.value, { field: name as ScalarFieldName })) return;
    }
  }
  for (const [extraIndex, extra] of event.extraFields.entries()) {
    if (!record(extra) || !exact(extra, ["path", "value"]) || !add(extra.path, extra.value, { extraIndex }, true)) return;
  }
  return out;
}
function resolveRef(event: CanonicalToolEvent, raw: unknown): { value: string; source: string } | undefined {
  if (!record(raw)) return;
  if (exact(raw, ["extraIndex"]) && index(raw.extraIndex)) {
    const value = event.extraFields[raw.extraIndex];
    return value && { value: value.value, source: value.path };
  }
  if (raw.field === "contents" && exact(raw, ["field", "leafIndex"]) && index(raw.leafIndex)) {
    const value = event.fields.contents?.leaves[raw.leafIndex];
    return value && { value: value.value, source: value.provenance };
  }
  if (exact(raw, ["field"]) && (scalarNames as readonly unknown[]).includes(raw.field)) {
    const value = event.fields[raw.field as ScalarFieldName];
    return value && { value: value.value, source: value.provenance };
  }
}
function cwdFragment(mapping: RewriteLayout["mapping"], catalog: Map<string, Fragment>): Fragment | undefined {
  const paths = mapping === "generic-hook-v1" ? ["/cwd", "/workspaceRoot", "/workspace_roots/0"] : ["/toolCall/args/Cwd", "/workspacePaths/0"];
  for (const path of paths) {
    const item = catalog.get(path);
    // Antigravity's workspacePaths[0] retains any string, including an empty one.
    if (item && (v1Str(item.value) !== undefined || path === "/workspacePaths/0")) return item;
  }
}
function dataProperty(target: object, key: string, value: unknown) {
  Object.defineProperty(target, key, { value, writable: true, configurable: true, enumerable: true });
}

/** Validate only the declared layout/references; cannot certify the sender's original stdin. */
export function materializeRewriteLayout(event: CanonicalToolEvent, raw: unknown = event.rewriteLayout): LayoutResult {
  try {
    if (!record(raw) || !exact(raw, own(raw, "envelopeCwd")
      ? ["version", "mapping", "sourceRoot", "sourcePresent", "envelopeCwd", "nodes"]
      : ["version", "mapping", "sourceRoot", "sourcePresent", "nodes"])
      || raw.version !== 1 || typeof raw.sourcePresent !== "boolean" || !dense(raw.nodes) || raw.nodes.length === 0) return bad("shape");
    if (raw.mapping !== "generic-hook-v1" && raw.mapping !== "antigravity-toolCall-v1") return bad("mapping");
    const roots = raw.mapping === "generic-hook-v1" ? [null, "/tool_input", "/toolInput", "/input"] : [null, "/toolCall/args"];
    if (!roots.includes(raw.sourceRoot as string | null)) return bad("mapping");
    const catalog = fragments(event);
    if (!catalog) return bad("reference");
    const cwd = cwdFragment(raw.mapping, catalog);
    if (cwd) {
      const supplied = resolveRef(event, raw.envelopeCwd);
      if (!supplied || supplied.source !== cwd.source || supplied.value !== cwd.value) return bad("reference");
    } else if (own(raw, "envelopeCwd")) return bad("reference");
    const materialized: unknown[] = [];
    const seenSources = new Set<string>();
    const todo: Array<{ at: number; path: string[]; parent?: number; key?: string }> = [{ at: 0, path: [] }];
    let expected = 0;
    while (todo.length) {
      const task = todo.pop()!;
      if (task.at !== expected++ || task.at >= raw.nodes.length) return bad("graph");
      const node = raw.nodes[task.at];
      if (!record(node)) return bad("shape");
      let value: unknown;
      const children: Array<{ at: number; path: string[]; parent: number; key: string }> = [];
      if (node.type === "object") {
        if (!exact(node, ["type", "entries"]) || !dense(node.entries)) return bad("shape");
        value = {};
        const keys = new Set<string>();
        for (const entry of node.entries) {
          if (!record(entry) || !exact(entry, ["key", "child"]) || typeof entry.key !== "string" || keys.has(entry.key) || !index(entry.child)) return bad("graph");
          keys.add(entry.key);
          dataProperty(value as object, entry.key, undefined);
          children.push({ at: entry.child, path: [...task.path, entry.key], parent: task.at, key: entry.key });
        }
        if (JSON.stringify(Object.keys(value as object)) !== JSON.stringify([...keys])) return bad("graph");
      } else if (node.type === "array") {
        if (!exact(node, ["type", "items"]) || !dense(node.items) || !node.items.every(index)) return bad("shape");
        value = [];
        for (const [i, child] of node.items.entries()) children.push({ at: child as number, path: [...task.path, String(i)], parent: task.at, key: String(i) });
      } else if (node.type === "string") {
        if (!exact(node, ["type", "ref", "source"]) || typeof node.source !== "string" || raw.sourceRoot === null) return bad("reference");
        const fragment = resolveRef(event, node.ref);
        const path = `${raw.sourceRoot}${encodePointer(task.path)}`;
        if (!fragment || fragment.source !== node.source || node.source !== path || seenSources.has(path)) return bad("reference");
        seenSources.add(path);
        value = fragment.value;
      } else if (node.type === "null") {
        if (!exact(node, ["type"])) return bad("shape");
        value = null;
      } else if (node.type === "boolean") {
        if (!exact(node, ["type", "value"]) || typeof node.value !== "boolean") return bad("shape");
        value = node.value;
      } else if (node.type === "number") {
        if (!exact(node, ["type", "value"]) || typeof node.value !== "number" || !Number.isFinite(node.value) || Object.is(node.value, -0)) return bad("shape");
        value = node.value;
      } else if (node.type === "numberSpecial") {
        if (!exact(node, ["type", "value"])) return bad("shape");
        if (node.value === "negative_zero") value = -0;
        else if (node.value === "positive_infinity") value = Infinity;
        else if (node.value === "negative_infinity") value = -Infinity;
        else return bad("shape");
      } else return bad("shape");
      if (task.at === 0 && node.type !== "object") return bad("shape");
      materialized[task.at] = value;
      if (task.parent !== undefined) dataProperty(materialized[task.parent] as object, task.key!, value);
      for (let i = children.length - 1; i >= 0; i--) {
        if (children[i].at <= task.at) return bad("graph");
        todo.push(children[i]);
      }
    }
    if (expected !== raw.nodes.length) return bad("graph");
    // Every declared string in the selected raw bag must be represented. This is not host completeness proof.
    if (raw.sourceRoot !== null) for (const source of catalog.keys()) {
      if (source.startsWith(`${raw.sourceRoot}/`) && !seenSources.has(source)) return bad("reference");
    }
    const bag = materialized[0] as Record<string, unknown>;
    if (raw.sourceRoot === null && Object.keys(bag).length) return bad("mapping");
    const mapped = raw.mapping === "antigravity-toolCall-v1" ? remapAntigravityArgs(bag) : { toolInput: bag, conflict: false };
    if (mapped.conflict) return bad("alias_conflict");
    // This is pure source-view construction. It is never an HTTP request or a legacy fingerprint preimage.
    const resolved = resolveEvalBody({ tool_name: event.tool.nativeName, tool_input: mapped.toolInput, cwd: cwd?.value });
    if (resolved.conflict) return bad("alias_conflict");
    const input = canonicalToEvalInput(event);
    for (const name of ["command", "filePath", "url", "dest", "cwd", "contents"] as const) {
      if (resolved[name] !== input[name]) return bad("projection");
    }
    const view = rewriteSource(resolved);
    if ((view !== undefined) !== raw.sourcePresent) return bad("source_presence");
    if (Buffer.byteLength(JSON.stringify({ ...event, rewriteLayout: raw }), "utf8") > BODY_LIMIT) return bad("byte_limit");
    return { ok: true, layout: raw as unknown as RewriteLayout, toolInput: mapped.toolInput, view };
  } catch {
    return bad("shape");
  }
}

/** Construct from the actual selected raw parameter bag; strings can only reference retained canonical fragments. */
export function buildRewriteLayout(raw: string, parsed: ParseEventResult): LayoutResult {
  try {
    if (!parsed.ok || parsed.aliasConflict) return bad("alias_conflict");
    const event = parsed.event;
    const hash = `sha256:${createHash("sha256").update(raw, "utf8").digest("hex")}`;
    if (hash !== event.rawPayloadHash) return bad("raw_binding");
    const source = JSON.parse(raw.replace(/^\uFEFF+/, "").trim()) as unknown;
    if (!record(source)) return bad("shape");
    const mapping = record(source.toolCall) ? "antigravity-toolCall-v1" : "generic-hook-v1";
    let sourceRoot: RewriteLayout["sourceRoot"] = null;
    let bag: Record<string, unknown> = {};
    if (mapping === "antigravity-toolCall-v1") {
      if (record((source.toolCall as Record<string, unknown>).args)) {
        sourceRoot = "/toolCall/args";
        bag = (source.toolCall as Record<string, unknown>).args as Record<string, unknown>;
      }
    } else for (const key of TOOL_INPUT_BAG_KEYS) {
      if (record(source[key])) { sourceRoot = `/${key}`; bag = source[key]; break; }
    }
    const catalog = fragments(event);
    if (!catalog) return bad("reference");
    const cwd = cwdFragment(mapping, catalog);
    const resolved = resolveEvalBody({ tool_name: event.tool.nativeName, tool_input: parsed.host.toolInput, cwd: cwd?.value });
    if (resolved.conflict) return bad("alias_conflict");
    const nodes: RewriteLayoutNode[] = [];
    const stack: Array<{ value: unknown; path: string[]; set?: (at: number) => void }> = [{ value: bag, path: [] }];
    while (stack.length) {
      const task = stack.pop()!, value = task.value, at = nodes.length;
      task.set?.(at);
      if (record(value)) {
        const entries = Object.entries(value).map(([key]) => ({ key, child: -1 }));
        nodes.push({ type: "object", entries });
        for (let i = entries.length - 1; i >= 0; i--) {
          const entry = entries[i];
          stack.push({ value: value[entry.key], path: [...task.path, entry.key], set: child => { entry.child = child; } });
        }
      } else if (Array.isArray(value)) {
        const items: number[] = new Array(value.length).fill(-1);
        nodes.push({ type: "array", items });
        for (let i = value.length - 1; i >= 0; i--) stack.push({ value: value[i], path: [...task.path, String(i)], set: child => { items[i] = child; } });
      } else if (typeof value === "string") {
        const source = `${sourceRoot}${encodePointer(task.path)}`;
        const fragment = catalog.get(source);
        if (!fragment || fragment.value !== value) return bad("reference");
        nodes.push({ type: "string", ref: fragment.ref, source });
      } else if (value === null) nodes.push({ type: "null" });
      else if (typeof value === "boolean") nodes.push({ type: "boolean", value });
      else if (typeof value === "number") {
        if (Object.is(value, -0)) nodes.push({ type: "numberSpecial", value: "negative_zero" });
        else if (value === Infinity) nodes.push({ type: "numberSpecial", value: "positive_infinity" });
        else if (value === -Infinity) nodes.push({ type: "numberSpecial", value: "negative_infinity" });
        else if (Number.isFinite(value)) nodes.push({ type: "number", value });
        else return bad("shape");
      } else return bad("shape");
    }
    const layout: RewriteLayout = { version: 1, mapping, sourceRoot, sourcePresent: rewriteSource(resolved) !== undefined, ...(cwd ? { envelopeCwd: cwd.ref } : {}), nodes };
    return materializeRewriteLayout(event, layout);
  } catch {
    return bad("shape");
  }
}
