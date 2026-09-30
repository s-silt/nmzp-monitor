import type { RewriteReplayWitness } from "../audit/evaluation-record.ts";
/** Versioned actual-render evidence. Not detector-union D5 spans, an HTTP route, or persisted source. */
import { createHash } from "node:crypto";
import { remapAntigravityArgs, stableJson } from "../hook-protocol.ts";
import { structuredRewrite, type PrivacyFns } from "../rewrite.ts";
import type { RewriteObservation } from "../rewrite-observer.ts";
import type { CustomPrivacyRule } from "../schema.ts";
import { encodePointer, v1Str } from "./v2-adapter.ts";
import type { CanonicalToolEvent, ScalarFieldName } from "./v2-adapter.ts";
import { layoutFragments, materializeRewriteLayout } from "./rewrite-layout.ts";
import type { LayoutStringRef } from "./rewrite-layout.ts";

export const RENDERED_REWRITE_REVISION = 1;
export type PublicRewriteObservation = Exclude<RewriteObservation, { type: "leaf" }>;
export interface RenderedCompositeEdit {
  type: "rendered_composite_v1";
  viewLeafIndex: number;
  derivation: "identity" | "legacy_fallback";
  sourceRef: LayoutStringRef;
  sourceHash: string;
  sourceBindingHash: string;
  /** UTF-16 coordinates in the exact effective-view leaf BEFORE any transformation. */
  span: [number, number];
  originalHash: string;
  /** Response/transient only. May contain copied source; NEVER an audit-safe replacement. */
  replacement: string;
}
export interface RenderedRewriteEvidence {
  version: 1;
  kind: "rendered_rewrite_evidence";
  coordinate: "effective_view_utf16";
  rendererRevision: 1;
  structuralProjection: "legacy_object_assignment_v1";
  layoutHash: string;
  baseFieldsHash: string;
  resultFieldsHash: string;
  baseViewHash: string;
  resultViewHash: string;
  edits: RenderedCompositeEdit[];
  observations: PublicRewriteObservation[];
  findings: Array<{ observationIndex: number; hitIndex: number | null }>;
  completion: { residue: "pass"; persona: "pass" | "not_run" };
}
interface Leaf { index: number; path: string[]; value: string }
interface BoundLeaf extends Leaf {
  source: string; sourceValue: string; sourceRef: LayoutStringRef;
  derivation: RenderedCompositeEdit["derivation"];
}
export type EvidenceFailure = { ok: false; code: "rewrite_evidence_invalid"; reason: "layout" | "source" | "outcome" | "observation" | "binding" | "edit" | "result" | "version" };
export type EvidenceResult =
  | { ok: true; evidence: RenderedRewriteEvidence; updatedInput: Record<string, unknown> }
  | { ok: false; code: "rewrite_refused"; reason: string; observations: PublicRewriteObservation[] }
  | EvidenceFailure;
const bad = (reason: EvidenceFailure["reason"]): EvidenceFailure => ({ ok: false, code: "rewrite_evidence_invalid", reason });
const hash = (text: string) => `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (v: object, key: string) => Object.prototype.hasOwnProperty.call(v, key);
const exactKeys = (v: object, keys: string[]) => Object.keys(v).length === keys.length && keys.every(key => own(v, key));

function leaves(value: unknown): Leaf[] {
  const out: Leaf[] = [], stack = [{ value, path: [] as string[] }];
  while (stack.length) {
    const node = stack.pop()!;
    if (typeof node.value === "string") out.push({ index: out.length, path: node.path, value: node.value });
    else if (Array.isArray(node.value)) for (let i = node.value.length - 1; i >= 0; i--) stack.push({ value: node.value[i], path: [...node.path, String(i)] });
    else if (record(node.value)) {
      const entries = Object.entries(node.value);
      for (let i = entries.length - 1; i >= 0; i--) stack.push({ value: entries[i][1], path: [...node.path, entries[i][0]] });
    }
  }
  return out;
}
function sourceView(event: CanonicalToolEvent) {
  const materialized = materializeRewriteLayout(event);
  if (!materialized.ok) return bad("layout");
  if (!materialized.view) return bad("source");
  const catalog = layoutFragments(event)!;
  const argMap = materialized.layout.mapping === "antigravity-toolCall-v1"
    ? remapAntigravityArgs(materialized.rawToolInput).hostArgMap : undefined;
  const bound: BoundLeaf[] = [];
  for (const leaf of leaves(materialized.view)) {
    const [first, ...rest] = leaf.path;
    let source: string | undefined, derivation: BoundLeaf["derivation"] = "identity";
    if (own(materialized.toolInput, first)) {
      const rawFirst = argMap && own(argMap, first) ? argMap[first] : first;
      source = `${materialized.layout.sourceRoot}${encodePointer([rawFirst, ...rest])}`;
    } else if (leaf.path.length === 1) {
      const field = ({ command: "command", url: "url", dest: "dest", file_path: "filePath" } as Record<string, ScalarFieldName>)[first];
      if (field) source = event.fields[field]?.provenance;
      derivation = "legacy_fallback";
    }
    const fragment = source ? catalog.get(source) : undefined;
    if (!fragment || (derivation === "identity" ? fragment.value : v1Str(fragment.value)) !== leaf.value) return bad("source");
    bound.push({ ...leaf, source: fragment.source, sourceValue: fragment.value, sourceRef: fragment.ref, derivation });
  }
  return { ok: true as const, view: materialized.view, leaves: bound };
}
function fieldsHash(event: CanonicalToolEvent, changed: Map<string, string> = new Map()): string {
  const values: Record<string, string | string[]> = {};
  for (const [key, field] of Object.entries(event.fields)) {
    if (key === "contents") values.contents = event.fields.contents!.leaves.map(leaf => changed.get(leaf.provenance) ?? leaf.value);
    else {
      const scalar = field as { value: string; provenance: string };
      values[key] = changed.get(scalar.provenance) ?? scalar.value;
    }
  }
  return hash(stableJson(values));
}
const sourceBindingHash = (leaf: BoundLeaf) => hash(stableJson({ source: leaf.source, value: leaf.sourceValue }));

/** Deliberately the existing walker's local object-assignment shape, including __proto__ semantics.
 * This versioned projection is not a prototype-safety repair and does not mutate input/global prototypes. */
function projectLegacyShape(value: unknown, edits: Map<number, string>, cursor = { index: 0 }): unknown {
  if (typeof value === "string") { const i = cursor.index++; return edits.has(i) ? edits.get(i)! : value; }
  if (Array.isArray(value)) return value.map(item => projectLegacyShape(item, edits, cursor));
  if (record(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = projectLegacyShape(item, edits, cursor);
    return out;
  }
  return value;
}

function observationData(raw: Record<string, unknown>, leafCount: number): boolean {
  if (!Array.isArray(raw.observations) || !Array.isArray(raw.findings) || !record(raw.completion)
    || !exactKeys(raw.completion, ["residue", "persona"]) || raw.completion.residue !== "pass"
    || !["pass", "not_run"].includes(raw.completion.persona as string)) return false;
  const findings: RenderedRewriteEvidence["findings"] = [];
  let residue = false, persona = false;
  for (const [observationIndex, item] of raw.observations.entries()) {
    if (!record(item) || !["outbound", "walk", "residue", "persona_residue"].includes(item.phase as string)
      || !["operation_context", "effective_leaf", "url_api_component", "decoded_url_path", "decoded_url_query", "prefixed_url_query", "decoded_url_fragment", "post_redaction_leaf", "serialized_view", "residue_string", "decoded_residue_string", "residue_url_component"].includes(item.coordinate as string)
      || (item.viewLeafIndex !== null && (!Number.isSafeInteger(item.viewLeafIndex) || (item.viewLeafIndex as number) < 0 || (item.viewLeafIndex as number) >= leafCount))) return false;
    const base = ["type", "phase", "coordinate", "viewLeafIndex"];
    if (item.type === "scan") {
      if (!exactKeys(item, [...base, "scanner", "inputLength", "hits"]) || !["secrets", "custom"].includes(item.scanner as string)
        || !Number.isSafeInteger(item.inputLength) || (item.inputLength as number) < 0 || !Array.isArray(item.hits)) return false;
      if (item.phase === "residue" && item.hits.length) return false;
      for (const [hitIndex, hit] of item.hits.entries()) {
        if (!record(hit) || !exactKeys(hit, ["index", "length", "kind"]) || !Number.isSafeInteger(hit.index) || !Number.isSafeInteger(hit.length)
          || (hit.index as number) < 0 || (hit.length as number) <= 0 || (hit.index as number) + (hit.length as number) > (item.inputLength as number)
          || (hit.kind !== null && typeof hit.kind !== "string")) return false;
        findings.push({ observationIndex, hitIndex });
      }
    } else if (item.type === "persona") {
      if (!exactKeys(item, [...base, "changed"]) || typeof item.changed !== "boolean") return false;
      if (item.phase === "persona_residue" && item.changed) return false;
      if (item.changed) findings.push({ observationIndex, hitIndex: null });
    } else if (item.type === "check") {
      if (!exactKeys(item, [...base, "check", "result"]) || !["outbound", "url_parse", "url_text_fallback", "shell_piece", "unquoted_redirect", "residue", "persona_residue"].includes(item.check as string)
        || !["pass", "fail", "true", "false", "fallback"].includes(item.result as string)) return false;
      // A successful artifact cannot contain a guard failure that actually short-circuits the rewrite.
      if (["shell_piece", "unquoted_redirect", "residue", "persona_residue"].includes(item.check as string) && item.result === "fail") return false;
      if (item.check === "residue" && item.result === "pass" && item.phase === "residue") residue = true;
      if (item.check === "persona_residue" && item.result === "pass" && item.phase === "persona_residue") persona = true;
    } else return false;
  }
  return residue && raw.completion.persona === (persona ? "pass" : "not_run") && stableJson(raw.findings) === stableJson(findings);
}

/** Verify bindings and apply only the exact declared composite edits; not proof that an untrusted sender ran scans. */
export function applyRenderedRewrite(event: CanonicalToolEvent, raw: unknown): { ok: true; updatedInput: Record<string, unknown> } | EvidenceFailure {
  try {
    if (!record(raw) || !exactKeys(raw, ["version", "kind", "coordinate", "rendererRevision", "structuralProjection", "layoutHash", "baseFieldsHash", "resultFieldsHash", "baseViewHash", "resultViewHash", "edits", "observations", "findings", "completion"])) return bad("version");
    if (raw.version !== 1 || raw.kind !== "rendered_rewrite_evidence" || raw.coordinate !== "effective_view_utf16"
      || raw.rendererRevision !== RENDERED_REWRITE_REVISION || raw.structuralProjection !== "legacy_object_assignment_v1") return bad("version");
    const source = sourceView(event); if (!source.ok) return source;
    if (raw.layoutHash !== hash(stableJson(event.rewriteLayout)) || raw.baseFieldsHash !== fieldsHash(event)
      || raw.baseViewHash !== hash(JSON.stringify(source.view))) return bad("binding");
    if (!observationData(raw, source.leaves.length)) return bad("observation");
    if (!Array.isArray(raw.edits)) return bad("edit");
    const changes = new Map<number, string>(), changedSources = new Map<string, string>();
    let previous = -1;
    for (const edit of raw.edits) {
      if (!record(edit) || !exactKeys(edit, ["type", "viewLeafIndex", "derivation", "sourceRef", "sourceHash", "sourceBindingHash", "span", "originalHash", "replacement"])
        || edit.type !== "rendered_composite_v1" || !Number.isSafeInteger(edit.viewLeafIndex) || (edit.viewLeafIndex as number) <= previous
        || typeof edit.replacement !== "string") return bad("edit");
      const leaf = source.leaves[edit.viewLeafIndex as number];
      if (!leaf || leaf.value.length === 0 || edit.derivation !== leaf.derivation
        || stableJson(edit.sourceRef) !== stableJson(leaf.sourceRef) || edit.sourceHash !== hash(leaf.sourceValue)
        || edit.sourceBindingHash !== sourceBindingHash(leaf) || edit.originalHash !== hash(leaf.value)
        || !Array.isArray(edit.span) || edit.span.length !== 2 || edit.span[0] !== 0 || edit.span[1] !== leaf.value.length
        || edit.replacement === leaf.value) return bad("edit");
      previous = leaf.index; changes.set(leaf.index, edit.replacement);
      if (leaf.derivation === "identity") changedSources.set(leaf.source, edit.replacement);
    }
    const updatedInput = projectLegacyShape(source.view, changes) as Record<string, unknown>;
    if (raw.resultFieldsHash !== fieldsHash(event, changedSources) || raw.resultViewHash !== hash(JSON.stringify(updatedInput))) return bad("result");
    return { ok: true, updatedInput };
  } catch { return bad("binding"); }
}

/** Runs the actual rewrite once, preserving its detector order and short circuits. No policy evaluation. */
export function buildRenderedRewriteEvidence(event: CanonicalToolEvent, rules: CustomPrivacyRule[], privacy: PrivacyFns): EvidenceResult {
  try {
    const source = sourceView(event); if (!source.ok) return source;
    const trace: RewriteObservation[] = [];
    const result = structuredRewrite(source.view, rules, privacy, observation => { trace.push(observation); });
    const observations = trace.filter((item): item is PublicRewriteObservation => item.type !== "leaf");
    if (!result.ok) return { ok: false, code: "rewrite_refused", reason: result.reason, observations };
    const ends = trace.filter((item): item is Extract<RewriteObservation, { type: "leaf" }> => item.type === "leaf" && item.status === "complete");
    if (ends.length !== source.leaves.length) return bad("observation");
    const residuePassed = observations.some(item => item.type === "check" && item.check === "residue" && item.result === "pass");
    if (!residuePassed) return bad("observation");
    const edits: RenderedCompositeEdit[] = [], changes = new Map<string, string>();
    for (const [i, ended] of ends.entries()) {
      const leaf = source.leaves[i];
      if (ended.viewLeafIndex !== leaf.index || stableJson(ended.path) !== stableJson(leaf.path) || ended.before !== leaf.value || ended.after === undefined) return bad("observation");
      if (ended.after === leaf.value) continue;
      if (!leaf.value.length) return bad("edit");
      edits.push({ type: "rendered_composite_v1", viewLeafIndex: i, derivation: leaf.derivation, sourceRef: leaf.sourceRef,
        sourceHash: hash(leaf.sourceValue), sourceBindingHash: sourceBindingHash(leaf), span: [0, leaf.value.length], originalHash: hash(leaf.value), replacement: ended.after });
      if (leaf.derivation === "identity") changes.set(leaf.source, ended.after);
    }
    const findings: RenderedRewriteEvidence["findings"] = [];
    observations.forEach((item, observationIndex) => {
      if (item.type === "scan") item.hits.forEach((_hit, hitIndex) => findings.push({ observationIndex, hitIndex }));
      else if (item.type === "persona" && item.changed) findings.push({ observationIndex, hitIndex: null });
    });
    const evidence: RenderedRewriteEvidence = {
      version: 1, kind: "rendered_rewrite_evidence", coordinate: "effective_view_utf16", rendererRevision: RENDERED_REWRITE_REVISION,
      structuralProjection: "legacy_object_assignment_v1", layoutHash: hash(stableJson(event.rewriteLayout)),
      baseFieldsHash: fieldsHash(event), resultFieldsHash: fieldsHash(event, changes), baseViewHash: hash(JSON.stringify(source.view)), resultViewHash: hash(JSON.stringify(result.updatedInput)),
      edits, observations, findings, completion: { residue: "pass", persona: observations.some(item => item.type === "check" && item.check === "persona_residue" && item.result === "pass") ? "pass" : "not_run" },
    };
    const applied = applyRenderedRewrite(event, evidence);
    if (!applied.ok || JSON.stringify(applied.updatedInput) !== JSON.stringify(result.updatedInput)) return bad("result");
    return { ok: true, evidence, updatedInput: result.updatedInput };
  } catch { return bad("outcome"); }
}

/** Metadata-only witness. Durable history/implementation ownership is enforced by evaluation-application. */
export type { RewriteReplayWitness } from "../audit/evaluation-record.ts";

export function rewriteReplayWitness(evidence: RenderedRewriteEvidence, rules: CustomPrivacyRule[]): RewriteReplayWitness {
  if (!record(evidence)) throw new Error("invalid_rewrite_witness");
  const hashes = [evidence.layoutHash, evidence.baseFieldsHash, evidence.resultFieldsHash, evidence.baseViewHash, evidence.resultViewHash];
  if (evidence.version !== 1 || evidence.rendererRevision !== RENDERED_REWRITE_REVISION
    || evidence.structuralProjection !== "legacy_object_assignment_v1" || !Array.isArray(evidence.edits)
    || hashes.some(value => typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value))) throw new Error("invalid_rewrite_witness");
  return { version: 1, rendererRevision: RENDERED_REWRITE_REVISION, structuralProjection: "legacy_object_assignment_v1", customRulesHash: hash(stableJson(rules)),
    layoutHash: evidence.layoutHash, baseFieldsHash: evidence.baseFieldsHash, resultFieldsHash: evidence.resultFieldsHash,
    baseViewHash: evidence.baseViewHash, resultViewHash: evidence.resultViewHash, editCount: evidence.edits.length, observationHash: hash(stableJson({ observations: evidence.observations, findings: evidence.findings, completion: evidence.completion })) };
}
export function replayRenderedRewrite(event: CanonicalToolEvent, witness: RewriteReplayWitness, historicalRules: CustomPrivacyRule[], historicalPrivacy: PrivacyFns): EvidenceResult {
  if (!record(witness) || !exactKeys(witness, ["version", "rendererRevision", "structuralProjection", "customRulesHash", "layoutHash", "baseFieldsHash", "resultFieldsHash", "baseViewHash", "resultViewHash", "editCount", "observationHash"])
    || witness.version !== 1 || witness.rendererRevision !== RENDERED_REWRITE_REVISION
    || witness.structuralProjection !== "legacy_object_assignment_v1" || witness.customRulesHash !== hash(stableJson(historicalRules))) return bad("binding");
  const regenerated = buildRenderedRewriteEvidence(event, historicalRules, historicalPrivacy);
  if (!regenerated.ok) return regenerated;
  if (stableJson(rewriteReplayWitness(regenerated.evidence, historicalRules)) !== stableJson(witness)) return bad("binding");
  return regenerated;
}
