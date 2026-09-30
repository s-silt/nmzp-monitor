import type { PrivacyFns, RewriteSpan } from "./rewrite.ts";

export type RewritePhase = "outbound" | "walk" | "residue" | "persona_residue";
export type RewriteCoordinate = "operation_context" | "effective_leaf" | "url_api_component" | "decoded_url_path" | "decoded_url_query" | "prefixed_url_query" | "decoded_url_fragment" | "post_redaction_leaf" | "serialized_view" | "residue_string" | "decoded_residue_string" | "residue_url_component";
interface TraceContext { phase: RewritePhase; coordinate: RewriteCoordinate; viewLeafIndex: number | null }
export type RewriteObservation =
  | (TraceContext & { type: "scan"; scanner: "secrets" | "custom"; inputLength: number; hits: Array<{ index: number; length: number; kind: string | null }> })
  | (TraceContext & { type: "check"; check: "outbound" | "url_parse" | "url_text_fallback" | "shell_piece" | "unquoted_redirect" | "residue" | "persona_residue"; result: "pass" | "fail" | "true" | "false" | "fallback" })
  | (TraceContext & { type: "persona"; changed: boolean })
  | { type: "leaf"; viewLeafIndex: number; path: string[]; before: string; after?: string; status: "enter" | "complete" | "refused" };
export type RewriteObserver = (observation: RewriteObservation) => void;

/** Optional isolated observation. Callback failure or mutation never changes the real rewrite. */
export class RewriteTrace {
  phase: RewritePhase = "outbound";
  coordinate: RewriteCoordinate = "operation_context";
  viewLeafIndex: number | null = null;
  private nextLeaf = 0;
  private observer: RewriteObserver;
  constructor(observer: RewriteObserver) { this.observer = observer; }
  emit(build: () => RewriteObservation): void {
    try { this.observer(build()); } catch { /* Observation is not enforcement. */ }
  }
  context(): TraceContext { return { phase: this.phase, coordinate: this.coordinate, viewLeafIndex: this.viewLeafIndex }; }
  check(check: Extract<RewriteObservation, { type: "check" }>["check"], result: Extract<RewriteObservation, { type: "check" }>["result"]): void {
    this.emit(() => ({ ...this.context(), type: "check", check, result }));
  }
  leaf(path: string[], before: string): number {
    const index = this.nextLeaf++;
    this.viewLeafIndex = index; this.coordinate = "effective_leaf";
    this.emit(() => ({ type: "leaf", viewLeafIndex: index, path: [...path], before, status: "enter" }));
    return index;
  }
  endLeaf(index: number, path: string[], before: string, after?: string): void {
    this.emit(() => ({ type: "leaf", viewLeafIndex: index, path: [...path], before, ...(after === undefined ? {} : { after }), status: after === undefined ? "refused" : "complete" }));
    this.viewLeafIndex = null;
  }
  inCoordinate<T>(coordinate: RewriteCoordinate, run: () => T): T {
    const previous = this.coordinate; this.coordinate = coordinate;
    try { return run(); } finally { this.coordinate = previous; }
  }
  privacy(original: PrivacyFns): PrivacyFns {
    const scanned = (scanner: "secrets" | "custom", text: string, hits: RewriteSpan[]) => {
      this.emit(() => ({ ...this.context(), type: "scan", scanner, inputLength: text.length,
        hits: hits.map(hit => ({ index: hit.index, length: hit.length, kind: typeof hit.kind === "string" ? hit.kind : null })) }));
      return hits;
    };
    return {
      ...original,
      scanSecrets: text => scanned("secrets", text, original.scanSecrets(text)),
      scanCustom: (text, rules) => scanned("custom", text, original.scanCustom(text, rules)),
      ...(original.cloakPersona ? { cloakPersona: (text: string) => {
        const result = original.cloakPersona!(text);
        this.emit(() => ({ ...this.context(), type: "persona", changed: result.changed }));
        return result;
      } } : {}),
      ...(original.shouldCloakPersona ? { shouldCloakPersona: (input: Parameters<NonNullable<PrivacyFns["shouldCloakPersona"]>>[0]) => {
        const result = original.shouldCloakPersona!(input); this.check("outbound", result ? "true" : "false"); return result;
      } } : {}),
    };
  }
}
