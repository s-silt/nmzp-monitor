/** Public metadata only; counters describe this process load, never a lifetime integrity ledger. */
export interface EvidenceWindow {
  limit: number;
  retained: number;
  droppedSinceLoad: number;
  invalidLinesOnLoad: number;
  loadedAt: number;
  oldestTs?: number;
  newestTs?: number;
  historyCompleteness: "unknown";
  receiptDelivery: "best_effort";
  networkMirrorState?: "current" | "repair_required";
}
export function parseEvidenceWindow(raw: unknown): EvidenceWindow | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  const keys = ["limit", "retained", "droppedSinceLoad", "invalidLinesOnLoad", "loadedAt"] as const;
  for (const k of keys)
    if (typeof r[k] !== "number" || !Number.isSafeInteger(r[k]) || (r[k] as number) < 0)
      return undefined;
  if (
    r.historyCompleteness !== "unknown" ||
    r.receiptDelivery !== "best_effort" ||
    (r.retained as number) > (r.limit as number)
  )
    return undefined;
  const out: EvidenceWindow = {
    limit: r.limit as number,
    retained: r.retained as number,
    droppedSinceLoad: r.droppedSinceLoad as number,
    invalidLinesOnLoad: r.invalidLinesOnLoad as number,
    loadedAt: r.loadedAt as number,
    historyCompleteness: "unknown",
    receiptDelivery: "best_effort",
  };
  for (const key of ["oldestTs", "newestTs"] as const)
    if (typeof r[key] === "number" && Number.isSafeInteger(r[key]) && r[key] > 0) out[key] = r[key];
  if (r.networkMirrorState === "current" || r.networkMirrorState === "repair_required") out.networkMirrorState = r.networkMirrorState;
  return out;
}
