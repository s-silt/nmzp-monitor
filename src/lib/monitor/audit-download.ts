/** Bounded browser export: stream to a chosen file; small-browser fallback is capped. */
export interface AuditExportStreamOptions {
  format?: "json" | "jsonl";
  gzip?: boolean;
  machineId?: string;
  agent?: string;
  decision?: string;
  risk?: string;
  ruleId?: string;
  fromTs?: number;
  toTs?: number;
  signal?: AbortSignal;
  onProgress?: (progress: { bytesRead: number; status: "downloading" | "completed" | "error" | "cancelled" }) => void;
  /** Explicit output for embedders/tests; ordinary UI uses the browser save dialog. */
  destination?: WritableStream<Uint8Array>;
}

export interface AuditExportDownloadResult {
  ok: boolean;
  complete?: boolean;
  deletionsDuringExport?: number;
  exportedCount?: number;
  totalBytes: number;
  status?: number;
  error?: string;
}

const FALLBACK_LIMIT = 16 * 1024 * 1024;

async function outputFile(options: AuditExportStreamOptions): Promise<WritableStream<Uint8Array>> {
  if (options.destination) return options.destination;
  const extension = `${options.format ?? "json"}${options.gzip ? ".gz" : ""}`;
  const name = `nmzp-audit-${Date.now()}.${extension}`;
  const picker = (globalThis as typeof globalThis & {
    showSaveFilePicker?: (options: { suggestedName: string }) => Promise<{ createWritable(): Promise<WritableStream<Uint8Array>> }>;
  }).showSaveFilePicker;
  if (picker) return (await picker({ suggestedName: name })).createWritable();
  if (typeof document === "undefined") throw new Error("streaming_save_unavailable");
  // Browsers without file streams may download a small export, never an unbounded Blob.
  let bytes = 0;
  let chunks: Uint8Array[] = [];
  return new WritableStream<Uint8Array>({
    write(chunk) {
      bytes += chunk.byteLength;
      if (bytes > FALLBACK_LIMIT) throw new Error("streaming_save_required_above_16_mib");
      chunks.push(chunk.slice());
    },
    close() {
      const blob = new Blob(chunks as BlobPart[], { type: options.gzip ? "application/gzip" : "application/octet-stream" });
      chunks = [];
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    },
    abort() { chunks = []; },
  });
}

function summary(tail: string, format: "json" | "jsonl") {
  let value: Record<string, unknown>;
  if (format === "jsonl") {
    const line = tail.trimEnd().split("\n").at(-1);
    try { value = JSON.parse(line ?? "") as Record<string, unknown>; }
    catch { throw new Error("incomplete_stream_missing_summary"); }
    if (!value || value.kind !== "summary") throw new Error("incomplete_stream_missing_summary");
  } else {
    const match = tail.match(/\],"exportedCount":(\d+),"complete":(true|false),"deletionsDuringExport":(\d+)\}\s*$/);
    if (!match) throw new Error("incomplete_stream_missing_summary");
    value = { exportedCount: Number(match[1]), complete: match[2] === "true", deletionsDuringExport: Number(match[3]) };
  }
  if (typeof value.complete !== "boolean" || !Number.isSafeInteger(value.exportedCount)
    || (value.exportedCount as number) < 0 || !Number.isSafeInteger(value.deletionsDuringExport)
    || (value.deletionsDuringExport as number) < 0) throw new Error("invalid_export_summary");
  return { complete: value.complete, exportedCount: value.exportedCount as number,
    deletionsDuringExport: value.deletionsDuringExport as number };
}

export async function streamAuditDownload(options: AuditExportStreamOptions, headers: HeadersInit): Promise<AuditExportDownloadResult> {
  let totalBytes = 0;
  let status: number | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let writer: { write(chunk: Uint8Array<ArrayBuffer>): Promise<void>; close(): Promise<void>;
    abort(reason?: unknown): Promise<void>; releaseLock(): void } | undefined;
  let outputDone: Promise<void> | undefined;
  const cancel = () => { void reader?.cancel().catch(() => {}); };
  try {
    options.signal?.throwIfAborted();
    const destination = await outputFile(options);
    // Fetch decodes Content-Encoding. Recompress the saved file so .gz contains gzip bytes.
    if (options.gzip) {
      const compression = new CompressionStream("gzip");
      outputDone = compression.readable.pipeTo(destination, { signal: options.signal });
      void outputDone.catch(() => {});
      writer = compression.writable.getWriter();
    } else writer = destination.getWriter();
    const params = new URLSearchParams();
    for (const key of ["format", "machineId", "agent", "decision", "risk", "ruleId", "fromTs", "toTs"] as const) {
      const value = options[key];
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
    params.set("gzip", options.gzip ? "1" : "0");
    const res = await fetch(`/api/v1/audit/export?${params}`, { credentials: "include", headers, signal: options.signal });
    status = res.status;
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => null);
      throw new Error(body && typeof body === "object" && "error" in body && typeof body.error === "string" ? body.error : `http_${res.status}`);
    }
    if (!res.body) throw new Error("empty_response_body");
    reader = res.body.getReader();
    options.signal?.addEventListener("abort", cancel, { once: true });
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let tail = "";
    while (true) {
      options.signal?.throwIfAborted();
      const { done, value } = await reader.read();
      options.signal?.throwIfAborted();
      if (done) break;
      totalBytes += value.byteLength;
      tail = (tail + decoder.decode(value, { stream: true })).slice(-4096);
      await writer.write(value.slice());
      options.onProgress?.({ bytesRead: totalBytes, status: "downloading" });
    }
    tail = (tail + decoder.decode()).slice(-4096);
    const result = summary(tail, options.format ?? "json");
    await writer.close();
    await outputDone;
    options.onProgress?.({ bytesRead: totalBytes, status: "completed" });
    return { ok: true, ...result, totalBytes };
  } catch (error) {
    await reader?.cancel().catch(() => {});
    await writer?.abort(error).catch(() => {});
    await outputDone?.catch(() => {});
    const cancelled = options.signal?.aborted || (error instanceof Error && error.name === "AbortError");
    options.onProgress?.({ bytesRead: totalBytes, status: cancelled ? "cancelled" : "error" });
    return { ok: false, status, error: cancelled ? "cancelled" : error instanceof Error ? error.message : "stream_error", totalBytes };
  } finally {
    options.signal?.removeEventListener("abort", cancel);
    reader?.releaseLock();
    writer?.releaseLock();
  }
}
