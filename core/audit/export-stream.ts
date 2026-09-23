import { type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import type { NmzpStore } from "../persist.ts";
import type { StoredEvent } from "../schema.ts";
import type { AuditQuery } from "./store.ts";

export interface AuditExportOptions {
  response: ServerResponse;
  store: NmzpStore;
  format: "json" | "jsonl";
  gzip: boolean;
  filter: Omit<AuditQuery,"limit"|"highWatermark"|"beforeSeq">;
  project: (event: StoredEvent) => unknown;
  signal?: AbortSignal;
}

/** Fixed database cutoff; pages and serializes incrementally, including gzip. */
export async function writeAuditExport(options: AuditExportOptions): Promise<void> {
  const deletionWatermark=await options.store.auditDeletionHighWatermark();
  const first = await options.store.queryAudit({limit:25,...options.filter});
  const metadata = {kind:"metadata",formatVersion:1,highWatermark:first.highWatermark,
    filters:options.filter,historyCompleteness:"unknown",startedAt:Date.now()};
  const signal = options.signal;
  async function* chunks(): AsyncGenerator<string> {
    let page = first;
    let count = 0;
    let comma = false;
    if (options.format === "json") yield `{"metadata":${JSON.stringify(metadata)},"events":[`;
    else yield `${JSON.stringify(metadata)}\n`;
    while (true) {
      if (signal?.aborted) throw new Error("audit_export_cancelled");
      for (const event of page.events) {
        if (signal?.aborted) throw new Error("audit_export_cancelled");
        const item = JSON.stringify(options.project(event));
        yield options.format === "json" ? `${comma?",":""}${item}` : `${item}\n`;
        comma = true;
        count++;
      }
      if (page.nextBeforeSeq === null) break;
      page = await options.store.queryAudit({limit:25,...options.filter,
        highWatermark:first.highWatermark,beforeSeq:page.nextBeforeSeq});
    }
    const deletionsDuringExport=await options.store.auditDeletionsAfter(deletionWatermark,first.highWatermark);
    const complete=deletionsDuringExport===0;
    if (options.format === "json") yield `],"exportedCount":${count},"complete":${complete},"deletionsDuringExport":${deletionsDuringExport}}\n`;
    else yield `${JSON.stringify({kind:"summary",exportedCount:count,complete,deletionsDuringExport})}\n`;
  }

  options.response.writeHead(200, {
    "content-type":options.format === "json" ? "application/json; charset=utf-8" : "application/x-ndjson; charset=utf-8",
    "cache-control":"no-store",
    ...(options.gzip ? {"content-encoding":"gzip"} : {}),
  });
  const source=Readable.from(chunks());
  if (options.gzip) await pipeline(source,createGzip(),options.response,{signal});
  else await pipeline(source,options.response,{signal});
}
