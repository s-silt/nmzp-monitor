import type { IncomingMessage, ServerResponse } from "node:http";
import { json } from "../http-util.ts";
import type { NmzpStore } from "../persist.ts";
import { writeAuditExport } from "./export-stream.ts";
import { publicStoredEvent } from "./public-event.ts";

interface AuditHttpContext {
  store: NmzpStore;
  requireAdmin: (req: IncomingMessage, res: ServerResponse) => boolean;
}

function queryNumber(search: URLSearchParams, name: string, fallback?: number): number | undefined {
  const value = search.get(name);
  if (value === null) return fallback;
  if (!/^[0-9]+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error("audit_query_invalid");
  return Number(value);
}

function filterFrom(search: URLSearchParams) {
  const filter = {
    fromTs: queryNumber(search,"fromTs"), toTs: queryNumber(search,"toTs"),
    machineId: search.get("machineId") ?? undefined, agent: search.get("agent") ?? undefined,
    decision: search.get("decision") ?? undefined, risk: search.get("risk") ?? undefined,
    ruleId: search.get("ruleId") ?? undefined,
  };
  if (Object.values(filter).some((value) => typeof value === "string" && (!value || value.length > 128))) {
    throw new Error("audit_query_invalid");
  }
  return filter;
}

/** Handles only the optional admin audit endpoints; old routes remain in serve.ts. */
export async function handleAuditHttp(req: IncomingMessage, res: ServerResponse, pathname: string,
  search: URLSearchParams, context: AuditHttpContext): Promise<boolean> {
  if (req.method !== "GET" || !["/api/v1/audit/events","/api/v1/audit/storage","/api/v1/audit/export"].includes(pathname)) {
    return false;
  }
  if (!context.requireAdmin(req,res)) return true;
  if (context.store.getStorageMode() !== "sqlite") {
    json(res,404,{ok:false,error:"storage_not_enabled"});
    return true;
  }
  if (pathname === "/api/v1/audit/storage") {
    json(res,200,await context.store.auditStatus());
    return true;
  }
  if (pathname === "/api/v1/audit/events") {
    let query;
    try {
      query = {limit:queryNumber(search,"limit",20)!,highWatermark:queryNumber(search,"highWatermark"),
        beforeSeq:queryNumber(search,"beforeSeq"),...filterFrom(search)};
      if(query.limit<1 || query.limit>25)throw new Error("audit_query_invalid");
    } catch { json(res,400,{ok:false,error:"audit_query_invalid"}); return true; }
    let page;
    try {page=await context.store.queryAudit(query);}
    catch(error){if(error instanceof Error && error.message==="audit_query_invalid"){
      json(res,400,{ok:false,error:"audit_query_invalid"});return true;
    }throw error;}
    const payload={events:page.events.map(publicStoredEvent),highWatermark:page.highWatermark,
      nextBeforeSeq:page.nextBeforeSeq,historyCompleteness:"unknown"};
    if(Buffer.byteLength(JSON.stringify(payload),"utf8")>4*1024*1024){
      json(res,413,{ok:false,error:"audit_page_too_large"});return true;
    }
    json(res,200,payload);
    return true;
  }
  const format=search.get("format")??"json",gzip=search.get("gzip")??"0";
  if ((format!=="json" && format!=="jsonl") || (gzip!=="0" && gzip!=="1")) {
    json(res,400,{ok:false,error:"audit_export_options_invalid"});return true;
  }
  let filter;
  try {filter=filterFrom(search);}
  catch {json(res,400,{ok:false,error:"audit_export_options_invalid"});return true;}
  const controller=new AbortController();
  res.once("close",()=>controller.abort());
  try {await writeAuditExport({response:res,store:context.store,format,gzip:gzip==="1",filter,
    project:publicStoredEvent,signal:controller.signal});}
  catch(error){if(!res.headersSent)throw error;if(!res.destroyed)res.destroy(error instanceof Error?error:undefined);}
  return true;
}
