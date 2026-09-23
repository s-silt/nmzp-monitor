import type { IncomingMessage, ServerResponse } from "node:http";
import { json, readLimited } from "../http-util.ts";
import type { NmzpStore } from "../persist.ts";

interface HistoryHttpContext {
  store: NmzpStore;
  requireAdmin: (req: IncomingMessage, res: ServerResponse) => boolean;
}

/** Optional version history routes; publication still uses the existing v1 policy route. */
export async function handlePolicyHistoryHttp(req: IncomingMessage, res: ServerResponse, pathname: string,
  search: URLSearchParams, context: HistoryHttpContext): Promise<boolean> {
  const list=req.method==="GET"&&pathname==="/api/v1/policy/history";
  const detail=req.method==="GET"&&/^\/api\/v1\/policy\/history\/[1-9][0-9]*$/.test(pathname);
  const restore=req.method==="POST"&&pathname==="/api/v1/policy/restore";
  if(!list&&!detail&&!restore)return false;
  if(!context.requireAdmin(req,res))return true;
  if(context.store.getStorageMode()!=="sqlite"){
    json(res,404,{ok:false,error:"storage_not_enabled"});return true;
  }
  if(list){
    const beforeRaw=search.get("beforeVersion"),limitRaw=search.get("limit");
    if((beforeRaw!==null&&!/^[1-9][0-9]*$/.test(beforeRaw))||(limitRaw!==null&&!/^[1-9][0-9]*$/.test(limitRaw))){
      json(res,400,{ok:false,error:"invalid_history_query"});return true;
    }
    const before=beforeRaw===null?Number.MAX_SAFE_INTEGER:Number(beforeRaw);
    const limit=limitRaw===null?50:Number(limitRaw);
    if(!Number.isSafeInteger(before)||!Number.isSafeInteger(limit)||limit>100){
      json(res,400,{ok:false,error:"invalid_history_query"});return true;
    }
    const revisions=context.store.listPolicyHistory(before,limit);
    json(res,200,{revisions,nextBeforeVersion:revisions.length===limit?revisions.at(-1)!.version:null});
    return true;
  }
  if(detail){
    const version=Number(pathname.slice("/api/v1/policy/history/".length));
    if(!Number.isSafeInteger(version)){json(res,400,{ok:false,error:"invalid_history_version"});return true;}
    const historical=context.store.getHistoricalPolicy(version);
    if(!historical){json(res,404,{ok:false,error:"policy_history_missing"});return true;}
    json(res,200,{version,formatVersion:historical.formatVersion,hash:historical.hash,
      publishedAt:historical.publishedAt,rulesHash:historical.rulesHash,engineVersion:historical.engineVersion,
      policy:historical.policy});
    return true;
  }
  const body=await readLimited(req);
  if(!body.ok){json(res,413,{ok:false,error:"payload_too_large"});return true;}
  let parsed:{expectedVersion?:number;sourceVersion?:number};
  try{parsed=JSON.parse(body.text||"{}");}catch{json(res,400,{ok:false,error:"bad_json"});return true;}
  if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)||!Number.isSafeInteger(parsed.expectedVersion)||!Number.isSafeInteger(parsed.sourceVersion)
    ||parsed.expectedVersion!<1||parsed.sourceVersion!<1){
    json(res,400,{ok:false,error:"invalid_restore_request"});return true;
  }
  if(!context.store.getHistoricalPolicy(parsed.sourceVersion!)){
    json(res,404,{ok:false,error:"policy_history_missing"});return true;
  }
  const restored=await context.store.restorePolicy(parsed.expectedVersion!,parsed.sourceVersion!);
  if("conflict" in restored){json(res,409,{ok:false,error:"cas_conflict",version:restored.version});return true;}
  json(res,200,{ok:true,version:restored.version,mode:restored.mode,stopped:restored.stopped});
  return true;
}
