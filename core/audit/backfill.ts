import type { Decision, Enforcement, Risk } from "../schema.ts";

export type BackfillRequest =
  | {kind:"event";eventId:string;payload:{eventId:string;ts:number;agent:string;tool:string;decision:Decision;
      risk:Risk;policyVersion:number;ruleId?:string}}
  | {kind:"receipt";eventId:string;payload:{eventId:string;evaluation:Decision;enforcement:Enforcement}};

const DECISIONS=new Set(["block","confirm","allow","log","rewrite"]);
const RISKS=new Set(["high","medium","low","info"]);
const ENFORCEMENTS=new Set(["blocked","returned_deny","pending_verify","timeout","failed","delivered","offline","degraded"]);
function record(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==="object"&&!Array.isArray(v);}
function keys(v:Record<string,unknown>,allowed:readonly string[]):boolean{return Object.keys(v).every((key)=>allowed.includes(key));}
function label(v:unknown,max=128):v is string{return typeof v==="string"&&v.length>0&&v.length<=max
  && ![...v].some((char)=>{const code=char.codePointAt(0)!;return code<32||code===127;});}

/** Strict metadata-only protocol; input, command, URL and redacted body are forbidden. */
export function parseBackfill(raw:unknown):BackfillRequest|null {
  if(!record(raw)||!keys(raw,["kind","eventId","payload"])||!label(raw.eventId)||!record(raw.payload))return null;
  const p=raw.payload;
  if(p.eventId!==raw.eventId)return null;
  if(raw.kind==="receipt"){
    if(!keys(p,["eventId","evaluation","enforcement"])||!DECISIONS.has(p.evaluation as string)||!ENFORCEMENTS.has(p.enforcement as string))return null;
    return raw as BackfillRequest;
  }
  if(raw.kind==="event"){
    if(!keys(p,["eventId","ts","agent","tool","decision","risk","policyVersion","ruleId"])
      || !Number.isSafeInteger(p.ts) || (p.ts as number)<0 || !Number.isSafeInteger(p.policyVersion) || (p.policyVersion as number)<1
      || !label(p.agent,64) || !label(p.tool,128) || !DECISIONS.has(p.decision as string)||!RISKS.has(p.risk as string)
      || (p.ruleId!==undefined&&!label(p.ruleId,128)))return null;
    return raw as BackfillRequest;
  }
  return null;
}
