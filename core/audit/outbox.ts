import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import { TextDecoder } from "node:util";
import { pinnedHttps } from "../https-client.ts";
import { withFileLock } from "../file-lock.ts";
import type { DeviceCreds } from "../hook.ts";
import { parseBackfill } from "./backfill.ts";

export type OutboxPayload =
  | {kind:"receipt";eventId:string;payload:{eventId:string;evaluation:string;enforcement:string}}
  | {kind:"event";eventId:string;payload:{eventId:string;ts:number;agent:string;tool:string;decision:string;risk:string;policyVersion:number;ruleId?:string}};

type Pending = OutboxPayload & {binding:string;payloadHash:string;createdAt:number;attempts:number;nextAt:number};
interface State {formatVersion:1;items:Pending[];dropped:number;expired:number;quarantined:number;conflicts:number}
const MAX_ITEMS=256;
const MAX_BYTES=256*1024;
const MAX_AGE=7*86400_000;
const MAX_ATTEMPTS=8;
const LOCK_MS=200;
const RECEIPT_FIELDS=new Set(["eventId","evaluation","enforcement"]);
const EVENT_FIELDS=new Set(["eventId","ts","agent","tool","decision","risk","policyVersion","ruleId"]);

function path(home:string){return join(home,".nmzp","audit-outbox.json");}
function initial():State{return {formatVersion:1,items:[],dropped:0,expired:0,quarantined:0,conflicts:0};}
function binding(creds:DeviceCreds):string {
  return createHash("sha256").update(JSON.stringify([creds.deviceId,creds.token,creds.fingerprintSha256])).digest("hex");
}
function hash(payload:OutboxPayload):string{return createHash("sha256").update(JSON.stringify(payload)).digest("hex");}
function validate(item:OutboxPayload):void {
  if(!parseBackfill(item))throw new Error("outbox_payload_invalid");
  if(!item || !["receipt","event"].includes(item.kind) || typeof item.eventId!=="string" || !item.eventId
    || item.eventId.length>128 || !item.payload || typeof item.payload!=="object" || Array.isArray(item.payload)
    || item.payload.eventId!==item.eventId)throw new Error("outbox_payload_invalid");
  const allowed=item.kind==="receipt"?RECEIPT_FIELDS:EVENT_FIELDS;
  if(Object.keys(item.payload).some((key)=>!allowed.has(key)))throw new Error("outbox_payload_invalid");
  if(item.kind==="event" && (!Number.isSafeInteger(item.payload.ts)||!Number.isSafeInteger(item.payload.policyVersion)))throw new Error("outbox_payload_invalid");
  if(Buffer.byteLength(JSON.stringify(item),"utf8")>2048)throw new Error("outbox_payload_invalid");
}
async function load(home:string):Promise<State>{
  const file=path(home);
  try {
    const info=await lstat(file);
    if(!info.isFile() || info.isSymbolicLink() || info.size>MAX_BYTES)throw new Error("outbox_corrupt");
    const bytes=await readFile(file);
    if(bytes.length>MAX_BYTES)throw new Error("outbox_corrupt");
    const state=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)) as State;
    if(state.formatVersion!==1 || !Array.isArray(state.items) || state.items.length>MAX_ITEMS
      || !Number.isSafeInteger(state.dropped) || !Number.isSafeInteger(state.expired)
      || !Number.isSafeInteger(state.quarantined) || !Number.isSafeInteger(state.conflicts))throw new Error("outbox_corrupt");
    for(const entry of state.items){
      const item={kind:entry.kind,eventId:entry.eventId,payload:entry.payload} as OutboxPayload;
      try{validate(item);}catch{throw new Error("outbox_corrupt");}
      if(!/^[a-f0-9]{64}$/.test(entry.binding)||entry.payloadHash!==hash(item)
        || !Number.isSafeInteger(entry.createdAt)||!Number.isSafeInteger(entry.nextAt)
        || !Number.isSafeInteger(entry.attempts)||entry.attempts<0||entry.attempts>=MAX_ATTEMPTS)throw new Error("outbox_corrupt");
    }
    return state;
  } catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return initial();throw error;}
}
async function save(home:string,state:State):Promise<void>{
  const dir=join(home,".nmzp");await mkdir(dir,{recursive:true,mode:0o700});
  const bytes=JSON.stringify(state);
  if(Buffer.byteLength(bytes,"utf8")>MAX_BYTES)throw new Error("outbox_full");
  const temporary=join(dir,`audit-outbox.json.tmp.${process.pid}.${randomUUID()}`);
  const handle=await open(temporary,"wx",0o600);
  let renamed=false;
  try {await handle.writeFile(bytes);await handle.sync();await handle.close();await rename(temporary,path(home));renamed=true;}
  finally {try{await handle.close();}catch{/* already closed after write */}if(!renamed)await unlink(temporary).catch(()=>undefined);}
}
function expire(state:State,now:number):void {
  const before=state.items.length;
  state.items=state.items.filter((item)=>now-item.createdAt<MAX_AGE);
  state.expired+=before-state.items.length;
}
async function transact<T>(home:string,fn:(state:State)=>Promise<T>|T):Promise<T>{
  return withFileLock(join(home,".nmzp"),async()=>{
    const state=await load(home);
    const result=await fn(state);
    await save(home,state);
    return result;
  },{timeoutMs:LOCK_MS});
}

export async function enqueueOutbox(home:string,creds:DeviceCreds,item:OutboxPayload,options:{now?:number}={}):Promise<{queued:boolean;reason?:string}> {
  validate(item);
  const now=options.now??Date.now();
  return transact(home,(state)=>{
    expire(state,now);
    const payloadHash=hash(item), key=`${item.kind}:${item.eventId}`, owner=binding(creds);
    const priorIndex=state.items.findIndex((entry)=>`${entry.kind}:${entry.eventId}`===key);
    const prior=priorIndex<0?undefined:state.items[priorIndex];
    if(prior && prior.binding!==owner){state.items.splice(priorIndex,1);state.quarantined++;}
    else if(prior){if(prior.payloadHash!==payloadHash){state.conflicts++;return {queued:false,reason:"conflict"};}return {queued:true};}
    if(state.items.length>=MAX_ITEMS){state.dropped++;return {queued:false,reason:"full"};}
    state.items.push({...item,binding:owner,payloadHash,createdAt:now,attempts:0,nextAt:now});
    if(Buffer.byteLength(JSON.stringify(state),"utf8")>MAX_BYTES){state.items.pop();state.dropped++;return {queued:false,reason:"full"};}
    return {queued:true};
  });
}

export async function outboxStatus(home:string){
  const state=await load(home);
  return {pending:state.items.length,dropped:state.dropped,expired:state.expired,
    quarantined:state.quarantined,conflicts:state.conflicts};
}

type Sender=(item:OutboxPayload)=>Promise<{status:number;body:Record<string,unknown>}>;
async function realSend(creds:DeviceCreds,item:OutboxPayload,timeoutMs:number):ReturnType<Sender>{
  let result=await pinnedHttps({url:`${creds.url}/api/v1/audit/backfill`,method:"POST",
    body:JSON.stringify({kind:item.kind,eventId:item.eventId,payload:item.payload}),headers:{authorization:`Bearer ${creds.token}`,"content-type":"application/json"},
    caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256,timeoutMs,maxBodyBytes:8192});
  // The default 2,000-row window mode retains the existing receipt endpoint.
  if(item.kind==="receipt" && result.status===404){
    result=await pinnedHttps({url:`${creds.url}/api/v1/receipt`,method:"POST",
      body:JSON.stringify(item.payload),headers:{authorization:`Bearer ${creds.token}`,"content-type":"application/json"},
      caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256,timeoutMs,maxBodyBytes:8192});
  }
  let body:Record<string,unknown>={};
  try{body=JSON.parse(result.body||"{}");}catch{body={};}
  return {status:result.status,body};
}

export async function drainOutbox(home:string,creds:DeviceCreds,options:{allowEvents?:boolean;now?:number;maxItems?:number;timeoutMs?:number;send?:Sender}={}):Promise<{acked:number;pending:number}> {
  const now=options.now??Date.now(),owner=binding(creds),max=Math.min(2,Math.max(1,options.maxItems??2));
  const selected=await transact(home,(state)=>{
    expire(state,now);
    const before=state.items.length;
    state.items=state.items.filter((item)=>item.binding===owner);
    state.quarantined+=before-state.items.length;
    return state.items.filter((item)=>item.nextAt<=now && (options.allowEvents!==false || item.kind==="receipt"))
      .sort((a,b)=>(a.kind==="event"?0:1)-(b.kind==="event"?0:1)||a.createdAt-b.createdAt).slice(0,max);
  });
  let acked=0;
  for(const item of selected){
    let result:{status:number;body:Record<string,unknown>};
    try{result=await (options.send??((entry)=>realSend(creds,entry,options.timeoutMs??500)))(item);}
    catch{result={status:0,body:{}};}
    const acknowledged=result.status===200 && result.body.ok===true && result.body.eventId===item.eventId;
    await transact(home,(state)=>{
      const index=state.items.findIndex((entry)=>entry.kind===item.kind && entry.eventId===item.eventId && entry.payloadHash===item.payloadHash);
      if(index<0)return;
      if(acknowledged){state.items.splice(index,1);acked++;return;}
      if(result.status===404 && result.body.error==="storage_not_enabled"){
        state.items.splice(index,1);state.dropped++;return;
      }
      if([401,403,409].includes(result.status)){state.items.splice(index,1);state.quarantined++;return;}
      const entry=state.items[index];entry.attempts++;
      if(entry.attempts>=MAX_ATTEMPTS){state.items.splice(index,1);state.dropped++;return;}
      entry.nextAt=now+Math.min(3600_000,1000*2**entry.attempts);
    });
  }
  return {acked,pending:(await load(home)).items.length};
}
