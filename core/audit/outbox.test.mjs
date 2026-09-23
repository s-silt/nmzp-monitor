import assert from "node:assert/strict";
import { it, mock } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { enqueueOutbox, drainOutbox, outboxStatus } from "./outbox.ts";

const creds={deviceId:"m",token:"SECRET_TOKEN",url:"https://127.0.0.1:1",caPem:"synthetic",fingerprintSha256:"f".repeat(64)};

it("persists a bounded receipt without credentials and removes it only after core acknowledgement", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-"));t.after(()=>rm(home,{recursive:true,force:true}));
  const item={kind:"receipt",eventId:"e",payload:{eventId:"e",evaluation:"block",enforcement:"returned_deny"}};
  assert.equal((await enqueueOutbox(home,creds,item,{now:1000})).queued,true);
  const raw=await readFile(join(home,".nmzp","audit-outbox.json"),"utf8");
  assert.doesNotMatch(raw,/SECRET_TOKEN|synthetic/);
  assert.equal((await outboxStatus(home)).pending,1);
  const failed=await drainOutbox(home,creds,{send:async()=>({status:503,body:{ok:false}}),now:1000});
  assert.equal(failed.acked,0);
  assert.equal((await outboxStatus(home)).pending,1);
  const good=await drainOutbox(home,creds,{send:async()=>({status:200,body:{ok:true,eventId:"e"}}),now:5000});
  assert.equal(good.acked,1);
  assert.equal((await outboxStatus(home)).pending,0);
});

it("quarantines old identity after rejoin and never sends paused event metadata", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-"));t.after(()=>rm(home,{recursive:true,force:true}));
  await enqueueOutbox(home,creds,{kind:"event",eventId:"e",payload:{eventId:"e",ts:1,agent:"grok",tool:"Read",decision:"block",risk:"high",policyVersion:1}});
  let sent=0;
  await drainOutbox(home,creds,{allowEvents:false,send:async()=>{sent++;return {status:200,body:{ok:true,eventId:"e"}};}});
  assert.equal(sent,0);
  assert.equal((await outboxStatus(home)).pending,1);
  await drainOutbox(home,{...creds,deviceId:"new"},{send:async()=>{sent++;return {status:200,body:{ok:true,eventId:"e"}};}});
  assert.equal(sent,0);
  assert.equal((await outboxStatus(home)).quarantined,1);
});

it("accounts for queue-limit drops and a new identity can reuse an event ID", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-"));t.after(()=>rm(home,{recursive:true,force:true}));
  const old={kind:"event",eventId:"same",payload:{eventId:"same",ts:1,agent:"grok",tool:"Read",decision:"allow",risk:"info",policyVersion:1}};
  await enqueueOutbox(home,creds,old);
  const next={...creds,deviceId:"rejoined"};
  assert.equal((await enqueueOutbox(home,next,{...old,payload:{...old.payload,decision:"block"}})).queued,true);
  assert.equal((await outboxStatus(home)).quarantined,1);
  let full=false;
  for(let i=0;i<256;i++){
    const result=await enqueueOutbox(home,next,{kind:"event",eventId:`bulk-${i}`,
      payload:{eventId:`bulk-${i}`,ts:1,agent:"grok",tool:"Read",decision:"allow",risk:"info",policyVersion:1}});
    if(!result.queued){assert.equal(result.reason,"full");full=true;break;}
  }
  assert.equal(full,true);
  assert.ok((await outboxStatus(home)).dropped>0);
});


const TOTAL_BUDGET_MS=400;

async function listenReceiptServer(t,onRequest){
  const { createServer } = await import("node:https");
  const { generateNmzpCert } = await import("../tls.ts");
  const tls=generateNmzpCert(),requests=[];
  const server=createServer({key:tls.keyPem,cert:tls.certPem},(req,res)=>{
    requests.push(req.url);req.resume();onRequest(req,res);
  });
  await new Promise((resolve)=>server.listen(0,"127.0.0.1",resolve));
  t.after(()=>new Promise((resolve)=>{server.close(resolve);server.closeAllConnections();}));
  const address=server.address();
  if(!address||typeof address==="string")throw new Error("listen");
  return {requests,identity:{...creds,url:`https://127.0.0.1:${address.port}`,caPem:tls.certPem,fingerprintSha256:tls.fingerprintSha256}};
}

function receipt(eventId){
  return {kind:"receipt",eventId,payload:{eventId,evaluation:"allow",enforcement:"delivered"}};
}

it("legacy receipt fallback delivers through the receipt endpoint", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-fallback-"));
  t.after(()=>rm(home,{recursive:true,force:true}));
  const {requests,identity}=await listenReceiptServer(t,(req,res)=>{
    const backfill=req.url.endsWith("backfill");
    res.writeHead(backfill?404:200,{"content-type":"application/json"});
    res.end(JSON.stringify(backfill?{ok:false,error:"storage_not_enabled"}:{ok:true,eventId:"a"}));
  });
  await enqueueOutbox(home,identity,receipt("a"));
  const drained=await drainOutbox(home,identity,{timeoutMs:TOTAL_BUDGET_MS});
  assert.deepEqual(requests,["/api/v1/audit/backfill","/api/v1/receipt"],"legacy fallback reaches the receipt endpoint");
  assert.equal(drained.acked,1);assert.equal((await outboxStatus(home)).pending,0);
});

it("legacy receipt fallback and multiple queued items share one total network deadline", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-deadline-"));
  t.after(()=>rm(home,{recursive:true,force:true}));
  const origin=1_000_000;
  let now=origin;
  const {requests,identity}=await listenReceiptServer(t,(req,res)=>{
    if(req.url.endsWith("backfill"))now=origin+TOTAL_BUDGET_MS;
    const backfill=req.url.endsWith("backfill");
    res.writeHead(backfill?404:200,{"content-type":"application/json"});
    res.end(JSON.stringify(backfill?{ok:false,error:"storage_not_enabled"}:{ok:true,eventId:"a"}));
  });
  for(const eventId of ["a","b"])await enqueueOutbox(home,identity,receipt(eventId));
  const clock=mock.method(performance,"now",()=>now);
  try{
    const drained=await drainOutbox(home,identity,{timeoutMs:TOTAL_BUDGET_MS});
    assert.deepEqual(requests,["/api/v1/audit/backfill"],"exhausted total budget does not open a fresh fallback request");
    assert.equal(drained.acked,0);assert.equal((await outboxStatus(home)).pending,2);
  }finally{clock.mock.restore();}
});

it("queued items share one network budget", async (t) => {
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-budget-"));
  t.after(()=>rm(home,{recursive:true,force:true}));
  const origin=1_000_000;
  let now=origin;
  const shared=TOTAL_BUDGET_MS-Math.min(50,TOTAL_BUDGET_MS/10);
  for(const eventId of ["a","b"])await enqueueOutbox(home,creds,receipt(eventId));
  const calls=[];
  const clock=mock.method(performance,"now",()=>now);
  try{
    const drained=await drainOutbox(home,creds,{timeoutMs:TOTAL_BUDGET_MS,send:async(item,timeoutMs)=>{
      calls.push({eventId:item.eventId,timeoutMs});now+=timeoutMs;return {status:0,body:{}};
    }});
    assert.deepEqual(calls.map((call)=>call.eventId),["a"],"second item does not get a fresh budget");
    assert.equal(calls[0].timeoutMs,shared,"item uses the shared network budget");
    assert.equal(drained.acked,0);assert.equal((await outboxStatus(home)).pending,2);
  }finally{clock.mock.restore();}
});
