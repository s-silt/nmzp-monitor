import assert from "node:assert/strict";
import { it } from "node:test";
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


it("legacy receipt fallback and multiple queued items share one total network deadline", async (t) => {
  const { createServer } = await import("node:https");
  const { generateNmzpCert } = await import("../tls.ts");
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-deadline-"));
  t.after(()=>rm(home,{recursive:true,force:true}));
  const tls=generateNmzpCert(),requests=[];
  const server=createServer({key:tls.keyPem,cert:tls.certPem},(req,res)=>{
    requests.push(req.url);req.resume();
    const timer=setTimeout(()=>{
      res.writeHead(req.url.endsWith("backfill")?404:200,{"content-type":"application/json"});
      res.end(JSON.stringify(req.url.endsWith("backfill")?{ok:false,error:"storage_not_enabled"}:{ok:true,eventId:"a"}));
    },req.url.endsWith("backfill")?100:1000);
    res.once("close",()=>clearTimeout(timer));
  });
  await new Promise((resolve)=>server.listen(0,"127.0.0.1",resolve));
  t.after(()=>new Promise((resolve)=>{server.close(resolve);server.closeAllConnections();}));
  const identity={...creds,url:`https://127.0.0.1:${server.address().port}`,caPem:tls.certPem,fingerprintSha256:tls.fingerprintSha256};
  for(const eventId of ["a","b"])await enqueueOutbox(home,identity,{kind:"receipt",eventId,payload:{eventId,evaluation:"allow",enforcement:"delivered"}});
  const drained=await drainOutbox(home,identity,{timeoutMs:400});
  assert.deepEqual(requests,["/api/v1/audit/backfill","/api/v1/receipt"],"no fresh deadline for a second item after a fallback consumed the budget");
  assert.equal(drained.acked,0);assert.equal((await outboxStatus(home)).pending,2);
});
