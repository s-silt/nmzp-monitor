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
