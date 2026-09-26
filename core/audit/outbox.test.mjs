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

it("does not accept an acknowledgement carrying a different eventId", async (t) => {
  const home = await mkdtemp(join(tmpdir(), "nmzp-outbox-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  const item = { kind: "receipt", eventId: "e", payload: { eventId: "e", evaluation: "block", enforcement: "returned_deny" } };
  assert.equal((await enqueueOutbox(home, creds, item, { now: 1000 })).queued, true);
  const drained = await drainOutbox(home, creds, {
    send: async () => ({ status: 200, body: { ok: true, eventId: "other" } }),
    now: 5000,
  });
  assert.equal(drained.acked, 0);
  assert.equal((await outboxStatus(home)).pending, 1);
});

for (const status of [401, 403, 409]) {
  it(`quarantines an outbox item when the server returns ${status}`, async (t) => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-outbox-"));
    t.after(() => rm(home, { recursive: true, force: true }));
    const item = { kind: "receipt", eventId: "e", payload: { eventId: "e", evaluation: "block", enforcement: "returned_deny" } };
    assert.equal((await enqueueOutbox(home, creds, item, { now: 1000 })).queued, true);
    const drained = await drainOutbox(home, creds, {
      send: async () => ({ status, body: { ok: false } }),
      now: 5000,
    });
    assert.equal(drained.acked, 0);
    const state = await outboxStatus(home);
    assert.equal(state.quarantined, 1);
    assert.equal(state.pending, 0);
  });
}

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

const OUTBOX_TTL_MS=7*86400_000;

async function tempHome(t){
  const home=await mkdtemp(join(tmpdir(),"nmzp-outbox-"));
  t.after(()=>rm(home,{recursive:true,force:true}));
  return home;
}
async function savedOutbox(home){
  return JSON.parse(await readFile(join(home,".nmzp","audit-outbox.json"),"utf8"));
}
async function writeOutbox(home,state){
  const {writeFile}=await import("node:fs/promises");
  await writeFile(join(home,".nmzp","audit-outbox.json"),JSON.stringify(state));
}
async function failRecoverable(home,times){
  let now=0;
  for(let i=0;i<times;i++){
    const state=await savedOutbox(home);
    if(state.items.length>0)now=state.items[0].nextAt;
    const drained=await drainOutbox(home,creds,{send:async()=>({status:503,body:{ok:false}}),now});
    assert.equal(drained.acked,0);
  }
  return now;
}

it("recoverable failures beyond eight attempts stay pending inside the ttl", async (t) => {
  const home=await tempHome(t);
  const createdAt=1000;
  assert.equal((await enqueueOutbox(home,creds,receipt("evt-retry"),{now:createdAt})).queued,true);
  const now=await failRecoverable(home,12);
  const status=await outboxStatus(home,{now});
  assert.deepEqual(
    {pending:status.pending,dropped:status.dropped,expired:status.expired},
    {pending:1,dropped:0,expired:0},
    "recoverable failures inside ttl stay pending",
  );
  assert.ok(now-createdAt<OUTBOX_TTL_MS);
  const saved=await savedOutbox(home);
  assert.equal(saved.items.length,1);
  assert.equal(saved.items[0].attempts,12);
  assert.equal(saved.items[0].createdAt,createdAt);
  assert.equal(saved.items[0].nextAt-now,3600_000);
  saved.items[0].attempts=1_000_000;
  await writeOutbox(home,saved);
  const capped=await drainOutbox(home,creds,{send:async()=>({status:503,body:{ok:false}}),now:saved.items[0].nextAt});
  assert.equal(capped.acked,0);
  const atCap=await savedOutbox(home);
  assert.equal(atCap.items.length,1);
  assert.equal(atCap.items[0].attempts,1_000_000);
  assert.equal((await outboxStatus(home,{now:saved.items[0].nextAt})).pending,1);
  atCap.items[0].attempts=1_000_001;
  await writeOutbox(home,atCap);
  await assert.rejects(()=>outboxStatus(home),{message:"outbox_corrupt"});
  atCap.items[0].attempts=-1;
  await writeOutbox(home,atCap);
  await assert.rejects(()=>outboxStatus(home),{message:"outbox_corrupt"});
});

it("a later matching ack removes the long-retried item exactly once", async (t) => {
  const home=await tempHome(t);
  const eventId="evt-long-retry";
  assert.equal((await enqueueOutbox(home,creds,receipt(eventId),{now:1000})).queued,true);
  let now=await failRecoverable(home,12);
  assert.equal((await outboxStatus(home,{now})).pending,1,"long-retried item remains until a matching ack");
  now=(await savedOutbox(home)).items[0].nextAt;
  const mismatch=await drainOutbox(home,creds,{send:async()=>({status:200,body:{ok:true,eventId:"other"}}),now});
  assert.equal(mismatch.acked,0);
  assert.equal((await outboxStatus(home,{now})).pending,1);
  now=(await savedOutbox(home)).items[0].nextAt;
  let sends=0;
  const matched=await drainOutbox(home,creds,{
    send:async()=>{sends++;return {status:200,body:{ok:true,eventId}};},
    now,
  });
  assert.equal(matched.acked,1);
  assert.equal(sends,1);
  assert.equal((await outboxStatus(home,{now})).pending,0);
  const repeat=await drainOutbox(home,creds,{
    send:async()=>{sends++;return {status:200,body:{ok:true,eventId}};},
    now,
  });
  assert.equal(repeat.acked,0);
  assert.equal(sends,1,"matching ack removes the item exactly once");
  assert.equal((await outboxStatus(home,{now})).pending,0);
});

it("items past the ttl expire and are counted as expired", async (t) => {
  const home=await tempHome(t);
  const createdAt=1_000_000;
  assert.equal((await enqueueOutbox(home,creds,receipt("evt-ttl"),{now:createdAt})).queued,true);
  let sends=0;
  const drained=await drainOutbox(home,creds,{
    send:async()=>{sends++;return {status:503,body:{ok:false}};},
    now:createdAt+OUTBOX_TTL_MS,
  });
  const status=await outboxStatus(home,{now:createdAt+OUTBOX_TTL_MS});
  assert.deepEqual(
    {pending:status.pending,dropped:status.dropped,expired:status.expired},
    {pending:0,dropped:0,expired:1},
    "ttl expiry is counted as expired",
  );
  assert.equal(sends,0);
  assert.equal(drained.acked,0);
});

it("401 403 409 still quarantine immediately", async (t) => {
  for(const status of [401,403,409]){
    const home=await tempHome(t);
    assert.equal((await enqueueOutbox(home,creds,receipt(`evt-${status}`),{now:1000})).queued,true);
    let calls=0;
    const drained=await drainOutbox(home,creds,{
      send:async()=>{calls++;return {status,body:{ok:false}};},
      now:1000,
    });
    const state=await outboxStatus(home,{now:1000});
    assert.equal(calls,1);
    assert.deepEqual(
      {acked:drained.acked,pending:state.pending,quarantined:state.quarantined,dropped:state.dropped,expired:state.expired},
      {acked:0,pending:0,quarantined:1,dropped:0,expired:0},
    );
  }
});

it("legacy outbox file with attempts below eight still loads", async (t) => {
  const home=await tempHome(t);
  assert.equal((await enqueueOutbox(home,creds,receipt("evt-legacy"),{now:1000})).queued,true);
  const state=await savedOutbox(home);
  state.items[0].attempts=7;
  await writeOutbox(home,state);
  const status=await outboxStatus(home,{now:1000});
  assert.equal(status.pending,1,"legacy attempts below eight still load");
  assert.equal(status.dropped,0);
  const drained=await drainOutbox(home,creds,{
    send:async()=>({status:200,body:{ok:true,eventId:"evt-legacy"}}),
    now:1000,
  });
  assert.equal(drained.acked,1);
  assert.equal((await outboxStatus(home,{now:1000})).pending,0);
});

it("status reports the oldest pending age without payloads", async (t) => {
  const home=await tempHome(t);
  assert.equal((await enqueueOutbox(home,creds,receipt("evt-newer-PAYLOAD_MARKER"),{now:15_000})).queued,true);
  assert.equal((await enqueueOutbox(home,creds,receipt("evt-older-PAYLOAD_MARKER"),{now:5_000})).queued,true);
  const status=await outboxStatus(home,{now:95_000});
  assert.deepEqual(status,{
    pending:2,dropped:0,expired:0,quarantined:0,conflicts:0,oldestPendingAgeMs:90_000,
  });
  assert.doesNotMatch(JSON.stringify(status),/SECRET_TOKEN|PAYLOAD_MARKER|synthetic/);
  const emptyHome=await tempHome(t);
  const empty=await outboxStatus(emptyHome,{now:95_000});
  assert.deepEqual(empty,{
    pending:0,dropped:0,expired:0,quarantined:0,conflicts:0,oldestPendingAgeMs:null,
  });
});
