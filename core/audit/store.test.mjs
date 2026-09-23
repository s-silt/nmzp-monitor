import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { AuditStore } from "./store.ts";

const event = (id, input = "x".repeat(4000)) => ({id,ts:100,machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Bash",nativeTool:"Bash",input,
  risk:"info",decision:"log",category:"other",workdirScope:"project",redacted:"summary",policyVersion:1,evaluation:"log",enforcement:"pending_verify"});

it("stores compressed events durably, keeps receipts separate and detects conflicting IDs", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const path = join(dir,"nmzp.db");
  const store = AuditStore.create(path);
  assert.equal((await store.append(event("a"))).inserted,true);
  assert.equal((await store.append(event("a"))).inserted,false);
  await assert.rejects(store.append(event("a","different")),/audit_event_conflict/);
  const db = new DatabaseSync(path,{readOnly:true});
  const before = db.prepare("SELECT codec,body FROM audit_events WHERE id='a'").get();
  assert.equal(before.codec,"gzip");
  db.close();
  assert.equal((await store.updateReceipt("m","a","delivered")).enforcement,"delivered");
  assert.equal((await AuditStore.open(path).get("m","a")).enforcement,"delivered");
  const afterDb = new DatabaseSync(path,{readOnly:true});
  assert.deepEqual(afterDb.prepare("SELECT body FROM audit_events WHERE id='a'").get().body,before.body);
  afterDb.close();
});

it("pages by stable sequence when timestamps tie and new events arrive", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const store = AuditStore.create(join(dir,"nmzp.db"));
  for (let i=0;i<5;i++) await store.append(event(String(i),"tiny"));
  const first = await store.query({limit:2});
  assert.deepEqual(first.events.map((e)=>e.id),["4","3"]);
  await store.append(event("5","tiny"));
  const second = await store.query({limit:2,highWatermark:first.highWatermark,beforeSeq:first.nextBeforeSeq});
  assert.deepEqual(second.events.map((e)=>e.id),["2","1"]);
});

it("rejects corrupted compressed content instead of returning an empty event", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const path = join(dir,"nmzp.db");
  const store = AuditStore.create(path);
  await store.append(event("a"));
  const db = new DatabaseSync(path);
  db.prepare("UPDATE audit_events SET body=? WHERE id='a'").run(Buffer.from("not gzip"));
  db.close();
  await assert.rejects(store.get("m","a"),/audit_corrupt/);
});

it("record retention removes the oldest body but leaves a retry tombstone", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  const store=AuditStore.create(join(dir,"nmzp.db"),{maxRecords:2,maxAgeMs:0,minFreeBytes:0});
  for(const id of ["a","b","c"])await store.append(event(id,"tiny"));
  assert.deepEqual((await store.query({limit:10})).events.map((e)=>e.id),["c","b"]);
  assert.equal(await store.get("m","a"),undefined);
  assert.equal((await store.getTombstone("m","a"))?.reason,"max_records");
  const status=store.status();
  assert.equal(status.retained,2);
  assert.equal(status.deleted,1);
});

it("capacity failure is explicit and cannot acknowledge a missing event", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  const store=AuditStore.create(join(dir,"nmzp.db"),{maxDbBytes:1,minFreeBytes:0});
  await assert.rejects(store.append(event("full","tiny")),/audit_capacity_exceeded/);
  assert.equal(await store.get("m","full"),undefined);
});

it("clear removes durable history, records a range and preserves retry tombstones", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  const store=AuditStore.create(join(dir,"nmzp.db"),{minFreeBytes:0});
  await store.append(event("before","tiny"));
  const watermark=store.deletionHighWatermark();
  assert.equal(store.clear(),1);
  assert.deepEqual((await store.query({limit:10})).events,[]);
  assert.equal((await store.getTombstone("m","before"))?.reason,"admin_clear");
  assert.equal(store.deletionCountAfter(watermark,1),1);
  assert.equal(store.status().retained,0);
  await assert.rejects(store.append(event("before","tiny")),/audit_event_expired/);
});

it("maintenance catches up an aged or reduced-limit backlog in bounded steps", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  const path=join(dir,"nmzp.db"),initial=AuditStore.create(path,{maxRecords:10,maxAgeMs:0,minFreeBytes:0});
  for(let i=0;i<5;i++)await initial.append(event(String(i),"tiny"));
  const limited=AuditStore.open(path,false,{maxRecords:2,maxAgeMs:1000,minFreeBytes:0});
  const db=new DatabaseSync(path);
  try{db.prepare("UPDATE audit_events SET ingested_at=1 WHERE id='0'").run();}
  finally{db.close();}
  assert.ok(limited.status().retentionPending>=3);
  assert.equal(limited.maintenanceStep(Date.now()).removed,3);
  assert.equal(limited.status().retained,2);
  assert.equal(limited.status().retentionPending,0);
  assert.equal((await limited.getTombstone("m","0"))?.reason,"max_age");
});
