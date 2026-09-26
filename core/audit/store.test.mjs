import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { it } from "node:test";
import { mkdtemp, rm, stat, statfs } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { decodeJson, encodeJson } from "./json-codec.ts";
import { AuditStore } from "./store.ts";

const event = (id, input = "x".repeat(4000)) => ({id,ts:100,machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Bash",nativeTool:"Bash",input,
  risk:"info",decision:"log",category:"other",workdirScope:"project",redacted:"summary",policyVersion:1,evaluation:"log",enforcement:"pending_verify"});

const incompressibleInput = () => randomBytes(100_000).toString("base64");

function pageSpace(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const pageCount = Number(db.prepare("PRAGMA page_count").get().page_count);
    const freelistCount = Number(db.prepare("PRAGMA freelist_count").get().freelist_count);
    const pageSize = Number(db.prepare("PRAGMA page_size").get().page_size);
    return {
      pageCount,
      freelistCount,
      pageSize,
      usedBytes: (pageCount - freelistCount) * pageSize,
      reusableBytes: freelistCount * pageSize,
    };
  } finally {
    db.close();
  }
}

async function appendUntilCapacity(store, path, payload, prefix, maxDbBytes) {
  let accepted = 0;
  let rejected = false;
  for (let i = 0; i < 40; i++) {
    try {
      await store.append(event(`${prefix}-${i}`, payload));
      accepted += 1;
      const size = (await stat(path)).size;
      assert.ok(size <= maxDbBytes, `physical file ${size} exceeds maxDbBytes ${maxDbBytes}`);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ERR_ASSERTION") throw error;
      assert.match(String(error), /audit_capacity_exceeded/);
      rejected = true;
      break;
    }
  }
  assert.equal(rejected, true);
  return accepted;
}

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

it("rejects a decodable body whose hash does not match", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const store = AuditStore.create(path, { minFreeBytes: 0 });
  await store.append(event("body-hash", "tiny"));
  const db = new DatabaseSync(path);
  try {
    const row = db.prepare("SELECT format_version, codec, raw_bytes, body, body_hash FROM audit_events WHERE id='body-hash'").get();
    const decoded = await decodeJson({
      version: row.format_version,
      codec: row.codec,
      rawBytes: row.raw_bytes,
      data: Buffer.from(row.body),
    });
    assert.equal(decoded && typeof decoded === "object" && !Array.isArray(decoded), true);
    decoded.redacted = "tampered-valid-body";
    const encoded = await encodeJson(decoded);
    assert.notEqual(createHash("sha256").update(encoded.data).digest("hex"), row.body_hash);
    db.prepare("UPDATE audit_events SET body=?, raw_bytes=?, codec=?, format_version=? WHERE id='body-hash'").run(
      encoded.data,
      encoded.rawBytes,
      encoded.codec,
      encoded.version,
    );
  } finally {
    db.close();
  }
  await assert.rejects(store.get("m", "body-hash"), /audit_corrupt/);
});

it("rejects a decodable body when ts or policyVersion differs", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const store = AuditStore.create(path, { minFreeBytes: 0 });
  await store.append(event("ts-row", "tiny"));
  await store.append(event("pv-row", "tiny"));
  const db = new DatabaseSync(path);
  try {
    db.prepare("UPDATE audit_events SET ts=? WHERE id='ts-row'").run(101);
    db.prepare("UPDATE audit_events SET policy_version=? WHERE id='pv-row'").run(2);
  } finally {
    db.close();
  }
  await assert.rejects(store.get("m", "ts-row"), /audit_corrupt/);
  await assert.rejects(store.get("m", "pv-row"), /audit_corrupt/);
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

it("append reuses freelist pages after clear under a fixed maxDbBytes", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const maxDbBytes = 2 << 20;
  const store = AuditStore.create(path, { maxDbBytes, maxRecords: 100, minFreeBytes: 0 });
  const payload = incompressibleInput();
  const accepted = await appendUntilCapacity(store, path, payload, "fill", maxDbBytes);
  assert.ok(accepted >= 10, `accepted ${accepted} incompressible events before the ceiling`);
  assert.equal(store.clear(), accepted);
  const cleared = store.status();
  const space = pageSpace(path);
  assert.equal(cleared.retained, 0);
  assert.ok(cleared.tombstones > 0);
  assert.ok(cleared.reusableBytes > 0);
  assert.equal(cleared.reusableBytes, space.reusableBytes);
  assert.equal(cleared.dbBytes, (await stat(path)).size);
  assert.ok(cleared.dbBytes <= maxDbBytes);
  await assert.doesNotReject(
    () => store.append(event("reused", payload)),
    "append after clear must reuse freed pages",
  );
  const after = store.status();
  const afterSpace = pageSpace(path);
  const size = (await stat(path)).size;
  assert.equal(after.retained, 1);
  assert.equal((await store.get("m", "reused"))?.id, "reused");
  assert.equal(after.usedBytes, afterSpace.usedBytes);
  assert.equal(after.reusableBytes, afterSpace.reusableBytes);
  assert.equal(after.usedBytes + after.reusableBytes, afterSpace.pageCount * afterSpace.pageSize);
  assert.equal(after.dbBytes, size);
  assert.ok(size <= maxDbBytes, `physical file ${size} exceeds maxDbBytes ${maxDbBytes}`);
  assert.ok(after.tombstones > 0);
});

it("capacity still refuses growth beyond reusable pages", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const maxDbBytes = 2 << 20;
  const store = AuditStore.create(path, { maxDbBytes, maxRecords: 100, minFreeBytes: 0 });
  const payload = incompressibleInput();
  const accepted = await appendUntilCapacity(store, path, payload, "seed", maxDbBytes);
  assert.ok(accepted >= 10);
  assert.equal(store.clear(), accepted);
  const cleared = store.status();
  assert.equal(cleared.retained, 0);
  assert.ok(cleared.tombstones > 0);
  assert.ok(cleared.reusableBytes > 0);
  assert.ok(cleared.dbBytes <= maxDbBytes);
  let reused = 0;
  let rejected = false;
  let size = (await stat(path)).size;
  for (let i = 0; i < 40; i++) {
    try {
      await store.append(event(`burst-${i}`, payload));
      reused += 1;
      size = (await stat(path)).size;
      assert.ok(size <= maxDbBytes, `physical file ${size} exceeds maxDbBytes ${maxDbBytes}`);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ERR_ASSERTION") throw error;
      assert.match(String(error), /audit_capacity_exceeded/);
      assert.equal((await stat(path)).size, size);
      rejected = true;
      break;
    }
  }
  assert.equal(rejected, true);
  assert.ok(reused >= 1, "burst must accept a write that fits in reusable pages");
  assert.ok(size <= maxDbBytes);
  const after = store.status();
  const space = pageSpace(path);
  assert.equal(after.usedBytes, space.usedBytes);
  assert.equal(after.reusableBytes, space.reusableBytes);
  assert.equal(after.dbBytes, size);
  assert.ok(after.tombstones >= accepted);
});

it("free-disk floor still refuses", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db");
  const store = AuditStore.create(path, { maxRecords: 100, minFreeBytes: 0 });
  await store.append(event("bulk", incompressibleInput()));
  assert.equal(store.clear(), 1);
  const cleared = store.status();
  assert.equal(cleared.retained, 0);
  assert.ok(cleared.tombstones > 0);
  assert.ok(cleared.reusableBytes > 0);
  const free = await statfs(dir);
  const freeBytes = Number(free.bavail) * Number(free.bsize);
  const minFreeBytes = Number.MAX_SAFE_INTEGER;
  assert.ok(freeBytes < minFreeBytes);
  const floored = AuditStore.open(path, false, {
    maxRecords: 100,
    minFreeBytes,
    maxDbBytes: cleared.limits.maxDbBytes,
  });
  assert.ok(floored.status().reusableBytes > 0);
  await assert.rejects(floored.append(event("floor", "tiny")), /audit_capacity_exceeded/);
  assert.equal(await floored.get("m", "floor"), undefined);
});
