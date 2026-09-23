import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { AuditRuntime } from "./runtime.ts";

function event(id) {
  return {id,ts:1,machineId:"device",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",
    nativeTool:"Read",input:"synthetic",redacted:"synthetic",risk:"info",decision:"allow",category:"other",
    workdirScope:"project",policyVersion:1,evaluation:"allow",enforcement:"offline"};
}

test("live audit worker preserves write ordering and has bounded calls", async (t) => {
  const dir = await mkdtemp(join(tmpdir(),"nmzp-audit-worker-"));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const runtime = await AuditRuntime.open(join(dir,"nmzp.db"),{create:true,retention:{minFreeBytes:0}});
  t.after(() => runtime.close());
  const writes=await Promise.all([runtime.append(event("a")),runtime.append(event("b"))]);
  assert.deepEqual(writes.map((result)=>result.inserted),[true,true]);
  assert.deepEqual((await runtime.query({limit:2})).events.map((row)=>row.id),["b","a"]);
  assert.equal((await runtime.status()).retained,2);
  assert.equal((await runtime.updateReceipt("device","a","delivered")).enforcement,"delivered");
  const db=new DatabaseSync(join(dir,"nmzp.db"));
  try {db.prepare("UPDATE audit_events SET body=? WHERE id='a'").run(Buffer.from("corrupt"));}
  finally {db.close();}
  await assert.rejects(runtime.get("device","a"),/audit_corrupt/);
  assert.equal((await runtime.status()).retained,2,"a corrupt row must not silently disable the whole store");
  const calls=Array.from({length:40},()=>runtime.status());
  assert.ok((await Promise.allSettled(calls)).some((result)=>result.status==="rejected"
    && result.reason.message==="audit_queue_full"));
  await runtime.close();
  await assert.rejects(runtime.status(),/audit_worker_closed/);
});

test("worker startup errors propagate without leaving a live worker", async () => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-missing-"));
  try {await assert.rejects(AuditRuntime.open(join(dir,"missing.db")),/ENOENT|unable to open|audit_schema_invalid/);}
  finally {await rm(dir,{recursive:true,force:true});}
});
