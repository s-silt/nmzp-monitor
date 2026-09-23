import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadMonitor } from "./paths.ts";
import { AuditStore } from "./audit/store.ts";
import { NmzpStore } from "./persist.ts";
import { preflightDataDir, migrateDataDir, recoverPolicyProjection } from "./migrate.ts";

const source = await loadMonitor(dirname(fileURLToPath(import.meta.url)));
const policy = {version:4,updatedAt:4,mode:"enforcing",stopped:false,customRules:[]};
const event = (id) => ({id,ts:1,machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
  input:"x",risk:"info",decision:"allow",category:"other",workdirScope:"project",redacted:"x",policyVersion:2,evaluation:"allow",enforcement:"delivered"});

it("preflight is read only and reports legacy gaps, duplicates and a damaged tail", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-migrate-")); t.after(()=>rm(dir,{recursive:true,force:true}));
  await writeFile(join(dir,"policy.json"),JSON.stringify(policy));
  await writeFile(join(dir,"events.jsonl"),JSON.stringify(event("a"))+"\n"+JSON.stringify(event("a"))+"\n{" );
  const before=await readFile(join(dir,"events.jsonl"));
  const report=await preflightDataDir(dir,source);
  assert.equal(report.events.valid,2);
  assert.equal(report.events.duplicate,1);
  assert.equal(report.events.invalid,1);
  assert.equal(report.events.missingHistory,2);
  assert.equal(report.canMigrate,false);
  assert.deepEqual(await readFile(join(dir,"events.jsonl")),before);
});

it("explicit migration backs up raw files, resumes after interruption and does not invent old policy", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-migrate-")); t.after(()=>rm(dir,{recursive:true,force:true}));
  const policyBytes=Buffer.from(JSON.stringify(policy)+"\r\n");
  await writeFile(join(dir,"policy.json"),policyBytes);
  await writeFile(join(dir,"events.jsonl"),[event("a"),event("b")].map(JSON.stringify).join("\n")+"\n");
  await assert.rejects(migrateDataDir(dir,source,{afterImported:()=>{throw Error("synthetic_interrupt")}}),/synthetic_interrupt/);
  await assert.rejects(new NmzpStore(dir).load({storageMode:"sqlite",policySource:source}),/migration_incomplete/);
  assert.deepEqual(await readFile(join(dir,".nmzp-migration-backup","policy.json")),policyBytes);
  const done=await migrateDataDir(dir,source);
  assert.equal(done.state,"complete");
  const audit=AuditStore.open(join(dir,"nmzp.db"));
  assert.deepEqual((await audit.query({limit:10})).events.map((e)=>e.id),["b","a"]);
  assert.equal(done.historyBaselineVersion,4);
  assert.equal((await migrateDataDir(dir,source)).state,"complete");
  const store=new NmzpStore(dir);
  await store.load({storageMode:"sqlite",policySource:source});
  assert.equal(store.listEvents().length,2);
  assert.equal(store.getHistoricalPolicy(2),undefined);
  assert.equal(store.getHistoricalPolicy(4)?.hash!==undefined,true);
  await store.close();
  await assert.rejects(new NmzpStore(dir).load({policySource:source}),/storage_mode_mismatch/);
});

it("refuses a changed legacy source after interruption and preserves its original-byte backup", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-migrate-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  await writeFile(join(dir,"policy.json"),JSON.stringify(policy));
  const original=Buffer.from(JSON.stringify(event("one"))+"\r\n");
  await writeFile(join(dir,"events.jsonl"),original);
  await assert.rejects(migrateDataDir(dir,source,{afterImported:()=>{throw Error("synthetic_interrupt")}}),/synthetic_interrupt/);
  await writeFile(join(dir,"events.jsonl"),Buffer.from(JSON.stringify(event("one"))+"\n"));
  await assert.rejects(migrateDataDir(dir,source),/migration_source_changed/);
  assert.deepEqual(await readFile(join(dir,".nmzp-migration-backup","events.jsonl")),original);
});

it("recovery keeps the overwritten projection bytes and restores only the committed database revision", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-recover-"));t.after(()=>rm(dir,{recursive:true,force:true}));
  await writeFile(join(dir,"policy.json"),JSON.stringify(policy));
  await migrateDataDir(dir,source);
  const altered=JSON.stringify({...policy,mode:"off"});
  await writeFile(join(dir,"policy.json"),altered);
  const result=await recoverPolicyProjection(dir,source);
  assert.equal(result.recovered,true);
  assert.equal(JSON.parse(await readFile(join(dir,"policy.json"),"utf8")).mode,"enforcing");
  assert.equal(await readFile(result.backupPath,"utf8"),altered);
});
