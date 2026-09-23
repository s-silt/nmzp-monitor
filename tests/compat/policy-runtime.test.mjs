import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, readFile, rm, writeFile, open, lstat, rename, unlink, mkdir, utimes } from "node:fs/promises";
import { spawn } from "node:child_process";
import { request as httpsRequest } from "node:https";
import { gunzipSync } from "node:zlib";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { NmzpStore, bootstrapAdmin } from "../../core/persist.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import { interpretEvaluateResponse, runHook, settleHookAfterStdout } from "../../core/hook.ts";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { probeTick } from "../../core/probe.ts";
import { outboxStatus, enqueueOutbox } from "../../core/audit/outbox.ts";
import { parseApiState } from "../../src/lib/monitor/api.ts";
import { mapEvent } from "../../src/lib/monitor/map-event.ts";

const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-policy-runtime-"));
  let server;
  t.after(async () => {
    try { await server?.close(); } finally { await rm(dir, { recursive: true, force: true }); }
  });
  server = await startServer({ dataDir: dir, coreDir, host: "127.0.0.1", port: 0, uiDir: null, ...options });
  const request = async (path, method = "GET", body, token = server.adminToken) => {
    const res = await pinnedHttps({ url: `${server.url}${path}`, method,
      caPem: server.tls.certPem, fingerprintSha256: server.tls.fingerprintSha256,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), timeoutMs: 5000 });
    return { status: res.status, body: JSON.parse(res.body) };
  };
  const enroll = async () => {
    const ticket = await request("/api/v1/ticket", "POST");
    const joined = await request("/api/v1/join", "POST", { ticket: ticket.body.ticket, hostname: "synthetic", os: "win32", user: "fixture" });
    assert.equal(joined.status, 200);
    return joined.body.deviceToken;
  };
  return { dir, get server() { return server; }, request, enroll,
    async stop() { await server.close(); server = undefined; },
    async start() { server = await startServer({ dataDir: dir, coreDir, host: "127.0.0.1", port: 0, uiDir: null, ...options }); } };
}

it("running core excludes another store before bootstrap or policy writes", async (t) => {
  const f = await fixture(t);
  const before = await readFile(join(f.dir, "policy.json"));
  const contender = new NmzpStore(f.dir);
  t.after(() => contender.close?.());
  await assert.rejects(contender.load(), /policy_writer_busy/);
  assert.deepEqual(await readFile(join(f.dir, "policy.json")), before);
});

it("default window mode keeps 2,000 recent rows without creating a database", async (t) => {
  const f = await fixture(t);
  const state = await f.request("/api/v1/state");
  assert.equal(state.body.evidenceWindow.limit, 2000);
  assert.equal((await f.request("/api/v1/policy/history")).body.error, "storage_not_enabled");
  await assert.rejects(readFile(join(f.dir, "nmzp.db")), {code:"ENOENT"});
});

it("SQLite mode persists audit events and receipt updates without events.jsonl", async (t) => {
  const f = await fixture(t,{storageMode:"sqlite"});
  const ev = {id:"persistent",ts:100,machineId:"synthetic",agent:"grok",sessionId:"s",layer:"app_pre",
    tool:"Bash",nativeTool:"Bash",input:"x".repeat(4000),risk:"info",decision:"log",category:"other",
    workdirScope:"project",redacted:"summary",policyVersion:1,evaluation:"log",enforcement:"pending_verify"};
  await f.server.store.appendEvent(ev);
  assert.equal(f.server.store.listEvents().length,1);
  assert.equal((await f.server.store.updateReceipt("synthetic","persistent","delivered")).enforcement,"delivered");
  await f.stop();
  await f.start();
  assert.equal(f.server.store.listEvents()[0].enforcement,"delivered");
  await assert.rejects(readFile(join(f.dir,"events.jsonl")),{code:"ENOENT"});
});

it("admin audit pagination has a stable cutoff and rejects unauthorized reads", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"});
  const base={ts:100,machineId:"synthetic",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
    input:"x",risk:"info",decision:"allow",category:"other",workdirScope:"project",redacted:"x",policyVersion:1,evaluation:"allow",enforcement:"delivered"};
  for(let i=0;i<5;i++)await f.server.store.appendEvent({...base,id:String(i)});
  const first=await f.request("/api/v1/audit/events?limit=2");
  assert.equal(first.status,200);
  assert.deepEqual(first.body.events.map((e)=>e.id),["4","3"]);
  await f.server.store.appendEvent({...base,id:"5"});
  const second=await f.request(`/api/v1/audit/events?limit=2&highWatermark=${first.body.highWatermark}&beforeSeq=${first.body.nextBeforeSeq}`);
  assert.deepEqual(second.body.events.map((e)=>e.id),["2","1"]);
  assert.equal((await f.request("/api/v1/audit/events?limit=2","GET",undefined,"wrong")).status,401);
});

it("every new admin history and audit route rejects a device credential", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"}),token=await f.enroll();
  for(const path of ["/api/v1/policy/history","/api/v1/policy/history/1","/api/v1/audit/events",
    "/api/v1/audit/storage","/api/v1/audit/export?format=json"]){
    assert.equal((await f.request(path,"GET",undefined,token)).status,401,path);
  }
  assert.equal((await f.request("/api/v1/policy/restore","POST",{expectedVersion:1,sourceVersion:1},token)).status,401);
  assert.equal((await f.request("/api/v1/audit/backfill","POST",{kind:"receipt",eventId:"e",
    payload:{eventId:"e",evaluation:"allow",enforcement:"delivered"}},f.server.adminToken)).status,401);
});

it("new audit export streams JSON and gzip JSONL without changing the old export", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"});
  const ev={id:"x",ts:100,machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
    input:"small",risk:"info",decision:"allow",category:"other",workdirScope:"project",redacted:"small",policyVersion:1,evaluation:"allow",enforcement:"delivered"};
  await f.server.store.appendEvent(ev);
  const plain=await f.request("/api/v1/audit/export?format=json");
  assert.equal(plain.status,200);
  assert.equal(plain.body.events[0].id,"x");
  assert.equal(plain.body.exportedCount,1);
  const gz=await new Promise((resolve,reject)=>{
    const req=httpsRequest(`${f.server.url}/api/v1/audit/export?format=jsonl&gzip=1`,
      {ca:f.server.tls.certPem,headers:{authorization:`Bearer ${f.server.adminToken}`}},(res)=>{
        const parts=[];res.on("data",(chunk)=>parts.push(chunk));res.on("end",()=>resolve({status:res.statusCode,body:Buffer.concat(parts)}));res.on("error",reject);
      });req.on("error",reject);req.end();
  });
  assert.equal(gz.status,200);
  const lines=gunzipSync(gz.body).toString("utf8").trim().split("\n").map(JSON.parse);
  assert.equal(lines[0].kind,"metadata");
  assert.equal(lines[1].id,"x");
  assert.equal(lines[2].exportedCount,1);
  assert.equal((await f.request("/api/v1/export")).body.events[0].id,"x");
});

it("cancelled streamed export releases its response and leaves the core queryable", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"});
  const base={ts:Date.now(),machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
    input:"x".repeat(3000),risk:"info",decision:"allow",category:"other",workdirScope:"project",
    redacted:"x".repeat(3000),policyVersion:1,evaluation:"allow",enforcement:"delivered"};
  for(let i=0;i<80;i++)await f.server.store.appendEvent({...base,id:`cancel-${i}`});
  const firstChunk=await new Promise((resolve)=>{
    const req=httpsRequest(`${f.server.url}/api/v1/audit/export?format=jsonl&gzip=1`,
      {ca:f.server.tls.certPem,headers:{authorization:`Bearer ${f.server.adminToken}`}},(res)=>{
        res.once("data",()=>{req.destroy();resolve(true);});res.on("error",()=>resolve(true));
      });req.on("error",()=>resolve(true));req.end();
  });
  assert.equal(firstChunk,true);
  assert.equal((await f.request("/api/v1/audit/storage")).status,200);
});

it("a full SQLite budget denies evaluation without acknowledging an unrecorded event", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite",auditRetention:{maxDbBytes:1,minFreeBytes:0}});
  const token=await f.enroll();
  const result=await f.request("/api/v1/evaluate","POST",{eventId:"full",tool_name:"Read",tool_input:{file_path:"x"}},token);
  assert.equal(result.status,503);
  assert.equal(result.body.error,"audit_storage_unavailable");
  assert.equal(interpretEvaluateResponse(result.status,JSON.stringify(result.body)).action,"deny");
  assert.equal(f.server.store.listEvents().length,0);
});

it("running SQLite core removes aged audit rows in a bounded maintenance tick", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite",auditRetention:{maxAgeMs:1000,minFreeBytes:0}});
  const ev={id:"aged",ts:1,machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
    input:"tiny",risk:"info",decision:"allow",category:"other",workdirScope:"project",redacted:"tiny",
    policyVersion:1,evaluation:"allow",enforcement:"delivered"};
  await f.server.store.appendEvent(ev);
  const db=new DatabaseSync(join(f.dir,"nmzp.db"));
  try{db.prepare("UPDATE audit_events SET ingested_at=1 WHERE id='aged'").run();}finally{db.close();}
  const deadline=Date.now()+3000;
  while((await f.request("/api/v1/audit/storage")).body.retained!==0 && Date.now()<deadline){
    await new Promise((resolve)=>setTimeout(resolve,100));
  }
  const status=(await f.request("/api/v1/audit/storage")).body;
  assert.equal(status.retained,0);
  assert.equal(status.deleted,1);
  assert.equal((await f.request("/api/v1/audit/events")).body.events.length,0);
  assert.equal((await f.request("/api/v1/state")).body.events.length,0);
});

it("record-limit pruning updates both SQLite history and the legacy recent window", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite",auditRetention:{maxRecords:2,maxAgeMs:0,minFreeBytes:0}});
  const base={ts:Date.now(),machineId:"m",agent:"grok",sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",
    input:"tiny",risk:"info",decision:"allow",category:"other",workdirScope:"project",redacted:"tiny",
    policyVersion:1,evaluation:"allow",enforcement:"delivered"};
  for(const id of ["a","b","c"])await f.server.store.appendEvent({...base,id});
  assert.deepEqual((await f.request("/api/v1/state")).body.events.map((row)=>row.id),["b","c"]);
  assert.deepEqual((await f.request("/api/v1/audit/events")).body.events.map((row)=>row.id),["c","b"]);
  assert.equal((await f.request("/api/v1/audit/storage")).body.retained,2);
});

it("device backfill accepts metadata and receipts idempotently without tool content", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"});
  const token=await f.enroll();
  const payload={eventId:"offline-1",ts:Date.now(),agent:"unknown-agent",tool:"Read",decision:"block",risk:"high",policyVersion:1};
  const event=await f.request("/api/v1/audit/backfill","POST",{kind:"event",eventId:"offline-1",payload},token);
  assert.equal(event.status,200);
  assert.equal((await f.request("/api/v1/audit/backfill","POST",{kind:"event",eventId:"offline-1",payload},token)).body.duplicate,true);
  const stored=f.server.store.listEvents()[0];
  assert.equal(stored.agent,"unknown-agent");
  assert.equal(stored.input,"");
  assert.equal(stored.policyHash,undefined);
  const state=parseApiState((await f.request("/api/v1/state")).body);
  const mapped=mapEvent(state?.events.find((row)=>row.id==="offline-1"));
  assert.equal(mapped?.agent,"unknown");
  assert.equal(mapped?.rawAgent,"unknown-agent");
  const receipt={kind:"receipt",eventId:"offline-1",payload:{eventId:"offline-1",evaluation:"block",enforcement:"returned_deny"}};
  assert.equal((await f.request("/api/v1/audit/backfill","POST",receipt,token)).status,200);
  assert.equal((await f.request("/api/v1/audit/backfill","POST",receipt,token)).body.duplicate,true);
  assert.equal((await f.request("/api/v1/audit/backfill","POST",{kind:"event",eventId:"offline-1",payload:{...payload,input:"secret"}},token)).status,400);
  await f.request("/api/v1/policy","PUT",{expectedVersion:1,stopped:true});
  assert.equal((await f.request("/api/v1/audit/backfill","POST",{kind:"event",eventId:"paused",payload:{...payload,eventId:"paused"}},token)).status,503);
});

it("offline Hook queues only metadata and the next active probe tick backfills it", async (t) => {
  const f=await fixture(t,{storageMode:"sqlite"}),token=await f.enroll();
  const home=join(f.dir,"device-home");await mkdir(join(home,".nmzp"),{recursive:true});
  const creds={deviceId:f.server.store.listDevices()[0].id,token,url:"https://127.0.0.1:1",
    caPem:f.server.tls.certPem,fingerprintSha256:f.server.tls.fingerprintSha256};
  await writeFile(join(home,".nmzp","credentials.json"),JSON.stringify(creds));
  await writePolicyCache(join(home,".nmzp","policy-cache.json"),f.server.store.getPolicy());
  const result=await runHook({home,coreDir,argv:["--agent","grok"],
    stdin:JSON.stringify({eventId:"offline-hook",tool_name:"Read",tool_input:{file_path:"private-path"}})});
  assert.ok(result.pendingBackfill);
  await settleHookAfterStdout({home,result});
  assert.equal((await outboxStatus(home)).pending,1);
  const outbox=await readFile(join(home,".nmzp","audit-outbox.json"),"utf8");
  assert.doesNotMatch(outbox,/private-path|tool_input|contents/);
  await writeFile(join(home,".nmzp","credentials.json"),JSON.stringify({...creds,url:f.server.url}));
  const tick=await probeTick({home,heartbeat:async()=>({status:200,body:"{}"}),
    collectDiscovery:async()=>({schemaVersion:1,platform:"win32",checkedAt:Date.now(),completedAt:Date.now(),status:"error",items:[],sources:[]}),
    collectSnapshotGuard:async()=>({error:"unsupported"}),collectNetwork:async()=>({status:"unsupported",startedAt:Date.now(),finishedAt:Date.now(),connections:[],attribution:"none"})});
  assert.equal(tick.ok,true);
  assert.equal((await outboxStatus(home)).pending,0);
  const stored=await f.server.store.getEvent(creds.deviceId,"offline-hook");
  assert.equal(stored?.source,"offline_backfill");
  assert.equal(stored?.input,"");
  await enqueueOutbox(home,{...creds,url:f.server.url},{kind:"event",eventId:"paused-hook",
    payload:{eventId:"paused-hook",ts:Date.now(),agent:"grok",tool:"Read",decision:"allow",risk:"info",policyVersion:1}});
  await f.server.store.stop();
  assert.equal((await probeTick({home,heartbeat:async()=>({status:200,body:"{}"})})).pollOnly,true);
  assert.equal((await outboxStatus(home)).pending,1);
  assert.equal(await f.server.store.getEvent(creds.deviceId,"paused-hook"),undefined);
  await f.server.store.resume();
  assert.equal((await probeTick({home,heartbeat:async()=>({status:200,body:"{}"}),
    collectDiscovery:async()=>({schemaVersion:1,platform:"win32",checkedAt:Date.now(),completedAt:Date.now(),status:"error",items:[],sources:[]}),
    collectSnapshotGuard:async()=>({error:"unsupported"}),collectNetwork:async()=>({status:"unsupported",startedAt:Date.now(),finishedAt:Date.now(),connections:[],attribution:"none"})})).ok,true);
  assert.equal((await outboxStatus(home)).pending,0);
});

it("HTTP publication uses the durable service and fences an ambiguous commit", async (t) => {
  let fail = false;
  const f = await fixture(t, { policyFileOperations: { open, lstat, unlink, rename: async (...args) => {
    await rename(...args); if (fail) throw Error("synthetic post-rename failure");
  } } });
  const token = await f.enroll();
  const version = f.server.store.getPolicy().version;
  fail = true;
  const save = await f.request("/api/v1/policy", "PUT", { expectedVersion: version, mode: "permissive" });
  assert.equal(save.status, 503);
  assert.equal(save.body.error, "policy_recovery_required");
  assert.equal(JSON.parse(await readFile(join(f.dir, "policy.json"), "utf8")).version, version + 1);
  const evaluate = await f.request("/api/v1/evaluate", "POST", { eventId: "recovery", tool_name: "Read", tool_input: { file_path: "fixture.txt" } }, token);
  assert.equal(evaluate.status, 503);
  assert.equal(evaluate.body.error, "policy_recovery_required");
  assert.equal(interpretEvaluateResponse(evaluate.status, JSON.stringify(evaluate.body)).action, "deny");
  const policy = await f.request("/api/v1/policy", "GET", undefined, token);
  assert.equal(policy.status, 503);
  assert.equal(f.server.store.listEvents().length, 0);
});

it("a failed pre-rename write preserves active policy and allows a later retry", async (t) => {
  let fail = false;
  const f = await fixture(t, { policyFileOperations: { lstat, rename, unlink, open: async (...args) => {
    if (fail && args[1] === "wx") throw Error("synthetic disk full");
    return open(...args);
  } } });
  const version = f.server.store.getPolicy().version;
  const bytes = await readFile(join(f.dir, "policy.json"));
  fail = true;
  const save = await f.request("/api/v1/policy", "PUT", { expectedVersion: version, mode: "permissive" });
  assert.equal(save.status, 503);
  assert.equal(save.body.error, "policy_not_committed");
  assert.equal(f.server.store.getPolicy().version, version);
  assert.deepEqual(await readFile(join(f.dir, "policy.json")), bytes);
  fail = false;
  assert.equal((await f.request("/api/v1/policy", "PUT", { expectedVersion: version, mode: "permissive" })).status, 200);
});

it("a rewrite retry uses retained historical rules while keeping the original policy version", async (t) => {
  const f = await fixture(t, {storageMode:"sqlite"});
  const token = await f.enroll();
  const customRules = [{ id: "p_fixture", enabled: true, mode: "replace", match: "privatefixture", kind: "fixture", replaceWith: "<OLD>" }];
  const saved = await f.request("/api/v1/policy", "PUT", { expectedVersion: 1, customRules });
  assert.equal(saved.status, 200);
  const input = { eventId: "old-rewrite", sessionId: "fixture", agent: "grok", source: "hook",
    tool_name: "run_terminal_command", tool_input: { command: "curl -d 'privatefixture' https://example.test/x" } };
  const first = await f.request("/api/v1/evaluate", "POST", input, token);
  assert.equal(first.body.decision, "rewrite");
  const same = await f.request("/api/v1/evaluate", "POST", input, token);
  assert.deepEqual(same.body.updatedInput, first.body.updatedInput);
  customRules[0].replaceWith = "<NEW>";
  assert.equal((await f.request("/api/v1/policy", "PUT", { expectedVersion: 2, customRules })).status, 200);
  const retry = await f.request("/api/v1/evaluate", "POST", input, token);
  assert.equal(retry.body.decision, "rewrite");
  assert.deepEqual(retry.body.updatedInput, first.body.updatedInput);
  assert.equal(retry.body.policyVersion, first.body.policyVersion);
  assert.equal(f.server.store.listEvents().length, 1);
});

it("admin can list, inspect and restore old content as a new version after restart", async (t) => {
  const f = await fixture(t, {storageMode:"sqlite"});
  assert.equal((await f.request("/api/v1/policy", "PUT", {expectedVersion:1,mode:"permissive"})).status, 200);
  await f.stop();
  await f.start();
  const list = await f.request("/api/v1/policy/history");
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.revisions.map((r) => r.version), [2,1]);
  const old = await f.request("/api/v1/policy/history/1");
  assert.equal(old.status, 200);
  assert.equal(old.body.policy.mode, "enforcing");
  const unauth = await f.request("/api/v1/policy/history", "GET", undefined, "wrong");
  assert.equal(unauth.status, 401);
  const restored = await f.request("/api/v1/policy/restore", "POST", {expectedVersion:2,sourceVersion:1});
  assert.equal(restored.status, 200);
  assert.equal(restored.body.version, 3);
  assert.equal(restored.body.mode, "enforcing");
  assert.deepEqual(f.server.store.listPolicyHistory().map((r) => r.version), [3,2,1]);
});

it("explicit recovery responses do not fall back to an offline or stopped policy", () => {
  for (const body of [{ error: "policy_recovery_required" }, { error: "policy_recovery_required", stopped: true }]) {
    assert.deepEqual(interpretEvaluateResponse(503, JSON.stringify(body)), { action: "deny", reason: "policy_recovery_required", evaluation: "block" });
  }
});

it("noncanonical historical policy is rejected without rewriting its bytes", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-policy-legacy-"));
  const store = new NmzpStore(dir);
  t.after(async () => { await store.close?.(); await rm(dir, { recursive: true, force: true }); });
  const bytes = JSON.stringify({ version: 1, updatedAt: 1, mode: "enforcing", stopped: false, customRules: [{ match: "synthetic" }] });
  await writeFile(join(dir, "policy.json"), bytes);
  await assert.rejects(store.load(), /invalid_custom_rules/);
  assert.equal(await readFile(join(dir, "policy.json"), "utf8"), bytes);
});

async function child(args, dir) {
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, ["--experimental-strip-types", ...args], {
      env: { ...process.env, NMZP_DATA: dir }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { processChild.kill(); reject(Error("owned test child timeout")); }, 10000);
    processChild.stdout.on("data", (data) => { stdout += data; });
    processChild.stderr.on("data", (data) => { stderr += data; });
    processChild.on("error", (error) => { clearTimeout(timer); reject(error); });
    processChild.on("exit", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

it("another Node process cannot steal an old-looking writer lock, and normal close releases it", async (t) => {
  const f = await fixture(t);
  const lock = join(f.dir, ".policy-writer.lock");
  const before = await readFile(lock);
  await utimes(lock, new Date(0), new Date(0));
  const moduleUrl = new URL("../../core/persist.ts", import.meta.url).href;
  const source = `import { NmzpStore } from ${JSON.stringify(moduleUrl)}; const store = new NmzpStore(process.env.NMZP_DATA); try { await store.load(); await store.close(); } catch (e) { console.error(e.message); process.exitCode = 19; }`;
  const blocked = await child(["--input-type=module", "-e", source], f.dir);
  assert.equal(blocked.code, 19);
  assert.match(blocked.stderr, /policy_writer_busy/);
  assert.deepEqual(await readFile(lock), before);
  await f.stop();
  const accepted = await child(["--input-type=module", "-e", source], f.dir);
  assert.equal(accepted.code, 0, accepted.stderr);
  await assert.rejects(readFile(lock), { code: "ENOENT" });
});

it("offline CLI stop/resume uses the same service and releases its writer ownership", async (t) => {
  const f = await fixture(t);
  await f.stop();
  const entry = join(coreDir, "nmzp.mjs");
  const stopped = await child([entry, "rights", "stop"], f.dir);
  assert.equal(stopped.code, 0, stopped.stderr);
  assert.equal(JSON.parse(await readFile(join(f.dir, "policy.json"), "utf8")).stopped, true);
  const resumed = await child([entry, "rights", "resume"], f.dir);
  assert.equal(resumed.code, 0, resumed.stderr);
  const policy = JSON.parse(await readFile(join(f.dir, "policy.json"), "utf8"));
  assert.equal(policy.stopped, false);
  assert.equal(policy.version, 3);
  await f.start();
  assert.equal(f.server.store.getPolicy().version, 3);
});

it("real Hook denies explicit recovery even with an off or stopped cached policy", async (t) => {
  let fail = false;
  const f = await fixture(t, { policyFileOperations: { open, lstat, unlink, rename: async (...args) => {
    await rename(...args); if (fail) throw Error("synthetic ambiguous commit");
  } } });
  const token = await f.enroll();
  const home = join(f.dir, "synthetic-home");
  await mkdir(join(home, ".nmzp"), { recursive: true });
  await writeFile(join(home, ".nmzp", "credentials.json"), JSON.stringify({ deviceId: "fixture", token,
    url: f.server.url, caPem: f.server.tls.certPem, fingerprintSha256: f.server.tls.fingerprintSha256 }));
  const policy = f.server.store.getPolicy();
  fail = true;
  assert.equal((await f.request("/api/v1/policy", "PUT", { expectedVersion: policy.version, mode: "permissive" })).status, 503);
  for (const stopped of [false, true]) {
    await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), { ...policy, mode: "off", stopped });
    const hook = await runHook({ home, coreDir, env: {}, argv: ["--agent", "grok"],
      stdin: JSON.stringify({ hookEventName: "pre_tool_use", eventId: `recovery-${stopped}`, sessionId: "fixture",
        toolName: "run_terminal_command", toolInput: { command: "echo synthetic" } }) });
    assert.equal(hook.exitCode, 2);
    assert.match(hook.stdout, /policy_recovery_required/);
  }
});

it("publication capacity is bounded before the disk queue, and request input is captured immediately", async (t) => {
  let pause = false, resume;
  const gate = new Promise((resolve) => { resume = resolve; });
  const f = await fixture(t, { policyFileOperations: { lstat, rename, unlink, open: async (...args) => {
    if (pause && args[1] === "wx") await gate;
    return open(...args);
  } } });
  const patch = { mode: "permissive" };
  pause = true;
  const first = f.server.store.casPolicy(1, patch);
  patch.mode = "off";
  const pending = Array.from({ length: 40 }, () => f.server.store.casPolicy(1, { stopped: true }));
  // Attach handlers immediately, before releasing the first disk write.
  const results = Promise.allSettled(pending);
  await new Promise((resolve) => setTimeout(resolve, 10));
  resume();
  assert.equal((await first).mode, "permissive");
  const settled = await results;
  assert.ok(settled.some((r) => r.status === "rejected" && r.reason.code === "policy_queue_full"));
  for (const result of settled.filter((r) => r.status === "fulfilled")) assert.deepEqual(result.value, { conflict: true, version: 2 });
});

it("stopped evaluation rechecks recovery after waiting for the request body", async (t) => {
  let fail = false;
  const f = await fixture(t, { policyFileOperations: { open, lstat, unlink, rename: async (...args) => {
    await rename(...args); if (fail) throw Error("synthetic ambiguous commit");
  } } });
  const token = await f.enroll();
  await f.request("/api/v1/policy", "PUT", { expectedVersion: 1, stopped: true });
  let seen;
  const captured = new Promise((resolve) => { seen = resolve; });
  const original = f.server.store.capturePolicy.bind(f.server.store);
  t.mock.method(f.server.store, "capturePolicy", () => { const snapshot = original(); seen(); return snapshot; });
  let request;
  const response = new Promise((resolve, reject) => {
    request = httpsRequest(`${f.server.url}/api/v1/evaluate`, { method: "POST", ca: f.server.tls.certPem,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, timeout: 5000 }, (res) => {
      let body = ""; res.on("data", (data) => { body += data; });
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(body) }));
    });
    request.on("error", reject); request.on("timeout", () => request.destroy(Error("test request timeout")));
    request.write('{"eventId":"slow"');
  });
  await captured;
  fail = true;
  assert.equal((await f.request("/api/v1/policy", "PUT", { expectedVersion: 2, stopped: false })).status, 503);
  request.end('}');
  const result = await response;
  assert.equal(result.status, 503);
  assert.equal(result.body.error, "policy_recovery_required");
});

it("offline policy replacement cannot pass the history projection check even at the same version", async (t) => {
  const f = await fixture(t, {storageMode:"sqlite"});
  const token = await f.enroll();
  const customRules = [{ id: "p_fixture", enabled: true, mode: "replace", match: "privatefixture", kind: "fixture", replaceWith: "<OLD>" }];
  await f.request("/api/v1/policy", "PUT", { expectedVersion: 1, customRules });
  const input = { eventId: "hash-rewrite", sessionId: "fixture", agent: "grok", source: "hook",
    tool_name: "run_terminal_command", tool_input: { command: "curl -d 'privatefixture' https://example.test/x" } };
  assert.equal((await f.request("/api/v1/evaluate", "POST", input, token)).body.decision, "rewrite");
  await f.stop();
  const file = join(f.dir, "policy.json");
  const policy = JSON.parse(await readFile(file, "utf8"));
  policy.customRules[0].replaceWith = "<NEW>";
  await writeFile(file, JSON.stringify(policy));
  await assert.rejects(f.start(), /policy_recovery_required/);
});

it("CLI graceful signal handling closes the listener and releases ownership before exit", async (t) => {
  const f = await fixture(t);
  await f.stop();
  const cliUrl = new URL("../../core/cli.ts", import.meta.url).href;
  // Emit a Node signal event in our child: this tests the lifecycle handler, not Windows console delivery.
  const source = `import { main } from ${JSON.stringify(cliUrl)}; process.env.NMZP_BIND="127.0.0.1"; process.env.NMZP_PORT="0"; await main(["serve"], ${JSON.stringify(coreDir)}); if (!process.emit("SIGTERM")) process.exit(21);`;
  const stopped = await child(["--input-type=module", "-e", source], f.dir);
  assert.equal(stopped.code, 0, stopped.stderr);
  await assert.rejects(readFile(join(f.dir, ".policy-writer.lock")), { code: "ENOENT" });
  await f.start();
});

it("explicit read-only snapshots can inspect a running store but cannot write or bootstrap", async (t) => {
  const f = await fixture(t);
  const observer = new NmzpStore(f.dir);
  t.after(() => observer.close());
  const policy = await readFile(join(f.dir, "policy.json"));
  const devices = await readFile(join(f.dir, "devices.json"));
  await observer.load({ readOnly: true });
  assert.equal(observer.getPolicy().version, 1);
  await assert.rejects(observer.casPolicy(1, { stopped: true }), /store_read_only/);
  await assert.rejects(observer.clearEvents(), /store_read_only/);
  await assert.rejects(observer.saveDevices(), /store_read_only/);
  const adminBytes = await readFile(join(f.dir, "admin.token"));
  await assert.rejects(bootstrapAdmin(observer), /store_read_only/);
  assert.deepEqual(await readFile(join(f.dir, "admin.token")), adminBytes);
  assert.deepEqual(await readFile(join(f.dir, "policy.json")), policy);
  assert.deepEqual(await readFile(join(f.dir, "devices.json")), devices);
  const missing = new NmzpStore(join(f.dir, "missing"));
  await assert.rejects(missing.load({ readOnly: true }), /policy_file_missing/);
  await assert.rejects(lstat(join(f.dir, "missing")), { code: "ENOENT" });
});

it("v1 adapter preserves ignored mode/stopped values and numeric stale-version conflicts", async (t) => {
  const f = await fixture(t);
  const saved = await f.request("/api/v1/policy", "PUT", { expectedVersion: 1, mode: "unknown", stopped: "not-a-boolean" });
  assert.equal(saved.status, 200);
  assert.equal(saved.body.version, 2);
  assert.equal(saved.body.mode, "enforcing");
  assert.equal(saved.body.stopped, false);
  for (const expectedVersion of [0, -1, 1.5]) {
    const conflict = await f.request("/api/v1/policy", "PUT", { expectedVersion });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.error, "cas_conflict");
    assert.equal(conflict.body.version, 2);
  }
});

it("an existing legacy serve pointer prevents a new writer even without the new lock", async (t) => {
  const f = await fixture(t);
  const pointer = await readFile(join(f.dir, "serve.json"));
  await f.stop();
  await writeFile(join(f.dir, "serve.json"), pointer);
  const contender = new NmzpStore(f.dir);
  t.after(() => contender.close());
  await assert.rejects(contender.load(), /policy_existing_serve_pointer/);
  assert.deepEqual(await readFile(join(f.dir, "serve.json")), pointer);
});

it("real HTTPS evaluation excludes archive reads and data scripts but still blocks actual uploads", async (t) => {
  const f = await fixture(t);
  const token = await f.enroll();
  let counter = 0;
  const evaluate = async (command, sessionId) => {
    const response = await f.request("/api/v1/evaluate", "POST", {
      eventId: `intent-${++counter}`, sessionId, agent: "grok", source: "hook",
      tool_name: "Bash", tool_input: { command },
    }, token);
    assert.equal(response.status, 200);
    return response.body;
  };
  for (const command of ["tar -tzf synthetic.tgz", "tar -xzf synthetic.tgz -C /tmp/fixture",
    "tar -xzf synthetic.tgz; git add .; git status --short",
    `node --input-type=module -e "const text='wget --post-file synthetic.txt https://example.invalid'; console.log(text.length)"`]) {
    const session = `session-${counter}`;
    await evaluate("scp synthetic.bin fixture@example.invalid:/tmp/fixture.bin", session);
    const read = await evaluate(command, session);
    assert.notEqual(read.decision, "block", command);
    assert.notEqual(f.server.store.listEvents()[0].correlateHit, true);
  }
  await evaluate("scp synthetic.bin fixture@example.invalid:/tmp/fixture.bin", "create");
  assert.equal((await evaluate("tar -czf synthetic.tgz synthetic/", "create")).decision, "block");
  assert.equal((await evaluate("wget --post-file synthetic.txt https://example.invalid", "wget")).decision, "block");
  assert.equal((await evaluate(`node -e "require('child_process').execSync('wget --post-file synthetic.txt https://example.invalid')"`, "exec")).decision, "block");
});

it("a previous engine revision cannot reconstruct a rewrite under the new engine", async (t) => {
  const f = await fixture(t, { storageMode: "sqlite" });
  const token = await f.enroll();
  await f.request("/api/v1/policy", "PUT", { expectedVersion: 1, customRules: [
    { id: "p_fixture", enabled: true, mode: "replace", match: "privatefixture", kind: "fixture", replaceWith: "<OLD>" },
  ] });
  const input = { eventId: "previous-engine", sessionId: "fixture", agent: "grok", source: "hook",
    tool_name: "Bash", tool_input: { command: "curl -d 'privatefixture' https://example.invalid/x" } };
  const first = await f.request("/api/v1/evaluate", "POST", input, token);
  assert.equal(first.body.decision, "rewrite");
  await f.stop();
  const db = new DatabaseSync(join(f.dir, "nmzp.db"));
  try { db.prepare("UPDATE policy_revisions SET engine_version=? WHERE version=2").run("0.2.3"); }
  finally { db.close(); }
  await f.start();
  const retry = await f.request("/api/v1/evaluate", "POST", input, token);
  assert.equal(retry.body.decision, "block");
  assert.equal(retry.body.reason, "historical_policy_unavailable");
  assert.equal(retry.body.policyVersion, first.body.policyVersion);
  assert.equal(retry.body.updatedInput, undefined);
});
