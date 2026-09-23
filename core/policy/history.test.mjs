import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { PolicyHistory } from "./history.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const policy = (version, mode = "enforcing") => createPolicySnapshot({ version, updatedAt: version, mode, stopped: false, customRules: [] });

it("commits current pointer and immutable history in one transaction across reopen", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-"));
  const db = PolicyHistory.create(join(dir, "policy-history.db"), policy(1), "rules-a", "engine-a");
  t.after(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });
  assert.equal(db.current().policy.version, 1);
  assert.equal(db.commit(policy(2, "permissive"), policy(1), "rules-a", "engine-a"), "committed");
  assert.equal(db.current().policy.version, 2);
  assert.equal(db.get(1)?.hash, policy(1).hash);
  assert.equal(db.commit(policy(2, "permissive"), policy(1), "rules-a", "engine-a"), "conflict");
  db.close();
  const reopened = PolicyHistory.open(join(dir, "policy-history.db"));
  assert.equal(reopened.current().hash, policy(2, "permissive").hash);
  assert.deepEqual(reopened.list().map((r) => r.version), [2, 1]);
  assert.equal(reopened.get(2)?.rulesHash, "rules-a");
  reopened.close();
});

it("failed transaction preserves both current and history", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-"));
  const db = PolicyHistory.create(join(dir, "policy-history.db"), policy(1), "rules-a", "engine-a");
  t.after(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });
  assert.throws(() => db.commit(policy(3), policy(1), "rules-a", "engine-a"), /policy_history_transition/);
  assert.equal(db.current().policy.version, 1);
  assert.deepEqual(db.list().map((r) => r.version), [1]);
});

it("bounds revisions while preserving any version cited by retained audit events", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-history-")),path=join(dir,"history.db");
  const history=PolicyHistory.create(path,policy(10000),"rules-a","engine-a");
  t.after(async()=>{history.close();await rm(dir,{recursive:true,force:true});});
  const db=new DatabaseSync(path);
  try {
    db.exec("CREATE TABLE audit_events(policy_version INTEGER NOT NULL)");
    db.exec("INSERT INTO audit_events(policy_version) VALUES(1)");
    db.exec(`WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<9999)
      INSERT INTO policy_revisions(version,format_version,policy_json,hash,published_at,rules_hash,engine_version)
      SELECT v,1,'{}',lower(hex(zeroblob(32))),1,'rules-a','engine-a' FROM n`);
  } finally {db.close();}
  assert.equal(history.commit(policy(10001),policy(10000),"rules-a","engine-a"),"committed");
  const verify=new DatabaseSync(path,{readOnly:true});
  try {
    assert.equal(verify.prepare("SELECT count(*) AS n FROM policy_revisions").get().n,10000);
    assert.equal(verify.prepare("SELECT count(*) AS n FROM policy_revisions WHERE version=1").get().n,1);
    assert.equal(verify.prepare("SELECT count(*) AS n FROM policy_revisions WHERE version=2").get().n,0);
    assert.equal(history.current().policy.version,10001);
  } finally {verify.close();}
});

it("refuses a new revision without deleting history still cited by audit", async (t) => {
  const dir=await mkdtemp(join(tmpdir(),"nmzp-history-")),path=join(dir,"history.db");
  const history=PolicyHistory.create(path,policy(10000),"rules-a","engine-a");
  t.after(async()=>{history.close();await rm(dir,{recursive:true,force:true});});
  const db=new DatabaseSync(path);
  try {
    db.exec("CREATE TABLE audit_events(policy_version INTEGER NOT NULL)");
    db.exec("CREATE INDEX audit_events_policy_version ON audit_events(policy_version)");
    db.exec(`WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<9999)
      INSERT INTO policy_revisions(version,format_version,policy_json,hash,published_at,rules_hash,engine_version)
      SELECT v,1,'{}',lower(hex(zeroblob(32))),1,'rules-a','engine-a' FROM n`);
    db.exec("INSERT INTO audit_events(policy_version) SELECT version FROM policy_revisions WHERE version<10000");
  } finally {db.close();}
  assert.equal(history.commit(policy(10001),policy(10000),"rules-a","engine-a"),"capacity");
  assert.equal(history.current().policy.version,10000);
  const verify=new DatabaseSync(path,{readOnly:true});
  try {assert.equal(verify.prepare("SELECT count(*) AS n FROM policy_revisions").get().n,10000);}
  finally {verify.close();}
});
