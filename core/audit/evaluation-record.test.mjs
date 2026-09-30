import assert from "node:assert/strict";
import { test } from "node:test";
import { Writable } from "node:stream";
import { writeAuditExport } from "./export-stream.ts";
import { auditMaintenanceDelay } from "../serve.ts";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { AuditStore } from "./store.ts";
import { AuditEvents } from "./events.ts";
import { AuditRuntime } from "./runtime.ts";
import { ownedEvaluationRecord } from "./evaluation-record.ts";
import { decodeJson } from "./json-codec.ts";

const h = `sha256:${"a".repeat(64)}`;
const event = (id, machineId = "m") => ({ id, machineId, ts: 100, agent: "grok", sessionId: "s", layer: "app_pre", tool: "Bash", nativeTool: "Bash", input: "safe", redacted: "safe", risk: "info", decision: "allow", category: "other", workdirScope: "project", policyVersion: 1, evaluation: "allow", enforcement: "pending_verify" });
const record = (id, internalOnly = true) => ({ kind: "v2_evaluation", version: 1, originProtocol: "v2", hashScheme: "canonical_event_v1_without_upload_size", requestHash: h, id, machineId: "m", ts: 100, policyVersion: 1, internalOnly,
  binding: { version: 1, policyHash: h, rulesHash: h, implementationHash: h },
  outcome: { decision: "allow", reason: internalOnly ? "processing_stopped" : "allow", ruleIndex: null, risk: "info", threat: null, scope: internalOnly ? "unknown" : "project", rewriteStatus: "NONE", enforcement: internalOnly ? "delivered" : "pending_verify", overrideSource: null, exemptionIndex: null, secretKindIndices: [], correlateHit: false },
  ...(!internalOnly ? { publicEvent: { ...event(id), policyHash: h.slice(7) } } : {}) });
async function fixture(t, retention = {}) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-private-eval-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "nmzp.db"), limits = { minFreeBytes: 0, maxAgeMs: 0, ...retention };
  return { dir, path, limits, store: AuditStore.create(path, limits) };
}

test("closed private codec rejects nested/free-form source channels and inconsistent public projection", () => {
  assert.deepEqual(ownedEvaluationRecord(record("id")), record("id"));
  for (const mutate of [r => r.raw = "source", r => r.outcome.reason = "secret_source", r => r.outcome.findings = ["source"], r => r.binding.layout = {}, r => r.requestHash = "source", r => r.outcome.ruleIndex = -1, r => r.outcome.secretKindIndices = ["source"], r => r.publicEvent = event("id"), r => r.internalOnly = 7]) {
    const r = record("id"); mutate(r); assert.throws(() => ownedEvaluationRecord(r), /audit_evaluation_invalid/);
  }
  const r = record("id", false); r.publicEvent.risk = "high"; assert.throws(() => ownedEvaluationRecord(r), /audit_evaluation_invalid/);
});

test("hidden records survive reopen yet never enter public history, counts, receipts, backfill, or exports' query path", async t => {
  const { store, path, limits } = await fixture(t);
  await store.append(event("visible")); await store.appendEvaluation(record("hidden"));
  const reopened = AuditStore.open(path, false, limits);
  assert.deepEqual((await reopened.lookupIdentity("m", "hidden")).record, record("hidden"));
  assert.equal(await reopened.get("m", "hidden"), undefined);
  assert.deepEqual((await reopened.recent(10)).map(e => e.id), ["visible"]);
  assert.deepEqual((await reopened.query({ limit: 10 })).events.map(e => e.id), ["visible"]);
  assert.equal((await reopened.query({ limit: 10 })).highWatermark, 1);
  assert.deepEqual((await reopened.query({ limit: 10, highWatermark: Number.MAX_SAFE_INTEGER })).corrupt, []);
  assert.equal(reopened.status().retained, 1);
  assert.deepEqual(await reopened.updateReceipt("m", "hidden", "delivered"), { error: "not_found" });
  assert.deepEqual(await reopened.confirmBackfillReceipt("m", "hidden", "allow", "delivered"), { error: "not_found" });
  await assert.rejects(reopened.append(event("hidden")), /audit_event_protocol_incompatible/);
});

test("independent retention preserves visible rows and copies full V2 identity into bounded tombstones", async t => {
  const { store, path } = await fixture(t, { maxRecords: 2, tombstoneMs: 1000 });
  await store.append(event("v1")); await store.append(event("v2"));
  for (let i = 0; i < 4; i++) await store.appendEvaluation(record(`hidden${i}`));
  assert.deepEqual((await store.recent(10)).map(e => e.id), ["v1", "v2"]);
  const tomb = await store.lookupIdentity("m", "hidden0");
  assert.equal(tomb.kind, "tombstone"); assert.equal(tomb.originProtocol, "v2"); assert.equal(tomb.requestHash, h); assert.equal(tomb.internalOnly, true);
  assert.equal(await store.getTombstone("m", "hidden0"), undefined);
  assert.equal(store.status().deleted, 0); assert.equal(store.status().tombstones, 0);
  const db = new DatabaseSync(path); assert.deepEqual({ ...db.prepare("SELECT retained_count,internal_count FROM audit_meta").get() }, { retained_count: 2, internal_count: 2 });
  db.prepare("UPDATE audit_tombstones SET deleted_at=?").run(Date.now() - 2000); db.close();
  assert.equal(await store.lookupIdentity("m", "hidden0"), undefined);
  await store.append(event("hidden0")); // Identity really expires; origin is not immortal.
});

test("admin clear tombstones hidden rows intentionally without leaking them in deletion counts", async t => {
  const { store } = await fixture(t);
  await store.append(event("visible")); await store.appendEvaluation(record("hidden"));
  assert.equal(store.clear(), 1); assert.equal(store.status().deleted, 1); assert.equal(store.status().retained, 0);
  const tomb = await store.lookupIdentity("m", "hidden"); assert.equal(tomb.kind, "tombstone"); assert.equal(tomb.originProtocol, "v2"); assert.equal(tomb.reason, "admin_clear");
  await assert.rejects(store.appendEvaluation(record("hidden")), /audit_event_expired/);
});

test("receipt updates only mutable SQL enforcement, including after reopen; immutable outcome/body do not change", async t => {
  const { store, path, limits } = await fixture(t); const r = record("public", false);
  await store.appendEvaluation(r); await store.updateReceipt("m", "public", "delivered");
  assert.equal((await store.get("m", "public")).enforcement, "delivered");
  assert.deepEqual((await AuditStore.open(path, false, limits).lookupIdentity("m", "public")).record, r);
  assert.equal((await store.confirmBackfillReceipt("m", "public", "block", "delivered")).error, "evaluation_immutable");
  const db = new DatabaseSync(path); const row = db.prepare("SELECT * FROM audit_events").get(); db.close();
  assert.deepEqual(await decodeJson({ version: row.format_version, codec: row.codec, rawBytes: row.raw_bytes, data: Buffer.from(row.body) }), r);
});

test("codec and indexed SQL origin/hash/visibility are crosschecked; malformed migration rolls back", async t => {
  const { store, path, limits } = await fixture(t); await store.appendEvaluation(record("id"));
  const db = new DatabaseSync(path); db.exec("UPDATE audit_events SET canonical_request_hash='sha256:' || replace(hex(zeroblob(32)),'0','b')"); db.close();
  await assert.rejects(store.lookupIdentity("m", "id"), /audit_corrupt/);
  const bad = new DatabaseSync(path); bad.exec("UPDATE audit_events SET origin_protocol='unknown'"); bad.close();
  assert.throws(() => AuditStore.open(path, false, limits), /audit_corrupt/);
  assert.throws(() => AuditStore.open(path, true, limits), /audit_corrupt/);
});

test("transactional legacy migration assigns V1 only to missing legacy origin", async t => {
  const { store, path, limits } = await fixture(t); await store.append(event("old"));
  const db = new DatabaseSync(path);
  db.exec("DROP INDEX audit_events_visibility_seq");
  for (const table of ["audit_events", "audit_tombstones"]) for (const col of ["origin_protocol", "canonical_hash_scheme", "canonical_request_hash", "internal_only"]) db.exec(`ALTER TABLE ${table} DROP COLUMN ${col}`);
  db.exec("ALTER TABLE audit_meta DROP COLUMN internal_count"); db.close();
  const bytes = await readFile(path);
  const readonly = AuditStore.open(path, true, limits);
  assert.deepEqual((await readonly.query({ limit: 10 })).events.map(e => e.id), ["old"]);
  assert.equal((await readonly.lookupIdentity("m", "old")).originProtocol, "v1");
  assert.equal(readonly.status().retained, 1);
  let exported = "";
  const response = new Writable({ write(chunk, _encoding, next) { exported += chunk.toString(); next(); } });
  response.writeHead = () => undefined;
  await writeAuditExport({ response, store: { queryAudit: query => readonly.query(query), auditDeletionHighWatermark: () => readonly.deletionHighWatermark(), auditDeletionsAfter: (a, b) => readonly.deletionCountAfter(a, b) }, format: "json", gzip: false, filter: {}, project: e => ({ id: e.id }) });
  assert.deepEqual(JSON.parse(exported).events, [{ id: "old" }]); assert.equal(JSON.parse(exported).complete, true);
  assert.deepEqual(await readFile(path), bytes, "read-only legacy projection must not alter database bytes");
  const migrated = AuditStore.open(path, false, limits); assert.equal((await migrated.lookupIdentity("m", "old")).originProtocol, "v1");
});

test("AuditEvents uses collision-free tuples in both window and worker caches; hidden rows remain absent on recovery projection", async t => {
  const { dir, path, limits } = await fixture(t);
  const window = await AuditEvents.open(join(dir, "events.jsonl"));
  await window.append(event("b:c", "a")); await window.append(event("c", "a:b"));
  assert.equal((await window.get("a", "b:c")).machineId, "a"); assert.equal((await window.get("a:b", "c")).machineId, "a:b");
  const runtime = await AuditRuntime.open(path, { retention: limits });
  const log = await AuditEvents.open(join(dir, "unused"), { runtime });
  await log.append(event("visible")); await log.appendEvaluation(record("hidden"));
  assert.deepEqual(log.list().map(e => e.id), ["visible"]); assert.equal(log.evidenceWindow("disabled").retained, 1);
  await log.close();
  const again = await AuditRuntime.open(path, { retention: limits });
  const recovered = await AuditEvents.open(join(dir, "unused"), { runtime: again });
  try { assert.deepEqual(recovered.list().map(e => e.id), ["visible"]); assert.equal((await recovered.lookupIdentity("m", "hidden")).originProtocol, "v2"); }
  finally { await recovered.close(); }
});


test("failed SQLite transaction leaves neither decision row, identity nor counter change", async t => {
  const { store, path } = await fixture(t);
  const db = new DatabaseSync(path);
  db.exec("CREATE TRIGGER reject_evaluation AFTER INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic transaction abort'); END"); db.close();
  await assert.rejects(store.appendEvaluation(record("rollback")), /synthetic transaction abort/);
  assert.equal(await store.lookupIdentity("m", "rollback"), undefined);
  const check = new DatabaseSync(path); assert.deepEqual({ ...check.prepare("SELECT retained_count,internal_count FROM audit_meta").get() }, { retained_count: 0, internal_count: 0 }); check.close();
});


test("partial modern schema and NULL modern origin are rejected without changing database bytes", async t => {
  for (const damage of ["ALTER TABLE audit_meta DROP COLUMN internal_count", "ALTER TABLE audit_tombstones DROP COLUMN canonical_request_hash", "UPDATE audit_events SET origin_protocol=NULL", "UPDATE audit_meta SET internal_count=0"]) {
    const { store, path, limits } = await fixture(t, { maxRecords: 1 });
    await store.appendEvaluation(record("first"));
    const db = new DatabaseSync(path); db.exec(damage); db.close();
    const before = await readFile(path);
    for (const readOnly of [true, false]) {
      assert.throws(() => AuditStore.open(path, readOnly, limits), /audit_corrupt/, damage);
      assert.deepEqual(await readFile(path), before, `${damage}: rejected open must not repair/reclassify private data`);
    }
    assert.throws(() => AuditStore.create(path, limits), /audit_corrupt/);
    assert.deepEqual(await readFile(path), before, `${damage}: create must not repair a partially modern database`);
  }
});


test("hidden-only full maintenance batch requests fast scheduling without exposing private counts", async t => {
  const { dir, path, store, limits } = await fixture(t, { maxRecords: 200 });
  for (let i = 0; i < 101; i++) await store.appendEvaluation(record(`private_${i}`));
  const runtime = await AuditRuntime.open(path, { retention: { ...limits, maxRecords: 1 } });
  const events = await AuditEvents.open(join(dir, "unused"), { runtime }); t.after(() => events.close());
  let followup = false;
  const removed = await events.maintain(value => { followup = value; });
  assert.equal(removed, 0); assert.equal(followup, true); assert.equal(auditMaintenanceDelay(removed, followup), 50);
  const next = await events.maintain(value => { followup = value; });
  assert.equal(next, 0); assert.equal(followup, false); assert.equal(auditMaintenanceDelay(next, followup), 60000);
  assert.equal((await runtime.status()).deleted, 0); assert.equal((await runtime.status()).retained, 0);
});
