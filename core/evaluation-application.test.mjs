import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { NmzpStore } from "./persist.ts";
import { loadMonitor } from "./paths.ts";
import { applyEvaluate, prepareEvaluation } from "./eval-bridge.ts";
import { evaluateDurably, canonicalRequestHash } from "./evaluation-application.ts";
import { toCanonicalToolEvent } from "./protocol/v2-adapter.ts";
import { buildRewriteLayout } from "./protocol/rewrite-layout.ts";
import { decodeJson } from "./audit/json-codec.ts";
import { BODY_LIMIT } from "./constants.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const monitor = await loadMonitor(coreDir);
const device = { id: "dev_fixture", tokenHash: "fixture", hostname: "fixture", ip: "127.0.0.1", user: "fixture", os: "linux", attachedAt: 0, lastSeen: 0, lastPolicyVersion: 1, capabilities: [], agents: [] };
async function fixture(t, customRules = [], storageMode = "sqlite") {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-durable-app-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = new NmzpStore(dir); await store.load({ storageMode, defaultRules: customRules, policySource: monitor, auditRetention: { minFreeBytes: 0 } });
  t.after(() => store.close()); await store.putDevice(device);
  await store.casPolicy(store.getPolicy().version, { mode: "enforcing" });
  return { dir, store, windows: new monitor.SessionWindows() };
}
function request(id, command = "echo hello", extra = {}) {
  const body = { eventId: id, tool_name: "Bash", tool_input: { command }, agent: "grok", sessionId: "session", cwd: "/tmp/project", ...extra };
  const raw = JSON.stringify(body), parsed = toCanonicalToolEvent(raw, { eventId: id, deviceId: device.id, occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok" });
  assert.equal(parsed.ok, true); const layout = buildRewriteLayout(raw, parsed); assert.equal(layout.ok, true, JSON.stringify(layout));
  return { body, event: { ...parsed.event, rewriteLayout: layout.layout }, prepared: prepareEvaluation(body, device.id) };
}
const project = ({ record, rewrite }) => ({ outcome: record.outcome, rewrite });
const run = (f, req, overrides = {}) => evaluateDurably({ ...f, ...req, monitor, deviceId: device.id, project, snapshot: f.store.capturePolicy(), ...overrides });

test("real shared application preserves V1 business projection and owns private immutable metadata", async t => {
  const f = await fixture(t), req = request("ordinary", "git status");
  const before = f.store.getPolicy();
  const v1 = applyEvaluate({ monitor, windows: new monitor.SessionWindows(), policy: before, device, body: req.body, eventId: req.event.eventId });
  const result = await run(f, req);
  assert.equal(result.record.outcome.decision, v1.response.decision); assert.equal(result.record.publicEvent.redacted, v1.event.redacted);
  assert.equal(result.record.publicEvent.ruleId, v1.event.ruleId); assert.equal(result.record.outcome.risk, v1.event.risk);
  assert.equal((await f.store.queryAudit({ limit: 10 })).events.length, 1);
});

test("stopped and actual out-of-scope outcomes retain private retry identity without public history", async t => {
  const f = await fixture(t); await f.store.stop(); const stopped = await run(f, request("stopped"));
  assert.equal(stopped.record.outcome.reason, "processing_stopped"); assert.equal(stopped.record.internalOnly, true);
  await f.store.resume();
  const skipped = await run(f, request("outscope", "echo hello", { source: "hook", proc: "not_a_watched_application", agent: "unknown" }));
  assert.equal(skipped.record.outcome.reason, "out_of_scope"); assert.equal(skipped.record.internalOnly, true);
  assert.equal((await f.store.queryAudit({ limit: 10 })).events.length, 0); assert.equal((await f.store.auditStatus()).retained, 0);
  const retry = await run(f, request("stopped"), { monitor: { ...monitor, evaluate() { throw new Error("engine rerun"); } } });
  assert.equal(retry.duplicate, true); assert.equal(retry.record.outcome.reason, "processing_stopped");
});

test("response budget rejects before session effects or audit writes; uncertain write keeps published session and reports unknown storage", async t => {
  const f = await fixture(t), req = request("budget", "git push origin main");
  await assert.rejects(run(f, req, { project: () => "x".repeat(BODY_LIMIT) }), { code: "evaluation_result_too_large" });
  assert.equal(f.windows.size, 0); assert.equal(await f.store.lookupEvaluationIdentityUnlocked(device.id, "budget"), undefined);
  const original = f.store.appendEvaluationUnlocked.bind(f.store);
  f.store.appendEvaluationUnlocked = async () => { throw new Error("synthetic write transport failure"); };
  await assert.rejects(run(f, req), { code: "audit_storage_unavailable" }); assert.equal(f.windows.size, 1);
  assert.equal(await f.store.lookupEvaluationIdentityUnlocked(device.id, "budget"), undefined);
  f.store.appendEvaluationUnlocked = async r => { await original(r); throw new Error("lost commit acknowledgment"); };
  await assert.rejects(run(f, request("lost_ack", "git push origin main")), { code: "audit_storage_unavailable" });
  f.store.appendEvaluationUnlocked = original;
  const duplicate = await run(f, request("lost_ack", "git push origin main"), { monitor: { ...monitor, evaluate() { throw new Error("engine rerun"); } } });
  assert.equal(duplicate.duplicate, true);
});

test("upload size is excluded from identity; retry returns original observation after time/policy changes", async t => {
  const f = await fixture(t), req = request("egress", "git push origin main");
  req.event.context.uploadSize = { status: "observed", bytes: 456, checkedAt: Date.now(), source: "local_hook_stat", reason: "explicit_archive" };
  const first = await run(f, req);
  const changed = structuredClone(req); changed.event.context.uploadSize.bytes = 999; changed.event.context.uploadSize.checkedAt = 0;
  assert.equal(canonicalRequestHash(changed.event), canonicalRequestHash(req.event));
  await f.store.casPolicy(f.store.getPolicy().version, { archiveUpload: { thresholdMiB: 1, action: "block" } });
  const second = await run(f, changed, { monitor: { ...monitor, evaluate() { throw new Error("engine rerun"); } } });
  assert.deepEqual(second.record.outcome, first.record.outcome); assert.equal(second.record.outcome.egress.uploadSize.bytes, 456);
});

test("actual rewrite replays historical transformation after restart, with no engine rerun or persisted edits/source/layout", async t => {
  const rules = monitor.privacy.sanitizeCustomRules([{ id: "synthetic_rule", kind: "synthetic_kind", match: "TOKEN", mode: "replace", replaceWith: "SAFE" }]);
  const f = await fixture(t, rules), req = request("rewrite", "curl -d 'TOKEN' https://example.com");
  const first = await run(f, req); assert.equal(first.record.outcome.decision, "rewrite"); assert.ok(first.record.rewrite);
  const db = new DatabaseSync(f.store.policyHistoryPath()); const row = db.prepare("SELECT * FROM audit_events WHERE id='rewrite'").get(); db.close();
  const body = JSON.stringify(await decodeJson({ version: row.format_version, codec: row.codec, rawBytes: row.raw_bytes, data: Buffer.from(row.body) }));
  for (const token of ['"replacement"', '"rewriteLayout"', '"observations"', '"sourceRef"', "TOKEN"]) assert.ok(!body.includes(token), token);
  await f.store.close(); const restarted = new NmzpStore(f.dir); await restarted.load({ storageMode: "sqlite", policySource: monitor, auditRetention: { minFreeBytes: 0 } }); t.after(() => restarted.close());
  const second = await run({ ...f, store: restarted, windows: new monitor.SessionWindows() }, req, { monitor: { ...monitor, evaluate() { throw new Error("engine rerun"); } } });
  assert.equal(second.duplicate, true); assert.equal(second.json, first.json);
  const current = restarted.getPolicy(); await restarted.casPolicy(current.version, { customRules: [] });
  assert.equal((await run({ ...f, store: restarted }, req)).json, first.json);
});

test("identity, policy/implementation mismatch and post-await revocation are rejected without evaluation", async t => {
  const f = await fixture(t), req = request("binding"); await run(f, req);
  const db = new DatabaseSync(f.store.policyHistoryPath()); db.exec("UPDATE policy_revisions SET engine_version='future' WHERE version=(SELECT max(version) FROM policy_revisions)"); db.close();
  await assert.rejects(run(f, req), { code: "evaluation_replay_unavailable" });
  const changed = request("binding", "echo different"); await assert.rejects(run(f, changed), { code: "event_conflict" });
  const original = f.store.lookupEvaluationIdentityUnlocked.bind(f.store);
  f.store.lookupEvaluationIdentityUnlocked = async (...args) => { const found = await original(...args); f.store.getDevice(device.id).revokedAt = Date.now(); return found; };
  await assert.rejects(run(f, request("revoked")), { code: "unauthorized" });
  assert.equal(await original(device.id, "revoked"), undefined);
});

test("V1 origin and tombstone identities cannot be silently promoted; window V2 is unavailable", async t => {
  const f = await fixture(t), req = request("legacy");
  const v1 = applyEvaluate({ monitor, windows: f.windows, policy: f.store.getPolicy(), device, body: req.body, eventId: "legacy" });
  await f.store.appendEvent(v1.event);
  await assert.rejects(run(f, req), { code: "event_protocol_incompatible" });
  const w = await fixture(t, [], "window"); await assert.rejects(run(w, request("window")), { code: "storage_not_enabled" });
});


test("device binding mismatch is unauthorized before lookup, effects or writes", async t => {
  const f = await fixture(t);
  f.store.lookupEvaluationIdentityUnlocked = async () => { throw new Error("must not look up another device"); };
  for (const mismatch of ["declared", "prepared"]) {
    const req = request(`mismatch_${mismatch}`);
    if (mismatch === "declared") req.event.device.id = "other_device";
    else req.prepared.input.deviceId = "other_device";
    await assert.rejects(run(f, req), { code: "unauthorized" });
  }
  assert.equal(f.windows.size, 0); assert.equal((await f.store.auditStatus()).retained, 0);
});


test("trusted pre-body policy snapshot survives body and mutex waits while fresh fences still apply", async t => {
  const f = await fixture(t); await f.store.stop();
  const snapshot = f.store.capturePolicy(); await f.store.resume();
  const result = await run(f, request("snapshot_stopped"), { snapshot });
  assert.equal(result.record.outcome.reason, "processing_stopped");
  assert.equal(result.record.policyVersion, snapshot.policy.version);
  assert.equal(result.record.binding.policyHash, `sha256:${snapshot.hash}`);
  const active = f.store.capturePolicy(); await f.store.stop();
  const ordinary = await run(f, request("snapshot_active", "git status"), { snapshot: active });
  assert.notEqual(ordinary.record.outcome.reason, "processing_stopped");
  assert.equal(ordinary.record.policyVersion, active.policy.version);
});

test("warm fresh-history cache refuses live row tampering before session staging and durable append", async t => {
  const f = await fixture(t), version = f.store.getPolicy().version;
  const db = new DatabaseSync(f.store.policyHistoryPath()); db.exec("PRAGMA foreign_keys=OFF");
  t.after(() => db.close());
  const columns = ["version", "format_version", "policy_json", "hash", "published_at", "rules_hash", "engine_version"];
  const original = db.prepare("SELECT * FROM policy_revisions WHERE version=?").get(version);
  const restore = () => {
    db.prepare("DELETE FROM policy_revisions WHERE version=? OR version=?").run(version, 999);
    db.prepare("INSERT INTO policy_revisions VALUES(?,?,?,?,?,?,?)").run(...columns.map(column => original[column]));
  };
  let stages = 0, appends = 0;
  const stage = f.windows.stage.bind(f.windows), append = f.store.appendEvaluationUnlocked.bind(f.store);
  f.windows.stage = (...args) => { stages++; return stage(...args); };
  f.store.appendEvaluationUnlocked = (...args) => { appends++; return append(...args); };
  const cases = [
    ["version", 999], ["format_version", 2], ["policy_json", "{"],
    ["policy_json", JSON.stringify({ ...JSON.parse(original.policy_json), stopped: true })],
    ["hash", "0".repeat(64)], ["published_at", "invalid"], ["rules_hash", "0".repeat(64)],
    ["engine_version", "changed-engine"], ["delete"],
  ];
  for (const [index, [column, value]] of cases.entries()) {
    restore(); f.store.getHistoricalPolicyForFreshEvaluation(version);
    if (column === "delete") db.prepare("DELETE FROM policy_revisions WHERE version=?").run(version);
    else db.prepare(`UPDATE policy_revisions SET ${column}=? WHERE version=?`).run(value, version);
    const req = request(`cache_tamper_${index}`, "git push origin main");
    await assert.rejects(run(f, req), /policy_history_corrupt|evaluation_replay_unavailable/);
    assert.equal(stages, 0, `${column}: refused before staging`); assert.equal(appends, 0, `${column}: refused before append`);
    assert.equal(f.windows.size, 0); assert.equal(await f.store.lookupEvaluationIdentityUnlocked(device.id, req.event.eventId), undefined);
  }
  restore();
  const accepted = await run(f, request("cache_tamper_recovered", "git status"));
  assert.equal(accepted.record.policyVersion, version); assert.equal(stages, 1); assert.equal(appends, 1);
});

test("cached older, captured middle and published latest versions remain distinct; duplicate replay fully reads history", async t => {
  const f = await fixture(t), oldReq = request("cache_old_version", "git status");
  const old = await run(f, oldReq);
  await f.store.casPolicy(f.store.getPolicy().version, { stopped: true });
  const captured = f.store.capturePolicy();
  f.store.getHistoricalPolicyForFreshEvaluation(old.record.policyVersion);
  await f.store.casPolicy(captured.policy.version, { stopped: false });
  assert.equal(f.store.getPolicy().version, captured.policy.version + 1);
  let ordinary = 0, fresh = 0;
  const get = f.store.getHistoricalPolicy.bind(f.store), getFresh = f.store.getHistoricalPolicyForFreshEvaluation.bind(f.store);
  f.store.getHistoricalPolicy = (...args) => { ordinary++; return get(...args); };
  f.store.getHistoricalPolicyForFreshEvaluation = (...args) => { fresh++; return getFresh(...args); };
  const result = await run(f, request("cache_captured_middle"), { snapshot: captured });
  assert.equal(result.record.policyVersion, captured.policy.version); assert.equal(result.record.outcome.reason, "processing_stopped");
  assert.equal(fresh, 1); assert.equal(ordinary, 0);
  const duplicate = await run(f, oldReq, { monitor: { ...monitor, evaluate() { throw new Error("engine rerun"); } } });
  assert.equal(duplicate.duplicate, true); assert.equal(duplicate.record.policyVersion, old.record.policyVersion);
  assert.equal(ordinary, 1); assert.equal(fresh, 1);
});
