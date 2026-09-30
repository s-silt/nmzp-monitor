import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { PolicyHistory } from "./history.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const policy = (version, mode = "enforcing") => createPolicySnapshot({ version, updatedAt: version, mode, customRules: [{ id: "fixture", nested: ["owned"] }] });
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-cache-")), path = join(dir, "history.db");
  const history = PolicyHistory.create(path, policy(1), "rules-a", "engine-a");
  t.after(async () => { history.close(); await rm(dir, { recursive: true, force: true }); });
  return { dir, path, history };
}
function sql(path, fn) {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys=OFF"); // External-tamper fixtures may break the current pointer.
  try { return fn(db); } finally { db.close(); }
}
function update(path, column, value, version = 1) {
  sql(path, db => db.prepare(`UPDATE policy_revisions SET ${column}=? WHERE version=?`).run(value, version));
}
function observe(t) {
  const counts = { parse: 0, hash: 0, selects: 0, connections: new Set(), closed: new Set(), pragmas: 0 };
  const parse = JSON.parse, hash = crypto.createHash, prepare = DatabaseSync.prototype.prepare;
  const close = DatabaseSync.prototype.close, exec = DatabaseSync.prototype.exec;
  t.mock.method(JSON, "parse", function(...args) { counts.parse++; return parse.apply(this, args); });
  t.mock.method(crypto, "createHash", function(...args) { counts.hash++; return hash.apply(this, args); });
  syncBuiltinESMExports();
  t.mock.method(DatabaseSync.prototype, "prepare", function(statement, ...args) {
    if (statement === "SELECT * FROM policy_revisions WHERE version=?") { counts.selects++; counts.connections.add(this); }
    return prepare.call(this, statement, ...args);
  });
  t.mock.method(DatabaseSync.prototype, "exec", function(statement, ...args) {
    if (statement === "PRAGMA busy_timeout=1000") counts.pragmas++;
    return exec.call(this, statement, ...args);
  });
  t.mock.method(DatabaseSync.prototype, "close", function(...args) { counts.closed.add(this); return close.apply(this, args); });
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return counts;
}

test("fresh cache hits still SELECT through a new short-lived connection but skip parsing and snapshot hashing", async t => {
  const { history } = await fixture(t), counts = observe(t);
  const first = history.getForFreshEvaluation(1);
  assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
  for (let i = 0; i < 10; i++) assert.equal(history.getForFreshEvaluation(1), first);
  assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
  assert.equal(counts.selects, 11); assert.equal(counts.connections.size, 11); assert.equal(counts.pragmas, 11);
  for (const db of counts.connections) assert.ok(counts.closed.has(db));
  assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.policy));
  assert.ok(Object.isFrozen(first.policy.customRules)); assert.ok(Object.isFrozen(first.policy.customRules[0].nested));
  assert.throws(() => { first.policy.customRules[0].nested[0] = "changed"; }, TypeError);
  assert.throws(() => { first.rulesHash = "forged"; }, TypeError);
  assert.deepEqual(Object.keys(history), [], "no cache key or seed is public");
});

test("ordinary get/current always fully decode and only successful internal reads seed the fresh cache", async t => {
  const { history } = await fixture(t), counts = observe(t);
  const first = history.get(1); assert.equal(history.getForFreshEvaluation(1), first);
  assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
  const second = history.get(1); assert.notEqual(second, first); assert.equal(counts.parse, 2);
  assert.equal(history.getForFreshEvaluation(1), second); assert.equal(counts.hash, 2);
  const third = history.current(); assert.notEqual(third, second); assert.equal(counts.parse, 3);
  assert.equal(history.getForFreshEvaluation(1), third); assert.equal(counts.hash, 3);
  const again = history.current(); assert.notEqual(again, third); assert.equal(counts.parse, 4);
});

for (const [column, value, requestedVersion] of [
  ["version", 2, 2], ["format_version", 2], ["policy_json", '{"version":1,"updatedAt":1,"mode":"off"}'],
  ["hash", "0".repeat(64)], ["published_at", "invalid-timestamp"],
  ["rules_hash", Buffer.from("rules-a")], ["engine_version", Buffer.from("engine-a")],
]) test(`warm fresh cache preserves original refusal when ${column} alone changes`, async t => {
  const { path, history } = await fixture(t);
  history.getForFreshEvaluation(1); update(path, column, value);
  assert.throws(() => history.getForFreshEvaluation(requestedVersion ?? 1), /policy_history_corrupt/);
  assert.throws(() => history.get(requestedVersion ?? 1), /policy_history_corrupt/);
});

for (const [column, value] of [
  ["format_version", Buffer.from("1")], ["policy_json", Buffer.from(JSON.stringify(policy(1).policy))],
  ["hash", Buffer.from(policy(1).hash)], ["published_at", Buffer.from("1")],
]) test(`warm cache does not coerce ${column} SQL types`, async t => {
  const { path, history } = await fixture(t);
  history.getForFreshEvaluation(1); update(path, column, value);
  assert.throws(() => history.getForFreshEvaluation(1), /policy_history_corrupt/);
});

test("SQL version string cannot reuse a numeric validated tuple", async t => {
  const { path, history } = await fixture(t); history.getForFreshEvaluation(1);
  sql(path, db => db.exec(`ALTER TABLE policy_revisions RENAME TO old_revisions;
    CREATE TABLE policy_revisions(version TEXT PRIMARY KEY, format_version INTEGER, policy_json TEXT, hash TEXT, published_at INTEGER, rules_hash TEXT, engine_version TEXT);
    INSERT INTO policy_revisions SELECT CAST(version AS REAL), format_version, policy_json, hash, published_at, rules_hash, engine_version FROM old_revisions;`));
  assert.equal(sql(path, db => typeof db.prepare("SELECT * FROM policy_revisions WHERE version=?").get(1).version), "string");
  assert.throws(() => history.getForFreshEvaluation(1), /policy_history_corrupt/);
});

for (const [column, property, value] of [["published_at", "publishedAt", 123], ["rules_hash", "rulesHash", "changed-rules"], ["engine_version", "engineVersion", "changed-engine"]]) {
  test(`valid changed ${column} is fully decoded and retains original semantics`, async t => {
    const { path, history } = await fixture(t), before = history.getForFreshEvaluation(1);
    update(path, column, value); const counts = observe(t);
    const after = history.getForFreshEvaluation(1);
    assert.notEqual(after, before); assert.equal(after[property], value);
    assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
    assert.equal(history.getForFreshEvaluation(1), after); assert.equal(counts.parse, 1);
  });
}

test("different raw policy JSON with identical canonical content is validated once then cacheable", async t => {
  const { path, history } = await fixture(t), before = history.getForFreshEvaluation(1);
  const reordered = JSON.stringify(Object.fromEntries(Object.entries(before.policy).reverse()), null, 2);
  update(path, "policy_json", reordered); const counts = observe(t);
  const after = history.getForFreshEvaluation(1);
  assert.notEqual(after, before); assert.equal(after.hash, before.hash); assert.deepEqual(after.policy, before.policy);
  assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
  assert.equal(history.getForFreshEvaluation(1), after); assert.equal(counts.parse, 1);
});

test("malformed JSON never seeds the cache; deletion and recreation cannot return stale data", async t => {
  const { path, history } = await fixture(t), before = history.getForFreshEvaluation(1);
  update(path, "policy_json", "{");
  assert.throws(() => history.getForFreshEvaluation(1), /policy_history_corrupt/);
  assert.throws(() => history.getForFreshEvaluation(1), /policy_history_corrupt/);
  sql(path, db => db.exec("DELETE FROM policy_revisions WHERE version=1"));
  assert.equal(history.getForFreshEvaluation(1), undefined);
  const replacement = policy(1, "off");
  sql(path, db => db.prepare("INSERT INTO policy_revisions VALUES(1,1,?,?,123,'rules-b','engine-b')").run(JSON.stringify(replacement.policy), replacement.hash));
  const after = history.getForFreshEvaluation(1);
  assert.notEqual(after, before); assert.equal(after.hash, replacement.hash); assert.equal(after.rulesHash, "rules-b");
  assert.equal(history.getForFreshEvaluation(1), after);
});

test("one entry follows the requested captured version across publications and older reads", async t => {
  const { history } = await fixture(t);
  assert.equal(history.commit(policy(2), policy(1), "rules-a", "engine-a"), "committed");
  const old = history.getForFreshEvaluation(1), captured = policy(2);
  assert.equal(history.commit(policy(3), captured, "rules-a", "engine-a"), "committed");
  history.current(); // Seed third version, then request the older captured second version.
  const second = history.getForFreshEvaluation(captured.policy.version);
  assert.equal(second.hash, captured.hash); assert.equal(second.policy.version, 2);
  const first = history.getForFreshEvaluation(1); assert.notEqual(first, old, "old entry was evicted");
  assert.equal(first.hash, old.hash); assert.notEqual(history.getForFreshEvaluation(2), second, "only one entry is retained");
  for (const bad of [0, -1, 1.5, NaN, "1"]) assert.throws(() => history.getForFreshEvaluation(bad), /policy_history_version_invalid/);
});

test("closed cache cannot be reused and reopened history validates persisted bytes afresh", async t => {
  const { path, history } = await fixture(t), cached = history.getForFreshEvaluation(1);
  history.close(); assert.throws(() => history.getForFreshEvaluation(1), /policy_history_closed/);
  const counts = observe(t), reopened = PolicyHistory.open(path, true); t.after(() => reopened.close());
  assert.equal(counts.parse, 1); assert.equal(counts.hash, 1);
  const current = reopened.getForFreshEvaluation(1); assert.notEqual(current, cached); assert.equal(counts.parse, 1);
  reopened.close(); update(path, "hash", "0".repeat(64));
  assert.throws(() => PolicyHistory.open(path), /policy_history_corrupt/);
});

test("fresh connections follow database pathname replacement instead of a cached inode", async t => {
  const { path, dir, history } = await fixture(t), cached = history.getForFreshEvaluation(1);
  const replacementPath = join(dir, "replacement.db"), replacement = policy(1, "off");
  PolicyHistory.create(replacementPath, replacement, "other-rules", "other-engine").close();
  await rename(replacementPath, path);
  const changed = history.getForFreshEvaluation(1);
  assert.notEqual(changed, cached); assert.equal(changed.hash, replacement.hash); assert.equal(changed.rulesHash, "other-rules");
  const corruptPath = join(dir, "corrupt.db");
  PolicyHistory.create(corruptPath, policy(1), "rules-a", "engine-a").close();
  update(corruptPath, "policy_json", "{"); await rename(corruptPath, path);
  assert.throws(() => history.getForFreshEvaluation(1), /policy_history_corrupt/);
});
