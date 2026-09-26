import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { it } from "node:test";
import { PolicyHistory } from "./history.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const policy = (version) => createPolicySnapshot({ version, updatedAt: version, mode: "enforcing", stopped: false, customRules: [] });

const childSource = [
  'import { DatabaseSync } from "node:sqlite";',
  "const path = process.env.NMZP_HOT_JOURNAL_DB;",
  "if (!path) throw new Error('nmzp_hot_journal_db_missing');",
  "const db = new DatabaseSync(path);",
  'db.exec("PRAGMA journal_mode=DELETE");',
  'db.exec("PRAGMA cache_size=1");',
  'db.exec("BEGIN IMMEDIATE");',
  "db.exec(\"INSERT INTO policy_revisions(version,format_version,policy_json,hash,published_at,rules_hash,engine_version) VALUES(2,1,randomblob(8388608),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,'spill','spill')\");",
  'db.exec("UPDATE policy_current SET version=2 WHERE singleton=1");',
  "if (typeof process.send !== 'function') throw new Error('nmzp_hot_journal_ipc_missing');",
  "process.send({ ready: true });",
  "setInterval(() => {}, 1000);",
  "",
].join("\n");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readSchema(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name, tbl_name").all();
  } finally { db.close(); }
}

function readHistoryHashes(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare("SELECT version, hash FROM policy_revisions ORDER BY version").all();
  } finally { db.close(); }
}

async function assertJournalGoneOrEmpty(journalPath) {
  try {
    const info = await stat(journalPath);
    assert.equal(info.size, 0, "hot journal must be gone or empty");
  } catch (error) {
    assert.equal(error.code, "ENOENT");
  }
}

async function crashOwnedWriter(path) {
  const env = { ...process.env, NMZP_HOT_JOURNAL_DB: path };
  delete env.NODE_CHANNEL_FD;
  delete env.NODE_TEST_CONTEXT;
  for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
  const child = spawn(process.execPath, ["--input-type=module", "-e", childSource], {
    env,
    stdio: ["ignore", "ignore", "pipe", "ipc"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr?.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        child.kill("SIGKILL");
        reject(new Error(`owned child ready watchdog expired stderr=${stderr}`));
      }, 20_000);
      const onMessage = (message) => {
        if (!message || message.ready !== true) return;
        cleanup();
        resolve();
      };
      const onExit = (code, signal) => {
        cleanup();
        reject(new Error(`owned child exited before ready code=${code} signal=${signal} stderr=${stderr}`));
      };
      function cleanup() {
        clearTimeout(timer);
        child.off("message", onMessage);
        child.off("exit", onExit);
      }
      child.on("message", onMessage);
      child.once("exit", onExit);
    });
    const exited = once(child, "exit");
    const exitTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }, 20_000);
    assert.equal(child.kill("SIGKILL"), true, "owned child must receive SIGKILL");
    const [code, signal] = await exited;
    clearTimeout(exitTimer);
    assert.equal(code, null);
    assert.equal(signal, "SIGKILL");
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
}

async function hotJournal(t, prepare) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-recovery-"));
  t.after(async () => { await rm(dir, { recursive: true, force: true }); });
  const path = join(dir, "history.db");
  const initial = policy(1);
  const created = PolicyHistory.create(path, initial, "rules-a", "engine-a");
  created.close();
  const afterCreate = await readFile(path);
  if (prepare) await prepare(path);
  const baseline = await readFile(path);
  await crashOwnedWriter(path);
  const journalPath = `${path}-journal`;
  const journalStat = await stat(journalPath);
  assert.equal(journalStat.isFile(), true, "hot journal must exist");
  assert.ok(journalStat.size > 0, "hot journal must be non-empty");
  const spilled = await readFile(path);
  assert.equal(baseline.equals(spilled), false, "uncommitted spill must change the main database bytes");
  return { path, initial, afterCreate, journalPath };
}

it("writable open rolls back a crashed writer's hot journal", { timeout: 60_000 }, async (t) => {
  const { path, initial, afterCreate, journalPath } = await hotJournal(t);
  assert.equal(afterCreate.equals(await readFile(path)), false, "uncommitted spill must change the database copied right after create");
  let opened;
  assert.doesNotThrow(() => { opened = PolicyHistory.open(path); }, "writable open must recover the hot journal");
  t.after(() => opened.close());
  assert.equal(opened.current().policy.version, 1);
  assert.equal(opened.current().hash, initial.hash);
  assert.equal(opened.get(2), undefined);
  await assertJournalGoneOrEmpty(journalPath);
});

it("read-only open refuses a hot journal without changing any bytes", { timeout: 60_000 }, async (t) => {
  const { path, journalPath } = await hotJournal(t);
  const database = sha256(await readFile(path));
  const journal = sha256(await readFile(journalPath));
  assert.throws(() => PolicyHistory.open(path, true));
  assert.equal(sha256(await readFile(path)), database);
  assert.equal(sha256(await readFile(journalPath)), journal);
});

it("corrupt or missing history is still rejected on writable open", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-recovery-"));
  t.after(async () => { await rm(dir, { recursive: true, force: true }); });
  const garbagePath = join(dir, "garbage.db");
  const garbage = Buffer.from("not a sqlite database");
  await writeFile(garbagePath, garbage);
  const garbageHash = sha256(garbage);
  assert.throws(() => PolicyHistory.open(garbagePath));
  assert.equal(sha256(await readFile(garbagePath)), garbageHash);
  assert.equal(existsSync(`${garbagePath}-journal`), false);

  const missing = join(dir, "missing.db");
  assert.throws(() => PolicyHistory.open(missing));
  assert.equal(existsSync(missing), false);
  assert.equal(existsSync(`${missing}-journal`), false);

  const historyPath = join(dir, "history.db");
  const initial = policy(1);
  const created = PolicyHistory.create(historyPath, initial, "rules-a", "engine-a");
  created.close();
  const raw = new DatabaseSync(historyPath);
  try {
    raw.prepare("UPDATE policy_revisions SET hash=? WHERE version=1").run("0".repeat(64));
  } finally { raw.close(); }
  assert.throws(() => PolicyHistory.open(historyPath), /policy_history_corrupt/);
  const verify = new DatabaseSync(historyPath, { readOnly: true });
  try {
    assert.equal(verify.prepare("SELECT hash FROM policy_revisions WHERE version=1").get().hash, "0".repeat(64));
    assert.notEqual(verify.prepare("SELECT hash FROM policy_revisions WHERE version=1").get().hash, initial.hash);
  } finally { verify.close(); }
});

it("unrelated tables survive hot journal recovery", { timeout: 60_000 }, async (t) => {
  let schema;
  let hashes;
  let row;
  const { path, initial, journalPath } = await hotJournal(t, async (dbPath) => {
    const db = new DatabaseSync(dbPath);
    try {
      db.exec("CREATE TABLE fixture_unrelated(id INTEGER PRIMARY KEY, note TEXT NOT NULL)");
      db.prepare("INSERT INTO fixture_unrelated(id, note) VALUES(1, 'kept')").run();
    } finally { db.close(); }
    schema = readSchema(dbPath);
    hashes = readHistoryHashes(dbPath);
    const rowDb = new DatabaseSync(dbPath, { readOnly: true });
    try {
      row = rowDb.prepare("SELECT id, note FROM fixture_unrelated").all();
    } finally { rowDb.close(); }
  });
  assert.equal(row.length, 1);
  assert.equal(row[0].id, 1);
  assert.equal(row[0].note, "kept");
  assert.equal(schema.some((entry) => entry.name === "fixture_unrelated" && typeof entry.sql === "string"), true);
  assert.deepEqual(hashes.map((item) => item.version), [1]);
  let opened;
  assert.doesNotThrow(() => { opened = PolicyHistory.open(path); }, "writable open must recover the hot journal");
  t.after(() => opened.close());
  assert.equal(opened.current().policy.version, 1);
  assert.equal(opened.current().hash, initial.hash);
  assert.equal(opened.get(2), undefined);
  assert.deepEqual(readSchema(path), schema);
  assert.deepEqual(readHistoryHashes(path), hashes);
  const after = new DatabaseSync(path, { readOnly: true });
  try {
    assert.deepEqual(after.prepare("SELECT id, note FROM fixture_unrelated").all(), row);
  } finally { after.close(); }
  await assertJournalGoneOrEmpty(journalPath);
});
