import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { it } from "node:test";
import { FilePolicyStore } from "./file-store.ts";
import { HistoricalCommit } from "./history-commit.ts";
import { PolicyHistory } from "./history.ts";
import { PolicyPublisher } from "./publisher.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const RULES = "synthetic-rules";
const ENGINE = "synthetic-engine";

function canonical(policy) {
  return `${JSON.stringify(createPolicySnapshot(policy).policy)}\n`;
}

function rejection(expected, message) {
  return (error) => {
    assert.equal(error?.code ?? error?.message, expected, message);
    return true;
  };
}

async function openPublisher(t, policy = { version: 1, updatedAt: 1, mode: "enforcing" }) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-history-contention-"));
  const path = join(dir, "policy.json");
  const dbPath = join(dir, "history.db");
  const snapshot = createPolicySnapshot(policy);
  await writeFile(path, canonical(policy), { mode: 0o600 });
  const history = PolicyHistory.create(dbPath, snapshot, RULES, ENGINE);
  const file = await FilePolicyStore.open({ path, durability: "file" });
  const commit = new HistoricalCommit(path, file, history, RULES, ENGINE);
  const publisher = await PolicyPublisher.open(policy, {
    prepare: () => {},
    persist: commit.persist,
    now: () => 2,
  });
  t.after(async () => {
    history.close();
    await rm(dir, { recursive: true, force: true });
  });
  return { path, dbPath, history, publisher };
}

// Synchronous SQLite busy waits block this event loop, so the lock holder is a child.
const LOCK_HOLDER = `
import { DatabaseSync } from "node:sqlite";
const db = new DatabaseSync(process.env.NMZP_CONTENTION_DB);
db.exec("BEGIN EXCLUSIVE");
process.send("ready");
await new Promise((resolve) => setTimeout(resolve, 300));
db.exec("COMMIT");
db.close();
`;

function childEnv(dbPath) {
  const env = { ...process.env, NMZP_CONTENTION_DB: dbPath };
  delete env.NODE_CHANNEL_FD;
  for (const key of Object.keys(env)) {
    if (key.startsWith("NODE_TEST_")) delete env[key];
  }
  return env;
}

async function withBriefExclusiveLock(dbPath, run) {
  const child = spawn(process.execPath, ["--input-type=module", "-e", LOCK_HOLDER], {
    env: childEnv(dbPath),
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true,
  });
  child.stdout?.resume();
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk) => {
    if (stderr.length < 2000) stderr += chunk;
  });
  child.on("error", () => {});
  const watchdog = setTimeout(() => { child.kill(); }, 20_000);
  try {
    await new Promise((resolve, reject) => {
      child.once("message", (message) => {
        if (message === "ready") resolve();
        else reject(new Error("unexpected lock child message"));
      });
      child.once("exit", (code, signal) => {
        reject(new Error(`lock child exited before ready code=${code} signal=${signal} stderr=${stderr}`));
      });
    });
    await run();
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => {
        child.once("exit", () => resolve());
        if (child.exitCode !== null || child.signalCode !== null) resolve();
        else child.kill();
      });
    }
    clearTimeout(watchdog);
  }
}

it("publish under a held exclusive lock is rejected as not committed and does not fence", async (t) => {
  const { path, dbPath, history, publisher } = await openPublisher(t);
  const lock = new DatabaseSync(dbPath);
  try {
    lock.exec("BEGIN EXCLUSIVE");
    await assert.rejects(
      publisher.publish(1, { mode: "permissive" }),
      rejection("policy_not_committed", "precommit contention must not fence"),
    );
  } finally {
    lock.exec("ROLLBACK");
    lock.close();
  }
  assert.equal(publisher.capture().policy.version, 1);
  assert.equal(publisher.recoveryRequired, false);
  assert.equal(history.current().policy.version, 1);
  assert.equal(JSON.parse(await readFile(path, "utf8")).version, 1);
  const published = await publisher.publish(1, { mode: "permissive" });
  assert.equal(published.conflict, false);
  assert.equal(published.snapshot.policy.version, 2);
  assert.equal(history.current().policy.version, 2);
  assert.equal(JSON.parse(await readFile(path, "utf8")).version, 2);
});

it("reads wait for a briefly held lock instead of failing", async (t) => {
  const { dbPath, history } = await openPublisher(t);
  await withBriefExclusiveLock(dbPath, () => {
    let current;
    assert.doesNotThrow(() => { current = history.current(); }, "read must wait for the lock");
    assert.equal(current.policy.version, 1);
  });
});

it("contention after the commit started still fences", async (t) => {
  const { path, history, publisher } = await openPublisher(t);
  const busy = new Error("database is locked");
  busy.code = "ERR_SQLITE_ERROR";
  busy.errcode = 5;
  assert.equal(busy.errcode & 0xff, 5, "synthetic error must be SQLITE_BUSY");
  let commits = 0;
  history.commit = () => {
    commits += 1;
    throw busy;
  };
  await assert.rejects(
    publisher.publish(1, { mode: "permissive" }),
    rejection("policy_recovery_required", "contention after commit must still fence"),
  );
  assert.equal(publisher.recoveryRequired, true, "contention after commit must still fence");
  assert.equal(history.current().policy.version, 1);
  assert.equal(JSON.parse(await readFile(path, "utf8")).version, 1);
  await assert.rejects(
    publisher.publish(1, { mode: "off" }),
    rejection("policy_recovery_required", "contention after commit must still fence"),
  );
  assert.equal(commits, 1, "contention after commit must still fence");
});

it("projection mismatch still requires recovery", async (t) => {
  const { path, history, publisher } = await openPublisher(t);
  await writeFile(path, canonical({ version: 1, updatedAt: 1, mode: "permissive" }));
  await assert.rejects(
    publisher.publish(1, { mode: "off" }),
    rejection("policy_recovery_required", "projection mismatch still requires recovery"),
  );
  assert.equal(publisher.recoveryRequired, true);
  assert.equal(history.current().policy.version, 1);
  await assert.rejects(
    publisher.publish(1, { mode: "off" }),
    rejection("policy_recovery_required", "projection mismatch still requires recovery"),
  );
});
