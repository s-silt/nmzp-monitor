import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { it } from "node:test";
import { AuditStore } from "../audit/store.ts";
import { PolicyHistory } from "./history.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const policy = (version, mode = "enforcing") =>
  createPolicySnapshot({
    version,
    updatedAt: version,
    mode,
    stopped: false,
    customRules: [],
  });

const auditEvent = (id) => ({
  id,
  ts: 100,
  machineId: "m",
  agent: "grok",
  sessionId: "s",
  layer: "app_pre",
  tool: "Bash",
  nativeTool: "Bash",
  input: "tiny",
  risk: "info",
  decision: "log",
  category: "other",
  workdirScope: "project",
  redacted: "summary",
  policyVersion: 1,
  evaluation: "log",
  enforcement: "pending_verify",
});

let observationQueue = Promise.resolve();

function exclusive(task) {
  const run = observationQueue.then(task, task);
  observationQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

function installWriteObserver(t) {
  const original = DatabaseSync.prototype.exec;
  const writeConnections = [];
  function wrappedExec(sql) {
    const result = original.call(this, sql);
    if (typeof sql === "string" && sql.includes("journal_mode")) {
      writeConnections.push({
        synchronous: this.prepare("PRAGMA synchronous").get().synchronous,
        journalMode: this.prepare("PRAGMA journal_mode").get().journal_mode,
      });
    }
    return result;
  }
  const restore = () => {
    if (DatabaseSync.prototype.exec === wrappedExec) {
      DatabaseSync.prototype.exec = original;
    }
  };
  t.after(restore);
  DatabaseSync.prototype.exec = wrappedExec;
  return { writeConnections, restore };
}

function assertExtraDelete(writeConnections) {
  assert.ok(writeConnections.length >= 2);
  for (const connection of writeConnections) {
    assert.equal(connection.synchronous, 3, "write connection must request synchronous EXTRA");
    assert.equal(connection.journalMode, "delete");
  }
}

it("policy history write connections use synchronous EXTRA with DELETE journal", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-sqlite-durability-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "policy-history.db");
  await exclusive(async () => {
    const { writeConnections, restore } = installWriteObserver(t);
    try {
      const history = PolicyHistory.create(path, policy(1), "rules-a", "engine-a");
      try {
        assert.equal(history.commit(policy(2), policy(1), "rules-a", "engine-a"), "committed");
      } finally {
        history.close();
      }
      assertExtraDelete(writeConnections);
    } finally {
      restore();
    }
  });
});

it("audit store write connections use synchronous EXTRA with DELETE journal", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-sqlite-durability-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "audit.db");
  const options = { minFreeBytes: 0 };
  await exclusive(async () => {
    const { writeConnections, restore } = installWriteObserver(t);
    try {
      AuditStore.create(path, options);
      const store = AuditStore.open(path, false, options);
      assert.equal((await store.append(auditEvent("durability"))).inserted, true);
      assertExtraDelete(writeConnections);
    } finally {
      restore();
    }
  });
});

it("read-only connections stay read-only", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-sqlite-durability-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "policy-history.db");
  const created = PolicyHistory.create(path, policy(1), "rules-a", "engine-a");
  created.close();
  await exclusive(async () => {
    const { writeConnections, restore } = installWriteObserver(t);
    try {
      const history = PolicyHistory.open(path, true);
      try {
        assert.equal(history.current().policy.version, 1);
        assert.equal(writeConnections.length, 0);
        assert.throws(
          () => history.commit(policy(2), policy(1), "rules-a", "engine-a"),
          /policy_history_read_only/,
        );
        assert.equal(writeConnections.length, 0);
      } finally {
        history.close();
      }
    } finally {
      restore();
    }
  });
});
