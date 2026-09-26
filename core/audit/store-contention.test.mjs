import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it } from "node:test";
import { AuditStore } from "./store.ts";

const event = {
  id: "held", ts: 100, machineId: "m", agent: "grok", sessionId: "s", layer: "app_pre",
  tool: "Bash", nativeTool: "Bash", input: "x", risk: "info", decision: "log", category: "other",
  workdirScope: "project", redacted: "summary", policyVersion: 1, evaluation: "log", enforcement: "pending_verify",
};

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

it("audit reads wait for a briefly held write lock", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-contention-"));
  const path = join(dir, "audit.db");
  const store = AuditStore.create(path);
  t.after(() => rm(dir, { recursive: true, force: true }));
  assert.equal((await store.append(event)).inserted, true);
  await withBriefExclusiveLock(path, async () => {
    await assert.doesNotReject(async () => {
      const rows = await store.recent(1);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].id, "held");
    }, "audit read must wait for the lock");
  });
});
