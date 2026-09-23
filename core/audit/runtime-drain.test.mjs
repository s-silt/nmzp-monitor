import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { AuditRuntime } from "./runtime.ts";

function event(id) {
  return {
    id, ts: 1, machineId: "synthetic-device", agent: "grok", sessionId: "synthetic-session",
    layer: "app_pre", tool: "Read", nativeTool: "Read", input: "synthetic ".repeat(1000),
    redacted: "synthetic", risk: "info", decision: "log", category: "file_read",
    workdirScope: "project", policyVersion: 1, evaluation: "log", enforcement: "offline",
  };
}

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-drain-"));
  const path = join(dir, "nmzp.db");
  const opened = [];
  t.after(async () => {
    // Always release workers before removing their SQLite files (also on Windows).
    await Promise.allSettled(opened.map((runtime) => runtime.close()));
    await rm(dir, { recursive: true, force: true });
  });
  return async (options) => {
    const runtime = await AuditRuntime.open(path, { retention: { minFreeBytes: 0 }, ...options });
    opened.push(runtime);
    return runtime;
  };
}

test("runtime close is shared and admitted SQLite writes survive reopening", { timeout: 30_000 }, async (t) => {
  const open = await fixture(t);
  const runtime = await open({ create: true });
  const writes = Array.from({ length: 8 }, (_, i) => runtime.append(event(`e${i}`)));
  const outcomes = Promise.allSettled(writes);
  const first = runtime.close();
  const second = runtime.close();
  assert.equal(second === first, true, "runtime must delegate the single close promise");
  await assert.rejects(runtime.append(event("not-admitted")), { message: "audit_worker_closed" });
  await first;
  assert.ok((await outcomes).every((row) => row.status === "fulfilled" && row.value.inserted));
  const reopened = await open();
  assert.equal((await reopened.status()).retained, 8);
  assert.deepEqual((await reopened.recent(8)).map((row) => row.id), Array.from({ length: 8 }, (_, i) => `e${i}`));
  assert.equal(await reopened.get("synthetic-device", "not-admitted"), undefined);
});

test("close does not turn a failed SQLite operation into a successful write", { timeout: 30_000 }, async (t) => {
  const open = await fixture(t);
  const runtime = await open({ create: true });
  const failed = assert.rejects(runtime.append({ id: "invalid" }), { message: "audit_event_invalid" });
  const good = runtime.append(event("valid"));
  const closing = runtime.close();
  await failed;
  assert.equal((await good).inserted, true);
  await closing;
  const reopened = await open();
  assert.equal((await reopened.status()).retained, 1);
  assert.equal((await reopened.get("synthetic-device", "valid")).id, "valid");
});

test("receipt updates drain without changing the stored decision or policy version", { timeout: 30_000 }, async (t) => {
  const open = await fixture(t);
  const runtime = await open({ create: true });
  await runtime.append(event("receipt"));
  const receipt = runtime.updateReceipt("synthetic-device", "receipt", "delivered");
  const closing = runtime.close();
  assert.equal((await receipt).enforcement, "delivered");
  await closing;
  const reopened = await open();
  const stored = await reopened.get("synthetic-device", "receipt");
  assert.equal(stored.enforcement, "delivered");
  assert.equal(stored.decision, "log");
  assert.equal(stored.evaluation, "log");
  assert.equal(stored.policyVersion, 1);
  assert.deepEqual(stored.input, event("receipt").input);
});
