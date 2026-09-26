import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { AuditEvents } from "./events.ts";
import { AuditRuntime } from "./runtime.ts";

function event(id) {
  return {
    id, ts: 1, machineId: "device", agent: "grok", sessionId: "s", layer: "app_pre", tool: "Read",
    nativeTool: "Read", input: "synthetic", redacted: "synthetic", risk: "info", decision: "allow",
    category: "other", workdirScope: "project", policyVersion: 1, evaluation: "allow", enforcement: "offline",
  };
}

function deferred() {
  let resolve = () => undefined;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, budgetMs = 2000) {
  const start = Date.now();
  while (Date.now() - start < budgetMs) {
    if (predicate()) return true;
    await delay(5);
  }
  return Boolean(predicate());
}

class FakePort extends EventEmitter {
  constructor(workerData) {
    super();
    this.workerData = workerData;
    this.messages = [];
    this.terminateCalls = 0;
    this.exited = false;
    this.failStartup = false;
    this.terminationGate = undefined;
    this.spawnedAt = Date.now();
    this.terminatedAt = 0;
    queueMicrotask(() => {
      if (this.exited) return;
      if (this.failStartup) this.emit("message", { ready: false, error: "synthetic_open_failure" });
      else this.emit("message", { ready: true });
    });
  }

  on(event, listener) { super.on(event, listener); return this; }
  off(event, listener) { super.off(event, listener); return this; }

  postMessage(message) {
    this.messages.push(message);
    this.onMessage?.(message);
  }

  async terminate() {
    this.terminateCalls += 1;
    if (this.terminationGate) await this.terminationGate;
    this.terminatedAt = Date.now();
    this.exit(1);
    return 1;
  }

  exit(code = 1) {
    if (this.exited) return;
    this.exited = true;
    this.emit("exit", code);
  }
}

async function openRuntime(t, { delays = [0, 0, 0], onSpawn } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-recover-"));
  const ports = [];
  let runtime;
  t.after(async () => {
    await runtime?.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  });
  runtime = await AuditRuntime.open(join(dir, "nmzp.db"), {
    create: true,
    retention: { minFreeBytes: 0 },
    recoveryDelaysMs: delays,
    spawn(workerData) {
      const port = new FakePort(workerData);
      ports.push(port);
      onSpawn?.(port, ports.length);
      return port;
    },
  });
  assert.equal(ports.length, 1, "spawn seam must construct the audit worker");
  assert.equal(runtime.state, "ready");
  return { dir, runtime, ports };
}

test("in-flight audit call rejects once and is not replayed", { timeout: 10_000 }, async (t) => {
  const { runtime, ports } = await openRuntime(t, {
    delays: [5, 5, 5],
    onSpawn(port, index) {
      port.onMessage = (message) => {
        if (index === 1 || message.operation !== "append") return;
        port.emit("message", { id: message.id, value: { inserted: true, event: message.args[0] } });
      };
    },
  });
  let settlements = 0;
  const pending = runtime.append(event("inflight"));
  pending.then(() => { settlements += 1; }, () => { settlements += 1; });
  assert.equal(await waitFor(() => ports[0].messages.some((message) => message.operation === "append")), true);
  ports[0].emit("error", new Error("synthetic_worker_down"));
  await assert.rejects(pending, { message: "synthetic_worker_down" });
  assert.equal(await waitFor(() => ports.length >= 2 && runtime.state === "ready"), true, "replacement worker must become ready");
  await delay(30);
  assert.equal(settlements, 1, "in-flight call must reject exactly once");
  const replayed = ports.slice(1).some((port) => port.messages.some((message) => message.operation === "append"));
  assert.equal(replayed, false, "failed in-flight request must not be replayed");
});

test("replacement worker starts only after the failed worker terminates", { timeout: 10_000 }, async (t) => {
  const gate = deferred();
  const { runtime, ports } = await openRuntime(t, {
    delays: [0, 0, 0],
    onSpawn(port, index) {
      if (index === 1) port.terminationGate = gate.promise;
    },
  });
  t.after(() => gate.resolve());
  ports[0].emit("error", new Error("synthetic_worker_down"));
  await delay(40);
  assert.equal(ports.length, 1, "replacement must not spawn before termination resolves");
  gate.resolve();
  assert.equal(await waitFor(() => ports.length >= 2), true, "replacement must spawn after termination resolves");
  assert.ok(ports[1].spawnedAt >= ports[0].terminatedAt, "replacement must spawn only after the old terminate resolved");
  assert.equal(runtime.state === "recovering" || runtime.state === "ready", true);
});

test("replacement worker opens with create false", { timeout: 10_000 }, async (t) => {
  const { ports } = await openRuntime(t, { delays: [0, 0, 0] });
  assert.equal(ports[0].workerData.create, true);
  ports[0].emit("error", new Error("synthetic_worker_down"));
  assert.equal(await waitFor(() => ports.length >= 2), true, "replacement worker must be spawned");
  assert.equal(ports[1].workerData.create, false, "replacement must open with create false");
  assert.equal(ports[1].workerData.readOnly, ports[0].workerData.readOnly);
  assert.deepEqual(ports[1].workerData.retention, { minFreeBytes: 0 });
});

test("calls during recovery reject with audit_worker_recovering", { timeout: 10_000 }, async (t) => {
  const { runtime, ports } = await openRuntime(t, { delays: [400, 400, 400] });
  ports[0].emit("error", new Error("synthetic_worker_down"));
  assert.equal(runtime.state, "recovering");
  await assert.rejects(runtime.status(), { message: "audit_worker_recovering" });
  await assert.rejects(runtime.append(event("later")), { message: "audit_worker_recovering" });
});

test("recovered runtime appends and runs the reconciler", { timeout: 10_000 }, async (t) => {
  const { runtime, ports } = await openRuntime(t, {
    delays: [0, 0, 0],
    onSpawn(port) {
      port.onMessage = (message) => {
        if (message.operation === "recent") port.emit("message", { id: message.id, value: [event("committed")] });
        if (message.operation === "append") {
          port.emit("message", { id: message.id, value: { inserted: true, event: message.args[0] } });
        }
      };
    },
  });
  assert.equal(typeof runtime.setReconciler, "function", "runtime must expose a recovery reconciler");
  let runs = 0;
  let recentRows = [];
  runtime.setReconciler(async (channel) => {
    runs += 1;
    recentRows = await channel.call("recent", 5);
  });
  ports[0].emit("error", new Error("synthetic_worker_down"));
  assert.equal(await waitFor(() => runtime.state === "ready" && ports.length >= 2), true, "runtime must leave recovery");
  assert.equal(runs, 1, "reconciler must run before the runtime is ready");
  assert.equal(recentRows[0]?.id, "committed");
  const appended = await runtime.append(event("after"));
  assert.equal(appended.inserted, true);
  assert.equal(ports[1].messages.filter((message) => message.operation === "append").length, 1);
});

test("recovery attempts stop at the delay list and fatal fires once", { timeout: 10_000 }, async (t) => {
  let fatals = 0;
  const { runtime, ports } = await openRuntime(t, {
    delays: [0, 0, 0],
    onSpawn(port, index) {
      if (index > 1) port.failStartup = true;
    },
  });
  runtime.onFatal(() => { fatals += 1; });
  ports[0].emit("error", new Error("synthetic_worker_down"));
  assert.equal(await waitFor(() => fatals === 1), true, "fatal listener must fire after the bounded attempts");
  assert.equal(ports.length, 4, "attempts must be capped at the delay list length");
  assert.equal(runtime.state, "failed");
  await delay(30);
  assert.equal(fatals, 1, "fatal listener must fire exactly once");
  await assert.rejects(runtime.status(), { message: "audit_worker_unavailable" });
});

test("close during backoff cancels the timer and resolves", { timeout: 10_000 }, async (t) => {
  const gate = deferred();
  const { runtime, ports } = await openRuntime(t, {
    delays: [1500, 1500, 1500],
    onSpawn(port, index) {
      if (index === 1) port.terminationGate = gate.promise;
    },
  });
  t.after(() => gate.resolve());
  ports[0].emit("error", new Error("synthetic_worker_down"));
  assert.equal(await waitFor(() => ports[0].terminateCalls >= 1), true, "old worker must start terminating before backoff");
  gate.resolve();
  assert.equal(await waitFor(() => ports[0].terminatedAt > 0), true, "old terminate must resolve before backoff");
  await delay(30);
  assert.equal(ports.length, 1, "backoff must still be pending when close starts");
  const started = Date.now();
  const first = runtime.close();
  const second = runtime.close();
  assert.equal(first, second, "concurrent close shares one promise");
  await first;
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 400, `close during backoff must resolve without waiting out the timer (${elapsed}ms)`);
  await delay(50);
  assert.equal(ports.length, 1, "close during backoff must not spawn a replacement");
});

test("cached get rejects while the runtime is recovering", { timeout: 10_000 }, async (t) => {
  const { dir, runtime, ports } = await openRuntime(t, {
    delays: [400, 400, 400],
    onSpawn(port) {
      port.onMessage = (message) => {
        if (message.operation === "recent") port.emit("message", { id: message.id, value: [event("kept")] });
      };
    },
  });
  const events = await AuditEvents.open(join(dir, "events.jsonl"), { runtime });
  assert.equal((await events.get("device", "kept"))?.id, "kept");
  ports[0].emit("error", new Error("synthetic_worker_down"));
  await assert.rejects(events.get("device", "kept"), { message: "audit_worker_recovering" });
  assert.equal(events.list().some((row) => row.id === "kept"), true);
});
