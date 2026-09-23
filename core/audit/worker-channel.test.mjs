import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { Worker } from "node:worker_threads";
import { AuditWorkerChannel } from "./worker-channel.ts";

// Unit transport only; no SQLite, files, HTTP, host hooks or user configuration.
class FakeWorker extends EventEmitter {
  messages = [];
  terminateCalls = 0;
  stopped = false;
  sendError;
  terminationError;
  terminationGate;
  onSend;

  postMessage(message) {
    if (this.sendError) throw this.sendError;
    this.messages.push(message);
    this.onSend?.(message);
  }

  exit(code = 0) {
    if (this.stopped) return;
    this.stopped = true;
    this.emit("exit", code);
  }

  async terminate() {
    this.terminateCalls++;
    if (this.terminationGate) await this.terminationGate;
    if (this.terminationError) throw this.terminationError;
    this.exit(1);
    return 1;
  }

  reply(index, value) { this.emit("message", { id: this.messages[index].id, value }); }
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function opened(t) {
  const worker = new FakeWorker();
  const opening = AuditWorkerChannel.open(worker);
  worker.emit("message", { ready: true });
  const channel = await opening;
  t.after(async () => {
    worker.exit(99); // settle any requests left by a failed assertion
    await channel.close().catch(() => undefined);
  });
  return { worker, channel };
}

function assertDetached(worker) {
  for (const name of ["message", "error", "messageerror", "exit"]) {
    assert.equal(worker.listenerCount(name), 0, `${name} listener must be removed`);
  }
}

const microtasks = async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); };

test("open waits for the worker ready handshake", async (t) => {
  const worker = new FakeWorker();
  const opening = AuditWorkerChannel.open(worker);
  let settled = false;
  opening.then(() => { settled = true; });
  await microtasks();
  assert.equal(settled, false);
  worker.emit("message", { ready: true });
  const channel = await opening;
  t.after(() => channel.close());
  const call = channel.call("get", "synthetic-device", "synthetic-id");
  assert.deepEqual(worker.messages[0], { id: 1, operation: "get", args: ["synthetic-device", "synthetic-id"] });
  worker.reply(0, undefined);
  assert.equal(await call, undefined);
});

test("startup rejection awaits termination and preserves the worker error", async () => {
  const worker = new FakeWorker();
  const gate = deferred();
  worker.terminationGate = gate.promise;
  const opening = AuditWorkerChannel.open(worker);
  const rejected = assert.rejects(opening, { message: "synthetic_open_failure" });
  let complete = false;
  rejected.then(() => { complete = true; });
  worker.emit("message", { ready: false, error: "synthetic_open_failure" });
  await microtasks();
  assert.equal(complete, false, "open must await worker cleanup");
  gate.resolve();
  await rejected;
  assert.equal(worker.terminateCalls, 1);
  assertDetached(worker);
});

for (const [label, event, value, expected] of [
  ["error", "error", new Error("synthetic_start_error"), "synthetic_start_error"],
  ["messageerror", "messageerror", new Error("synthetic_clone_error"), "audit_worker_message_error"],
  ["zero exit", "exit", 0, "audit_worker_exited:0"],
]) {
  test(`startup ${label} rejects without waiting for the start deadline`, async () => {
    const worker = new FakeWorker();
    const rejected = assert.rejects(AuditWorkerChannel.open(worker), { message: expected });
    if (event === "exit") worker.exit(value); else worker.emit(event, value);
    await rejected;
    assertDetached(worker);
  });
}

test("startup timeout terminates and removes all lifecycle listeners", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const worker = new FakeWorker();
  const rejected = assert.rejects(AuditWorkerChannel.open(worker), { message: "audit_worker_start_timeout" });
  t.mock.timers.tick(30_000);
  await rejected;
  assert.equal(worker.terminateCalls, 1);
  assertDetached(worker);
});

test("non-boolean ready must not be mistaken for success", async () => {
  const worker = new FakeWorker();
  const rejected = assert.rejects(AuditWorkerChannel.open(worker), { message: "audit_worker_protocol_error" });
  worker.emit("message", { ready: "yes" });
  await rejected;
  assertDetached(worker);
});

test("replies correlate by id even when they arrive out of order", async (t) => {
  const { channel, worker } = await opened(t);
  const first = channel.call("status");
  const second = channel.call("recent", 2);
  worker.reply(1, ["synthetic-second"]);
  worker.reply(0, { retained: 2 });
  assert.deepEqual(await first, { retained: 2 });
  assert.deepEqual(await second, ["synthetic-second"]);
});

test("per-operation storage error does not disable a healthy channel", async (t) => {
  const { channel, worker } = await opened(t);
  const rejected = assert.rejects(channel.call("get", "d", "a"), { message: "audit_corrupt" });
  worker.emit("message", { id: 1, error: "audit_corrupt" });
  await rejected;
  const next = channel.call("status");
  worker.reply(1, { retained: 1 });
  assert.deepEqual(await next, { retained: 1 });
  assert.equal(worker.terminateCalls, 0);
});

test("32 accepted calls fill the queue; settlement frees a slot", async (t) => {
  const { channel, worker } = await opened(t);
  const calls = Array.from({ length: 32 }, () => channel.call("status"));
  const results = Promise.all(calls);
  await assert.rejects(channel.call("status"), { message: "audit_queue_full" });
  assert.equal(worker.messages.length, 32);
  worker.reply(0, 0);
  assert.equal(await calls[0], 0);
  const admitted = channel.call("status");
  assert.equal(worker.messages.length, 33);
  for (let i = 1; i < 33; i++) worker.reply(i, i);
  assert.equal((await results).length, 32);
  assert.equal(await admitted, 32);
});

test("synchronous send failure frees its slot and deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { channel, worker } = await opened(t);
  worker.sendError = new Error("synthetic_clone_failure");
  await assert.rejects(channel.call("append", () => undefined), { message: "synthetic_clone_failure" });
  worker.sendError = undefined;
  const next = channel.call("status");
  worker.reply(0, 7);
  assert.equal(await next, 7);
  t.mock.timers.tick(60_000);
  assert.equal(worker.terminateCalls, 0, "settled calls must leave no timeout behind");
});

test("a synchronous response cannot beat pending registration", async (t) => {
  const { channel, worker } = await opened(t);
  worker.onSend = ({ id }) => worker.emit("message", { id, value: 3 });
  assert.equal(await channel.call("status"), 3);
});

test("duplicate and unknown reply ids do not overwrite another result", async (t) => {
  const { channel, worker } = await opened(t);
  const first = channel.call("status");
  worker.reply(0, 1);
  assert.equal(await first, 1);
  const second = channel.call("status");
  worker.emit("message", { id: 1, value: "stale" });
  worker.emit("message", { id: 900, value: "unknown" });
  worker.reply(1, 2);
  assert.equal(await second, 2);
});

for (const bad of [null, [], { id: 1 }, { id: 1, value: "wrong", error: "also_wrong" }, { id: "1", value: 1 }]) {
  test(`malformed reply ${JSON.stringify(bad)} rejects pending calls`, async (t) => {
    const { channel, worker } = await opened(t);
    const rejected = assert.rejects(channel.call("status"), { message: "audit_worker_protocol_error" });
    worker.emit("message", bad);
    await rejected;
    await assert.rejects(channel.call("status"), { message: "audit_worker_protocol_error" });
    await channel.close();
  });
}

test("close stops admission immediately but drains accepted work", async (t) => {
  const { channel, worker } = await opened(t);
  const pending = channel.call("append", { id: "synthetic" });
  // Observe cleanup rejection if an earlier assertion deliberately fails under mutation.
  void pending.catch(() => undefined);
  const closing = channel.close();
  assert.equal(channel.close() === closing, true, "all close callers share the same promise");
  let closed = false;
  closing.then(() => { closed = true; });
  await microtasks();
  assert.equal(closed, false);
  assert.equal(worker.terminateCalls, 0);
  await assert.rejects(channel.call("status"), { message: "audit_worker_closed" });
  worker.reply(0, { inserted: true });
  assert.deepEqual(await pending, { inserted: true });
  await closing;
  assert.equal(worker.terminateCalls, 1);
  assert.equal(channel.close() === closing, true);
  assertDetached(worker);
});

for (const code of [0, 73]) {
  test(`close drains rejected promises when worker exits ${code} with work pending`, async (t) => {
    const { channel, worker } = await opened(t);
    const rejected = assert.rejects(channel.call("append", { id: "synthetic" }), { message: `audit_worker_exited:${code}` });
    const closing = channel.close();
    worker.exit(code);
    await rejected;
    await closing;
    assert.equal(worker.terminateCalls, 0, "already exited worker needs no termination");
    assertDetached(worker);
  });
}

test("operation timeout during close rejects the whole lane and completes cleanup", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { channel, worker } = await opened(t);
  const settled = Promise.allSettled([channel.call("append", {}), channel.call("get", "d", "a")]);
  let settledByDeadline = false;
  settled.then(() => { settledByDeadline = true; });
  const closing = channel.close();
  t.mock.timers.tick(30_000);
  await microtasks();
  assert.equal(settledByDeadline, true, "the original deadline must still settle calls during close");
  const outcomes = await settled;
  assert.ok(outcomes.every((result) => result.status === "rejected" && result.reason.message === "audit_worker_timeout"));
  await closing;
  assert.equal(worker.terminateCalls, 1);
  assertDetached(worker);
});

test("worker error during close rejects accepted work instead of hanging", async (t) => {
  const { channel, worker } = await opened(t);
  const failure = new Error("synthetic_worker_error");
  const rejected = assert.rejects(channel.call("status"), (error) => error === failure);
  const closing = channel.close();
  worker.emit("error", failure);
  await rejected;
  await closing;
  assert.equal(worker.terminateCalls, 1);
});

test("message deserialization failure is fatal even while closing", async (t) => {
  const { channel, worker } = await opened(t);
  const rejected = assert.rejects(channel.call("status"), { message: "audit_worker_message_error" });
  const closing = channel.close();
  worker.emit("messageerror", new Error("synthetic"));
  await rejected;
  await closing;
});

test("idle open worker exiting zero is not a healthy runtime", async (t) => {
  const { channel, worker } = await opened(t);
  worker.exit(0);
  await assert.rejects(channel.call("status"), { message: "audit_worker_exited:0" });
  await channel.close();
});

test("concurrent close callers both await actual termination", async (t) => {
  const { channel, worker } = await opened(t);
  const gate = deferred();
  worker.terminationGate = gate.promise;
  t.after(() => gate.resolve());
  const first = channel.close();
  const second = channel.close();
  assert.equal(first === second, true);
  let returned = false;
  second.then(() => { returned = true; });
  await microtasks();
  try {
    assert.equal(returned, false);
  } finally {
    gate.resolve();
  }
  await Promise.all([first, second]);
  assert.equal(worker.terminateCalls, 1);
});

test("termination rejection is observed and cannot become successful close", async (t) => {
  const { channel, worker } = await opened(t);
  worker.terminationError = new Error("synthetic_termination_failed");
  const closing = channel.close();
  await assert.rejects(closing, { message: "synthetic_termination_failed" });
  assert.equal(channel.close() === closing, true);
  await assert.rejects(channel.close(), { message: "synthetic_termination_failed" });
  await assert.rejects(channel.call("status"), { message: "audit_worker_closed" });
});

test("one fatal failure is retained; pending calls are not retried", async (t) => {
  const { channel, worker } = await opened(t);
  const failure = new Error("first_failure");
  const rejected = assert.rejects(channel.call("append", {}), (error) => error === failure);
  worker.emit("error", failure);
  worker.emit("error", new Error("second_failure"));
  await rejected;
  await assert.rejects(channel.call("status"), (error) => error === failure);
  assert.equal(worker.messages.length, 1, "no automatic write replay");
  await channel.close();
});

// Real Node Worker transport, deliberately NOT the SQLite backend. Only this
// test-created thread is terminated. The shared gate avoids timing-based sleeps.
const workerSource = `
import { parentPort, workerData } from 'node:worker_threads';
const gate = new Int32Array(workerData);
parentPort.postMessage({ ready: true });
parentPort.on('message', ({ id, operation }) => {
  if (operation === 'exit') process.exit(73);
  if (operation === 'throw') throw new Error('synthetic_thread_failure');
  if (operation === 'wait') Atomics.wait(gate, 0, 0, 10000);
  parentPort.postMessage({ id, value: operation });
});
`;

async function realWorker(t) {
  const buffer = new SharedArrayBuffer(4);
  const gate = new Int32Array(buffer);
  const worker = new Worker(new URL(`data:text/javascript,${encodeURIComponent(workerSource)}`), { workerData: buffer });
  t.after(async () => { Atomics.store(gate, 0, 1); Atomics.notify(gate, 0); await worker.terminate(); });
  const channel = await AuditWorkerChannel.open(worker);
  return { channel, worker, gate };
}

test("real Worker drains the admitted request before shutdown", { timeout: 15_000 }, async (t) => {
  const { channel, worker, gate } = await realWorker(t);
  const call = channel.call("wait");
  const closing = channel.close();
  assert.equal(closing === channel.close(), true);
  await assert.rejects(channel.call("status"), /audit_worker_closed/);
  Atomics.store(gate, 0, 1);
  Atomics.notify(gate, 0);
  assert.equal(await call, "wait");
  await closing;
  assert.equal(worker.threadId, -1);
});

test("real Worker exit during close rejects work and settles close", { timeout: 15_000 }, async (t) => {
  const { channel, worker } = await realWorker(t);
  const rejected = assert.rejects(channel.call("exit"), { message: "audit_worker_exited:73" });
  const closing = channel.close();
  await rejected;
  await closing;
  assert.equal(worker.threadId, -1);
});

test("real Worker exception during close does not lose the rejection", { timeout: 15_000 }, async (t) => {
  const { channel, worker } = await realWorker(t);
  const rejected = assert.rejects(channel.call("throw"), /synthetic_thread_failure/);
  const closing = channel.close();
  await rejected;
  await closing;
  assert.equal(worker.threadId, -1);
});


test("failure immediately after ready is not returned as a successful open", async () => {
  const worker = new FakeWorker();
  const rejected = assert.rejects(AuditWorkerChannel.open(worker), { message: "after_ready_failure" });
  worker.emit("message", { ready: true });
  worker.emit("error", new Error("after_ready_failure"));
  await rejected;
  assertDetached(worker);
});
