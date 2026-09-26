import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { AuditWorkerChannel, type AuditWorkerPort } from "./audit/worker-channel.ts";
import { json } from "./http-util.ts";
import { pinnedHttps } from "./https-client.ts";
import { resetCapacityMetrics, snapshotCapacity } from "./metrics.ts";
import { NmzpStore } from "./persist.ts";
import { startServer } from "./serve.ts";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const coreDir = dirname(fileURLToPath(import.meta.url));

class FakeWorker extends EventEmitter {
  messages: Array<{ id: number; operation: string; args: unknown[] }> = [];
  sendError?: Error;

  postMessage(message: { id: number; operation: string; args: unknown[] }): void {
    if (this.sendError) throw this.sendError;
    this.messages.push(message);
  }

  async terminate(): Promise<number> {
    this.emit("exit", 1);
    return 1;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function runNode(args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", ...args], {
      cwd: root,
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

describe("capacity metrics", { concurrency: false }, () => {
  it("a contended store mutex records queue depth, wait, and releases a failed task", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-metrics-mutex-"));
    const store = new NmzpStore(dir);
    try {
      await store.load();
      resetCapacityMetrics();
      let release: () => void = () => undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const first = store.withMutex(async () => {
        await gate;
        throw new Error("fail-task");
      });
      const second = store.withMutex(async () => "second");
      await delay(30);
      release();
      await assert.rejects(first, /fail-task/);
      assert.equal(await second, "second");
      const snap = snapshotCapacity();
      assert.ok(snap.mutex.queuedMax >= 2, "contended mutex must record a positive queue");
      assert.equal(snap.mutex.queuedCurrent, 0, "a failed task must release the queue");
      assert.ok(snap.mutex.waitMs.count >= 2);
      assert.ok(snap.mutex.waitMs.maxMs > 0, "the waiting task must record a positive wait");
      assert.ok(snap.mutex.holdMs.count >= 2);
      assert.equal(snap.mutex.waitMs.counts.length, snap.mutex.waitMs.edgesMs.length + 1);
      assert.equal(JSON.stringify(snap).includes("fail-task"), false);
    } finally {
      await store.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("worker queue rejection and a failed send are counted without keeping the slot", async () => {
    resetCapacityMetrics();
    const worker = new FakeWorker();
    const opening = AuditWorkerChannel.open(worker as unknown as AuditWorkerPort);
    worker.emit("message", { ready: true });
    const channel = await opening;
    try {
      worker.sendError = new Error("clone_failed");
      await assert.rejects(channel.call("get", "synthetic-device", "synthetic-id"), /clone_failed/);
      worker.sendError = undefined;
      const calls: Array<Promise<unknown>> = [];
      for (let i = 0; i < 32; i++) calls.push(channel.call("append", `row-${i}`));
      await assert.rejects(channel.call("append", "overflow"), /audit_queue_full/);
      for (const message of worker.messages) worker.emit("message", { id: message.id, value: null });
      await Promise.all(calls);
      const snap = snapshotCapacity();
      assert.ok(snap.worker.errors.task_failed >= 1);
      assert.ok(snap.worker.errors.queue_full >= 1);
      assert.equal(snap.worker.queueCurrent, 0);
      assert.ok(snap.worker.queueMax >= 32);
      assert.equal(JSON.stringify(snap).includes("synthetic-device"), false);
      assert.equal(JSON.stringify(snap).includes("clone_failed"), false);
    } finally {
      await channel.close().catch(() => undefined);
    }
  });

  it("a worker timeout is counted when the channel releases the pending call", async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    resetCapacityMetrics();
    const worker = new FakeWorker();
    const opening = AuditWorkerChannel.open(worker as unknown as AuditWorkerPort);
    worker.emit("message", { ready: true });
    const channel = await opening;
    const rejected = assert.rejects(channel.call("get", "device-should-not-appear", "event"), /audit_worker_timeout/);
    t.mock.timers.tick(30_000);
    await rejected;
    const snap = snapshotCapacity();
    assert.ok(snap.worker.errors.timeout >= 1);
    assert.equal(snap.worker.queueCurrent, 0);
    assert.equal(JSON.stringify(snap).includes("device-should-not-appear"), false);
    await channel.close().catch(() => undefined);
  });

  it("request counters use fixed status keys and drop the response body", () => {
    resetCapacityMetrics();
    let raw = "";
    const res = {
      writeHead() {},
      end(body: string) {
        raw = body;
      },
    } as unknown as ServerResponse;
    json(res, 200, { access: "admin", hostname: "secret-host" });
    assert.equal(JSON.parse(raw).ok, undefined);
    json(res, 404, { ok: false, error: "not_found", deviceId: "dev-secret" });
    json(res, 418, { error: "teapot" });
    const snap = snapshotCapacity();
    assert.equal(snap.requests.status["200"], 1);
    assert.equal(snap.requests.status["404"], 1);
    assert.equal(snap.requests.other, 1);
    assert.equal(Object.keys(snap.requests.status).length, 12);
    const text = JSON.stringify(snap);
    assert.equal(text.includes("secret-host"), false);
    assert.equal(text.includes("dev-secret"), false);
    assert.equal(text.includes("not_found"), false);
    assert.equal(Number.isFinite(snap.eventLoop.delayMs.maxMs), true);
  });

  it("the dry-run harness stays on a synthetic temp dir and does not extrapolate capacity", { timeout: 60_000 }, async () => {
    const script = join(root, "scripts", "bench-capacity.mjs");
    const refused = await runNode([script]);
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, /explicit --dry-run or --run-synthetic required/);

    const outside = join(root, "not-temp-capacity");
    const badDir = await runNode([script, "--dry-run", "--data-dir", outside]);
    assert.notEqual(badDir.code, 0);
    assert.match(badDir.stderr, /supplied --data-dir is rejected/);
    assert.equal(existsSync(outside), false);

    const owned = await mkdtemp(join(tmpdir(), "nmzp-supplied-"));
    const sentinel = join(owned, "sentinel.txt");
    await writeFile(sentinel, "keep-supplied");
    const supplied = await runNode([script, "--dry-run", "--data-dir", owned]);
    assert.notEqual(supplied.code, 0);
    assert.match(supplied.stderr, /supplied --data-dir is rejected/);
    assert.equal(await readFile(sentinel, "utf8"), "keep-supplied");
    assert.equal(existsSync(owned), true);

    const rootSentinel = join(tmpdir(), `nmzp-root-sentinel-${process.pid}`);
    await writeFile(rootSentinel, "keep-root");
    const rootDir = await runNode([script, "--dry-run", "--data-dir", tmpdir()]);
    assert.notEqual(rootDir.code, 0);
    assert.match(rootDir.stderr, /supplied --data-dir is rejected/);
    assert.equal(await readFile(rootSentinel, "utf8"), "keep-root");

    const linkParent = await mkdtemp(join(tmpdir(), "nmzp-link-"));
    const linkTarget = join(linkParent, "target");
    const link = join(linkParent, "link");
    await mkdir(linkTarget);
    await writeFile(join(linkTarget, "sentinel.txt"), "keep-link");
    await symlink(linkTarget, link, process.platform === "win32" ? "junction" : "dir");
    const linked = await runNode([script, "--dry-run", "--data-dir", link]);
    assert.notEqual(linked.code, 0);
    assert.match(linked.stderr, /supplied --data-dir is rejected/);
    assert.equal(await readFile(join(linkTarget, "sentinel.txt"), "utf8"), "keep-link");
    assert.equal(existsSync(link), true);

    const badBind = await runNode([script, "--dry-run", "--bind", "0.0.0.0"]);
    assert.notEqual(badBind.code, 0);
    assert.match(badBind.stderr, /non-loopback/);

    const run = await runNode([script, "--dry-run"], { NMZP_DATA: outside });
    assert.equal(run.code, 0, run.stderr);
    const report = JSON.parse(run.stdout) as {
      mode: string;
      synthetic: boolean;
      bind: string;
      dataDir: string;
      validatesRoutes: boolean;
      routeCapacity: boolean;
      extrapolation: string;
      productionCapacity: null;
      claimsProductionCapacity: boolean;
      matrix: { executed: boolean; devices: number[] };
      metrics: { mutex: { queuedMax: number; waitMs: { maxMs: number; count: number } } };
    };
    assert.equal(report.mode, "dry-run");
    assert.equal(report.synthetic, true);
    assert.equal(report.validatesRoutes, false);
    assert.equal(report.routeCapacity, false);
    assert.equal(report.bind, "127.0.0.1");
    assert.equal(report.extrapolation, "not_performed");
    assert.equal(report.productionCapacity, null);
    assert.equal(report.claimsProductionCapacity, false);
    assert.equal(report.matrix.executed, false);
    assert.deepEqual(report.matrix.devices, [10, 25, 50, 100]);
    assert.ok(report.dataDir.includes("nmzp-capacity-dry-"));
    assert.equal(report.dataDir.includes(outside), false);
    assert.equal(report.dataDir.includes(owned), false);
    assert.equal(existsSync(report.dataDir), false);
    assert.equal(await readFile(sentinel, "utf8"), "keep-supplied");
    assert.ok(report.metrics.mutex.queuedMax >= 2);
    assert.ok(report.metrics.mutex.waitMs.count >= 2);
    assert.ok(report.metrics.mutex.waitMs.maxMs > 0);
    assert.equal(run.stdout.includes("BEGIN CERTIFICATE"), false);
    await unlink(rootSentinel);
    await rm(owned, { recursive: true, force: true });
    await rm(linkParent, { recursive: true, force: true });
  });

  it("state and evaluate latency are recorded on loopback", { timeout: 60_000 }, async () => {
    resetCapacityMetrics();
    const dir = await mkdtemp(join(tmpdir(), "nmzp-route-latency-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    try {
      const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
      const state = await pinnedHttps({
        url: `${srv.url}/api/v1/state`,
        method: "GET",
        headers: { authorization: `Bearer ${srv.adminToken}` },
        ...pin,
        timeoutMs: 8000,
      });
      assert.equal(state.status, 200);
      const ticket = await pinnedHttps({
        url: `${srv.url}/api/v1/ticket`,
        method: "POST",
        body: "{}",
        headers: { authorization: `Bearer ${srv.adminToken}`, "content-type": "application/json" },
        ...pin,
        timeoutMs: 8000,
      });
      assert.equal(ticket.status, 200);
      const joined = await pinnedHttps({
        url: `${srv.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify({
          ticket: (JSON.parse(ticket.body) as { ticket: string }).ticket,
          hostname: "synth",
          os: "linux",
          user: "fixture",
        }),
        headers: { "content-type": "application/json" },
        ...pin,
        timeoutMs: 8000,
      });
      assert.equal(joined.status, 200);
      const deviceToken = (JSON.parse(joined.body) as { deviceToken: string }).deviceToken;
      const evaluated = await pinnedHttps({
        url: `${srv.url}/api/v1/evaluate`,
        method: "POST",
        body: JSON.stringify({
          eventId: "route-latency-1",
          agent: "grok",
          tool_name: "Read",
          tool_input: { file_path: "README.md" },
        }),
        headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
        ...pin,
        timeoutMs: 8000,
      });
      assert.equal(evaluated.status, 200);
      const snap = snapshotCapacity();
      assert.ok(snap.routes.state.count >= 1);
      assert.ok(snap.routes.evaluate.count >= 1);
      assert.equal(Number.isFinite(snap.routes.state.maxMs), true);
      assert.equal(Number.isFinite(snap.routes.evaluate.maxMs), true);
      const text = JSON.stringify(snap);
      assert.equal(text.includes(srv.adminToken), false);
      assert.equal(text.includes(deviceToken), false);
      assert.equal(text.includes("route-latency-1"), false);
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("run-synthetic drives loopback routes and deletes only its own directory", { timeout: 60_000 }, async () => {
    const script = join(root, "scripts", "bench-capacity.mjs");
    const owned = await mkdtemp(join(tmpdir(), "nmzp-synth-owned-"));
    await writeFile(join(owned, "sentinel.txt"), "keep-synthetic");
    const run = await runNode([
      script,
      "--run-synthetic",
      "--devices",
      "1",
      "--duration-ms",
      "200",
      "--storage",
      "window",
      "--concurrency",
      "1",
      "--poll-ms",
      "50",
      "--bind",
      "127.0.0.1",
    ], { NMZP_DATA: owned });
    assert.equal(run.code, 0, run.stderr);
    const report = JSON.parse(run.stdout) as {
      mode: string;
      routeCapacity: string;
      claimsProductionCapacity: boolean;
      productionCapacity: null;
      matrix: { executed: boolean };
      dataDir: string;
      outcomes: { state: { "200": number }; evaluate: { "200": number }; heartbeat: { "200": number } };
      latency: { state: { count: number; p50: number | null; p95: number | null; p99: number | null }; evaluate: { count: number; p99: number | null } };
      metrics: { routes: { state: { count: number }; evaluate: { count: number } } };
    };
    assert.equal(report.mode, "run-synthetic");
    assert.equal(report.routeCapacity, "synthetic-loopback-only");
    assert.equal(report.claimsProductionCapacity, false);
    assert.equal(report.productionCapacity, null);
    assert.equal(report.matrix.executed, false);
    assert.ok(report.dataDir.includes("nmzp-capacity-synth-"));
    assert.equal(existsSync(report.dataDir), false);
    assert.equal(await readFile(join(owned, "sentinel.txt"), "utf8"), "keep-synthetic");
    assert.ok(report.outcomes.state["200"] >= 1);
    assert.ok(report.outcomes.evaluate["200"] >= 1);
    assert.ok(report.outcomes.heartbeat["200"] >= 1);
    assert.ok(report.latency.state.count >= 1);
    assert.ok(report.latency.evaluate.count >= 1);
    assert.equal(report.latency.state.count, report.metrics.routes.state.count);
    assert.equal(typeof report.latency.state.p50, "number");
    assert.equal(typeof report.latency.evaluate.p99, "number");
    assert.equal(run.stdout.includes("BEGIN CERTIFICATE"), false);
    await rm(owned, { recursive: true, force: true });
  });
});
