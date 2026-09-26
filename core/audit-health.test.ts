import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { Worker } from "node:worker_threads";
import { pinnedHttps } from "./https-client.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = import.meta.dirname;
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function record(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

async function request(srv: RunningServer, path: string, init: { method?: string; token?: string; body?: string } = {}) {
  const headers: Record<string, string> = {};
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await pinnedHttps({
    url: `${srv.url}${path}`,
    method: init.method ?? "GET",
    headers,
    body: init.body,
    caPem: srv.tls.certPem,
    fingerprintSha256: srv.tls.fingerprintSha256,
    timeoutMs: 8_000,
  });
  let body: unknown = null;
  try { body = JSON.parse(res.body); } catch { body = null; }
  return { status: res.status, body };
}

async function withSqlite(
  delays: number[],
  run: (ctx: { srv: RunningServer; workers: Worker[]; spawned: () => number }) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-audit-health-"));
  const workers: Worker[] = [];
  let spawned = 0;
  let srv: RunningServer | undefined;
  try {
    srv = await startServer({
      dataDir: dir,
      host: "127.0.0.1",
      port: 0,
      coreDir,
      uiDir: null,
      storageMode: "sqlite",
      auditRetention: { minFreeBytes: 0 },
      auditRecoveryDelaysMs: delays,
      auditWorkerSpawn(workerData) {
        spawned += 1;
        const worker = new Worker(new URL("./audit/runtime-worker.ts", import.meta.url), {
          execArgv: ["--experimental-strip-types"],
          workerData,
        });
        workers.push(worker);
        return worker;
      },
    });
    assert.equal(spawned, 1, "auditWorkerSpawn must construct the sqlite audit worker");
    await run({ srv, workers, spawned: () => spawned });
  } finally {
    await srv?.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  }
}

async function health(srv: RunningServer) {
  try {
    const res = await request(srv, "/health");
    return { status: res.status, body: record(res.body) };
  } catch {
    return { status: 0, body: null };
  }
}

describe("sqlite audit worker health", () => {
  it("sqlite /health reports 503 while the audit worker is down", { timeout: 30_000 }, async () => {
    await withSqlite([5_000, 5_000, 5_000, 5_000, 5_000], async ({ srv, workers }) => {
      const worker = workers[0];
      assert.ok(worker, "spawn seam must return the live audit worker");
      await worker.terminate();
      let seen = await health(srv);
      const deadline = Date.now() + 1_500;
      while (seen.status !== 503 && Date.now() < deadline) {
        await delay(20);
        seen = await health(srv);
      }
      assert.equal(seen.status, 503, "health must be 503 while the audit worker is down");
      assert.equal(seen.body?.ok, false);
      assert.equal(seen.body?.name, "nmzp");
      assert.equal(typeof seen.body?.version, "string");
      assert.match(String(seen.body?.audit), /^(recovering|failed)$/);
    });
  });

  it("audit worker recovers and evaluate succeeds again", { timeout: 30_000 }, async () => {
    await withSqlite([40, 80, 160, 320, 640], async ({ srv, workers, spawned }) => {
      const ticket = await request(srv, "/api/v1/ticket", { method: "POST", token: srv.adminToken });
      assert.equal(ticket.status, 200);
      const joined = await request(srv, "/api/v1/join", {
        method: "POST",
        body: JSON.stringify({ ticket: record(ticket.body)?.ticket, hostname: "synthetic", user: "fixture", os: "win32" }),
      });
      assert.equal(joined.status, 200);
      const deviceToken = record(joined.body)?.deviceToken;
      assert.equal(typeof deviceToken, "string");
      const before = await request(srv, "/api/v1/evaluate", {
        method: "POST",
        token: deviceToken as string,
        body: JSON.stringify({
          eventId: "evt-before-crash",
          sessionId: "s",
          agent: "grok",
          tool_name: "Read",
          tool_input: { file_path: "synthetic.txt" },
        }),
      });
      assert.equal(before.status, 200);
      const worker = workers[0];
      assert.ok(worker);
      await worker.terminate();
      let seen = await health(srv);
      const deadline = Date.now() + 8_000;
      while (Date.now() < deadline && !(seen.status === 200 && seen.body?.audit === "ready" && spawned() >= 2)) {
        await delay(20);
        seen = await health(srv);
      }
      assert.ok(spawned() >= 2, "a replacement audit worker must be opened");
      assert.equal(seen.status, 200, "health must be 200 after the audit worker recovers");
      assert.equal(seen.body?.audit, "ready");
      const after = await request(srv, "/api/v1/evaluate", {
        method: "POST",
        token: deviceToken as string,
        body: JSON.stringify({
          eventId: "evt-after-recovery",
          sessionId: "s",
          agent: "grok",
          tool_name: "Read",
          tool_input: { file_path: "synthetic.txt" },
        }),
      });
      assert.equal(after.status, 200, "evaluate must succeed after audit worker recovery");
      const page = await request(srv, "/api/v1/audit/events?limit=20", { token: srv.adminToken });
      assert.equal(page.status, 200);
      const events = record(page.body)?.events;
      assert.equal(Array.isArray(events), true);
      assert.ok(
        (events as Array<{ id?: string }>).some((row) => row.id === "evt-before-crash"),
        "event committed before the crash must remain readable",
      );
    });
  });
});
