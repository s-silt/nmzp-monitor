import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { startServer } from "../../core/serve.ts";
import { startAdminProxy } from "../../core/admin-proxy.ts";
import { downloadAuditExportStream, fetchAuditEvents, fetchAuditStorage, fetchPolicyHistory } from "../../src/lib/monitor/api.ts";

// Only temporary synthetic storage, loopback listeners and in-memory test destinations.
it("real board proxy streams large plain/gzip exports into the browser consumer and pins TLS", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "nmzp-board-export-"));
  let core, proxy, wrongPin;
  const realFetch = globalThis.fetch;
  t.after(async () => {
    globalThis.fetch = realFetch;
    await wrongPin?.close(); await proxy?.close(); await core?.close();
    await rm(root, { recursive: true, force: true });
  });
  core = await startServer({ dataDir: root, coreDir: fileURLToPath(new URL("../../core/", import.meta.url)),
    host: "127.0.0.1", port: 0, uiDir: null, storageMode: "sqlite" });
  const options = { ctUrl: core.url, caPem: core.tls.certPem, fingerprintSha256: core.tls.fingerprintSha256,
    adminToken: core.adminToken, host: "127.0.0.1", port: 0, uiDir: null };
  proxy = await startAdminProxy(options);
  assert.equal((await realFetch(proxy.url + "/api/v1/audit/export")).status, 401);
  const login = async (server) => {
    const response = await realFetch(server.url + "/api/v1/session", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ token: core.adminToken }) });
    assert.equal(response.status, 200);
    return response.headers.get("set-cookie").split(";")[0];
  };
  const cookie = await login(proxy);
  for (let i = 0; i < 80; i++) await core.store.appendEvent({
    id: `synthetic-${i}`, ts: Date.now(), machineId: "synthetic", agent: "grok", sessionId: "s", layer: "app_pre",
    tool: "Read", nativeTool: "Read", input: "synthetic".repeat(400), redacted: "synthetic".repeat(400),
    risk: "info", decision: "log", category: "other", workdirScope: "project", policyVersion: 1,
    evaluation: "log", enforcement: "pending_verify",
  });
  globalThis.fetch = (path, init) => realFetch(new URL(String(path), proxy.url), { ...init,
    headers: { ...Object.fromEntries(new Headers(init?.headers)), cookie } });
  assert.equal((await fetchAuditEvents({ limit: 20 })).data.events.length, 20);
  assert.equal((await fetchAuditStorage()).data.retained, 80);
  assert.equal((await fetchPolicyHistory()).data.revisions[0].version, 1);
  for (const format of ["json", "jsonl"]) for (const gzip of [false, true]) {
    const chunks = [];
    let closed = false;
    const result = await downloadAuditExportStream({ format, gzip, destination: new WritableStream({
      write(chunk) { chunks.push(Buffer.from(chunk)); }, close() { closed = true; },
    }) });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.exportedCount, 80);
    assert.equal(result.complete, true);
    assert.ok(result.totalBytes > 128 * 1024, "goes beyond the former buffered proxy limit");
    assert.equal(closed, true);
    const bytes = Buffer.concat(chunks);
    if (gzip) assert.equal(bytes.subarray(0, 2).toString("hex"), "1f8b", ".gz is actual gzip");
    const text = (gzip ? gunzipSync(bytes) : bytes).toString("utf8");
    if (format === "json") assert.equal(JSON.parse(text).events.length, 80);
    else assert.equal(JSON.parse(text.trim().split("\n").at(-1)).exportedCount, 80);
  }
  const controller = new AbortController();
  let aborted = false;
  const cancelled = await downloadAuditExportStream({ signal: controller.signal, destination: new WritableStream({
    write() { controller.abort(); }, abort() { aborted = true; },
  }) });
  assert.equal(cancelled.error, "cancelled");
  assert.equal(aborted, true);
  assert.equal((await fetchAuditStorage()).ok, true);
  wrongPin = await startAdminProxy({ ...options, fingerprintSha256: "0".repeat(64) });
  const wrongCookie = await login(wrongPin);
  assert.equal((await realFetch(wrongPin.url + "/api/v1/audit/export", { headers: { cookie: wrongCookie } })).status, 502);
});

it("invalid history responses and truncated exports never become empty success", async (t) => {
  const realFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = realFetch; });
  globalThis.fetch = async () => new Response("{}", { status: 200 });
  for (const query of [() => fetchAuditEvents({}), fetchAuditStorage, fetchPolicyHistory]) {
    assert.equal((await query()).ok, false);
  }
  let aborted = false, closed = false;
  globalThis.fetch = async () => new Response('{"metadata":{},"events":[{"text":"complete: true"}');
  const result = await downloadAuditExportStream({ destination: new WritableStream({
    abort() { aborted = true; }, close() { closed = true; },
  }) });
  assert.equal(result.error, "incomplete_stream_missing_summary");
  assert.equal(aborted, true);
  assert.equal(closed, false);
});
