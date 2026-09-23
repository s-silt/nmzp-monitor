import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import {
  fetchAuditEvents,
  fetchAuditStorage,
  downloadAuditExportStream as downloadToStream,
  fetchPolicyHistory,
  fetchPolicyRevisionDetail,
  restorePolicyRevision,
  setAdminToken,
} from "../../src/lib/monitor/api.ts";

const downloadAuditExportStream = (options) => downloadToStream({ ...options, destination: new WritableStream() });

const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));

class MemoryStorage {
  #values = new Map();
  get length() { return this.#values.size; }
  key(index) { return [...this.#values.keys()][index] ?? null; }
  getItem(key) { return this.#values.get(String(key)) ?? null; }
  setItem(key, value) { this.#values.set(String(key), String(value)); }
  removeItem(key) { this.#values.delete(String(key)); }
  clear() { this.#values.clear(); }
}

function replaceGlobal(t, name, value) {
  const original = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { configurable: true, value });
  t.after(() => {
    if (original) Object.defineProperty(globalThis, name, original);
    else Reflect.deleteProperty(globalThis, name);
  });
}

describe("frontend history API client unit characterization", { concurrency: false }, () => {
  beforeEach((t) => {
    replaceGlobal(t, "sessionStorage", new MemoryStorage());
    replaceGlobal(t, "localStorage", new MemoryStorage());
    setAdminToken("synthetic-admin-token");
  });

  it("fetchAuditEvents builds query params, includes auth headers, and maps events", async (t) => {
    const rawEvents = [
      {
        id: "evt-1",
        ts: 1_800_000_000_000,
        machineId: "pc-1",
        agent: "grok",
        sessionId: "s1",
        layer: "app_pre",
        tool: "Read",
        nativeTool: "Read",
        risk: "info",
        decision: "allow",
        category: "file_read",
        redacted: "redacted-1",
        policyVersion: 2,
        enforcement: "delivered",
      },
      {
        id: "evt-2",
        ts: 1_800_000_000_001,
        machineId: "pc-1",
        agent: "custom-agent-x",
        sessionId: "s1",
        layer: "app_pre",
        tool: "Read",
        nativeTool: "Read",
        risk: "low",
        decision: "allow",
        category: "file_read",
        redacted: "redacted-2",
        policyVersion: 2,
        enforcement: "offline",
      },
    ];

    let capturedUrl = "";
    let capturedHeaders = null;
    replaceGlobal(t, "fetch", async (input, init) => {
      capturedUrl = String(input);
      capturedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({
        events: rawEvents,
        highWatermark: 100,
        nextBeforeSeq: 95,
        historyCompleteness: "unknown",
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await fetchAuditEvents({
      limit: 20,
      highWatermark: 100,
      beforeSeq: 98,
      machineId: "pc-1",
      agent: "grok",
      decision: "allow",
      risk: "info",
      ruleId: "rule-1",
      fromTs: 1000,
      toTs: 2000,
    });

    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.data.events.length, 2);
    assert.equal(result.data.highWatermark, 100);
    assert.equal(result.data.nextBeforeSeq, 95);

    // Verify unknown Agent preservation
    const unknownAgentEvt = result.data.events.find((e) => e.id === "evt-2");
    assert.ok(unknownAgentEvt);
    assert.equal(unknownAgentEvt.agent, "unknown");
    assert.equal(unknownAgentEvt.rawAgent, "custom-agent-x");

    // Verify headers & URL params
    assert.equal(capturedHeaders.get("authorization"), "Bearer synthetic-admin-token");
    const u = new URL(capturedUrl, "http://localhost");
    assert.equal(u.pathname, "/api/v1/audit/events");
    assert.equal(u.searchParams.get("limit"), "20");
    assert.equal(u.searchParams.get("highWatermark"), "100");
    assert.equal(u.searchParams.get("beforeSeq"), "98");
    assert.equal(u.searchParams.get("machineId"), "pc-1");
    assert.equal(u.searchParams.get("agent"), "grok");
    assert.equal(u.searchParams.get("decision"), "allow");
    assert.equal(u.searchParams.get("risk"), "info");
    assert.equal(u.searchParams.get("ruleId"), "rule-1");
    assert.equal(u.searchParams.get("fromTs"), "1000");
    assert.equal(u.searchParams.get("toTs"), "2000");
  });

  it("fetchAuditEvents handles 404 storage_not_enabled cleanly", async (t) => {
    replaceGlobal(t, "fetch", async () => {
      return new Response(JSON.stringify({ ok: false, error: "storage_not_enabled" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await fetchAuditEvents({});
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.status, 404);
    assert.equal(result.error, "storage_not_enabled");
  });

  it("fetchAuditStorage returns SQLite metrics or errors", async (t) => {
    const fixtureStatus = {
      retained: 2450,
      deleted: 12,
      tombstones: 12,
      retentionPending: 0,
      dbBytes: 7340032,
      reusableBytes: 4096,
      limits: {
        maxRecords: 100000,
        maxAgeMs: 2592000000,
        maxDbBytes: 1073741824,
        minFreeBytes: 268435456,
        tombstoneMs: 7776000000,
      },
      physicalShrink: "manual_vacuum_required",
    };

    replaceGlobal(t, "fetch", async () => {
      return new Response(JSON.stringify(fixtureStatus), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await fetchAuditStorage();
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.deepEqual(result.data, fixtureStatus);
  });

  it("downloadAuditExportStream validates stream completion and detects deletionsDuringExport", async (t) => {
    // 1. Successful JSON stream with complete: true
    const jsonBody = '{"metadata":{"formatVersion":1},"events":[],"exportedCount":10,"complete":true,"deletionsDuringExport":0}\n';
    replaceGlobal(t, "fetch", async () => {
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(jsonBody));
          controller.close();
        },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    let progressCalled = false;
    const res1 = await downloadAuditExportStream({
      format: "json",
      onProgress: (p) => {
        if (p.status === "completed") progressCalled = true;
      },
    });
    assert.equal(res1.ok, true);
    assert.equal(res1.complete, true);
    assert.equal(res1.exportedCount, 10);
    assert.equal(res1.deletionsDuringExport, 0);
    assert.equal(progressCalled, true);

    // 2. Stream with complete: false (deletions occurred during export)
    const jsonBodyPruned = '{"metadata":{},"events":[],"exportedCount":10,"complete":false,"deletionsDuringExport":5}\n';
    replaceGlobal(t, "fetch", async () => {
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(jsonBodyPruned));
          controller.close();
        },
      }), { status: 200 });
    });

    const res2 = await downloadAuditExportStream({ format: "json" });
    assert.equal(res2.ok, true);
    assert.equal(res2.complete, false);
    assert.equal(res2.deletionsDuringExport, 5);

    // 3. Truncated stream missing summary
    const truncatedBody = '{"metadata":{},"events":[{"id":"evt-1"}';
    replaceGlobal(t, "fetch", async () => {
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(truncatedBody));
          controller.close();
        },
      }), { status: 200 });
    });

    const res3 = await downloadAuditExportStream({ format: "json" });
    assert.equal(res3.ok, false);
    assert.equal(res3.error, "incomplete_stream_missing_summary");
  });

  it("downloadAuditExportStream supports cancellation via AbortSignal", async (t) => {
    const controller = new AbortController();
    replaceGlobal(t, "fetch", async (_input, init) => {
      init.signal?.throwIfAborted();
      return new Response(new ReadableStream({
        start(ctrl) {
          ctrl.enqueue(new TextEncoder().encode("chunk-1"));
        },
      }), { status: 200 });
    });

    controller.abort();
    const res = await downloadAuditExportStream({
      signal: controller.signal,
    });
    assert.equal(res.ok, false);
    assert.equal(res.error, "cancelled");
  });

  it("fetchPolicyHistory and fetchPolicyRevisionDetail retrieve versions and details", async (t) => {
    const revisions = [
      { version: 2, hash: "b".repeat(64), publishedAt: 2000, rulesHash: "d".repeat(64), engineVersion: "0.2.3" },
      { version: 1, hash: "a".repeat(64), publishedAt: 1000, rulesHash: "c".repeat(64), engineVersion: "0.2.3" },
    ];
    replaceGlobal(t, "fetch", async (input) => {
      const url = String(input);
      if (url.includes("/api/v1/policy/history/1")) {
        return new Response(JSON.stringify({
          version: 1, formatVersion: 1, hash: "a".repeat(64), publishedAt: 1000,
          rulesHash: "c".repeat(64), engineVersion: "0.2.3", policy: { mode: "enforcing" },
        }), { status: 200 });
      }
      return new Response(JSON.stringify({
        revisions,
        nextBeforeVersion: null,
      }), { status: 200 });
    });

    const listRes = await fetchPolicyHistory({ limit: 50 });
    assert.equal(listRes.ok, true);
    if (!listRes.ok) return;
    assert.equal(listRes.data.revisions.length, 2);
    assert.equal(listRes.data.nextBeforeVersion, null);

    const detailRes = await fetchPolicyRevisionDetail(1);
    assert.equal(detailRes.ok, true);
    if (!detailRes.ok) return;
    assert.equal(detailRes.data.version, 1);
    assert.deepEqual(detailRes.data.policy, { mode: "enforcing" });
  });

  it("restorePolicyRevision sends expectedVersion and handles CAS 409 conflict", async (t) => {
    // 1. CAS Conflict 409
    replaceGlobal(t, "fetch", async () => {
      return new Response(JSON.stringify({ ok: false, error: "cas_conflict", version: 5 }), {
        status: 409,
        headers: { "content-type": "application/json" },
      });
    });

    const conflict = await restorePolicyRevision({ expectedVersion: 3, sourceVersion: 2 });
    assert.equal(conflict.ok, false);
    assert.equal(conflict.status, 409);
    assert.equal(conflict.error, "cas_conflict");
    assert.equal(conflict.version, 5);

    // 2. Successful incremental restore
    replaceGlobal(t, "fetch", async (_input, init) => {
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.expectedVersion, 5);
      assert.equal(parsed.sourceVersion, 2);
      return new Response(JSON.stringify({ ok: true, version: 6, mode: "enforcing", stopped: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const success = await restorePolicyRevision({ expectedVersion: 5, sourceVersion: 2 });
    assert.equal(success.ok, true);
    assert.equal(success.version, 6);
    assert.equal(success.mode, "enforcing");
    assert.equal(success.stopped, false);
  });
});

describe("real server integration: window mode vs sqlite mode", () => {
  async function setupServer(t, storageMode) {
    const dir = await mkdtemp(join(tmpdir(), `nmzp-test-${storageMode}-`));
    let server;
    t.after(async () => {
      try { await server?.close(); } finally { await rm(dir, { recursive: true, force: true }); }
    });
    server = await startServer({
      dataDir: dir,
      coreDir,
      host: "127.0.0.1",
      port: 0,
      uiDir: null,
      storageMode,
    });

    const request = async (path, { method = "GET", body, token = server.adminToken } = {}) => {
      const res = await pinnedHttps({
        url: `${server.url}${path}`,
        method,
        caPem: server.tls.certPem,
        fingerprintSha256: server.tls.fingerprintSha256,
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        timeoutMs: 5000,
      });
      let parsed = null;
      try { parsed = JSON.parse(res.body); } catch { /* text */ }
      return { status: res.status, body: parsed, rawBody: res.body };
    };

    const enrollDevice = async () => {
      const ticket = await request("/api/v1/ticket", { method: "POST" });
      const joinRes = await request("/api/v1/join", {
        method: "POST",
        token: "",
        body: { ticket: ticket.body.ticket, hostname: "pc-fixture", os: "win32", user: "u" },
      });
      assert.equal(joinRes.status, 200);
      return joinRes.body;
    };

    const evaluateEvent = async (deviceToken, id = "evt-fixture", agent = "grok") => {
      const evalRes = await request("/api/v1/evaluate", {
        method: "POST",
        token: deviceToken,
        body: {
          eventId: id,
          sessionId: "s",
          agent,
          source: "hook",
          tool_name: "read_file",
          tool_input: { path: "test.txt" },
        },
      });
      assert.equal(evalRes.status, 200);
      return evalRes.body;
    };

    return { server, dir, request, enrollDevice, evaluateEvent };
  }

  it("window mode: returns 404 storage_not_enabled while preserving legacy v1 APIs", async (t) => {
    const f = await setupServer(t, "window");

    // 1. New endpoints must return 404 storage_not_enabled
    const auditEvents = await f.request("/api/v1/audit/events");
    assert.equal(auditEvents.status, 404);
    assert.equal(auditEvents.body.error, "storage_not_enabled");

    const auditStorage = await f.request("/api/v1/audit/storage");
    assert.equal(auditStorage.status, 404);
    assert.equal(auditStorage.body.error, "storage_not_enabled");

    const auditExport = await f.request("/api/v1/audit/export");
    assert.equal(auditExport.status, 404);
    assert.equal(auditExport.body.error, "storage_not_enabled");

    const policyHistory = await f.request("/api/v1/policy/history");
    assert.equal(policyHistory.status, 404);
    assert.equal(policyHistory.body.error, "storage_not_enabled");

    const policyRestore = await f.request("/api/v1/policy/restore", {
      method: "POST",
      body: { expectedVersion: 1, sourceVersion: 1 },
    });
    assert.equal(policyRestore.status, 404);
    assert.equal(policyRestore.body.error, "storage_not_enabled");

    // 2. Legacy v1 APIs remain untouched and functional
    const state = await f.request("/api/v1/state");
    assert.equal(state.status, 200);
    assert.equal(state.body.mode, "enforcing");
    assert.equal(state.body.evidenceWindow.limit, 2000);

    const oldExport = await f.request("/api/v1/export");
    assert.equal(oldExport.status, 200);
    assert.ok(Array.isArray(oldExport.body.events));
  });

  it("sqlite mode: supports events pagination, storage status, streaming export, and CAS restore", async (t) => {
    const f = await setupServer(t, "sqlite");
    const device = await f.enrollDevice();

    // Generate 3 evaluated events
    await f.evaluateEvent(device.deviceToken, "evt-1", "grok");
    await f.evaluateEvent(device.deviceToken, "evt-2", "codex");
    await f.evaluateEvent(device.deviceToken, "evt-3", "unknown_custom_agent");

    // 1. Audit storage status
    const storageRes = await f.request("/api/v1/audit/storage");
    assert.equal(storageRes.status, 200);
    assert.ok(storageRes.body.retained >= 3);
    assert.equal(typeof storageRes.body.dbBytes, "number");
    assert.equal(typeof storageRes.body.limits.maxRecords, "number");

    // 2. Audit events pagination (limit 2)
    const page1 = await f.request("/api/v1/audit/events?limit=2");
    assert.equal(page1.status, 200);
    assert.equal(page1.body.events.length, 2);
    assert.ok(page1.body.highWatermark > 0);
    assert.ok(page1.body.nextBeforeSeq !== null);

    // Page 2
    const page2 = await f.request(
      `/api/v1/audit/events?limit=2&highWatermark=${page1.body.highWatermark}&beforeSeq=${page1.body.nextBeforeSeq}`,
    );
    assert.equal(page2.status, 200);
    assert.ok(page2.body.events.length >= 1);

    // Filter by agent=grok
    const filteredGrok = await f.request("/api/v1/audit/events?limit=10&agent=grok");
    assert.equal(filteredGrok.status, 200);
    for (const evt of filteredGrok.body.events) {
      assert.equal(evt.agent, "grok");
    }

    // 3. Export streamed JSON
    const exportJson = await f.request("/api/v1/audit/export?format=json&gzip=0");
    assert.equal(exportJson.status, 200);
    assert.equal(exportJson.body.complete, true);
    assert.ok(exportJson.body.exportedCount >= 3);

    // 4. Policy history & restore
    const historyRes = await f.request("/api/v1/policy/history");
    assert.equal(historyRes.status, 200);
    assert.ok(historyRes.body.revisions.length >= 1);
    const initialRev = historyRes.body.revisions[0];
    assert.equal(initialRev.version, 1);

    // Policy revision detail
    const detailRes = await f.request("/api/v1/policy/history/1");
    assert.equal(detailRes.status, 200);
    assert.equal(detailRes.body.version, 1);
    assert.ok(detailRes.body.policy);

    // CAS conflict on restore
    const invalidRestore = await f.request("/api/v1/policy/restore", { method: "POST", body: null });
    assert.equal(invalidRestore.status, 400);
    const conflictRes = await f.request("/api/v1/policy/restore", {
      method: "POST",
      body: { expectedVersion: 999, sourceVersion: 1 },
    });
    assert.equal(conflictRes.status, 409);
    assert.equal(conflictRes.body.error, "cas_conflict");

    // Successful restore (expectedVersion: 1 -> creates version 2)
    const restoreRes = await f.request("/api/v1/policy/restore", {
      method: "POST",
      body: { expectedVersion: 1, sourceVersion: 1 },
    });
    assert.equal(restoreRes.status, 200);
    assert.equal(restoreRes.body.ok, true);
    assert.equal(restoreRes.body.version, 2);

    // Verify history now includes version 2
    const updatedHistory = await f.request("/api/v1/policy/history");
    assert.equal(updatedHistory.body.revisions[0].version, 2);
  });

  it("authorization: read-only viewer and device credentials cannot access admin audit routes", async (t) => {
    const f = await setupServer(t, "sqlite");
    const device = await f.enrollDevice();

    // 1. Unauthenticated requests are rejected (401)
    const unauth = await f.request("/api/v1/audit/events", { token: "" });
    assert.equal(unauth.status, 401);

    // 2. Device token cannot access admin routes (rejected with 401 unauthorized)
    const devAudit = await f.request("/api/v1/audit/events", { token: device.deviceToken });
    assert.equal(devAudit.status, 401);

    const devStorage = await f.request("/api/v1/audit/storage", { token: device.deviceToken });
    assert.equal(devStorage.status, 401);

    const devExport = await f.request("/api/v1/audit/export", { token: device.deviceToken });
    assert.equal(devExport.status, 401);

    const devPolicyHistory = await f.request("/api/v1/policy/history", { token: device.deviceToken });
    assert.equal(devPolicyHistory.status, 401);

    const devPolicyRestore = await f.request("/api/v1/policy/restore", {
      method: "POST",
      token: device.deviceToken,
      body: { expectedVersion: 1, sourceVersion: 1 },
    });
    assert.equal(devPolicyRestore.status, 401);
  });
});
