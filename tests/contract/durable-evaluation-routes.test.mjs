import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import { sha256Hex } from "../../core/auth.ts";
import { loadMonitor } from "../../core/paths.ts";
import { prepareEvaluation } from "../../core/eval-bridge.ts";
import { evaluateDurably } from "../../core/evaluation-application.ts";
import { toCanonicalToolEvent } from "../../core/protocol/v2-adapter.ts";
import { buildRewriteLayout } from "../../core/protocol/rewrite-layout.ts";
import { compileAll, createAjv, loadSchemas } from "./protocol-checks.mjs";

const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
const schemas = loadSchemas(), validators = compileAll(createAjv(schemas), schemas);

test("real HTTPS V1 protocol precheck, stopped ordinary bytes, hidden receipt isolation and metadata-only backfill", async t => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-durable-routes-"));
  const srv = await startServer({ dataDir: dir, coreDir, host: "127.0.0.1", port: 0, uiDir: null, storageMode: "sqlite" });
  t.after(async () => { await srv.close(); await rm(dir, { recursive: true, force: true }); });
  const token = "synthetic-private-evaluation-test";
  await srv.store.putDevice({ id: "fixture", tokenHash: sha256Hex(token), hostname: "fixture", user: "fixture", ip: "127.0.0.1", os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [] });
  const call = async (path, body, auth = token) => {
    const r = await pinnedHttps({ url: srv.url + path, method: "POST", caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256,
      headers: { authorization: `Bearer ${auth}`, "content-type": "application/json" }, body: JSON.stringify(body) });
    const parsed = JSON.parse(r.body);
    if (path.startsWith("/api/v2/") && r.status >= 400) assert.equal(validators["error-envelope.schema.json"](parsed), true, JSON.stringify(validators["error-envelope.schema.json"].errors));
    return { ...r, parsed };
  };
  const monitor = await loadMonitor(coreDir); await srv.store.stop();
  const body = { eventId: "private", agent: "grok", tool_name: "Bash", tool_input: { command: "echo fixture" } }, raw = JSON.stringify(body);
  const parsed = toCanonicalToolEvent(raw, { deviceId: "fixture", eventId: "private", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok" });
  assert.equal(parsed.ok, true); const layout = buildRewriteLayout(raw, parsed); assert.equal(layout.ok, true);
  await evaluateDurably({ store: srv.store, snapshot: srv.store.capturePolicy(), monitor, windows: new monitor.SessionWindows(), event: { ...parsed.event, rewriteLayout: layout.layout }, prepared: prepareEvaluation(body, "fixture"), deviceId: "fixture", project: ({ record }) => record.outcome });
  assert.equal((await call("/api/v1/evaluate", body)).status, 409);
  assert.equal((await call("/api/v1/evaluate", body)).parsed.error, "event_protocol_incompatible");
  const ordinary = await call("/api/v1/evaluate", { ...body, eventId: "ordinary" });
  assert.equal(ordinary.body, JSON.stringify({ eventId: "ordinary", decision: "allow", reason: "processing_stopped", stopped: true, ruleIds: [], policyVersion: srv.store.getPolicy().version, summary: "", enforcement: "delivered" }));
  assert.equal((await call("/api/v2/receipts", { eventId: "private", enforcement: "delivered" })).parsed.error.code, "not_found");
  await srv.store.resume();
  assert.equal((await call("/api/v1/evaluate", body)).parsed.error, "event_protocol_incompatible");
  const backfill = await call("/api/v2/backfill", { kind: "event", eventId: "private", payload: { eventId: "private", ts: 1, agent: "grok", tool: "Bash", decision: "allow", risk: "info", policyVersion: 1 } });
  assert.equal(backfill.status, 409); assert.equal(backfill.parsed.error.code, "event_protocol_incompatible");
  assert.equal((await call("/api/v2/backfill", { kind: "receipt", eventId: "private", payload: { eventId: "private", evaluation: "allow", enforcement: "delivered" } })).parsed.error.code, "not_found");
  assert.equal((await srv.store.queryAudit({ limit: 10 })).events.length, 0);
  await srv.store.clearEvents(); assert.equal((await call("/api/v1/evaluate", body)).parsed.error, "event_protocol_incompatible");
  assert.equal((await call("/api/v1/evaluate", body, "bad")).status, 401);
});
