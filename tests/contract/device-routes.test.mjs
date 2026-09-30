import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { sha256Hex } from "../../core/auth.ts";
import { assertPin } from "../../core/https-client.ts";
import { newProbeBinding, proofMessage } from "../../core/probe-auth.ts";
import { BODY_LIMIT } from "../../core/constants.ts";
import { compileAll, createAjv, loadSchemas } from "./protocol-checks.mjs";

const schemas = loadSchemas();
const validators = compileAll(createAjv(schemas), schemas);
const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
const paths = { policy: ["GET", "/api/v2/policy"], receipt: ["POST", "/api/v2/receipts"], backfill: ["POST", "/api/v2/backfill"], heartbeat: ["POST", "/api/v2/heartbeat"] };
const successSchemas = { "/api/v2/policy": "policy", "/api/v2/receipts": "receipt", "/api/v2/backfill": "backfill", "/api/v2/heartbeat": "heartbeat" };

async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-v2-device-"));
  let srv;
  t.after(async () => { try { await srv?.close(); } finally { await rm(dir, { recursive: true, force: true }); } });
  srv = await startServer({ dataDir: dir, coreDir, host: "127.0.0.1", port: 0, uiDir: null, ...options });
  const token = id => `synthetic-device-token-${id}`;
  for (const id of ["a", "b"]) await srv.store.putDevice({ id, tokenHash: sha256Hex(token(id)), hostname: "fixture", user: "fixture", ip: "127.0.0.1", os: "linux", attachedAt: 1000, lastSeen: 1000, lastPolicyVersion: 1, agents: [], capabilities: [] });
  const call = (path, { method = "POST", body, raw, auth = token("a"), headers = {}, holdBody = false } = {}) => new Promise((resolve, reject) => {
    const text = raw ?? (body === undefined ? "" : JSON.stringify(body));
    const req = httpsRequest(new URL(path, srv.url), { method, ca: srv.tls.certPem, rejectUnauthorized: true, agent: false,
      headers: { ...(auth ? { authorization: `Bearer ${auth}` } : {}), "content-type": "application/json", "content-length": holdBody ? 100 : Buffer.byteLength(text), ...headers } }, res => {
      const chunks = [];
      res.on("data", b => chunks.push(b));
      res.on("error", reject);
      res.on("end", () => {
        clearTimeout(timer);
        const raw = Buffer.concat(chunks).toString("utf8");
        try {
          const body = raw ? JSON.parse(raw) : null;
          if (path.startsWith("/api/v2/")) {
            if (res.statusCode >= 400) {
              assert.equal(validators["error-envelope.schema.json"](body), true, JSON.stringify(body));
              assert.ok(body.error.requestId);
            } else if (res.statusCode === 304) assert.equal(raw, "");
            else assert.equal(validators[`${successSchemas[path]}-response.schema.json`](body), true, `${path}: ${JSON.stringify(body)}`);
          }
          resolve({ status: res.statusCode, body, raw, headers: res.headers });
        } catch (error) { reject(error); }
        finally { req.destroy(); }
      });
    });
    const timer = setTimeout(() => req.destroy(new Error("test_request_timeout")), 10_000);
    req.on("error", error => { clearTimeout(timer); reject(error); });
    req.on("socket", socket => socket.once("secureConnect", () => {
      try { assertPin(socket, srv.tls.fingerprintSha256); } catch (error) { req.destroy(error); return; }
      if (holdBody) req.flushHeaders(); else req.end(text);
    }));
  });
  return { srv, dir, token, call };
}
function errorIs(response, code, status) {
  assert.equal(response.status, status);
  assert.equal(response.body.error.code, code);
  assert.equal(Object.hasOwn(response.body.error, "data"), false);
}
function event(id, machineId = "a", extra = {}) {
  return { id, machineId, ts: 1000, agent: "grok", sessionId: "s", layer: "app_pre", tool: "Read", nativeTool: "Read", input: "", redacted: "", risk: "info", decision: "allow", category: "other", workdirScope: "project", policyVersion: 1, evaluation: "allow", enforcement: "pending_verify", ...extra };
}
function backfill(id) {
  return { kind: "event", eventId: id, payload: { eventId: id, ts: 0, agent: "grok", tool: "Read", decision: "allow", risk: "info", policyVersion: 1 } };
}
const noMachine = row => { const { machineId: _machineId, ...rest } = row; return rest; };

test("four v2 routes authenticate before reading body, reject admin/wrong/revoked credentials", async t => {
  const f = await fixture(t);
  for (const [method, path] of Object.values(paths)) {
    for (const auth of [null, "wrong", f.srv.adminToken]) errorIs(await f.call(path, { method, auth, holdBody: true }), "unauthorized", 401);
  }
  errorIs(await f.call("/api/v2/evaluate", { body: {} }), "bad_schema", 400);
  for (const method of ["PUT", "DELETE"]) errorIs(await f.call(paths.policy[1], { method }), "not_found", 404);
  await f.srv.store.revokeDevice("a", Date.now());
  for (const [method, path] of Object.values(paths)) errorIs(await f.call(path, { method, holdBody: true }), "unauthorized", 401);
});

test("policy HTTPS response matches v1 plus rulesHash; exact strong ETag and empty 304", async t => {
  const f = await fixture(t);
  const v1 = await f.call("/api/v1/policy", { method: "GET" });
  const v2 = await f.call(paths.policy[1], { method: "GET" });
  const { rulesHash, ...body } = v2.body;
  assert.deepEqual(body, v1.body);
  assert.match(rulesHash, /^sha256:[0-9a-f]{64}$/);
  const etag = `"p${body.version}.${rulesHash.slice(7)}.e${body.engineRevision}"`;
  assert.equal(v2.headers.etag, etag);
  for (const header of [etag, `"other",${etag}`, `${etag},"other"`]) {
    const result = await f.call(paths.policy[1], { method: "GET", headers: { "if-none-match": header } });
    assert.equal(result.status, 304); assert.equal(result.raw, ""); assert.equal(result.headers.etag, etag);
  }
  for (const header of ["*", `W/${etag}`, `"other", ${etag}`, '"different"']) {
    const result = await f.call(paths.policy[1], { method: "GET", headers: { "if-none-match": header } });
    assert.equal(result.status, 200); assert.deepEqual(result.body, v2.body);
  }
  const legacy = await f.call("/api/v1/policy", { method: "GET", headers: { "if-none-match": etag } });
  assert.equal(legacy.status, 200); assert.equal(legacy.headers.etag, undefined);
});

test("receipt real HTTPS differential preserves isolation, immutable/truthy semantics and audit projection", async t => {
  const f = await fixture(t);
  for (const id of ["a", "b"]) await f.srv.store.appendEvent(event("same", id));
  const body = { eventId: "same", evaluation: false, enforcement: "delivered", ignored: "secret-not-stored" };
  const v1 = await f.call("/api/v1/receipt", { body });
  const v2 = await f.call(paths.receipt[1], { body, auth: f.token("b") });
  assert.deepEqual(v2.body, v1.body);
  assert.deepEqual(noMachine(await f.srv.store.getEvent("b", "same")), noMachine(await f.srv.store.getEvent("a", "same")));
  assert.equal(JSON.stringify(await f.srv.store.getEvent("b", "same")).includes("secret-not-stored"), false);
  errorIs(await f.call(paths.receipt[1], { body: { ...body, evaluation: "block" } }), "evaluation_immutable", 409);
  await f.srv.store.appendEvent(event("only-a"));
  errorIs(await f.call(paths.receipt[1], { auth: f.token("b"), body: { ...body, eventId: "only-a" } }), "not_found", 404);
  errorIs(await f.call(paths.receipt[1], { body: { ...body, eventId: "missing" } }), "not_found", 404);
  await f.srv.store.appendEvent(event("model", "a", { layer: "model_response" }));
  errorIs(await f.call(paths.receipt[1], { body: { ...body, eventId: "model" } }), "forbidden", 403);
  errorIs(await f.call(paths.receipt[1], { raw: "null" }), "bad_receipt", 400);
  const legacyNull = await f.call("/api/v1/receipt", { raw: "null" });
  assert.equal(legacyNull.status, 500); assert.equal(legacyNull.body.error, "internal_error");
  errorIs(await f.call(paths.receipt[1], { raw: "{" }), "bad_json", 400);
  errorIs(await f.call(paths.receipt[1], { raw: "x".repeat(BODY_LIMIT + 1) }), "payload_too_large", 413);
});

test("backfill real HTTPS shares metadata-only/idempotency and distinguishes final receipt conflict", async t => {
  const f = await fixture(t, { storageMode: "sqlite" });
  const body = backfill("same");
  const v1 = await f.call("/api/v1/audit/backfill", { body });
  const v2 = await f.call(paths.backfill[1], { body, auth: f.token("b") });
  assert.deepEqual(v2.body, v1.body);
  assert.deepEqual(noMachine(await f.srv.store.getEvent("b", "same")), noMachine(await f.srv.store.getEvent("a", "same")));
  const stored = await f.srv.store.getEvent("b", "same");
  assert.equal(stored.hookBlind, true); assert.equal(stored.ts, 0); assert.equal(stored.input, ""); assert.equal(stored.redacted, "");
  assert.equal((await f.call(paths.backfill[1], { body })).body.duplicate, true);
  errorIs(await f.call(paths.backfill[1], { body: { ...body, payload: { ...body.payload, tool: "Write" } } }), "event_conflict", 409);
  errorIs(await f.call(paths.backfill[1], { body: { ...body, payload: { ...body.payload, input: "must-not-store" } } }), "bad_backfill", 400);
  errorIs(await f.call(paths.backfill[1], { raw: "{" }), "bad_backfill", 400);
  const receipt = { kind: "receipt", eventId: "same", payload: { eventId: "same", evaluation: "allow", enforcement: "delivered" } };
  assert.deepEqual((await f.call(paths.backfill[1], { body: receipt, auth: f.token("b") })).body, (await f.call("/api/v1/audit/backfill", { body: receipt })).body);
  assert.equal((await f.call(paths.backfill[1], { body: receipt })).body.duplicate, true);
  const conflicting = { ...receipt, payload: { ...receipt.payload, enforcement: "returned_deny" } };
  errorIs(await f.call(paths.backfill[1], { body: conflicting }), "conflict", 409);
  const oldConflict = await f.call("/api/v1/audit/backfill", { body: conflicting });
  assert.equal(oldConflict.status, 409); assert.equal(oldConflict.body.error, "conflict");
  errorIs(await f.call(paths.backfill[1], { body: { ...receipt, payload: { ...receipt.payload, evaluation: "block" } } }), "evaluation_immutable", 409);
  errorIs(await f.call(paths.backfill[1], { body: { kind: "receipt", eventId: "missing", payload: { ...receipt.payload, eventId: "missing" } } }), "not_found", 404);
  await f.srv.store.appendEvent(event("model", "a", { layer: "model_response" }));
  errorIs(await f.call(paths.backfill[1], { body: { kind: "receipt", eventId: "model", payload: { ...receipt.payload, eventId: "model" } } }), "forbidden", 403);
  await f.call("/api/v1/policy", { method: "PUT", auth: f.srv.adminToken, body: { expectedVersion: 1, stopped: true } });
  errorIs(await f.call(paths.backfill[1], { body: backfill("stopped") }), "processing_stopped", 503);
});

test("backfill keeps storage-disabled and real retained tombstone errors", async t => {
  const window = await fixture(t);
  errorIs(await window.call(paths.backfill[1], { raw: "{" }), "storage_not_enabled", 404);
  const f = await fixture(t, { storageMode: "sqlite", auditRetention: { maxRecords: 1, maxAgeMs: 0, minFreeBytes: 0 } });
  for (const id of ["old", "new"]) assert.equal((await f.call(paths.backfill[1], { body: backfill(id) })).status, 200);
  await f.srv.store.maintainAuditRetentionStep();
  assert.ok(await f.srv.store.getAuditTombstone("a", "old"));
  errorIs(await f.call(paths.backfill[1], { body: backfill("old") }), "event_expired", 409);
  const legacy = await f.call("/api/v1/audit/backfill", { body: backfill("old") });
  assert.equal(legacy.status, 409); assert.equal(legacy.body.error, "event_expired");
});

test("heartbeat shared business state preserves pollOnly, version checks and unknown-field privacy", async t => {
  const f = await fixture(t);
  const body = { hostname: "new", user: "u", policyVersion: 0.5, agents: ["grok"], capabilities: [{ id: "future", supported: true, active: false, unknown: "secret" }], unknown: "secret" };
  const old = await f.call("/api/v1/heartbeat", { body });
  const current = await f.call(paths.heartbeat[1], { body, auth: f.token("b") });
  assert.deepEqual(current.body, old.body);
  const project = d => ({ hostname: d.hostname, user: d.user, ip: d.ip, lastPolicyVersion: d.lastPolicyVersion, agents: d.agents, capabilities: d.capabilities, agentProcs: d.agentProcs, stoppedAck: d.stoppedAck, stopAckVersion: d.stopAckVersion });
  assert.deepEqual(project(f.srv.store.getDevice("a")), project(f.srv.store.getDevice("b")));
  assert.equal(f.srv.store.getDevice("b").lastPolicyVersion, 1);
  assert.equal(JSON.stringify(f.srv.store.getDevice("b")).includes("secret"), false);
  const poll = { pollOnly: true, hostname: "ignored", agents: ["ignored"], policyVersion: -1 };
  assert.deepEqual((await f.call(paths.heartbeat[1], { body: poll, auth: f.token("b") })).body, (await f.call("/api/v1/heartbeat", { body: poll })).body);
  assert.equal(f.srv.store.getDevice("b").hostname, "new");
  assert.deepEqual(project(f.srv.store.getDevice("a")), project(f.srv.store.getDevice("b")));
  errorIs(await f.call(paths.heartbeat[1], { body: { hostname: "😀".repeat(129) } }), "bad_heartbeat", 400);
  errorIs(await f.call(paths.heartbeat[1], { raw: "{" }), "bad_json", 400);
  assert.equal((await f.call("/api/v1/policy", { method: "PUT", auth: f.srv.adminToken, body: { expectedVersion: 1, stopped: true } })).status, 200);
  const ack = { pollOnly: true, stoppedAck: true, policyVersion: f.srv.store.getPolicy().version };
  const v1Ack = await f.call("/api/v1/heartbeat", { body: ack });
  const v2Ack = await f.call(paths.heartbeat[1], { body: ack, auth: f.token("b") });
  assert.deepEqual(v2Ack.body, v1Ack.body);
  assert.equal(v2Ack.body.stopState, "stop_confirmed");
  assert.equal(v2Ack.body.mode, "off");
});

test("heartbeat alias verifies the original v1-path proof and exact bytes; nonce/device binding stays single-use", async t => {
  const f = await fixture(t);
  const keys = generateKeyPairSync("ed25519");
  const binding = newProbeBinding(keys.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
  await f.srv.store.bindProbe("a", binding);
  const challenge = async () => (await f.call("/api/v1/probe/challenge", { method: "GET" })).body;
  const proof = (c, raw, id = "a") => ({ "x-nmzp-challenge": c.nonce, "x-nmzp-signature": sign(null, proofMessage(id, binding.keyId, c.nonce, raw), keys.privateKey).toString("base64") });
  const raw = '{ "pollOnly" : true, "policyVersion": 1 }';
  errorIs(await f.call(paths.heartbeat[1], { raw: "{" }), "probe_proof_required", 401);
  let c = await challenge();
  const headers = proof(c, raw);
  assert.equal((await f.call(paths.heartbeat[1], { raw, headers })).status, 200);
  errorIs(await f.call(paths.heartbeat[1], { raw, headers }), "probe_proof_required", 401);
  c = await challenge();
  errorIs(await f.call(paths.heartbeat[1], { raw: JSON.stringify(JSON.parse(raw)), headers: proof(c, raw) }), "probe_proof_required", 401);
  c = await challenge();
  errorIs(await f.call(paths.heartbeat[1], { raw, headers: proof(c, raw, "b") }), "probe_proof_required", 401);
  await f.srv.store.bindProbe("b", binding);
  c = await challenge();
  const crossDeviceProof = proof(c, raw);
  errorIs(await f.call(paths.heartbeat[1], { auth: f.token("b"), raw, headers: crossDeviceProof }), "probe_proof_required", 401);
  assert.equal((await f.call(paths.heartbeat[1], { raw, headers: crossDeviceProof })).status, 200);
  c = await challenge();
  assert.equal((await f.call("/api/v1/heartbeat", { raw, headers: proof(c, raw) })).status, 200);
});

test("outer device failures keep fixed private messages and unknown-write disposition", async t => {
  const f = await fixture(t);
  const original = f.srv.store.touchDevice;
  const secret = "synthetic-private-exception";
  try {
    for (const [exception, code, status, outcome] of [["audit_fixture_" + secret, "audit_storage_unavailable", 503, "unknown"], [secret, "internal_error", 500, "unknown"], ["policy_recovery_required", "policy_recovery_required", 503, "not_committed"]]) {
      let calls = 0;
      f.srv.store.touchDevice = async () => { calls++; throw new Error(exception); };
      const result = await f.call(paths.heartbeat[1], { body: {} });
      errorIs(result, code, status); assert.equal(result.body.error.outcome, outcome);
      assert.equal(result.raw.includes(secret), false); assert.equal(calls, 1);
    }
  } finally { f.srv.store.touchDevice = original; }
});


test("revocation during shared backfill/heartbeat waits stays rejected without writes", async t => {
  const f = await fixture(t, { storageMode: "sqlite" });
  const mutex = f.srv.store.withMutex;
  try {
    f.srv.store.withMutex = async fn => {
      await f.srv.store.revokeDevice("a", Date.now());
      return mutex.call(f.srv.store, fn);
    };
    errorIs(await f.call(paths.backfill[1], { body: backfill("revoked-wait") }), "unauthorized", 401);
    assert.equal(await f.srv.store.getEvent("a", "revoked-wait"), undefined);
  } finally { f.srv.store.withMutex = mutex; }
  const touch = f.srv.store.touchDevice;
  try {
    f.srv.store.touchDevice = async (...args) => {
      await f.srv.store.revokeDevice("b", Date.now());
      return touch.apply(f.srv.store, args);
    };
    errorIs(await f.call(paths.heartbeat[1], { auth: f.token("b"), body: { hostname: "must-not-land" } }), "unauthorized", 401);
    assert.equal(f.srv.store.getDevice("b").hostname, "fixture");
  } finally { f.srv.store.touchDevice = touch; }
});
