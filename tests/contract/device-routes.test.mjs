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

test("admin clients round-trip; device policy omits them and the ETag formula gains no client bytes", async t => {
  const f = await fixture(t);
  const before = await f.call("/api/v2/policy", { method: "GET" });
  const clients = [{ deviceId: "a", agent: "grok", mode: "log_only" }];
  const put = await f.call("/api/v1/policy", { method: "PUT", auth: f.srv.adminToken, body: { expectedVersion: before.body.version, clients } });
  assert.equal(put.status, 200);
  assert.deepEqual(put.body.clients, clients);
  assert.deepEqual(f.srv.store.getPolicy().clients, clients);
  const v1 = await f.call("/api/v1/policy", { method: "GET" });
  const v2 = await f.call("/api/v2/policy", { method: "GET" });
  assert.equal(Object.hasOwn(v1.body, "clients"), false);
  assert.equal(Object.hasOwn(v2.body, "clients"), false);
  assert.equal(JSON.stringify(v1.body).includes("log_only"), false);
  assert.equal(v2.body.rulesHash, before.body.rulesHash);
  assert.equal(v2.body.engineRevision, before.body.engineRevision);
  assert.equal(v2.body.version, before.body.version + 1);
  const etag = `"p${v2.body.version}.${v2.body.rulesHash.slice(7)}.e${v2.body.engineRevision}"`;
  assert.equal(v2.headers.etag, etag);
  assert.equal(String(v2.headers.etag).includes("log_only"), false);
  assert.equal(String(v2.headers.etag).includes("grok"), false);
  const denied = await f.call("/api/v1/policy", { method: "PUT", body: { expectedVersion: v2.body.version, clients: [] } });
  assert.equal(denied.status, 401);
  assert.equal(denied.body.error, "unauthorized");
  const bad = await f.call("/api/v1/policy", { method: "PUT", auth: f.srv.adminToken, body: { expectedVersion: v2.body.version, clients: [{ deviceId: "a", mode: "follow" }] } });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, "invalid_policy_clients");
  assert.deepEqual(f.srv.store.getPolicy().clients, clients);
});

test("receipt real HTTPS differential preserves isolation, immutable/truthy semantics and audit projection", async t => {
  const f = await fixture(t);
  for (const id of ["a", "b"]) await f.srv.store.appendEvent(event("same", id));
  const v1Body = { eventId: "same", evaluation: false, enforcement: "delivered", ignored: "secret-not-stored" };
  const body = { eventId: "same", evaluation: false, enforcement: "delivered" };
  const v1 = await f.call("/api/v1/receipt", { body: v1Body });
  const v2 = await f.call(paths.receipt[1], { body, auth: f.token("b") });
  assert.deepEqual(v2.body, v1.body);
  assert.deepEqual(noMachine(await f.srv.store.getEvent("b", "same")), noMachine(await f.srv.store.getEvent("a", "same")));
  assert.equal(JSON.stringify(await f.srv.store.getEvent("b", "same")).includes("secret-not-stored"), false);
  errorIs(await f.call(paths.receipt[1], { body: v1Body }), "bad_receipt", 400);
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
  const legacy = { hostname: "new", user: "u", policyVersion: 0.5, agents: ["grok"], capabilities: [{ id: "future", supported: true, active: false, unknown: "secret" }], unknown: "secret" };
  const body = { hostname: "new", user: "u", policyVersion: 0.5, agents: ["grok"], capabilities: [{ id: "future", supported: true, active: false, unknown: "secret" }] };
  const old = await f.call("/api/v1/heartbeat", { body: legacy });
  const current = await f.call(paths.heartbeat[1], { body, auth: f.token("b") });
  assert.deepEqual(current.body, old.body);
  errorIs(await f.call(paths.heartbeat[1], { body: legacy, auth: f.token("b") }), "bad_heartbeat", 400);
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

test("IC-10 v2 device routes reject duplicate members, invalid UTF-8 and unknown members; v1 stays unstrict", async t => {
  const f = await fixture(t, { storageMode: "sqlite" });
  await f.srv.store.appendEvent(event("rc-strict"));
  const dupReceipt = Buffer.from('{"eventId":"rc-strict","eventId":"rc-strict","evaluation":false,"enforcement":"delivered"}');
  errorIs(await f.call(paths.receipt[1], { raw: dupReceipt }), "duplicate_member", 400);
  assert.equal((await f.call("/api/v1/receipt", { raw: dupReceipt })).status, 200);
  const utf8Receipt = Buffer.concat([
    Buffer.from('{"eventId":"rc-strict","evaluation":false,"enforcement":"delivered","note":"'),
    Buffer.from([0xff]),
    Buffer.from('"}'),
  ]);
  errorIs(await f.call(paths.receipt[1], { raw: utf8Receipt }), "invalid_utf8", 400);
  assert.equal((await f.call("/api/v1/receipt", { raw: utf8Receipt })).status, 200);
  errorIs(await f.call(paths.receipt[1], { body: { eventId: "rc-strict", evaluation: false, enforcement: "delivered", ignored: "x" } }), "bad_receipt", 400);
  assert.equal((await f.call("/api/v1/receipt", { body: { eventId: "rc-strict", evaluation: false, enforcement: "delivered", ignored: "x" } })).status, 200);

  const dupBeat = Buffer.from('{"hostname":"h","hostname":"h"}');
  errorIs(await f.call(paths.heartbeat[1], { raw: dupBeat }), "duplicate_member", 400);
  assert.equal((await f.call("/api/v1/heartbeat", { raw: dupBeat })).status, 200);
  const utf8Beat = Buffer.concat([Buffer.from('{"hostname":"'), Buffer.from([0xff]), Buffer.from('"}')]);
  errorIs(await f.call(paths.heartbeat[1], { raw: utf8Beat }), "invalid_utf8", 400);
  assert.equal((await f.call("/api/v1/heartbeat", { raw: utf8Beat })).status, 200);
  errorIs(await f.call(paths.heartbeat[1], { body: { hostname: "closed", unknown: "x" } }), "bad_heartbeat", 400);
  assert.equal((await f.call("/api/v1/heartbeat", { body: { hostname: "closed", unknown: "x" } })).status, 200);

  const dupFill = Buffer.from('{"kind":"event","kind":"event","eventId":"bf-dup","payload":{"eventId":"bf-dup","ts":0,"agent":"grok","tool":"Read","decision":"allow","risk":"info","policyVersion":1}}');
  errorIs(await f.call(paths.backfill[1], { raw: dupFill }), "duplicate_member", 400);
  assert.equal((await f.call("/api/v1/audit/backfill", { raw: dupFill })).status, 200);
  const utf8Fill = Buffer.concat([
    Buffer.from('{"kind":"event","eventId":"bf-utf8","payload":{"eventId":"bf-utf8","ts":0,"agent":"gro'),
    Buffer.from([0xff]),
    Buffer.from('k","tool":"Read","decision":"allow","risk":"info","policyVersion":1}}'),
  ]);
  errorIs(await f.call(paths.backfill[1], { raw: utf8Fill }), "invalid_utf8", 400);
  assert.equal((await f.call("/api/v1/audit/backfill", { raw: utf8Fill })).status, 200);
});

test("v2 receipts, backfill and heartbeat bind optional body device.id to the token and leave v1 unchanged", async t => {
  const f = await fixture(t, { storageMode: "sqlite" });
  const badDevices = [{ id: "a", extra: 1 }, "a", { id: 1 }];
  const dropId = row => { const { id: _id, ...rest } = row; return rest; };
  const receipt = (id, device) => ({ eventId: id, enforcement: "delivered", ...(device === undefined ? {} : { device }) });

  await f.srv.store.appendEvent(event("rc-plain"));
  await f.srv.store.appendEvent(event("rc-bound"));
  const plainReceipt = await f.call(paths.receipt[1], { body: receipt("rc-plain") });
  const boundReceipt = await f.call(paths.receipt[1], { body: receipt("rc-bound", { id: "a" }) });
  assert.equal(plainReceipt.status, 200);
  assert.deepEqual({ ...boundReceipt.body, eventId: "rc-plain" }, plainReceipt.body);
  assert.deepEqual(dropId(await f.srv.store.getEvent("a", "rc-bound")), dropId(await f.srv.store.getEvent("a", "rc-plain")));

  await f.srv.store.appendEvent(event("rc-mismatch"));
  const pending = (await f.srv.store.getEvent("a", "rc-mismatch")).enforcement;
  errorIs(await f.call(paths.receipt[1], { body: receipt("rc-mismatch", { id: "b" }) }), "unauthorized", 401);
  assert.equal((await f.srv.store.getEvent("a", "rc-mismatch")).enforcement, pending);
  assert.equal(await f.srv.store.getEvent("b", "rc-mismatch"), undefined);
  for (const device of badDevices) {
    errorIs(await f.call(paths.receipt[1], { body: receipt("rc-mismatch", device) }), "unauthorized", 401);
    assert.equal((await f.srv.store.getEvent("a", "rc-mismatch")).enforcement, pending);
  }
  await f.srv.store.appendEvent(event("v1-rc-plain"));
  await f.srv.store.appendEvent(event("v1-rc-mismatch"));
  const v1PlainReceipt = await f.call("/api/v1/receipt", { body: receipt("v1-rc-plain") });
  const v1Mismatch = await f.call("/api/v1/receipt", { body: receipt("v1-rc-mismatch", { id: "b" }) });
  assert.equal(v1PlainReceipt.status, 200);
  assert.deepEqual({ ...v1Mismatch.body, eventId: "v1-rc-plain" }, v1PlainReceipt.body);
  assert.equal((await f.srv.store.getEvent("a", "v1-rc-mismatch")).enforcement, "delivered");
  for (const [index, device] of badDevices.entries()) {
    const id = `v1-rc-${index}`;
    await f.srv.store.appendEvent(event(id));
    const legacy = await f.call("/api/v1/receipt", { body: receipt(id, device) });
    assert.equal(legacy.status, 200);
    assert.deepEqual({ ...legacy.body, eventId: "v1-rc-plain" }, v1PlainReceipt.body);
    assert.equal((await f.srv.store.getEvent("a", id)).enforcement, "delivered");
  }

  const plainBackfill = await f.call(paths.backfill[1], { body: backfill("bf-plain") });
  const boundBackfill = await f.call(paths.backfill[1], { body: { ...backfill("bf-bound"), device: { id: "a" } } });
  assert.equal(plainBackfill.status, 200);
  assert.deepEqual({ ...boundBackfill.body, eventId: "bf-plain" }, plainBackfill.body);
  assert.deepEqual(dropId(await f.srv.store.getEvent("a", "bf-bound")), dropId(await f.srv.store.getEvent("a", "bf-plain")));
  errorIs(await f.call(paths.backfill[1], { body: { ...backfill("bf-mismatch"), device: { id: "b" } } }), "unauthorized", 401);
  assert.equal(await f.srv.store.getEvent("a", "bf-mismatch"), undefined);
  assert.equal(await f.srv.store.getEvent("b", "bf-mismatch"), undefined);
  for (const [index, device] of badDevices.entries()) {
    const id = `bf-bad-${index}`;
    errorIs(await f.call(paths.backfill[1], { body: { ...backfill(id), device } }), "unauthorized", 401);
    assert.equal(await f.srv.store.getEvent("a", id), undefined);
  }
  errorIs(await f.call(paths.backfill[1], { body: { ...backfill("bf-other"), device: { id: "a" }, other: 1 } }), "bad_backfill", 400);
  assert.equal(await f.srv.store.getEvent("a", "bf-other"), undefined);
  for (const [index, device] of [{ id: "a" }, { id: "b" }, ...badDevices].entries()) {
    const id = `bf-v1-${index}`;
    const legacy = await f.call("/api/v1/audit/backfill", { body: { ...backfill(id), device } });
    assert.equal(legacy.status, 400);
    assert.equal(legacy.body.ok, false);
    assert.equal(legacy.body.error, "bad_backfill");
    assert.equal(await f.srv.store.getEvent("a", id), undefined);
  }

  const heartbeat = { hostname: "bound-host", policyVersion: 1 };
  const plainHeartbeat = await f.call(paths.heartbeat[1], { body: heartbeat, auth: f.token("b") });
  const boundHeartbeat = await f.call(paths.heartbeat[1], { body: { ...heartbeat, device: { id: "a" } } });
  assert.equal(plainHeartbeat.status, 200);
  assert.deepEqual(boundHeartbeat.body, plainHeartbeat.body);
  assert.equal(f.srv.store.getDevice("a").hostname, "bound-host");
  assert.equal(f.srv.store.getDevice("b").hostname, "bound-host");
  errorIs(await f.call(paths.heartbeat[1], { body: { hostname: "stolen", policyVersion: 1, device: { id: "b" } } }), "unauthorized", 401);
  for (const device of badDevices) errorIs(await f.call(paths.heartbeat[1], { body: { hostname: "stolen", policyVersion: 1, device } }), "unauthorized", 401);
  assert.equal(f.srv.store.getDevice("a").hostname, "bound-host");
  assert.equal(f.srv.store.getDevice("b").hostname, "bound-host");
  const v1Heartbeat = { hostname: "v1-host", policyVersion: 1 };
  const v1PlainHeartbeat = await f.call("/api/v1/heartbeat", { body: v1Heartbeat, auth: f.token("b") });
  const v1DeviceHeartbeat = await f.call("/api/v1/heartbeat", { body: { ...v1Heartbeat, device: { id: "b" } } });
  assert.equal(v1DeviceHeartbeat.status, 200);
  assert.deepEqual(v1DeviceHeartbeat.body, v1PlainHeartbeat.body);
  assert.equal(f.srv.store.getDevice("a").hostname, "v1-host");
  for (const [index, device] of badDevices.entries()) {
    const hostname = `v1-shape-${index}`;
    const legacy = await f.call("/api/v1/heartbeat", { body: { hostname, policyVersion: 1, device } });
    assert.equal(legacy.status, 200);
    assert.deepEqual(legacy.body, v1PlainHeartbeat.body);
    assert.equal(f.srv.store.getDevice("a").hostname, hostname);
  }

  const keys = generateKeyPairSync("ed25519");
  const binding = newProbeBinding(keys.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
  await f.srv.store.bindProbe("a", binding);
  const raw = JSON.stringify({ hostname: "proved", policyVersion: 1, device: { id: "a" } });
  const challenge = (await f.call("/api/v1/probe/challenge", { method: "GET" })).body;
  const headers = { "x-nmzp-challenge": challenge.nonce, "x-nmzp-signature": sign(null, proofMessage("a", binding.keyId, challenge.nonce, raw), keys.privateKey).toString("base64") };
  assert.equal((await f.call(paths.heartbeat[1], { raw, headers })).status, 200);
  assert.equal(f.srv.store.getDevice("a").hostname, "proved");
});
