import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { request as httpRequest } from "node:http";
import { startServer } from "../../core/serve.ts";
import { startLanViewer } from "../../core/lan-viewer.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import { parseApiState, exportApi } from "../../src/lib/monitor/api.ts";
import { mapEvent } from "../../src/lib/monitor/map-event.ts";
import { RULES } from "../../src/lib/monitor/rules.ts";
import { protectedRuleIds } from "../../src/lib/monitor/overrides.ts";

// Real, isolated HTTP/HTTPS servers. No fetch mock, live core, host CLI, process
// enumeration, ACL changes, install/uninstall or OS certificate-store access.
// These characterize existing v1 responses; they do not integrate PolicyPublisher.
const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
const TEST_TIMEOUT = 30_000;

async function harness(t) {
  const root = await mkdtemp(join(tmpdir(), "nmzp-backend-v1-"));
  const dataDir = join(root, "data");
  let core;
  let viewer;
  t.after(async () => {
    // Try all cleanup operations, even if one server fails to close.
    const errors = [];
    for (const server of [viewer, core]) {
      if (server) try { await server.close(); } catch (error) { errors.push(error); }
    }
    assert.equal(dirname(resolve(root)), resolve(tmpdir()));
    assert.ok(basename(root).startsWith("nmzp-backend-v1-"));
    await rm(root, { recursive: true, force: true });
    if (errors.length) throw new AggregateError(errors, "temporary server cleanup failed");
  });
  const start = () => startServer({ dataDir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
  core = await start();

  async function request(path, { method = "GET", token = core.adminToken, body } = {}) {
    assert.ok(path.startsWith("/api/v1/") || path === "/health");
    const base = new URL(core.url);
    assert.equal(base.hostname, "127.0.0.1");
    assert.ok(Number(base.port) > 0);
    const result = await pinnedHttps({
      url: `${core.url}${path}`, method,
      caPem: core.tls.certPem, fingerprintSha256: core.tls.fingerprintSha256,
      timeoutMs: 5000, maxBodyBytes: 8 * 1024 * 1024,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: result.status, text: result.body, data: JSON.parse(result.body) };
  }

  async function state() {
    const result = await request("/api/v1/state");
    assert.equal(result.status, 200);
    const parsed = parseApiState(result.data);
    assert.ok(parsed, "the REAL state response must be accepted by the existing consumer");
    return parsed;
  }

  async function enroll(name = "synthetic-pc") {
    const ticket = await request("/api/v1/ticket", { method: "POST" });
    assert.equal(ticket.status, 200);
    const result = await request("/api/v1/join", {
      method: "POST", token: "",
      body: { ticket: ticket.data.ticket, hostname: name, os: "win32", user: "synthetic-user" },
    });
    assert.equal(result.status, 200);
    assert.ok(result.data.deviceId); assert.ok(result.data.deviceToken);
    return result.data;
  }

  async function evaluate(device, id = "synthetic-event") {
    // This string is evaluated as DATA by the policy engine. No shell is started.
    const result = await request("/api/v1/evaluate", {
      method: "POST", token: device.deviceToken,
      body: {
        eventId: id, sessionId: "synthetic-session", agent: "grok", source: "hook",
        tool_name: "run_terminal_command", tool_input: { command: "echo nmzp-synthetic-fixture" },
      },
    });
    assert.equal(result.status, 200);
    assert.equal(result.data.eventId, id);
    return result.data;
  }

  return {
    request, state, enroll, evaluate, dataDir,
    get adminToken() { return core.adminToken; },
    async restart() {
      await core.close(); core = undefined;
      core = await start();
    },
    async viewer() {
      assert.equal(viewer, undefined);
      viewer = await startLanViewer({
        host: "127.0.0.1", port: 0, allowedCidrs: ["127.0.0.0/8"], uiDir: null,
        ctUrl: core.url, caPem: core.tls.certPem,
        fingerprintSha256: core.tls.fingerprintSha256, adminToken: core.adminToken,
      });
      return viewer;
    },
  };
}

function viewerRequest(port, path, method = "GET", token = "", body) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  return new Promise((resolveRequest, reject) => {
    let settled = false;
    let timer;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error); else resolveRequest(result);
    };
    const req = httpRequest({
      host: "127.0.0.1", port, path, method, agent: false,
      headers: {
        "connection": "close", "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      const chunks = []; let bytes = 0;
      res.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 8 * 1024 * 1024) {
          const error = new Error("temporary viewer response too large");
          res.destroy(error); finish(error); return;
        }
        chunks.push(chunk);
      });
      res.on("error", (error) => finish(error));
      res.on("end", () => {
        try { finish(null, { status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString("utf8")) }); }
        catch (error) { finish(error); }
      });
    });
    timer = setTimeout(() => {
      const error = new Error("temporary viewer request timeout");
      req.destroy(error); finish(error);
    }, 5000);
    req.on("error", (error) => finish(error));
    req.end(payload);
  });
}

describe("real backend v1 consumer contracts", { concurrency: false }, () => {
  it("returns a consumable state and rejects unauthenticated/invalid access", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const initial = await f.state();
    assert.equal(initial.access, "admin");
    assert.equal(typeof initial.policyVersion, "number");
    assert.ok(Array.isArray(initial.events)); assert.ok(Array.isArray(initial.devices));
    for (const token of ["", "synthetic-invalid-token"]) {
      assert.equal((await f.request("/api/v1/state", { token })).status, 401);
    }
    const device = await f.enroll();
    assert.equal((await f.request("/api/v1/state", { token: device.deviceToken })).status, 401);
    assert.equal((await f.request("/api/v1/policy", {
      method: "PUT", token: device.deviceToken, body: { expectedVersion: initial.policyVersion, mode: "off" },
    })).status, 401);
    assert.equal((await f.state()).policyVersion, initial.policyVersion);
  });

  it("real evaluated events survive the existing frontend event parser", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const device = await f.enroll();
    const decision = await f.evaluate(device);
    const state = await f.state();
    const raw = state.events.find((row) => row.id === decision.eventId);
    assert.ok(raw, "event must exist in actual state");
    const mapped = mapEvent(raw);
    assert.ok(mapped, "event must not disappear in the existing frontend parser");
    assert.equal(mapped.id, decision.eventId);
    assert.equal(mapped.decision, decision.decision);
    assert.equal(mapped.policyVersion, decision.policyVersion);
    assert.equal(mapped.agent, "grok");
  });

  it("concurrent policy edits have exactly one commit and one version conflict", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const initial = await f.state();
    const replies = await Promise.all(["permissive", "off"].map((mode) => f.request("/api/v1/policy", {
      method: "PUT", body: { expectedVersion: initial.policyVersion, mode },
    })));
    assert.deepEqual(replies.map((r) => r.status).sort(), [200, 409]);
    const winner = replies.find((r) => r.status === 200).data;
    const loser = replies.find((r) => r.status === 409).data;
    assert.equal(winner.version, initial.policyVersion + 1);
    assert.equal(typeof winner.version, "number");
    assert.equal(loser.error, "cas_conflict"); assert.equal(loser.version, winner.version);
    const current = await f.state();
    assert.equal(current.policyVersion, winner.version); assert.equal(current.mode, winner.mode);
    const onDisk = JSON.parse(await readFile(join(f.dataDir, "policy.json"), "utf8"));
    assert.equal(onDisk.version, winner.version); assert.equal(onDisk.mode, winner.mode);
    // This is normal file persistence verification, NOT proof of fsync/power-loss durability.
  });

  it("rejects protected-rule downgrade and preserves the published version", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const initial = await f.state();
    const ruleId = protectedRuleIds(RULES)[0];
    assert.ok(ruleId, "fixture must target an actual protected rule");
    const denied = await f.request("/api/v1/policy", {
      method: "PUT", body: {
        expectedVersion: initial.policyVersion,
        overrides: { rules: { [ruleId]: "off" }, families: {} },
      },
    });
    assert.equal(denied.status, 400); assert.equal(denied.data.error, "protected_rule_override");
    assert.equal((await f.state()).policyVersion, initial.policyVersion);
  });

  it("committed policy survives a normal close/reopen and reaches the device endpoint", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const device = await f.enroll();
    const initial = await f.state();
    const saved = await f.request("/api/v1/policy", {
      method: "PUT", body: { expectedVersion: initial.policyVersion, mode: "permissive" },
    });
    assert.equal(saved.status, 200);
    await f.restart();
    const state = await f.state();
    assert.equal(state.policyVersion, saved.data.version); assert.equal(state.mode, "permissive");
    const synced = await f.request("/api/v1/policy", { token: device.deviceToken });
    assert.equal(synced.status, 200); assert.equal(synced.data.version, saved.data.version);
    assert.equal(synced.data.mode, "permissive");
  });

  it("isolates device receipts and preserves immutable evaluation", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const a = await f.enroll("synthetic-a"); const b = await f.enroll("synthetic-b");
    const event = await f.evaluate(a);
    const receipt = { eventId: event.eventId, evaluation: event.decision, enforcement: "delivered" };
    const foreign = await f.request("/api/v1/receipt", { method: "POST", token: b.deviceToken, body: receipt });
    assert.ok([403, 404].includes(foreign.status));
    const changed = await f.request("/api/v1/receipt", {
      method: "POST", token: a.deviceToken,
      body: { ...receipt, evaluation: event.decision === "allow" ? "block" : "allow" },
    });
    assert.equal(changed.status, 409); assert.equal(changed.data.error, "evaluation_immutable");
    const accepted = await f.request("/api/v1/receipt", { method: "POST", token: a.deviceToken, body: receipt });
    assert.equal(accepted.status, 200);
    const mapped = mapEvent((await f.state()).events.find((row) => row.id === event.eventId));
    assert.ok(mapped); assert.equal(mapped.decision, event.decision); assert.equal(mapped.enforcement, "delivered");
  });

  it("exports ordinary v1 JSON and persistently clears the isolated event collection", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const device = await f.enroll(); const event = await f.evaluate(device);
    const exported = await f.request("/api/v1/export");
    assert.equal(exported.status, 200); assert.equal(exported.data.version, 1);
    assert.ok(Array.isArray(exported.data.events)); assert.ok(Array.isArray(exported.data.machines));
    const row = exported.data.events.find((item) => item.id === event.eventId);
    assert.ok(row); assert.equal(typeof row.redacted, "string");
    assert.equal(Object.hasOwn(exported.data, "codec"), false);
    const originalFetch=globalThis.fetch;
    try {
      globalThis.fetch=async (url,init)=>{
        assert.equal(url,"/api/v1/export");
        const actual=await f.request(url,{method:init?.method??"GET"});
        return new Response(actual.text,{status:actual.status,headers:{"content-type":"application/json"}});
      };
      const consumed=JSON.parse(await exportApi());
      assert.equal(consumed.version,1);
      assert.ok(consumed.events.some((item)=>item.id===event.eventId));
    } finally {globalThis.fetch=originalFetch;}
    assert.equal((await f.request("/api/v1/events", { method: "DELETE", token: "" })).status, 401);
    assert.equal((await f.request("/api/v1/events", { method: "DELETE" })).status, 200);
    assert.deepEqual((await f.state()).events, []);
    await f.restart();
    assert.deepEqual((await f.state()).events, []);
  });

  it("the real viewer projects consumable state and denies writes even with admin credentials", { timeout: TEST_TIMEOUT }, async (t) => {
    const f = await harness(t);
    const initial = await f.state();
    const device = await f.enroll(); const event = await f.evaluate(device);
    const viewer = await f.viewer();
    const response = await viewerRequest(viewer.port, "/api/v1/state");
    assert.equal(response.status, 200);
    const state = parseApiState(response.data);
    assert.ok(state); assert.equal(state.access, "viewer");
    const mapped = mapEvent(state.events.find((row) => row.id === event.eventId));
    assert.ok(mapped); assert.equal(mapped.id, event.eventId);
    assert.ok(!JSON.stringify(response.data).includes(f.adminToken));
    for (const [path, method, body] of [
      ["/api/v1/policy", "PUT", { expectedVersion: initial.policyVersion, mode: "off" }],
      ["/api/v1/events", "DELETE", undefined],
      ["/api/v1/session", "POST", { token: f.adminToken }],
    ]) {
      const denied = await viewerRequest(viewer.port, path, method, f.adminToken, body);
      assert.equal(denied.status, 405); assert.equal(denied.data.error, "method_not_allowed");
    }
    const unchanged = await f.state();
    assert.equal(unchanged.policyVersion, initial.policyVersion);
    assert.ok(unchanged.events.some((row) => row.id === event.eventId));
  });
});
