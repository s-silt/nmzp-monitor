import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import {
  clearEventsApi,
  exportApi,
  fetchState,
  getAdminToken,
  login,
  parseAccess,
  parseApiState,
  putPolicy,
  setAdminToken,
} from "../../src/lib/monitor/api.ts";
import { mapEvent } from "../../src/lib/monitor/map-event.ts";

// Consumer characterization tests: use the real v1 client, but synthetic HTTP
// responses and Storage. These are NOT tests of server authorization or writes.
const TOKEN_KEY = "nmzp-admin-token";
const TEST_TOKEN = "synthetic-test-token-not-a-credential";
const TS = 1_800_000_000_000;

function stateFixture(overrides = {}) {
  return {
    serverTime: TS,
    policyVersion: 7,
    mode: "enforcing",
    stopped: false,
    customRules: [],
    devices: [],
    events: [],
    capabilities: {},
    access: "admin",
    ...overrides,
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

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

function captureFetch(t, respond) {
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    writable: true,
    value: t.mock.fn(async (input, init) => {
      const call = { url: String(input), init: init ?? {} };
      calls.push(call);
      return respond(call, calls.length);
    }),
  });
  return calls;
}

function assertRequest(call, path, method, token = TEST_TOKEN) {
  assert.equal(call.url, path);
  assert.equal(call.init.method ?? "GET", method);
  assert.equal(call.init.credentials, "include");
  const headers = new Headers(call.init.headers);
  assert.equal(headers.get("authorization"), token ? `Bearer ${token}` : null);
  assert.ok(!call.url.includes(TEST_TOKEN), "credentials must not enter the URL");
  return headers;
}

function without(object, ...keys) {
  const copy = { ...object };
  for (const key of keys) delete copy[key];
  return copy;
}

describe("v1 state consumer compatibility", () => {
  it("accepts the legacy required fields and supplies existing optional defaults", () => {
    const raw = {
      policyVersion: 7,
      mode: "enforcing",
      stopped: false,
      devices: [],
      events: [],
    };
    const parsed = parseApiState(raw);
    assert.ok(parsed);
    assert.equal(parsed.policyVersion, 7);
    assert.equal(parsed.serverTime, 0);
    assert.deepEqual(parsed.customRules, []);
    assert.deepEqual(parsed.networkHistory, []);
    assert.deepEqual(parsed.capabilities, {});
    // Historical AUTHENTICATED replies omitted access. Not an auth mechanism.
    assert.equal(parsed.access, "admin");
    assert.deepEqual(parsed.archiveUpload, { thresholdMiB: 200, action: "warn" });
    assert.equal(parsed.githubUpload.mode, "selected");
  });

  it("preserves all three policy modes without renaming their wire values", () => {
    for (const mode of ["enforcing", "permissive", "off"]) {
      const parsed = parseApiState(stateFixture({ mode, stopped: mode === "off" }));
      assert.ok(parsed);
      assert.equal(parsed.mode, mode);
      assert.equal(parsed.stopped, mode === "off");
    }
  });

  it("rejects invalid roots and storage envelopes instead of treating them as state", () => {
    for (const raw of [null, [], 42, "{}", true, { codec: "gzip", data: "fixture" }]) {
      assert.equal(parseApiState(raw), null);
    }
  });

  it("rejects removed or type-changed required fields", () => {
    for (const key of ["policyVersion", "mode", "stopped", "devices", "events"]) {
      assert.equal(parseApiState(without(stateFixture(), key)), null, key);
    }
    const cases = [
      { policyVersion: "7" }, { policyVersion: NaN }, { policyVersion: Infinity },
      { mode: "observe" }, { stopped: "false" }, { devices: {} },
      { events: { rows: [] } }, { events: "[]" }, { customRules: null },
    ];
    for (const patch of cases) assert.equal(parseApiState(stateFixture(patch)), null);
  });

  it("preserves device, event, network, and policy context without reordering", () => {
    const events = [
      { id: "fixture-b", ts: TS, redacted: "synthetic second row" },
      { id: "fixture-a", ts: TS - 1, redacted: "synthetic first row" },
    ];
    const raw = stateFixture({
      access: "viewer",
      devices: [{ id: "fixture-device", hostname: "synthetic-host" }],
      events,
      evidenceWindow: {
        limit: 2000, retained: 2, historyCompleteness: "unknown",
        receiptDelivery: "best_effort", oldestTs: TS - 1, newestTs: TS,
      },
      networkHistory: [{ id: "fixture-net" }],
      eventEndpoints: { "fixture-a": [] },
      deviceNetwork: { "fixture-device": { status: "not_sampled" } },
      overrides: { rules: { sample_rule: "log" }, families: {} },
      exemptions: [],
      githubUpload: { mode: "selected", agents: ["codex"] },
      archiveUpload: { thresholdMiB: 256, action: "warn" },
    });
    const before = structuredClone(raw);
    const parsed = parseApiState(raw);
    assert.ok(parsed);
    for (const key of [
      "devices", "events", "evidenceWindow", "networkHistory", "eventEndpoints",
      "deviceNetwork", "overrides", "exemptions", "githubUpload", "archiveUpload",
    ]) assert.deepEqual(parsed[key], raw[key], key);
    assert.equal(parsed.access, "viewer");
    assert.deepEqual(raw, before, "parser must not mutate its input");
    // parseApiState keeps event rows opaque. The store maps each row with mapEvent
    // and drops nulls, so a row that only has id/ts/redacted is not a usable event.
  });

  it("maps a complete synthetic audit row and drops rows the current contract rejects", () => {
    const complete = {
      id: "fixture-event",
      ts: TS,
      machineId: "fixture-device",
      agent: "codex",
      sessionId: "fixture-session",
      layer: "app_pre",
      tool: "Read",
      nativeTool: "Read",
      risk: "info",
      decision: "log",
      category: "file_read",
      redacted: "synthetic redacted row",
      policyVersion: 7,
    };
    const mapped = mapEvent(complete);
    assert.ok(mapped);
    assert.equal(mapped.id, complete.id);
    assert.equal(mapped.agent, "codex");
    assert.equal(mapped.tool, "Read");
    assert.equal(mapped.decision, "log");
    assert.equal(mapped.category, "file_read");
    assert.equal(mapped.policyVersion, 7);
    assert.equal(mapped.redacted, complete.redacted);

    const state = parseApiState(stateFixture({ events: [complete, { id: "fixture-partial", ts: TS, redacted: "not an event" }] }));
    assert.ok(state);
    const kept = state.events.map((row) => mapEvent(row)).filter((row) => row);
    assert.equal(kept.length, 1);
    assert.equal(kept[0].id, "fixture-event");
    for (const row of [null, [], { id: "fixture-partial" }, { ...complete, agent: "not-a-host" }, { ...complete, decision: "observe" }]) {
      assert.equal(mapEvent(row), null);
    }
  });

  it("does not infer historical completeness from absent evidence metadata", () => {
    const parsed = parseApiState(stateFixture());
    assert.ok(parsed);
    assert.equal(parsed.evidenceWindow, undefined);
  });

  it("keeps existing normalization for malformed optional containers", () => {
    const parsed = parseApiState(stateFixture({
      networkHistory: {}, eventEndpoints: [], deviceNetwork: [],
      capabilities: [], exemptions: {},
    }));
    assert.ok(parsed);
    assert.deepEqual(parsed.networkHistory, []);
    assert.deepEqual(parsed.capabilities, {});
    assert.equal(parsed.eventEndpoints, undefined);
    assert.equal(parsed.deviceNetwork, undefined);
    assert.equal(parsed.exemptions, undefined);
  });

  it("tolerates additive top-level metadata without consuming it as existing data", () => {
    const raw = stateFixture({ optionalFutureMetadata: { fixture: true } });
    assert.deepEqual(parseApiState(raw), parseApiState(stateFixture()));
  });

  it("does not upgrade explicit viewer or unknown nonempty roles to admin", () => {
    assert.equal(parseAccess("admin"), "admin");
    for (const role of ["viewer", "operator", "ADMIN", 1, {}, []]) {
      assert.equal(parseAccess(role), "viewer");
      assert.equal(parseApiState(stateFixture({ access: role })).access, "viewer");
    }
  });
});

describe("v1 client request/response compatibility", { concurrency: false }, () => {
  beforeEach((t) => {
    replaceGlobal(t, "sessionStorage", new MemoryStorage());
    replaceGlobal(t, "localStorage", new MemoryStorage());
    setAdminToken(TEST_TOKEN);
    // All requests must be handled by an explicit per-test fake. No live traffic.
    replaceGlobal(t, "fetch", async () => {
      throw new Error("Unexpected fetch: this test must not access a live server");
    });
  });

  it("GET state retains relative path, cookies, bearer, and JSON response shape", async (t) => {
    const raw = stateFixture();
    const calls = captureFetch(t, () => jsonResponse(raw));
    const result = await fetchState();
    assert.equal(calls.length, 1);
    assertRequest(calls[0], "/api/v1/state", "GET");
    assert.equal(calls[0].init.body, undefined);
    assert.deepEqual(result, { ok: true, state: parseApiState(raw) });
  });

  it("read-only state needs no bearer when no token is present", async (t) => {
    setAdminToken("");
    const calls = captureFetch(t, () => jsonResponse(stateFixture({ access: "viewer" })));
    const result = await fetchState();
    assert.equal(result.ok, true);
    assert.equal(result.state.access, "viewer");
    assertRequest(calls[0], "/api/v1/state", "GET", "");
  });

  it("state preserves 401 and 403 as errors even with a valid-looking body", async (t) => {
    const statuses = [401, 403];
    const calls = captureFetch(t, (_call, number) => jsonResponse(stateFixture(), statuses[number - 1]));
    for (const status of statuses) assert.deepEqual(await fetchState(), { ok: false, status });
    assert.equal(calls.length, 2);
  });

  it("state does not accept malformed JSON or a nested data wrapper", async (t) => {
    const replies = [
      new Response("{", { status: 200 }),
      jsonResponse({ data: stateFixture() }),
    ];
    captureFetch(t, (_call, number) => replies[number - 1]);
    for (let i = 0; i < replies.length; i++) assert.equal((await fetchState()).ok, false);
  });

  it("state propagates transport failure rather than synthesizing success", async (t) => {
    const failure = new Error("synthetic transport failure");
    const calls = captureFetch(t, () => { throw failure; });
    await assert.rejects(fetchState(), (error) => error === failure);
    assert.equal(calls.length, 1);
  });

  it("PUT policy sends the current fields and reads the committed version", async (t) => {
    const patch = {
      expectedVersion: 7, mode: "enforcing", stopped: false, customRules: [],
      overrides: { rules: { sample_rule: "block" }, families: {} },
      exemptions: [], githubUpload: { mode: "selected", agents: ["codex"] },
      archiveUpload: { thresholdMiB: 256, action: "warn" },
    };
    const reply = {
      ok: true, version: 8, mode: "enforcing", stopped: false, customRules: [],
      overrides: patch.overrides, exemptions: [],
    };
    const calls = captureFetch(t, () => jsonResponse(reply));
    assert.deepEqual(await putPolicy(patch), reply);
    assert.equal(calls.length, 1);
    const headers = assertRequest(calls[0], "/api/v1/policy", "PUT");
    assert.equal(headers.get("content-type"), "application/json");
    assert.deepEqual(JSON.parse(calls[0].init.body), patch);
  });

  it("a partial policy edit does not invent other required request fields", async (t) => {
    const patch = { expectedVersion: 7, stopped: true };
    const calls = captureFetch(t, () => jsonResponse({
      ok: true, version: 8, mode: "off", stopped: true, customRules: [],
    }));
    const result = await putPolicy(patch);
    assert.equal(result.ok, true);
    assert.equal(result.version, 8);
    assert.deepEqual(JSON.parse(calls[0].init.body), patch);
  });

  it("policy CAS conflict remains 409 and is not retried automatically", async (t) => {
    const calls = captureFetch(t, () => jsonResponse({
      ok: false, error: "cas_conflict", version: 8,
    }, 409));
    assert.deepEqual(await putPolicy({ expectedVersion: 7, mode: "off" }), {
      ok: false, status: 409, error: "cas_conflict",
    });
    assert.equal(calls.length, 1, "a conflict must not overwrite a newer edit by retry");
  });

  it("policy surfaces protected-rule rejection codes to the caller", async (t) => {
    const errors = ["protected_rule_override", "protected_rule_exemption"];
    const calls = captureFetch(t, (_call, number) => jsonResponse({
      error: errors[number - 1],
    }, 400));
    for (const error of errors) {
      assert.deepEqual(await putPolicy({ expectedVersion: 7 }), {
        ok: false, status: 400, error,
      });
    }
    assert.equal(calls.length, 2);
    // This tests error propagation, NOT the server's protected-rule enforcement.
  });

  it("policy does not turn a non-JSON error body into a successful save", async (t) => {
    captureFetch(t, () => new Response("<html>unavailable</html>", { status: 500 }));
    assert.deepEqual(await putPolicy({ expectedVersion: 7, stopped: true }), {
      ok: false,
      status: 500,
      error: "bad_json",
    });
  });

  it("policy preserves authorization failure instead of mapping it to a save", async (t) => {
    const statuses = [401, 403];
    captureFetch(t, (_call, number) => jsonResponse({ error: "unauthorized" }, statuses[number - 1]));
    for (const status of statuses) {
      assert.deepEqual(await putPolicy({ expectedVersion: 7 }), {
        ok: false, status, error: "unauthorized",
      });
    }
  });

  it("login sends a JSON token in the body and stores it only on success", async (t) => {
    setAdminToken("");
    localStorage.setItem(TOKEN_KEY, "synthetic-legacy-token");
    const calls = captureFetch(t, () => jsonResponse({ ok: true }));
    assert.equal(await login(TEST_TOKEN), true);
    const headers = assertRequest(calls[0], "/api/v1/session", "POST", "");
    assert.equal(headers.get("content-type"), "application/json");
    assert.deepEqual(JSON.parse(calls[0].init.body), { token: TEST_TOKEN });
    assert.equal(getAdminToken(), TEST_TOKEN);
    assert.equal(localStorage.getItem(TOKEN_KEY), null);
  });

  it("failed login does not save the rejected token", async (t) => {
    setAdminToken("");
    captureFetch(t, () => jsonResponse({ error: "unauthorized" }, 401));
    assert.equal(await login(TEST_TOKEN), false);
    assert.equal(getAdminToken(), "");
    assert.equal(localStorage.getItem(TOKEN_KEY), null);
  });

  it("clearing the session token removes bearer authorization from later requests", async (t) => {
    assert.equal(getAdminToken(), TEST_TOKEN);
    setAdminToken("");
    assert.equal(getAdminToken(), "");
    const calls = captureFetch(t, () => jsonResponse(stateFixture({ access: "viewer" })));
    await fetchState();
    assertRequest(calls[0], "/api/v1/state", "GET", "");
  });

  it("token helpers remain safe when browser storage is unavailable", () => {
    // beforeEach registered the only restoration for this property.
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      value: undefined,
    });
    assert.equal(getAdminToken(), "");
    assert.doesNotThrow(() => setAdminToken(TEST_TOKEN));
    assert.equal(getAdminToken(), "");
  });

  it("DELETE events keeps the existing method and success result", async (t) => {
    const calls = captureFetch(t, () => jsonResponse({ ok: true }));
    assert.equal(await clearEventsApi(), true);
    assert.equal(calls.length, 1);
    assertRequest(calls[0], "/api/v1/events", "DELETE");
    assert.equal(calls[0].init.body, undefined);
  });

  it("DELETE events reports a rejected clear as false", async (t) => {
    const calls = captureFetch(t, () => jsonResponse({ error: "unauthorized" }, 403));
    assert.equal(await clearEventsApi(), false);
    assert.equal(calls.length, 1);
  });

  it("GET export still gives the caller a JSON string, not an encoded storage record", async (t) => {
    const bundle = {
      version: 1, exportedAt: TS,
      events: [{ id: "fixture-event", redacted: "synthetic audit 中文" }],
      machines: [], rules: [],
      policy: { version: 7, mode: "enforcing" },
    };
    const calls = captureFetch(t, () => jsonResponse(bundle));
    const result = await exportApi();
    assert.equal(typeof result, "string");
    assert.deepEqual(JSON.parse(result), bundle);
    assertRequest(calls[0], "/api/v1/export", "GET");
    assert.equal(calls.length, 1);
    // Native fetch's Content-Encoding decoding is not simulated here.
  });

  it("GET export rejects unsuccessful HTTP status even with valid JSON", async (t) => {
    captureFetch(t, () => jsonResponse({ version: 1, events: [] }, 403));
    await assert.rejects(exportApi(), /export_failed/);
  });
});
