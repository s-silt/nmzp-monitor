import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseReceiptBody } from "../../core/receipt-schema.ts";
import { parseBackfill } from "../../core/audit/backfill.ts";
import { parseHeartbeatBody } from "../../core/heartbeat-schema.ts";
import { parseUploadSize, permissionMode } from "../../core/egress-schema.ts";
import { requestFingerprint } from "../../core/eval-bridge.ts";
import { canonicalDeviceMatches, legacyCanonicalContext, serverAdapterContext } from "../../core/protocol/v2-context.ts";
import { v2AccessError } from "../../core/protocol/v2-error.ts";
import { toCanonicalToolEvent } from "../../core/protocol/v2-adapter.ts";
import { compileAll, createAjv, loadSchemas } from "./protocol-checks.mjs";

const schemas = loadSchemas();
const validators = compileAll(createAjv(schemas), schemas);
const receipt = validators["receipt-request.schema.json"];
const heartbeat = validators["heartbeat-request.schema.json"];
const backfill = validators["backfill-request.schema.json"];
const now = 1_790_000_000_000;

const openapi = readFileSync(new URL("../../contract/protocol/openapi.yaml", import.meta.url), "utf8");
const requestBodies = [["receipts", "receipt"], ["backfill", "backfill"], ["heartbeat", "heartbeat"]];

function assertOpenApiRequestContracts(raw) {
  // Git may check YAML out with CRLF on Windows; line endings are not a contract.
  const api = raw.replace(/\r\n?/g, "\n");
  assert.match(api, /\nsecurity:\n {2}- deviceBearer: \[\]/);
  assert.match(api, /deviceBearer:\n {6}type: http\n {6}scheme: bearer/);
  for (const [path, schema] of requestBodies) {
    const operation = api.split(`  /api/v2/${path}:`)[1].split(/\n {2}\/api\/v2\//)[0];
    assert.match(operation, new RegExp(`requestBody:[\\s\\S]*schemas/${schema}-request.schema.json`));
  }
}

for (const [label, newline] of [["LF", "\n"], ["CRLF", "\r\n"]]) {
  const lf = openapi.replace(/\r\n?/g, "\n");
  const encode = value => value.replace(/\n/g, newline);
  test(`candidate OpenAPI declares device bearer and all three request bodies (${label})`, () => {
    assertOpenApiRequestContracts(encode(lf));
  });

  test(`OpenAPI contract assertions reject missing bearer and request bodies (${label})`, () => {
    const mutations = [
      lf.replace("\nsecurity:\n  - deviceBearer: []", ""),
      lf.replace("      scheme: bearer", "      scheme: basic"),
      ...requestBodies.map(([, schema]) => lf.replace(`$ref: ./schemas/${schema}-request.schema.json`, "$ref: ./schemas/wrong-request.schema.json")),
      ...requestBodies.map(([path]) => lf.replace(
        new RegExp(`(  /api/v2/${path}:[\\s\\S]*?)      requestBody:[\\s\\S]*?(?=      responses:)`),
        "$1",
      )),
    ];
    for (const mutation of mutations) {
      assert.notEqual(mutation, lf, "negative fixture must remove or change a contract");
      assert.throws(() => assertOpenApiRequestContracts(encode(mutation)), { code: "ERR_ASSERTION" });
    }
  });
}

test("receipt schema and v2 parser preserve falsy evaluation and unknown-key ignore", () => {
  for (const evaluation of [null, false, 0, "", "allow", "unexpected", {}, []]) {
    const value = { eventId: "id", enforcement: "delivered", evaluation, unknown: "ignored" };
    assert.equal(receipt(value), true);
    assert.ok(parseReceiptBody(value));
    assert.equal(Object.hasOwn(parseReceiptBody(value), "unknown"), false);
  }
  for (const value of [null, [], {}, { eventId: 1, enforcement: "delivered" }, { eventId: "", enforcement: "delivered" }]) {
    assert.equal(receipt(value), false);
    assert.equal(parseReceiptBody(value), null);
  }
});

const event = () => ({ kind: "event", eventId: "event", payload: { eventId: "event", ts: 0, agent: "grok", tool: "Bash", decision: "log", risk: "info", policyVersion: 1 } });
test("backfill schema follows metadata-only branches; parser keeps cross-field/UTF-16 obligations", () => {
  const good = [event(), { kind: "receipt", eventId: "event", payload: { eventId: "event", evaluation: "allow", enforcement: "delivered" } }];
  for (const value of good) { assert.equal(backfill(value), true); assert.ok(parseBackfill(value)); }
  for (const edit of [v => { v.command = "secret"; }, v => { v.payload.input = "secret"; }, v => { v.payload.ts = -1; }, v => { v.payload.policyVersion = 0; }, v => { v.payload.agent = "bad\u007f"; }]) {
    const value = event(); edit(value); assert.equal(backfill(value), false); assert.equal(parseBackfill(value), null);
  }
  for (const edit of [v => { v.payload.eventId = "different"; }, v => { v.payload.relatedEventId = "event"; }, v => { v.payload.agent = "😀".repeat(33); }]) {
    const value = event(); edit(value); assert.equal(backfill(value), true); assert.equal(parseBackfill(value), null);
  }
});

test("heartbeat maintains fractional/negative policyVersion and auxiliary/unknown-key semantics", () => {
  for (const policyVersion of [-1, 0, 0.5, 1]) {
    const value = { policyVersion, unknown: { secret: "ignored" }, discovery: null, network: "malformed", agentProcs: 0, snapshotGuard: [] };
    assert.equal(heartbeat(value), true);
    assert.deepEqual(parseHeartbeatBody(value), { ok: true, fields: { policyVersion } });
  }
  for (const value of [null, [], { hostname: null }, { pollOnly: 1 }, { agents: Array(257).fill("a") }, { capabilities: [{ id: "x", active: true }] }]) {
    assert.equal(heartbeat(value), false); assert.equal(parseHeartbeatBody(value).ok, false);
  }
  const cap = { id: "hook_x", supported: true, active: false, ignored: "not retained" };
  const good = { hostname: "😀".repeat(128), capabilities: [cap] };
  assert.equal(heartbeat(good), true); assert.equal(parseHeartbeatBody(good).ok, true);
  assert.equal(Object.hasOwn(parseHeartbeatBody(good).fields.capabilities[0], "ignored"), false);
  const long = { hostname: "😀".repeat(129) };
  assert.equal(heartbeat(long), true); // Structural schema cannot stand in for the UTF-16 parser.
  assert.equal(parseHeartbeatBody(long).ok, false);
});

test("server contexts use observed identity/time/revision; client-declared epoch and revision zero remain valid", () => {
  const ctx = serverAdapterContext("device-one", "event", now);
  assert.equal(ctx.occurredAt, new Date(now).toISOString());
  assert.ok(ctx.adapterRevision > 0);
  assert.throws(() => serverAdapterContext("UNOBSERVED_DEVICE", "event", now));
  assert.throws(() => serverAdapterContext("device-one", "event", 0));
  const parsed = toCanonicalToolEvent('{"tool_name":"Bash","tool_input":{"command":"echo hi"}}', { ...ctx, occurredAt: "1970-01-01T00:00:00Z", adapterRevision: 0 });
  assert.equal(parsed.ok, true);
  assert.equal(validators["canonical-tool-event.schema.json"](parsed.event), true);
  assert.equal(canonicalDeviceMatches(parsed.event, "device-one"), true);
  assert.equal(canonicalDeviceMatches(parsed.event, "device-two"), false);
  assert.equal(parsed.event.host.adapterRevision, 0);
  for (const origin of ["HOOK", "PROBE", "BACKFILL"]) {
    for (const hookBlind of [true, false, undefined, "true", 1]) {
      const context = legacyCanonicalContext(origin, { hookBlind }, now);
      assert.equal(context.hookBlind, origin === "BACKFILL" || (origin === "PROBE" && hookBlind === true));
    }
  }
});

test("optional metadata uses existing parsers and never expands old request fingerprints", () => {
  for (const mode of ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions", "new", null, 1]) {
    const context = legacyCanonicalContext("HOOK", { permissionMode: mode }, now);
    assert.equal(context.permissionMode, permissionMode(mode));
  }
  for (const age of [-30001, -30000, 29999, 30000, 60000]) {
    const raw = { status: "observed", bytes: 100, checkedAt: now - age, source: "local_hook_stat", reason: "explicit_archive", ignored: "not retained" };
    const context = legacyCanonicalContext("HOOK", { uploadSize: raw }, now);
    assert.deepEqual(context.uploadSize, parseUploadSize(raw, now));
    if (context.uploadSize) assert.equal(validators["upload-size.schema.json"](context.uploadSize), true);
    assert.equal(requestFingerprint({ command: "echo ok", uploadSize: raw }), requestFingerprint({ command: "echo ok" }));
  }
  assert.equal(legacyCanonicalContext("HOOK", { uploadSize: { bad: true } }, now).uploadSize, undefined);
  assert.equal(requestFingerprint({ permissionMode: "unknown" }), requestFingerprint({}));
  assert.notEqual(requestFingerprint({ permissionMode: "auto" }), requestFingerprint({}));
});

test("ownership errors preserve status, no-data/rejected semantics and fixed safe messages", () => {
  for (const [code, status] of [["unauthorized", 401], ["forbidden", 403], ["not_found", 404]]) {
    const result = v2AccessError(code, "request-test");
    assert.equal(result.status, status);
    assert.equal(result.body.error.outcome, "rejected");
    assert.equal(result.body.error.retryable, false);
    assert.equal(Object.hasOwn(result.body.error, "data"), false);
    assert.equal(validators["error-envelope.schema.json"](result.body), true);
    assert.equal(result.body.error.message.includes("request-test"), false);
  }
});
