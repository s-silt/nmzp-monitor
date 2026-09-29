import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { parseHookEvent } from "../../core/hook-protocol.ts";
import { resolveGoldenStdin } from "../compat/golden-stdin.mjs";
import { ERROR_DISPOSITION, ifNoneMatchHits, policyETag, v2Error } from "../../core/protocol/v2-error.ts";
import { toCanonicalToolEvent } from "../../core/protocol/v2-adapter.ts";
import { compileAll, createAjv, loadJson, loadSchemas } from "./protocol-checks.mjs";

const HEX = "51003ce0c1fdf505f5c5384dc00be53f2e4c5e4a788a57b1919e48d807ad9a8b";
const HASH = `sha256:${HEX}`;
const ETAG_PATTERN = /^"p(0|[1-9][0-9]*)\.[0-9a-f]{64}\.e(0|[1-9][0-9]*)"$/;

const schemas = loadSchemas();
const validators = compileAll(createAjv(schemas), schemas);
const errorValidate = validators["error-envelope.schema.json"];
const eventValidate = validators["canonical-tool-event.schema.json"];
const envelopeEnum = loadJson(new URL("../../contract/protocol/schemas/error-envelope.schema.json", import.meta.url)).properties
  .error.properties.code.enum;

const CTX = {
  occurredAt: "1970-01-01T00:00:00Z",
  deviceId: "UNOBSERVED_DEVICE",
  adapterRevision: 0,
  eventId: "evt-wp21c",
};

function envelopeFor(code) {
  if (code === "policy_conflict") {
    return v2Error(code, {
      message: "policy changed",
      requestId: "req-policy",
      data: { currentVersion: 0, currentRulesHash: HASH },
    });
  }
  if (code === "cas_conflict") {
    return v2Error(code, { message: "version changed", requestId: "req-cas", data: { currentVersion: 3 } });
  }
  return v2Error(code, { message: "refused", requestId: "req-plain" });
}

describe("v2 error envelope", () => {
  test("every ErrorCode from v2Error matches the disposition table and the schema", () => {
    assert.deepEqual(Object.keys(ERROR_DISPOSITION), envelopeEnum);
    for (const code of envelopeEnum) {
      const body = envelopeFor(code);
      assert.equal(errorValidate(body), true, `${code}: ${JSON.stringify(errorValidate.errors)}`);
      assert.equal(body.error.code, code);
      assert.equal(body.error.retryable, ERROR_DISPOSITION[code].retryable);
      assert.equal(body.error.outcome, ERROR_DISPOSITION[code].outcome);
      if (code === "policy_conflict" || code === "cas_conflict") assert.ok(body.error.data);
      else assert.equal(Object.hasOwn(body.error, "data"), false);
    }
  });

  test("v2Error rejects data that the schema would reject", () => {
    assert.throws(() => v2Error("bad_json", { message: "m", requestId: "r", data: { currentVersion: 1 } }));
    assert.throws(() => v2Error("cas_conflict", { message: "m", requestId: "r", data: { currentVersion: 1, extra: true } }));
    assert.throws(() => v2Error("cas_conflict", { message: "m", requestId: "r" }));
    assert.throws(() => v2Error("policy_conflict", { message: "m", requestId: "r", data: { currentVersion: 1, currentRulesHash: HEX } }));
    assert.throws(() => v2Error("policy_conflict", { message: "", requestId: "r", data: { currentVersion: 1, currentRulesHash: HASH } }));
    assert.throws(() => v2Error("not_a_code", { message: "m", requestId: "r" }));
  });
});

describe("policy ETag", () => {
  const etag = policyETag({ version: 1, rulesHash: HASH, engineRevision: 2 });

  test("formats a strong quoted ETag and accepts both hash spellings", () => {
    assert.equal(policyETag({ version: 0, rulesHash: HEX, engineRevision: 0 }), `"p0.${HEX}.e0"`);
    assert.equal(etag, `"p1.${HEX}.e2"`);
    assert.equal(policyETag({ version: 10, rulesHash: HASH, engineRevision: 2 }), `"p10.${HEX}.e2"`);
    assert.equal(policyETag({ version: 1, rulesHash: HEX, engineRevision: 2 }), etag);
    assert.match(etag, ETAG_PATTERN);
    assert.equal(etag.includes("sha256:"), false);
  });

  test("rejects hashes and revisions outside the byte format", () => {
    const bad = [
      { version: 1, rulesHash: HEX.toUpperCase(), engineRevision: 2 },
      { version: 1, rulesHash: HEX.slice(0, 63), engineRevision: 2 },
      { version: 1, rulesHash: `sha256:${HEX.toUpperCase()}`, engineRevision: 2 },
      { version: 1, rulesHash: "", engineRevision: 2 },
      { version: 1, rulesHash: `sha256:${HEX}`, engineRevision: -1 },
      { version: -1, rulesHash: HEX, engineRevision: 2 },
      { version: 1.5, rulesHash: HEX, engineRevision: 2 },
      { version: 1, rulesHash: HEX, engineRevision: 1.5 },
      { version: "1", rulesHash: HEX, engineRevision: 2 },
    ];
    for (const input of bad) assert.throws(() => policyETag(input), JSON.stringify(input));
  });

  test("If-None-Match hits only byte-equal strong tags", () => {
    assert.equal(ifNoneMatchHits(etag, etag), true);
    assert.equal(ifNoneMatchHits(`${etag},${etag}`, etag), true);
    assert.equal(ifNoneMatchHits(`other,${etag}`, etag), true);
    assert.equal(ifNoneMatchHits(`*,${etag}`, etag), true);
    assert.equal(ifNoneMatchHits(`W/${etag},${etag}`, etag), true);
    assert.equal(ifNoneMatchHits(`${etag},`, etag), true);
    assert.equal(ifNoneMatchHits(`other, ${etag}`, etag), false);
    assert.equal(ifNoneMatchHits(` ${etag}`, etag), false);
    assert.equal(ifNoneMatchHits(`${etag} `, etag), false);
    assert.equal(ifNoneMatchHits(`W/${etag}`, etag), false);
    assert.equal(ifNoneMatchHits("*", etag), false);
    assert.equal(ifNoneMatchHits(`*, W/${etag}`, etag), false);
    assert.equal(ifNoneMatchHits("", etag), false);
    assert.equal(ifNoneMatchHits(null, etag), false);
    assert.equal(ifNoneMatchHits(undefined, etag), false);
    assert.equal(ifNoneMatchHits(etag, ""), false);
    assert.equal(ifNoneMatchHits(etag.slice(1), etag), false);
    assert.equal(ifNoneMatchHits(`${etag}x`, etag), false);
  });
});

describe("adapter hookBlind", () => {
  test("HOOK events from the golden stdin keep hookBlind false and match the schema", () => {
    const golden = JSON.parse(readFileSync(new URL("../compat/fixtures/hook-bytes-golden.json", import.meta.url), "utf8"));
    const failures = [];
    let checked = 0;
    let sample = null;
    for (const item of golden.cases) {
      const stdin = resolveGoldenStdin(item);
      if (item.kind === "bootstrap" || typeof stdin !== "string") continue;
      const parsed = parseHookEvent(stdin);
      const result = toCanonicalToolEvent(stdin, {
        ...CTX,
        agentFlag: item.host,
        eventId: parsed?.eventId || CTX.eventId,
      });
      if (!result.ok) continue;
      checked += 1;
      sample ??= result.event;
      if (result.event.origin !== "HOOK") failures.push(`${item.id} origin`);
      if (result.event.context?.hookBlind !== false) failures.push(`${item.id} hookBlind`);
      if (!eventValidate(result.event)) {
        const details = (eventValidate.errors ?? []).map((err) => `${err.instancePath} ${err.keyword}`).join(",");
        failures.push(`${item.id} schema ${details}`);
      }
    }
    assert.ok(checked > 0);
    assert.deepEqual(failures, []);

    const hooked = structuredClone(sample);
    hooked.context.hookBlind = true;
    assert.equal(eventValidate(hooked), false);
    hooked.origin = "PROBE";
    assert.equal(eventValidate(hooked), true);
    hooked.origin = "BACKFILL";
    assert.equal(eventValidate(hooked), true);
  });
});
