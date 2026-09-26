import assert from "node:assert/strict";
import { it, type TestContext } from "node:test";
import { putPolicy, restorePolicyRevision } from "./api.ts";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

it("putPolicy reports an unknown outcome on a 502 proxy failure", async (t: TestContext) => {
  const original = globalThis.fetch;
  let calls = 0;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async () => {
    calls += 1;
    return jsonResponse(502, { ok: false, error: "ct_unreachable" });
  }) as typeof fetch;

  const result = await putPolicy({ expectedVersion: 1, mode: "off" });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.outcome, "unknown");
  assert.equal(calls, 1);
});

it("putPolicy reports an unknown outcome when the transport fails after sending", async (t: TestContext) => {
  const original = globalThis.fetch;
  let calls = 0;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async () => {
    calls += 1;
    throw new TypeError("synthetic response lost after server write");
  }) as typeof fetch;

  let result: Awaited<ReturnType<typeof putPolicy>> | undefined;
  await assert.doesNotReject(async () => {
    result = await putPolicy({ expectedVersion: 1, stopped: true });
  });
  assert.ok(result);
  assert.equal(result.ok, false);
  if (!result || result.ok) return;
  assert.equal(result.outcome, "unknown");
  assert.equal(calls, 1);
});

it("putPolicy keeps 409 as a conflict and 400 as a rejection", async (t: TestContext) => {
  const original = globalThis.fetch;
  let calls = 0;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async () => {
    calls += 1;
    if (calls === 1) return jsonResponse(409, { ok: false, error: "cas_conflict", version: 8 });
    return jsonResponse(400, { error: "protected_rule_override" });
  }) as typeof fetch;

  const conflict = await putPolicy({ expectedVersion: 7, mode: "off" });
  const rejected = await putPolicy({ expectedVersion: 7, mode: "off" });
  assert.equal(conflict.ok, false);
  assert.equal(rejected.ok, false);
  if (conflict.ok || rejected.ok) return;
  assert.equal(conflict.outcome, "conflict");
  assert.equal(rejected.outcome, "rejected");
  assert.equal(calls, 2);
});

it("restorePolicyRevision reports an unknown outcome on 502 and on transport loss", async (t: TestContext) => {
  const original = globalThis.fetch;
  let calls = 0;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async () => {
    calls += 1;
    return jsonResponse(502, { ok: false, error: "ct_unreachable" });
  }) as typeof fetch;

  const proxied = await restorePolicyRevision({ expectedVersion: 3, sourceVersion: 1 });
  assert.equal(proxied.ok, false);
  assert.equal(proxied.outcome, "unknown");
  assert.equal(calls, 1);

  calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    throw new TypeError("synthetic response lost after server write");
  }) as typeof fetch;
  let transported: Awaited<ReturnType<typeof restorePolicyRevision>> | undefined;
  await assert.doesNotReject(async () => {
    transported = await restorePolicyRevision({ expectedVersion: 3, sourceVersion: 1 });
  });
  assert.equal(transported?.ok, false);
  assert.equal(transported?.outcome, "unknown");
  assert.equal(calls, 1);
});
