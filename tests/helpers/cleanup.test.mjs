import assert from "node:assert/strict";
import { setImmediate } from "node:timers/promises";
import { test } from "node:test";
import { cleanupAfter } from "./cleanup.mjs";

test("cleanup awaits late and restarted resources before removing their directory", async t => {
  const calls = [];
  await t.test("owned fixture", t => {
    const cleanup = cleanupAfter(t);
    cleanup(() => calls.push("remove"));
    cleanup(async () => { calls.push("store:start"); await setImmediate(); calls.push("store:end"); });
    cleanup(async () => { calls.push("restart:start"); await setImmediate(); calls.push("restart:end"); });
    cleanup(() => calls.push("database"));
  });
  assert.deepEqual(calls, ["database", "restart:start", "restart:end", "store:start", "store:end", "remove"]);
});

test("cleanup attempts every resource and preserves close and removal errors", async () => {
  let after;
  const cleanup = cleanupAfter({ after(callback) { assert.equal(after, undefined); after = callback; } });
  const calls = [], closeError = new Error("close failed"), removeError = new Error("remove failed");
  cleanup(() => { calls.push("remove"); throw removeError; });
  cleanup(async () => { calls.push("store:start"); await setImmediate(); calls.push("store:end"); });
  cleanup(async () => { await setImmediate(); calls.push("database"); throw closeError; });
  await assert.rejects(after(), error => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [closeError, removeError]);
    return true;
  });
  assert.deepEqual(calls, ["database", "store:start", "store:end", "remove"]);
});
