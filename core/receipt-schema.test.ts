import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLegacyReceiptBody, parseReceiptBody, receiptEvaluationChanges } from "./receipt-schema.ts";

// Literal predicate from serve.ts at 173ecd3, independent of the extracted implementation.
function oracle(raw: unknown, evaluation: unknown) {
  const parsed = raw as { eventId?: unknown; evaluation?: unknown; enforcement?: unknown };
  const values = new Set(["blocked", "returned_deny", "pending_verify", "timeout", "failed", "delivered", "offline", "degraded"]);
  if (!parsed.eventId || !parsed.enforcement || !values.has(parsed.enforcement as string)) return "bad_receipt";
  if (parsed.evaluation && parsed.evaluation !== evaluation) return "evaluation_immutable";
  return { eventId: parsed.eventId, enforcement: parsed.enforcement };
}
function outcome(fn: () => unknown) {
  try { return { result: fn() }; } catch (error) { return { error: (error as Error).name }; }
}

test("receipt extraction preserves legacy JSON truthiness, malformed and immutable outcomes", () => {
  const inputs: unknown[] = [null, false, true, 0, 42, "", "text", [], {}, { eventId: "id" }];
  for (const eventId of [null, false, 0, 1, "", " ", "id", [], {}]) {
    for (const evaluation of [undefined, null, false, true, 0, 1, "", "allow", "block", [], {}]) {
      for (const enforcement of [undefined, "", "bogus", "blocked", "returned_deny", "pending_verify", "timeout", "failed", "delivered", "offline", "degraded"]) {
        inputs.push({ eventId, evaluation, enforcement, ignored: "not retained" });
      }
    }
  }
  for (const raw of inputs) {
    for (const current of ["allow", "block", undefined]) {
      assert.deepEqual(outcome(() => {
        const parsed = parseLegacyReceiptBody(raw);
        if (!parsed) return "bad_receipt";
        if (receiptEvaluationChanges(parsed, current)) return "evaluation_immutable";
        return { eventId: parsed.eventId, enforcement: parsed.enforcement };
      }), outcome(() => oracle(raw, current)));
    }
  }
});

test("candidate receipt rejects nonobjects/non-string id without imposing new evaluation rules", () => {
  for (const raw of [null, [], 1, true, "id", { eventId: 1, enforcement: "delivered" }]) assert.equal(parseReceiptBody(raw), null);
  const result = parseReceiptBody({ eventId: " ", enforcement: "delivered", evaluation: false, privateUnknown: "do not retain" });
  assert.deepEqual(result, { eventId: " ", enforcement: "delivered", evaluation: false });
  assert.equal(receiptEvaluationChanges(result!, "allow"), false);
});
