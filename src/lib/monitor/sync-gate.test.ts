import assert from "node:assert/strict";
import { it } from "node:test";
import { createSyncGate } from "./sync-gate.ts";

it("later request wins over an earlier slow response", () => {
  const gate = createSyncGate();
  const a = gate.begin();
  const b = gate.begin();
  assert.equal(gate.accept(b), true, "later request must be accepted");
  assert.equal(gate.accept(a), false, "earlier slow response must be discarded");
});

it("a response started before a mutation cannot overwrite the mutation state", () => {
  const gate = createSyncGate();
  const a = gate.begin();
  gate.noteMutation();
  assert.equal(gate.accept(a), false, "response started before a mutation must be discarded");
  const c = gate.begin();
  assert.equal(gate.accept(c), true, "reconcile read after the mutation must be accepted");
});
