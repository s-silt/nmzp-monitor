import assert from "node:assert/strict";
import { it } from "node:test";
import { parseBackfill } from "./backfill.ts";

it("rejects an envelope with extra top-level fields", () => {
  const payload = {
    eventId: "e",
    ts: 1,
    agent: "grok",
    tool: "Read",
    decision: "allow",
    risk: "info",
    policyVersion: 1,
  };
  assert.ok(parseBackfill({ kind: "event", eventId: "e", payload }));
  assert.equal(parseBackfill({ kind: "event", eventId: "e", payload, tool_input: { secret: "DO_NOT_SEND" } }), null);
});
