import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { policyRulesHash } from "./policy/nmzp-service.ts";

const source = { RULES: [{ id: "synthetic_rule", action: "log" }] };

describe("rewrite semantics binding", () => {
  it("policyRulesHash must differ from the legacy bare RULES hash", () => {
    const bound = policyRulesHash(source);
    const legacy = createHash("sha256").update(JSON.stringify(source.RULES), "utf8").digest("hex");
    assert.equal(bound === legacy, false, "policyRulesHash must differ from the legacy bare RULES hash");
  });

  it("policyRulesHash is deterministic and changes when RULES change", () => {
    const first = policyRulesHash(source);
    const again = policyRulesHash({ RULES: [{ id: "synthetic_rule", action: "log" }] });
    assert.equal(first, again);
    assert.match(first, /^[a-f0-9]{64}$/);
    const changed = policyRulesHash({ RULES: [{ id: "other_rule", action: "block" }] });
    assert.notEqual(changed, first);
    assert.match(changed, /^[a-f0-9]{64}$/);
  });
});
