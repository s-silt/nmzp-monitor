import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { REDACT_TAG, redactAll, scanCustom } from "./privacy.ts";

describe("privacy scan completeness", () => {
  it("does not stop custom scanning after 16 hits", () => {
    const rules = [
      {
        id: "p_emp",
        enabled: true,
        mode: "replace" as const,
        match: "EMP-\\d{4}",
        kind: "emp_id",
        replaceWith: REDACT_TAG,
      },
    ];
    const text = Array.from({ length: 20 }, (_, i) => `EMP-${String(i).padStart(4, "0")}`).join(" ");
    const hits = scanCustom(text, rules);
    assert.equal(hits.length, 20);
    const painted = redactAll(text, [], hits);
    assert.equal(painted.includes("EMP-"), false);
  });

  it("paints overlapping secret spans without dropping either match", () => {
    const text = "xxxxAAAAYYYY";
    const painted = redactAll(
      text,
      [
        { kind: "a", index: 2, length: 6 },
        { kind: "b", index: 4, length: 6 },
      ],
      [],
    );
    assert.equal(painted, `xx${REDACT_TAG}YY`);
    assert.equal(painted.includes("AAAA"), false);
  });
});
