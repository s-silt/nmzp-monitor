import assert from "node:assert/strict";
import { it } from "node:test";
import { t } from "./i18n.ts";
import { mutationMessageKey, requestedFieldsMatch } from "./policy-mutation.ts";

it("requestedFieldsMatch is true for the same content with different key order", () => {
  assert.equal(
    requestedFieldsMatch(
      { stopped: false, mode: "enforcing", overrides: { rules: { a: "block" }, families: { x: "log" } } },
      { mode: "enforcing", overrides: { families: { x: "log" }, rules: { a: "block" } }, stopped: false },
    ),
    true,
  );
  assert.equal(
    requestedFieldsMatch(
      { expectedVersion: 2, exemptions: [{ id: "e1", match: "abcd" }] },
      { policyVersion: 9, exemptions: [{ match: "abcd", id: "e1" }] },
    ),
    true,
  );
});

it("requestedFieldsMatch is false when another writer changed an unrelated requested field", () => {
  assert.equal(
    requestedFieldsMatch(
      {
        mode: "off",
        exemptions: [{ id: "ex-1", ruleId: "r", match: "safe" }],
        overrides: { rules: { sample: "block" }, families: { secret: "log" } },
      },
      {
        overrides: { families: { secret: "log" }, rules: { sample: "block" } },
        exemptions: [{ match: "other", ruleId: "r", id: "ex-1" }],
        mode: "off",
      },
    ),
    false,
  );
  assert.equal(
    requestedFieldsMatch(
      { customRules: [{ id: "a" }, { id: "b" }] },
      { customRules: [{ id: "b" }, { id: "a" }] },
    ),
    false,
  );
});

it("requestedFieldsMatch is false when only the version increased", () => {
  assert.equal(requestedFieldsMatch({ expectedVersion: 4 }, { policyVersion: 5 }), false);
  assert.equal(
    requestedFieldsMatch(
      { expectedVersion: 4, mode: "enforcing" },
      { policyVersion: 5, mode: "enforcing" },
    ),
    true,
  );
});

it("mutationMessageKey maps conflict, rejected, unknown, and matching unknown", () => {
  assert.equal(mutationMessageKey({ kind: "conflict" }), "mutationConflict");
  assert.equal(mutationMessageKey({ kind: "rejected", error: "protected_rule_override" }), "mutationFailed");
  assert.equal(mutationMessageKey({ kind: "unknown", matchesRequest: false }), "mutationUnknown");
  assert.equal(mutationMessageKey({ kind: "unknown", matchesRequest: true }), "mutationUnknownMatches");
  assert.equal(mutationMessageKey({ kind: "ok" }), "mutationFailed");
  assert.equal(mutationMessageKey(null), "mutationFailed");
  assert.equal(t("zh", "mutationConflict"), "策略版本冲突（409）：未写入，已同步最新状态，请重新确认");
  assert.equal(t("en", "mutationConflict"), "Policy version conflict (409): not written; latest state synced, please review again");
  assert.equal(
    t("zh", "mutationUnknown"),
    "结果未知：未收到 CT 确认，写入可能已生效。已只读同步最新状态，请核对后再操作，不要直接重复提交",
  );
  assert.equal(
    t("en", "mutationUnknown"),
    "Outcome unknown: CT did not confirm; the write may have taken effect. Latest state was re-read; check it before acting and do not simply resubmit",
  );
  assert.equal(
    t("zh", "mutationUnknownMatches"),
    "结果未知：同步后当前策略已包含本次提交的内容（可能由本次或其他管理员写入）",
  );
  assert.equal(
    t("en", "mutationUnknownMatches"),
    "Outcome unknown: after re-reading, the current policy already contains the submitted change (written by this request or another admin)",
  );
  assert.equal(t("zh", "mutationFailed"), "未写入：CT 未确认");
});
