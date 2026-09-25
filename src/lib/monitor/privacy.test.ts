import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { REDACT_TAG, redactAll, scanCustom, scanSecrets } from "./privacy.ts";

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

const ORDER_ID = "1234567890123456";
const SNOWFLAKE = "123456789012345678";
const NANOS = "1700000000123456789";
const CARD = "6222021234567890123";
const CN_ID = "110101199001011237";
const MOBILE = "13800001234";
const AWS = `AKIA${"A".repeat(16)}`;

describe("numeric context and JSON phone", () => {
  it("R1 opaque order id must not be bank-card PII", () => {
    const text = `curl https://api.example.com/orders/${ORDER_ID}`;
    const hits = scanSecrets(text).filter((h) => h.kind === "bank_card");
    assert.equal(hits.length, 0, "R1 opaque order id must not be bank-card PII");
  });

  it("R2 snowflake path id is not bank-card PII", () => {
    const text = `curl https://discord.example.invalid/api/channels/${SNOWFLAKE}/messages/${SNOWFLAKE}`;
    assert.equal(scanSecrets(text).some((h) => h.kind === "bank_card"), false);
    assert.equal(text.includes(SNOWFLAKE), true);
  });

  it("R4 explicit timestamp is not bank-card PII", () => {
    const text = `curl -d 'timestamp=${NANOS}' https://example.invalid/u`;
    const hits = scanSecrets(text).filter((h) => h.kind === "bank_card" || h.kind === "phone");
    assert.equal(hits.length, 0, "R4 explicit timestamp must not be bank-card PII");
  });

  it("R5 JSON phone field must be recognized", () => {
    const text = `{"phone":"${MOBILE}"}`;
    const hits = scanSecrets(text).filter((h) => h.kind === "phone");
    assert.equal(hits.length, 1, "R5 JSON phone field must be recognized");
    assert.equal(hits[0]?.index, text.indexOf(MOBILE));
    assert.equal(hits[0]?.length, MOBILE.length);
  });

  it("recognizes only the documented JSON phone keys and mainland mobile shape", () => {
    const keys = [
      "phone", "mobile", "tel", "telephone", "phoneNumber", "mobilePhone",
      "phone_number", "mobile_number", "mobile_phone", "tel_number",
      "手机", "手机号", "电话",
    ];
    for (const key of keys) {
      const text = `{"${key}":"${MOBILE}"}`;
      assert.equal(scanSecrets(text).some((h) => h.kind === "phone"), true, key);
    }
    assert.equal(scanSecrets(`{"phone":"+86 ${MOBILE}"}`).some((h) => h.kind === "phone"), true);
    assert.equal(scanSecrets(`{"phone":${MOBILE}}`).some((h) => h.kind === "phone"), true);
    for (const key of ["id", "orderId", "userId", "timestamp", "created_at", "snowflake", "microphone"]) {
      assert.equal(scanSecrets(`{"${key}":"${MOBILE}"}`).some((h) => h.kind === "phone"), false, key);
    }
    assert.equal(scanSecrets(`{"phone":"${CN_ID}"}`).some((h) => h.kind === "phone"), false);
    assert.equal(scanSecrets(`{"phone":"${NANOS}"}`).some((h) => h.kind === "phone"), false);
    assert.equal(scanSecrets(`{"id":"${NANOS}"}`).some((h) => h.kind === "bank_card"), false);
    assert.equal(scanSecrets(`{"timestamp":"${NANOS}"}`).some((h) => h.kind === "bank_card"), false);
  });

  it("keeps card bodies, explicit card keys, userinfo, credential query values, and cn_id paths", () => {
    assert.equal(scanSecrets(`card ${CARD} end`).some((h) => h.kind === "bank_card"), true);
    assert.equal(scanSecrets(`{"bank_card":"${CARD}"}`).some((h) => h.kind === "bank_card"), true);
    assert.equal(scanSecrets(`https://user:${CARD}@example.invalid/p`).some((h) => h.kind === "bank_card"), true);
    assert.equal(scanSecrets(`https://example.invalid/p?pan=${CARD}`).some((h) => h.kind === "bank_card"), true);
    assert.equal(scanSecrets(`https://example.invalid/p?password=${CARD}`).some((h) => h.kind === "bank_card"), true);
    assert.equal(scanSecrets(`https://example.invalid/${CN_ID}`).some((h) => h.kind === "cn_id"), true);
    assert.equal(scanSecrets(`key ${AWS}`).some((h) => h.kind === "aws_key"), true);
    assert.equal(scanSecrets(`id ${ORDER_ID} bare`).some((h) => h.kind === "bank_card"), true);
  });
});
