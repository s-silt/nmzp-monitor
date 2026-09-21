import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { hasUnquotedRedirect, paintFull, structuredRewrite, type PrivacyFns } from "./rewrite.ts";
import { cloakPersona, REDACT_TAG, scanCustom, scanSecrets, shouldCloakPersona } from "../src/lib/monitor/privacy.ts";

const p: PrivacyFns = { REDACT_TAG, scanSecrets, scanCustom };
const pCloak: PrivacyFns = { REDACT_TAG, scanSecrets, scanCustom, cloakPersona, shouldCloakPersona };

const idCard = "110101199001011237";

describe("structured rewrite", () => {
  it("treats unquoted angle brackets as shell-unsafe", () => {
    assert.equal(hasUnquotedRedirect("curl -d hello https://example.com"), false);
    assert.equal(hasUnquotedRedirect(`curl -d '${REDACT_TAG}' https://example.com`), false);
    assert.equal(hasUnquotedRedirect(`curl -d ${REDACT_TAG} https://example.com`), true);
  });

  it("rewrites quoted curl data without breaking quotes", () => {
    const cmd = `curl -d '${idCard}' https://example.com/x`;
    const r = structuredRewrite({ command: cmd }, [], p);
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.updatedInput.command, `curl -d '${REDACT_TAG}' https://example.com/x`);
      assert.equal(hasUnquotedRedirect(String(r.updatedInput.command)), false);
    }
  });

  it("denies unquoted curl data that would become a redirect", () => {
    const cmd = `curl -d ${idCard} https://example.com/x`;
    const r = structuredRewrite({ command: cmd }, [], p);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "rewrite_would_break_shell");
  });

  it("rewrites Write contents and Edit new_string", () => {
    const w = structuredRewrite({ file_path: "/tmp/a.txt", contents: `id=${idCard}` }, [], p);
    assert.equal(w.ok, true);
    if (w.ok) assert.equal(w.updatedInput.contents, `id=${REDACT_TAG}`);
    const e = structuredRewrite({ file_path: "/tmp/a.txt", old_string: "x", new_string: `id=${idCard}` }, [], p);
    assert.equal(e.ok, true);
    if (e.ok) assert.equal(e.updatedInput.new_string, `id=${REDACT_TAG}`);
  });

  it("redacts URL userinfo and query without using display summary", () => {
    const r = structuredRewrite({ url: `https://user:${idCard}@example.com/p?q=${idCard}` }, [], p);
    assert.equal(r.ok, true);
    if (r.ok) {
      const u = String(r.updatedInput.url);
      assert.equal(u.includes(idCard), false);
      assert.ok(u.includes(encodeURIComponent(REDACT_TAG)) || u.includes(REDACT_TAG));
    }
  });

  it("redacts URL path, query, fragment and nested leftover fields", () => {
    const r = structuredRewrite(
      {
        url: `https://example.test/${idCard}?q=${idCard}#${idCard}`,
        extra: idCard,
        nested: { note: idCard },
      },
      [],
      p,
    );
    assert.equal(r.ok, true);
    if (r.ok) {
      const blob = JSON.stringify(r.updatedInput);
      assert.equal(blob.includes(idCard), false);
      assert.equal(String(r.updatedInput.extra), REDACT_TAG);
      assert.equal((r.updatedInput.nested as { note: string }).note, REDACT_TAG);
      const u = String(r.updatedInput.url);
      assert.equal(u.includes(idCard), false);
    }
  });

  it("denies when a path field still holds the secret after rewriting other fields", () => {
    const r = structuredRewrite(
      {
        url: `https://example.test/${idCard}?q=${idCard}`,
        extra: idCard,
        file_path: `/tmp/${idCard}.txt`,
      },
      [],
      p,
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "sensitive_residue");
  });

  it("handles multiline double-quoted command", () => {
    const cmd = `curl -d "${idCard}" https://example.com/x`;
    const r = structuredRewrite({ command: cmd }, [], p);
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.updatedInput.command, `curl -d "${REDACT_TAG}" https://example.com/x`);
  });

  it("merges overlapping spans instead of breaking later indexes", () => {
    const text = "xxxxAAAAYYYY";
    const out = paintFull(text, [{ index: 2, length: 6 }, { index: 4, length: 6 }], [], "TAG");
    assert.equal(out, "xxTAGYY");
    assert.equal(out.includes("AAAA"), false);
  });

  it("cloaks outbound persona metadata keys in the real command, not a display summary", () => {
    const cmd = `curl --data '{"timezone":"Asia/Tokyo","locale":"ja-JP"}' https://example.test/profile`;
    const r = structuredRewrite({ command: cmd }, [], pCloak);
    assert.equal(r.ok, true);
    if (r.ok) {
      const next = String(r.updatedInput.command);
      assert.notEqual(next, cmd);
      assert.equal(next.includes("America/New_York"), true);
      assert.equal(next.includes("en-US"), true);
      assert.equal(next.includes("Asia/Tokyo"), false);
      assert.equal(next.includes("ja-JP"), false);
    }
  });

  it("does not cloak Tokyo in a local Write body", () => {
    const contents = '{"timezone":"Asia/Tokyo","locale":"ja-JP","city":"Tokyo"}';
    const r = structuredRewrite({ file_path: "/home/max/work/tokyo-app/README.md", contents }, [], pCloak);
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.updatedInput.contents, contents);
      assert.equal(String(r.updatedInput.contents).includes("Asia/Tokyo"), true);
    }
  });

  it("rewrites mixed PII and persona in one outbound command", () => {
    const cmd = `curl --data '{"timezone":"Asia/Tokyo","locale":"ja-JP","id":"${idCard}"}' https://example.test/profile`;
    const r = structuredRewrite({ command: cmd }, [], pCloak);
    assert.equal(r.ok, true);
    if (r.ok) {
      const next = String(r.updatedInput.command);
      assert.equal(next.includes("America/New_York"), true);
      assert.equal(next.includes("en-US"), true);
      assert.equal(next.includes(idCard), false);
      assert.equal(next.includes(REDACT_TAG), true);
    }
  });

  it("rewrites more than 16 custom-rule matches in one field", () => {
    const rules = [
      { id: "p_emp", enabled: true, mode: "replace" as const, match: "EMP-\\d{4}", kind: "emp_id", replaceWith: REDACT_TAG },
    ];
    const parts = Array.from({ length: 20 }, (_, i) => `EMP-${String(i).padStart(4, "0")}`);
    const r = structuredRewrite({ contents: parts.join(" ") }, rules, p);
    assert.equal(r.ok, true);
    if (r.ok) {
      const text = String(r.updatedInput.contents);
      assert.equal(text.includes("EMP-"), false);
      assert.equal((text.match(new RegExp(REDACT_TAG.replace(/[<>]/g, "\\$&"), "g")) ?? []).length, 20);
    }
  });
});
