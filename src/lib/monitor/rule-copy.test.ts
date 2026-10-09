import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { LOCKED_RULE_IDS, protectionLevel } from "./overrides.ts";
import { ruleCopy } from "./rule-copy.ts";
import { RULE_COPY_EN } from "./rule-copy.en.ts";
import { RULE_COPY_ZH } from "./rule-copy.zh.ts";
import { RULES } from "./rules.ts";

const BANNED = [/100%/, /彻底/, /completely/i, /guarantee/i];

function leafKeyPaths(value: unknown): string[] {
  const out: string[] = [];
  const walk = (node: unknown, path: string): void => {
    if (node !== null && typeof node === "object") {
      for (const key of Object.keys(node as Record<string, unknown>).sort()) {
        walk((node as Record<string, unknown>)[key], path ? `${path}.${key}` : key);
      }
      return;
    }
    out.push(path);
  };
  walk(value, "");
  return out;
}

function assertCopyStrings(value: unknown, path: string, summaryMax: number): void {
  if (typeof value === "string") {
    assert.equal(value.trim(), value, `${path} has surrounding whitespace`);
    assert.ok(value.length > 0, `${path} is empty`);
    for (const banned of BANNED) {
      assert.equal(banned.test(value), false, `${path} contains ${banned}`);
    }
    if (path.endsWith(".summary")) {
      assert.ok(
        Array.from(value).length <= summaryMax,
        `${path} length ${Array.from(value).length} > ${summaryMax}`,
      );
    }
    return;
  }
  assert.equal(typeof value, "object", path);
  assert.ok(value, path);
  for (const key of Object.keys(value as Record<string, unknown>)) {
    assertCopyStrings((value as Record<string, unknown>)[key], path ? `${path}.${key}` : key, summaryMax);
  }
}

describe("rule copy", () => {
  it("uses the same keys in Chinese and English", () => {
    assert.deepEqual(leafKeyPaths(RULE_COPY_ZH), leafKeyPaths(RULE_COPY_EN));
  });

  it("covers exactly the families that appear on RULES", () => {
    const seen = new Set<string>();
    for (const rule of RULES) {
      if (rule.family) seen.add(rule.family);
    }
    assert.deepEqual([...Object.keys(RULE_COPY_ZH.families)].sort(), [...seen].sort());
    assert.deepEqual([...Object.keys(RULE_COPY_EN.families)].sort(), [...seen].sort());
  });

  it("covers the 29 protected rules, and locked ids match LOCKED_RULE_IDS", () => {
    const byId = new Map(RULES.map((rule) => [rule.id, rule]));
    const protectedIds = RULES.filter((rule) => protectionLevel(rule) !== "none").map((rule) => rule.id);
    assert.equal(protectedIds.length, 29);
    assert.equal(new Set(protectedIds).size, 29);
    for (const copy of [RULE_COPY_ZH.rules, RULE_COPY_EN.rules]) {
      const ids = Object.keys(copy);
      assert.deepEqual(new Set(ids), new Set(protectedIds));
      const locked = ids.filter((id) => {
        const rule = byId.get(id);
        assert.ok(rule, id);
        return protectionLevel(rule) === "locked";
      });
      assert.deepEqual(new Set(locked), new Set(LOCKED_RULE_IDS));
    }
    assert.equal(LOCKED_RULE_IDS.length, 12);
  });

  it("keeps every string non-empty, unpadded, and free of overclaim wording", () => {
    assertCopyStrings(RULE_COPY_ZH, "zh", 40);
    assertCopyStrings(RULE_COPY_EN, "en", 120);
  });

  it("says locked rules still block in log-only client mode", () => {
    assert.match(RULE_COPY_ZH.clientMode.log_only.summary, /锁定/);
    assert.match(RULE_COPY_EN.clientMode.log_only.summary, /locked/);
  });

  it("selects English only for en, and Chinese for every other locale", () => {
    assert.equal(ruleCopy("en"), RULE_COPY_EN);
    assert.equal(ruleCopy("zh"), RULE_COPY_ZH);
    assert.equal(ruleCopy("xx"), RULE_COPY_ZH);
  });
});
