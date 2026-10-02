import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EXEMPTION_MAX_TTL_MS,
  MAX_EXEMPTIONS,
  MAX_RULE_OVERRIDES,
  customRuleState,
  parseCustomRuleScope,
  MAX_CLIENT_MODES,
  parsePolicyClients,
  parsePolicyExemptions,
  parsePolicyOverrides,
  policyClients,
  policyExemptions,
  policyOverrides,
  selectClientMode,
} from "./policy-schema.ts";

describe("policy overrides shape", () => {
  it("defaults to empty and accepts partial objects", () => {
    assert.deepEqual(policyOverrides(undefined), { rules: {}, families: {} });
    assert.deepEqual(policyOverrides(null), { rules: {}, families: {} });
    assert.deepEqual(parsePolicyOverrides({}), { rules: {}, families: {} });
    assert.deepEqual(parsePolicyOverrides({ rules: { sudo_usage: "block" } }), {
      rules: { sudo_usage: "block" },
      families: {},
    });
    assert.deepEqual(
      parsePolicyOverrides({
        rules: { sudo_usage: "log", download_operation: "off" },
        families: { destructive: "block", recon: "log" },
      }),
      { rules: { sudo_usage: "log", download_operation: "off" }, families: { destructive: "block", recon: "log" } },
    );
  });

  it("rejects malformed shapes instead of guessing", () => {
    const bad: unknown[] = [
      [],
      "x",
      1,
      { rules: [] },
      { rules: { "Bad Id": "block" } },
      { rules: { "privacy:pii": "log" } },
      { rules: { sudo_usage: "allow" } },
      { rules: { sudo_usage: true } },
      { families: { destructive: "off" } },
      { families: { nope: "block" } },
      { families: [] },
      { rules: {}, families: {}, extra: 1 },
    ];
    for (const b of bad) assert.equal(parsePolicyOverrides(b), undefined, JSON.stringify(b));
    assert.equal(MAX_RULE_OVERRIDES, 128);
    const many = Object.fromEntries(Array.from({ length: MAX_RULE_OVERRIDES + 1 }, (_, i) => [`r_${i}`, "log"]));
    assert.equal(parsePolicyOverrides({ rules: many }), undefined);
    const exact = Object.fromEntries(Array.from({ length: MAX_RULE_OVERRIDES }, (_, i) => [`r_${i}`, "log"]));
    assert.ok(parsePolicyOverrides({ rules: exact }));
  });

  it("returns a copy, never the caller's object", () => {
    const raw = { rules: { sudo_usage: "block" as const }, families: {} };
    const parsed = parsePolicyOverrides(raw)!;
    parsed.rules.sudo_usage = "log";
    assert.equal(raw.rules.sudo_usage, "block");
    assert.notEqual(policyOverrides(undefined), policyOverrides(undefined));
  });
});

describe("policy exemptions shape", () => {
  const now = 1_790_000_000_000;
  const ok = {
    id: "x_npm",
    ruleId: "download_operation",
    match: "registry\\.npmjs\\.org",
    tools: ["Bash"],
    note: "npm registry",
    createdAt: now,
  };

  it("defaults to [] and keeps valid rows verbatim", () => {
    assert.deepEqual(policyExemptions(undefined), []);
    assert.deepEqual(policyExemptions(null), []);
    assert.deepEqual(parsePolicyExemptions([]), []);
    assert.deepEqual(parsePolicyExemptions([ok]), [ok]);
    const full = { ...ok, expiresAt: now + 1000, sourceEventId: "ev1" };
    assert.deepEqual(parsePolicyExemptions([full]), [full]);
    const minimal = { id: "x_1", ruleId: "p_abc", match: "四个字符", createdAt: 0 };
    assert.deepEqual(parsePolicyExemptions([minimal]), [minimal]);
    assert.equal(MAX_EXEMPTIONS, 32);
    assert.equal(EXEMPTION_MAX_TTL_MS, 365 * 24 * 60 * 60 * 1000);
  });

  it("rejects malformed rows — one bad row invalidates the list", () => {
    const bads: unknown[] = [
      { ...ok, id: "npm" },
      { ...ok, id: "x_" },
      { ...ok, id: "x_UPPER" },
      { ...ok, ruleId: "privacy:pii" },
      { ...ok, ruleId: "" },
      { ...ok, ruleId: "Bad" },
      { ...ok, match: "abc" },
      { ...ok, match: "a".repeat(81) },
      { ...ok, match: "abc\ndef" },
      { ...ok, match: 42 },
      { ...ok, tools: [] },
      { ...ok, tools: ["shell"] },
      { ...ok, tools: "Bash" },
      { ...ok, note: "n".repeat(121) },
      { ...ok, createdAt: -1 },
      { ...ok, createdAt: "1" },
      { ...ok, createdAt: 1.5 },
      { ...ok, expiresAt: now },
      { ...ok, expiresAt: now - 1 },
      { ...ok, expiresAt: now + EXEMPTION_MAX_TTL_MS + 1 },
      { ...ok, sourceEventId: 5 },
      { ...ok, sourceEventId: "e".repeat(65) },
      { ...ok, extra: true },
      "x",
      null,
    ];
    for (const b of bads) assert.equal(parsePolicyExemptions([b]), undefined, JSON.stringify(b));
    assert.equal(parsePolicyExemptions({}), undefined);
    assert.equal(parsePolicyExemptions("[]"), undefined);
    assert.equal(parsePolicyExemptions([ok, { ...ok }]), undefined, "duplicate id");
    assert.ok(parsePolicyExemptions([ok, { ...ok, expiresAt: now + EXEMPTION_MAX_TTL_MS }]) === undefined, "duplicate id even with different fields");
    assert.ok(parsePolicyExemptions([ok, { ...ok, id: "x_other" }]));
    const tooMany = Array.from({ length: MAX_EXEMPTIONS + 1 }, (_, i) => ({ ...ok, id: `x_${i}` }));
    assert.equal(parsePolicyExemptions(tooMany), undefined);
    assert.equal(parsePolicyExemptions(tooMany.slice(0, MAX_EXEMPTIONS))?.length, MAX_EXEMPTIONS);
  });

  it("does not filter by time — expiry is the engine's job", () => {
    const expired = { ...ok, createdAt: 10, expiresAt: 20 };
    assert.deepEqual(parsePolicyExemptions([expired]), [expired]);
  });

  it("returns copies", () => {
    const raw = [{ ...ok, tools: ["Bash"] }];
    const parsed = parsePolicyExemptions(raw)!;
    parsed[0]!.tools!.push("WebFetch");
    assert.deepEqual(raw[0]!.tools, ["Bash"]);
  });
});

describe("custom rule scope and state", () => {
  it("absent scope is fine; explicit scope must name known tools / fields", () => {
    assert.deepEqual(parseCustomRuleScope(undefined), { ok: true });
    assert.deepEqual(parseCustomRuleScope({}), { ok: true });
    assert.deepEqual(parseCustomRuleScope({ tools: ["Bash", "WebFetch"] }), { ok: true, scope: { tools: ["Bash", "WebFetch"] } });
    assert.deepEqual(parseCustomRuleScope({ fields: ["url", "command"] }), { ok: true, scope: { fields: ["url", "command"] } });
    assert.deepEqual(parseCustomRuleScope({ tools: ["Bash", "Bash"], fields: ["url"] }), {
      ok: true,
      scope: { tools: ["Bash"], fields: ["url"] },
    });
    const bad: unknown[] = [
      null,
      "Bash",
      [],
      { tools: [] },
      { fields: [] },
      { tools: ["shell"] },
      { tools: ["bash"] },
      { fields: ["tool_name"] },
      { fields: ["dest"] },
      { tools: "Bash" },
      { agents: ["zcode"] },
      { tools: ["Bash"], extra: 1 },
    ];
    for (const b of bad) assert.deepEqual(parseCustomRuleScope(b), { ok: false }, JSON.stringify(b));
  });

  it("dry-run implies not-enabled for old readers", () => {
    assert.equal(customRuleState({ enabled: true }), "on");
    assert.equal(customRuleState({}), "on");
    assert.equal(customRuleState({ enabled: false }), "off");
    assert.equal(customRuleState({ enabled: false, dryRun: true }), "dry_run");
    assert.equal(customRuleState({ enabled: true, dryRun: true }), "dry_run");
    assert.equal(customRuleState({ enabled: true, dryRun: "yes" }), "on");
    assert.equal(customRuleState({ enabled: false, dryRun: false }), "off");
  });
});

describe("policy clients shape", () => {
  const row = { deviceId: "a", agent: "grok", mode: "log_only" as const };

  it("defaults to [] and keeps a canonical copy", () => {
    assert.deepEqual(policyClients(undefined), []);
    assert.deepEqual(policyClients(null), []);
    assert.notEqual(policyClients(undefined), policyClients(undefined));
    const parsed = parsePolicyClients([{ mode: "log_only", agent: "grok", deviceId: "a" }]);
    assert.deepEqual(parsed, [row]);
    assert.deepEqual(Object.keys(parsed![0]!), ["deviceId", "agent", "mode"]);
    parsed![0]!.deviceId = "mutated";
    assert.equal(parsePolicyClients([row])![0]!.deviceId, "a");
    const wide = parsePolicyClients([{ deviceId: "b", mode: "log_only" }]);
    assert.deepEqual(wide, [{ deviceId: "b", mode: "log_only" }]);
    assert.deepEqual(Object.keys(wide![0]!), ["deviceId", "mode"]);
  });

  it("accepts 256 rows and both device-wide and agent-specific keys", () => {
    const exact = Array.from({ length: MAX_CLIENT_MODES }, (_, i) => ({ deviceId: `d${i}`, mode: "log_only" as const }));
    assert.equal(parsePolicyClients(exact)?.length, MAX_CLIENT_MODES);
    assert.equal(parsePolicyClients([...exact, { deviceId: "overflow", mode: "log_only" }]), undefined);
    const both = parsePolicyClients([
      { deviceId: "a", mode: "log_only" },
      { deviceId: "a", agent: "grok", mode: "log_only" },
    ]);
    assert.deepEqual(both, [
      { deviceId: "a", mode: "log_only" },
      { deviceId: "a", agent: "grok", mode: "log_only" },
    ]);
    assert.equal("a".repeat(128).length, 128);
    assert.ok(parsePolicyClients([{ deviceId: "a".repeat(128), agent: "b".repeat(128), mode: "log_only" }]));
  });

  it("rejects duplicates, bad modes, and bad labels", () => {
    const bad: unknown[] = [
      {},
      null,
      "a",
      { deviceId: "a", mode: "log_only", extra: 1 },
      [{ deviceId: "a", mode: "follow" }],
      [{ deviceId: "a", mode: "LOG_ONLY" }],
      [{ deviceId: "a" }],
      [{ mode: "log_only" }],
      [{ deviceId: "", mode: "log_only" }],
      [{ deviceId: " a", mode: "log_only" }],
      [{ deviceId: "a ", mode: "log_only" }],
      [{ deviceId: "a b", mode: "log_only" }],
      [{ deviceId: "a\nb", mode: "log_only" }],
      [{ deviceId: "a\u007fb", mode: "log_only" }],
      [{ deviceId: "a".repeat(129), mode: "log_only" }],
      [{ deviceId: "a", agent: "", mode: "log_only" }],
      [{ deviceId: "a", agent: null, mode: "log_only" }],
      [{ deviceId: "a", agent: "grok", mode: "log_only" }, { deviceId: "a", agent: "grok", mode: "log_only" }],
      [{ deviceId: "a", mode: "log_only" }, { deviceId: "a", mode: "log_only" }],
      [null],
    ];
    for (const value of bad) assert.equal(parsePolicyClients(value), undefined, JSON.stringify(value));
  });

  it("prefers an exact deviceId+agent row over a device-wide row", () => {
    const clients = [
      { deviceId: "a", mode: "log_only" as const },
      { deviceId: "a", agent: "grok", mode: "log_only" as const },
    ];
    assert.deepEqual(selectClientMode(clients, "a", "grok"), { deviceId: "a", agent: "grok", mode: "log_only" });
    assert.deepEqual(selectClientMode(clients, "a", "claude"), { deviceId: "a", mode: "log_only" });
    assert.equal(selectClientMode([{ deviceId: "a", agent: "grok", mode: "log_only" }], "a", "claude"), undefined);
    assert.equal(selectClientMode(clients, "b", "grok"), undefined);
    assert.equal(selectClientMode(undefined, "a", "grok"), undefined);
  });
});
