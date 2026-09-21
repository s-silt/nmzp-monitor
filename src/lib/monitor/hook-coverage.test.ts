import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatDateTime, formatRelative } from "./format.ts";
import { hookCoverage } from "./stats.ts";

describe("relative time never goes negative when the device clock is ahead of the browser", () => {
  it("future timestamps fall back to the absolute time; small skew is 'just now'", () => {
    const now = Date.UTC(2026, 8, 20, 12, 0, 0);
    for (const locale of ["zh", "en"] as const) {
      assert.equal(formatRelative(now + 3_000, locale, now), locale === "zh" ? "刚刚" : "just now");
      const ahead = formatRelative(now + 90_000, locale, now);
      assert.equal(ahead, formatDateTime(now + 90_000, locale));
      assert.doesNotMatch(ahead, /-\d|前|ago/);
      assert.equal(formatRelative(now - 90_000, locale, now), locale === "zh" ? "1 分钟前" : "1m ago");
    }
  });
});

describe("hookCoverage: per-agent active/reporting counts plus a per-machine breakdown", () => {
  const a = {
    id: "dev_a",
    hostname: "studio",
    capabilities: {
      hook_grok: { supported: true, active: true, lastSuccess: 10 },
      hook_codex: { supported: true, active: false, error: "hook_untrusted" },
    },
  };
  const b = { id: "dev_b", hostname: "lab", capabilities: { hook_grok: { supported: true, active: false, error: "offline" } } };
  const c = { id: "dev_c", hostname: "air" }; // old probe: no capabilities reported at all
  const rows = (cov: { perMachine: Array<{ machineId: string; hostname: string; cap?: { active: boolean } }> }) =>
    cov.perMachine.map((m) => [m.machineId, m.hostname, m.cap ? m.cap.active : null]);

  it("fleet view counts active/reporting and lists every visible machine in input order", () => {
    const cov = hookCoverage([a, b, c], "all", ["grok", "codex", "kimi"]);
    assert.equal(cov.grok!.active, 1);
    assert.equal(cov.grok!.reporting, 2);
    assert.deepEqual(rows(cov.grok!), [
      ["dev_a", "studio", true],
      ["dev_b", "lab", false],
      ["dev_c", "air", null],
    ]);
    assert.equal(cov.grok!.perMachine[0]!.cap?.lastSuccess, 10);
    assert.equal(cov.codex!.active, 0);
    assert.equal(cov.codex!.reporting, 1);
    assert.equal(cov.kimi!.active, 0);
    assert.equal(cov.kimi!.reporting, 0);
    assert.deepEqual(rows(cov.kimi!), [
      ["dev_a", "studio", null],
      ["dev_b", "lab", null],
      ["dev_c", "air", null],
    ]);
  });

  it("single-host view only sees that machine; an unknown host sees nothing", () => {
    const only = hookCoverage([a, b, c], "dev_b", ["grok"]);
    assert.equal(only.grok!.active, 0);
    assert.equal(only.grok!.reporting, 1);
    assert.deepEqual(rows(only.grok!), [["dev_b", "lab", false]]);
    const none = hookCoverage([a, b, c], "dev_zzz", ["grok"]);
    assert.deepEqual(none.grok, { active: 0, reporting: 0, perMachine: [] });
  });

  it("supported=false counts as reporting but never as active; requested agents always have an entry", () => {
    const d = { id: "dev_d", hostname: "old", capabilities: { hook_grok: { supported: false, active: false, error: "not_implemented" } } };
    const cov = hookCoverage([d], "all", ["grok", "cursor"]);
    assert.equal(cov.grok!.reporting, 1);
    assert.equal(cov.grok!.active, 0);
    assert.deepEqual(Object.keys(cov).sort(), ["cursor", "grok"]);
    assert.deepEqual(cov.cursor, { active: 0, reporting: 0, perMachine: [{ machineId: "dev_d", hostname: "old", cap: undefined }] });
  });
});
