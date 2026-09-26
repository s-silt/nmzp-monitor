import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import type { AuditEvent } from "./types.ts";
import {
  anyDeviceHookFact,
  discoveryEvidenceLines,
  discoveryRowEvidence,
  fleetHookStatusText,
  hookCapabilityForDiscovery,
  t,
} from "./i18n.ts";
import { scopedCapabilities, statsFrom } from "./stats.ts";

const discoverySrc = readFileSync(new URL("../../components/agent-discovery.tsx", import.meta.url), "utf8");
const indexSrc = readFileSync(new URL("../../routes/index.tsx", import.meta.url), "utf8");
const threatsSrc = readFileSync(new URL("../../routes/threats.tsx", import.meta.url), "utf8");
const shellSrc = readFileSync(new URL("../../components/shell.tsx", import.meta.url), "utf8");

function ev(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: "e1",
    ts: 1_700_000_000_000,
    machineId: "dev_pc",
    agent: "grok",
    sessionId: "",
    layer: "app_pre",
    tool: "Bash",
    nativeTool: "Bash",
    input: "x",
    risk: "high",
    decision: "block",
    category: "other",
    workdirScope: "other",
    redacted: "x",
    ...over,
  };
}

describe("device-reported blocks and rewrite decisions", () => {
  it("counts device-reported blocked separately from decisions and does not call rewrite an applied count", () => {
    const rows = [
      ev({ id: "blocked", enforcement: "blocked", decision: "block" }),
      ev({ id: "deny", enforcement: "returned_deny", decision: "block" }),
      ev({ id: "rewrite-delivered", decision: "rewrite", rewritten: true, enforcement: "delivered" }),
      ev({ id: "rewrite-open", decision: "rewrite", enforcement: "returned_deny" }),
      ev({ id: "rewritten-flag", decision: "log", rewritten: true }),
      ev({ id: "plain", decision: "log" }),
    ];
    const stats = statsFrom(rows);
    assert.equal(stats.blocked, 1);
    assert.equal(stats.returnedDeny, 2);
    assert.equal(stats.rewrite, 3);
    assert.notEqual(stats.rewrite, rows.filter((e) => e.enforcement === "delivered").length);

    for (const locale of ["zh", "en"] as const) {
      const blocked = t(locale, "blocked");
      const heading = t(locale, "whyBlocked");
      const drill = t(locale, "drillBlocked");
      const rewrite = t(locale, "rewriteDecisions");
      if (locale === "zh") {
        assert.match(blocked, /设备上报/);
        assert.match(blocked, /未独立验证/);
        assert.match(heading, /设备上报/);
        assert.match(heading, /未独立验证/);
        assert.match(drill, /设备上报/);
        assert.match(drill, /未独立验证/);
        assert.match(rewrite, /判定/);
        assert.match(rewrite, /未证实/);
        assert.equal(rewrite.includes("已采纳"), false);
        assert.equal(rewrite.includes("已应用"), false);
      } else {
        assert.match(blocked, /Device-reported/);
        assert.match(blocked, /not independently verified/i);
        assert.match(heading, /Device-reported/);
        assert.match(heading, /not independently verified/i);
        assert.match(drill, /Device-reported/);
        assert.match(rewrite, /decisions/i);
        assert.match(rewrite, /not verified/i);
        assert.equal(/applied|adopted/i.test(rewrite), false);
      }
    }
    assert.equal(t("zh", "rewrite"), "替换");
    assert.equal(t("en", "rewrite"), "Rewrite");
  });

  it("source contract: threats and the home tile bind those labels without changing the counters", () => {
    assert.match(threatsSrc, /e\.enforcement === "blocked"/);
    assert.match(threatsSrc, /tx\("blocked"\)/);
    assert.match(threatsSrc, /tx\("whyBlocked"\)/);
    assert.match(threatsSrc, /statsFrom\(events\)/);
    assert.match(indexSrc, /label=\{tx\("rewriteDecisions"\)\}/);
    assert.match(indexSrc, /value=\{homeReadyValue\(dataReady, stats\.rewrite, pendingLabel\)\}/);
    assert.match(indexSrc, /tx\("drillBlocked"\)/);
  });
});

describe("enforcing terminology", () => {
  it("keeps the locked Chinese short label, uses Enforcing in English, and keeps no extra popup", () => {
    assert.equal(t("zh", "enforcing"), "静默");
    assert.equal(t("en", "enforcing"), "Enforcing");
    for (const locale of ["zh", "en"] as const) {
      const hint = t(locale, "enforcingHint");
      const summary = t(locale, "modeEnforcingSummary");
      const overrides = t(locale, "overrideOnlyEnforcing");
      const intercept = t(locale, "interceptBody");
      if (locale === "zh") {
        assert.match(hint, /执行模式/);
        assert.match(hint, /不弹窗/);
        assert.match(hint, /不是静默快照/);
        assert.equal(hint.includes("静默外传"), false);
        assert.match(summary, /不额外弹窗/);
        assert.match(overrides, /静默/);
        assert.match(overrides, /执行模式/);
        assert.match(overrides, /不额外弹窗/);
        assert.match(intercept, /不新增弹窗/);
      } else {
        assert.match(hint, /Enforcing/);
        assert.match(hint, /no extra popup/i);
        assert.match(summary, /Enforcing/);
        assert.match(summary, /no extra popup/i);
        assert.match(overrides, /Enforcing/);
        assert.match(overrides, /no extra popup/i);
        assert.match(intercept, /no extra prompt/i);
        assert.equal(hint.includes("Quiet"), false);
        assert.equal(overrides.includes("Quiet"), false);
      }
    }
    assert.match(shellSrc, /title=\{modeHint\}/);
    assert.match(shellSrc, /tx\("enforcingHint"\)/);
    assert.match(indexSrc, /tx\("modeEnforcingSummary"\)/);
  });
});

describe("fleet hook evidence", () => {
  it("spells any-device when mixed hosts OR to active, and does not treat a missing cap as inactive", () => {
    const machines = [
      { id: "dev_a", capabilities: { hook_grok: { supported: true, active: true } } },
      { id: "dev_b", capabilities: { hook_grok: { supported: true, active: false, error: "offline" } } },
    ];
    const collapsed = scopedCapabilities(machines, "all").hook_grok;
    assert.equal(collapsed?.active, true);
    assert.equal(scopedCapabilities(machines, "dev_b").hook_grok?.active, false);
    const perDevice = [machines[0]!.capabilities.hook_grok, machines[1]!.capabilities.hook_grok];
    const fact = anyDeviceHookFact(perDevice);
    assert.equal(fact.reported, 2);
    assert.equal(fact.active, 1);
    assert.equal(fact.mixed, true);
    assert.equal(fact.anyActive, true);
    const mixed = fleetHookStatusText("zh", "all", collapsed, perDevice);
    assert.match(mixed, /任一设备/);
    assert.match(mixed, /不是每台/);
    assert.match(mixed, /不证明宿主已执行/);
    assert.notEqual(mixed, t("zh", "hookCapActive"));
    const mixedEn = fleetHookStatusText("en", "all", collapsed, perDevice);
    assert.match(mixedEn, /Any one device/);
    assert.match(mixedEn, /not every host/i);
    assert.match(mixedEn, /not proof the host enforced/i);

    const allActive = [
      { supported: true, active: true },
      { supported: true, active: true },
    ];
    assert.equal(anyDeviceHookFact(allActive).mixed, false);
    const every = fleetHookStatusText("zh", "all", { supported: true, active: true }, allActive);
    assert.match(every, /都有/);
    assert.match(every, /不证明宿主已执行/);

    const one = fleetHookStatusText("zh", "one", collapsed, [machines[1]!.capabilities.hook_grok]);
    assert.equal(one, t("zh", "hookCapNoReceipt"));
    assert.equal(one.includes("任一设备"), false);

    const missing = anyDeviceHookFact([{ supported: true, active: true }, undefined]);
    assert.equal(missing.reported, 1);
    assert.equal(missing.mixed, false);
    const sole = fleetHookStatusText("zh", "all", { supported: true, active: true }, [
      { supported: true, active: true },
      undefined,
    ]);
    assert.equal(sole, t("zh", "hookCapActive"));
    assert.equal(sole.includes("任一设备"), false);
  });

  it("source contract: the home hook explanation uses the fleet wording", () => {
    assert.match(indexSrc, /fleetHookStatusText\(/);
    assert.match(indexSrc, /hookAnyDeviceShort/);
  });
});

describe("discovery evidence", () => {
  it("does not show a verified hook or enrollment for an observed-only process", () => {
    const foreign = { hook_claude: { supported: true, active: true } };
    assert.equal(hookCapabilityForDiscovery("grok-cli", foreign), undefined);
    const row = discoveryRowEvidence({ running: "observed" }, hookCapabilityForDiscovery("grok-cli", foreign));
    assert.equal(row.observedProcess, "observed");
    assert.equal(row.configured, "unreported");
    assert.equal(row.trusted, "unreported");
    assert.equal(row.receipt, "unreported");
    assert.equal(row.enrolled, false);
    assert.equal(row.verifiedHook, false);
    const lines = discoveryEvidenceLines("zh", row);
    assert.match(lines.observed, /观察到进程/);
    assert.match(lines.observed, /不是已接入/);
    assert.match(lines.observed, /没有 Hook 已验证/);
    assert.equal(lines.receipt, "未上报");
    const en = discoveryEvidenceLines("en", row);
    assert.match(en.observed, /not enrolled/i);
    assert.match(en.observed, /hook not verified/i);
    assert.equal(/verified hook exists|enrolled hook/i.test(en.receipt), false);
  });

  it("keeps a device receipt distinct from this process and never records a new trusted identity", () => {
    const cap = { supported: true, active: true };
    const row = discoveryRowEvidence({ running: "observed", installation: "present", identity: "corroborated" }, cap);
    assert.equal(row.receipt, "recent_receipt");
    assert.equal(row.configured, "configured");
    assert.equal(row.trusted, "unreported");
    assert.equal(row.enrolled, false);
    assert.equal(row.verifiedHook, false);
    assert.notEqual(row.trusted, "trusted");
    const zh = discoveryEvidenceLines("zh", row);
    assert.match(zh.receipt, /24\s*小时/);
    assert.match(zh.receipt, /不证明这个进程已接入/);
    assert.match(zh.receipt, /不证明宿主已执行/);
    assert.match(zh.configured, /不是这个进程已接入/);

    const untrusted = discoveryRowEvidence(
      { running: "not_observed" },
      { supported: true, active: false, error: "hook_untrusted" },
    );
    assert.equal(untrusted.configured, "configured");
    assert.equal(untrusted.trusted, "untrusted");
    assert.equal(untrusted.receipt, "no_receipt");
    assert.equal(untrusted.verifiedHook, false);
    assert.match(discoveryEvidenceLines("en", untrusted).trusted, /not trusted/i);
    assert.match(discoveryEvidenceLines("en", untrusted).trusted, /not enrolled/i);

    const retrust = discoveryRowEvidence({ running: "unknown" }, { supported: true, active: false, error: "hook_modified" });
    assert.equal(retrust.trusted, "retrust");
    assert.equal(retrust.enrolled, false);

    const absent = discoveryRowEvidence({ running: "not_observed" }, { supported: true, active: false, error: "hook_not_installed" });
    assert.equal(absent.configured, "not_configured");
    assert.equal(absent.receipt, "no_receipt");

    const noAdapter = discoveryRowEvidence({ running: "observed" }, { supported: false, active: false });
    assert.equal(noAdapter.configured, "no_adapter");
    assert.equal(noAdapter.verifiedHook, false);

    const stale = discoveryRowEvidence({ running: "observed", identity: "candidate" }, undefined, { stale: true });
    assert.equal(stale.observedProcess, "unknown");
    assert.equal(stale.enrolled, false);

    const candidate = discoveryRowEvidence(
      { running: "observed", installation: "candidate", identity: "candidate" },
      undefined,
    );
    assert.equal(candidate.observedProcess, "candidate");
    assert.match(discoveryEvidenceLines("zh", candidate).observed, /候选应用进程/);
    assert.match(discoveryEvidenceLines("zh", candidate).observed, /不是已接入/);
  });

  it("source contract: local discovery does not inherit fleet OR caps or a single connected badge", () => {
    assert.equal(discoverySrc.includes("capabilities={scopedCaps}"), false);
    assert.equal(discoverySrc.includes("useScopedCapabilities"), false);
    assert.equal(discoverySrc.includes("tagReceiptConfirmed"), false);
    assert.match(discoverySrc, /discoveryRowEvidence\(/);
    assert.match(discoverySrc, /hookCapabilityForDiscovery\(/);
  });
});
