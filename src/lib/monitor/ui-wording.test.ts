import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { parseSnapshotGuardCli } from "../../../core/snapshot-guard.ts";
import { t } from "./i18n.ts";
import { PROPOSAL_SCHEMA, mergeProposal, type PolicyProposal } from "./policy-proposal.ts";

const indexSrc = readFileSync(new URL("../../routes/index.tsx", import.meta.url), "utf8");
const cliSrc = readFileSync(new URL("../../../core/cli.ts", import.meta.url), "utf8");
const i18nSrc = readFileSync(new URL("./i18n.ts", import.meta.url), "utf8");

const allHostKeys = [
  "firstMatch",
  "hookInstallHint",
  "demoBanner",
  "twoLayerHint",
  "guardLead",
  "scopeBody",
] as const;

describe("ui wording", () => {
  it("board shows the real snapshot CLI command", () => {
    assert.equal(
      indexSrc.includes("snapshot-guard apply"),
      false,
      "index.tsx must not show snapshot-guard apply",
    );
    assert.equal(indexSrc.includes("nmzp snapshot apply"), true, "index.tsx must show nmzp snapshot apply");
    assert.match(cliSrc, /cmd === "snapshot"/, "cli.ts must dispatch cmd === \"snapshot\"");
    assert.match(
      cliSrc,
      /nmzp snapshot status\|apply\|restore/,
      "cli.ts usage must list nmzp snapshot status|apply|restore",
    );
  });

  it("source-extracted board command is accepted by parseSnapshotGuardCli", () => {
    const at = indexSrc.indexOf("localSnapshotGuard");
    assert.ok(at > 0, "index.tsx must render the snapshot guard row");
    const shown = indexSrc.slice(at).match(/nmzp snapshot(?:-guard)? apply/)?.[0];
    assert.ok(shown, "snapshot guard row must contain an nmzp snapshot apply command");
    const tokens = shown.split(/\s+/);
    assert.deepEqual(tokens, ["nmzp", "snapshot", "apply"]);
    const parsed = parseSnapshotGuardCli(tokens.slice(2), "C:\\nmzp-lane-b-not-a-home");
    assert.equal(parsed.ok, true);
    if (parsed.ok) assert.equal(parsed.cmd, "apply");
    const internalUsage = parseSnapshotGuardCli(["snapshot-guard", "apply"], "C:\\nmzp-lane-b-not-a-home");
    assert.equal(internalUsage.ok, false);
  });

  it("hook receipt TTL wording does not claim missed calls or host enforcement", () => {
    const bypassZh = t("zh", "bypass");
    const bypassEn = t("en", "bypass");
    assert.equal(bypassZh.includes("漏掉"), false, "bypass zh must not contain 漏掉");
    assert.equal(bypassEn.toLowerCase().includes("missed"), false, "bypass en must not contain missed");
    assert.equal(bypassZh, "探针所见、不是 Hook 工具调用");
    assert.equal(bypassEn, "Probe-seen, not a hooked tool call");
    assert.equal(bypassZh.includes("已阻断"), false);
    assert.equal(/enforced|blocked/i.test(bypassEn), false);

    const zh = t("zh", "hookCapActive");
    const en = t("en", "hookCapActive");
    assert.match(zh, /24\s*小时/, "active receipt zh must name the 24 h window");
    assert.match(en, /24\s*h/i, "active receipt en must name the 24 h window");
    assert.match(zh, /回执/);
    assert.match(en, /receipt/i);
    assert.match(zh, /不证明宿主已执行/);
    assert.match(en, /not proof the host enforced/i);
    assert.equal(zh.includes("漏掉"), false);
    assert.equal(en.toLowerCase().includes("missed"), false);
  });

  it("all-host descriptions do not name only Grok and Claude", () => {
    for (const key of allHostKeys) {
      for (const locale of ["zh", "en"] as const) {
        const text = t(locale, key);
        assert.equal(text.includes("Grok / Claude"), false, `${key} ${locale} must not name only Grok / Claude`);
        assert.equal(text.includes("Grok/Claude"), false, `${key} ${locale} must not name only Grok/Claude`);
        if (locale === "zh") {
          assert.match(text, /已接入(?:的)?宿主/, `${key} zh must say 已接入的宿主`);
        } else {
          assert.match(text, /connected hosts/i, `${key} en must say connected hosts`);
        }
      }
    }
  });

  it("proposalForceDry names a force, not the omitted-field default", () => {
    assert.equal(t("en", "proposalForceDry"), "Force all new rules to dry run");
    assert.equal(t("en", "proposalForceDry").toLowerCase().includes("default"), false);
    assert.equal(t("zh", "proposalForceDry"), "全部先试运行");
    assert.equal(t("zh", "proposalForceDry").includes("默认"), false);

    const proposal: PolicyProposal = {
      schema: PROPOSAL_SCHEMA,
      customRules: [
        { match: "explicit-off", mode: "block", dryRun: false },
        { match: "omitted", mode: "block" },
      ],
    };
    const current = { overrides: { rules: {}, families: {} }, customRules: [], exemptions: [] };
    const now = 1_700_000_000_000;
    const forced = mergeProposal(current, proposal, { now, forceDryRun: true });
    const open = mergeProposal(current, proposal, { now, forceDryRun: false });
    assert.equal(forced.ok, true);
    assert.equal(open.ok, true);
    if (!forced.ok || !open.ok) return;
    const forcedExplicit = forced.next.customRules.find((rule) => rule.match === "explicit-off");
    const openExplicit = open.next.customRules.find((rule) => rule.match === "explicit-off");
    const openOmitted = open.next.customRules.find((rule) => rule.match === "omitted");
    assert.equal(forcedExplicit?.dryRun, true);
    assert.equal(forcedExplicit?.enabled, false);
    assert.equal(openExplicit?.enabled, true);
    assert.equal(openExplicit?.dryRun, undefined);
    assert.equal(openOmitted?.dryRun, true);
    assert.equal(openOmitted?.enabled, false);
  });

  it("dead exfil toast copy is removed", () => {
    assert.equal(/\btoastExfilDesc\b/.test(i18nSrc), false, "toastExfilDesc must be absent");
    assert.equal(/\btoastExfilTitle\b/.test(i18nSrc), false, "toastExfilTitle has no caller and must be absent");
    assert.equal(
      i18nSrc.includes("Hook 已拦截 tar/curl 打包外传"),
      false,
      "dead exfil toast copy must be absent",
    );
  });
});
