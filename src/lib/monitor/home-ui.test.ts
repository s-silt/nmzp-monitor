import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { homeReadyValue, t } from "./i18n.ts";

const BRANDS = /file\.io|transfer\.sh|webhook\.site|0x0\.st|google\.com|github\.com|baidu|taobao|chrome|firefox|safari|api\.z\.ai|openai\.com|x\.ai/i;
const homeUi = readFileSync(new URL("../../routes/index.tsx", import.meta.url), "utf8");

function copyOf(locale: "zh" | "en", key: "whyQuiet" | "probeLayerBody") {
  return t(locale, key);
}

describe("home hero and probe copy", () => {
  it("states two real scopes and does not claim only-hook or full coverage", () => {
    for (const locale of ["zh", "en"] as const) {
      const why = copyOf(locale, "whyQuiet");
      const probe = copyOf(locale, "probeLayerBody");
      assert.match(why, /Grok/);
      assert.match(why, /Claude/);
      assert.match(why, /ZCode/);
      assert.match(probe, /ZCode/);
      if (locale === "zh") {
        assert.match(why, /工具/);
        assert.match(why, /未接 Hook/);
        assert.match(why, /宿主 Hook 失败时可能放行/);
        assert.match(why, /Windows/);
        assert.match(why, /快照/);
        assert.match(why, /文件系统/);
        assert.match(why, /每台/);
        assert.match(why, /剪贴板/);
        assert.match(why, /屏幕/);
        assert.match(why, /网络/);
        assert.match(why, /未实现/);
        assert.equal(why.includes("当前只检查"), false);
        assert.equal(why.includes("没有后台文件"), false);
        assert.equal(why.includes("进程自己打包"), false);
        assert.equal(why.includes("直接拦"), false);
        assert.match(probe, /进程快照/);
        assert.match(probe, /独立于/);
        assert.match(probe, /上报/);
        assert.match(probe, /未实现/);
        assert.equal(probe.includes("没有后台文件或网络监护"), false);
        assert.equal(probe.includes("没有后台文件"), false);
      } else {
        assert.match(why, /pre-tool/i);
        assert.match(why, /Unhooked/);
        assert.match(why, /host hook failure/i);
        assert.match(why, /Windows/);
        assert.match(why, /snapshot/i);
        assert.match(why, /filesystem/i);
        assert.match(why, /clipboard/i);
        assert.match(why, /screen/i);
        assert.match(why, /not implemented/i);
        assert.equal(/only already-connected/i.test(why), false);
        assert.equal(/no background file/i.test(why), false);
        assert.match(probe, /process snapshot/i);
        assert.match(probe, /independent/i);
        assert.match(probe, /report/i);
        assert.match(probe, /not implemented/i);
        assert.equal(/no background file or network/i.test(probe), false);
      }
      assert.equal(BRANDS.test(why), false, why);
      assert.equal(BRANDS.test(probe), false, probe);
    }
  });
});

describe("homeReadyValue", () => {
  it("keeps pending until a successful CT sync, and uses 0 only for a real empty array", () => {
    assert.equal(homeReadyValue(false, 0, "加载中"), "加载中");
    assert.equal(homeReadyValue(false, 7, "加载中"), "加载中");
    assert.equal(homeReadyValue(true, 0, "加载中"), 0);
    assert.equal(homeReadyValue(true, 4, "加载中"), 4);
  });
});

describe("home process identity", () => {
  it("keeps the real identity list behind a closed native details/summary", () => {
    const start = homeUi.indexOf('{tx("identity")}');
    assert.ok(start > 0);
    const blockStart = homeUi.lastIndexOf("<section", start);
    const blockEnd = homeUi.indexOf("</section>", start);
    const block = homeUi.slice(blockStart, blockEnd);
    assert.match(block, /<details\b/);
    assert.match(block, /<summary\b/);
    assert.equal(/<details[^>]*\bopen\b/.test(block), false);
    assert.match(block, /collected\.length/);
    assert.match(block, /identityWarn/);
    assert.match(block, /identityUnknownUser/);
    assert.match(block, /collected\.map/);
    const summaryEnd = block.indexOf("</summary>");
    assert.ok(summaryEnd > 0);
    assert.ok(block.indexOf("<ul") > summaryEnd);
  });
});

describe("home overview wiring", () => {
  it("uses one dataReady flag for event-derived tiles and breakdowns", () => {
    assert.match(homeUi, /const dataReady = synced/);
    assert.match(homeUi, /homeReadyValue\(dataReady,/);
    assert.match(homeUi, /<SnapshotGuardSection /);
    const eventBlock = homeUi.slice(homeUi.indexOf("eventBreakdown"), homeUi.indexOf("riskBreakdown"));
    const riskBlock = homeUi.slice(homeUi.indexOf("riskBreakdown"), homeUi.indexOf("liveFeed"));
    assert.match(eventBlock, /dataReady/);
    assert.match(riskBlock, /dataReady/);
    assert.equal(eventBlock.includes("value={stats.layers.app_pre}") && !eventBlock.includes("dataReady"), false);
    assert.equal(/value=\{stats\.risks\.high\}/.test(riskBlock) && !riskBlock.includes("dataReady"), false);
    assert.match(eventBlock, /notCollected/);
    assert.equal(homeUi.includes("fireDanger"), false);
    assert.equal(homeUi.includes("fireSnapshot"), false);
    assert.equal(/putPolicy|clearEventsApi/.test(homeUi), false);
  });
});
