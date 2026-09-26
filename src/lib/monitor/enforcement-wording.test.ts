import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { formatHookResponse } from "../../../core/hook-protocol.ts";
import { t } from "./i18n.ts";

const historySrc = readFileSync(new URL("../../routes/history.tsx", import.meta.url), "utf8");
const i18nSrc = readFileSync(new URL("./i18n.ts", import.meta.url), "utf8");

describe("enforcement wording", () => {
  it("delivered receipt is worded as dispatch, not execution", () => {
    const zh = t("zh", "netEnforcementDelivered");
    const en = t("en", "netEnforcementDelivered");
    assert.match(zh, /未验证/, "netEnforcementDelivered zh must contain 未验证");
    assert.match(en, /unverified/, "netEnforcementDelivered en must contain unverified");
    assert.equal(zh, "指令已下发宿主（是否执行未验证）");
    assert.equal(en, "Instruction delivered to host (execution unverified)");
  });

  it("device-reported blocked is labelled as self-report", () => {
    const zh = t("zh", "blocked");
    const en = t("en", "blocked");
    assert.match(zh, /设备上报/, "blocked zh must contain 设备上报");
    assert.match(en, /Device-reported/, "blocked en must contain Device-reported");
    assert.equal(
      historySrc.includes("宿主已阻断"),
      false,
      "history.tsx must not contain the literal 宿主已阻断",
    );
    assert.match(historySrc, /tx\("blocked"\)/, "history badge must use tx(\"blocked\")");
    assert.equal(zh, "设备上报：宿主已拦截（未独立验证）");
    assert.equal(en, "Device-reported: host blocked (not independently verified)");
  });

  it("rewrite delivered badge states adoption is unverified", () => {
    assert.match(historySrc, /rewriteDelivered/, "history.tsx must reference rewriteDelivered");
    assert.match(
      historySrc,
      /decision === "rewrite" && evt\.enforcement === "delivered"/,
      "history rewrite badge must be rewrite and delivered",
    );
    // dict is not exported, and Msg rejects keys missing from the table.
    const row = /rewriteDelivered:\s*\{[^}]*zh:\s*"([^"]*)"[^}]*en:\s*"([^"]*)"/.exec(i18nSrc);
    assert.ok(row, "rewriteDelivered row missing from i18n table");
    assert.match(row[1] ?? "", /未验证/, "rewriteDelivered zh must contain 未验证");
    assert.match(row[2] ?? "", /unverified/, "rewriteDelivered en must contain unverified");
    assert.equal(row[1], "改写指令已下发；宿主是否采纳未验证");
    assert.equal(row[2], "Rewrite instruction delivered; host adoption unverified");
  });

  it("Kimi still maps rewrite to deny", () => {
    assert.deepEqual(
      formatHookResponse("kimi", {
        decision: "allow",
        reason: "rewrite",
        updatedInput: { command: "echo x" },
      }),
      {
        stdout:
          JSON.stringify({
            hookSpecificOutput: {
              permissionDecision: "deny",
              permissionDecisionReason: "rewrite_unsupported_host",
            },
          }) + "\n",
        exitCode: 2,
        stderr: "rewrite_unsupported_host\n",
      },
    );
  });
});
