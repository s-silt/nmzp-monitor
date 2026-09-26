import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { it } from "node:test";

it("restore dialog shows control changes and blocks confirm until known", () => {
  const source = readFileSync(new URL("../../routes/history.tsx", import.meta.url), "utf8");
  assert.match(
    source,
    /import\s*\{[^}]*\brestoreControlChanges\b[^}]*\}\s*from\s*["']@\/lib\/monitor\/restore-preview["'];/,
    "history must import restoreControlChanges",
  );
  assert.match(source, /restoreControlChanges\(/, "dialog must call restoreControlChanges");
  assert.match(source, /tx\("restoreControlTitle"\)/, "dialog must title the runtime control block");
  assert.match(source, /restorePreview\.changes\.map/, "dialog must list each runtime control change");
  assert.match(source, /tx\("restoreControlNone"\)/, "dialog must say when runtime controls do not change");
  assert.match(source, /tx\("restoreControlLoading"\)/, "dialog must show why confirm waits on the preview");
  assert.match(source, /tx\("restoreControlLoadFailed"\)/, "dialog must show a failed preview read");
  assert.match(source, /tx\("restoreControlUnknown"\)/, "dialog must show an unparseable preview");
  assert.match(
    source,
    /tx\("restoreControlStoppedDanger"\)/,
    "stopped false to true must surface the stop-evaluation warning",
  );
  const i18n = readFileSync(new URL("./i18n.ts", import.meta.url), "utf8");
  assert.match(i18n, /运行控制变化/);
  assert.match(i18n, /Runtime control changes/);
  assert.match(i18n, /恢复后将停止所有设备的 Hook 评估/);
  assert.match(i18n, /Restore will stop hook evaluation on all devices/);
  assert.equal(source.match(/restorePolicyRevision\(/g)?.length, 1);
  const labelAt = source.indexOf("确认发布递增恢复版本");
  assert.ok(labelAt >= 0, "restore confirm label missing");
  const buttonAt = source.lastIndexOf("<Button", labelAt);
  assert.ok(buttonAt >= 0, "restore confirm button missing");
  assert.match(
    source.slice(buttonAt, labelAt),
    /disabled=\{restoring \|\| restorePreview\.kind !== "ready"\}/,
    "confirm stays disabled until restore preview is known",
  );
});
