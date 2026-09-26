import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { it } from "node:test";

it("store sync discards stale responses", () => {
  const store = readFileSync(new URL("./store.ts", import.meta.url), "utf8");
  const history = readFileSync(new URL("../../routes/history.tsx", import.meta.url), "utf8");

  assert.match(
    store,
    /import\s*\{[^}]*\bcreateSyncGate\b[^}]*\}\s*from\s*["']\.\/sync-gate\.ts["']/,
    "source evidence only: store must import createSyncGate",
  );

  const start = store.indexOf("syncFromServer: async () => {");
  const end = store.indexOf("setLocale:", start);
  assert.ok(start >= 0 && end > start, "source evidence only: syncFromServer body missing");
  const body = store.slice(start, end);
  assert.match(body, /accept\(/, "source evidence only: syncFromServer must call accept(");

  const noted = store.indexOf("noteMutation(");
  const failure = store.indexOf("async function notePolicyFailure");
  const failureEnd = store.indexOf("async function settlePolicyPut", failure);
  const failureBody = store.slice(failure, failureEnd);
  const noteAt = failureBody.indexOf("noteMutation(");
  const syncAt = failureBody.indexOf("syncFromServer(");
  assert.ok(
    noted >= 0 && noteAt >= 0 && syncAt > noteAt,
    "source evidence only: reconcile read must start after noteMutation",
  );

  assert.match(history, /\bhistoryViewState\s*\(/, "source evidence only: history must use historyViewState");
  assert.ok(
    (history.match(/\bhistoryViewState\s*\(/g) ?? []).length >= 2,
    "source evidence only: history must use historyViewState for both lists",
  );
});
