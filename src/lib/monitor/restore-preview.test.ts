import assert from "node:assert/strict";
import { it } from "node:test";

const currentRunning = {
  mode: "enforcing",
  stopped: false,
  githubUpload: { agents: ["codex"], mode: "selected" },
  archiveUpload: { action: "warn" as const, thresholdMiB: 200 },
};

it("restore preview lists stopped and mode changes with exact values", async () => {
  const { restoreControlChanges } = await import("./restore-preview.ts");
  const changes = restoreControlChanges(
    {
      version: 3,
      updatedAt: 30,
      mode: "off",
      stopped: true,
      previousMode: "enforcing",
      customRules: [],
      githubUpload: { mode: "selected", agents: ["codex"] },
      archiveUpload: { thresholdMiB: 200, action: "warn" },
    },
    currentRunning,
  );
  assert.deepEqual(
    changes?.find((row) => row.field === "stopped"),
    { field: "stopped", current: false, restored: true },
    "stopped and mode changes must list exact current and restored values",
  );
  assert.deepEqual(
    changes?.find((row) => row.field === "mode"),
    { field: "mode", current: "enforcing", restored: "off" },
    "stopped and mode changes must list exact current and restored values",
  );
  assert.deepEqual(
    changes,
    [
      { field: "mode", current: "enforcing", restored: "off" },
      { field: "stopped", current: false, restored: true },
    ],
    "stopped and mode changes must list exact current and restored values",
  );
});

it("restore preview reports no changes when controls are equal", async () => {
  const { restoreControlChanges } = await import("./restore-preview.ts");
  const changes = restoreControlChanges(
    {
      version: 4,
      updatedAt: 9,
      mode: "enforcing",
      stopped: false,
      customRules: [{ id: "p_keep" }],
      githubUpload: { mode: "selected", agents: ["codex"], note: undefined },
      archiveUpload: { thresholdMiB: 200, action: "warn" },
    },
    currentRunning,
  );
  assert.deepEqual(changes, [], "equal controls must produce an empty change list");
});

it("unparseable historical body yields unknown", async () => {
  const { restoreControlChanges } = await import("./restore-preview.ts");
  for (const body of [null, undefined, "policy", 1, false, [], new Date()]) {
    assert.equal(
      restoreControlChanges(body, currentRunning),
      null,
      "unparseable historical body must yield unknown",
    );
  }
});

it("missing historical controls are absent only when current differs", async () => {
  const { restoreControlChanges } = await import("./restore-preview.ts");
  const absentUpload = restoreControlChanges(
    { version: 2, updatedAt: 2, mode: "enforcing", stopped: false, customRules: [] },
    {
      mode: "enforcing",
      stopped: false,
      githubUpload: { mode: "selected", agents: ["codex"] },
      archiveUpload: undefined,
    },
  );
  assert.deepEqual(absentUpload, [
    {
      field: "githubUpload",
      current: { mode: "selected", agents: ["codex"] },
      restored: undefined,
    },
  ]);
  const droppedStopped = restoreControlChanges(
    { version: 2, updatedAt: 2, mode: "enforcing", stopped: undefined, customRules: [] },
    {
      mode: "enforcing",
      stopped: false,
      githubUpload: undefined,
      archiveUpload: undefined,
    },
  );
  assert.deepEqual(droppedStopped, [{ field: "stopped", current: false, restored: undefined }]);
});
