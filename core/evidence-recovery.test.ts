import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, mkdir, rm, rename, appendFile, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NmzpStore } from "./persist.ts";
import { readPolicyCache, writePolicyCache } from "./policy-cache.ts";
import { exportBundleShape } from "./export.ts";
import { projectViewerExport } from "./lan-viewer.ts";
import { sha256Hex } from "./auth.ts";
import type { StoredEvent } from "./schema.ts";
const event: StoredEvent = {
  id: "recovery-fixture",
  ts: Date.now(),
  machineId: "fixture",
  agent: "grok",
  sessionId: "fixture",
  layer: "app_pre",
  tool: "Bash",
  nativeTool: "Bash",
  input: "safe",
  redacted: "safe",
  risk: "info",
  decision: "log",
  evaluation: "log",
  category: "other",
  workdirScope: "project",
  policyVersion: 1,
  enforcement: "pending_verify",
};
it("write failure does not poison dedup or receipts; retry and restart retain the real outcome", async () => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-recovery-"));
  try {
    const s = new NmzpStore(dir);
    await s.load();
    await mkdir(s.eventsPath());
    await assert.rejects(() => s.appendEvent(event));
    assert.equal(s.listEvents().length, 0);
    await rm(s.eventsPath(), { recursive: true });
    await s.appendEvent(event);
    assert.equal(s.listEvents().length, 1);
    await rename(s.eventsPath(), s.eventsPath() + ".held");
    await mkdir(s.eventsPath());
    await assert.rejects(() => s.updateReceipt("fixture", event.id, "returned_deny"));
    assert.equal(s.listEvents()[0]!.enforcement, "pending_verify");
    await rm(s.eventsPath(), { recursive: true });
    await rename(s.eventsPath() + ".held", s.eventsPath());
    await s.updateReceipt("fixture", event.id, "returned_deny");
    await appendFile(s.eventsPath(), "{corrupt\n");
    await s.close();
    const next = new NmzpStore(dir);
    await next.load();
    assert.equal(next.listEvents()[0]!.enforcement, "returned_deny");
    assert.equal(next.evidenceWindow().invalidLinesOnLoad, 1);
    assert.equal(next.evidenceWindow().historyCompleteness, "unknown");
    const ex = projectViewerExport(exportBundleShape(next));
    assert.ok(ex.ok);
    if (ex.ok) assert.deepEqual(ex.bundle.evidenceWindow, next.evidenceWindow());
    await next.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
it("atomic cache refuses invalid policy/future timestamp and retains prior file on failed replace", async () => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-cache-"));
  try {
    const path = join(dir, "policy.json");
    const policy = {
      version: 1,
      mode: "enforcing" as const,
      stopped: false,
      customRules: [],
      updatedAt: Date.now(),
    };
    await writePolicyCache(path, policy);
    assert.deepEqual(await readPolicyCache(path), policy);
    const raw = JSON.parse(await readFile(path, "utf8"));
    raw.savedAt = Date.now() + 1e9;
    await writeFile(path, JSON.stringify(raw));
    assert.equal(await readPolicyCache(path), null);
    raw.savedAt = Date.now();
    raw.policy.mode = "invented";
    raw.sha256 = sha256Hex(JSON.stringify(raw.policy));
    await writeFile(path, JSON.stringify(raw));
    assert.equal(await readPolicyCache(path), null);
    const blocked = join(dir, "occupied");
    await mkdir(blocked);
    await writeFile(join(blocked, "marker"), "keep");
    await assert.rejects(() => writePolicyCache(blocked, policy));
    assert.equal(await readFile(join(blocked, "marker"), "utf8"), "keep");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
