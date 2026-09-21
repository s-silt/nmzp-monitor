import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  NmzpStore,
  atomicWrite,
  bootstrapAdmin,
  deriveDeviceStatus,
  mergeHeartbeatSnapshotGuard,
  withFileLock,
} from "./persist.ts";
import type { DeviceRecord, SnapshotGuardReport } from "./schema.ts";
import { sha256Hex } from "./auth.ts";
import { MAX_EVENTS, OFFLINE_AFTER_MS, ARCHIVE_AFTER_MS } from "./constants.ts";

describe("persist", () => {
  it("derives online/dark/archived from heartbeat age", () => {
    const now = 1_000_000_000_000;
    assert.equal(deriveDeviceStatus(now, now), "online");
    assert.equal(deriveDeviceStatus(now - OFFLINE_AFTER_MS - 1, now), "dark");
    assert.equal(deriveDeviceStatus(now - ARCHIVE_AFTER_MS, now), "archived");
  });

  it("CAS policy, restart restore, event cap, admin hash", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-store-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      const boot = await bootstrapAdmin(s);
      assert.ok(boot.token.length > 20);
      assert.equal(s.adminHash(), sha256Hex(boot.token));
      const p1 = s.getPolicy();
      const ok = await s.casPolicy(p1.version, { mode: "permissive" });
      assert.ok(!("conflict" in ok));
      const bad = await s.casPolicy(p1.version, { mode: "off" });
      assert.ok("conflict" in bad);
      await s.appendEvent({
        id: "e1",
        ts: Date.now(),
        machineId: "dev_a",
        agent: "grok",
        sessionId: "s",
        layer: "app_pre",
        tool: "Bash",
        nativeTool: "Bash",
        input: "<标签>",
        risk: "high",
        decision: "block",
        category: "exfil",
        workdirScope: "project",
        redacted: "<标签>",
        policyVersion: 1,
        evaluation: "block",
        enforcement: "returned_deny",
      });
      const dup = await s.appendEvent({
        id: "e1",
        ts: Date.now(),
        machineId: "dev_a",
        agent: "grok",
        sessionId: "s",
        layer: "app_pre",
        tool: "Bash",
        nativeTool: "Bash",
        input: "<标签>",
        risk: "high",
        decision: "block",
        category: "exfil",
        workdirScope: "project",
        redacted: "<标签>",
        policyVersion: 1,
        evaluation: "block",
        enforcement: "returned_deny",
      });
      assert.equal(dup.duplicate, true);
      assert.equal(s.listEvents().length, 1);
      const s2 = new NmzpStore(dir);
      await s2.load();
      assert.equal(s2.getPolicy().mode, "permissive");
      assert.equal(s2.listEvents().length, 1);
      assert.equal(s2.listEvents()[0]!.redacted.includes("AKIA"), false);
      const s3 = new NmzpStore(dir);
      await s3.load();
      await Promise.all([
        s3.appendEvent({
          id: "c1",
          ts: Date.now(),
          machineId: "dev_a",
          agent: "claude",
          sessionId: "s",
          layer: "app_pre",
          tool: "Bash",
          nativeTool: "Bash",
          input: "x",
          risk: "info",
          decision: "log",
          category: "other",
          workdirScope: "project",
          redacted: "x",
          policyVersion: 1,
          evaluation: "log",
          enforcement: "delivered",
        }),
        s3.appendEvent({
          id: "c2",
          ts: Date.now(),
          machineId: "dev_a",
          agent: "claude",
          sessionId: "s",
          layer: "app_pre",
          tool: "Read",
          nativeTool: "Read",
          input: "y",
          risk: "info",
          decision: "log",
          category: "file_read",
          workdirScope: "project",
          redacted: "y",
          policyVersion: 1,
          evaluation: "log",
          enforcement: "delivered",
        }),
      ]);
      assert.equal(s3.listEvents().length, 3);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("seeds defaultRules only on ENOENT and never silent-resets a later empty array", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-store-"));
    try {
      const seed = [{ id: "p_x", enabled: true, mode: "replace" as const, match: "EMP-\\d{4}", kind: "emp", replaceWith: "<标签>" }];
      const s = new NmzpStore(dir);
      await s.load({ defaultRules: seed });
      assert.equal(s.getPolicy().customRules.length, 1);
      const cur = s.getPolicy();
      const cleared = await s.casPolicy(cur.version, { customRules: [] });
      assert.ok(!("conflict" in cleared));
      const s2 = new NmzpStore(dir);
      await s2.load({ defaultRules: seed });
      assert.equal(s2.getPolicy().customRules.length, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("throws on corrupt policy.json instead of resetting", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-store-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      await writeFile(s.policyPath(), "{not json", "utf8");
      const s2 = new NmzpStore(dir);
      await assert.rejects(() => s2.load(), /corrupt_json/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("withFileLock retries only EEXIST and immediately propagates fn errors", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-lock-"));
    try {
      let n = 0;
      await assert.rejects(
        () =>
          withFileLock(dir, async () => {
            n += 1;
            throw new Error("boom");
          }),
        /boom/,
      );
      assert.equal(n, 1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("appendEventUnlocked caps at MAX_EVENTS inside the mutex", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-cap-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      await s.withMutex(async () => {
        for (let i = 0; i < MAX_EVENTS + 8; i++) {
          s.appendEventUnlocked({
            id: `e${i}`,
            ts: Date.now(),
            machineId: "dev_a",
            agent: "grok",
            sessionId: "s",
            layer: "app_pre",
            tool: "Bash",
            nativeTool: "Bash",
            input: "x",
            risk: "info",
            decision: "log",
            category: "other",
            workdirScope: "project",
            redacted: "x",
            policyVersion: 1,
            evaluation: "log",
            enforcement: "delivered",
          });
        }
      });
      assert.equal(s.listEvents().length, MAX_EVENTS);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("atomicWrite keeps dest when rename cannot replace it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-atomic-"));
    const dest = join(dir, "keep.json");
    try {
      await mkdir(dest);
      await writeFile(join(dest, "inside.txt"), "KEEP", "utf8");
      await assert.rejects(() => atomicWrite(dest, "NEW"));
      const st = await stat(dest);
      assert.equal(st.isDirectory(), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  function device(id: string, extra: Partial<DeviceRecord> = {}): DeviceRecord {
    return {
      id,
      tokenHash: "h",
      hostname: id,
      ip: "127.0.0.1",
      user: "u",
      os: "win32",
      attachedAt: 1,
      lastSeen: 1,
      lastPolicyVersion: 1,
      capabilities: [],
      agents: [],
      ...extra,
    };
  }

  const guardA: SnapshotGuardReport = {
    supported: true,
    active: true,
    managed: true,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "protected",
    lastVerified: 1_700_000_000_000,
  };
  const guardB: SnapshotGuardReport = {
    supported: true,
    active: false,
    managed: false,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "none",
    error: "external_restriction",
    lastVerified: 1_700_000_000_100,
  };

  it("keeps snapshotGuard per device and projects unknown fields on load", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-store-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      await s.putDevice(device("dev_a", { snapshotGuard: guardA }));
      await s.putDevice(
        device("dev_b", {
          snapshotGuard: {
            ...guardB,
            zcodeRunning: true,
            sddl: "O:BAG",
            paths: ["C:\\\\.zcode"],
          } as unknown as SnapshotGuardReport,
        }),
      );
      assert.equal(s.getDevice("dev_a")?.snapshotGuard?.active, true);
      assert.equal(s.getDevice("dev_b")?.snapshotGuard?.error, "external_restriction");
      assert.equal("sddl" in (s.getDevice("dev_b")?.snapshotGuard ?? {}), false);
      assert.notEqual(s.getDevice("dev_a")?.snapshotGuard?.lastVerified, s.getDevice("dev_b")?.snapshotGuard?.lastVerified);

      await writeFile(
        s.devicesPath(),
        JSON.stringify({
          devices: [
            {
              ...device("dev_a", { snapshotGuard: { ...guardA, nested: { aces: ["S-1-5"] } } as unknown as SnapshotGuardReport }),
            },
            {
              ...device("dev_b", {
                snapshotGuard: {
                  supported: true,
                  active: true,
                  existingArchiveCoverage: "unknown",
                  lastVerified: 1,
                } as unknown as SnapshotGuardReport,
              }),
            },
          ],
        }),
      );
      const s2 = new NmzpStore(dir);
      await s2.load();
      assert.equal(s2.getDevice("dev_a")?.snapshotGuard?.active, true);
      assert.equal("nested" in (s2.getDevice("dev_a")?.snapshotGuard ?? {}), false);
      assert.equal(s2.getDevice("dev_b")?.snapshotGuard, undefined);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("non-poll heartbeat clears invalid snapshotGuard; pollOnly keeps lastVerified", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-hb-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      await s.putDevice(device("dev_a", { snapshotGuard: guardA }));
      const cleared = mergeHeartbeatSnapshotGuard(s.getDevice("dev_a")?.snapshotGuard, undefined, false);
      assert.equal(cleared, undefined);
      await s.touchDevice("dev_a", { snapshotGuard: cleared, lastSeen: 2 });
      assert.equal(s.getDevice("dev_a")?.snapshotGuard, undefined);

      await s.putDevice(device("dev_a", { snapshotGuard: guardA }));
      const kept = mergeHeartbeatSnapshotGuard(s.getDevice("dev_a")?.snapshotGuard, { active: true }, true);
      assert.equal(kept?.lastVerified, guardA.lastVerified);
      assert.equal(kept?.active, true);
      await s.touchDevice("dev_a", { lastSeen: 3 });
      assert.equal(s.getDevice("dev_a")?.snapshotGuard?.lastVerified, guardA.lastVerified);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

