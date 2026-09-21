import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { adaptSnapshotGuardLibraryStatus } from "./schema.ts";
import {
  SNAPSHOT_GUARD_PROBE_MS,
  collectSnapshotGuardStatus,
  snapshotGuardPlatformSupported,
} from "./snapshot-status-collector.ts";
import { snapshotGuardForHeartbeat, snapshotGuardReportFromCollector } from "./probe.ts";

const HANG = `import { spawnSync } from "node:child_process";
if (process.platform === "win32") spawnSync("ping", ["-n", "40", "127.0.0.1"], { windowsHide: true, stdio: "ignore" });
else spawnSync("sleep", ["40"], { stdio: "ignore" });
process.stdout.write(JSON.stringify({ supported: true, active: true, lastVerified: 99 }) + "\\n");
`;

describe("snapshot status collector (production child)", () => {
  it("default temp-home path returns public shape without injection", { timeout: 20_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-smoke-"));
    const home = join(dir, "home");
    await mkdir(home, { recursive: true });
    try {
      const t0 = Date.now();
      const raw = await collectSnapshotGuardStatus({ home });
      const dt = Date.now() - t0;
      const st = adaptSnapshotGuardLibraryStatus(raw) ?? snapshotGuardReportFromCollector(raw);
      assert.ok(st);
      assert.equal(typeof st.supported, "boolean");
      assert.equal(st.active, false);
      assert.equal("sddl" in st, false);
      assert.equal("paths" in st, false);
      assert.equal("zcodeRunning" in st, false);
      assert.equal(JSON.stringify(st).includes("S-1-5"), false);
      if (!snapshotGuardPlatformSupported()) {
        assert.equal(st.supported, false);
        assert.equal(st.error, "unsupported_platform");
        assert.equal(st.lastVerified, 0);
      }
      assert.ok(dt < SNAPSHOT_GUARD_PROBE_MS + 3_000, `default collect took ${dt}ms`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("kills a blocking spawnSync child within the real timeout budget", { timeout: 15_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-hang-"));
    const home = join(dir, "home");
    const workerPath = join(dir, "hang.mjs");
    await mkdir(home, { recursive: true });
    await writeFile(workerPath, HANG);
    try {
      const t0 = Date.now();
      const raw = await collectSnapshotGuardStatus({ home, timeoutMs: 500, workerPath });
      const dt = Date.now() - t0;
      assert.ok(dt < 4_000, `timeout did not fire; waited ${dt}ms`);
      assert.ok(dt >= 400, `timeout fired too early (${dt}ms)`);
      const st = snapshotGuardReportFromCollector(raw);
      assert.equal(st.active, false);
      assert.equal(st.error, "timeout");
      assert.equal(st.lastVerified, 0);
      assert.equal(st.supported, snapshotGuardPlatformSupported());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not share in-flight results across different homes", { timeout: 15_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-homes-"));
    const homeA = join(dir, "a");
    const homeB = join(dir, "b");
    const hang = join(dir, "hang.mjs");
    const echo = join(dir, "echo.mjs");
    await mkdir(homeA, { recursive: true });
    await mkdir(homeB, { recursive: true });
    await writeFile(hang, HANG);
    await writeFile(
      echo,
      `process.stdout.write(JSON.stringify({
        supported: true, active: false, managed: false, targetPresent: false,
        writeBlocked: false, existingArchiveCoverage: "none", error: "target_missing", lastVerified: 0
      }) + "\\n");\n`,
    );
    try {
      const hung = collectSnapshotGuardStatus({ home: homeA, timeoutMs: 1_500, workerPath: hang });
      const fast = collectSnapshotGuardStatus({ home: homeB, timeoutMs: 1_500, workerPath: echo });
      const winner = await Promise.race([
        fast.then(() => "fast" as const),
        new Promise<"slow">((resolve) => setTimeout(() => resolve("slow"), 700)),
      ]);
      assert.equal(winner, "fast");
      const fastSt = snapshotGuardReportFromCollector(await fast);
      assert.equal(fastSt.error, "target_missing");
      assert.equal(snapshotGuardReportFromCollector(await hung).error, "timeout");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("heartbeat default collect on temp home is bounded and skipped when stopped", { timeout: 20_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-hb-"));
    const home = join(dir, "home");
    await mkdir(home, { recursive: true });
    try {
      assert.equal(await snapshotGuardForHeartbeat({ home, stopped: true }), undefined);
      const r = await snapshotGuardForHeartbeat({ home, stopped: false });
      assert.ok(r);
      assert.equal(r!.active, false);
      assert.equal(typeof r!.lastVerified, "number");
      if (!snapshotGuardPlatformSupported()) {
        assert.equal(r!.supported, false);
        assert.equal(r!.lastVerified, 0);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
