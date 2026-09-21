import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { snapshotCliExitCode } from "./cli.ts";
import { pinnedHttps } from "./https-client.ts";
import { startLanViewer } from "./lan-viewer.ts";
import { startServer } from "./serve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "nmzp.mjs");

function spawnCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ stdout, stderr, code: 1 });
    }, 20_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

async function tmp(prefix: string) {
  return mkdtemp(join(tmpdir(), prefix));
}

function report(over: Record<string, unknown> = {}) {
  return {
    supported: true,
    active: true,
    managed: true,
    targetPresent: true,
    writeBlocked: true,
    existingArchiveCoverage: "protected",
    lastVerified: 1_700_000_000_000,
    ...over,
  };
}

const PUBLIC_SG = [
  "supported",
  "active",
  "managed",
  "targetPresent",
  "writeBlocked",
  "existingArchiveCoverage",
  "error",
  "lastVerified",
] as const;

function assertPublicSg(sg: Record<string, unknown>, expect: Record<string, unknown>) {
  for (const [k, v] of Object.entries(expect)) assert.equal(sg[k], v, k);
  assert.equal("sddl" in sg, false);
  assert.equal("path" in sg, false);
  assert.equal("target" in sg, false);
  for (const k of Object.keys(sg)) assert.ok((PUBLIC_SG as readonly string[]).includes(k), k);
}

describe("snapshot guard serve/LAN/CLI integration", () => {
  it("heartbeat stores public snapshotGuard, pollOnly keeps lastVerified, invalid clears, devices stay isolated", { timeout: 30_000 }, async () => {
    const dir = await tmp("nmzp-sg-int-");
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
    const admin = { authorization: `Bearer ${srv.adminToken}`, "content-type": "application/json" };
    const viewer = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: srv.url,
      caPem: srv.tls.certPem,
      fingerprintSha256: srv.tls.fingerprintSha256,
      adminToken: srv.adminToken,
    });
    try {
      async function join(hostname: string) {
        const ticketRes = await pinnedHttps({ url: `${srv.url}/api/v1/ticket`, method: "POST", headers: admin, ...pin });
        const ticket = (JSON.parse(ticketRes.body) as { ticket: string }).ticket;
        const joinRes = await pinnedHttps({
          url: `${srv.url}/api/v1/join`,
          method: "POST",
          body: JSON.stringify({ ticket, hostname, os: "win32", user: "u" }),
          headers: { "content-type": "application/json" },
          ...pin,
        });
        assert.equal(joinRes.status, 200);
        return JSON.parse(joinRes.body) as { deviceId: string; deviceToken: string };
      }
      const a = await join("pc-a");
      const b = await join("pc-b");
      const hb = (token: string, body: unknown) =>
        pinnedHttps({
          url: `${srv.url}/api/v1/heartbeat`,
          method: "POST",
          body: JSON.stringify(body),
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          ...pin,
        });

      const first = await hb(a.deviceToken, {
        hostname: "pc-a",
        snapshotGuard: {
          ...report({ lastVerified: 111 }),
          sddl: "O:BAG:SYD:(A;;GA;;;BA)",
          path: "C:\\\\Users\\\\a\\\\.zcode\\\\v2\\\\checkpoints",
        },
      });
      assert.equal(first.status, 200);
      const other = await hb(b.deviceToken, {
        hostname: "pc-b",
        snapshotGuard: report({
          active: false,
          managed: false,
          writeBlocked: false,
          existingArchiveCoverage: "none",
          lastVerified: 222,
          error: "external_restriction",
        }),
      });
      assert.equal(other.status, 200);

      const st1 = JSON.parse((await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin })).body) as {
        devices: Array<{ id: string; snapshotGuard?: Record<string, unknown>; tokenHash?: unknown }>;
      };
      const da = st1.devices.find((d) => d.id === a.deviceId)!;
      const db = st1.devices.find((d) => d.id === b.deviceId)!;
      assert.ok(da && db);
      assertPublicSg(da.snapshotGuard!, { lastVerified: 111, existingArchiveCoverage: "protected", active: true });
      assertPublicSg(db.snapshotGuard!, { lastVerified: 222, existingArchiveCoverage: "none", error: "external_restriction" });
      assert.equal(da.snapshotGuard!.lastVerified === db.snapshotGuard!.lastVerified, false);
      assert.equal("tokenHash" in da, false);
      const blob = JSON.stringify(st1);
      assert.equal(blob.includes("O:BAG"), false);
      assert.equal(blob.includes(".zcode"), false);

      const poll = await hb(a.deviceToken, {
        pollOnly: true,
        snapshotGuard: report({ lastVerified: 999, existingArchiveCoverage: "none", active: false, writeBlocked: false }),
      });
      assert.equal(poll.status, 200);
      const stPoll = JSON.parse((await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin })).body) as {
        devices: Array<{ id: string; snapshotGuard?: Record<string, unknown> }>;
      };
      const daPoll = stPoll.devices.find((d) => d.id === a.deviceId)!;
      assert.equal(daPoll.snapshotGuard!.lastVerified, 111);
      assert.equal(daPoll.snapshotGuard!.existingArchiveCoverage, "protected");
      const dbPoll = stPoll.devices.find((d) => d.id === b.deviceId)!;
      assert.equal(dbPoll.snapshotGuard!.lastVerified, 222);

      const bad = await hb(a.deviceToken, { hostname: "pc-a", snapshotGuard: { supported: true, lastVerified: -1 } });
      assert.equal(bad.status, 200);
      const stBad = JSON.parse((await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin })).body) as {
        devices: Array<{ id: string; snapshotGuard?: unknown }>;
      };
      assert.equal("snapshotGuard" in (stBad.devices.find((d) => d.id === a.deviceId) ?? {}), false);
      assert.equal((stBad.devices.find((d) => d.id === b.deviceId) as { snapshotGuard?: { lastVerified: number } }).snapshotGuard?.lastVerified, 222);

      const missing = await hb(b.deviceToken, { hostname: "pc-b" });
      assert.equal(missing.status, 200);
      const stMiss = JSON.parse((await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin })).body) as {
        devices: Array<{ id: string; snapshotGuard?: unknown }>;
      };
      assert.equal("snapshotGuard" in (stMiss.devices.find((d) => d.id === b.deviceId) ?? {}), false);

      const exp = JSON.parse((await pinnedHttps({ url: `${srv.url}/api/v1/export`, headers: admin, ...pin })).body) as {
        machines: Array<{ id: string; snapshotGuard?: Record<string, unknown> }>;
      };
      assert.equal(JSON.stringify(exp).includes("O:BAG"), false);

      const lan = await fetch(`${viewer.url}/api/v1/state`);
      assert.equal(lan.status, 200);
      const lanSt = (await lan.json()) as { devices: Array<{ id: string; snapshotGuard?: Record<string, unknown> }> };
      const lanText = JSON.stringify(lanSt);
      assert.equal(lanText.includes("O:BAG"), false);
      assert.equal(lanText.includes(".zcode\\\\v2"), false);
      const lanA = lanSt.devices.find((d) => d.id === a.deviceId);
      assert.equal(lanA?.snapshotGuard, undefined);
      const restored = await hb(a.deviceToken, { hostname: "pc-a", snapshotGuard: report({ lastVerified: 333, existingArchiveCoverage: "partial", active: false }) });
      assert.equal(restored.status, 200);
      const lan2 = await fetch(`${viewer.url}/api/v1/state`);
      const lanSt2 = (await lan2.json()) as { devices: Array<{ id: string; snapshotGuard?: Record<string, unknown> }> };
      const lanA2 = lanSt2.devices.find((d) => d.id === a.deviceId)!;
      assertPublicSg(lanA2.snapshotGuard!, { lastVerified: 333, existingArchiveCoverage: "partial", active: false });
    } finally {
      await viewer.close().catch(() => undefined);
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("CLI snapshot status uses --home and does not need a live core or print SDDL", { timeout: 20_000 }, async () => {
    const home = await tmp("nmzp-sg-cli-home-");
    const data = await tmp("nmzp-sg-cli-data-");
    try {
      const r = await spawnCli(["snapshot", "status", "--home", home], { NMZP_DATA: data });
      assert.equal(r.code, 0, r.stderr);
      const st = JSON.parse(r.stdout) as { supported: boolean; active: boolean; error?: string };
      assert.equal(typeof st.supported, "boolean");
      assert.equal(st.active, false);
      assert.equal(/sddl/i.test(r.stdout + r.stderr), false);
      assert.equal((r.stdout + r.stderr).includes("D:("), false);
      const usage = await spawnCli(["snapshot"], { NMZP_DATA: data });
      assert.notEqual(usage.code, 0);
      assert.match(usage.stderr, /nmzp snapshot status\|apply\|restore/);
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(data, { recursive: true, force: true });
    }
  });
});

describe("snapshot CLI exit codes", () => {
  it("apply exits 1 for coverage_unknown and inactive, 0 only when active without error", () => {
    assert.equal(snapshotCliExitCode("apply", { error: "coverage_unknown", active: false }), 1);
    assert.equal(snapshotCliExitCode("apply", { active: false }), 1);
    assert.equal(snapshotCliExitCode("apply", { error: "target_missing", active: false }), 1);
    assert.equal(snapshotCliExitCode("apply", { error: "external_restriction", active: true }), 1);
    assert.equal(snapshotCliExitCode("apply", { active: true }), 0);
  });

  it("status stays 0 when reading inactive or coverage_unknown", () => {
    assert.equal(snapshotCliExitCode("status", { error: "coverage_unknown", active: false }), 0);
    assert.equal(snapshotCliExitCode("status", { active: false }), 0);
    assert.equal(snapshotCliExitCode("status", { error: "target_missing", active: false }), 0);
    assert.equal(snapshotCliExitCode("status", { active: true }), 0);
  });

  it("restore fails only when the library reports error", () => {
    assert.equal(snapshotCliExitCode("restore", { error: "not_managed", active: false }), 1);
    assert.equal(snapshotCliExitCode("restore", { error: "coverage_unknown", active: false }), 1);
    assert.equal(snapshotCliExitCode("restore", { error: "conflict", active: false }), 1);
    assert.equal(snapshotCliExitCode("restore", { active: false }), 0);
    assert.equal(snapshotCliExitCode("restore", { active: true }), 0);
  });
});
