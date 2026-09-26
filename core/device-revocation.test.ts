import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { sha256Hex } from "./auth.ts";
import { pinnedHttps } from "./https-client.ts";
import type { NetworkOwnerGrant } from "./network-owner-schema.ts";
import { NmzpStore } from "./persist.ts";
import { newProbeBinding } from "./probe-auth.ts";
import type { DeviceRecord, StoredEvent } from "./schema.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = import.meta.dirname;

function record(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

function pinOf(srv: RunningServer) {
  return { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
}

async function call(
  srv: RunningServer,
  path: string,
  init: { method?: string; token?: string; body?: string } = {},
) {
  const headers: Record<string, string> = {};
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await pinnedHttps({
    url: `${srv.url}${path}`,
    method: init.method ?? "GET",
    headers,
    body: init.body,
    ...pinOf(srv),
    timeoutMs: 10_000,
  });
  let body: unknown = null;
  try {
    body = JSON.parse(res.body);
  } catch {
    body = null;
  }
  return { status: res.status, body, raw: res.body };
}

async function withServer(run: (srv: RunningServer, dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-m09-"));
  let srv: RunningServer | undefined;
  try {
    srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    await run(srv, dir);
  } finally {
    try {
      await srv?.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}

async function joinDevice(srv: RunningServer, hostname: string) {
  const ticket = await call(srv, "/api/v1/ticket", { method: "POST", token: srv.adminToken });
  assert.equal(ticket.status, 200);
  const joined = await call(srv, "/api/v1/join", {
    method: "POST",
    body: JSON.stringify({ ticket: record(ticket.body)?.ticket, hostname, user: "fixture", os: "linux" }),
  });
  assert.equal(joined.status, 200);
  const deviceId = record(joined.body)?.deviceId;
  const deviceToken = record(joined.body)?.deviceToken;
  assert.equal(typeof deviceId, "string");
  assert.equal(typeof deviceToken, "string");
  return { deviceId: deviceId as string, deviceToken: deviceToken as string };
}

function legacyHashHit(raw: string, token: string): boolean {
  const parsed = JSON.parse(raw) as { devices?: Array<{ tokenHash?: string }> };
  const hash = sha256Hex(token);
  return (parsed.devices ?? []).some((device) => device.tokenHash === hash);
}

function deviceRow(body: unknown, id: string): Record<string, unknown> {
  const devices = record(body)?.devices;
  assert.equal(Array.isArray(devices), true);
  const found = (devices as Array<Record<string, unknown>>).find((item) => item.id === id);
  assert.ok(found);
  return found;
}

function fixtureDevice(id: string, tokenHash: string): DeviceRecord {
  return {
    id,
    tokenHash,
    hostname: "fixture",
    ip: "127.0.0.1",
    user: "fixture",
    os: "win32",
    attachedAt: 1,
    lastSeen: 1000,
    lastPolicyVersion: 1,
    capabilities: [],
    agents: [],
  };
}

function ownerGrant(now: number): NetworkOwnerGrant {
  return {
    id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    agent: "grok",
    pid: 42,
    startedAt: now - 1000,
    pathHash: "ab".repeat(32),
    sha256: "cd".repeat(32),
    approvedAt: now,
    expiresAt: now + 60_000,
  };
}

describe("device credential revocation", () => {
  it("admin revoke returns 200", { timeout: 60_000 }, async () => {
    await withServer(async (srv, dir) => {
      const joined = await joinDevice(srv, "host-a");
      const first = await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: srv.adminToken,
        body: JSON.stringify({ deviceId: joined.deviceId }),
      });
      assert.equal(first.status, 200);
      assert.equal(record(first.body)?.ok, true);
      assert.equal(record(first.body)?.alreadyRevoked, false);
      const file = join(dir, "devices.json");
      const before = await readFile(file);
      const second = await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: srv.adminToken,
        body: JSON.stringify({ deviceId: joined.deviceId }),
      });
      assert.equal(second.status, 200);
      assert.equal(record(second.body)?.alreadyRevoked, true);
      assert.deepEqual(await readFile(file), before);
    });
  });

  it("revoked device bearer is rejected with 401", { timeout: 120_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m09-"));
    let srv: RunningServer | undefined;
    try {
      srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
      const first = await joinDevice(srv, "host-a");
      const second = await joinDevice(srv, "host-b");
      const evaluateBody = JSON.stringify({
        eventId: "evt-a",
        sessionId: "s",
        agent: "grok",
        tool_name: "Bash",
        tool_input: { command: "pwd" },
      });
      assert.equal((await call(srv, "/api/v1/policy", { token: first.deviceToken })).status, 200);
      assert.equal((await call(srv, "/api/v1/heartbeat", { method: "POST", token: first.deviceToken, body: "{}" })).status, 200);
      assert.equal((await call(srv, "/api/v1/heartbeat", { method: "POST", token: second.deviceToken, body: "{}" })).status, 200);
      assert.equal((await call(srv, "/api/v1/evaluate", { method: "POST", token: first.deviceToken, body: evaluateBody })).status, 200);
      const originalHash = sha256Hex(first.deviceToken);
      assert.equal(srv.store.getDevice(first.deviceId)?.tokenHash, originalHash);
      const policyVersion = srv.store.getPolicy().version;
      const fingerprint = srv.tls.fingerprintSha256;
      const adminToken = srv.adminToken;

      await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: adminToken,
        body: JSON.stringify({ deviceId: first.deviceId }),
      });
      const heartbeat = await call(srv, "/api/v1/heartbeat", { method: "POST", token: first.deviceToken, body: "{}" });
      assert.equal(heartbeat.status, 401);
      assert.equal((await call(srv, "/api/v1/evaluate", { method: "POST", token: first.deviceToken, body: evaluateBody })).status, 401);
      assert.equal(
        (await call(srv, "/api/v1/receipt", {
          method: "POST",
          token: first.deviceToken,
          body: JSON.stringify({ eventId: "evt-a", enforcement: "delivered" }),
        })).status,
        401,
      );
      assert.equal((await call(srv, "/api/v1/policy", { token: first.deviceToken })).status, 401);
      assert.equal((await call(srv, "/api/v1/heartbeat", { method: "POST", token: second.deviceToken, body: "{}" })).status, 200);
      assert.equal(srv.store.findDeviceByToken(first.deviceToken), undefined);
      assert.notEqual(srv.store.getDevice(first.deviceId)?.tokenHash, originalHash);
      assert.equal(typeof srv.store.getDevice(first.deviceId)?.revokedAt, "number");
      assert.equal(srv.store.getDevice(first.deviceId)?.hostname, "host-a");

      const disk = await readFile(join(dir, "devices.json"), "utf8");
      assert.equal(disk.includes(originalHash), false);
      assert.equal(disk.includes(first.deviceToken), false);
      assert.equal(legacyHashHit(disk, first.deviceToken), false);
      assert.equal(disk.includes(sha256Hex(second.deviceToken)), true);

      const state = await call(srv, "/api/v1/state", { token: adminToken });
      assert.equal(state.status, 200);
      const row = deviceRow(state.body, first.deviceId);
      assert.equal(row.revoked, true);
      assert.equal(typeof row.revokedAt, "number");
      assert.equal("tokenHash" in row, false);
      assert.equal(row.hostname, "host-a");
      assert.equal(deviceRow(state.body, second.deviceId).revoked, false);
      const events = record(state.body)?.events;
      assert.equal(Array.isArray(events), true);
      assert.ok((events as Array<{ id?: string; machineId?: string }>).some((event) => event.id === "evt-a" && event.machineId === first.deviceId));
      assert.equal(record(state.body)?.policyVersion, policyVersion);
      assert.equal(state.raw.includes(originalHash), false);
      assert.equal(state.raw.includes(first.deviceToken), false);

      await srv.close();
      srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
      assert.equal(srv.adminToken, adminToken);
      assert.equal(srv.tls.fingerprintSha256, fingerprint);
      assert.equal(srv.store.getPolicy().version, policyVersion);
      const restarted = await call(srv, "/api/v1/heartbeat", { method: "POST", token: first.deviceToken, body: "{}" });
      assert.equal(restarted.status, 401);
      assert.equal((await call(srv, "/api/v1/evaluate", { method: "POST", token: first.deviceToken, body: evaluateBody })).status, 401);
      assert.equal(
        (await call(srv, "/api/v1/receipt", {
          method: "POST",
          token: first.deviceToken,
          body: JSON.stringify({ eventId: "evt-a", enforcement: "delivered" }),
        })).status,
        401,
      );
      assert.equal((await call(srv, "/api/v1/policy", { token: first.deviceToken })).status, 401);
      assert.equal((await call(srv, "/api/v1/heartbeat", { method: "POST", token: second.deviceToken, body: "{}" })).status, 200);
      assert.equal((await call(srv, "/api/v1/policy", { token: second.deviceToken })).status, 200);
      assert.equal(srv.store.findDeviceByToken(first.deviceToken), undefined);
      const diskAfter = await readFile(join(dir, "devices.json"), "utf8");
      assert.equal(diskAfter.includes(originalHash), false);
      assert.equal(legacyHashHit(diskAfter, first.deviceToken), false);
      const again = await call(srv, "/api/v1/state", { token: adminToken });
      assert.equal(again.status, 200);
      assert.equal(deviceRow(again.body, first.deviceId).revoked, true);
      assert.equal(deviceRow(again.body, first.deviceId).hostname, "host-a");
      const againEvents = record(again.body)?.events;
      assert.ok((againEvents as Array<{ id?: string }>).some((event) => event.id === "evt-a"));
    } finally {
      try {
        await srv?.close();
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }
  });

  it("device bearer and wrong admin cannot revoke", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const joined = await joinDevice(srv, "host-a");
      const hash = sha256Hex(joined.deviceToken);
      const asDevice = await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({ deviceId: joined.deviceId }),
      });
      assert.ok(asDevice.status === 401 || asDevice.status === 403);
      const wrong = await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: "wrong-admin-token",
        body: JSON.stringify({ deviceId: joined.deviceId }),
      });
      assert.equal(wrong.status, 401);
      assert.equal((await call(srv, "/api/v1/heartbeat", { method: "POST", token: joined.deviceToken, body: "{}" })).status, 200);
      assert.equal(srv.store.getDevice(joined.deviceId)?.tokenHash, hash);
      assert.equal(srv.store.getDevice(joined.deviceId)?.revokedAt, undefined);
    });
  });

  it("unknown device is 404 and a bad body is 400", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const missing = await call(srv, "/api/v1/devices/revoke", {
        method: "POST",
        token: srv.adminToken,
        body: JSON.stringify({ deviceId: "dev_missing" }),
      });
      assert.equal(missing.status, 404);
      assert.equal(record(missing.body)?.error, "device_not_found");
      for (const body of ["{", "[]", "{}", "{\"deviceId\":1}", "{\"deviceId\":\"\"}", "{\"deviceId\":\" dev_x\"}"]) {
        const bad = await call(srv, "/api/v1/devices/revoke", { method: "POST", token: srv.adminToken, body });
        assert.equal(bad.status, 400);
      }
    });
  });

  it("queued touch after revoke does not reinstate the credential", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m09-store-"));
    const store = new NmzpStore(dir);
    try {
      await store.load();
      const original = sha256Hex("synthetic-device-token-a");
      const id = "dev_stale";
      await store.putDevice(fixtureDevice(id, original));
      const publicKey = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).toString("base64");
      const binding = newProbeBinding(publicKey);
      assert.equal(await store.bindProbe(id, binding), true);
      assert.equal(await store.updateNetworkOwner(id, ownerGrant(Date.now())), true);
      assert.equal(store.getDevice(id)?.networkOwners?.length, 1);
      const revoked = await store.revokeDevice(id, 1_700_000_000_000);
      assert.equal(revoked.ok, true);
      if (revoked.ok) assert.equal(revoked.alreadyRevoked, false);
      const current = store.getDevice(id);
      assert.ok(current);
      assert.equal(current.lastSeen, 1000);
      assert.notEqual(current.tokenHash, original);
      assert.equal(current.revokedAt, 1_700_000_000_000);
      assert.equal(current.probeBinding?.revoked, true);
      assert.deepEqual(current.networkOwners, []);
      const replacement = current.tokenHash;
      await store.touchDevice(id, {
        ...current,
        lastSeen: 9000,
        hostname: "stale-host",
        tokenHash: original,
        revokedAt: undefined,
        networkOwners: [ownerGrant(Date.now())],
        probeBinding: { ...binding, revoked: false },
      } as Parameters<NmzpStore["touchDevice"]>[1]);
      const after = store.getDevice(id);
      assert.ok(after);
      assert.equal(after.lastSeen, 1000);
      assert.equal(after.tokenHash, replacement);
      assert.equal(after.revokedAt, 1_700_000_000_000);
      assert.equal(after.hostname, "fixture");
      assert.equal(after.probeBinding?.revoked, true);
      assert.deepEqual(after.networkOwners, []);
      assert.equal(store.findDeviceByToken("synthetic-device-token-a"), undefined);
      await store.putDevice({ ...fixtureDevice(id, original), lastSeen: 9000, hostname: "stale-host" });
      assert.equal(store.getDevice(id)?.tokenHash, replacement);
      assert.equal(store.getDevice(id)?.revokedAt, 1_700_000_000_000);
      assert.equal(store.getDevice(id)?.lastSeen, 1000);
      assert.equal(await store.bindProbe(id, newProbeBinding(generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).toString("base64"))), false);
      assert.equal(await store.updateNetworkOwner(id, ownerGrant(Date.now())), false);
      assert.equal(await store.applyNetworkSample(id, { status: "unsupported" }, false, 1_700_000_000_000), undefined);
      assert.equal(store.getDevice(id)?.tokenHash, replacement);
      assert.equal(store.getDevice(id)?.lastSeen, 1000);
      assert.equal(store.getDevice(id)?.probeBinding?.keyId, binding.keyId);
      const disk = await readFile(join(dir, "devices.json"), "utf8");
      assert.equal(disk.includes(original), false);
      assert.equal(legacyHashHit(disk, "synthetic-device-token-a"), false);
    } finally {
      await store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a missing device row still updates its receipt; a revoked row does not", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m09-receipt-"));
    const store = new NmzpStore(dir);
    const event: StoredEvent = {
      id: "evt-receipt",
      ts: 1_700_000_000_000,
      machineId: "fixture",
      agent: "grok",
      sessionId: "fixture",
      layer: "app_pre",
      tool: "Bash",
      nativeTool: "Bash",
      input: "pwd",
      redacted: "pwd",
      risk: "info",
      decision: "log",
      evaluation: "log",
      category: "other",
      workdirScope: "project",
      policyVersion: 1,
      enforcement: "pending_verify",
    };
    try {
      await store.load();
      await store.appendEvent(event);
      const updated = await store.updateReceipt("fixture", event.id, "delivered");
      assert.equal("error" in updated, false);
      if (!("error" in updated)) assert.equal(updated.enforcement, "delivered");
      await assert.rejects(
        () => store.confirmBackfillReceipt("fixture", event.id, "log", "returned_deny"),
        /storage_not_enabled/,
      );
      assert.equal(store.listEvents()[0]?.enforcement, "delivered");
      await store.putDevice(fixtureDevice("fixture", sha256Hex("synthetic-device-token-receipt")));
      const revoked = await store.revokeDevice("fixture", 1_700_000_000_000);
      assert.equal(revoked.ok, true);
      const blocked = await store.updateReceipt("fixture", event.id, "returned_deny");
      assert.equal("error" in blocked && blocked.error, "unauthorized");
      const backfill = await store.confirmBackfillReceipt("fixture", event.id, "log", "returned_deny");
      assert.equal("error" in backfill && backfill.error, "unauthorized");
      assert.equal(store.listEvents()[0]?.enforcement, "delivered");
    } finally {
      await store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("failed revoke publication leaves the stored credential unchanged", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m09-fail-"));
    const store = new NmzpStore(dir);
    try {
      await store.load();
      const id = "dev_fail";
      const tokenHash = sha256Hex("synthetic-device-token-fail");
      await store.putDevice(fixtureDevice(id, tokenHash));
      await rm(store.devicesPath());
      await mkdir(store.devicesPath());
      await assert.rejects(() => store.revokeDevice(id, 1_700_000_000_000));
      const kept = store.getDevice(id);
      assert.equal(kept?.tokenHash, tokenHash);
      assert.equal(kept?.revokedAt, undefined);
      assert.equal(kept?.hostname, "fixture");
      assert.equal(store.findDeviceByToken("synthetic-device-token-fail")?.id, id);
    } finally {
      await store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("outcome-unknown revocation write keeps the device revoked in memory", async () => {
    const atomicFile = await import("./atomic-file.ts");
    const { closeSync, fsyncSync } = await import("node:fs");
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m15-revoke-"));
    const store = new NmzpStore(dir);
    const directoryFd = 2_100_000_003;
    let directoryOpens = 0;
    try {
      assert.equal(typeof atomicFile.setAtomicFileIoForTesting, "function", "seam missing");
      await store.load();
      const originalToken = "synthetic-device-token-outcome";
      const id = "dev_outcome";
      await store.putDevice(fixtureDevice(id, sha256Hex(originalToken)));
      atomicFile.setAtomicFileIoForTesting({
        platform: "linux",
        openDirectory: () => {
          directoryOpens += 1;
          return directoryFd;
        },
        fsync: (fd: number) => {
          if (fd === directoryFd) {
            const error = new Error("EIO") as NodeJS.ErrnoException;
            error.code = "EIO";
            throw error;
          }
          fsyncSync(fd);
        },
        close: (fd: number) => {
          if (fd === directoryFd) return;
          closeSync(fd);
        },
      });
      let thrown: unknown;
      try {
        await store.revokeDevice(id, 1_700_000_000_000);
      } catch (error) {
        thrown = error;
      }
      assert.equal(
        thrown instanceof atomicFile.AtomicWriteOutcomeUnknownError &&
          thrown.code === "atomic_write_outcome_unknown",
        true,
        "atomic_write_outcome_unknown",
      );
      assert.equal(store.findDeviceByToken(originalToken), undefined, "revoked token stays unusable");
      assert.equal(store.getDevice(id)?.revokedAt, 1_700_000_000_000, "revokedAt retained");
      assert.notEqual(
        store.getDevice(id)?.tokenHash,
        sha256Hex(originalToken),
        "revoked token stays unusable",
      );
      assert.equal(directoryOpens, 1, "rename once");
      atomicFile.setAtomicFileIoForTesting(undefined);
      await store.saveDevices();
      const disk = await readFile(join(dir, "devices.json"), "utf8");
      const parsed = JSON.parse(disk) as {
        devices?: Array<{ id?: string; revokedAt?: unknown; tokenHash?: string }>;
      };
      const row = parsed.devices?.find((device) => device.id === id);
      assert.equal(row?.revokedAt, 1_700_000_000_000, "snapshot keeps revocation");
      assert.equal(legacyHashHit(disk, originalToken), false, "snapshot keeps revocation");
    } finally {
      if (typeof atomicFile.setAtomicFileIoForTesting === "function") {
        atomicFile.setAtomicFileIoForTesting(undefined);
      }
      await store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
