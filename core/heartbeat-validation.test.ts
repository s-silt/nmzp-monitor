import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { sha256Hex } from "./auth.ts";
import { pinnedHttps } from "./https-client.ts";
import { startLanViewer, type RunningLanViewer } from "./lan-viewer.ts";
import { newProbeBinding, proofMessage } from "./probe-auth.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = import.meta.dirname;

/** Mirrors HEARTBEAT_LIMITS. */
const LIMITS = {
  labelChars: 256,
  agentCount: 256,
  agentChars: 256,
  capabilityCount: 256,
  capabilityIdChars: 48,
  errorChars: 1024,
} as const;

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
  init: { method?: string; token?: string; body?: string; headers?: Record<string, string> } = {},
) {
  const headers: Record<string, string> = { ...init.headers };
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  if (init.body !== undefined && !headers["content-type"]) headers["content-type"] = "application/json";
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
  return { status: res.status, body };
}

async function withServer(run: (srv: RunningServer, dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-m08-"));
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

async function joinDevice(srv: RunningServer, hostname = "synthetic-heartbeat") {
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

async function deviceBytes(dir: string): Promise<Buffer> {
  return readFile(join(dir, "devices.json"));
}

function stateDevices(body: unknown): Array<Record<string, unknown>> {
  const devices = record(body)?.devices;
  assert.equal(Array.isArray(devices), true);
  return devices as Array<Record<string, unknown>>;
}

function oneDevice(body: unknown, id: string): Record<string, unknown> {
  const found = stateDevices(body).find((item) => item.id === id);
  assert.ok(found);
  return found;
}

const realCapabilities = (now: number) => [
  { id: "heartbeat", supported: true, active: true, lastSuccess: now },
  { id: "process_snapshot", supported: true, active: false, error: "unknown" },
  { id: "hook_grok", supported: true, active: false, error: "hook_not_installed" },
  { id: "hook_codex", supported: true, active: false, lastSuccess: now - 1000, error: "offline" },
  { id: "quota", supported: false, active: false, error: "not_collected" },
  { id: "network_sample", supported: true, active: false, error: "not_sampled" },
  { id: "future_sensor", supported: true, active: false, error: "offline", nested: { ignored: true } },
];

describe("heartbeat ingress", () => {
  it("capabilities:[null] heartbeat returns 400 and /api/v1/state stays 200", { timeout: 60_000 }, async () => {
    await withServer(async (srv, dir) => {
      const joined = await joinDevice(srv);
      const before = srv.store.getDevice(joined.deviceId);
      assert.ok(before);
      const bytes = await deviceBytes(dir);
      const hb = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({ capabilities: [null] }),
      });
      assert.equal(hb.status, 400);
      assert.equal(record(hb.body)?.error, "bad_heartbeat");
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const after = srv.store.getDevice(joined.deviceId);
      assert.equal(after?.lastSeen, before.lastSeen);
      assert.equal(after?.tokenHash, before.tokenHash);
      assert.deepEqual(after?.capabilities, []);
      assert.equal((await deviceBytes(dir)).equals(bytes), true);
      const row = oneDevice(state.body, joined.deviceId);
      assert.equal(row.hostname, "synthetic-heartbeat");
      assert.deepEqual(row.capabilities, []);
    });
  });

  it("malformed heartbeat types and oversize fields return 400 without device writes", { timeout: 60_000 }, async () => {
    await withServer(async (srv, dir) => {
      const joined = await joinDevice(srv);
      const before = srv.store.getDevice(joined.deviceId);
      assert.ok(before);
      const bytes = await deviceBytes(dir);
      const cases: Array<[string, string]> = [
        ["null", "null"],
        ["array", "[]"],
        ["number", "1"],
        ["boolean", "true"],
        ["string", JSON.stringify("synthetic")],
        ["bad-json", "{"],
        ["hostname-number", JSON.stringify({ hostname: 1 })],
        ["user-object", JSON.stringify({ user: { name: "fixture" } })],
        ["ip-array", JSON.stringify({ ip: ["127.0.0.1"] })],
        ["agents-string", JSON.stringify({ agents: "grok" })],
        ["agents-number", JSON.stringify({ agents: [1] })],
        ["agents-object", JSON.stringify({ agents: [{ id: "grok" }] })],
        ["capabilities-object", JSON.stringify({ capabilities: { id: "hook_grok" } })],
        ["capabilities-string", JSON.stringify({ capabilities: ["hook_grok"] })],
        ["capability-null", JSON.stringify({ capabilities: [null] })],
        ["capability-active-string", JSON.stringify({ capabilities: [{ id: "hook_grok", supported: true, active: "true" }] })],
        ["capability-missing-active", JSON.stringify({ capabilities: [{ id: "hook_grok", supported: true }] })],
        ["capability-empty-id", JSON.stringify({ capabilities: [{ id: "", supported: true, active: true }] })],
        ["capability-bad-time", JSON.stringify({ capabilities: [{ id: "future_sensor", supported: true, active: true, lastSuccess: "1" }] })],
        ["capability-bad-error", JSON.stringify({ capabilities: [{ id: "future_sensor", supported: true, active: true, error: { nested: true } }] })],
        ["policy-string", JSON.stringify({ policyVersion: "1" })],
        ["policy-null", JSON.stringify({ policyVersion: null })],
        ["poll-string", JSON.stringify({ pollOnly: "true" })],
        ["ack-number", JSON.stringify({ stoppedAck: 1 })],
        ["hostname-oversize", JSON.stringify({ hostname: "h".repeat(LIMITS.labelChars + 1) })],
        ["agent-oversize", JSON.stringify({ agents: ["a".repeat(LIMITS.agentChars + 1)] })],
        ["agents-count", JSON.stringify({ agents: Array.from({ length: LIMITS.agentCount + 1 }, () => "grok") })],
        ["capability-id-oversize", JSON.stringify({ capabilities: [{ id: "a".repeat(LIMITS.capabilityIdChars + 1), supported: true, active: true }] })],
        ["error-oversize", JSON.stringify({ capabilities: [{ id: "future_sensor", supported: true, active: false, error: "e".repeat(LIMITS.errorChars + 1) }] })],
        ["capabilities-count", JSON.stringify({ capabilities: Array.from({ length: LIMITS.capabilityCount + 1 }, () => ({ id: "future_sensor", supported: true, active: false })) })],
      ];
      for (const [label, payload] of cases) {
        const res = await call(srv, "/api/v1/heartbeat", { method: "POST", token: joined.deviceToken, body: payload });
        assert.equal(res.status, 400, label);
        assert.equal(record(res.body)?.error, label === "bad-json" ? "bad_json" : "bad_heartbeat", label);
        assert.equal(srv.store.getDevice(joined.deviceId)?.lastSeen, before.lastSeen, label);
        assert.equal(srv.store.getDevice(joined.deviceId)?.tokenHash, before.tokenHash, label);
        assert.equal((await deviceBytes(dir)).equals(bytes), true, label);
      }
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
    });
  });

  it("valid probe-shaped heartbeat retains fields and does not adopt identity from the body", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const joined = await joinDevice(srv);
      const before = srv.store.getDevice(joined.deviceId);
      assert.ok(before);
      const now = Date.now();
      const sent = {
        hostname: "retained-host",
        user: "retained-user",
        ip: "203.0.113.10",
        agents: ["grok", "future"],
        agentProcs: [{ agent: "not-a-proc" }],
        capabilities: realCapabilities(now),
        os: "darwin",
        policyVersion: before.lastPolicyVersion,
        stoppedAck: false,
        id: "forged-id",
        tokenHash: "ab".repeat(32),
        token: "forged-token",
        deviceId: "forged-device",
        discovery: { schemaVersion: "nope" },
        network: { status: "not-a-real-status" },
        snapshotGuard: {
          supported: true,
          active: false,
          managed: false,
          targetPresent: false,
          writeBlocked: false,
          existingArchiveCoverage: "none",
          lastVerified: 111,
          error: "not_verified",
        },
      };
      const hb = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify(sent),
      });
      assert.equal(hb.status, 200);
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const row = oneDevice(state.body, joined.deviceId);
      assert.equal(row.hostname, "retained-host");
      assert.equal(row.user, "retained-user");
      assert.equal(row.ip, "203.0.113.10");
      assert.equal(row.os, "linux");
      assert.deepEqual(row.agents, ["grok", "future"]);
      assert.deepEqual(row.agentProcs, []);
      assert.equal("discovery" in row, false);
      assert.equal("network" in row, false);
      assert.equal((row.snapshotGuard as { lastVerified?: number }).lastVerified, 111);
      const caps = row.capabilities as Array<Record<string, unknown>>;
      assert.equal(caps.find((item) => item.id === "future_sensor")?.active, false);
      assert.equal(caps.find((item) => item.id === "heartbeat")?.active, true);
      assert.equal(caps.some((item) => item.nested !== undefined), false);
      assert.equal(JSON.stringify(state.body).includes("forged-token"), false);
      const stored = srv.store.getDevice(joined.deviceId);
      assert.equal(stored?.id, joined.deviceId);
      assert.equal(stored?.tokenHash, before.tokenHash);
      assert.equal(stored?.id === "forged-id", false);
      const again = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({}),
      });
      assert.equal(again.status, 200);
      const kept = oneDevice((await call(srv, "/api/v1/state", { token: srv.adminToken })).body, joined.deviceId);
      assert.equal(kept.hostname, "retained-host");
      assert.deepEqual(kept.agents, ["grok", "future"]);
      assert.equal((kept.capabilities as Array<{ id: string }>).some((item) => item.id === "future_sensor"), true);
      assert.equal((await call(srv, "/api/v1/policy", { token: joined.deviceToken })).status, 200);
      assert.equal((await call(srv, "/api/v1/policy", { token: "forged-token" })).status, 401);
    });
  });

  it("pollOnly keeps stored presentation and a malformed poll does not move lastSeen", { timeout: 60_000 }, async () => {
    await withServer(async (srv, dir) => {
      const joined = await joinDevice(srv);
      const now = Date.now();
      assert.equal(
        (await call(srv, "/api/v1/heartbeat", {
          method: "POST",
          token: joined.deviceToken,
          body: JSON.stringify({
            hostname: "kept-host",
            user: "kept-user",
            agents: ["grok"],
            capabilities: [{ id: "heartbeat", supported: true, active: true, lastSuccess: now }],
            snapshotGuard: {
              supported: true,
              active: false,
              managed: false,
              targetPresent: false,
              writeBlocked: false,
              existingArchiveCoverage: "none",
              lastVerified: 111,
              error: "not_verified",
            },
          }),
        })).status,
        200,
      );
      const current = await call(srv, "/api/v1/state", { token: srv.adminToken });
      const version = record(current.body)?.policyVersion;
      assert.equal(typeof version, "number");
      const stopped = await call(srv, "/api/v1/policy", {
        method: "PUT",
        token: srv.adminToken,
        body: JSON.stringify({ expectedVersion: version, stopped: true }),
      });
      assert.equal(stopped.status, 200);
      const stoppedVersion = record(stopped.body)?.version;
      const pending = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({ pollOnly: true, stoppedAck: true }),
      });
      assert.equal(pending.status, 200);
      assert.notEqual(record(pending.body)?.stopState, "stop_confirmed");
      const confirmed = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({
          pollOnly: true,
          stoppedAck: true,
          policyVersion: stoppedVersion,
          hostname: "poll-host",
          user: "poll-user",
          agents: ["other"],
          capabilities: [{ id: "future_sensor", supported: true, active: true }],
          snapshotGuard: {
            supported: true,
            active: false,
            managed: false,
            targetPresent: false,
            writeBlocked: false,
            existingArchiveCoverage: "none",
            lastVerified: 999,
            error: "not_verified",
          },
        }),
      });
      assert.equal(confirmed.status, 200);
      assert.equal(record(confirmed.body)?.stopState, "stop_confirmed");
      const row = oneDevice((await call(srv, "/api/v1/state", { token: srv.adminToken })).body, joined.deviceId);
      assert.equal(row.hostname, "kept-host");
      assert.equal(row.user, "kept-user");
      assert.deepEqual(row.agents, ["grok"]);
      assert.deepEqual(row.capabilities, [{ id: "heartbeat", supported: true, active: true, lastSuccess: now }]);
      assert.equal((row.snapshotGuard as { lastVerified?: number }).lastVerified, 111);
      const seen = srv.store.getDevice(joined.deviceId)?.lastSeen;
      const bytes = await deviceBytes(dir);
      const bad = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({ pollOnly: true, capabilities: [null] }),
      });
      assert.equal(bad.status, 400);
      assert.equal(record(bad.body)?.error, "bad_heartbeat");
      assert.equal(srv.store.getDevice(joined.deviceId)?.lastSeen, seen);
      assert.equal((await deviceBytes(dir)).equals(bytes), true);
      const still = oneDevice((await call(srv, "/api/v1/state", { token: srv.adminToken })).body, joined.deviceId);
      assert.equal(still.hostname, "kept-host");
      assert.equal((still.capabilities as Array<{ id: string }>)[0]?.id, "heartbeat");
    });
  });

  it("probe binding still requires proof before a malformed heartbeat is rejected", { timeout: 60_000 }, async () => {
    await withServer(async (srv, dir) => {
      const joined = await joinDevice(srv);
      const pair = generateKeyPairSync("ed25519");
      const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
      const privateKey = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      const binding = newProbeBinding(publicKey);
      const enrolled = await call(srv, "/api/v1/probe/binding", {
        method: "POST",
        token: srv.adminToken,
        body: JSON.stringify({ deviceId: joined.deviceId, action: "enroll", publicKey }),
      });
      assert.equal(enrolled.status, 200);
      const seen = srv.store.getDevice(joined.deviceId)?.lastSeen;
      const hash = srv.store.getDevice(joined.deviceId)?.tokenHash;
      const bytes = await deviceBytes(dir);
      const unsigned = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: JSON.stringify({ capabilities: [null] }),
      });
      assert.equal(unsigned.status, 401);
      assert.equal(record(unsigned.body)?.error, "probe_proof_required");
      assert.equal(srv.store.getDevice(joined.deviceId)?.lastSeen, seen);
      const malformed = JSON.stringify({ capabilities: [null] });
      const challenge = await call(srv, "/api/v1/probe/challenge", { token: joined.deviceToken });
      assert.equal(challenge.status, 200);
      const nonce = record(challenge.body)?.nonce;
      assert.equal(typeof nonce, "string");
      assert.equal(record(challenge.body)?.keyId, binding.keyId);
      const signature = sign(null, proofMessage(joined.deviceId, binding.keyId, nonce as string, malformed), privateKey).toString("base64");
      const headers = { "x-nmzp-challenge": nonce as string, "x-nmzp-signature": signature };
      const proved = await call(srv, "/api/v1/heartbeat", { method: "POST", token: joined.deviceToken, body: malformed, headers });
      assert.equal(proved.status, 400);
      assert.equal(record(proved.body)?.error, "bad_heartbeat");
      const replay = await call(srv, "/api/v1/heartbeat", { method: "POST", token: joined.deviceToken, body: malformed, headers });
      assert.equal(replay.status, 401);
      assert.equal(srv.store.getDevice(joined.deviceId)?.lastSeen, seen);
      assert.equal(srv.store.getDevice(joined.deviceId)?.tokenHash, hash);
      assert.equal((await deviceBytes(dir)).equals(bytes), true);
      const goodBody = JSON.stringify({ hostname: "signed-host", capabilities: [{ id: "future_sensor", supported: true, active: false, error: "offline" }] });
      const next = await call(srv, "/api/v1/probe/challenge", { token: joined.deviceToken });
      const nextNonce = record(next.body)?.nonce;
      assert.equal(typeof nextNonce, "string");
      const goodSig = sign(null, proofMessage(joined.deviceId, binding.keyId, nextNonce as string, goodBody), privateKey).toString("base64");
      const good = await call(srv, "/api/v1/heartbeat", {
        method: "POST",
        token: joined.deviceToken,
        body: goodBody,
        headers: { "x-nmzp-challenge": nextNonce as string, "x-nmzp-signature": goodSig },
      });
      assert.equal(good.status, 200);
      const row = oneDevice((await call(srv, "/api/v1/state", { token: srv.adminToken })).body, joined.deviceId);
      assert.equal(row.hostname, "signed-host");
      assert.equal((row.capabilities as Array<{ id: string; active: boolean }>).find((item) => item.id === "future_sensor")?.active, false);
      assert.equal(srv.store.getDevice(joined.deviceId)?.tokenHash, hash);
      assert.ok((srv.store.getDevice(joined.deviceId)?.lastSeen ?? 0) >= (seen ?? 0));
    });
  });
});

describe("legacy malformed device projection", () => {
  it("legacy malformed device fixture keeps /api/v1/state at 200", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-m08-legacy-"));
    const legacyToken = "legacy-device-token";
    const cleanToken = "clean-device-token";
    const legacyHash = sha256Hex(legacyToken);
    const cleanHash = sha256Hex(cleanToken);
    const seen = 1_700_000_000_000;
    const devices = {
      snapshotVersion: 1,
      networkHistory: [],
      devices: [
        {
          id: "legacy-device",
          tokenHash: legacyHash,
          hostname: { bad: true },
          ip: 12,
          user: null,
          os: "linux",
          attachedAt: seen,
          lastSeen: seen,
          lastPolicyVersion: 1,
          capabilities: [
            null,
            { id: "hook_claude", supported: "yes", active: true },
            { id: "hook_codex", active: true },
            { id: "hook_grok", supported: true, active: true, error: { nested: true } },
            { id: "not a valid id", supported: true, active: true },
            { id: "future_sensor", supported: true, active: false, error: "offline" },
            { id: "hook_zcode", supported: true, active: true, lastSuccess: seen },
          ],
          agents: ["grok", 7, { x: 1 }, "claude"],
          snapshotGuard: {
            supported: true,
            active: false,
            managed: false,
            targetPresent: false,
            writeBlocked: false,
            existingArchiveCoverage: "none",
            lastVerified: 111,
            error: "not_verified",
          },
        },
        {
          id: "clean-device",
          tokenHash: cleanHash,
          hostname: "clean-host",
          ip: "127.0.0.1",
          user: "clean",
          os: "win32",
          attachedAt: seen,
          lastSeen: seen,
          lastPolicyVersion: 1,
          capabilities: [{ id: "heartbeat", supported: true, active: true, lastSuccess: seen }],
          agents: ["claude"],
        },
      ],
    };
    const path = join(dir, "devices.json");
    await writeFile(path, JSON.stringify(devices, null, 2));
    const before = await readFile(path);
    let srv: RunningServer | undefined;
    let viewer: RunningLanViewer | undefined;
    try {
      srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
      viewer = await startLanViewer({
        host: "127.0.0.1",
        port: 0,
        allowedCidrs: ["127.0.0.0/8"],
        uiDir: null,
        ctUrl: srv.url,
        caPem: srv.tls.certPem,
        fingerprintSha256: srv.tls.fingerprintSha256,
        adminToken: srv.adminToken,
        timeoutMs: 10_000,
      });
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const rows = stateDevices(state.body);
      assert.deepEqual(rows.map((item) => item.id).sort(), ["clean-device", "legacy-device"]);
      const legacy = oneDevice(state.body, "legacy-device");
      const caps = legacy.capabilities as Array<{ id: string; active: boolean }>;
      assert.deepEqual(caps.map((item) => item.id).sort(), ["future_sensor", "hook_zcode"]);
      assert.equal(caps.find((item) => item.id === "hook_zcode")?.active, true);
      assert.equal(caps.find((item) => item.id === "future_sensor")?.active, false);
      assert.equal(caps.some((item) => item.id === "hook_grok" || item.id === "hook_claude" || item.id === "hook_codex"), false);
      assert.equal(legacy.hostname, "");
      assert.equal(legacy.ip, "");
      assert.equal(legacy.user, "");
      assert.deepEqual(legacy.agents, ["grok", "claude"]);
      assert.equal((legacy.snapshotGuard as { lastVerified?: number }).lastVerified, 111);
      const flags = record(state.body)?.capabilities as Record<string, { active?: boolean }>;
      assert.equal(flags.hookGrok?.active, false);
      assert.equal(flags.hookClaude?.active, false);
      assert.equal(flags.hookCodex?.active, false);
      const clean = oneDevice(state.body, "clean-device");
      assert.equal(clean.hostname, "clean-host");
      assert.equal((clean.capabilities as Array<{ id: string; active: boolean }>)[0]?.active, true);
      assert.equal(JSON.stringify(state.body).includes(legacyHash), false);
      assert.equal(JSON.stringify(state.body).includes(legacyToken), false);
      const disk = JSON.parse((await readFile(path)).toString()) as { devices: Array<Record<string, unknown>> };
      assert.equal(disk.devices[0]?.id, "legacy-device");
      assert.equal(disk.devices[0]?.tokenHash, legacyHash);
      assert.equal(disk.devices[1]?.tokenHash, cleanHash);
      assert.equal((disk.devices[0]?.capabilities as unknown[])[0], null);
      assert.equal((await readFile(path)).equals(before), true);
      assert.equal(srv.store.getDevice("legacy-device")?.tokenHash, legacyHash);
      assert.equal(srv.store.getDevice("clean-device")?.tokenHash, cleanHash);
      assert.equal((await call(srv, "/api/v1/policy", { token: legacyToken })).status, 200);
      assert.equal((await call(srv, "/api/v1/policy", { token: cleanToken })).status, 200);
      assert.equal((await call(srv, "/api/v1/policy", { token: "wrong-token" })).status, 401);
      const viewed = await fetch(`${viewer.url}/api/v1/state`);
      assert.equal(viewed.status, 200);
      const viewerBody = await viewed.json() as { devices?: Array<Record<string, unknown>> };
      const viewerLegacy = viewerBody.devices?.find((item) => item.id === "legacy-device");
      const viewerCaps = (viewerLegacy?.capabilities ?? []) as Array<{ id: string; active: boolean }>;
      assert.deepEqual(viewerCaps.map((item) => item.id).sort(), ["future_sensor", "hook_zcode"]);
      assert.equal(viewerCaps.find((item) => item.id === "hook_zcode")?.active, true);
      assert.equal(viewerCaps.some((item) => item.active && item.id !== "hook_zcode"), false);
      assert.equal(JSON.stringify(viewerBody).includes(legacyToken), false);
      assert.equal(JSON.stringify(viewerBody).includes(legacyHash), false);
      assert.equal((await readFile(path)).equals(before), true);
    } finally {
      try {
        await viewer?.close();
      } finally {
        try {
          await srv?.close();
        } finally {
          await rm(dir, { recursive: true, force: true });
        }
      }
    }
  });
});
