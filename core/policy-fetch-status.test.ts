import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { pinnedHttps } from "./https-client.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = import.meta.dirname;

function assertRecord(body: unknown): Record<string, unknown> {
  assert.ok(body && typeof body === "object" && !Array.isArray(body));
  return body as Record<string, unknown>;
}

function safeInteger(value: unknown, message: string): number {
  assert.equal(typeof value, "number", message);
  assert.equal(Number.isSafeInteger(value), true, message);
  return value as number;
}

function oneDevice(body: unknown, id: string): Record<string, unknown> {
  const devices = assertRecord(body).devices;
  assert.equal(Array.isArray(devices), true);
  const found = (devices as unknown[]).find((item) => {
    return !!item && typeof item === "object" && !Array.isArray(item) && (item as { id?: unknown }).id === id;
  });
  assert.ok(found && typeof found === "object" && !Array.isArray(found));
  return found as Record<string, unknown>;
}

async function call(
  srv: RunningServer,
  path: string,
  init: { method?: string; token?: string; body?: string } = {},
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {};
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await pinnedHttps({
    url: `${srv.url}${path}`,
    method: init.method ?? "GET",
    headers,
    body: init.body,
    caPem: srv.tls.certPem,
    fingerprintSha256: srv.tls.fingerprintSha256,
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

async function withServer(run: (srv: RunningServer) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-m06-"));
  let srv: RunningServer | undefined;
  try {
    srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    await run(srv);
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
  const ticketValue = assertRecord(ticket.body).ticket;
  assert.equal(typeof ticketValue, "string");
  const joined = await call(srv, "/api/v1/join", {
    method: "POST",
    body: JSON.stringify({ ticket: ticketValue, hostname, user: "fixture", os: "linux" }),
  });
  assert.equal(joined.status, 200);
  const body = assertRecord(joined.body);
  assert.equal(typeof body.deviceId, "string");
  assert.equal(typeof body.deviceToken, "string");
  return { deviceId: body.deviceId as string, deviceToken: body.deviceToken as string };
}

async function heartbeat(srv: RunningServer, token: string, body: Record<string, unknown>) {
  return call(srv, "/api/v1/heartbeat", { method: "POST", token, body: JSON.stringify(body) });
}

async function observedVersion(srv: RunningServer, deviceId: string): Promise<number> {
  const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
  assert.equal(state.status, 200);
  const fromState = safeInteger(oneDevice(state.body, deviceId).lastPolicyVersion, "state lastPolicyVersion");
  assert.equal(srv.store.getDevice(deviceId)?.lastPolicyVersion, fromState, "state lastPolicyVersion matches the store");
  return fromState;
}

describe("probe reported policy fetch", () => {
  it("join alone is not counted as fetched", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const joined = await joinDevice(srv, "fetch-join");
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const row = oneDevice(state.body, joined.deviceId);
      const policyVersion = safeInteger(assertRecord(state.body).policyVersion, "policy version");
      assert.ok(policyVersion >= 1);
      assert.equal(row.hostname, "fetch-join");
      assert.equal(row.user, "fixture");
      assert.equal(row.os, "linux");
      assert.equal(row.lastPolicyVersion, 0, "join alone leaves lastPolicyVersion at 0");
      assert.equal(
        srv.store.getDevice(joined.deviceId)?.lastPolicyVersion,
        0,
        "join alone leaves lastPolicyVersion at 0",
      );
      assert.notEqual(row.lastPolicyVersion, policyVersion);
    });
  });

  it("future reported policy version does not overwrite the stored version", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const joined = await joinDevice(srv, "fetch-future");
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const policyVersion = safeInteger(assertRecord(state.body).policyVersion, "policy version");
      const before = await observedVersion(srv, joined.deviceId);
      const normal = await heartbeat(srv, joined.deviceToken, {});
      assert.equal(normal.status, 200);
      assert.equal(assertRecord(normal.body).policyVersion, policyVersion);
      assert.equal(await observedVersion(srv, joined.deviceId), before, "plain heartbeat keeps the stored version");

      const futureVersion = policyVersion + 5;
      const future = await heartbeat(srv, joined.deviceToken, { policyVersion: futureVersion });
      assert.equal(future.status, normal.status, "future policyVersion keeps the heartbeat status");
      assert.equal(future.status, 200);
      assert.equal(
        await observedVersion(srv, joined.deviceId),
        before,
        "future reported policy version must not overwrite the stored version",
      );

      const polled = await heartbeat(srv, joined.deviceToken, { pollOnly: true, policyVersion: futureVersion });
      assert.equal(polled.status, 200);
      assert.equal(
        await observedVersion(srv, joined.deviceId),
        before,
        "future reported policy version must not overwrite the stored version",
      );

      const valid = await heartbeat(srv, joined.deviceToken, { policyVersion });
      assert.equal(valid.status, 200);
      assert.equal(await observedVersion(srv, joined.deviceId), policyVersion);

      const again = await heartbeat(srv, joined.deviceToken, { policyVersion: futureVersion });
      assert.equal(again.status, 200);
      assert.equal(
        await observedVersion(srv, joined.deviceId),
        policyVersion,
        "future reported policy version must not overwrite the stored version",
      );

      const fraction = await heartbeat(srv, joined.deviceToken, { policyVersion: policyVersion - 0.5 });
      assert.equal(fraction.status, 200);
      assert.equal(
        await observedVersion(srv, joined.deviceId),
        policyVersion,
        "non-integer policyVersion is not recorded",
      );
    });
  });

  it("valid reported version is recorded", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const full = await joinDevice(srv, "fetch-valid-full");
      const polled = await joinDevice(srv, "fetch-valid-poll");
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const policyVersion = safeInteger(assertRecord(state.body).policyVersion, "policy version");
      assert.ok(policyVersion >= 1);

      const reported = await heartbeat(srv, full.deviceToken, { policyVersion });
      assert.equal(reported.status, 200);
      assert.equal(assertRecord(reported.body).policyVersion, policyVersion);
      assert.equal(await observedVersion(srv, full.deviceId), policyVersion);

      const quiet = await heartbeat(srv, polled.deviceToken, { pollOnly: true, policyVersion });
      assert.equal(quiet.status, 200);
      assert.equal(await observedVersion(srv, polled.deviceId), policyVersion);

      const older = await heartbeat(srv, full.deviceToken, { policyVersion: 0 });
      assert.equal(older.status, 200);
      assert.equal(await observedVersion(srv, full.deviceId), 0);
    });
  });

  it("stopped acknowledgement still requires the exact version", { timeout: 60_000 }, async () => {
    await withServer(async (srv) => {
      const joined = await joinDevice(srv, "fetch-stop");
      const state = await call(srv, "/api/v1/state", { token: srv.adminToken });
      assert.equal(state.status, 200);
      const previous = safeInteger(assertRecord(state.body).policyVersion, "policy version");
      const stopped = await call(srv, "/api/v1/policy", {
        method: "PUT",
        token: srv.adminToken,
        body: JSON.stringify({ expectedVersion: previous, stopped: true }),
      });
      assert.equal(stopped.status, 200);
      const current = safeInteger(assertRecord(stopped.body).version, "stopped version");
      assert.ok(current > previous);

      const fetched = await heartbeat(srv, joined.deviceToken, { policyVersion: current });
      assert.equal(fetched.status, 200);
      assert.notEqual(assertRecord(fetched.body).stopState, "stop_confirmed");
      assert.equal(await observedVersion(srv, joined.deviceId), current);

      const ahead = await heartbeat(srv, joined.deviceToken, { stoppedAck: true, policyVersion: current + 5 });
      assert.equal(ahead.status, 200);
      assert.notEqual(assertRecord(ahead.body).stopState, "stop_confirmed", "a future version does not acknowledge stop");

      const older = await heartbeat(srv, joined.deviceToken, { stoppedAck: true, policyVersion: previous });
      assert.equal(older.status, 200);
      assert.notEqual(assertRecord(older.body).stopState, "stop_confirmed", "an older version does not acknowledge stop");
      assert.notEqual(srv.store.getDevice(joined.deviceId)?.stoppedAck, true);

      const exact = await heartbeat(srv, joined.deviceToken, { stoppedAck: true, policyVersion: current });
      assert.equal(exact.status, 200);
      assert.equal(assertRecord(exact.body).stopState, "stop_confirmed", "the exact version acknowledges stop");
      assert.equal(srv.store.getDevice(joined.deviceId)?.stoppedAck, true);
      assert.equal(srv.store.getDevice(joined.deviceId)?.stopAckVersion, current);
    });
  });
});
