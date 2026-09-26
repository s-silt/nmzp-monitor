import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseApiState, readDeviceRevocation, revokeDeviceApi, type ApiDevice } from "./api.ts";

function device(over: Partial<ApiDevice> & Record<string, unknown> = {}): ApiDevice {
  return {
    id: "dev_fixture",
    hostname: "synthetic-host",
    ip: "127.0.0.1",
    user: "fixture",
    os: "linux",
    lastSeen: 1,
    attachedAt: 1,
    status: "online",
    capabilities: [],
    agents: [],
    ...over,
  };
}

describe("device revocation mapping", () => {
  it("maps revoked fields and drops credential material", () => {
    assert.deepEqual(readDeviceRevocation({ revoked: false, revokedAt: null }), { revoked: false, revokedAt: null });
    assert.deepEqual(readDeviceRevocation({ revokedAt: 1_700_000_000_000 }), { revoked: true, revokedAt: 1_700_000_000_000 });
    assert.deepEqual(readDeviceRevocation({ revoked: true, revokedAt: 1.5 }), { revoked: true, revokedAt: null });
    assert.deepEqual(readDeviceRevocation({ revokedAt: 0 }), { revoked: false, revokedAt: null });

    const parsed = parseApiState({
      policyVersion: 1,
      mode: "enforcing",
      stopped: false,
      devices: [{ ...device(), revoked: true, revokedAt: 1_700_000_000_000, tokenHash: "ab".repeat(32), probeBinding: { publicKey: "hidden" } }],
      events: [],
    });
    assert.ok(parsed);
    const row = parsed.devices[0] as ApiDevice & { tokenHash?: string; probeBinding?: unknown };
    assert.equal(row.revoked, true);
    assert.equal(row.revokedAt, 1_700_000_000_000);
    assert.equal("tokenHash" in row, false);
    assert.equal("probeBinding" in row, false);
    const mapped = { id: row.id, hostname: row.hostname, ...readDeviceRevocation(row) };
    assert.deepEqual(
      { id: mapped.id, hostname: mapped.hostname, revoked: mapped.revoked, revokedAt: mapped.revokedAt },
      { id: "dev_fixture", hostname: "synthetic-host", revoked: true, revokedAt: 1_700_000_000_000 },
    );
    assert.equal(JSON.stringify(mapped).includes("ab".repeat(32)), false);
  });

  it("posts the revoke call with only the device id", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return new Response(JSON.stringify({ ok: true, alreadyRevoked: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    try {
      const result = await revokeDeviceApi("dev_fixture");
      assert.equal(result.ok, true);
      if (result.ok) assert.equal(result.alreadyRevoked, false);
      assert.equal(calls.length, 1);
      assert.equal(calls[0]?.url, "/api/v1/devices/revoke");
      assert.equal(calls[0]?.init.method, "POST");
      assert.equal(calls[0]?.init.credentials, "include");
      assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { deviceId: "dev_fixture" });
      assert.equal(String(calls[0]?.init.body).includes("token"), false);
    } finally {
      globalThis.fetch = original;
    }
  });

});
