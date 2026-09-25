import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { startAdminProxy, type RunningProxy } from "./admin-proxy.ts";

const TOKEN = "admin-token-fixture";

async function start(): Promise<RunningProxy> {
  return startAdminProxy({
    ctUrl: "https://127.0.0.1:1",
    caPem: "not-a-cert",
    fingerprintSha256: "ab".repeat(32),
    adminToken: TOKEN,
    host: "127.0.0.1",
    port: 0,
    uiDir: null,
  });
}

function sessionCookie(headers: Headers): string {
  const listed = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  const raw = listed[0] ?? headers.get("set-cookie") ?? "";
  const cookie = raw.split(";", 1)[0] ?? "";
  assert.equal(cookie.startsWith("nmzp_proxy="), true);
  return cookie;
}

describe("admin proxy session boundary", () => {
  it("rejects a wrong admin token on POST /api/v1/session", async () => {
    const proxy = await start();
    try {
      const wrong = await fetch(`${proxy.url}/api/v1/session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: "wrong-token" }),
      });
      assert.equal(wrong.status, 401);
      const body = (await wrong.json()) as { error?: string };
      assert.equal(body.error, "unauthorized");
    } finally {
      await proxy.close();
    }
  });

  it("rejects an expired proxy session", async (t) => {
    const proxy = await start();
    t.mock.timers.enable({ apis: ["Date"], now: 1_700_000_000_000 });
    try {
      const login = await fetch(`${proxy.url}/api/v1/session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: TOKEN }),
      });
      assert.equal(login.status, 200);
      const cookie = sessionCookie(login.headers);
      const before = await fetch(`${proxy.url}/api/v1/evaluate`, { headers: { cookie } });
      assert.equal(before.status, 403);
      t.mock.timers.tick(12 * 60 * 60 * 1000 + 1);
      const after = await fetch(`${proxy.url}/api/v1/evaluate`, { headers: { cookie } });
      assert.equal(after.status, 401);
      const body = (await after.json()) as { error?: string };
      assert.equal(body.error, "unauthorized");
    } finally {
      t.mock.timers.reset();
      await proxy.close();
    }
  });
});
