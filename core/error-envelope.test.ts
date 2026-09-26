import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { BODY_LIMIT } from "./constants.ts";
import { pinnedHttps, type PinResponse } from "./https-client.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

function call(
  srv: RunningServer,
  method: string,
  path: string,
  opts: { token?: string; body?: string; origin?: string } = {},
): Promise<PinResponse> {
  return pinnedHttps({
    url: `${srv.url}${path}`,
    method,
    body: opts.body,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body === undefined ? {} : { "content-type": "application/json" }),
      ...(opts.origin ? { origin: opts.origin } : {}),
    },
    caPem: srv.tls.certPem,
    fingerprintSha256: srv.tls.fingerprintSha256,
    timeoutMs: 8000,
    maxBodyBytes: BODY_LIMIT + 4096,
  });
}

describe("core error envelope", () => {
  it("representative failures keep ok:false and the existing error text", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-envelope-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    try {
      const cases: Array<{ name: string; method: string; path: string; token?: string; body?: string; origin?: string; status: number; error: string; ruleIds?: string[] }> = [
        { name: "400", method: "PUT", path: "/api/v1/policy", token: srv.adminToken, body: "{", status: 400, error: "bad_json" },
        {
          name: "400-github",
          method: "PUT",
          path: "/api/v1/policy",
          token: srv.adminToken,
          body: JSON.stringify({ expectedVersion: 1, githubUpload: { mode: "selected", agents: ["invented"] } }),
          status: 400,
          error: "invalid_github_policy",
        },
        {
          name: "400-rule",
          method: "PUT",
          path: "/api/v1/policy",
          token: srv.adminToken,
          body: JSON.stringify({ expectedVersion: 1, overrides: { rules: { not_a_rule: "block" } } }),
          status: 400,
          error: "unknown_rule_override",
          ruleIds: ["not_a_rule"],
        },
        { name: "401", method: "GET", path: "/api/v1/state", status: 401, error: "unauthorized" },
        { name: "403", method: "GET", path: "/api/v1/state", token: srv.adminToken, origin: "https://evil.example", status: 403, error: "origin" },
        { name: "404", method: "GET", path: "/api/v1/missing-envelope", status: 404, error: "not_found" },
        { name: "405", method: "DELETE", path: "/api/v1/network-owners", status: 405, error: "method" },
        {
          name: "409",
          method: "PUT",
          path: "/api/v1/policy",
          token: srv.adminToken,
          body: JSON.stringify({ expectedVersion: 999_999, stopped: false }),
          status: 409,
          error: "cas_conflict",
        },
        {
          name: "413",
          method: "POST",
          path: "/api/v1/network-owners",
          token: srv.adminToken,
          body: "x".repeat(BODY_LIMIT + 1),
          status: 413,
          error: "too_large",
        },
      ];
      for (const item of cases) {
        const res = await call(srv, item.method, item.path, item);
        const body = JSON.parse(res.body) as { ok?: unknown; error?: unknown; ruleIds?: unknown };
        assert.equal(res.status, item.status, item.name);
        assert.equal(body.ok, false, item.name);
        assert.equal(body.error, item.error, item.name);
        if (item.ruleIds) assert.deepEqual(body.ruleIds, item.ruleIds, item.name);
        assert.equal(JSON.stringify(body).includes(srv.adminToken), false, item.name);
      }

      const store = srv.store as { listDevices: () => unknown };
      const original = store.listDevices.bind(srv.store);
      store.listDevices = () => {
        throw new Error("synthetic-envelope");
      };
      try {
        const failed = await call(srv, "GET", "/api/v1/state", { token: srv.adminToken });
        const body = JSON.parse(failed.body) as { ok?: unknown; error?: unknown };
        assert.equal(failed.status, 500);
        assert.equal(body.ok, false);
        assert.equal(body.error, "internal_error");
        assert.equal(failed.body.includes("synthetic-envelope"), false);
      } finally {
        store.listDevices = original;
      }

      const health = await call(srv, "GET", "/health");
      const healthBody = JSON.parse(health.body) as { ok?: unknown; access?: unknown };
      assert.equal(health.status, 200);
      assert.equal(healthBody.ok, true);
      const state = await call(srv, "GET", "/api/v1/state", { token: srv.adminToken });
      const stateBody = JSON.parse(state.body) as { ok?: unknown; access?: unknown };
      assert.equal(state.status, 200);
      assert.equal(stateBody.access, "admin");
      assert.equal(stateBody.ok, undefined);
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
