import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { startServer, type RunningServer } from "./serve.ts";
import { pinnedHttps } from "./https-client.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

type DeviceRow = { id: string; hostname: string; ip: string; user: string; os: string };

function record(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

function pinOf(srv: RunningServer) {
  return { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
}

async function withServer(run: (srv: RunningServer) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-join-validation-"));
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

async function readJson(srv: RunningServer, path: string, init: { method?: string; body?: string; admin?: boolean }) {
  const headers: Record<string, string> = {};
  if (init.admin) headers.authorization = `Bearer ${srv.adminToken}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const res = await pinnedHttps({
    url: `${srv.url}${path}`,
    method: init.method ?? "GET",
    headers,
    body: init.body,
    ...pinOf(srv),
    timeoutMs: 5000,
  });
  let body: unknown = null;
  try {
    body = JSON.parse(res.body);
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

async function issueTicket(srv: RunningServer): Promise<string> {
  const res = await readJson(srv, "/api/v1/ticket", { method: "POST", admin: true });
  assert.equal(res.status, 200);
  const ticket = record(res.body)?.ticket;
  assert.equal(typeof ticket === "string" && ticket.length > 0, true);
  return ticket as string;
}

function postJoin(srv: RunningServer, body: unknown) {
  return readJson(srv, "/api/v1/join", { method: "POST", body: JSON.stringify(body) });
}

async function devices(srv: RunningServer): Promise<DeviceRow[]> {
  const res = await readJson(srv, "/api/v1/state", { admin: true });
  assert.equal(res.status, 200);
  const list = record(res.body)?.devices;
  assert.equal(Array.isArray(list), true);
  return list as DeviceRow[];
}

async function device(srv: RunningServer, id: unknown): Promise<DeviceRow> {
  assert.equal(typeof id, "string");
  const row = (await devices(srv)).find((item) => item.id === id);
  assert.ok(row);
  return row;
}

async function rejectStored(srv: RunningServer, malformed: unknown, ticket: string): Promise<void> {
  const before = (await devices(srv)).length;
  const bad = await postJoin(srv, malformed);
  assert.equal(bad.status, 400);
  assert.equal(record(bad.body)?.error, "bad_json");
  assert.equal((await devices(srv)).length, before);
  const good = await postJoin(srv, { ticket, hostname: "synthetic-valid", user: "fixture", os: "linux" });
  assert.equal(good.status, 200);
}

describe("join ticket is consumed only after the body validates", () => {
  it("malformed hostname does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const bad = await postJoin(srv, { ticket, hostname: { synthetic: true } });
      assert.equal(bad.status, 400);
      assert.equal(record(bad.body)?.ok, false);
      assert.equal(record(bad.body)?.error, "bad_json");
      assert.equal((await devices(srv)).length, 0);
      const good = await postJoin(srv, { ticket, hostname: "synthetic-valid", user: "fixture", os: "linux" });
      assert.equal(good.status, 200);
      const row = await device(srv, record(good.body)?.deviceId);
      assert.equal(row.hostname, "synthetic-valid");
      assert.equal(row.user, "fixture");
      assert.equal(row.os, "linux");
    });
  });

  it("malformed user does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const user of [{ synthetic: true }, 7, ["fixture"], true]) {
        const ticket = await issueTicket(srv);
        await rejectStored(srv, { ticket, hostname: "synthetic-valid", user, os: "linux" }, ticket);
      }
    });
  });

  it("malformed ip does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const ip of [{ synthetic: true }, 7, ["203.0.113.10"], false]) {
        const ticket = await issueTicket(srv);
        await rejectStored(srv, { ticket, hostname: "synthetic-valid", ip }, ticket);
      }
    });
  });

  it("null malformed body does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const bad = await postJoin(srv, null);
      assert.equal(bad.status, 400);
      assert.equal(record(bad.body)?.error, "bad_json");
      const good = await postJoin(srv, { ticket, hostname: "synthetic-valid", user: "fixture", os: "linux" });
      assert.equal(good.status, 200);
    });
  });

  it("array malformed body does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const bad = await postJoin(srv, [{ ticket, hostname: "synthetic-valid" }]);
      assert.equal(bad.status, 400);
      assert.equal(record(bad.body)?.error, "bad_json");
      const good = await postJoin(srv, { ticket, hostname: "synthetic-valid", user: "fixture", os: "win32" });
      assert.equal(good.status, 200);
      assert.equal((await device(srv, record(good.body)?.deviceId)).os, "win32");
    });
  });

  it("primitive malformed body does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const body of ["synthetic", 1, true]) {
        const ticket = await issueTicket(srv);
        const bad = await postJoin(srv, body);
        assert.equal(bad.status, 400);
        assert.equal(record(bad.body)?.error, "bad_json");
        const good = await postJoin(srv, { ticket, hostname: "synthetic-valid" });
        assert.equal(good.status, 200);
      }
    });
  });

  it("other malformed hostname types do not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const hostname of [12, true, ["synthetic-valid"]]) {
        const ticket = await issueTicket(srv);
        await rejectStored(srv, { ticket, hostname }, ticket);
      }
    });
  });

  it("malformed os does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const os of [{ name: "linux" }, ["linux"], 1, true]) {
        const ticket = await issueTicket(srv);
        await rejectStored(srv, { ticket, hostname: "synthetic-valid", os }, ticket);
      }
    });
  });

  it("omitted join fields keep accepted defaults", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const created = await postJoin(srv, { ticket, unexpected: { keep: true } });
      assert.equal(created.status, 200);
      const row = await device(srv, record(created.body)?.deviceId);
      assert.equal(row.hostname, "host");
      assert.equal(row.user, "");
      assert.equal(row.ip, "");
      assert.equal(row.os, "win32");
    });
  });

  it("null join fields keep accepted defaults", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const created = await postJoin(srv, { ticket, hostname: null, user: null, ip: null, os: null });
      assert.equal(created.status, 200);
      const row = await device(srv, record(created.body)?.deviceId);
      assert.equal(row.hostname, "host");
      assert.equal(row.user, "");
      assert.equal(row.ip, "");
      assert.equal(row.os, "win32");
      const reuse = await postJoin(srv, { ticket, hostname: "synthetic-valid" });
      assert.equal(reuse.status, 401);
      assert.equal(record(reuse.body)?.error, "join_ticket_invalid");
    });
  });

  it("empty strings and unknown os strings keep accepted defaults", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const emptyTicket = await issueTicket(srv);
      const empty = await postJoin(srv, { ticket: emptyTicket, hostname: "", user: "", ip: "", os: "" });
      assert.equal(empty.status, 200);
      const emptyRow = await device(srv, record(empty.body)?.deviceId);
      assert.equal(emptyRow.hostname, "");
      assert.equal(emptyRow.user, "");
      assert.equal(emptyRow.ip, "");
      assert.equal(emptyRow.os, "win32");

      for (const os of ["freebsd", "win32 "]) {
        const ticket = await issueTicket(srv);
        const created = await postJoin(srv, { ticket, hostname: "synthetic-valid", os });
        assert.equal(created.status, 200);
        assert.equal((await device(srv, record(created.body)?.deviceId)).os, "win32");
      }
    });
  });

  it("hostname user and ip keep truncation at 80 and 64", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const exactHost = "h".repeat(80);
      const exactUser = "u".repeat(64);
      const exactIp = "1".repeat(64);
      const exact = await postJoin(srv, {
        ticket: await issueTicket(srv),
        hostname: exactHost,
        user: exactUser,
        ip: exactIp,
        os: "linux",
      });
      assert.equal(exact.status, 200);
      const exactRow = await device(srv, record(exact.body)?.deviceId);
      assert.equal(exactRow.hostname, exactHost);
      assert.equal(exactRow.user, exactUser);
      assert.equal(exactRow.ip, exactIp);
      assert.equal(exactRow.os, "linux");

      const longHost = `${exactHost}Z`;
      const longUser = `${exactUser}Z`;
      const longIp = `${exactIp}Z`;
      const long = await postJoin(srv, {
        ticket: await issueTicket(srv),
        hostname: longHost,
        user: longUser,
        ip: longIp,
      });
      assert.equal(long.status, 200);
      const longRow = await device(srv, record(long.body)?.deviceId);
      assert.equal(longRow.hostname, longHost.slice(0, 80));
      assert.equal(longRow.user, longUser.slice(0, 64));
      assert.equal(longRow.ip, longIp.slice(0, 64));
    });
  });

  it("supported os values are stored", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      for (const os of ["darwin", "linux", "win32"] as const) {
        const created = await postJoin(srv, {
          ticket: await issueTicket(srv),
          hostname: "synthetic-valid",
          os,
        });
        assert.equal(created.status, 200);
        assert.equal((await device(srv, record(created.body)?.deviceId)).os, os);
      }
    });
  });

  it("non-string ticket is rejected before consumption", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      for (const badTicket of [1, 0, true, false, { value: "x" }, ["ticket"]]) {
        const bad = await postJoin(srv, { ticket: badTicket, hostname: "synthetic-valid" });
        assert.equal(bad.status, 400);
        assert.equal(record(bad.body)?.error, "bad_json");
      }
      const good = await postJoin(srv, { ticket, hostname: "synthetic-valid" });
      assert.equal(good.status, 200);
    });
  });

  it("missing or empty ticket stays invalid without blocking a later join", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const bodies = [
        { hostname: "synthetic-valid" },
        { ticket: "", hostname: "synthetic-valid" },
        { ticket: null, hostname: "synthetic-valid" },
      ];
      for (const body of bodies) {
        const bad = await postJoin(srv, body);
        assert.equal(bad.status, 401);
        assert.equal(record(bad.body)?.error, "join_ticket_invalid");
      }
      assert.equal((await postJoin(srv, { ticket, hostname: "synthetic-valid" })).status, 200);
    });
  });

  it("reused successful ticket is rejected", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const body = { ticket, hostname: "pc1", os: "win32", user: "u" };
      const first = await postJoin(srv, body);
      assert.equal(first.status, 200);
      assert.equal(typeof record(first.body)?.deviceId === "string", true);
      assert.equal(typeof record(first.body)?.deviceToken === "string", true);
      const second = await postJoin(srv, body);
      assert.equal(second.status, 401);
      assert.equal(record(second.body)?.error, "join_ticket_invalid");
    });
  });

  it("two concurrent valid joins with one ticket yield one success", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const body = { ticket, hostname: "concurrent-host", os: "win32", user: "fixture" };
      const [left, right] = await Promise.all([postJoin(srv, body), postJoin(srv, body)]);
      const statuses = [left.status, right.status].slice().sort((a, b) => a - b);
      assert.deepEqual(statuses, [200, 401]);
      const denied = [left, right].find((item) => item.status === 401);
      assert.equal(record(denied?.body)?.error, "join_ticket_invalid");
      const listed = await devices(srv);
      assert.equal(listed.length, 1);
      assert.equal(listed[0]?.hostname, "concurrent-host");
      assert.equal(listed[0]?.os, "win32");
      assert.equal(listed[0]?.user, "fixture");
    });
  });

  it("malformed json does not consume a valid join ticket", { timeout: 30_000 }, async () => {
    await withServer(async (srv) => {
      const ticket = await issueTicket(srv);
      const bad = await readJson(srv, "/api/v1/join", { method: "POST", body: "{" });
      assert.equal(bad.status, 400);
      assert.equal(record(bad.body)?.error, "bad_json");
      const good = await postJoin(srv, { ticket, hostname: "synthetic-valid", os: "darwin" });
      assert.equal(good.status, 200);
      assert.equal((await device(srv, record(good.body)?.deviceId)).os, "darwin");
    });
  });
});
