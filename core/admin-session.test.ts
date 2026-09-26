import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import type { IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { startServer, type RunningServer, type ServeOpts } from "./serve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

interface CtResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

function setCookieHeaders(headers: IncomingHttpHeaders): string[] {
  const raw = headers["set-cookie"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [raw];
}

function cookieValue(setCookie: string): string {
  const pair = setCookie.split(";", 1)[0] ?? "";
  const eq = pair.indexOf("=");
  if (eq < 0) return "";
  return decodeURIComponent(pair.slice(eq + 1));
}

function ctRequest(
  srv: RunningServer,
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<CtResponse> {
  const body = init.body ?? "";
  const headers = { ...(init.headers ?? {}) };
  if (body) headers["content-length"] = String(Buffer.byteLength(body));
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      srv.url + path,
      {
        method: init.method ?? "GET",
        ca: srv.tls.certPem,
        rejectUnauthorized: true,
        headers,
      },
      (res) => {
        const parts: Buffer[] = [];
        res.on("data", (chunk: Buffer) => parts.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(parts).toString("utf8"),
          }),
        );
        res.on("error", reject);
      },
    );
    req.setTimeout(8_000, () => req.destroy(new Error("ct request timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

async function withServer(extra: Partial<ServeOpts>, fn: (srv: RunningServer) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-admin-session-"));
  let srv: RunningServer | undefined;
  try {
    srv = await startServer({
      dataDir: dir,
      host: "127.0.0.1",
      port: 0,
      coreDir,
      uiDir: null,
      ...extra,
    });
    await fn(srv);
  } finally {
    await srv?.close();
    await rm(dir, { recursive: true, force: true });
  }
}

async function issueSession(srv: RunningServer, token = srv.adminToken): Promise<string> {
  const res = await ctRequest(srv, "/api/v1/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true });
  const setCookie = setCookieHeaders(res.headers)[0];
  assert.ok(setCookie, "login sets a session cookie");
  return setCookie;
}

function sessionCookie(setCookie: string): string {
  return `nmzp_admin=${encodeURIComponent(cookieValue(setCookie))}`;
}

async function state(srv: RunningServer, headers: Record<string, string>): Promise<CtResponse> {
  return ctRequest(srv, "/api/v1/state", { headers });
}

describe("CT admin session", { concurrency: false }, () => {
  it("session cookie does not contain the admin token", async () => {
    await withServer({}, async (srv) => {
      const setCookie = await issueSession(srv);
      assert.equal(setCookie.includes(srv.adminToken), false, "cookie must not contain the admin token");
      const sid = cookieValue(setCookie);
      assert.notEqual(sid, srv.adminToken, "cookie must not equal the admin token");
      assert.ok(sid.length >= 43, "session id must be at least 32 bytes");
      assert.match(setCookie, /HttpOnly/);
      assert.match(setCookie, /SameSite=Strict/);
      assert.match(setCookie, /(^|;\s*)Secure(;|$)/);
      assert.match(setCookie, /Max-Age=43200/);
      assert.match(setCookie, /Path=\//);
      const again = await issueSession(srv);
      assert.notEqual(cookieValue(again), sid, "session ids must be random");
      assert.equal(again.includes(srv.adminToken), false, "cookie must not contain the admin token");
    });
  });

  it("session cookie authenticates /api/v1/state", async () => {
    await withServer({}, async (srv) => {
      const setCookie = await issueSession(srv);
      const res = await state(srv, { cookie: sessionCookie(setCookie) });
      assert.equal(res.status, 200);
      assert.equal((JSON.parse(res.body) as { access?: string }).access, "admin");
      assert.equal(res.body.includes(srv.adminToken), false, "state response must not contain the admin token");
    });
  });

  it("rejects a forged session cookie", async () => {
    await withServer({}, async (srv) => {
      const res = await state(srv, { cookie: "nmzp_admin=forged-session-cookie" });
      assert.equal(res.status, 401, "forged session cookie must be rejected");
      assert.equal((JSON.parse(res.body) as { error?: string }).error, "unauthorized");
      assert.equal(res.body.includes(srv.adminToken), false, "error body must not contain the admin token");
    });
  });

  it("rejects the raw admin token presented as a cookie", async () => {
    await withServer({}, async (srv) => {
      const res = await state(srv, { cookie: `nmzp_admin=${encodeURIComponent(srv.adminToken)}` });
      assert.equal(res.status, 401, "raw admin token cookie must be rejected");
      assert.equal((JSON.parse(res.body) as { error?: string }).error, "unauthorized");
      assert.equal(res.body.includes(srv.adminToken), false, "error body must not contain the admin token");
    });
  });

  it("admin bearer still authenticates /api/v1/state", async () => {
    await withServer({}, async (srv) => {
      const res = await state(srv, { authorization: `Bearer ${srv.adminToken}` });
      assert.equal(res.status, 200);
      assert.equal((JSON.parse(res.body) as { access?: string }).access, "admin");
      assert.equal(res.body.includes(srv.adminToken), false, "state response must not contain the admin token");
      const setCookie = await issueSession(srv);
      const wrongBearer = await state(srv, {
        authorization: "Bearer wrong-admin-token",
        cookie: sessionCookie(setCookie),
      });
      assert.equal(wrongBearer.status, 401, "wrong bearer must not fall through to the session cookie");
    });
  });

  it("rejects an expired session cookie", async () => {
    let now = 1_700_000_000_000;
    await withServer({ adminSessionNow: () => now }, async (srv) => {
      const setCookie = await issueSession(srv);
      const cookie = sessionCookie(setCookie);
      assert.equal((await state(srv, { cookie })).status, 200);
      now += SESSION_TTL_MS - 1;
      assert.equal((await state(srv, { cookie })).status, 200);
      now += 1;
      const expired = await state(srv, { cookie });
      assert.equal(expired.status, 401, "expired session cookie must be rejected");
      assert.equal((JSON.parse(expired.body) as { error?: string }).error, "unauthorized");
      const again = await state(srv, { cookie });
      assert.equal(again.status, 401, "expired session cookie must be rejected");
    });
  });

  it("logout revokes the session cookie", async () => {
    await withServer({}, async (srv) => {
      const setCookie = await issueSession(srv);
      const cookie = sessionCookie(setCookie);
      const sid = cookieValue(setCookie);
      const absent = await ctRequest(srv, "/api/v1/session", { method: "DELETE" });
      assert.equal(absent.status, 200);
      assert.deepEqual(JSON.parse(absent.body), { ok: true });
      assert.equal((await state(srv, { cookie })).status, 200);
      const cleared = await ctRequest(srv, "/api/v1/session", { method: "DELETE", headers: { cookie } });
      assert.equal(cleared.status, 200);
      assert.deepEqual(JSON.parse(cleared.body), { ok: true });
      const clearCookie = setCookieHeaders(cleared.headers)[0] ?? "";
      assert.match(clearCookie, /Max-Age=0/);
      assert.match(clearCookie, /HttpOnly/);
      assert.match(clearCookie, /SameSite=Strict/);
      assert.match(clearCookie, /(^|;\s*)Secure(;|$)/);
      assert.equal(clearCookie.includes(sid), false, "cleared cookie must not echo the session id");
      assert.equal(clearCookie.includes(srv.adminToken), false, "cleared cookie must not contain the admin token");
      const after = await state(srv, { cookie });
      assert.equal(after.status, 401, "logged-out session cookie must be rejected");
    });
  });

  it("session cookie does not authenticate a device route", async () => {
    await withServer({}, async (srv) => {
      const setCookie = await issueSession(srv);
      const sid = cookieValue(setCookie);
      const asCookie = await ctRequest(srv, "/api/v1/probe/challenge", {
        headers: { cookie: sessionCookie(setCookie) },
      });
      assert.equal(asCookie.status, 401, "session cookie must not authenticate a device route");
      const asBearer = await ctRequest(srv, "/api/v1/probe/challenge", {
        headers: { authorization: `Bearer ${sid}` },
      });
      assert.equal(asBearer.status, 401, "session id must not authenticate a device route");
      assert.equal(asCookie.body.includes(srv.adminToken), false, "error body must not contain the admin token");
      assert.equal(asBearer.body.includes(sid), false, "error body must not contain the session id");
    });
  });

  it("session exchange keeps origin and credential rejections", async () => {
    await withServer({}, async (srv) => {
      const wrong = await ctRequest(srv, "/api/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: "wrong-admin-token" }),
      });
      assert.equal(wrong.status, 401);
      assert.equal((JSON.parse(wrong.body) as { error?: string }).error, "unauthorized");
      assert.equal(setCookieHeaders(wrong.headers).length, 0);
      assert.equal(wrong.body.includes(srv.adminToken), false, "error body must not contain the admin token");
      const badJson = await ctRequest(srv, "/api/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      });
      assert.equal(badJson.status, 400);
      assert.equal((JSON.parse(badJson.body) as { error?: string }).error, "bad_json");
      const foreign = await ctRequest(srv, "/api/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://evil.example" },
        body: JSON.stringify({ token: srv.adminToken }),
      });
      assert.equal(foreign.status, 403);
      assert.equal((JSON.parse(foreign.body) as { error?: string }).error, "origin");
      assert.equal(setCookieHeaders(foreign.headers).length, 0);
      const setCookie = await issueSession(srv);
      const csrf = await ctRequest(srv, "/api/v1/session", {
        method: "DELETE",
        headers: { cookie: sessionCookie(setCookie), origin: "https://evil.example" },
      });
      assert.equal(csrf.status, 403);
      assert.equal((JSON.parse(csrf.body) as { error?: string }).error, "origin");
      assert.equal((await state(srv, { cookie: sessionCookie(setCookie) })).status, 200);
    });
  });

  it("session cap evicts the oldest live session", async () => {
    await withServer({}, async (srv) => {
      const issued: string[] = [];
      for (let i = 0; i < 65; i++) issued.push(cookieValue(await issueSession(srv)));
      assert.equal((await state(srv, { cookie: `nmzp_admin=${issued[0]}` })).status, 401);
      assert.equal((await state(srv, { cookie: `nmzp_admin=${issued[1]}` })).status, 200);
      assert.equal((await state(srv, { cookie: `nmzp_admin=${issued[64]}` })).status, 200);
    });
  });
});
