import {discoveryLocalRequest} from "./agent-discovery-local.ts";
/**
 * Loopback HTTP admin proxy. Browser talks http://127.0.0.1 (no self-signed warning).
 * Proxy pins CT HTTPS. Not anonymous. Admin token never in URL or logs.
 * Device evaluate/heartbeat/join/receipt are not proxied (no tool bodies on HTTP).
 */
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { newSecret, parseCookie, safeEqualStr } from "./auth.ts";
import { json, originOk, readLimited, isLoopback, loopbackHostHeader, serveStatic, mimeForPath } from "./http-util.ts";
import { pinnedHttps } from "./https-client.ts";
import { forwardPinnedExport } from "./https-stream.ts";
import { ADMIN_BODY_LIMIT, BODY_LIMIT } from "./constants.ts";

const COOKIE = "nmzp_proxy";
const DEVICE_ONLY = new Set(["/api/v1/evaluate", "/api/v1/heartbeat", "/api/v1/join", "/api/v1/receipt", "/api/v1/audit/backfill"]);

export interface AdminProxyOpts {
  ctUrl: string;
  caPem: string;
  fingerprintSha256: string;
  adminToken: string;
  host?: string;
  port?: number;
  uiDir?: string | null;
  discoveryHome?: string;
}

export interface RunningProxy {
  host: string;
  port: number;
  url: string;
  close: () => Promise<void>;
}

const sessions = new Map<string, number>();

function sessionOk(req: IncomingMessage): boolean {
  const sid = parseCookie(req.headers.cookie, COOKIE);
  if (!sid) return false;
  const exp = sessions.get(sid);
  if (!exp || exp < Date.now()) {
    if (sid) sessions.delete(sid);
    return false;
  }
  return true;
}

function allowForward(pathname: string, method: string): boolean {
  if (DEVICE_ONLY.has(pathname)) return false;
  if (pathname === "/api/v1/policy" && method === "GET") return false;
  return true;
}

const LOGIN_HTML = `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>NMZP</title>
  <style>
    body{font-family:system-ui,sans-serif;margin:0;background:#111;color:#eee;display:flex;min-height:100vh;align-items:center;justify-content:center}
    form{display:flex;flex-direction:column;gap:12px;background:#1c1c1c;padding:24px;border-radius:12px;min-width:280px}
    input{padding:8px;border-radius:6px;border:1px solid #333;background:#0d0d0d;color:#eee}
    button{padding:8px 12px;border:0;border-radius:6px;background:#3b82f6;color:#fff}
    p{font-size:12px;color:#aaa;margin:0}
  </style>
</head>
<body>
  <form id="f">
    <h1 style="font-size:18px;margin:0">NMZP</h1>
    <p>本机管理口令。口令不进 URL、不进日志。</p>
    <input id="t" type="password" autocomplete="off" aria-label="admin token"/>
    <label style="font-size:12px;color:#aaa">选择本机口令文件
      <input id="file" type="file" accept=".token,.txt,text/plain"/>
    </label>
    <button type="submit">登录</button>
    <p id="err" style="color:#f66"></p>
  </form>
  <script>
    const t = document.getElementById("t");
    document.getElementById("file").addEventListener("change", async (e) => {
      const input = e.target;
      const f = input.files && input.files[0];
      input.value = "";
      if (!f) return;
      t.value = (await f.text()).trim();
      document.getElementById("f").requestSubmit();
    });
    document.getElementById("f").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = document.getElementById("err");
      err.textContent = "";
      try {
        const res = await fetch("/api/v1/session", {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: t.value })
        });
        if (!res.ok) { err.textContent = "登录失败"; return; }
        location.href = "/";
      } catch {
        err.textContent = "无法连接";
      }
    });
  </script>
</body>
</html>
`;

function sendLoginHtml(res: ServerResponse): void {
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(LOGIN_HTML);
}

export async function startAdminProxy(opts: AdminProxyOpts): Promise<RunningProxy> {
  const host = opts.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1") throw new Error("admin proxy must bind loopback");
  const ct = opts.ctUrl.replace(/\/$/, "");
  const pin = { caPem: opts.caPem, fingerprintSha256: opts.fingerprintSha256 };
  const listen = { port: opts.port ?? 0 };
  const uiDir = opts.uiDir ?? null;
  let activeExports = 0;

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    if (!isLoopback(req)) {
      json(res, 403, { ok: false, error: "loopback_only" });
      return;
    }
    if (!loopbackHostHeader(req.headers.host, listen.port)) {
      json(res, 403, { ok: false, error: "bad_host" });
      return;
    }
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    const pathname = u.pathname;
    const method = req.method ?? "GET";

    if (method === "POST" && pathname === "/api/v1/session") {
      if (!originOk(req)) {
        json(res, 403, { ok: false, error: "origin" });
        return;
      }
      const body = await readLimited(req);
      if (!body.ok) {
        json(res, 413, { ok: false, error: "payload_too_large" });
        return;
      }
      let token = "";
      try {
        token = String((JSON.parse(body.text || "{}") as { token?: string }).token ?? "");
      } catch {
        json(res, 400, { ok: false, error: "bad_json" });
        return;
      }
      if (!token || !safeEqualStr(token, opts.adminToken)) {
        json(res, 401, { ok: false, error: "unauthorized" });
        return;
      }
      const sid = newSecret(24);
      sessions.set(sid, Date.now() + 12 * 60 * 60 * 1000);
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict`,
        "cache-control": "no-store",
      });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (pathname === "/health") {
      json(res, 200, { ok: true, name: "nmzp-proxy" });
      return;
    }

    const isApi = pathname.startsWith("/api/");
    if (!isApi && (method === "GET" || method === "HEAD")) {
      if (uiDir && serveStatic(res, uiDir, pathname)) return;
      if (await proxyCtStatic(pathname, res)) return;
      if (pathname === "/" || pathname === "/index.html") {
        sendLoginHtml(res);
        return;
      }
      json(res, 404, { ok: false, error: "not_found" });
      return;
    }

    if (!sessionOk(req)) {
      if (!isApi && (method === "GET" || method === "HEAD")) {
        sendLoginHtml(res);
        return;
      }
      json(res, 401, { ok: false, error: "unauthorized" });
      return;
    }
    if (!originOk(req)) {
      json(res, 403, { ok: false, error: "origin" });
      return;
    }
    if (pathname.startsWith("/api/v1/local/discovery")) {
      let value:unknown;
      if(method!=="GET") {const b=await readLimited(req);if(!b.ok){json(res,413,{ok:false});return;}try{value=JSON.parse(b.text||"null");}catch{json(res,400,{ok:false});return;}}
      const result=await discoveryLocalRequest(method,pathname,value,opts.discoveryHome);json(res,result.status,result.body);return;
    }
    if (!allowForward(pathname, method)) {
      json(res, 403, { ok: false, error: "admin_proxy_only" });
      return;
    }

    if (method === "GET" && pathname === "/api/v1/audit/export") {
      if (activeExports >= 2) { json(res, 503, { ok: false, error: "export_busy" }); return; }
      activeExports++;
      try {
        await forwardPinnedExport({ url: `${ct}${pathname}${u.search}`, ...pin,
          headers: { authorization: `Bearer ${opts.adminToken}` } }, res);
      } catch {
        if (res.headersSent) res.destroy();
        else json(res, 502, { ok: false, error: "ct_unreachable" });
      } finally { activeExports--; }
      return;
    }

    if (!isApi) {
      if (uiDir && serveStatic(res, uiDir, pathname)) return;
      if (await proxyCtStatic(pathname, res)) return;
      json(res, 404, { ok: false, error: "not_found" });
      return;
    }

    let body: string | undefined;
    if (method !== "GET" && method !== "HEAD") {
      const read = await readLimited(req);
      if (!read.ok) {
        json(res, 413, { ok: false, error: "payload_too_large" });
        return;
      }
      body = read.text;
    }
    try {
      const adminPath = pathname === "/api/v1/state" || pathname === "/api/v1/export";
      const fwd = await pinnedHttps({
        url: `${ct}${pathname}${u.search}`,
        method,
        body,
        headers: {
          authorization: `Bearer ${opts.adminToken}`,
          ...(body ? { "content-type": req.headers["content-type"] || "application/json" } : {}),
        },
        ...pin,
        maxBodyBytes: pathname === "/api/v1/audit/events" ? 4 * 1024 * 1024 : adminPath ? ADMIN_BODY_LIMIT : BODY_LIMIT,
      });
      const ctype =
        pathname.startsWith("/api/") || pathname === "/health"
          ? "application/json; charset=utf-8"
          : mimeForPath(pathname);
      res.writeHead(fwd.status, {
        "content-type": ctype,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      });
      res.end(fwd.raw);
    } catch {
      json(res, 502, { ok: false, error: "ct_unreachable" });
    }
  };

  async function proxyCtStatic(pathname: string, res: ServerResponse): Promise<boolean> {
    if (pathname.startsWith("/api/")) return false;
    try {
      const fwd = await pinnedHttps({
        url: `${ct}${pathname === "/" ? "/" : pathname}`,
        method: "GET",
        ...pin,
        timeoutMs: 4000,
        maxBodyBytes: ADMIN_BODY_LIMIT,
      });
      if (fwd.status === 404 || fwd.status === 401 || fwd.status === 403) return false;
      if (fwd.status === 0) return false;
      const type = mimeForPath(pathname);
      res.writeHead(fwd.status, {
        "content-type": type === "application/octet-stream" ? "text/html; charset=utf-8" : type,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      });
      res.end(fwd.raw);
      return true;
    } catch {
      return false;
    }
  }

  const server: Server = createServer((req, res) => {
    void handler(req, res).catch(() => {
      if (!res.headersSent) json(res, 500, { ok: false, error: "internal_error" });
    });
  });
  const port = opts.port ?? 0;
  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => resolve());
    server.on("error", reject);
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("listen failed");
  listen.port = addr.port;
  return {
    host,
    port: addr.port,
    url: `http://${host}:${addr.port}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((e) => (e ? reject(e) : resolve()));
      }),
  };
}
