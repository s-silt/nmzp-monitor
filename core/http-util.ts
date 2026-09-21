import type { IncomingMessage, ServerResponse } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, sep } from "node:path";
import { BODY_LIMIT } from "./constants.ts";

export function json(res: ServerResponse, status: number, body: unknown): void {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": Buffer.byteLength(raw),
  });
  res.end(raw);
}

export async function readLimited(
  req: IncomingMessage,
  limit = BODY_LIMIT,
): Promise<{ ok: true; text: string } | { ok: false; tooLarge: true }> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    const b = c as Buffer;
    n += b.length;
    if (n > limit) {
      req.resume();
      return { ok: false, tooLarge: true };
    }
    chunks.push(b);
  }
  return { ok: true, text: Buffer.concat(chunks).toString("utf8") };
}

export function originOk(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  const host = req.headers.host;
  if (!host) return false;
  try {
    const u = new URL(origin);
    return u.host === host;
  } catch {
    return false;
  }
}

/** Reject DNS rebinding: Host must be loopback. */
export function loopbackHostHeader(hostHeader: string | undefined, listenPort: number): boolean {
  const h = (hostHeader ?? "").trim().toLowerCase();
  if (!h) return false;
  const allowed = new Set([
    "127.0.0.1",
    "localhost",
    `[::1]`,
    `127.0.0.1:${listenPort}`,
    `localhost:${listenPort}`,
    `[::1]:${listenPort}`,
  ]);
  return allowed.has(h);
}

export const STATIC_MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".map": "application/json",
  ".txt": "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json",
};

export function mimeForPath(pathname: string): string {
  const ext = extname(pathname.split("?")[0] ?? "").toLowerCase();
  if (ext && STATIC_MIME[ext]) return STATIC_MIME[ext];
  if (pathname === "/" || pathname.endsWith("/")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}

export function isLoopback(req: IncomingMessage): boolean {
  const ip = req.socket.remoteAddress ?? "";
  return ip === "127.0.0.1" || ip === "::1" || ip === ":ffff:127.0.0.1";
}

const MIME = STATIC_MIME;

export function serveStatic(res: ServerResponse, uiDir: string, urlPath: string): boolean {
  const decoded = decodeURIComponent(urlPath.split("?")[0] ?? "/");
  const rel = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const abs = normalize(join(uiDir, rel));
  if (!abs.startsWith(normalize(uiDir) + sep) && abs !== normalize(uiDir)) return false;
  if (existsSync(abs) && statSync(abs).isFile()) {
    const type = MIME[extname(abs).toLowerCase()] ?? "application/octet-stream";
    res.writeHead(200, { "content-type": type, "x-content-type-options": "nosniff" });
    createReadStream(abs).pipe(res);
    return true;
  }
  const index = join(uiDir, "index.html");
  if (existsSync(index)) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    createReadStream(index).pipe(res);
    return true;
  }
  return false;
}
