import { createHash } from "node:crypto";
import { request as httpsRequest, type RequestOptions } from "node:https";
import type { TLSSocket } from "node:tls";
import { URL } from "node:url";
import { BODY_LIMIT } from "./constants.ts";

export interface PinRequest {
  url: string;
  method?: string;
  body?: string | Buffer;
  headers?: Record<string, string>;
  caPem: string;
  fingerprintSha256: string;
  timeoutMs?: number;
  maxBodyBytes?: number;
}

export interface PinResponse {
  status: number;
  body: string;
  raw: Buffer;
}

function peerFingerprints(sock: TLSSocket): string[] {
  const peer = sock.getPeerCertificate(true);
  const cands: string[] = [];
  if (peer.raw) cands.push(createHash("sha256").update(peer.raw as Buffer).digest("hex"));
  if (peer.fingerprint256) cands.push(String(peer.fingerprint256).replace(/:/g, "").toLowerCase());
  return cands;
}

/** Missing pin or missing peer cert is a failure. authorized=true is not a substitute. */
export function assertPin(sock: TLSSocket, expectedHex: string): void {
  const expected = (expectedHex ?? "").toLowerCase().replace(/:/g, "");
  if (!/^[0-9a-f]{64}$/.test(expected)) throw new Error("tls pin required");
  const cands = peerFingerprints(sock);
  if (!cands.length) throw new Error("tls fingerprint mismatch");
  if (!cands.includes(expected)) throw new Error("tls fingerprint mismatch");
}

function normalizePin(hex: string): string {
  return (hex ?? "").toLowerCase().replace(/:/g, "");
}

/**
 * Device-side HTTPS. agent:false so each request handshakes and secureConnect always fires.
 * Pins the CT certificate on secureConnect before writing the body. Never rejectUnauthorized:false.
 * timeoutMs is a wall deadline covering DNS/TLS, not only socket inactivity.
 */
export function pinnedHttps(opts: PinRequest): Promise<PinResponse> {
  const u = new URL(opts.url);
  if (u.protocol !== "https:") throw new Error("https required");
  const pin = normalizePin(opts.fingerprintSha256);
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new Error("tls pin required");
  if (!opts.caPem) throw new Error("tls pin required");
  const timeoutMs = opts.timeoutMs ?? 8000;
  const maxBody = opts.maxBodyBytes ?? BODY_LIMIT;
  const payload = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body ?? "", "utf8");
  const reqOpts: RequestOptions = {
    protocol: "https:",
    hostname: u.hostname,
    port: u.port || 443,
    path: `${u.pathname}${u.search}`,
    method: opts.method ?? "GET",
    headers: { ...(opts.headers ?? {}), "content-length": payload.length },
    ca: opts.caPem,
    rejectUnauthorized: true,
    agent: false,
    ...(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(u.hostname) ? {} : { servername: u.hostname }),
  };
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn();
    };
    const fail = (e: unknown) =>
      finish(() => reject(e instanceof Error ? e : new Error(String(e))));
    const req = httpsRequest(reqOpts, (res) => {
      const chunks: Buffer[] = [];
      let n = 0;
      res.on("data", (c) => {
        const b = c as Buffer;
        n += b.length;
        if (n > maxBody) {
          res.destroy();
          fail(new Error("response_too_large"));
          return;
        }
        chunks.push(b);
      });
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        finish(() => resolve({ status: res.statusCode ?? 0, body: raw.toString("utf8"), raw }));
      });
      res.on("error", fail);
    });
    const timer = setTimeout(() => {
      req.destroy();
      fail(new Error("timeout"));
    }, timeoutMs);
    req.on("error", fail);
    req.on("socket", (sock: TLSSocket) => {
      sock.once("secureConnect", () => {
        try {
          assertPin(sock, pin);
        } catch (e) {
          req.destroy();
          fail(e);
          return;
        }
        if (payload.length) req.write(payload);
        req.end();
      });
    });
  });
}
