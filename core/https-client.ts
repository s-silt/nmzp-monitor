import { createHash } from "node:crypto";
import { request as httpsRequest, type RequestOptions } from "node:https";
import type { TLSSocket } from "node:tls";
import { URL } from "node:url";
import { BODY_LIMIT } from "./constants.ts";

/** connect: TCP/DNS refused or not up. tls: handshake failed after TCP. pin: fingerprint. response: after handshake. */
export type PinnedHttpsPhase = "connect" | "tls" | "pin" | "response";

export interface PinRequest {
  url: string;
  method?: string;
  body?: string | Buffer;
  headers?: Record<string, string>;
  caPem: string;
  fingerprintSha256: string;
  timeoutMs?: number;
  /** TCP + TLS budget. Omitted: one total deadline, same errors as before this option existed. */
  connectTimeoutMs?: number;
  maxBodyBytes?: number;
  /** Invoked synchronously after the pin check, immediately before the body is written. */
  onBodySent?: () => void;
}

export interface PinResponse {
  status: number;
  body: string;
  raw: Buffer;
}

function peerFingerprints(sock: TLSSocket): string[] {
  const peer = sock.getPeerCertificate(true);
  const cands: string[] = [];
  if (peer.raw)
    cands.push(
      createHash("sha256")
        .update(peer.raw as Buffer)
        .digest("hex"),
    );
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

const CONNECT_CODES = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "EAI_NODATA",
  "ECONNREFUSED",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
  "EADDRNOTAVAIL",
]);

const TLS_CODES = new Set([
  "EPROTO",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "CERT_SIGNATURE_FAILURE",
]);

function isTlsTransportFailure(code: string, message: string): boolean {
  if (code.startsWith("ERR_SSL_") || code.startsWith("ERR_TLS_") || TLS_CODES.has(code))
    return true;
  return /handshake|certificate|ssl3|tlsv1|\bssl\b/i.test(message);
}

/** Classify a socket or DNS error. Handshake completion (secureConnect + pin) is the response phase. */
export function phaseForTransportError(input: {
  code?: string;
  message?: string;
  tcpUp: boolean;
  handshakeDone: boolean;
}): PinnedHttpsPhase {
  if (input.handshakeDone) return "response";
  const code = input.code ?? "";
  if (CONNECT_CODES.has(code)) return "connect";
  if (isTlsTransportFailure(code, input.message ?? "")) return "tls";
  if (input.tcpUp) return "tls";
  return "connect";
}

let connectObserver: (() => void) | undefined;

/** Test-only. Counts real pinnedHttps attempts. Production leaves this unset. */
export function setPinnedHttpsConnectObserverForTesting(observer?: () => void): void {
  connectObserver = observer;
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
  const connectTimeoutMs = opts.connectTimeoutMs;
  const classifyPhase = connectTimeoutMs !== undefined;
  const maxBody = opts.maxBodyBytes ?? BODY_LIMIT;
  const payload = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body ?? "", "utf8");
  try {
    connectObserver?.();
  } catch {
    /* observer must not change the request outcome */
  }
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
    let tcpUp = false;
    let handshakeDone = false;
    let httpReceived = false;
    let connectTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      if (connectTimer) clearTimeout(connectTimer);
      fn();
    };
    const fail = (e: unknown, phase?: PinnedHttpsPhase) => {
      const err = e instanceof Error ? e : new Error(String(e));
      if (classifyPhase && phase !== undefined) {
        Object.defineProperty(err, "phase", { value: phase, enumerable: true });
        if (httpReceived)
          Object.defineProperty(err, "httpReceived", { value: true, enumerable: true });
      }
      finish(() => reject(err));
    };
    const transportPhase = (error: unknown): PinnedHttpsPhase => {
      const code =
        error && typeof error === "object" ? (error as { code?: unknown }).code : undefined;
      const message = error instanceof Error ? error.message : "";
      return phaseForTransportError({
        code: typeof code === "string" ? code : undefined,
        message,
        tcpUp,
        handshakeDone,
      });
    };
    const timeoutPhase = (): PinnedHttpsPhase => {
      if (handshakeDone) return "response";
      return tcpUp ? "tls" : "connect";
    };
    const req = httpsRequest(reqOpts, (res) => {
      httpReceived = true;
      const chunks: Buffer[] = [];
      let n = 0;
      res.on("data", (c) => {
        const b = c as Buffer;
        n += b.length;
        if (n > maxBody) {
          res.destroy();
          fail(new Error("response_too_large"), classifyPhase ? "response" : undefined);
          return;
        }
        chunks.push(b);
      });
      res.on("end", () => {
        const raw = Buffer.concat(chunks);
        finish(() => resolve({ status: res.statusCode ?? 0, body: raw.toString("utf8"), raw }));
      });
      res.on("error", (error) => fail(error, classifyPhase ? transportPhase(error) : undefined));
    });
    const totalTimer = setTimeout(() => {
      req.destroy();
      fail(new Error("timeout"), classifyPhase ? timeoutPhase() : undefined);
    }, timeoutMs);
    if (connectTimeoutMs !== undefined) {
      connectTimer = setTimeout(() => {
        req.destroy();
        fail(new Error("timeout"), timeoutPhase());
      }, connectTimeoutMs);
    }
    if (settled) {
      clearTimeout(totalTimer);
      if (connectTimer) clearTimeout(connectTimer);
    }
    req.on("error", (error) => fail(error, classifyPhase ? transportPhase(error) : undefined));
    req.on("socket", (sock: TLSSocket) => {
      const markTcp = () => {
        tcpUp = true;
      };
      if (sock.connecting !== true && sock.readyState === "open") markTcp();
      sock.once("connect", markTcp);
      sock.once("secureConnect", () => {
        if (connectTimer) clearTimeout(connectTimer);
        connectTimer = undefined;
        try {
          assertPin(sock, pin);
        } catch (e) {
          req.destroy();
          fail(e, classifyPhase ? "pin" : undefined);
          return;
        }
        handshakeDone = true;
        try {
          opts.onBodySent?.();
        } catch {
          /* callback must not change the request outcome */
        }
        if (payload.length) req.write(payload);
        req.end();
      });
    });
  });
}
