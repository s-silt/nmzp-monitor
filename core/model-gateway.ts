import {ResponseRiskObserver, type ResponseObservation} from "./model-response-risk.ts";
/**
 * Loopback model-request inspection gateway.
 *
 * Intended as the only outbound forwarder a brokered Windows agent is
 * *configured* to use. This process does not block direct sockets, raw DNS,
 * or other processes — forced restriction is a separate native worker
 * (WFP / AppContainer). Do not treat a green gateway as "direct outbound blocked".
 *
 * Production upstream TLS always uses rejectUnauthorized:true. Loopback HTTP
 * is available only via an explicit trusted-caller factory, never a public
 * request field. Client session tokens are not sent upstream. Upstream
 * credentials come only from host config and are never logged.
 *
 * Response inspection is advisory and bounded to chat/completions JSON/SSE; no universal poisoning claim.
 */

import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  createServer,
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
  type Server,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import { request as httpsRequest } from "node:https";
import {
  IMPLEMENTED_MODEL_ROUTES,
  inspectModelPayload,
  isModelGatewayRoute,
  MODEL_GATEWAY_ROUTES,
  publicProtocolField,
  type InspectTap,
} from "./model-gateway-inspect.ts";
import { BODY_LIMIT } from "./constants.ts";

export {
  IMPLEMENTED_MODEL_ROUTES,
  inspectModelPayload,
  MODEL_GATEWAY_ROUTES,
  publicProtocolField,
  REDACT_TAG,
} from "./model-gateway-inspect.ts";

export const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_TIMEOUT_MS = 30 * 60 * 1000;
const MIN_TIMEOUT_MS = 100;
const DEFAULT_HEADER_IDLE_MS = 15_000;
const DEFAULT_BODY_IDLE_MS = 30_000;
const DEFAULT_STREAM_IDLE_MS = 60_000;
const DEFAULT_MAX_INFLIGHT = 8;
const DEFAULT_MAX_CONNECTIONS = 16;
const MAX_BODY_CAP = 2_097_152;
const DEFAULT_MAX_OUT_BYTES = 8_388_608;
const METHOD_META = new Set(["POST", "GET", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"]);

const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store, no-cache, must-revalidate",
  pragma: "no-cache",
  expires: "0",
  "x-content-type-options": "nosniff",
  connection: "close",
};

export type CreateUpstreamRequest = (
  options: RequestOptions,
  callback: (res: IncomingMessage) => void,
) => ClientRequest;

export interface ModelGatewayConfig {
  bindHost?: string;
  bindPort?: number;
  sessionToken?: string;
  /** Unique fixed origin, e.g. https://api.openai.com — no path/query/userinfo. */
  upstreamOrigin: string;
  allowedRoutes?: string[];
  /** Host-configured upstream credential. Never logged. Never taken from the client. */
  upstreamToken?: string;
  /** Absolute request budget. Default 10 minutes. */
  timeoutMs?: number;
  headerIdleMs?: number;
  bodyIdleMs?: number;
  streamIdleMs?: number;
  maxInflight?: number;
  maxConnections?: number;
  maxOutBytes?: number;
  bodyLimit?: number;
  /**
   * Trusted-caller only. Lets synthetic tests inject loopback HTTP.
   * Must be a function; never a request header/body flag.
   */
  createUpstreamRequest?: CreateUpstreamRequest;
  onEvent?: (event: ModelGatewayEvent) => unknown;
  log?: (line: string) => void;
  /** Trusted-caller only. Fixture diagnosis; never a request field. */
  onInspectTap?: InspectTap;
}

export interface ModelGatewayEvent {
  requestId?: string;
  upstreamHost?: string;
  responseObservation?: ResponseObservation;
  transport?: {upstreamComplete:boolean;clientWriteComplete:boolean;outcome:"complete"|"cancelled"|"timeout"|"upstream_error"|"gateway_closed"|"output_limit"|"unknown"};
  t: number;
  result: "ok" | "deny" | "error";
  code: string;
  method?: string;
  route?: string;
  stream?: boolean;
  inBytes?: number;
  outBytes?: number;
  redacted?: boolean;
  /** Short protocol field name on deny; never a value/secret. */
  field?: string;
}

export interface ModelGatewayStatus {
  bindHost: string;
  port: number;
  url: string;
  upstreamHost: string;
  allowedRoutes: string[];
  implementedRoutes: string[];
  inflight: number;
  timeoutMs: number;
  headerIdleMs: number;
  maxInflight: number;
  /** Always false: this module does not prevent other sockets. */
  blocksDirectOutbound: false;
  /** Bounded heuristic observation, not automatic blocking or universal detection. */
  audit: {pending:number;failed:number;timedOut:number;dropped:number;lastFailureAt?:number};
  poisonDetection: true;
  responseInspection: "chat_completions_json_sse_alert_only";
  covertChannelComplete: false;
}

export interface ModelGatewayHandle {
  port: number;
  url: string;
  /** Trusted caller only. Not included in status() or events. */
  sessionToken: string;
  close: () => Promise<void>;
  status: () => ModelGatewayStatus;
}

interface Normalized {
  audit: {pending:number;failed:number;timedOut:number;dropped:number;lastFailureAt?:number};
  bindHost: string;
  bindPort: number;
  sessionToken: string;
  origin: URL;
  allowedRoutes: Set<string>;
  upstreamToken: string | undefined;
  timeoutMs: number;
  headerIdleMs: number;
  bodyIdleMs: number;
  streamIdleMs: number;
  maxInflight: number;
  maxConnections: number;
  maxOutBytes: number;
  bodyLimit: number;
  createUpstreamRequest: CreateUpstreamRequest | undefined;
  onEvent: ((event: ModelGatewayEvent) => unknown) | undefined;
  log: ((line: string) => void) | undefined;
  onInspectTap: InspectTap | undefined;
}

interface Inflight {
  abort: AbortController;
  req: IncomingMessage;
  res: ServerResponse;
  up?: ClientRequest;
}

function isLoopbackHostname(host: string): boolean {
  const h = host.toLowerCase();
  return h === "127.0.0.1" || h === "localhost" || h === "::1";
}

function parseOrigin(raw: string, allowHttpLoopback: boolean): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("origin_invalid");
  }
  if (u.username || u.password || u.search || u.hash) throw new Error("origin_invalid");
  if (u.pathname && u.pathname !== "/") throw new Error("origin_invalid");
  if (allowHttpLoopback) {
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("origin_invalid");
    if (!isLoopbackHostname(u.hostname)) throw new Error("origin_invalid");
    return u;
  }
  if (u.protocol !== "https:") throw new Error("origin_invalid");
  return u;
}

function resolveSessionToken(token: string | undefined): string {
  if (token === undefined) return randomBytes(32).toString("base64url");
  if (typeof token !== "string" || token.length < 32 || token.length > 256) throw new Error("token_invalid");
  if (/[\s\r\n]/.test(token)) throw new Error("token_invalid");
  return token;
}

function boundInt(v: number | undefined, fallback: number, min: number, max: number, code: string): number {
  const n = v ?? fallback;
  if (!Number.isFinite(n) || n < min || n > max) throw new Error(code);
  return Math.floor(n);
}

function methodMeta(method: string | undefined): string {
  const u = (method ?? "").toUpperCase();
  return METHOD_META.has(u) ? u : "OTHER";
}

function normalizeConfig(config: ModelGatewayConfig): Normalized {
  if (!config || typeof config !== "object") throw new Error("config_invalid");
  if (config.createUpstreamRequest !== undefined && typeof config.createUpstreamRequest !== "function") {
    throw new Error("factory_invalid");
  }
  const allowHttpLoopback = typeof config.createUpstreamRequest === "function";
  const origin = parseOrigin(config.upstreamOrigin, allowHttpLoopback);
  const bindHost = config.bindHost ?? "127.0.0.1";
  if (!isLoopbackHostname(bindHost) && bindHost !== "127.0.0.1") throw new Error("bind_invalid");
  if (bindHost !== "127.0.0.1" && bindHost !== "::1" && bindHost !== "localhost") throw new Error("bind_invalid");
  const allowed = config.allowedRoutes ?? [...MODEL_GATEWAY_ROUTES];
  if (!Array.isArray(allowed) || !allowed.length) throw new Error("routes_invalid");
  for (const r of allowed) {
    if (!isModelGatewayRoute(r)) throw new Error("routes_invalid");
  }
  if (config.upstreamToken !== undefined) {
    if (typeof config.upstreamToken !== "string" || !config.upstreamToken || config.upstreamToken.length > 8192) {
      throw new Error("token_invalid");
    }
  }
  const timeoutMs = boundInt(config.timeoutMs, DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, "timeout_invalid");
  const headerIdleMs = boundInt(config.headerIdleMs, DEFAULT_HEADER_IDLE_MS, 20, 120_000, "timeout_invalid");
  const bodyIdleMs = boundInt(config.bodyIdleMs, DEFAULT_BODY_IDLE_MS, 20, 120_000, "timeout_invalid");
  const streamIdleMs = boundInt(config.streamIdleMs, DEFAULT_STREAM_IDLE_MS, 20, 300_000, "timeout_invalid");
  const maxInflight = boundInt(config.maxInflight, DEFAULT_MAX_INFLIGHT, 1, 64, "limit_invalid");
  const maxConnections = boundInt(config.maxConnections, DEFAULT_MAX_CONNECTIONS, 1, 128, "limit_invalid");
  const maxOutBytes = boundInt(config.maxOutBytes, DEFAULT_MAX_OUT_BYTES, 64, 32 * 1024 * 1024, "limit_invalid");
  const bodyLimit = config.bodyLimit ?? BODY_LIMIT;
  if (!Number.isFinite(bodyLimit) || bodyLimit < 1024 || bodyLimit > MAX_BODY_CAP) throw new Error("limit_invalid");
  const bindPort = config.bindPort ?? 0;
  if (!Number.isInteger(bindPort) || bindPort < 0 || bindPort > 65535) throw new Error("bind_invalid");
  return {
    bindHost,
    bindPort,
    sessionToken: resolveSessionToken(config.sessionToken),
    origin,
    allowedRoutes: new Set(allowed),
    upstreamToken: config.upstreamToken,
    timeoutMs,
    headerIdleMs,
    bodyIdleMs,
    streamIdleMs,
    maxInflight,
    maxConnections,
    maxOutBytes,
    bodyLimit,
    createUpstreamRequest: config.createUpstreamRequest,
    onEvent: config.onEvent,
    audit: {pending:0,failed:0,timedOut:0,dropped:0},
    log: config.log,
    onInspectTap: typeof config.onInspectTap === "function" ? config.onInspectTap : undefined,
  };
}

function tokenEqual(provided: string, expected: string): boolean {
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length || a.length === 0) {
    if (a.length > 0) timingSafeEqual(a, Buffer.alloc(a.length, a[0]!));
    return false;
  }
  return timingSafeEqual(a, b);
}

function parseBearer(header: string | undefined): string | null {
  if (!header || typeof header !== "string") return null;
  const m = /^Bearer\s+(\S+)/i.exec(header.trim());
  return m ? m[1]! : null;
}

function listenPortOf(server: Server): number {
  const a = server.address();
  if (!a || typeof a === "string") return -1;
  return a.port;
}

function hostHeaderOk(hostHeader: string | undefined, port: number): boolean {
  const h = (hostHeader ?? "").trim().toLowerCase();
  if (!h) return false;
  return h === `127.0.0.1:${port}` || h === `localhost:${port}` || h === `[::1]:${port}`;
}

function clientPath(url: string | undefined): { ok: true; path: string } | { ok: false; code: string } {
  const raw = url ?? "";
  if (!raw.startsWith("/") || raw.startsWith("//")) return { ok: false, code: "route_denied" };
  if (raw.includes("?") || raw.includes("#")) return { ok: false, code: "query_denied" };
  if (raw.includes("\\") || raw.includes("%") || raw.includes("..") || raw.includes("\0")) {
    return { ok: false, code: "route_denied" };
  }
  if (/[^\x21-\x7e]/.test(raw) || raw.includes("//")) return { ok: false, code: "route_denied" };
  if (!isModelGatewayRoute(raw)) return { ok: false, code: "route_denied" };
  return { ok: true, path: raw };
}

function jsonContentType(value: string | undefined): boolean {
  if (!value) return false;
  const parts = value.split(";").map((p) => p.trim());
  const main = (parts[0] ?? "").toLowerCase();
  if (main !== "application/json") return false;
  for (const p of parts.slice(1)) {
    const eq = p.indexOf("=");
    if (eq <= 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    const v = p.slice(eq + 1).trim().toLowerCase().replace(/"/g, "");
    if (k === "charset" && v !== "utf-8") return false;
  }
  return true;
}

function badContentEncoding(value: string | string[] | undefined): boolean {
  if (!value) return false;
  const s = Array.isArray(value) ? value.join(",") : value;
  return s
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean)
    .some((p) => p !== "identity");
}

function hasUpgrade(req: IncomingMessage): boolean {
  const conn = String(req.headers.connection ?? "");
  if (/\bupgrade\b/i.test(conn)) return true;
  return Boolean(req.headers.upgrade);
}

function sendError(res: ServerResponse, status: number, code: string): void {
  if (res.headersSent || res.destroyed || res.writableEnded) {
    res.destroy();
    return;
  }
  const raw = JSON.stringify({ error: code });
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(raw),
  });
  res.end(raw);
}

function statusFor(code: string): number {
  switch (code) {
    case "auth_denied":
      return 401;
    case "host_denied":
    case "route_denied":
    case "method_denied":
    case "upgrade_denied":
    case "query_denied":
    case "secret_blocked":
      return 403;
    case "body_too_large":
      return 413;
    case "busy":
      return 429;
    case "timeout":
      return 408;
    case "cancelled":
      return 499;
    case "gateway_closed":
      return 503;
    case "protocol_unsupported":
      return 501;
    case "upstream_redirect":
    case "upstream_type":
    case "upstream_encoding":
    case "upstream_error":
      return 502;
    default:
      return 400;
  }
}

function drain(req: IncomingMessage): void {
  req.resume();
}

async function readBody(
  req: IncomingMessage,
  limit: number,
  signal: AbortSignal,
  bodyIdleMs: number,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let n = 0;
  let overflow = false;
  let idleHit = false;
  let idle: ReturnType<typeof setTimeout> | undefined;
  const bumpIdle = (): void => {
    if (idle) clearTimeout(idle);
    idle = setTimeout(() => {
      idleHit = true;
      req.destroy();
    }, bodyIdleMs);
  };
  bumpIdle();
  try {
    for await (const c of req) {
      if (signal.aborted) throw new DenyRead("cancelled");
      if (idleHit) throw new DenyRead("timeout");
      bumpIdle();
      const b = c as Buffer;
      n += b.length;
      if (n > limit) {
        overflow = true;
        if (n > limit + 65_536) {
          req.destroy();
          throw new DenyRead("body_too_large");
        }
        continue;
      }
      chunks.push(b);
    }
  } catch (e) {
    if (idleHit) throw new DenyRead("timeout");
    throw e;
  } finally {
    if (idle) clearTimeout(idle);
  }
  if (overflow) throw new DenyRead("body_too_large");
  return Buffer.concat(chunks);
}

class DenyRead extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.name = "DenyRead";
    this.code = code;
  }
}

function utf8Strict(buf: Buffer): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    return null;
  }
}

function emit(
  cfg: Normalized,
  event: Omit<ModelGatewayEvent, "t">,
): void {
  const field = event.field !== undefined ? publicProtocolField(event.field) : undefined;
  const row: ModelGatewayEvent = { t: Date.now(), ...event, method: methodMeta(event.method), field };
  const markFailure = (): void => { cfg.audit.failed++; cfg.audit.lastFailureAt=Date.now(); };
  if (cfg.audit.pending >= 32) { cfg.audit.dropped++; cfg.audit.lastFailureAt=Date.now(); }
  else {
    try {
      const receipt = cfg.onEvent?.(row);
      if (receipt && typeof (receipt as PromiseLike<unknown>).then === "function") {
        cfg.audit.pending++;
        const timer=setTimeout(()=>{cfg.audit.timedOut++;cfg.audit.lastFailureAt=Date.now();},1000);
        timer.unref();
        // Timed-out unresolved promises continue occupying a slot. A hung sink cannot grow an unlimited queue.
        Promise.resolve(receipt).then(()=>{clearTimeout(timer);cfg.audit.pending--;},()=>{clearTimeout(timer);cfg.audit.pending--;markFailure();});
      }
    } catch { markFailure(); }
  }
  if (cfg.log) {
    try { cfg.log(
      JSON.stringify({
        result: row.result,
        code: row.code,
        method: methodMeta(row.method),
        route: row.route,
        stream: row.stream,
        inBytes: row.inBytes,
        outBytes: row.outBytes,
        redacted: row.redacted,
        field: row.field,
      }),
    ); } catch { markFailure(); }
  }
}

function originPort(origin: URL): number {
  if (origin.port) return Number(origin.port);
  return origin.protocol === "https:" ? 443 : 80;
}

function upstreamHeaders(
  origin: URL,
  bodyLen: number,
  stream: boolean,
  upstreamToken: string | undefined,
): Record<string, string> {
  const headers: Record<string, string> = {
    host: origin.host,
    "content-type": "application/json",
    "content-length": String(bodyLen),
    accept: stream ? "text/event-stream" : "application/json",
    "accept-encoding": "identity",
    connection: "close",
  };
  if (upstreamToken) headers.authorization = `Bearer ${upstreamToken}`;
  return headers;
}

function openUpstream(
  cfg: Normalized,
  options: RequestOptions,
  cb: (res: IncomingMessage) => void,
): ClientRequest {
  if (cfg.createUpstreamRequest) return cfg.createUpstreamRequest(options, cb);
  if (options.protocol !== "https:") throw new Error("upstream_https_required");
  const hostname = typeof options.hostname === "string" ? options.hostname : undefined;
  const ipLiteral = hostname ? /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":") : true;
  return httpsRequest(
    {
      protocol: "https:",
      hostname: options.hostname,
      port: options.port,
      path: options.path,
      method: "POST",
      headers: options.headers,
      timeout: options.timeout,
      rejectUnauthorized: true,
      agent: false,
      ...(hostname && !ipLiteral ? { servername: hostname } : {}),
    },
    cb,
  );
}

function allowedUpstreamType(ctype: string): "sse" | "json" | "text" | null {
  const main = ctype.split(";")[0]!.trim().toLowerCase();
  if (main === "text/event-stream") return "sse";
  if (main === "application/json") return "json";
  if (main === "text/plain") return "text";
  return null;
}

function destroyInflight(item: Inflight): void {
  try {
    item.abort.abort();
  } catch {
    /* ignore */
  }
  if (item.up && !item.up.destroyed) item.up.destroy();
  if (!item.req.destroyed) item.req.destroy();
  if (!item.res.destroyed) item.res.destroy();
}

export async function startModelGateway(config: ModelGatewayConfig): Promise<ModelGatewayHandle> {
  const cfg = normalizeConfig(config);
  const inflight = new Set<Inflight>();
  let closed = false;
  let closing: Promise<void> | undefined;

  const server: Server = createServer((req, res) => {
    clearHeaderIdle(req.socket);
    void handle(req, res);
  });
  server.maxConnections = cfg.maxConnections;
  const headerIdle = Math.min(cfg.headerIdleMs, cfg.timeoutMs);
  server.keepAliveTimeout = Math.max(1, Math.min(headerIdle, 5_000));
  server.headersTimeout = headerIdle;
  server.requestTimeout = cfg.timeoutMs;
  server.timeout = 0;
  const checkMs = Math.max(20, Math.min(headerIdle, 250));
  (server as Server & { connectionsCheckingInterval?: number }).connectionsCheckingInterval = checkMs;
  const headerTimers = new WeakMap<Socket, ReturnType<typeof setTimeout>>();
  const armHeaderIdle = (socket: Socket): void => {
    const prev = headerTimers.get(socket);
    if (prev) clearTimeout(prev);
    const t = setTimeout(() => {
      if (!socket.destroyed) {
        emit(cfg, { result: "error", code: "timeout", method: "OTHER" });
        try {
          socket.write("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        } catch {
          /* ignore */
        }
        socket.destroy();
      }
    }, headerIdle);
    headerTimers.set(socket, t);
    socket.once("close", () => {
      const x = headerTimers.get(socket);
      if (x) clearTimeout(x);
    });
  };
  const clearHeaderIdle = (socket: Socket | undefined): void => {
    if (!socket) return;
    const t = headerTimers.get(socket);
    if (t) {
      clearTimeout(t);
      headerTimers.delete(socket);
    }
  };
  server.prependListener("connection", armHeaderIdle);
  server.on("connect", (_req, socket) => {
    clearHeaderIdle(socket as unknown as Socket);
    emit(cfg, { result: "deny", code: "method_denied", method: methodMeta("CONNECT") });
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    socket.destroy();
  });
  server.on("upgrade", (req, socket) => {
    clearHeaderIdle(socket as unknown as Socket);
    emit(cfg, { result: "deny", code: "upgrade_denied", method: methodMeta(req.method) });
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    socket.destroy();
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const item: Inflight = { abort: new AbortController(), req, res };
    const requestId = randomUUID();
    let answered = false;
    let tracked = false;
    const fail = (code: string, extra?: Partial<ModelGatewayEvent>): void => {
      if (answered) return;
      answered = true;
      drain(req);
      sendError(res, statusFor(code), code);
      emit(cfg, {
        result: code === "timeout" || code === "upstream_error" ? "error" : "deny",
        code,
        method: methodMeta(req.method),
        ...extra,
        field: extra?.field !== undefined ? publicProtocolField(extra.field) : undefined,
      });
    };

    if (closed) {
      fail("gateway_closed");
      return;
    }
    const started = Date.now();
    let absTimer: ReturnType<typeof setTimeout> | undefined;
    let absoluteTimeout = false;
    const finish = (): void => {
      if (absTimer) clearTimeout(absTimer);
      if (tracked) inflight.delete(item);
    };

    try {
      if (!isLoopbackAddress(req.socket.remoteAddress)) {
        fail("host_denied");
        return;
      }
      const port = listenPortOf(server);
      if (port < 0 || !hostHeaderOk(req.headers.host, port)) {
        fail("host_denied");
        return;
      }
      if (hasUpgrade(req)) {
        fail("upgrade_denied");
        return;
      }
      if (Array.isArray(req.headers.authorization)) {
        fail("auth_denied");
        return;
      }
      const provided = parseBearer(req.headers.authorization) ?? "";
      if (!tokenEqual(provided, cfg.sessionToken)) {
        fail("auth_denied");
        return;
      }
      if (inflight.size >= cfg.maxInflight) {
        emit(cfg, { result: "deny", code: "busy", method: methodMeta(req.method) });
        sendError(res, 429, "busy");
        req.resume();
        return;
      }
      inflight.add(item);
      tracked = true;
      absTimer = setTimeout(() => {
        absoluteTimeout = true;
        if (item.up) item.up.destroy();
        fail("timeout");
        destroyInflight(item);
      }, cfg.timeoutMs);
      if (req.method !== "POST") {
        fail("method_denied", { method: methodMeta(req.method) });
        return;
      }
      const path = clientPath(req.url);
      if (!path.ok) {
        fail(path.code);
        return;
      }
      if (!cfg.allowedRoutes.has(path.path)) {
        fail("route_denied", { route: path.path });
        return;
      }
      if (!IMPLEMENTED_MODEL_ROUTES.has(path.path)) {
        fail("protocol_unsupported", { route: path.path });
        return;
      }
      if (!jsonContentType(headerVal(req.headers["content-type"]))) {
        fail("content_type", { route: path.path });
        return;
      }
      if (badContentEncoding(req.headers["content-encoding"])) {
        fail("content_encoding", { route: path.path });
        return;
      }

      let rawBuf: Buffer;
      try {
        rawBuf = await readBody(req, cfg.bodyLimit, item.abort.signal, cfg.bodyIdleMs);
      } catch (e) {
        const code = e instanceof DenyRead ? e.code : item.abort.signal.aborted ? "cancelled" : "malformed";
        fail(code, { route: path.path });
        return;
      }
      if (item.abort.signal.aborted || closed || res.destroyed) {
        fail("cancelled", { route: path.path, inBytes: rawBuf.length });
        return;
      }
      const text = utf8Strict(rawBuf);
      if (text === null) {
        fail("malformed", { route: path.path, inBytes: rawBuf.length });
        return;
      }
      const inspected = inspectModelPayload(path.path, text, cfg.onInspectTap);
      if (!inspected.ok) {
        fail(inspected.code, {
          route: path.path,
          inBytes: rawBuf.length,
          field: publicProtocolField(inspected.field),
        });
        return;
      }

      const outBody = Buffer.from(JSON.stringify(inspected.payload), "utf8");
      const remaining = Math.max(50, cfg.timeoutMs - (Date.now() - started));
      const headers = upstreamHeaders(cfg.origin, outBody.length, inspected.stream, cfg.upstreamToken);
      const options: RequestOptions = {
        protocol: cfg.origin.protocol,
        hostname: cfg.origin.hostname,
        port: originPort(cfg.origin),
        path: path.path,
        method: "POST",
        headers,
        timeout: remaining,
        agent: false,
      };

      await new Promise<void>((resolve) => {
        let settled = false;
        let observer: ResponseRiskObserver | undefined;
        let responseEnded = false;
        let failureCause: NonNullable<ModelGatewayEvent["transport"]>["outcome"] | undefined;
        let streamIdle: ReturnType<typeof setTimeout> | undefined;
        let upResRef: IncomingMessage | undefined;
        const done = (outcome: NonNullable<ModelGatewayEvent["transport"]>["outcome"] = "unknown"): void => {
          if (settled) return;
          settled = true;
          outcome = absoluteTimeout ? "timeout" : failureCause ?? outcome;
          if (observer) {
            const observation = observer.finish(!responseEnded);
            emit(cfg, {result: outcome === "complete" ? "ok" : "error", code:"response_observed", requestId, upstreamHost:cfg.origin.hostname, route:path.path, responseObservation:observation, transport:{upstreamComplete:responseEnded,clientWriteComplete:responseEnded && res.writableFinished,outcome}});
          }
          if (streamIdle) clearTimeout(streamIdle);
          resolve();
        };
        const bumpStreamIdle = (): void => {
          if (streamIdle) clearTimeout(streamIdle);
          streamIdle = setTimeout(() => {
            failureCause = "timeout";
            item.up?.destroy();
            upResRef?.destroy();
            if (!res.headersSent) fail("timeout", { route: path.path, inBytes: rawBuf.length });
            else res.destroy();
            done("timeout");
          }, cfg.streamIdleMs);
        };
        const onClientGone = (): void => {
          if (settled) return;
          failureCause ??= "cancelled";
          item.up?.destroy();
          upResRef?.destroy();
          if (!res.writableEnded && !answered) fail("cancelled", { route: path.path, inBytes: rawBuf.length });
          else if (!res.writableEnded) res.destroy();
          done("cancelled");
        };
        req.on("aborted", onClientGone);
        res.on("close", () => {
          if (!res.writableFinished) onClientGone();
        });
        res.once("finish", () => {
          if (responseEnded && !settled) {
            emit(cfg,{result:"ok",code:"forwarded",requestId,method:"POST",route:path.path,stream:inspected.stream,inBytes:rawBuf.length,outBytes,redacted:inspected.redacted});
            done("complete");
          }
        });
        item.abort.signal.addEventListener("abort", () => {
          failureCause ??= absoluteTimeout ? "timeout" : "gateway_closed";
          item.up?.destroy();
          upResRef?.destroy();
          if (!answered) fail("gateway_closed", { route: path.path, inBytes: rawBuf.length });
          else res.destroy();
          done(absoluteTimeout ? "timeout" : "gateway_closed");
        });
        let outBytes = 0;
        let upReq: ClientRequest;
        try {
          upReq = openUpstream(cfg, options, (upRes) => {
            upResRef = upRes;
            if (settled) {
              upRes.resume();
              upRes.destroy();
              return;
            }
            const code = upRes.statusCode ?? 0;
            if (code >= 300 && code < 400) {
              upRes.resume();
              upRes.destroy();
              fail("upstream_redirect", { route: path.path, inBytes: rawBuf.length });
              done();
              return;
            }
            if (badContentEncoding(upRes.headers["content-encoding"])) {
              upRes.resume();
              upRes.destroy();
              fail("upstream_encoding", { route: path.path, inBytes: rawBuf.length });
              done();
              return;
            }
            const kind = allowedUpstreamType(String(upRes.headers["content-type"] ?? ""));
            if (!kind) {
              upRes.resume();
              upRes.destroy();
              fail("upstream_type", { route: path.path, inBytes: rawBuf.length });
              done();
              return;
            }
            if (res.headersSent || res.destroyed) {
              upRes.destroy();
              done();
              return;
            }
            observer = new ResponseRiskObserver(kind);
            const ctype =
              kind === "sse"
                ? "text/event-stream; charset=utf-8"
                : kind === "json"
                  ? "application/json; charset=utf-8"
                  : "text/plain; charset=utf-8";
            answered = true;
            // Honor an explicit client close after the terminating chunk has been flushed.
            if (String(req.headers.connection ?? "").toLowerCase().split(",").some(t=>t.trim()==="close")) {
              const downstreamSocket=req.socket;res.once("finish",()=>downstreamSocket.end());
            }
            res.writeHead(code || 200, {
              ...SECURITY_HEADERS,
              "content-type": ctype,
              // Close-delimited EOF cannot distinguish failure from completion on older Node clients.
              "transfer-encoding": "chunked",
              // Node 24.15 fetch treats Connection: close truncation as EOF even with chunked.
              "connection": "keep-alive",
            });
            bumpStreamIdle();
            upRes.on("data", (c: Buffer) => {
              bumpStreamIdle();
              observer?.push(c);
              outBytes += c.length;
              if (outBytes > cfg.maxOutBytes) {
                failureCause = "output_limit";
                upRes.destroy();
                upReq.destroy();
                res.destroy();
                done("output_limit");
                return;
              }
              if (res.destroyed || !res.writable) {
                upRes.destroy();
                done();
                return;
              }
              const ok = res.write(c);
              if (!ok) upRes.pause();
            });
            res.on("drain", () => upRes.resume());
            upRes.on("end", () => {
              responseEnded = true;
              if (!res.destroyed && !res.writableEnded) res.end();

              // Completion is reported only by the downstream finish event.
            });
            upRes.on("error", () => {
              upReq.destroy();
              if (!res.headersSent) fail("upstream_error", { route: path.path });
              else res.destroy();
              done("upstream_error");
            });
            upRes.on("aborted", () => {
              upReq.destroy();
              if (!res.writableEnded) res.destroy();
              done("upstream_error");
            });
            upRes.on("close", () => {
              if (!settled && !responseEnded) {
                if (!res.writableEnded) res.destroy();
                done("upstream_error");
              }
            });
          });
        } catch {
          fail("upstream_error", { route: path.path, inBytes: rawBuf.length });
          done();
          return;
        }
        item.up = upReq;
        upReq.on("timeout", () => {
          failureCause = "timeout";
          upReq.destroy();
          if (!res.headersSent) fail("timeout", { route: path.path, inBytes: rawBuf.length });
          else res.destroy();
          done("timeout");
        });
        upReq.on("error", () => {
          if (settled) return;
          if (!res.headersSent) fail("upstream_error", { route: path.path, inBytes: rawBuf.length });
          else res.destroy();
          done("upstream_error");
        });
        upReq.on("close", () => {
          if (settled || responseEnded) return;
          if (!res.headersSent) fail("upstream_error", { route: path.path, inBytes: rawBuf.length });
          else if (!res.writableEnded) res.destroy();
          done("upstream_error");
        });
        upReq.write(outBody);
        upReq.end();
      });
    } finally {
      finish();
    }
  }

  await new Promise<void>((resolve, reject) => {
    const onErr = (e: Error): void => reject(e);
    server.once("error", onErr);
    server.listen(cfg.bindPort, cfg.bindHost, () => {
      server.off("error", onErr);
      resolve();
    });
  });

  const port = listenPortOf(server);
  if (port < 0) {
    server.close();
    throw new Error("listen_failed");
  }
  const url = `http://${cfg.bindHost === "::1" ? "[::1]" : cfg.bindHost}:${port}`;

  const close = async (): Promise<void> => {
    if (closing) return closing;
    closed = true;
    closing = (async () => {
      for (const item of inflight) destroyInflight(item);
      inflight.clear();
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((e) => (e ? reject(e) : resolve()));
      });
    })();
    return closing;
  };

  const status = (): ModelGatewayStatus => ({
    bindHost: cfg.bindHost,
    port,
    url,
    upstreamHost: cfg.origin.host,
    allowedRoutes: [...cfg.allowedRoutes],
    implementedRoutes: [...IMPLEMENTED_MODEL_ROUTES],
    inflight: inflight.size,
    timeoutMs: cfg.timeoutMs,
    headerIdleMs: cfg.headerIdleMs,
    maxInflight: cfg.maxInflight,
    blocksDirectOutbound: false,
    poisonDetection: true,
      responseInspection: "chat_completions_json_sse_alert_only",
    covertChannelComplete: false,
    audit: {...cfg.audit},
  });

  return { port, url, sessionToken: cfg.sessionToken, close, status };
}

function headerVal(v: string | string[] | undefined): string | undefined {
  if (Array.isArray(v)) return v[0];
  return v;
}

function isLoopbackAddress(addr: string | undefined): boolean {
  if (!addr) return false;
  return addr === "127.0.0.1" || addr === "::1" || addr === ":ffff:127.0.0.1" || addr === "::ffff:127.0.0.1";
}

/** Test helper: loopback HTTP factory. Trusted caller only. */
export function loopbackHttpFactory(options: RequestOptions, cb: (res: IncomingMessage) => void): ClientRequest {
  const host = String(options.hostname ?? "");
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    throw new Error("origin_invalid");
  }
  return httpRequest(
    {
      protocol: "http:",
      hostname: options.hostname,
      port: options.port,
      path: options.path,
      method: options.method ?? "POST",
      headers: options.headers,
      timeout: options.timeout,
      agent: false,
    },
    cb,
  );
}
