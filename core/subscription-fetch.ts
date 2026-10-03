import { lookup as dnsLookup } from "node:dns/promises";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { NMZP_VERSION } from "./constants.ts";
import { subscriptionEtagOk } from "./subscription-schema.ts";

export const SUBSCRIPTION_TIMEOUT_MS = 10_000;
export const SUBSCRIPTION_MAX_BYTES = 256 * 1024;
const MAX_REDIRECTS = 3;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export type SubscriptionFetchResult =
  | { kind: "ok"; body: unknown; etag?: string }
  | { kind: "not_modified" }
  | { kind: "error"; code: string };

export interface ResolvedAddress {
  address: string;
  family: number;
}

export interface SubscriptionFetchOptions {
  etag?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxBytes?: number;
  /** Trusted test seams. Production uses system DNS, isPublicAddress and the default CA store. */
  resolve?: (hostname: string) => Promise<ResolvedAddress[]>;
  addressAllowed?: (address: string) => boolean;
  ca?: string;
}

class FetchFailure extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function ipv4Value(ip: string): number | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const n = Number(part);
    if (n > 255) return undefined;
    value = value * 256 + n;
  }
  return value;
}

function ipv6Value(ip: string): bigint | undefined {
  if (ip.includes("%")) return undefined;
  let text = ip;
  let tail: number[] = [];
  const lastColon = text.lastIndexOf(":");
  if (text.slice(lastColon + 1).includes(".")) {
    const v4 = ipv4Value(text.slice(lastColon + 1));
    if (v4 === undefined) return undefined;
    tail = [Math.floor(v4 / 65536), v4 % 65536];
    text = text.slice(0, lastColon + 1) + "0";
  }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const groupsNeeded = 8 - (tail.length ? 1 : 0);
  let groups: string[];
  if (halves.length === 2) {
    const fill = groupsNeeded - head.length - rest.length;
    if (fill < 1) return undefined;
    groups = [...head, ...Array<string>(fill).fill("0"), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== groupsNeeded) return undefined;
  const words: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return undefined;
    words.push(parseInt(group, 16));
  }
  if (tail.length) words.splice(words.length - 1, 1, ...tail);
  let value = 0n;
  for (const word of words) value = (value << 16n) | BigInt(word);
  return value;
}

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];
// Global unicast 2000::/3 only. Inside it: IETF special (incl. Teredo), documentation, 6to4.
const V6_BLOCKED: Array<[string, number]> = [["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20]];

function inV4(value: number, [base, prefix]: [string, number]): boolean {
  const size = 2 ** (32 - prefix);
  return Math.floor(value / size) === Math.floor(ipv4Value(base)! / size);
}

function inV6(value: bigint, [base, prefix]: [string, number]): boolean {
  const shift = BigInt(128 - prefix);
  return value >> shift === ipv6Value(base)! >> shift;
}

/**
 * Public unicast only. Loopback, link-local, private, CGNAT, multicast, documentation, reserved
 * and every IPv6 form that embeds or maps an IPv4 address are refused (SSRF).
 */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const value = ipv4Value(address);
    return value !== undefined && !V4_BLOCKED.some((range) => inV4(value, range));
  }
  if (family === 6) {
    const value = ipv6Value(address);
    if (value === undefined || !inV6(value, ["2000::", 3])) return false;
    return !V6_BLOCKED.some((range) => inV6(value, range));
  }
  return false;
}

async function systemResolve(hostname: string): Promise<ResolvedAddress[]> {
  return dnsLookup(hostname, { all: true, verbatim: true });
}

function bareHost(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

/** dns.lookup takes no signal; the wall deadline must still cover a hung resolver. */
function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const onAbort = (): void => reject(new Error("aborted"));
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/** Every resolved address must pass; the connection then goes to the vetted address only. */
async function vet(hostname: string, options: SubscriptionFetchOptions, signal: AbortSignal): Promise<ResolvedAddress> {
  const allowed = options.addressAllowed ?? isPublicAddress;
  const host = bareHost(hostname);
  const literal = isIP(host);
  let addresses: ResolvedAddress[];
  if (literal) addresses = [{ address: host, family: literal }];
  else {
    try { addresses = await raceAbort((options.resolve ?? systemResolve)(host), signal); }
    catch (error) {
      if (signal.aborted) throw error;
      throw new FetchFailure("dns_failed");
    }
  }
  if (!addresses.length) throw new FetchFailure("dns_failed");
  if (addresses.some((row) => !allowed(row.address))) throw new FetchFailure("address_blocked");
  return addresses[0]!;
}

function pinnedLookup(target: ResolvedAddress): LookupFunction {
  return ((_hostname: string, lookupOptions: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (lookupOptions?.all) callback(null, [{ address: target.address, family: target.family }]);
    else callback(null, target.address, target.family);
  }) as unknown as LookupFunction;
}

function send(url: URL, target: ResolvedAddress, options: SubscriptionFetchOptions, signal: AbortSignal): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {
      accept: "application/json",
      "user-agent": `nmzp-monitor/${NMZP_VERSION}`,
    };
    if (options.etag) headers["if-none-match"] = options.etag;
    const req = httpsRequest(url, {
      method: "GET",
      agent: false,
      headers,
      lookup: pinnedLookup(target),
      signal,
      ...(options.ca ? { ca: options.ca } : {}),
    }, resolve);
    req.on("error", reject);
    req.end();
  });
}

function readCapped(res: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let ended = false;
    res.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        res.destroy();
        reject(new FetchFailure("too_large"));
        return;
      }
      chunks.push(chunk);
    });
    res.on("end", () => {
      ended = true;
      resolve(Buffer.concat(chunks));
    });
    res.on("error", reject);
    // A deadline abort or reset closes without "end"; errorCode() maps it to timeout first.
    res.on("close", () => {
      if (!ended) reject(new FetchFailure("network_error"));
    });
  });
}

function errorCode(error: unknown, signal: AbortSignal, external?: AbortSignal): string {
  if (signal.aborted) return external?.aborted ? "aborted" : "timeout";
  if (error instanceof FetchFailure) return error.code;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ECONNREFUSED") return "connect_failed";
  if (code.startsWith("ERR_TLS") || code.startsWith("CERT_") || code.includes("SELF_SIGNED") || code.startsWith("UNABLE_TO_")
    || code === "DEPTH_ZERO_SELF_SIGNED_CERT" || code === "HOSTNAME_MISMATCH") return "tls_error";
  return "network_error";
}

async function run(start: URL, options: SubscriptionFetchOptions, signal: AbortSignal): Promise<SubscriptionFetchResult> {
  let current = start;
  for (let hop = 0; ; hop++) {
    const target = await vet(current.hostname, options, signal);
    const res = await send(current, target, options, signal);
    const status = res.statusCode ?? 0;
    // Bodies other than a 200 are never read: destroy instead of draining an unbounded stream.
    if (REDIRECTS.has(status)) {
      res.destroy();
      if (hop >= MAX_REDIRECTS) throw new FetchFailure("redirect_limit");
      const location = res.headers.location;
      if (!location) throw new FetchFailure("redirect_invalid");
      let next: URL;
      try { next = new URL(location, current); }
      catch { throw new FetchFailure("redirect_invalid"); }
      if (next.protocol !== "https:" || next.username || next.password) throw new FetchFailure("redirect_invalid");
      if (next.hostname !== current.hostname || next.port !== current.port) throw new FetchFailure("redirect_cross_host");
      next.hash = "";
      current = next;
      continue;
    }
    if (status === 304) {
      res.destroy();
      if (!options.etag) throw new FetchFailure("http_304");
      return { kind: "not_modified" };
    }
    if (status !== 200) {
      res.destroy();
      throw new FetchFailure(status >= 100 && status <= 599 ? `http_${status}` : "http_invalid");
    }
    const encoding = res.headers["content-encoding"];
    if (encoding !== undefined && encoding.toLowerCase() !== "identity") {
      res.destroy();
      throw new FetchFailure("unsupported_encoding");
    }
    const maxBytes = options.maxBytes ?? SUBSCRIPTION_MAX_BYTES;
    const declared = Number(res.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
      res.destroy();
      throw new FetchFailure("too_large");
    }
    const raw = await readCapped(res, maxBytes);
    let body: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
      body = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    } catch {
      throw new FetchFailure("invalid_json");
    }
    const etag = res.headers.etag;
    return subscriptionEtagOk(etag) ? { kind: "ok", body, etag } : { kind: "ok", body };
  }
}

/**
 * Core-only HTTPS GET for a rule subscription. One wall deadline covers DNS, TLS, redirects and
 * the body. Same-host redirects only. Never throws: every failure is a stable error code.
 */
export async function fetchSubscription(url: string, options: SubscriptionFetchOptions = {}): Promise<SubscriptionFetchResult> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? SUBSCRIPTION_TIMEOUT_MS);
  const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
  let start: URL;
  try { start = new URL(url); }
  catch { return { kind: "error", code: "invalid_url" }; }
  if (start.protocol !== "https:") return { kind: "error", code: "invalid_url" };
  try {
    if (signal.aborted) throw new FetchFailure(options.signal?.aborted ? "aborted" : "timeout");
    return await run(start, options, signal);
  } catch (error) {
    return { kind: "error", code: errorCode(error, signal, options.signal) };
  }
}
