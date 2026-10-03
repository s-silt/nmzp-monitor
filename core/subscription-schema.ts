import { RULE_ID_RE } from "./policy-schema.ts";

/** WP-26d remote rule subscription. Only the core fetches it; devices never see this field. */
export interface PolicySubscription {
  id: string;
  url: string;
  enabled: boolean;
  intervalMinutes: number;
  lastFetchedAt?: number;
  lastEtag?: string;
  lastDigest?: string;
  lastError?: string;
}

export const MAX_SUBSCRIPTIONS = 16;
export const MIN_SUBSCRIPTION_INTERVAL_MINUTES = 60;
export const MAX_SUBSCRIPTION_INTERVAL_MINUTES = 7 * 24 * 60;
export const DEFAULT_SUBSCRIPTION_INTERVAL_MINUTES = 60;
export const SUBSCRIPTION_URL_MAX = 2048;

const ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const SUBSCRIPTION_KEYS = new Set(["id", "url", "enabled", "intervalMinutes", "lastFetchedAt", "lastEtag", "lastDigest", "lastError"]);

function plainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function printableAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/**
 * HTTPS only, no userinfo, no fragment. Returns the WHATWG-normalized href so the stored
 * value is exactly what the fetcher requests. Address checks happen at fetch time (DNS).
 */
export function parseSubscriptionUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length < 1 || raw.length > SUBSCRIPTION_URL_MAX || !printableAscii(raw)) return undefined;
  let url: URL;
  try { url = new URL(raw); }
  catch { return undefined; }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.hash) return undefined;
  const href = url.href;
  return href.length <= SUBSCRIPTION_URL_MAX ? href : undefined;
}

export function subscriptionEtagOk(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 256 && printableAscii(value);
}

function intervalOk(value: unknown): value is number {
  return Number.isSafeInteger(value) &&
    (value as number) >= MIN_SUBSCRIPTION_INTERVAL_MINUTES && (value as number) <= MAX_SUBSCRIPTION_INTERVAL_MINUTES;
}

export function parseSubscriptionInterval(raw: unknown): number | undefined {
  return intervalOk(raw) ? raw : undefined;
}

/** Undefined on any bad element, duplicate id, or more than MAX_SUBSCRIPTIONS rows. */
export function parsePolicySubscriptions(raw: unknown): PolicySubscription[] | undefined {
  if (!Array.isArray(raw) || raw.length > MAX_SUBSCRIPTIONS) return undefined;
  const out: PolicySubscription[] = [];
  const seen = new Set<string>();
  for (const row of raw) {
    if (!plainObject(row)) return undefined;
    for (const key of Object.keys(row)) if (!SUBSCRIPTION_KEYS.has(key)) return undefined;
    if (typeof row.id !== "string" || !RULE_ID_RE.test(row.id) || seen.has(row.id)) return undefined;
    const url = parseSubscriptionUrl(row.url);
    if (!url || url !== row.url) return undefined;
    if (typeof row.enabled !== "boolean" || !intervalOk(row.intervalMinutes)) return undefined;
    const item: PolicySubscription = { id: row.id, url, enabled: row.enabled, intervalMinutes: row.intervalMinutes };
    if (row.lastFetchedAt !== undefined) {
      if (!Number.isSafeInteger(row.lastFetchedAt) || (row.lastFetchedAt as number) < 0) return undefined;
      item.lastFetchedAt = row.lastFetchedAt as number;
    }
    if (row.lastEtag !== undefined) {
      if (!subscriptionEtagOk(row.lastEtag)) return undefined;
      item.lastEtag = row.lastEtag;
    }
    if (row.lastDigest !== undefined) {
      if (typeof row.lastDigest !== "string" || !DIGEST_RE.test(row.lastDigest)) return undefined;
      item.lastDigest = row.lastDigest;
    }
    if (row.lastError !== undefined) {
      if (typeof row.lastError !== "string" || !ERROR_CODE_RE.test(row.lastError)) return undefined;
      item.lastError = row.lastError;
    }
    seen.add(row.id);
    out.push(item);
  }
  return out;
}
