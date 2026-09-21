const RELATIVE_MIN = 60_000;
const RELATIVE_HOUR = 3_600_000;
const UTC8_MS = 8 * 60 * 60 * 1000;
/** ECMAScript TimeClip: |t| > 8.64e15 is an invalid Date. */
const TIME_CLIP_MS = 8.64e15;
const INVALID_TS = "—";

/** Wall clock in fixed UTC+8 (Asia/Shanghai, no DST). */
function utc8Stamp(ts: number): { date: string; time: string } | null {
  if (!Number.isFinite(ts) || ts <= 0) return null;
  const shifted = ts + UTC8_MS;
  if (!Number.isFinite(shifted) || Math.abs(shifted) > TIME_CLIP_MS) return null;
  const d = new Date(shifted);
  if (!Number.isFinite(d.getTime())) return null;
  try {
    const iso = d.toISOString();
    return { date: iso.slice(0, 10), time: iso.slice(11, 19) };
  } catch {
    return null;
  }
}

export function uid(prefix = "e") {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-4)}`;
}

export function shortId(id: string) {
  return id.replace(/^s_/, "").slice(0, 7);
}

export function formatTime(ts: number, _locale: "zh" | "en") {
  return utc8Stamp(ts)?.time ?? INVALID_TS;
}

export function formatDateTime(ts: number, _locale: "zh" | "en") {
  const stamp = utc8Stamp(ts);
  if (!stamp) return INVALID_TS;
  const date = ts >= 1735689600000 ? stamp.date.replace(/-/g, "\u2011") : stamp.date;
  return `${date} ${stamp.time}`;
}

export function formatRelative(ts: number, locale: "zh" | "en", now = Date.now()) {
  if (ts - now > 8_000) return formatDateTime(ts, locale);
  const d = now - ts;
  if (d < 8_000) return locale === "zh" ? "刚刚" : "just now";
  if (d < RELATIVE_MIN) return locale === "zh" ? `${Math.floor(d / 1000)} 秒前` : `${Math.floor(d / 1000)}s ago`;
  if (d < RELATIVE_HOUR)
    return locale === "zh" ? `${Math.floor(d / RELATIVE_MIN)} 分钟前` : `${Math.floor(d / RELATIVE_MIN)}m ago`;
  const h = Math.floor(d / RELATIVE_HOUR);
  return locale === "zh" ? `${h} 小时前` : `${h}h ago`;
}

export function formatCompact(n: number) {
  if (n < 1000) return String(n);
  if (n < 10_000) return `${(n / 1000).toFixed(1)}k`;
  if (n < 1_000_000) return `${Math.round(n / 1000)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatTokens(n: number) {
  if (n < 1000) return String(n);
  if (n < 10_000) return `${(n / 1000).toFixed(1)}k`;
  return `${Math.round(n / 1000)}k`;
}

export function truncate(s: string, n = 88) {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

export function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]!;
}

export function jitter(min: number, max: number) {
  return min + Math.random() * (max - min);
}

/**
 * Strips URL credentials (user:pass@) and sensitive signature/auth query parameters
 * so they are never exposed in UI details or logs.
 */
export function sanitizeDisplayUrl(text: string): string {
  if (!text) return "";
  let s = text.replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1");
  s = s.replace(
    /([?&](?:(?:X-Amz-[^=&\s]+|Signature|OSSAccessKeyId|Expires|SecurityToken|token|access[-_]?token|secret|password|passwd|key|auth|api[-_]?key)=[^&\s]*))/gi,
    "",
  );
  s = s.replace(/\?&+/g, "?").replace(/[?&](?=\s|$)/g, "");
  return s;
}
