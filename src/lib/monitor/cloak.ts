/**
 * Listed agents, outbound hook plaintext only.
 * Profile tags become a US user: Asia/Tokyo → America/New_York, ja-JP → en-US.
 * Does not change the clock, local Tokyo files, TLS, or the model-API IP.
 */

const TELEMETRY_HOST =
  /(?:^|\.)(statsig\.(com|net)|statsig\.anthropic\.com|sentry\.io|amplitude\.com|api\.segment\.(io|com)|segment\.io|api\.honeycomb\.io|telemetry\.anthropic\.com)$/i;

const TELEMETRY_PATH = /\/(telemetry|event_logging|analytics|statsig)\b/i;

const MODEL_CHAT =
  /(?:^|\.)(api\.anthropic\.com|api\.openai\.com|api\.x\.ai|api\.z\.ai|open\.bigmodel\.cn)$/i;

const CLOAK_TOOLS = new Set(["Bash", "WebFetch", "WebSearch", "MCP"]);

const OUT = /\b(curl|wget|httpie|aria2c)\b|https?:\/\//i;

type Replacer = (match: string, ...args: string[]) => string;

/** Metadata keys only. Place names in the user's work are left alone. */
const FIELDS: Array<{ kind: string; re: RegExp; to: string | Replacer }> = [
  {
    kind: "tz",
    re: /("(?:timezone|timeZone|time_zone|tz)"\s*:\s*")Asia\/Tokyo(")/g,
    to: (_m, a, b) => `${a}America/New_York${b}`,
  },
  {
    kind: "tz",
    re: /((?:^|[^\w])(?:timezone|time[_-]?zone|\btz)\s*[:=]\s*["']?)Asia\/Tokyo\b/gi,
    to: (_m, a) => `${a}America/New_York`,
  },
  {
    kind: "offset",
    re: /("(?:utc[_-]?offset|gmt_offset|tz_offset|offset)"\s*:\s*")(?:\+09:00|\+0900)(")/gi,
    to: (_m, a, b) => `${a}-05:00${b}`,
  },
  {
    kind: "locale",
    re: /("(?:locale|language|lang|accept[-_]?language)"\s*:\s*")ja[-_]JP(")/gi,
    to: (_m, a, b) => `${a}en-US${b}`,
  },
  {
    kind: "locale",
    re: /((?:^|[^\w])(?:locale|language|\blang|LC_ALL|LC_TIME|LANG|Accept-Language)\s*[:=]\s*["']?)ja[-_]JP\b/gi,
    to: (_m, a) => `${a}en-US`,
  },
  {
    kind: "country",
    re: /("(?:country_name|countryName)"\s*:\s*")Japan(")/gi,
    to: (_m, a, b) => `${a}United States${b}`,
  },
  {
    kind: "country",
    re: /((?:^|[^\w])(?:country_name|countryName)\s*[:=]\s*["']?)Japan\b/gi,
    to: (_m, a) => `${a}United States`,
  },
  {
    kind: "country",
    re: /("(?:country[_-]?code|geo[_-]?country|\bcountry)"\s*:\s*")(?:JP|JPN)(")/gi,
    to: (_m, a, b) => `${a}US${b}`,
  },
  {
    kind: "country",
    re: /((?:^|[^\w])(?:country[_-]?code|geo[_-]?country|\bcountry)\s*[:=]\s*["']?)(?:JP|JPN)\b/gi,
    to: (_m, a) => `${a}US`,
  },
];

export function isTelemetryHost(host: string) {
  return TELEMETRY_HOST.test(host.trim().toLowerCase());
}

export function isTelemetryUrl(blob: string) {
  if (!blob) return false;
  if (MODEL_CHAT.test(blob) && /\/v1\/(messages|chat|responses)/i.test(blob) && !TELEMETRY_PATH.test(blob)) {
    return false;
  }
  return TELEMETRY_HOST.test(blob) || TELEMETRY_PATH.test(blob);
}

export function shouldCloakPersona(input: {
  agent?: string;
  tool: string;
  command?: string;
  url?: string;
  dest?: string;
}) {
  if (!CLOAK_TOOLS.has(input.tool)) return false;
  if (input.url || input.dest) return true;
  return OUT.test(input.command ?? "");
}

export function cloakPersona(text: string): { text: string; changed: boolean; kinds: string[] } {
  if (!text) return { text, changed: false, kinds: [] };
  let out = text;
  const kinds: string[] = [];
  for (const p of FIELDS) {
    p.re.lastIndex = 0;
    if (!p.re.test(out)) continue;
    p.re.lastIndex = 0;
    out = out.replace(p.re, p.to as Replacer);
    if (!kinds.includes(p.kind)) kinds.push(p.kind);
  }
  return { text: out, changed: out !== text, kinds };
}
