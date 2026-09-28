import { readFileSync, type Stats } from "node:fs";
import { isIP } from "node:net";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_AUDIT_RETENTION, type AuditRetention } from "../audit/store.ts";
import { validateJsonSchema } from "../doctor/schema-validate.ts";
import { parseCidr } from "../lan-viewer.ts";
import { pathHasSymlinkAncestry } from "./posix.ts";

export const CONFIG_SHOW_SCHEMA_VERSION = 1 as const;
export const DEFAULT_BIND = "0.0.0.0";
export const DEFAULT_PORT = 8787;
export const DEFAULT_STORAGE_MODE = "window" as const;
export const DEFAULT_VIEWER_PORT = 8789;
export const AUDIT_DAY_MS = 86400_000;
export const AUDIT_MB = 1024 * 1024;

export type ConfigSource = "DEFAULT" | "ENV" | "FILE";

export interface ConfigItem {
  key: string;
  value: string | number | null;
  source: ConfigSource;
  secret: boolean;
  securityRelevant: boolean;
  valid: boolean;
  isSet: boolean;
  problem?: string;
}

export interface ConfigShowReport {
  schemaVersion: typeof CONFIG_SHOW_SCHEMA_VERSION;
  items: ConfigItem[];
}

export interface ResolveConfigOpts {
  home?: string;
  dataDir?: string;
  /** Omit in production. Tests use this to present symlink ownership. */
  lstat?: (path: string) => Stats;
}

const HOSTNAME =
  /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;

export function defaultDataDir(home = homedir()): string {
  return join(home, ".nmzp", "ct-data");
}

export function defaultHomeDir(): string {
  return homedir();
}

export function isBindHost(raw: string): boolean {
  if (!raw || /\s/.test(raw)) return false;
  const bare = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  if (isIP(bare) !== 0) return true;
  return HOSTNAME.test(bare);
}

export function isWildcardBind(raw: string | number | null): boolean {
  return raw === "0.0.0.0" || raw === "::";
}

function envSet(env: NodeJS.ProcessEnv, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(env, key) && env[key] !== undefined;
}

function item(partial: Omit<ConfigItem, "isSet"> & { isSet: boolean }): ConfigItem {
  const row: ConfigItem = {
    key: partial.key,
    value: partial.value,
    source: partial.source,
    secret: partial.secret,
    securityRelevant: partial.securityRelevant,
    valid: partial.valid,
    isSet: partial.isSet,
  };
  if (partial.problem) row.problem = partial.problem;
  return row;
}

function sourceOf(env: NodeJS.ProcessEnv, key: string): ConfigSource {
  return envSet(env, key) ? "ENV" : "DEFAULT";
}

function parsePort(raw: string | undefined, fallback: number): { value: number; valid: boolean; problem?: string } {
  if (raw === undefined) return { value: fallback, valid: true };
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    return { value: fallback, valid: false, problem: "port is not an integer in 0-65535" };
  }
  return { value: n, valid: true };
}

function withoutUserinfo(url: URL): string {
  url.username = "";
  url.password = "";
  return url.href;
}

function parseHttpsUrl(raw: string | undefined): { value: string | null; valid: boolean; problem?: string } {
  if (raw === undefined) return { value: null, valid: true };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { value: raw, valid: false, problem: "must be an https URL" };
  }
  const userinfo = url.username !== "" || url.password !== "";
  const shown = userinfo ? withoutUserinfo(url) : raw;
  if (url.protocol !== "https:" || !url.hostname) {
    return { value: shown, valid: false, problem: "must be an https URL" };
  }
  if (userinfo) return { value: shown, valid: false, problem: "must be an https URL without userinfo" };
  return { value: raw, valid: true };
}

function parseStorage(raw: string | undefined): { value: "window" | "sqlite"; valid: boolean; problem?: string } {
  if (raw === undefined) return { value: DEFAULT_STORAGE_MODE, valid: true };
  if (raw === "window" || raw === "sqlite") return { value: raw, valid: true };
  return { value: DEFAULT_STORAGE_MODE, valid: false, problem: "must be window or sqlite" };
}

function parseAuditInt(
  raw: string | undefined,
  fallback: number,
  scale: number,
): { display: number; msOrBytes: number; valid: boolean; problem?: string } {
  if (raw === undefined) return { display: fallback / scale, msOrBytes: fallback, valid: true };
  if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(Number(raw) * scale)) {
    return { display: fallback / scale, msOrBytes: fallback, valid: false, problem: "not a safe non-negative integer" };
  }
  return { display: Number(raw), msOrBytes: Number(raw) * scale, valid: true };
}

function parseTlsHosts(raw: string | undefined): { value: string; hosts: string[]; valid: boolean; problem?: string } {
  if (raw === undefined) return { value: "", hosts: [], valid: true };
  const hosts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  for (const host of hosts) {
    if (!isBindHost(host)) {
      return { value: raw, hosts, valid: false, problem: `invalid TLS host ${host}` };
    }
  }
  return { value: raw, hosts, valid: true };
}

function parseCidrList(raw: string | undefined): { value: string; valid: boolean; problem?: string } {
  if (raw === undefined) return { value: "", valid: true };
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    if (!parseCidr(part)) return { value: raw, valid: false, problem: `CIDR cannot be parsed: ${part}` };
  }
  return { value: raw, valid: true };
}

function validateDir(
  raw: string | undefined,
  fallback: string,
  label: string,
  lstat?: (path: string) => Stats,
): { value: string; valid: boolean; problem?: string } {
  const value = raw ?? fallback;
  if (!isAbsolute(value)) return { value, valid: false, problem: `${label} must be an absolute path` };
  const probed = pathHasSymlinkAncestry(value, lstat);
  if (!probed.ok) return { value, valid: false, problem: probed.reason };
  if (probed.found) return { value, valid: false, problem: `${label} or a parent is a symlink` };
  return { value, valid: true };
}

export function resolveEffectiveConfig(env: NodeJS.ProcessEnv, opts: ResolveConfigOpts = {}): ConfigShowReport {
  const homeFallback = opts.home ?? defaultHomeDir();
  const dataFallback = opts.dataDir ?? defaultDataDir();

  const bindRaw = env.NMZP_BIND;
  const bindValue = bindRaw ?? DEFAULT_BIND;
  const bindValid = isBindHost(bindValue);

  const port = parsePort(env.NMZP_PORT, DEFAULT_PORT);
  const data = validateDir(env.NMZP_DATA, dataFallback, "data directory", opts.lstat);
  const home = envSet(env, "NMZP_HOME")
    ? validateDir(env.NMZP_HOME, homeFallback, "home directory", opts.lstat)
    : { value: homeFallback, valid: true as const };
  const publicUrl = parseHttpsUrl(env.NMZP_PUBLIC_URL);
  const tls = parseTlsHosts(env.NMZP_TLS_HOSTS);
  const storage = parseStorage(env.NMZP_STORAGE_MODE);
  const viewerHostRaw = env.NMZP_VIEWER_HOST;
  const viewerHostValue = viewerHostRaw ?? "";
  const viewerHostValid = viewerHostRaw === undefined || isBindHost(viewerHostRaw);
  const viewerPort = parsePort(env.NMZP_VIEWER_PORT, DEFAULT_VIEWER_PORT);
  const viewerCidr = parseCidrList(env.NMZP_VIEWER_ALLOW_CIDR);
  const viewerCredSet = envSet(env, "NMZP_VIEWER_CREDENTIAL") && (env.NMZP_VIEWER_CREDENTIAL ?? "").trim() !== "";
  const upstreamSet = envSet(env, "NMZP_UPSTREAM_TOKEN") && (env.NMZP_UPSTREAM_TOKEN ?? "") !== "";
  const auditRecords = parseAuditInt(env.NMZP_AUDIT_MAX_RECORDS, DEFAULT_AUDIT_RETENTION.maxRecords, 1);
  const auditDays = parseAuditInt(env.NMZP_AUDIT_MAX_DAYS, DEFAULT_AUDIT_RETENTION.maxAgeMs, AUDIT_DAY_MS);
  const auditMb = parseAuditInt(env.NMZP_AUDIT_MAX_MB, DEFAULT_AUDIT_RETENTION.maxDbBytes, AUDIT_MB);
  const auditMinFree = parseAuditInt(env.NMZP_AUDIT_MIN_FREE_MB, DEFAULT_AUDIT_RETENTION.minFreeBytes, AUDIT_MB);
  const auditTomb = parseAuditInt(env.NMZP_AUDIT_TOMBSTONE_DAYS, DEFAULT_AUDIT_RETENTION.tombstoneMs, AUDIT_DAY_MS);

  const items: ConfigItem[] = [
    item({
      key: "NMZP_BIND",
      value: bindValue,
      source: sourceOf(env, "NMZP_BIND"),
      secret: false,
      securityRelevant: true,
      valid: bindValid,
      isSet: envSet(env, "NMZP_BIND"),
      problem: bindValid ? undefined : "not a valid IPv4/IPv6 literal or hostname",
    }),
    item({
      key: "NMZP_PORT",
      value: port.value,
      source: sourceOf(env, "NMZP_PORT"),
      secret: false,
      securityRelevant: true,
      valid: port.valid,
      isSet: envSet(env, "NMZP_PORT"),
      problem: port.problem,
    }),
    item({
      key: "NMZP_DATA",
      value: data.value,
      source: sourceOf(env, "NMZP_DATA"),
      secret: false,
      securityRelevant: true,
      valid: data.valid,
      isSet: envSet(env, "NMZP_DATA"),
      problem: data.problem,
    }),
    item({
      key: "NMZP_HOME",
      value: home.value,
      source: sourceOf(env, "NMZP_HOME"),
      secret: false,
      securityRelevant: false,
      valid: home.valid,
      isSet: envSet(env, "NMZP_HOME"),
      problem: home.problem,
    }),
    item({
      key: "NMZP_PUBLIC_URL",
      value: publicUrl.value,
      source: sourceOf(env, "NMZP_PUBLIC_URL"),
      secret: false,
      securityRelevant: true,
      valid: publicUrl.valid,
      isSet: envSet(env, "NMZP_PUBLIC_URL"),
      problem: publicUrl.problem,
    }),
    item({
      key: "NMZP_TLS_HOSTS",
      value: tls.value,
      source: sourceOf(env, "NMZP_TLS_HOSTS"),
      secret: false,
      securityRelevant: true,
      valid: tls.valid,
      isSet: envSet(env, "NMZP_TLS_HOSTS"),
      problem: tls.problem,
    }),
    item({
      key: "NMZP_STORAGE_MODE",
      value: storage.value,
      source: sourceOf(env, "NMZP_STORAGE_MODE"),
      secret: false,
      securityRelevant: true,
      valid: storage.valid,
      isSet: envSet(env, "NMZP_STORAGE_MODE"),
      problem: storage.problem,
    }),
    item({
      key: "NMZP_VIEWER_HOST",
      value: viewerHostValue,
      source: sourceOf(env, "NMZP_VIEWER_HOST"),
      secret: false,
      securityRelevant: true,
      valid: viewerHostValid,
      isSet: envSet(env, "NMZP_VIEWER_HOST"),
      problem: viewerHostValid ? undefined : "not a valid IPv4/IPv6 literal or hostname",
    }),
    item({
      key: "NMZP_VIEWER_PORT",
      value: viewerPort.value,
      source: sourceOf(env, "NMZP_VIEWER_PORT"),
      secret: false,
      securityRelevant: true,
      valid: viewerPort.valid,
      isSet: envSet(env, "NMZP_VIEWER_PORT"),
      problem: viewerPort.problem,
    }),
    item({
      key: "NMZP_VIEWER_ALLOW_CIDR",
      value: viewerCidr.value,
      source: sourceOf(env, "NMZP_VIEWER_ALLOW_CIDR"),
      secret: false,
      securityRelevant: true,
      valid: viewerCidr.valid,
      isSet: envSet(env, "NMZP_VIEWER_ALLOW_CIDR"),
      problem: viewerCidr.problem,
    }),
    item({
      key: "NMZP_VIEWER_CREDENTIAL",
      value: null,
      source: sourceOf(env, "NMZP_VIEWER_CREDENTIAL"),
      secret: true,
      securityRelevant: true,
      valid: true,
      isSet: viewerCredSet,
    }),
    item({
      key: "NMZP_UPSTREAM_TOKEN",
      value: null,
      source: sourceOf(env, "NMZP_UPSTREAM_TOKEN"),
      secret: true,
      securityRelevant: false,
      valid: true,
      isSet: upstreamSet,
    }),
    item({
      key: "NMZP_AUDIT_MAX_RECORDS",
      value: auditRecords.display,
      source: sourceOf(env, "NMZP_AUDIT_MAX_RECORDS"),
      secret: false,
      securityRelevant: false,
      valid: auditRecords.valid,
      isSet: envSet(env, "NMZP_AUDIT_MAX_RECORDS"),
      problem: auditRecords.problem,
    }),
    item({
      key: "NMZP_AUDIT_MAX_DAYS",
      value: auditDays.display,
      source: sourceOf(env, "NMZP_AUDIT_MAX_DAYS"),
      secret: false,
      securityRelevant: false,
      valid: auditDays.valid,
      isSet: envSet(env, "NMZP_AUDIT_MAX_DAYS"),
      problem: auditDays.problem,
    }),
    item({
      key: "NMZP_AUDIT_MAX_MB",
      value: auditMb.display,
      source: sourceOf(env, "NMZP_AUDIT_MAX_MB"),
      secret: false,
      securityRelevant: false,
      valid: auditMb.valid,
      isSet: envSet(env, "NMZP_AUDIT_MAX_MB"),
      problem: auditMb.problem,
    }),
    item({
      key: "NMZP_AUDIT_MIN_FREE_MB",
      value: auditMinFree.display,
      source: sourceOf(env, "NMZP_AUDIT_MIN_FREE_MB"),
      secret: false,
      securityRelevant: false,
      valid: auditMinFree.valid,
      isSet: envSet(env, "NMZP_AUDIT_MIN_FREE_MB"),
      problem: auditMinFree.problem,
    }),
    item({
      key: "NMZP_AUDIT_TOMBSTONE_DAYS",
      value: auditTomb.display,
      source: sourceOf(env, "NMZP_AUDIT_TOMBSTONE_DAYS"),
      secret: false,
      securityRelevant: false,
      valid: auditTomb.valid,
      isSet: envSet(env, "NMZP_AUDIT_TOMBSTONE_DAYS"),
      problem: auditTomb.problem,
    }),
  ];

  return { schemaVersion: CONFIG_SHOW_SCHEMA_VERSION, items };
}

export function formatConfigShow(report: ConfigShowReport): string {
  return `${report.items
    .map((row) => {
      const value = row.secret ? String(row.isSet) : row.value === null ? "null" : String(row.value);
      const problem = row.problem ? `  problem=${row.problem}` : "";
      return `${row.key}  ${value}  ${row.source}${problem}`;
    })
    .join("\n")}\n`;
}

export function itemByKey(report: ConfigShowReport, key: string): ConfigItem {
  const found = report.items.find((row) => row.key === key);
  if (!found) throw new Error(`missing config item ${key}`);
  return found;
}

export function serveAuditRetention(report: ConfigShowReport): AuditRetention {
  return {
    maxRecords: Number(itemByKey(report, "NMZP_AUDIT_MAX_RECORDS").value),
    maxAgeMs: Number(itemByKey(report, "NMZP_AUDIT_MAX_DAYS").value) * AUDIT_DAY_MS,
    maxDbBytes: Number(itemByKey(report, "NMZP_AUDIT_MAX_MB").value) * AUDIT_MB,
    minFreeBytes: Number(itemByKey(report, "NMZP_AUDIT_MIN_FREE_MB").value) * AUDIT_MB,
    tombstoneMs: Number(itemByKey(report, "NMZP_AUDIT_TOMBSTONE_DAYS").value) * AUDIT_DAY_MS,
  };
}

export function configShowSchemaPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract", "config-show.schema.json");
}

export function loadConfigShowSchema(): Record<string, unknown> {
  return JSON.parse(readFileSync(configShowSchemaPath(), "utf8")) as Record<string, unknown>;
}

export function validateConfigShow(data: unknown): { ok: true } | { ok: false; errors: string[] } {
  return validateJsonSchema(data, loadConfigShowSchema());
}
