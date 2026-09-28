/**
 * DoctorReport DTO shared with a future Admin API.
 * `/api/v2/doctor` is not mounted in this package.
 *
 * overall rank: ERROR > WARN > UNKNOWN > OK.
 */

export const DOCTOR_SCHEMA_VERSION = 1 as const;

/** Free space strictly below this is disk ERROR. */
export const DISK_MIN_FREE_BYTES = 200 * 1024 * 1024;

/** BLOCK+ASK count for one rule inside 24h. At or above this, friction is WARN. */
export const FRICTION_HIGH_COUNT = 50;

export const FRICTION_WINDOW_MS = 24 * 60 * 60 * 1000;
export const HOOK_OBSERVED_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Matches audit/outbox.ts MAX_ITEMS. A full outbox is queues ERROR. */
export const OUTBOX_FULL_ITEMS = 256;

/** Parallel checks. Wall time is the slowest check, not the sum. */
export const CHECK_TIMEOUT_MS = 2_500;

export const NOT_AVAILABLE_SUMMARY = "0.x 尚无此数据源";

export const CHECK_IDS = [
  "binary",
  "version",
  "service",
  "storage",
  "disk",
  "tls",
  "identity",
  "ct_reachability",
  "policy",
  "protected_rules",
  "audit",
  "backup",
  "config",
  "friction",
  "queues",
  "adapters",
  "hook_config",
  "hook_observed",
  "host_trust",
  "evidence_freshness",
  "update_status",
] as const;

export type CheckId = (typeof CHECK_IDS)[number];
export type DoctorRole = "server" | "device" | "unknown";
export type CheckStatus = "OK" | "WARN" | "ERROR" | "UNKNOWN";

export interface DoctorCheck {
  id: CheckId;
  status: CheckStatus;
  summary: string;
  remediation: string | null;
  details: Record<string, unknown>;
}

export interface DoctorReport {
  schemaVersion: typeof DOCTOR_SCHEMA_VERSION;
  role: DoctorRole;
  nmzpVersion: string;
  generatedAt: string;
  overall: CheckStatus;
  checks: DoctorCheck[];
}

const SERVER_ONLY = new Set<CheckId>(["storage", "audit", "backup", "friction"]);
const DEVICE_ONLY = new Set<CheckId>(["ct_reachability", "adapters", "hook_config", "host_trust"]);

const RANK: Record<CheckStatus, number> = { OK: 0, UNKNOWN: 1, WARN: 2, ERROR: 3 };

export function checksForRole(role: DoctorRole): CheckId[] {
  return CHECK_IDS.filter((id) => {
    if (role === "server") return !DEVICE_ONLY.has(id);
    if (role === "device") return !SERVER_ONLY.has(id);
    return !SERVER_ONLY.has(id) && !DEVICE_ONLY.has(id);
  });
}

export function aggregateOverall(statuses: readonly CheckStatus[]): CheckStatus {
  let best: CheckStatus = "OK";
  for (const status of statuses) {
    if (RANK[status] > RANK[best]) best = status;
  }
  return best;
}

export function doctorExitCode(report: Pick<DoctorReport, "overall">): 0 | 1 {
  return report.overall === "ERROR" ? 1 : 0;
}

export function checkResult(
  id: CheckId,
  status: CheckStatus,
  summary: string,
  remediation: string | null,
  details: Record<string, unknown> = {},
): DoctorCheck {
  return {
    id,
    status,
    summary: oneLine(summary),
    remediation: remediation === null ? null : oneLine(remediation),
    details,
  };
}

export function notAvailable(id: CheckId, extra: Record<string, unknown> = {}): DoctorCheck {
  return checkResult(id, "UNKNOWN", NOT_AVAILABLE_SUMMARY, null, { reason: "not_available", ...extra });
}

export function safeErrorCode(error: unknown): string {
  const code =
    error && typeof error === "object" && "code" in error ? (error as { code?: unknown }).code : undefined;
  if (typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code)) return code;
  if (typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)) return code.toLowerCase();
  const message = error instanceof Error ? error.message : "";
  if (/^[a-z][a-z0-9_]{0,63}$/.test(message)) return message;
  if (message.startsWith("corrupt_json")) return "corrupt_json";
  if (message.startsWith("policy_")) return message.split(":")[0]?.slice(0, 64) || "check_failed";
  return "check_failed";
}

export function displayPath(path: string, homes: readonly string[]): string {
  const norm = (value: string) => value.replace(/\\/g, "/").replace(/\/+$/, "");
  const needle = norm(path);
  const lower = needle.toLowerCase();
  for (const home of homes) {
    if (!home) continue;
    const prefix = norm(home);
    const prefixLower = prefix.toLowerCase();
    if (lower === prefixLower) return "~";
    if (lower.startsWith(`${prefixLower}/`)) return `~${needle.slice(prefix.length)}`;
  }
  return path;
}

export function formatDoctorText(report: DoctorReport): string {
  const lines: string[] = [];
  for (const item of report.checks) {
    lines.push(`${item.status}  ${item.id}  ${item.summary}`);
    if (item.remediation) lines.push(`  ${item.remediation}`);
  }
  return `${lines.join("\n")}\n`;
}

function oneLine(value: string): string {
  return value.replace(/[\r\n]+/g, " ").split("\0").join("").trim();
}

function scrubString(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, "[redacted]")
    .replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
}

export function scrubReport(report: DoctorReport): DoctorReport {
  return {
    schemaVersion: report.schemaVersion,
    role: report.role,
    nmzpVersion: report.nmzpVersion,
    generatedAt: report.generatedAt,
    overall: report.overall,
    checks: report.checks.map((item) => ({
      id: item.id,
      status: item.status,
      summary: scrubString(item.summary),
      remediation: item.remediation === null ? null : scrubString(item.remediation),
      details: scrubValue(item.details) as Record<string, unknown>,
    })),
  };
}

function scrubValue(value: unknown): unknown {
  if (typeof value === "string") return scrubString(value);
  if (Array.isArray(value)) return value.map((item) => scrubValue(item));
  if (!value || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) out[key] = scrubValue(item);
  return out;
}
