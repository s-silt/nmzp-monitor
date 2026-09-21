import { adapterById } from "./agent-catalog.ts";
export const DISCOVERY_TTL_MS = 180_000;
export const DISCOVERY_INTERVAL_MS = 60_000;
export const DISCOVERY_SOURCES = [
  "registry",
  "appx",
  "path",
  "packages",
  "extensions",
  "processes",
  "manual",
] as const;
export type DiscoverySource = (typeof DISCOVERY_SOURCES)[number];
export type ScanStatus = "ok" | "partial" | "timeout" | "permission" | "error" | "unsupported";
export interface DiscoveryProtection {
  id: "tool_pre" | "network" | "clipboard" | "screen" | "privacy" | "response";
  implementation: "adapter_available" | "experimental" | "unavailable";
  status: "not_verified";
  lastVerified: null;
}
export function discoveryProtections(adapterId: string): DiscoveryProtection[] {
  const a = adapterById(adapterId);
  return (["tool_pre", "network", "clipboard", "screen", "privacy", "response"] as const).map(
    (id) => ({
      id,
      implementation:
        id === "tool_pre" || id === "privacy"
          ? a?.hook
            ? "adapter_available"
            : "unavailable"
          : a?.hook === "grok"
            ? "experimental"
            : "unavailable",
      status: "not_verified",
      lastVerified: null,
    }),
  );
}
export const EVIDENCE = [
  "uninstall_record",
  "appx_record",
  "file_metadata",
  "signature_valid",
  "signature_unverified",
  "npm_manifest",
  "python_metadata",
  "extension_index",
  "extension_manifest",
  "path_entry",
  "manual_path",
  "process_identity",
] as const;
export const REASONS = [
  "name_only",
  "publisher_not_pinned",
  "unsigned_metadata",
  "shared_host",
  "runtime_unattributed",
  "scan_incomplete",
  "not_seen",
  "unsupported_form",
  "instance_not_bound",
  "metadata_conflict",
  "entry_unresolved",
] as const;
export interface DiscoveredAgent {
  instanceId: string;
  adapterId: string;
  version?: string;
  installation: "present" | "candidate" | "not_found" | "unknown";
  running: "observed" | "not_observed" | "unknown";
  identity: "corroborated" | "candidate";
  scopeEligible: false;
  evidence: Array<(typeof EVIDENCE)[number]>;
  reasons: Array<(typeof REASONS)[number]>;
  sources: DiscoverySource[];
  processes: Array<{ pid: number; startedAt: number }>;
  firstSeen: number;
  lastSeen: number;
  lastChecked: number;
  integration: "not_bound";
  protection: "not_verified";
  protections: DiscoveryProtection[];
}
export interface DiscoverySnapshot {
  schemaVersion: 1;
  platform: "win32" | "unsupported";
  checkedAt: number;
  completedAt: number;
  status: ScanStatus;
  sources: Array<{ id: DiscoverySource; status: ScanStatus }>;
  items: DiscoveredAgent[];
  receivedAt?: number;
}
const obj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const time = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const statuses = ["ok", "partial", "timeout", "permission", "error", "unsupported"];
export function safeVersion(v: unknown): string | undefined {
  return typeof v === "string" && /^[0-9][0-9A-Za-z.+_-]{0,63}$/.test(v) ? v : undefined;
}
/** Allowlist on every boundary, including restore and LAN. No free-form evidence/path/command fields. */
export function parseDiscovery(raw: unknown, now = Date.now()): DiscoverySnapshot | undefined {
  if (
    !obj(raw) ||
    raw.schemaVersion !== 1 ||
    !["win32", "unsupported"].includes(String(raw.platform)) ||
    !statuses.includes(String(raw.status)) ||
    !time(raw.checkedAt) ||
    !time(raw.completedAt) ||
    raw.completedAt < raw.checkedAt ||
    raw.completedAt > now + 60_000 ||
    !Array.isArray(raw.items) ||
    raw.items.length > 128 ||
    !Array.isArray(raw.sources) ||
    raw.sources.length > 7
  )
    return;
  const sources: DiscoverySnapshot["sources"] = [];
  for (const s of raw.sources) {
    if (
      !obj(s) ||
      !DISCOVERY_SOURCES.includes(s.id as DiscoverySource) ||
      !statuses.includes(String(s.status)) ||
      sources.some((x) => x.id === s.id)
    )
      return;
    sources.push({ id: s.id as DiscoverySource, status: s.status as ScanStatus });
  }
  const items: DiscoveredAgent[] = [];
  for (const r of raw.items) {
    if (
      !obj(r) ||
      typeof r.instanceId !== "string" ||
      !/^di_[a-f0-9]{32}$/.test(r.instanceId) ||
      items.some((i) => i.instanceId === r.instanceId) ||
      typeof r.adapterId !== "string" ||
      !adapterById(r.adapterId) ||
      !["present", "candidate", "not_found", "unknown"].includes(String(r.installation)) ||
      !["observed", "not_observed", "unknown"].includes(String(r.running)) ||
      !["corroborated", "candidate"].includes(String(r.identity)) ||
      !time(r.firstSeen) ||
      !time(r.lastSeen) ||
      !time(r.lastChecked) ||
      r.lastChecked > raw.completedAt ||
      r.lastSeen > r.lastChecked ||
      r.firstSeen > r.lastSeen ||
      !Array.isArray(r.evidence) ||
      !Array.isArray(r.reasons) ||
      !Array.isArray(r.sources) ||
      !Array.isArray(r.processes) ||
      r.processes.length > 32
    )
      return;
    if (
      r.evidence.some((e) => !EVIDENCE.includes(e)) ||
      r.reasons.some((e) => !REASONS.includes(e)) ||
      r.sources.some((s) => !DISCOVERY_SOURCES.includes(s))
    )
      return;
    const processes: DiscoveredAgent["processes"] = [];
    for (const p of r.processes) {
      if (
        !obj(p) ||
        !time(p.pid) ||
        p.pid <= 0 ||
        p.pid > 4_000_000_000 ||
        !time(p.startedAt) ||
        !p.startedAt ||
        p.startedAt > raw.completedAt
      )
        return;
      processes.push({ pid: p.pid, startedAt: p.startedAt });
    }
    const a = adapterById(r.adapterId)!;
    // Neither device uploads nor cached metadata may self-attest protection/trusted scope.
    items.push({
      instanceId: r.instanceId,
      adapterId: r.adapterId,
      version: safeVersion(r.version),
      installation: r.installation as DiscoveredAgent["installation"],
      running:
        a.form === "extension" || (r.running === "observed" && !processes.length)
          ? "unknown"
          : (r.running as DiscoveredAgent["running"]),
      identity: r.identity as DiscoveredAgent["identity"],
      scopeEligible: false,
      evidence: [...new Set(r.evidence)] as DiscoveredAgent["evidence"],
      reasons: [...new Set(r.reasons)] as DiscoveredAgent["reasons"],
      sources: [...new Set(r.sources)] as DiscoverySource[],
      processes: a.form === "extension" ? [] : processes,
      firstSeen: r.firstSeen,
      lastSeen: r.lastSeen,
      lastChecked: r.lastChecked,
      integration: "not_bound",
      protection: "not_verified",
      protections: discoveryProtections(r.adapterId),
    });
  }
  return {
    schemaVersion: 1,
    platform: raw.platform as DiscoverySnapshot["platform"],
    checkedAt: raw.checkedAt,
    completedAt: raw.completedAt,
    status:
      raw.status === "ok" &&
      (sources.length !== DISCOVERY_SOURCES.length || sources.some((s) => s.status !== "ok"))
        ? "partial"
        : (raw.status as ScanStatus),
    sources,
    items,
    ...(time(raw.receivedAt) ? { receivedAt: raw.receivedAt } : {}),
  };
}
export function discoveryStale(s: DiscoverySnapshot, now = Date.now()): boolean {
  return now - s.completedAt > DISCOVERY_TTL_MS || now < s.checkedAt;
}
export function mergeDiscovery(
  previous: DiscoverySnapshot | undefined,
  incoming: DiscoverySnapshot,
): DiscoverySnapshot {
  const items = [...incoming.items];
  for (const old of previous?.items ?? []) {
    const found = items.find((x) => x.instanceId === old.instanceId);
    if (found) {
      found.firstSeen = old.firstSeen;
      continue;
    }
    if (items.length >= 128) break;
    const complete =
      incoming.status === "ok" &&
      old.sources.every((id) => incoming.sources.some((s) => s.id === id && s.status === "ok"));
    items.push({
      ...old,
      installation: complete ? "not_found" : "unknown",
      running: complete ? "not_observed" : "unknown",
      processes: [],
      lastChecked: incoming.completedAt,
      reasons: [complete ? "not_seen" : "scan_incomplete"],
    });
  }
  return { ...incoming, items };
}
