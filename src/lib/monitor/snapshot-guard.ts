import type { ArchiveCoverage, MachineStatus, SnapshotGuard, SnapshotGuardState } from "./types.ts";
import type { Msg } from "./i18n.ts";

export const SNAPSHOT_STALE_MS = 15 * 60 * 1000;
/** Allow a small clock skew; significant future lastVerified is not fresh. */
export const SNAPSHOT_CLOCK_SKEW_MS = 2 * 60 * 1000;

const COVERAGE = new Set<ArchiveCoverage>(["none", "protected", "partial", "unknown"]);
const ERROR_CODE = /^[a-z][a-z0-9_]{0,47}$/;
const UNSUPPORTED_ERR = new Set(["unsupported", "unsupported_platform"]);
const FAIL_ERR = new Set(["failed", "status_failed", "timeout", "access_denied", "reparse_rejected"]);

export function parseSnapshotGuard(raw: unknown): SnapshotGuardState {
  if (raw === undefined || raw === null) return { status: "missing" };
  if (typeof raw !== "object" || Array.isArray(raw)) return { status: "invalid" };
  const o = raw as Record<string, unknown>;
  if (typeof o.supported !== "boolean") return { status: "invalid" };
  if (typeof o.active !== "boolean") return { status: "invalid" };
  if (typeof o.managed !== "boolean") return { status: "invalid" };
  if (typeof o.targetPresent !== "boolean") return { status: "invalid" };
  if (typeof o.writeBlocked !== "boolean") return { status: "invalid" };
  if (typeof o.existingArchiveCoverage !== "string" || !COVERAGE.has(o.existingArchiveCoverage as ArchiveCoverage)) {
    return { status: "invalid" };
  }
  let lastVerified = 0;
  if (o.lastVerified !== undefined) {
    if (typeof o.lastVerified !== "number" || !Number.isFinite(o.lastVerified) || o.lastVerified < 0) {
      return { status: "invalid" };
    }
    lastVerified = o.lastVerified;
  }
  const error = parseErrorField(o);
  if (error === "bad") return { status: "invalid" };

  if (o.active === true) {
    if (!o.supported || !o.managed || !o.targetPresent || !o.writeBlocked) return { status: "invalid" };
    if (o.existingArchiveCoverage !== "none" && o.existingArchiveCoverage !== "protected") return { status: "invalid" };
    if (lastVerified <= 0) return { status: "invalid" };
    if (error) return { status: "invalid" };
  }

  return {
    status: "ok",
    guard: {
      supported: o.supported,
      active: o.active,
      managed: o.managed,
      targetPresent: o.targetPresent,
      writeBlocked: o.writeBlocked,
      existingArchiveCoverage: o.existingArchiveCoverage as ArchiveCoverage,
      lastVerified,
      ...(error ? { error } : {}),
    },
  };
}

function parseErrorField(o: Record<string, unknown>): string | undefined | "bad" {
  if (!Object.prototype.hasOwnProperty.call(o, "error") || o.error === undefined || o.error === null) {
    return undefined;
  }
  if (typeof o.error !== "string") return "bad";
  const error = o.error.trim();
  if (!error) return undefined;
  if (!ERROR_CODE.test(error) || looksSensitiveError(error)) return "bad";
  return error;
}

function looksSensitiveError(error: string): boolean {
  if (error.includes("\\") || error.includes("/") || error.includes(":\\")) return true;
  if (/\b(D:|O:|S:|P:)/.test(error)) return true;
  return false;
}

export type SnapshotTone = "ok" | "warn" | "muted" | "stale";

export interface SnapshotFact {
  key: Msg;
  tone: SnapshotTone;
}

export interface SnapshotGuardView {
  status: SnapshotGuardState["status"];
  stale: boolean;
  write: SnapshotFact;
  coverage: SnapshotFact;
  provenance: SnapshotFact;
  lastVerified: number;
  errorKey?: Msg;
  activeKnownDirOnly: boolean;
}

export function snapshotGuardStale(
  guard: SnapshotGuard | undefined,
  hostStatus: MachineStatus,
  now: number,
): boolean {
  if (hostStatus === "dark" || hostStatus === "archived") return true;
  if (!guard || guard.lastVerified <= 0) return true;
  if (guard.lastVerified > now + SNAPSHOT_CLOCK_SKEW_MS) return true;
  if (now - guard.lastVerified > SNAPSHOT_STALE_MS) return true;
  return false;
}

function writeBlockedFact(g: SnapshotGuard): boolean {
  if (!g.writeBlocked) return false;
  if (!g.supported || !g.targetPresent || g.lastVerified <= 0) return false;
  if (g.error === "external_restriction" || g.error === "coverage_unknown") return true;
  if (g.error && UNSUPPORTED_ERR.has(g.error)) return false;
  if (g.error && FAIL_ERR.has(g.error)) return false;
  if (g.error === "target_missing" || g.error === "not_verified") return false;
  if (g.error) return false;
  return true;
}

function coverageProtectedGreen(g: SnapshotGuard, stale: boolean): boolean {
  if (stale) return false;
  if (g.existingArchiveCoverage !== "protected") return false;
  if (!g.supported || !g.targetPresent) return false;
  if (g.lastVerified <= 0) return false;
  if (g.error) return false;
  return true;
}

export function buildSnapshotView(
  state: SnapshotGuardState | undefined,
  hostStatus: MachineStatus,
  now: number,
): SnapshotGuardView {
  if (!state || state.status === "missing") {
    return {
      status: "missing",
      stale: false,
      write: { key: "notCollected", tone: "muted" },
      coverage: { key: "notCollected", tone: "muted" },
      provenance: { key: "notCollected", tone: "muted" },
      lastVerified: 0,
      activeKnownDirOnly: false,
    };
  }
  if (state.status === "invalid") {
    return {
      status: "invalid",
      stale: false,
      write: { key: "sgInvalid", tone: "muted" },
      coverage: { key: "sgInvalid", tone: "muted" },
      provenance: { key: "sgInvalid", tone: "muted" },
      lastVerified: 0,
      errorKey: "sgInvalid",
      activeKnownDirOnly: false,
    };
  }
  const g = state.guard;
  const stale = snapshotGuardStale(g, hostStatus, now);
  const err = g.error;

  // Failed/unverified checks are not evidence the target is absent.
  let write: SnapshotFact;
  if (UNSUPPORTED_ERR.has(err ?? "") || !g.supported) write = { key: "sgUnsupported", tone: "muted" };
  else if (err === "target_missing") write = { key: "sgTargetMissing", tone: "warn" };
  else if (FAIL_ERR.has(err ?? "")) write = { key: "sgErrorGeneric", tone: "warn" };
  else if (g.lastVerified <= 0 || err === "not_verified") write = { key: "sgNotVerified", tone: "muted" };
  else if (!g.targetPresent) write = { key: "sgTargetMissing", tone: "warn" };
  else if (writeBlockedFact(g)) write = { key: "sgWriteLimited", tone: stale ? "stale" : "ok" };
  else write = { key: "sgWriteNotLimited", tone: "muted" };

  let coverage: SnapshotFact;
  if (coverageProtectedGreen(g, stale)) {
    coverage = { key: "sgCoverageProtected", tone: "ok" };
  } else if (g.existingArchiveCoverage === "none" && !err && g.supported && g.targetPresent && g.lastVerified > 0 && !stale) {
    coverage = { key: "sgCoverageNone", tone: "muted" };
  } else if (g.existingArchiveCoverage === "none") {
    coverage = { key: "sgCoverageNone", tone: "muted" };
  } else if (g.existingArchiveCoverage === "partial") {
    coverage = { key: "sgCoveragePartial", tone: "warn" };
  } else {
    coverage = { key: "sgCoverageUnknown", tone: "warn" };
  }

  let provenance: SnapshotFact;
  if (!g.managed && err === "external_restriction") {
    provenance = { key: "sgProvenanceExternal", tone: "warn" };
  } else if (g.managed) {
    provenance = { key: "sgProvenanceNmzp", tone: "muted" };
  } else {
    provenance = { key: "sgProvenanceUnknown", tone: "muted" };
  }

  return {
    status: "ok",
    stale,
    write,
    coverage,
    provenance,
    lastVerified: g.lastVerified,
    errorKey: err && err !== "external_restriction" ? "sgErrorGeneric" : undefined,
    activeKnownDirOnly: g.active === true,
  };
}

export function snapshotHosts<T extends { id: string }>(machines: T[], host: string): T[] {
  if (host === "all") return machines;
  return machines.filter((m) => m.id === host);
}
