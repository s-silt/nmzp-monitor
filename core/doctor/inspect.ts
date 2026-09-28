import { X509Certificate } from "node:crypto";
import { existsSync, lstatSync, statfsSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { readProbeLock } from "../install-autostart.ts";
import { sha256Text } from "../install-fs.ts";
import { ENGINE_REVISION } from "../policy/engine-revision.ts";
import { certificateCovers, fingerprintSha256Pem } from "../tls.ts";
import type { AuditInput, ConfigInput, IdentityInput, PolicyInput, SignatureState, StorageInput, TlsInput } from "./classify.ts";
import { FRICTION_WINDOW_MS, HOOK_OBSERVED_WINDOW_MS, OUTBOX_FULL_ITEMS, displayPath, type DoctorRole } from "./report.ts";

const MAX_TEXT = 16 * 1024 * 1024;
const SAFE_HOST = /^[a-z][a-z0-9_-]{0,32}$/;
const SAFE_RULE = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_EVENT = /^[A-Za-z0-9_.:-]{1,128}$/;

export interface StatfsLike {
  bavail: bigint | number;
  bsize: bigint | number;
}

export interface InspectContext {
  home: string;
  dataDir: string;
  env: NodeJS.ProcessEnv;
  nowMs: number;
  role: DoctorRole;
  statfs?: (path: string) => StatfsLike;
  serverMinEngineRevision?: number | null;
  binarySignature?: SignatureState;
  adapterMismatches?: readonly string[];
  extraEvents?: unknown;
}

export function resolveHome(env: NodeJS.ProcessEnv, override?: string): string {
  if (override) return override;
  return env.NMZP_HOME || homedir();
}

export function resolveDataDir(env: NodeJS.ProcessEnv, override?: string): string {
  if (override) return override;
  return env.NMZP_DATA || join(homedir(), ".nmzp", "ct-data");
}

type Kind = "missing" | "file" | "dir" | "symlink" | "other" | "unreadable";

async function fileKind(path: string): Promise<Kind> {
  try {
    const st = await lstat(path);
    if (st.isSymbolicLink()) return "symlink";
    if (st.isFile()) return "file";
    if (st.isDirectory()) return "dir";
    return "other";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "unreadable";
  }
}

async function readText(path: string): Promise<{ ok: true; text: string } | { ok: false; code: string }> {
  const kind = await fileKind(path);
  if (kind === "missing") return { ok: false, code: "enoent" };
  if (kind !== "file") return { ok: false, code: "not_a_file" };
  try {
    const st = await lstat(path);
    if (st.size > MAX_TEXT) return { ok: false, code: "too_large" };
    return { ok: true, text: await readFile(path, "utf8") };
  } catch {
    return { ok: false, code: "unreadable" };
  }
}

async function readJson(path: string): Promise<{ ok: true; value: unknown } | { ok: false; code: string }> {
  const text = await readText(path);
  if (!text.ok) return text;
  try {
    return { ok: true, value: JSON.parse(text.text) as unknown };
  } catch {
    return { ok: false, code: "invalid_json" };
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function storageModeOf(env: NodeJS.ProcessEnv): "window" | "sqlite" | "invalid" {
  const value = env.NMZP_STORAGE_MODE ?? "window";
  return value === "window" || value === "sqlite" ? value : "invalid";
}

export async function readRole(home: string, dataDir: string): Promise<DoctorRole> {
  const device = await looksLikeDevice(home);
  const server =
    (await fileKind(join(dataDir, "policy.json"))) === "file" || (await fileKind(join(dataDir, "serve.json"))) === "file";
  if (device && server) return "unknown";
  if (device) return "device";
  if (server) return "server";
  return "unknown";
}

async function looksLikeDevice(home: string): Promise<boolean> {
  const read = await readJson(join(home, ".nmzp", "credentials.json"));
  if (!read.ok || !object(read.value)) return false;
  const row = read.value;
  return ["deviceId", "token", "url", "caPem", "fingerprintSha256"].every((key) => {
    const value = row[key];
    return typeof value === "string" && value.length > 0;
  });
}

function pidState(pid: unknown): "running" | "stopped" | "unknown" {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return "unknown";
  try {
    process.kill(pid, 0);
    return "running";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM" ? "unknown" : "stopped";
  }
}

async function readPointer(
  dataDir: string,
): Promise<{ pid: number; host: string; port: number } | null | "unreadable"> {
  const kind = await fileKind(join(dataDir, "serve.json"));
  if (kind === "missing") return null;
  if (kind !== "file") return "unreadable";
  try {
    const { readServePointer } = await import("../persist.ts");
    const pointer = await readServePointer(dataDir);
    if (!pointer || typeof pointer.host !== "string") return "unreadable";
    return { pid: pointer.pid, host: pointer.host, port: pointer.port };
  } catch {
    return "unreadable";
  }
}

export async function readServiceState(home: string, dataDir: string): Promise<"running" | "stopped" | null> {
  const signals: Array<"running" | "stopped" | "unknown"> = [];
  const pointer = await readPointer(dataDir);
  if (pointer === "unreadable") signals.push("unknown");
  else if (pointer) signals.push(pidState(pointer.pid));
  const probe = readProbeLock(home);
  if (probe) signals.push(pidState(probe.pid));
  if (signals.includes("running")) return "running";
  if (signals.includes("unknown")) return null;
  if (signals.includes("stopped")) return "stopped";
  return null;
}

export async function readListeners(dataDir: string): Promise<Array<{ name: "ct"; host: string; port: number }>> {
  const pointer = await readPointer(dataDir);
  if (!pointer || pointer === "unreadable") return [];
  if (!pointer.host || pointer.host.length > 255 || /[\s@]/.test(pointer.host)) return [];
  if (!Number.isInteger(pointer.port) || pointer.port < 0 || pointer.port > 65535) return [];
  return [{ name: "ct", host: pointer.host, port: pointer.port }];
}

export async function readBinary(ctx: InspectContext): Promise<{ exists: boolean; signature: SignatureState; path: string }> {
  const manifest = await readManifest(ctx.home);
  let expected = process.argv[1] ? resolve(process.argv[1]) : "";
  if (manifest && manifest !== "unreadable" && typeof manifest.runtimeDir === "string" && manifest.runtimeDir.length > 0) {
    expected = join(manifest.runtimeDir, "nmzp.mjs");
  }
  return {
    exists: (await fileKind(expected)) === "file",
    signature: ctx.binarySignature ?? "not_available",
    path: displayPath(expected, [ctx.home, homedir()]),
  };
}

export function readVersion(ctx: InspectContext): { local: number; required: number | null } {
  const required = ctx.serverMinEngineRevision === undefined ? null : ctx.serverMinEngineRevision;
  return { local: ENGINE_REVISION, required };
}

export function readDisk(ctx: InspectContext): { freeBytes: number | null; code?: string } {
  const path = existsSync(ctx.dataDir) ? ctx.dataDir : ctx.home;
  try {
    const stat = ctx.statfs ? ctx.statfs(path) : statfsSync(path);
    const free = Number(stat.bavail) * Number(stat.bsize);
    if (!Number.isFinite(free) || free < 0) return { freeBytes: null, code: "statfs_failed" };
    return { freeBytes: free };
  } catch {
    return { freeBytes: null, code: "statfs_failed" };
  }
}

function httpsHost(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" ? url.hostname : null;
  } catch {
    return null;
  }
}

export async function readTls(ctx: InspectContext): Promise<TlsInput> {
  if (ctx.role === "device") return tlsFromCredentials(ctx);
  const certPath = join(ctx.dataDir, "tls", "server.crt");
  const cert = await readText(certPath);
  if (!cert.ok) {
    if (ctx.role === "unknown") {
      const device = await tlsFromCredentials(ctx);
      if (device.material !== "absent") return device;
    }
    return { material: "absent", expired: false, san: "unchecked", fingerprint: "unchecked" };
  }
  const pin = await readJson(join(ctx.dataDir, "tls", "pin.json"));
  const expected =
    pin.ok && object(pin.value) && typeof pin.value.fingerprintSha256 === "string" ? pin.value.fingerprintSha256 : null;
  let pointerFingerprint: string | null = null;
  const pointerKind = await fileKind(join(ctx.dataDir, "serve.json"));
  if (pointerKind === "file") {
    const raw = await readJson(join(ctx.dataDir, "serve.json"));
    if (raw.ok && object(raw.value) && typeof raw.value.fingerprintSha256 === "string") {
      pointerFingerprint = raw.value.fingerprintSha256;
    }
  }
  const expectedFp = expected ?? pointerFingerprint;
  return describeCert(cert.text, expectedFp, httpsHost(ctx.env.NMZP_PUBLIC_URL), ctx.nowMs, pointerFingerprint, expected);
}

async function tlsFromCredentials(ctx: InspectContext): Promise<TlsInput> {
  const read = await readJson(join(ctx.home, ".nmzp", "credentials.json"));
  if (!read.ok || !object(read.value)) return { material: "absent", expired: false, san: "unchecked", fingerprint: "unchecked" };
  const pem = read.value.caPem;
  const fingerprint = read.value.fingerprintSha256;
  const url = read.value.url;
  if (typeof pem !== "string" || typeof fingerprint !== "string") {
    return { material: "invalid", expired: false, san: "unchecked", fingerprint: "unchecked" };
  }
  const host = typeof url === "string" ? httpsHost(url) : null;
  return describeCert(pem, fingerprint, host, ctx.nowMs, null, fingerprint);
}

function describeCert(
  pem: string,
  expected: string | null,
  host: string | null,
  nowMs: number,
  pointerFingerprint: string | null,
  pinFingerprint: string | null,
): TlsInput {
  try {
    const cert = new X509Certificate(pem);
    const expired = Date.parse(cert.validTo) <= nowMs;
    const actual = fingerprintSha256Pem(pem).toLowerCase();
    let fingerprint: TlsInput["fingerprint"] = "unchecked";
    if (expected) fingerprint = actual === expected.toLowerCase() ? "ok" : "mismatch";
    if (pinFingerprint && pointerFingerprint && pinFingerprint.toLowerCase() !== pointerFingerprint.toLowerCase()) {
      fingerprint = "mismatch";
    }
    const san: TlsInput["san"] = host ? (certificateCovers(pem, host) ? "ok" : "mismatch") : "unchecked";
    return { material: "present", expired, san, fingerprint, publicHost: host };
  } catch {
    return { material: "invalid", expired: false, san: "unchecked", fingerprint: "unchecked" };
  }
}

export async function readIdentity(ctx: InspectContext): Promise<IdentityInput> {
  const candidates = [
    ctx.dataDir,
    join(ctx.dataDir, "policy.json"),
    join(ctx.dataDir, "admin.token"),
    join(ctx.dataDir, "meta.json"),
    join(ctx.dataDir, "tls", "server.key"),
    join(ctx.dataDir, "tls", "server.crt"),
    join(ctx.dataDir, "tls", "pin.json"),
    join(ctx.home, ".nmzp"),
    join(ctx.home, ".nmzp", "credentials.json"),
    join(ctx.home, ".nmzp", "policy-cache.json"),
    join(ctx.home, ".nmzp", "manifest.json"),
  ];
  let saw = false;
  let wide = false;
  let unknownPerm = false;
  for (const path of candidates) {
    const kind = await fileKind(path);
    if (kind === "missing") continue;
    saw = true;
    if (kind === "unreadable" || kind === "symlink" || kind === "other") {
      unknownPerm = true;
      continue;
    }
    if (process.platform === "win32") {
      unknownPerm = true;
      continue;
    }
    try {
      if ((lstatSync(path).mode & 0o077) !== 0) wide = true;
    } catch {
      unknownPerm = true;
    }
  }
  const perm = !saw ? "ok" : unknownPerm && !wide ? "unknown" : wide ? "wide" : unknownPerm ? "unknown" : "ok";
  return { perm: process.platform === "win32" && saw ? "unknown" : perm, revoked: await readRevoked(ctx.dataDir) };
}

async function readRevoked(dataDir: string): Promise<boolean | null> {
  const path = join(dataDir, "devices.json");
  const kind = await fileKind(path);
  if (kind === "missing") return false;
  if (kind !== "file") return null;
  const read = await readJson(path);
  if (!read.ok || !object(read.value) || !Array.isArray(read.value.devices)) return null;
  for (const device of read.value.devices) {
    if (!object(device)) continue;
    if (typeof device.revokedAt === "number" && device.revokedAt > 0) return true;
  }
  return false;
}

export async function readStorage(ctx: InspectContext): Promise<StorageInput> {
  const mode = storageModeOf(ctx.env);
  const policyPath = join(ctx.dataDir, "policy.json");
  const policyKind = await fileKind(policyPath);
  let policy: StorageInput["policy"] = "missing";
  let schemaVersion: number | null = null;
  if (policyKind === "unreadable") policy = "unreadable";
  else if (policyKind !== "missing" && policyKind !== "file") policy = "invalid";
  else if (policyKind === "file") {
    try {
      const { FilePolicyStore } = await import("../policy/file-store.ts");
      const opened = await FilePolicyStore.open<Record<string, unknown> & { version: number; updatedAt: number }>({
        path: policyPath,
        durability: "file",
      });
      const snap = await opened.read();
      policy = policyShape(snap.policy) ? "ok" : "invalid";
      const raw = snap.policy.schemaVersion;
      schemaVersion = typeof raw === "number" ? raw : raw === undefined ? null : Number.NaN;
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : "";
      policy = code === "policy_file_read_failed" ? "unreadable" : "invalid";
    }
  }
  const devices = await readDevicesState(join(ctx.dataDir, "devices.json"));
  const dbPath = join(ctx.dataDir, "nmzp.db");
  const dbKind = await fileKind(dbPath);
  const db = dbKind === "missing" ? "missing" : "present";
  let integrity: StorageInput["integrity"] = "skipped";
  let history: StorageInput["history"] = "skipped";
  let auditFormat: number | null = null;
  if (dbKind === "file") {
    const inspected = inspectDatabase(dbPath);
    integrity = inspected.integrity;
    history = inspected.history;
    auditFormat = inspected.auditFormat;
  } else if (dbKind !== "missing") {
    integrity = "unreadable";
  }
  return {
    mode,
    policy,
    schemaVersion,
    devices: devices.state,
    devicesSnapshot: devices.snapshot,
    db,
    integrity,
    history,
    auditFormat,
  };
}

function policyShape(policy: Record<string, unknown>): boolean {
  return (
    Number.isInteger(policy.version) &&
    (policy.version as number) >= 1 &&
    (policy.mode === "enforcing" || policy.mode === "permissive" || policy.mode === "off") &&
    typeof policy.stopped === "boolean" &&
    Array.isArray(policy.customRules) &&
    Number.isInteger(policy.updatedAt)
  );
}

async function readDevicesState(path: string): Promise<{ state: StorageInput["devices"]; snapshot: number | null }> {
  const kind = await fileKind(path);
  if (kind === "missing") return { state: "missing", snapshot: null };
  if (kind === "unreadable") return { state: "unreadable", snapshot: null };
  if (kind !== "file") return { state: "invalid", snapshot: null };
  const read = await readJson(path);
  if (!read.ok || !object(read.value) || !Array.isArray(read.value.devices)) return { state: "invalid", snapshot: null };
  const snapshot = read.value.snapshotVersion;
  if (snapshot === undefined) return { state: "ok", snapshot: null };
  return { state: "ok", snapshot: typeof snapshot === "number" ? snapshot : Number.NaN };
}

function inspectDatabase(path: string): {
  integrity: StorageInput["integrity"];
  history: StorageInput["history"];
  auditFormat: number | null;
} {
  try {
    const db = new DatabaseSync(path, { readOnly: true });
    try {
      db.exec("PRAGMA query_only=ON");
      const rows = db.prepare("PRAGMA integrity_check").all() as Array<{ integrity_check?: string }>;
      if (!(rows.length === 1 && rows[0]?.integrity_check === "ok")) {
        return { integrity: "bad", history: "bad", auditFormat: null };
      }
      const names = new Set(
        (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name?: string }>).map((row) =>
          String(row.name),
        ),
      );
      let auditFormat: number | null = null;
      if (names.has("audit_meta")) {
        const row = db.prepare("SELECT format_version AS v FROM audit_meta").get() as { v?: unknown } | undefined;
        auditFormat = typeof row?.v === "number" ? row.v : -1;
      }
      const history = names.has("policy_current") && names.has("policy_revisions") ? "ok" : "missing";
      return { integrity: "ok", history, auditFormat };
    } finally {
      db.close();
    }
  } catch {
    return { integrity: "bad", history: "bad", auditFormat: null };
  }
}

export async function readPolicy(ctx: InspectContext): Promise<PolicyInput> {
  const cache = await readCacheState(join(ctx.home, ".nmzp", "policy-cache.json"));
  if (storageModeOf(ctx.env) !== "sqlite" || (await fileKind(join(ctx.dataDir, "nmzp.db"))) !== "file") {
    return { cache, headRulesHash: null, engineRulesHash: null };
  }
  try {
    const head = readHeadRulesHash(join(ctx.dataDir, "nmzp.db"));
    const { policyRulesHash } = await import("../policy/nmzp-service.ts");
    const { RULES } = await import("../../src/lib/monitor/rules.ts");
    return { cache, headRulesHash: head, engineRulesHash: head === null ? null : policyRulesHash({ RULES }) };
  } catch {
    return { cache, headRulesHash: null, engineRulesHash: null };
  }
}

function readHeadRulesHash(path: string): string | null {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec("PRAGMA query_only=ON");
    const row = db
      .prepare(
        "SELECT r.rules_hash AS rulesHash FROM policy_current c JOIN policy_revisions r ON r.version=c.version WHERE c.singleton=1",
      )
      .get() as { rulesHash?: unknown } | undefined;
    return typeof row?.rulesHash === "string" ? row.rulesHash : null;
  } finally {
    db.close();
  }
}

async function readCacheState(path: string): Promise<PolicyInput["cache"]> {
  const kind = await fileKind(path);
  if (kind === "missing") return "missing";
  if (kind !== "file") return "invalid";
  const { readPolicyCache } = await import("../policy-cache.ts");
  return (await readPolicyCache(path)) ? "valid" : "invalid";
}

export async function readProtected(ctx: InspectContext): Promise<{ downgrades: string[] | null; code?: string }> {
  const read = await readJson(join(ctx.dataDir, "policy.json"));
  if (!read.ok || !object(read.value)) return { downgrades: null, code: read.ok ? "policy_unreadable" : read.code };
  const { parsePolicyOverrides } = await import("../policy-schema.ts");
  if (read.value.overrides !== undefined && !parsePolicyOverrides(read.value.overrides)) {
    return { downgrades: null, code: "policy_overrides_invalid" };
  }
  const overrides = parsePolicyOverrides(read.value.overrides) ?? { rules: {}, families: {} };
  const { RULES } = await import("../../src/lib/monitor/rules.ts");
  const { protectedDowngrades } = await import("../../src/lib/monitor/overrides.ts");
  return { downgrades: protectedDowngrades(overrides, [...RULES]) };
}

export async function readAudit(ctx: InspectContext): Promise<AuditInput> {
  const mode = storageModeOf(ctx.env);
  if (mode === "invalid") return { mode, corruptCount: null, worker: "unknown", code: "invalid_storage_mode" };
  if (mode === "sqlite") return { mode, corruptCount: null, worker: "unknown", code: "audit_worker_not_observable" };
  const loaded = await readEventFile(join(ctx.dataDir, "events.jsonl"));
  if (loaded === "unreadable") return { mode, corruptCount: null, worker: "unknown", code: "events_unreadable" };
  return { mode, corruptCount: loaded === "missing" ? 0 : loaded.corrupt, worker: "not_applicable" };
}

interface SlimEvent {
  ts: number;
  agent: string | null;
  source: string | null;
  decision: string | null;
  ruleId: string | null;
  id: string | null;
}

async function readEventFile(path: string): Promise<{ rows: SlimEvent[]; corrupt: number } | "missing" | "unreadable"> {
  const kind = await fileKind(path);
  if (kind === "missing") return "missing";
  if (kind !== "file") return "unreadable";
  const text = await readText(path);
  if (!text.ok) return text.code === "enoent" ? "missing" : "unreadable";
  const rows: SlimEvent[] = [];
  let corrupt = 0;
  for (const line of text.text.split(/\n/)) {
    if (!line.trim()) continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      corrupt += 1;
      continue;
    }
    if (!object(value) || typeof value.id !== "string" || typeof value.redacted !== "string") {
      corrupt += 1;
      continue;
    }
    rows.push({
      ts: typeof value.ts === "number" ? value.ts : Number.NaN,
      agent: typeof value.agent === "string" && SAFE_HOST.test(value.agent) ? value.agent : null,
      source: typeof value.source === "string" && SAFE_HOST.test(value.source) ? value.source : null,
      decision: typeof value.decision === "string" && SAFE_HOST.test(value.decision) ? value.decision : null,
      ruleId: typeof value.ruleId === "string" && SAFE_RULE.test(value.ruleId) ? value.ruleId : null,
      id: typeof value.id === "string" && SAFE_EVENT.test(value.id) ? value.id : null,
    });
  }
  return { rows, corrupt };
}

export async function readConfig(ctx: InspectContext): Promise<ConfigInput> {
  const cacheKind = await fileKind(join(ctx.home, ".nmzp", "policy-cache.json"));
  let cacheInvalid = false;
  if (cacheKind === "file") {
    const { readPolicyCache } = await import("../policy-cache.ts");
    cacheInvalid = (await readPolicyCache(join(ctx.home, ".nmzp", "policy-cache.json"))) === null;
  } else if (cacheKind !== "missing") cacheInvalid = true;
  return {
    role: ctx.role,
    storageModeInvalid: storageModeOf(ctx.env) === "invalid",
    portInvalid: portInvalid(ctx.env.NMZP_PORT),
    publicUrlInvalid: publicUrlInvalid(ctx.env.NMZP_PUBLIC_URL),
    bind: bindOf(ctx.env.NMZP_BIND),
    cacheInvalid,
  };
}

function portInvalid(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  if (!/^[0-9]+$/.test(raw)) return true;
  return Number(raw) > 65535;
}

function publicUrlInvalid(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  return httpsHost(raw) === null;
}

function bindOf(raw: string | undefined): ConfigInput["bind"] {
  if (raw === undefined || raw === "") return "unset";
  if (raw === "127.0.0.1" || raw === "localhost" || raw === "::1") return "loopback";
  return "open";
}

export async function readFriction(
  ctx: InspectContext,
): Promise<Array<{ ruleId: string; count: number; samples: string[] }> | null> {
  const loaded = await readEventFile(join(ctx.dataDir, "events.jsonl"));
  if (loaded === "unreadable") return null;
  if (loaded === "missing") return [];
  const counts = new Map<string, { count: number; samples: string[] }>();
  for (const row of loaded.rows) {
    if (!Number.isFinite(row.ts) || row.ts < ctx.nowMs - FRICTION_WINDOW_MS || row.ts > ctx.nowMs + 60_000) continue;
    if (row.decision !== "block" && row.decision !== "confirm") continue;
    const ruleId = row.ruleId ?? "(none)";
    const slot = counts.get(ruleId) ?? { count: 0, samples: [] };
    slot.count += 1;
    if (row.id && slot.samples.length < 3) slot.samples.push(row.id);
    counts.set(ruleId, slot);
  }
  return [...counts].map(([ruleId, slot]) => ({ ruleId, count: slot.count, samples: slot.samples }));
}

export async function readQueues(ctx: InspectContext): Promise<{ role: DoctorRole; outbox: "missing" | "ok" | "full" | "dropped" | "corrupt" }> {
  const path = join(ctx.home, ".nmzp", "audit-outbox.json");
  const kind = await fileKind(path);
  if (kind === "missing") return { role: ctx.role, outbox: "missing" };
  if (kind !== "file") return { role: ctx.role, outbox: "corrupt" };
  try {
    const { outboxStatus } = await import("../audit/outbox.ts");
    const status = await outboxStatus(ctx.home, { now: ctx.nowMs });
    if (status.dropped > 0) return { role: ctx.role, outbox: "dropped" };
    if (status.pending >= OUTBOX_FULL_ITEMS) return { role: ctx.role, outbox: "full" };
    return { role: ctx.role, outbox: "ok" };
  } catch {
    return { role: ctx.role, outbox: "corrupt" };
  }
}

export async function readAdapters(ctx: InspectContext): Promise<{
  hosts: number;
  unreadable: boolean;
  ranges: "unavailable" | "checked";
  mismatches: string[];
}> {
  const path = join(ctx.home, ".nmzp", "discovery.json");
  const kind = await fileKind(path);
  if (kind === "missing") return { hosts: 0, unreadable: false, ranges: "unavailable", mismatches: [] };
  if (kind !== "file") return { hosts: 0, unreadable: true, ranges: "unavailable", mismatches: [] };
  const { readDiscovery } = await import("../agent-discovery.ts");
  const snap = readDiscovery(ctx.home);
  const hosts = snap?.items.length ?? 0;
  if (ctx.adapterMismatches) {
    return {
      hosts,
      unreadable: false,
      ranges: "checked",
      mismatches: ctx.adapterMismatches.filter((item) => SAFE_EVENT.test(item)).slice(0, 20),
    };
  }
  return { hosts, unreadable: false, ranges: "unavailable", mismatches: [] };
}

export async function readHookConfig(ctx: InspectContext): Promise<{ records: "none" | "unreadable" | "mismatch" | "match"; code?: string }> {
  const manifest = await readManifest(ctx.home);
  if (manifest === "unreadable") return { records: "unreadable", code: "manifest_unreadable" };
  if (!manifest) return { records: "none" };
  const records = manifestRecords(manifest);
  if (records.length === 0) return { records: "none" };
  let unreadable = false;
  for (const record of records) {
    const kind = await fileKind(record.path);
    if (kind === "unreadable" || kind === "symlink" || kind === "dir" || kind === "other") {
      unreadable = true;
      continue;
    }
    if (kind === "missing") return { records: "mismatch" };
    const text = await readText(record.path);
    if (!text.ok) {
      unreadable = true;
      continue;
    }
    if (sha256Text(text.text) !== record.sha) return { records: "mismatch" };
  }
  return unreadable ? { records: "unreadable", code: "hook_config_unreadable" } : { records: "match" };
}

function manifestRecords(manifest: Record<string, unknown>): Array<{ path: string; sha: string }> {
  const out: Array<{ path: string; sha: string }> = [];
  const push = (path: unknown, sha: unknown) => {
    if (typeof path === "string" && path.length > 0 && typeof sha === "string" && /^[a-f0-9]{64}$/.test(sha)) {
      out.push({ path, sha });
    }
  };
  if (object(manifest.grok)) push(manifest.grokPath, manifest.grok.writtenSha256);
  if (object(manifest.claude)) push(manifest.claudePath, manifest.claude.writtenSha256);
  if (object(manifest.antigravity)) push(manifest.antigravityPath, manifest.antigravity.writtenSha256);
  if (object(manifest.launcher)) push(manifest.launcher.path, manifest.launcher.writtenSha256);
  if (Array.isArray(manifest.hostFiles)) {
    for (const row of manifest.hostFiles) {
      if (object(row)) push(row.path, row.writtenSha256);
    }
  }
  return out;
}

export interface HookObservation {
  looked: boolean;
  unreadable: boolean;
  configured: string[];
  observed: string[];
  latest: Map<string, number>;
}

export async function readHookObservation(ctx: InspectContext): Promise<HookObservation> {
  const latest = new Map<string, number>();
  let looked = false;
  let unreadable = false;
  const note = (agent: unknown, ts: unknown, sourceHook: boolean) => {
    if (!sourceHook) return;
    if (typeof agent !== "string" || !SAFE_HOST.test(agent)) return;
    if (typeof ts !== "number" || !Number.isFinite(ts)) return;
    if (ts < ctx.nowMs - HOOK_OBSERVED_WINDOW_MS || ts > ctx.nowMs + 60_000) return;
    latest.set(agent, Math.max(latest.get(agent) ?? 0, ts));
  };
  const events = await readEventFile(join(ctx.dataDir, "events.jsonl"));
  if (events === "unreadable") unreadable = true;
  else if (events !== "missing") {
    looked = true;
    for (const row of events.rows) note(row.agent, row.ts, row.source === "hook");
  }
  const cache = await readJson(join(ctx.home, ".nmzp", "window-cache.json"));
  if (!cache.ok && cache.code !== "enoent") unreadable = true;
  else if (cache.ok && object(cache.value) && object(cache.value.keys)) {
    looked = true;
    for (const [key, value] of Object.entries(cache.value.keys)) {
      const agent = key.split("\0")[1] ?? "";
      const lastTs = object(value) ? value.lastTs : undefined;
      note(agent, lastTs, true);
    }
  } else if (cache.ok) unreadable = true;
  const outbox = await readJson(join(ctx.home, ".nmzp", "audit-outbox.json"));
  if (!outbox.ok && outbox.code !== "enoent") unreadable = true;
  else if (outbox.ok && object(outbox.value) && Array.isArray(outbox.value.items)) {
    looked = true;
    for (const item of outbox.value.items) {
      if (!object(item) || item.kind !== "event" || !object(item.payload)) continue;
      note(item.payload.agent, item.payload.ts, true);
    }
  } else if (outbox.ok) unreadable = true;
  if (Array.isArray(ctx.extraEvents)) {
    looked = true;
    for (const event of ctx.extraEvents) {
      if (!object(event)) continue;
      note(event.agent, event.ts, event.source === "hook");
    }
  }
  const configured = await configuredHosts(ctx.home);
  return { looked, unreadable, configured, observed: [...latest.keys()], latest };
}

async function configuredHosts(home: string): Promise<string[]> {
  const manifest = await readManifest(home);
  if (!manifest || manifest === "unreadable") return [];
  const hosts: string[] = [];
  if (typeof manifest.grokPath === "string") hosts.push("grok");
  if (typeof manifest.claudePath === "string") hosts.push("claude");
  if (typeof manifest.codexPath === "string") hosts.push("codex");
  if (typeof manifest.zcodePath === "string") hosts.push("zcode");
  if (typeof manifest.antigravityPath === "string") hosts.push("antigravity");
  if (Array.isArray(manifest.hostFiles)) {
    for (const row of manifest.hostFiles) {
      if (object(row) && typeof row.agent === "string" && SAFE_HOST.test(row.agent)) hosts.push(row.agent);
    }
  }
  return [...new Set(hosts)];
}

async function readManifest(home: string): Promise<Record<string, unknown> | null | "unreadable"> {
  const read = await readJson(join(home, ".nmzp", "manifest.json"));
  if (!read.ok) return read.code === "enoent" ? null : "unreadable";
  return object(read.value) ? read.value : "unreadable";
}

