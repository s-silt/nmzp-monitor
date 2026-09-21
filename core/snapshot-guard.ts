import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { atomicWriteFile, restrictPath } from "./install-fs.ts";
import type { Capability } from "./schema.ts";

/**
 * OS-level lock for the known ZCode snapshot path home/.zcode/v2/checkpoints.
 * Not a hook, watcher, or warn-only filter. Does not revoke pre-opened handles:
 * stop the old client before apply. Does not deny SYNCHRONIZE / ReadPermissions /
 * ChangePermissions, SYSTEM, or Administrators. Parent DELETE_CHILD and the
 * object's owner WRITE_DAC can still unlock. Linux/macOS unsupported this round.
 * ZCode 3.14.0 removed the upload pipeline; this is a tripwire for leftover
 * 3.12.3-style pack-and-OSS clients, not a claim that every version still exfiltrates.
 */
export const CHECKPOINTS_SEGMENTS = [".zcode", "v2", "checkpoints"] as const;
export const MANIFEST_SEGMENTS = [".nmzp", "snapshot-guard.json"] as const;
export const MAX_GUARD_ENTRIES = 256;
export const SNAPSHOT_GUARD_KIND = "nmzp-snapshot-guard";
export const SNAPSHOT_GUARD_VERSION = 1;

/** CreateFiles|CreateDirectories|Delete|DeleteSubdirectoriesAndFiles|WriteAttributes|WriteExtendedAttributes */
export const DIR_DENY_RIGHTS = 2 | 4 | 65536 | 64 | 256 | 16;
/** ReadData|WriteData|AppendData|Delete|WriteAttributes|WriteExtendedAttributes */
export const FILE_DENY_RIGHTS = 1 | 2 | 4 | 65536 | 256 | 16;

export type ArchiveCoverage = "none" | "protected" | "unprotected" | "partial" | "unknown";

export interface SnapshotGuardStatus {
  supported: boolean;
  active: boolean;
  managed: boolean;
  targetPresent: boolean;
  writeBlocked: boolean;
  existingArchiveCoverage: ArchiveCoverage;
  error?: string;
  lastVerified?: number;
  zcodeRunning?: boolean | null;
}

export interface SnapshotGuardOptions {
  home: string;
  now?: number;
  checkZcode?: () => Promise<{ ok: boolean; running: boolean }>;
  /** Test-only: helper fails after this many addDeny attempts. */
  failAfter?: number;
  /** Test-only: after injected failure, keep pending journal and skip auto-rollback. */
  leavePending?: boolean;
}

export interface GuardPaths {
  home: string;
  target: string;
  manifest: string;
}

interface AceRow {
  sid?: string;
  type?: string;
  rights?: number;
  inherit?: string;
}

interface InspectRow {
  path?: string;
  exists?: boolean;
  isDir?: boolean;
  reparse?: boolean;
  sddl?: string | null;
  ownerSid?: string | null;
  aces?: AceRow[];
  error?: string | null;
}

interface WalkItem {
  path: string;
  rel: string;
  isDir: boolean;
}

interface FileIdentity {
  creationTimeUtc: number;
  length?: number;
  ino: string;
  dev: string;
}

interface ManifestObject {
  rel: string;
  isDir: boolean;
  originalSddl: string;
  expectedSddl: string;
  identity: FileIdentity;
}

interface Manifest {
  version: number;
  kind: string;
  phase: "pending" | "applied";
  createdAt: number;
  userSid: string;
  home: string;
  target: string;
  objects: ManifestObject[];
}

type ManifestRead = { state: "missing" } | { state: "invalid" } | { state: "ok"; manifest: Manifest };

const coreDir = dirname(fileURLToPath(import.meta.url));
const PS1_NAME = "snapshot-guard-windows.ps1";
const PROBE_PREFIX = ".nmzp-sg-";
const SYNCHRONIZE = 0x100000;

function norm(p: string): string {
  return resolve(p).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

function inside(root: string, p: string): boolean {
  const r = norm(root);
  const x = norm(p);
  return x === r || x.startsWith(`${r}/`);
}

export function isSnapshotGuardSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32";
}

export function resolveGuardPaths(home: string): GuardPaths {
  if (!home || typeof home !== "string" || home.includes("\0")) {
    throw new Error("path_invalid");
  }
  const homeAbs = resolve(home);
  const target = resolve(homeAbs, ...CHECKPOINTS_SEGMENTS);
  const expected = resolve(join(homeAbs, ".zcode", "v2", "checkpoints"));
  if (norm(target) !== norm(expected) || !inside(homeAbs, target)) {
    throw new Error("path_invalid");
  }
  const manifest = resolve(homeAbs, ...MANIFEST_SEGMENTS);
  if (!inside(homeAbs, manifest) || inside(target, manifest)) {
    throw new Error("path_invalid");
  }
  return { home: homeAbs, target, manifest };
}

function baseStatus(partial: Partial<SnapshotGuardStatus> = {}): SnapshotGuardStatus {
  return {
    supported: false,
    active: false,
    managed: false,
    targetPresent: false,
    writeBlocked: false,
    existingArchiveCoverage: "unknown",
    lastVerified: Date.now(),
    ...partial,
  };
}

export function publicSnapshotGuardStatus(status: SnapshotGuardStatus): SnapshotGuardStatus {
  const coverage: Exclude<ArchiveCoverage, "unprotected"> =
    status.existingArchiveCoverage === "unprotected" ? "partial" : status.existingArchiveCoverage;
  const out: SnapshotGuardStatus = {
    supported: status.supported,
    active: status.active,
    managed: status.managed,
    targetPresent: status.targetPresent,
    writeBlocked: status.writeBlocked,
    existingArchiveCoverage: coverage,
    lastVerified: status.lastVerified ?? 0,
  };
  if (status.error) out.error = status.error;
  return out;
}

export function toSnapshotGuardCapability(status: SnapshotGuardStatus): Capability {
  const cap: Capability = {
    id: "snapshot_guard",
    supported: status.supported,
    active: status.active,
  };
  if (status.lastVerified != null) cap.lastSuccess = status.lastVerified;
  if (status.error) cap.error = status.error;
  return cap;
}

export function parseSnapshotGuardCli(
  argv: string[],
  defaultHome = homedir(),
): { ok: true; cmd: "status" | "apply" | "restore"; home: string } | { ok: false; error: string } {
  const cmd = argv[0];
  if (cmd !== "status" && cmd !== "apply" && cmd !== "restore") {
    return { ok: false, error: "usage: snapshot-guard status|apply|restore [--home <path>]" };
  }
  let home = defaultHome;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "--home" && argv[i + 1]) {
      home = argv[++i]!;
      continue;
    }
    return { ok: false, error: "usage: snapshot-guard status|apply|restore [--home <path>]" };
  }
  return { ok: true, cmd, home: resolve(home) };
}

let encodedPsCache: string | undefined;

export function powershellExe(): string {
  const root = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
  return join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

export function buildSnapshotGuardPsInvocation(inputPath: string): {
  file: string;
  args: string[];
  env: Record<string, string>;
} {
  if (!encodedPsCache) {
    const ps1 = readFileSync(join(coreDir, PS1_NAME), "utf8").replace(/^\uFEFF/, "");
    encodedPsCache = Buffer.from(ps1, "utf16le").toString("base64");
  }
  return {
    file: powershellExe(),
    args: ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPsCache],
    env: { NMZP_SG_INPUT: inputPath },
  };
}

function isDenied(e: unknown): boolean {
  const err = e as NodeJS.ErrnoException;
  const code = err?.code;
  if (code === "EACCES" || code === "EPERM") return true;
  const m = String(err?.message || "").toLowerCase();
  return m.includes("eacces") || m.includes("eperm") || m.includes("access is denied") || m.includes("permission denied");
}

function isReparseStat(st: Stats): boolean {
  if (st.isSymbolicLink()) return true;
  const attrs = (st as Stats & { attributes?: number }).attributes;
  if (typeof attrs === "number" && (attrs & 0x400) !== 0) return true;
  return false;
}

function idStr(v: unknown): string {
  if (typeof v === "bigint" || typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  return "";
}

function walkAncestors(path: string, stopAt?: string): string[] {
  const out: string[] = [];
  let cur = resolve(path);
  const stop = stopAt ? norm(stopAt) : "";
  const seen = new Set<string>();
  while (cur && !seen.has(norm(cur))) {
    seen.add(norm(cur));
    out.push(cur);
    if (stop && norm(cur) === stop) break;
    const parent = dirname(cur);
    if (!parent || norm(parent) === norm(cur)) break;
    cur = parent;
  }
  return out;
}

function pathHasReparse(path: string, stopAt?: string): boolean {
  for (const p of walkAncestors(path, stopAt)) {
    if (!existsSync(p)) continue;
    try {
      if (isReparseStat(lstatSync(p))) return true;
    } catch {
      return true;
    }
  }
  return false;
}

function reparseOnChain(home: string, target: string): boolean {
  if (pathHasReparse(target, home)) return true;
  const nmzp = join(home, ".nmzp");
  const manifest = join(home, ...MANIFEST_SEGMENTS);
  if (existsSync(nmzp) && pathHasReparse(nmzp, home)) return true;
  if (existsSync(manifest) && pathHasReparse(manifest, home)) return true;
  return false;
}

function identityOf(path: string, isDir: boolean): FileIdentity {
  const st = lstatSync(path);
  const creationTimeUtc = st.birthtimeMs && st.birthtimeMs > 0 ? st.birthtimeMs : st.ctimeMs;
  const base: FileIdentity = {
    creationTimeUtc,
    ino: idStr((st as Stats & { ino?: unknown }).ino),
    dev: idStr((st as Stats & { dev?: unknown }).dev),
  };
  if (!isDir) base.length = st.size;
  return base;
}

function identityMatch(path: string, isDir: boolean, expected: FileIdentity): boolean {
  try {
    const got = identityOf(path, isDir);
    if (expected.ino && expected.ino !== "0" && got.ino && got.ino !== "0") {
      if (got.ino !== expected.ino || got.dev !== expected.dev) return false;
    } else if (Math.abs(got.creationTimeUtc - expected.creationTimeUtc) > 2) {
      return false;
    }
    if (!isDir && got.length !== expected.length) return false;
    return true;
  } catch {
    return false;
  }
}

function safeRel(rel: string): boolean {
  if (rel === ".") return true;
  if (!rel || rel.includes("\0") || rel.includes("..")) return false;
  if (rel.startsWith("/") || rel.startsWith("\\") || /^[a-zA-Z]:/.test(rel)) return false;
  const parts = rel.replace(/\\/g, "/").split("/");
  return parts.every((p) => p.length > 0 && p !== "." && p !== "..");
}

function looksLikeSddl(s: string): boolean {
  return typeof s === "string" && s.length > 2 && s.length < 32768 && /^[OGD]:/i.test(s);
}

function aceIsOurs(ace: AceRow, userSid: string, kind: "dir" | "file"): boolean {
  if (!ace || String(ace.sid) !== userSid) return false;
  if (String(ace.type).toLowerCase() !== "deny") return false;
  const inherit = String(ace.inherit || "None");
  if (inherit !== "None") return false;
  const rights = Number(ace.rights ?? 0) | 0;
  if (rights & SYNCHRONIZE) return false;
  const want = kind === "dir" ? DIR_DENY_RIGHTS : FILE_DENY_RIGHTS;
  return (rights & want) === want && (rights & ~want) === 0;
}

function asArray<T>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  if (v && typeof v === "object") return [v as T];
  return [];
}

function parsePsJson(stdout: string): Record<string, unknown> {
  const t = (stdout || "").replace(/^\uFEFF/, "").trim();
  const start = t.indexOf("{");
  const end = t.lastIndexOf("}");
  if (start < 0 || end < start) throw new Error("ps_output_invalid");
  const parsed = JSON.parse(t.slice(start, end + 1)) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("ps_output_invalid");
  return parsed as Record<string, unknown>;
}

function assertSafeNmzpWorkdir(home: string): string {
  const homeAbs = resolve(home);
  if (pathHasReparse(homeAbs)) throw new Error("reparse_rejected");
  const work = join(homeAbs, ".nmzp");
  if (existsSync(work) && pathHasReparse(work, homeAbs)) throw new Error("reparse_rejected");
  mkdirSync(work, { recursive: true });
  if (pathHasReparse(work, homeAbs)) throw new Error("reparse_rejected");
  const manifest = join(work, "snapshot-guard.json");
  if (existsSync(manifest) && pathHasReparse(manifest, homeAbs)) throw new Error("reparse_rejected");
  return work;
}

function runPs(home: string, payload: Record<string, unknown>): Record<string, unknown> {
  const exe = powershellExe();
  if (!existsSync(exe)) throw new Error("ps_unavailable");
  const work = assertSafeNmzpWorkdir(home);
  const input = join(work, `${PROBE_PREFIX}in-${process.pid}-${randomBytes(4).toString("hex")}.json`);
  writeFileSync(input, JSON.stringify(payload), { encoding: "utf8", mode: 0o600 });
  try {
    const inv = buildSnapshotGuardPsInvocation(input);
    const r = spawnSync(inv.file, inv.args, {
      encoding: "utf8",
      windowsHide: true,
      timeout: 45_000,
      env: { ...process.env, ...inv.env },
    });
    if (r.error) throw new Error("ps_unavailable");
    const parsed = parsePsJson(r.stdout || "");
    if (parsed.ok === false && !parsed.results) {
      throw new Error(typeof parsed.error === "string" ? parsed.error : "ps_exception");
    }
    return parsed;
  } finally {
    try {
      unlinkSync(input);
    } catch {
      /* ignore */
    }
  }
}

function walkEntries(root: string, max: number): { items: WalkItem[]; truncated: boolean; accessDenied: boolean; skippedReparse: boolean } {
  const items: WalkItem[] = [{ path: root, rel: ".", isDir: true }];
  let truncated = false;
  let accessDenied = false;
  let skippedReparse = false;
  const queue: WalkItem[] = [{ path: root, rel: ".", isDir: true }];
  while (queue.length) {
    const cur = queue.shift()!;
    let ents;
    try {
      ents = readdirSync(cur.path, { withFileTypes: true });
    } catch (e) {
      if (isDenied(e)) {
        accessDenied = true;
        continue;
      }
      throw e;
    }
    for (const ent of ents) {
      if (ent.name.startsWith(PROBE_PREFIX)) continue;
      if (items.length >= max) {
        truncated = true;
        break;
      }
      const p = join(cur.path, ent.name);
      const rel = cur.rel === "." ? ent.name : `${cur.rel.replace(/\\/g, "/")}/${ent.name}`;
      let st: Stats;
      try {
        st = lstatSync(p);
      } catch (e) {
        if (isDenied(e)) {
          accessDenied = true;
          continue;
        }
        throw e;
      }
      if (isReparseStat(st)) {
        skippedReparse = true;
        continue;
      }
      const isDir = st.isDirectory();
      items.push({ path: p, rel, isDir });
      if (isDir) queue.push({ path: p, rel, isDir });
    }
    if (truncated) break;
  }
  return { items, truncated, accessDenied, skippedReparse };
}

function probeCreate(dir: string): { writeBlocked: boolean; leftover: boolean; lastVerified: number } {
  const name = `${PROBE_PREFIX}${randomBytes(8).toString("hex")}`;
  const p = join(dir, name);
  const lastVerified = Date.now();
  try {
    const fd = openSync(p, "wx");
    closeSync(fd);
  } catch (e) {
    if (isDenied(e)) return { writeBlocked: true, leftover: false, lastVerified };
    throw e;
  }
  try {
    unlinkSync(p);
    return { writeBlocked: false, leftover: false, lastVerified };
  } catch {
    return { writeBlocked: false, leftover: true, lastVerified };
  }
}

function probeReadBlocked(path: string): boolean {
  try {
    const fd = openSync(path, "r");
    closeSync(fd);
    return false;
  } catch (e) {
    return isDenied(e);
  }
}

function probeDirs(dirs: WalkItem[]): { leftover: boolean; lastVerified: number; allBlocked: boolean; rootBlocked: boolean } {
  let leftover = false;
  let lastVerified = Date.now();
  let allBlocked = dirs.length > 0;
  let rootBlocked = false;
  for (const d of dirs) {
    const r = probeCreate(d.path);
    lastVerified = r.lastVerified;
    if (r.leftover) leftover = true;
    if (!r.writeBlocked) allBlocked = false;
    if (d.rel === ".") rootBlocked = r.writeBlocked;
  }
  if (!dirs.some((d) => d.rel === ".") && dirs[0]) {
    const r = probeCreate(dirs[0].path);
    rootBlocked = r.writeBlocked;
    if (r.leftover) leftover = true;
  }
  return { leftover, lastVerified, allBlocked, rootBlocked };
}

function writeBlockedFromWalk(
  walk: { truncated: boolean; accessDenied: boolean; skippedReparse: boolean },
  dirItems: WalkItem[],
  probes: { leftover: boolean; lastVerified: number; allBlocked: boolean; rootBlocked: boolean },
): { writeBlocked: boolean; lastVerified: number; leftover: boolean } {
  const rootOnlyInaccessible = walk.accessDenied && dirItems.length <= 1;
  if (probes.leftover) {
    return { writeBlocked: false, lastVerified: probes.lastVerified, leftover: true };
  }
  if (rootOnlyInaccessible) {
    return { writeBlocked: probes.rootBlocked, lastVerified: probes.lastVerified, leftover: false };
  }
  const incomplete = walk.truncated || walk.skippedReparse || walk.accessDenied;
  if (incomplete) {
    return { writeBlocked: false, lastVerified: probes.lastVerified, leftover: false };
  }
  return { writeBlocked: probes.allBlocked, lastVerified: probes.lastVerified, leftover: false };
}

function inspectPaths(home: string, paths: string[]): { userSid: string; rows: Map<string, InspectRow> } {
  const raw = runPs(home, { action: "inspect", paths });
  const userSid = typeof raw.userSid === "string" ? raw.userSid : "";
  const rows = new Map<string, InspectRow>();
  const items = asArray<InspectRow>(raw.items);
  for (const it of items) {
    if (it && typeof it.path === "string") rows.set(norm(it.path), it);
  }
  return { userSid, rows };
}

function defaultZcodeCheck(home: string): Promise<{ ok: boolean; running: boolean }> {
  return Promise.resolve().then(() => {
    try {
      const raw = runPs(home, { action: "zcode" });
      return { ok: raw.ok === true, running: raw.running === true };
    } catch {
      return { ok: false, running: false };
    }
  });
}

function parseManifest(raw: unknown, paths: GuardPaths): ManifestRead {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { state: "invalid" };
  const o = raw as Record<string, unknown>;
  if (o.kind !== SNAPSHOT_GUARD_KIND || o.version !== SNAPSHOT_GUARD_VERSION) return { state: "invalid" };
  if (o.phase !== "pending" && o.phase !== "applied") return { state: "invalid" };
  if (typeof o.userSid !== "string" || !/^S-1-5-[0-9-]+$/.test(o.userSid)) return { state: "invalid" };
  if (typeof o.home !== "string" || typeof o.target !== "string") return { state: "invalid" };
  if (norm(o.home) !== norm(paths.home) || norm(o.target) !== norm(paths.target)) return { state: "invalid" };
  if (typeof o.createdAt !== "number" || !Number.isFinite(o.createdAt)) return { state: "invalid" };
  if (!Array.isArray(o.objects) || o.objects.length === 0 || o.objects.length > MAX_GUARD_ENTRIES) return { state: "invalid" };
  const objects: ManifestObject[] = [];
  for (const row of o.objects) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return { state: "invalid" };
    const r = row as Record<string, unknown>;
    if (typeof r.rel !== "string" || !safeRel(r.rel)) return { state: "invalid" };
    if (typeof r.isDir !== "boolean") return { state: "invalid" };
    if (!looksLikeSddl(String(r.originalSddl || ""))) return { state: "invalid" };
    const expected = typeof r.expectedSddl === "string" ? r.expectedSddl : "";
    if (o.phase === "applied" && !looksLikeSddl(expected)) return { state: "invalid" };
    if (o.phase === "pending" && expected && !looksLikeSddl(expected)) return { state: "invalid" };
    const id = r.identity;
    if (!id || typeof id !== "object" || Array.isArray(id)) return { state: "invalid" };
    const ident = id as Record<string, unknown>;
    if (typeof ident.creationTimeUtc !== "number" || !Number.isFinite(ident.creationTimeUtc)) return { state: "invalid" };
    if (typeof ident.ino !== "string" || typeof ident.dev !== "string") return { state: "invalid" };
    const obj: ManifestObject = {
      rel: r.rel.replace(/\\/g, "/"),
      isDir: r.isDir,
      originalSddl: String(r.originalSddl),
      expectedSddl: expected,
      identity: {
        creationTimeUtc: ident.creationTimeUtc,
        ino: ident.ino,
        dev: ident.dev,
      },
    };
    if (!r.isDir) {
      if (typeof ident.length !== "number") return { state: "invalid" };
      obj.identity.length = ident.length;
    }
    const abs = obj.rel === "." ? paths.target : join(paths.target, obj.rel.split("/").join(sep));
    if (!inside(paths.target, abs) && norm(abs) !== norm(paths.target)) return { state: "invalid" };
    objects.push(obj);
  }
  return {
    state: "ok",
    manifest: {
      version: SNAPSHOT_GUARD_VERSION,
      kind: SNAPSHOT_GUARD_KIND,
      phase: o.phase,
      createdAt: o.createdAt,
      userSid: o.userSid,
      home: paths.home,
      target: paths.target,
      objects,
    },
  };
}

function readManifest(path: string, paths: GuardPaths): ManifestRead {
  if (!existsSync(path)) return { state: "missing" };
  try {
    return parseManifest(JSON.parse(readFileSync(path, "utf8")), paths);
  } catch {
    return { state: "invalid" };
  }
}

function fsyncExistingFile(path: string): void {
  const fd = openSync(path, "r+");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeManifest(path: string, m: Manifest): void {
  atomicWriteFile(path, JSON.stringify(m), 0o600);
  try {
    fsyncExistingFile(path);
  } catch {
    throw new Error("journal_persist_failed");
  }
  try {
    restrictPath(path);
  } catch {
    /* manifest still written; ACL restrict is best-effort */
  }
}

function objectAbs(paths: GuardPaths, rel: string): string {
  return rel === "." ? paths.target : join(paths.target, rel.split("/").join(sep));
}

function rollbackJournal(paths: GuardPaths, objects: ManifestObject[]): "ok" | "rollback_failed" {
  if (!objects.length) return "ok";
  const items: Array<{ path: string; originalSddl: string; expectedSddl: string }> = [];
  let blocked = false;
  for (const o of objects) {
    if (!looksLikeSddl(o.originalSddl) || !looksLikeSddl(o.expectedSddl)) {
      blocked = true;
      continue;
    }
    const p = objectAbs(paths, o.rel);
    if (!existsSync(p) || pathHasReparse(p, paths.home) || !identityMatch(p, o.isDir, o.identity)) {
      blocked = true;
      continue;
    }
    items.push({ path: p, originalSddl: o.originalSddl, expectedSddl: o.expectedSddl });
  }
  if (items.length) {
    try {
      const raw = runPs(paths.home, { action: "restoreSddl", items });
      const results = asArray<{ ok?: boolean; conflict?: boolean }>(raw.results);
      if (results.length !== items.length || results.some((r) => r.ok === false || r.conflict)) blocked = true;
    } catch {
      return "rollback_failed";
    }
  }
  return blocked ? "rollback_failed" : "ok";
}

function coverageOf(
  files: WalkItem[],
  inspect: Map<string, InspectRow>,
  userSid: string,
  flags: { accessDenied: boolean; truncated: boolean; skippedReparse: boolean },
): ArchiveCoverage {
  if (flags.accessDenied || flags.truncated || flags.skippedReparse) return "unknown";
  const onlyFiles = files.filter((f) => !f.isDir);
  if (!onlyFiles.length) return "none";
  let protectedN = 0;
  let known = 0;
  for (const f of onlyFiles) {
    const row = inspect.get(norm(f.path));
    if (!row || row.error === "access_denied") return "unknown";
    known += 1;
    if (aceIsOursOn(row, userSid, "file")) protectedN += 1;
  }
  if (protectedN === known && known === onlyFiles.length) return "protected";
  if (protectedN === 0) return "unprotected";
  return "partial";
}

function aceIsOursOn(row: InspectRow | undefined, userSid: string, kind: "dir" | "file"): boolean {
  if (!row || !Array.isArray(row.aces)) return false;
  return row.aces.some((a) => aceIsOurs(a, userSid, kind));
}

function finalizeActive(st: SnapshotGuardStatus): SnapshotGuardStatus {
  const coverageOk = st.existingArchiveCoverage === "none" || st.existingArchiveCoverage === "protected";
  st.active = Boolean(
    st.supported && st.managed && st.writeBlocked && st.targetPresent && coverageOk && !st.error,
  );
  return st;
}

function unsupported(): SnapshotGuardStatus {
  return baseStatus({ supported: false, error: "unsupported_platform", existingArchiveCoverage: "none" });
}

async function snapshotGuardStatusInner(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  if (!isSnapshotGuardSupported()) return unsupported();
  let paths: GuardPaths;
  try {
    paths = resolveGuardPaths(opts.home);
  } catch {
    return baseStatus({ supported: true, error: "path_invalid" });
  }
  if (reparseOnChain(paths.home, paths.target)) {
    return baseStatus({ supported: true, error: "reparse_rejected", targetPresent: existsSync(paths.target) });
  }
  if (!existsSync(paths.target)) {
    return baseStatus({ supported: true, error: "target_missing", existingArchiveCoverage: "none" });
  }
  let st: Stats;
  try {
    st = lstatSync(paths.target);
  } catch (e) {
    return baseStatus({
      supported: true,
      targetPresent: true,
      error: isDenied(e) ? "access_denied" : "status_failed",
    });
  }
  if (isReparseStat(st)) {
    return baseStatus({ supported: true, targetPresent: true, error: "reparse_rejected" });
  }
  if (!st.isDirectory()) {
    return baseStatus({ supported: true, targetPresent: true, error: "target_not_directory" });
  }

  const walk = walkEntries(paths.target, MAX_GUARD_ENTRIES);
  const inspectList = walk.accessDenied ? [paths.target] : walk.items.map((i) => i.path);
  let userSid = "";
  let rows = new Map<string, InspectRow>();
  try {
    const ins = inspectPaths(paths.home, inspectList);
    userSid = ins.userSid;
    rows = ins.rows;
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    return baseStatus({
      supported: true,
      targetPresent: true,
      error: msg === "reparse_rejected" ? "reparse_rejected" : "access_denied",
    });
  }
  const targetRow = rows.get(norm(paths.target));
  if (targetRow?.reparse) {
    return baseStatus({ supported: true, targetPresent: true, error: "reparse_rejected" });
  }

  const mf = readManifest(paths.manifest, paths);
  if (mf.state === "invalid") {
    return baseStatus({ supported: true, targetPresent: true, error: "manifest_invalid" });
  }
  const managed = Boolean(mf.state === "ok" && mf.manifest.phase === "applied" && mf.manifest.userSid === userSid);
  const dirItems = walk.items.filter((i) => i.isDir);
  const probes = probeDirs(dirItems.length ? dirItems : [{ path: paths.target, rel: ".", isDir: true }]);
  const wb = writeBlockedFromWalk(walk, dirItems, probes);
  if (wb.leftover) {
    return baseStatus({
      supported: true,
      targetPresent: true,
      writeBlocked: false,
      managed,
      error: "probe_leftover",
      lastVerified: wb.lastVerified,
    });
  }
  const coverage = walk.accessDenied ? "unknown" : coverageOf(walk.items, rows, userSid, walk);
  const stOut = baseStatus({
    supported: true,
    managed,
    targetPresent: true,
    writeBlocked: wb.writeBlocked,
    existingArchiveCoverage: coverage,
    lastVerified: wb.lastVerified,
  });
  if (mf.state === "ok" && mf.manifest.phase === "pending") stOut.error = "apply_failed";
  else if (wb.writeBlocked && !managed) {
    stOut.error = "external_restriction";
    if (walk.accessDenied) stOut.existingArchiveCoverage = "unknown";
  }
  return finalizeActive(stOut);
}

export async function snapshotGuardStatus(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  try {
    return await snapshotGuardStatusInner(opts);
  } catch (e) {
    return baseStatus({
      supported: isSnapshotGuardSupported(),
      error: isDenied(e) ? "access_denied" : "status_failed",
    });
  }
}

function finishApply(
  paths: GuardPaths,
  walk: { truncated: boolean; accessDenied: boolean; skippedReparse: boolean; items?: WalkItem[] },
  toGuard: WalkItem[],
  userSid: string,
): SnapshotGuardStatus {
  const dirItems = toGuard.filter((i) => i.isDir);
  const probes = probeDirs(dirItems.length ? dirItems : [{ path: paths.target, rel: ".", isDir: true }]);
  const wb = writeBlockedFromWalk(walk, dirItems, probes);
  if (wb.leftover) return baseStatus({ supported: true, targetPresent: true, error: "probe_leftover", zcodeRunning: false });
  const after = inspectPaths(paths.home, walk.accessDenied ? [paths.target] : toGuard.map((i) => i.path));
  const coverage = walk.accessDenied ? "unknown" : coverageOf(toGuard, after.rows, userSid, walk);
  const filesOk = toGuard.filter((i) => !i.isDir).every((f) => probeReadBlocked(f.path));
  const proven = wb.writeBlocked && filesOk && (coverage === "none" || coverage === "protected");
  const stOut = baseStatus({
    supported: true,
    managed: true,
    targetPresent: true,
    writeBlocked: proven,
    existingArchiveCoverage: coverage,
    lastVerified: wb.lastVerified,
    zcodeRunning: false,
  });
  if (!proven) stOut.error = coverage === "none" || coverage === "protected" ? "write_still_allowed" : "coverage_unknown";
  if (stOut.error === "write_still_allowed") stOut.managed = true;
  return finalizeActive(stOut);
}

async function snapshotGuardApplyInner(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  if (!isSnapshotGuardSupported()) return unsupported();
  let paths: GuardPaths;
  try {
    paths = resolveGuardPaths(opts.home);
  } catch {
    return baseStatus({ supported: true, error: "path_invalid" });
  }
  if (reparseOnChain(paths.home, paths.target)) {
    return baseStatus({ supported: true, error: "reparse_rejected", zcodeRunning: false });
  }
  if (!existsSync(paths.target)) {
    return baseStatus({ supported: true, error: "target_missing", zcodeRunning: false, existingArchiveCoverage: "none" });
  }
  const check = opts.checkZcode ?? (() => defaultZcodeCheck(paths.home));
  const zc = await check();
  if (!zc.ok) return baseStatus({ supported: true, error: "process_list_failed", zcodeRunning: null });
  if (zc.running) return baseStatus({ supported: true, error: "zcode_running", zcodeRunning: true });
  const st = lstatSync(paths.target);
  if (isReparseStat(st)) return baseStatus({ supported: true, targetPresent: true, error: "reparse_rejected", zcodeRunning: false });
  if (!st.isDirectory()) {
    return baseStatus({ supported: true, targetPresent: true, error: "target_not_directory", zcodeRunning: false });
  }

  const walk = walkEntries(paths.target, MAX_GUARD_ENTRIES);
  const inspectList = walk.accessDenied ? [paths.target] : walk.items.map((i) => i.path);
  const ins = inspectPaths(paths.home, inspectList);
  const targetRow = ins.rows.get(norm(paths.target));
  if (targetRow?.reparse) {
    return baseStatus({ supported: true, targetPresent: true, error: "reparse_rejected", zcodeRunning: false });
  }

  const mf = readManifest(paths.manifest, paths);
  if (mf.state === "invalid") {
    return baseStatus({ supported: true, targetPresent: true, error: "manifest_invalid", zcodeRunning: false });
  }
  if (mf.state === "ok" && mf.manifest.userSid !== ins.userSid) {
    return baseStatus({ supported: true, targetPresent: true, error: "manifest_invalid", zcodeRunning: false });
  }
  if (mf.state === "ok" && mf.manifest.phase === "pending") {
    const rb = rollbackJournal(paths, mf.manifest.objects);
    if (rb === "rollback_failed") {
      return baseStatus({ supported: true, targetPresent: true, error: "rollback_failed", zcodeRunning: false });
    }
    try {
      unlinkSync(paths.manifest);
    } catch {
      /* continue */
    }
  }

  const appliedOwned = mf.state === "ok" && mf.manifest.phase === "applied" && mf.manifest.userSid === ins.userSid;
  const dirItems = (walk.accessDenied ? [{ path: paths.target, rel: ".", isDir: true }] : walk.items).filter((i) => i.isDir);
  const probes0 = probeDirs(dirItems.length ? dirItems : [{ path: paths.target, rel: ".", isDir: true }]);
  const wb0 = writeBlockedFromWalk(walk, dirItems, probes0);
  if (probes0.leftover) {
    return baseStatus({ supported: true, targetPresent: true, error: "probe_leftover", lastVerified: wb0.lastVerified, zcodeRunning: false });
  }

  if (!appliedOwned && (wb0.writeBlocked || (walk.accessDenied && probes0.rootBlocked))) {
    return finalizeActive(
      baseStatus({
        supported: true,
        targetPresent: true,
        writeBlocked: probes0.rootBlocked,
        managed: false,
        existingArchiveCoverage: walk.accessDenied ? "unknown" : coverageOf(walk.items, ins.rows, ins.userSid, walk),
        error: "external_restriction",
        lastVerified: wb0.lastVerified,
        zcodeRunning: false,
      }),
    );
  }

  if (appliedOwned) {
    return reapplyManaged(opts, paths, walk, ins, mf.manifest);
  }

  const toGuard = walk.accessDenied ? [{ path: paths.target, rel: ".", isDir: true }] : walk.items;
  for (const it of toGuard) {
    if (pathHasReparse(it.path, paths.home)) {
      return baseStatus({ supported: true, targetPresent: true, error: "reparse_rejected", zcodeRunning: false });
    }
  }

  const planRaw = runPs(paths.home, {
    action: "planDeny",
    items: toGuard.map((it) => ({
      path: it.path,
      rights: it.isDir ? DIR_DENY_RIGHTS : FILE_DENY_RIGHTS,
    })),
  });
  const planRows = asArray<{
    path?: string;
    ok?: boolean;
    originalSddl?: string;
    expectedSddl?: string;
    alreadyPresent?: boolean;
    error?: string;
  }>(planRaw.results);
  if (planRows.length !== toGuard.length || planRows.some((r) => r.ok === false || !looksLikeSddl(String(r.originalSddl)) || !looksLikeSddl(String(r.expectedSddl)))) {
    return baseStatus({ supported: true, targetPresent: true, error: "apply_failed", zcodeRunning: false });
  }
  if (planRows.some((r) => r.alreadyPresent)) {
    return finalizeActive(
      baseStatus({
        supported: true,
        targetPresent: true,
        writeBlocked: probes0.rootBlocked,
        managed: false,
        existingArchiveCoverage: walk.accessDenied ? "unknown" : coverageOf(walk.items, ins.rows, ins.userSid, walk),
        error: "external_restriction",
        lastVerified: wb0.lastVerified,
        zcodeRunning: false,
      }),
    );
  }

  const objects: ManifestObject[] = [];
  const byPath = new Map(planRows.map((r) => [norm(String(r.path)), r]));
  for (const it of toGuard) {
    const plan = byPath.get(norm(it.path));
    if (!plan?.originalSddl || !plan.expectedSddl) {
      return baseStatus({ supported: true, targetPresent: true, error: "apply_failed", zcodeRunning: false });
    }
    objects.push({
      rel: it.rel.replace(/\\/g, "/"),
      isDir: it.isDir,
      originalSddl: plan.originalSddl,
      expectedSddl: plan.expectedSddl,
      identity: identityOf(it.path, it.isDir),
    });
  }

  const pending: Manifest = {
    version: SNAPSHOT_GUARD_VERSION,
    kind: SNAPSHOT_GUARD_KIND,
    phase: "pending",
    createdAt: opts.now ?? Date.now(),
    userSid: ins.userSid,
    home: paths.home,
    target: paths.target,
    objects,
  };
  writeManifest(paths.manifest, pending);

  const failPayload: Record<string, unknown> = {
    action: "addDeny",
    items: objects.map((o) => ({
      path: objectAbs(paths, o.rel),
      rights: o.isDir ? DIR_DENY_RIGHTS : FILE_DENY_RIGHTS,
      expectedOriginal: o.originalSddl,
      expectedNew: o.expectedSddl,
    })),
  };
  if (opts.failAfter && opts.failAfter > 0) failPayload.failAfter = opts.failAfter;

  let results: Array<{
    path?: string;
    ok?: boolean;
    changed?: boolean;
    conflict?: boolean;
    originalSddl?: string;
    expectedSddl?: string;
  }> = [];
  try {
    const raw = runPs(paths.home, failPayload);
    results = asArray(raw.results);
  } catch {
    const rb = rollbackJournal(paths, pending.objects);
    if (rb === "rollback_failed") {
      return baseStatus({ supported: true, targetPresent: true, error: "rollback_failed", zcodeRunning: false });
    }
    try {
      unlinkSync(paths.manifest);
    } catch {
      /* ignore */
    }
    return baseStatus({ supported: true, targetPresent: true, error: "apply_failed", zcodeRunning: false });
  }

  const failed =
    results.length !== objects.length || results.some((r) => r.ok === false || r.conflict);
  if (failed) {
    if (opts.leavePending) {
      return baseStatus({ supported: true, targetPresent: true, error: "apply_failed", zcodeRunning: false });
    }
    const rb = rollbackJournal(paths, pending.objects);
    if (rb === "rollback_failed") {
      return baseStatus({ supported: true, targetPresent: true, error: "rollback_failed", zcodeRunning: false });
    }
    try {
      unlinkSync(paths.manifest);
    } catch {
      /* ignore */
    }
    return baseStatus({ supported: true, targetPresent: true, error: "apply_failed", zcodeRunning: false });
  }

  const applied: Manifest = { ...pending, phase: "applied" };
  writeManifest(paths.manifest, applied);
  const done = finishApply(paths, walk, toGuard, ins.userSid);
  if (done.error === "write_still_allowed" || done.error === "probe_leftover") {
    const rb = rollbackJournal(paths, applied.objects);
    if (rb === "rollback_failed") {
      return baseStatus({ supported: true, targetPresent: true, error: "rollback_failed", zcodeRunning: false });
    }
    try {
      unlinkSync(paths.manifest);
    } catch {
      /* ignore */
    }
    return baseStatus({ supported: true, targetPresent: true, error: done.error, zcodeRunning: false });
  }
  return done;
}

function reapplyManaged(
  opts: SnapshotGuardOptions,
  paths: GuardPaths,
  walk: { items: WalkItem[]; truncated: boolean; accessDenied: boolean; skippedReparse: boolean },
  ins: { userSid: string; rows: Map<string, InspectRow> },
  manifest: Manifest,
): SnapshotGuardStatus {
  const needAdd: WalkItem[] = [];
  for (const obj of manifest.objects) {
    const p = objectAbs(paths, obj.rel);
    if (!existsSync(p) || pathHasReparse(p, paths.home) || !identityMatch(p, obj.isDir, obj.identity)) {
      return baseStatus({
        supported: true,
        targetPresent: true,
        managed: true,
        error: "conflict",
        zcodeRunning: false,
      });
    }
    const row = ins.rows.get(norm(p));
    const cur = row?.sddl;
    if (!cur) {
      return baseStatus({ supported: true, targetPresent: true, managed: true, error: "access_denied", zcodeRunning: false });
    }
    if (cur === obj.expectedSddl) continue;
    if (cur === obj.originalSddl) {
      needAdd.push({ path: p, rel: obj.rel, isDir: obj.isDir });
      continue;
    }
    return baseStatus({
      supported: true,
      targetPresent: true,
      managed: true,
      error: "conflict",
      zcodeRunning: false,
    });
  }
  if (needAdd.length) {
    try {
      fsyncExistingFile(paths.manifest);
    } catch {
      return baseStatus({ supported: true, targetPresent: true, managed: true, error: "journal_persist_failed", zcodeRunning: false });
    }
    const needAddObjs = needAdd.map((it) => manifest.objects.find((o) => o.rel === it.rel)!);
    const raw = runPs(paths.home, {
      action: "addDeny",
      items: needAdd.map((it) => {
        const obj = manifest.objects.find((o) => o.rel === it.rel)!;
        return {
          path: it.path,
          rights: it.isDir ? DIR_DENY_RIGHTS : FILE_DENY_RIGHTS,
          expectedOriginal: obj.originalSddl,
          expectedNew: obj.expectedSddl,
        };
      }),
      ...(opts.failAfter && opts.failAfter > 0 ? { failAfter: opts.failAfter } : {}),
    });
    const results = asArray<{
      ok?: boolean;
      changed?: boolean;
      conflict?: boolean;
      originalSddl?: string;
      expectedSddl?: string;
      path?: string;
    }>(raw.results);
    if (results.length !== needAdd.length || results.some((r) => r.ok === false || r.conflict)) {
      const rb = rollbackJournal(paths, needAddObjs);
      if (rb === "rollback_failed") {
        return baseStatus({ supported: true, targetPresent: true, managed: true, error: "rollback_failed", zcodeRunning: false });
      }
      return baseStatus({ supported: true, targetPresent: true, managed: true, error: "apply_failed", zcodeRunning: false });
    }
    for (const r of results) {
      if (!r.path || !r.expectedSddl) continue;
      const obj = manifest.objects.find((o) => norm(objectAbs(paths, o.rel)) === norm(r.path!));
      if (obj && r.expectedSddl) obj.expectedSddl = r.expectedSddl;
    }
    writeManifest(paths.manifest, manifest);
  }
  const toGuard = walk.accessDenied ? [{ path: paths.target, rel: ".", isDir: true }] : walk.items;
  return finishApply(paths, walk, toGuard, ins.userSid);
}

export async function snapshotGuardApply(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  try {
    return await snapshotGuardApplyInner(opts);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    return baseStatus({
      supported: isSnapshotGuardSupported(),
      error: isDenied(e) ? "access_denied" : msg === "journal_persist_failed" ? "journal_persist_failed" : "apply_failed",
    });
  }
}

export async function snapshotGuardRestore(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  try {
    return await snapshotGuardRestoreInner(opts);
  } catch (e) {
    return baseStatus({
      supported: isSnapshotGuardSupported(),
      error: isDenied(e) ? "access_denied" : "apply_failed",
    });
  }
}

async function snapshotGuardRestoreInner(opts: SnapshotGuardOptions): Promise<SnapshotGuardStatus> {
  if (!isSnapshotGuardSupported()) return unsupported();
  let paths: GuardPaths;
  try {
    paths = resolveGuardPaths(opts.home);
  } catch {
    return baseStatus({ supported: true, error: "path_invalid" });
  }
  if (reparseOnChain(paths.home, paths.target)) {
    return baseStatus({ supported: true, targetPresent: existsSync(paths.target), error: "reparse_rejected", zcodeRunning: false });
  }
  const check = opts.checkZcode ?? (() => defaultZcodeCheck(paths.home));
  const zc = await check();
  if (!zc.ok) return baseStatus({ supported: true, error: "process_list_failed", zcodeRunning: null });
  if (zc.running) return baseStatus({ supported: true, error: "zcode_running", zcodeRunning: true });

  const mf = readManifest(paths.manifest, paths);
  if (mf.state === "missing") {
    return baseStatus({
      supported: true,
      targetPresent: existsSync(paths.target),
      error: "not_managed",
      zcodeRunning: false,
    });
  }
  if (mf.state === "invalid") {
    return baseStatus({
      supported: true,
      targetPresent: existsSync(paths.target),
      error: "manifest_invalid",
      zcodeRunning: false,
    });
  }
  const who = inspectPaths(paths.home, [existsSync(paths.target) ? paths.target : paths.home]);
  if (mf.manifest.userSid !== who.userSid) {
    return baseStatus({
      supported: true,
      targetPresent: existsSync(paths.target),
      error: "not_managed",
      zcodeRunning: false,
    });
  }

  if (mf.manifest.phase === "pending") {
    const rb = rollbackJournal(paths, mf.manifest.objects);
    if (rb === "rollback_failed") {
      return baseStatus({
        supported: true,
        targetPresent: existsSync(paths.target),
        error: "conflict",
        zcodeRunning: false,
      });
    }
    try {
      unlinkSync(paths.manifest);
    } catch {
      /* keep trying status */
    }
    const afterPending = existsSync(paths.target)
      ? await snapshotGuardStatus({ home: paths.home, now: opts.now })
      : baseStatus({ supported: true, error: "target_missing", zcodeRunning: false });
    afterPending.managed = false;
    afterPending.zcodeRunning = false;
    return finalizeActive(afterPending);
  }

  let conflict = false;
  const restoreItems: Array<{ path: string; originalSddl: string; expectedSddl: string }> = [];
  for (const obj of mf.manifest.objects) {
    const p = objectAbs(paths, obj.rel);
    if (!inside(paths.target, p) && norm(p) !== norm(paths.target)) {
      conflict = true;
      continue;
    }
    if (!looksLikeSddl(obj.originalSddl) || !looksLikeSddl(obj.expectedSddl)) {
      conflict = true;
      continue;
    }
    if (!existsSync(p) || pathHasReparse(p, paths.home) || !identityMatch(p, obj.isDir, obj.identity)) {
      conflict = true;
      continue;
    }
    restoreItems.push({ path: p, originalSddl: obj.originalSddl, expectedSddl: obj.expectedSddl });
  }

  if (restoreItems.length) {
    const raw = runPs(paths.home, {
      action: "restoreSddl",
      items: restoreItems.map((it) => ({
        path: it.path,
        originalSddl: it.originalSddl,
        expectedSddl: it.expectedSddl,
      })),
    });
    const results = asArray<{ ok?: boolean; conflict?: boolean }>(raw.results);
    if (results.length !== restoreItems.length || results.some((r) => r.ok === false || r.conflict)) conflict = true;
  }

  const after = existsSync(paths.target)
    ? await snapshotGuardStatus({ home: paths.home, now: opts.now })
    : baseStatus({ supported: true, error: "target_missing", zcodeRunning: false });
  after.zcodeRunning = false;
  if (conflict) {
    after.error = "conflict";
    after.managed = true;
    return finalizeActive(after);
  }
  try {
    unlinkSync(paths.manifest);
  } catch {
    /* restore already applied ACL */
  }
  after.managed = false;
  if (after.error === "external_restriction" && !after.writeBlocked) delete after.error;
  return finalizeActive(after);
}

