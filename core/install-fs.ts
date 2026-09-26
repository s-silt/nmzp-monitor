import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

export function sha256Text(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

export interface AtomicFs {
  mkdirSync: (path: string, opts: { recursive: boolean }) => void;
  writeFileSync: (path: string, body: string, opts: { encoding: BufferEncoding; mode: number }) => void;
  renameSync: (from: string, to: string) => void;
  existsSync: (path: string) => boolean;
  unlinkSync: (path: string) => void;
}

const defaultAtomicFs: AtomicFs = {
  mkdirSync: (path, opts) => {
    mkdirSync(path, opts);
  },
  writeFileSync: (path, body, opts) => {
    const fd = openSync(path, "wx", opts.mode);
    try {
      const buf = Buffer.from(body, "utf8");
      let offset = 0;
      while (offset < buf.length) {
        const wrote = writeSync(fd, buf, offset);
        if (!Number.isSafeInteger(wrote) || wrote < 1) throw new Error("atomic_write_failed");
        offset += wrote;
      }
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  },
  renameSync: (from, to) => {
    renameSync(from, to);
  },
  existsSync: (path) => existsSync(path),
  unlinkSync: (path) => {
    unlinkSync(path);
  },
};

/**
 * Refuse a symlink or junction on the path or an existing ancestor.
 * A rename can still race after this lstat; callers re-read bytes immediately before publish.
 */
export function assertNoSymlinkAncestry(target: string): void {
  const abs = resolve(target);
  const chain: string[] = [];
  let cur = abs;
  while (true) {
    chain.push(cur);
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  for (const prefix of chain.reverse()) {
    let st;
    try {
      st = lstatSync(prefix);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return;
      throw error;
    }
    if (st.isSymbolicLink()) throw new Error("unsafe_symlink");
  }
  try {
    const finalStat = lstatSync(abs);
    if (!finalStat.isFile()) throw new Error("atomic_write_failed");
  } catch (error) {
    if (error instanceof Error && error.message === "unsafe_symlink") throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return;
    throw error;
  }
}

/** Single rename onto the live path. Never move or unlink the official file. Fail with a fixed code. */
export function atomicWriteFile(path: string, body: string, mode = 0o600, io: AtomicFs = defaultAtomicFs): void {
  if (io === defaultAtomicFs) assertNoSymlinkAncestry(path);
  io.mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  io.writeFileSync(tmp, body, { encoding: "utf8", mode });
  try {
    io.renameSync(tmp, path);
  } catch {
    try {
      io.unlinkSync(tmp);
    } catch {
      /* ignore tmp cleanup */
    }
    throw new Error("atomic_write_failed");
  }
}

/** Path is passed via env, never interpolated into the script. */
export const ACL_RESTRICT_PS = `
$ErrorActionPreference = 'Stop'
$p = $env:NMZP_ACL_PATH
if (-not $p) { throw 'acl_restrict_failed' }
$item = Get-Item -LiteralPath $p
if ($item.PSIsContainer) {
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $inh = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
} else {
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $inh = [System.Security.AccessControl.InheritanceFlags]::None
}
$prop = [System.Security.AccessControl.PropagationFlags]::None
$acl.SetAccessRuleProtection($true, $false)
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$user = New-Object System.Security.Principal.NTAccount($id.Name)
$sys = New-Object System.Security.Principal.NTAccount('NT AUTHORITY\\SYSTEM')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'Modify', $inh, $prop, 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sys, 'FullControl', $inh, $prop, 'Allow')))
$item.SetAccessControl($acl)
`;

export function restrictPath(target: string): void {
  if (!existsSync(target)) return;
  if (process.platform !== "win32") {
    const st = statSync(target);
    chmodSync(target, st.isDirectory() ? 0o700 : 0o600);
    return;
  }
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ACL_RESTRICT_PS], {
    windowsHide: true,
    encoding: "utf8",
    env: { ...process.env, NMZP_ACL_PATH: target },
  });
  if (r.status !== 0) {
    throw new Error("acl_restrict_failed");
  }
}

export interface FileSnap {
  path: string;
  absent: boolean;
  text: string | null;
  sha256: string | null;
  dev: number | null;
  ino: number | null;
}

/** Bytes plus dev/ino of a regular file. A symlink is not a usable snapshot. */
export function snapshotPath(target: string): FileSnap {
  let st;
  try {
    st = lstatSync(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { path: target, absent: true, text: null, sha256: null, dev: null, ino: null };
    }
    throw error;
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new Error("unsafe_symlink");
  const text = readFileSync(target, "utf8");
  return { path: target, absent: false, text, sha256: sha256Text(text), dev: st.dev, ino: st.ino };
}

/** True when current bytes, hash, and path identity still match the snapshot. */
export function snapshotsMatch(target: string, snap: FileSnap): boolean {
  if (resolve(target) !== resolve(snap.path)) return false;
  let st;
  try {
    st = lstatSync(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return snap.absent;
    return false;
  }
  if (st.isSymbolicLink() || !st.isFile()) return false;
  if (snap.absent) return false;
  if (snap.dev !== null && snap.ino !== null && (st.dev !== snap.dev || st.ino !== snap.ino)) return false;
  const text = readFileSync(target, "utf8");
  return sha256Text(text) === snap.sha256 && text === snap.text;
}

export interface RollbackReport {
  ok: boolean;
  restored: string[];
  removed: string[];
  preservedExternal: string[];
  failed: Array<{ path: string; error: string }>;
}

type Tracked = {
  path: string;
  kind: "file" | "dir" | "tree";
  prior: string | null;
  expected: string | null;
};

export class FileRollback {
  private items: Tracked[] = [];

  constructor(backupDir: string) {
    mkdirSync(backupDir, { recursive: true });
    restrictPath(backupDir);
  }

  /** Register a file that was absent. `expected` is the body this join will write. */
  noteCreated(path: string, expected: string): void {
    this.items.push({ path, kind: "file", prior: null, expected });
  }

  /** Register an empty directory this join created. Not removed when it still holds other entries. */
  noteCreatedDir(path: string): void {
    this.items.push({ path, kind: "dir", prior: null, expected: null });
  }

  /** Register a directory tree this join created, removed as a tree only if it is still a real directory. */
  noteCreatedTree(path: string): void {
    this.items.push({ path, kind: "tree", prior: null, expected: null });
  }

  /** Register a file this join will replace. Restoration runs only while the bytes are still `expected`. */
  notePrior(path: string, prior: string, expected: string): void {
    this.items.push({ path, kind: "file", prior, expected });
  }

  noteMissingParents(target: string): void {
    const missing: string[] = [];
    let cur = dirname(target);
    while (true) {
      try {
        const st = lstatSync(cur);
        if (st.isSymbolicLink()) throw new Error("unsafe_symlink");
        break;
      } catch (error) {
        if (error instanceof Error && error.message === "unsafe_symlink") throw error;
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        missing.push(cur);
        const parent = dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }
    }
    for (const dir of missing.reverse()) this.noteCreatedDir(dir);
    if (missing.length) mkdirSync(dirname(target), { recursive: true });
  }

  rollback(): RollbackReport {
    const restored: string[] = [];
    const removed: string[] = [];
    const preservedExternal: string[] = [];
    const failed: Array<{ path: string; error: string }> = [];
    const fail = (path: string, error: unknown) => {
      failed.push({ path, error: error instanceof Error ? error.message : "rollback_failed" });
    };
    for (const item of [...this.items].reverse()) {
      try {
        if (item.kind === "dir") {
          this.rollbackDir(item.path, false, removed, preservedExternal);
          continue;
        }
        if (item.kind === "tree") {
          this.rollbackDir(item.path, true, removed, preservedExternal);
          continue;
        }
        const current = this.readRegular(item.path);
        if (current.kind === "other") {
          preservedExternal.push(item.path);
          continue;
        }
        const expectedHash = item.expected === null ? null : sha256Text(item.expected);
        if (item.prior === null) {
          if (current.kind === "absent") continue;
          if (expectedHash !== null && sha256Text(current.text) !== expectedHash) {
            preservedExternal.push(item.path);
            continue;
          }
          rmSync(item.path, { force: true });
          removed.push(item.path);
          continue;
        }
        if (current.kind === "absent") {
          preservedExternal.push(item.path);
          continue;
        }
        if (expectedHash !== null && sha256Text(current.text) !== expectedHash) {
          preservedExternal.push(item.path);
          continue;
        }
        if (current.text === item.prior) continue;
        atomicWriteFile(item.path, item.prior, 0o600);
        restored.push(item.path);
      } catch (error) {
        fail(item.path, error);
      }
    }
    return { ok: failed.length === 0, restored, removed, preservedExternal, failed };
  }

  private readRegular(path: string): { kind: "absent" } | { kind: "other" } | { kind: "file"; text: string } {
    try {
      const st = lstatSync(path);
      if (st.isSymbolicLink() || !st.isFile()) return { kind: "other" };
      return { kind: "file", text: readFileSync(path, "utf8") };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { kind: "absent" };
      throw error;
    }
  }

  private rollbackDir(
    path: string,
    tree: boolean,
    removed: string[],
    preservedExternal: string[],
  ): void {
    let st;
    try {
      st = lstatSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (st.isSymbolicLink()) {
      preservedExternal.push(path);
      return;
    }
    if (!st.isDirectory()) {
      preservedExternal.push(path);
      return;
    }
    try {
      if (!tree) {
        rmdirSync(path);
      } else {
        rmSync(path, { recursive: true, force: true });
      }
      removed.push(path);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (!tree && (code === "ENOTEMPTY" || code === "EEXIST" || code === "ENOENT" || code === "ENOTDIR")) {
        preservedExternal.push(path);
        return;
      }
      throw error;
    }
  }
}

const installChains = new Map<string, Promise<void>>();

type PidState = "alive" | "dead" | "unknown";

/** Only ESRCH is dead. EPERM and every other error stay unknown. */
function pidState(pid: number): PidState {
  if (!Number.isInteger(pid) || pid <= 0) return "unknown";
  try {
    process.kill(pid, 0);
    return "alive";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH" ? "dead" : "unknown";
  }
}

type LockRecord = { pid: number; nonce: string; startedAt: number };

function parseLockRecord(raw: string): LockRecord | null {
  try {
    const rec = JSON.parse(raw) as { pid?: unknown; nonce?: unknown; startedAt?: unknown };
    if (!Number.isInteger(rec.pid) || (rec.pid as number) <= 0) return null;
    if (typeof rec.nonce !== "string" || rec.nonce.length < 16) return null;
    if (!Number.isInteger(rec.startedAt)) return null;
    return { pid: rec.pid as number, nonce: rec.nonce, startedAt: rec.startedAt as number };
  } catch {
    return null;
  }
}

/** Reject a symlink or junction on this path or an existing ancestor. A missing tail is allowed. */
function assertDirectoryAncestry(target: string): void {
  const abs = resolve(target);
  const chain: string[] = [];
  let cur = abs;
  while (true) {
    chain.push(cur);
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  for (const prefix of chain.reverse()) {
    let st;
    try {
      st = lstatSync(prefix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (st.isSymbolicLink()) throw new Error("unsafe_symlink");
  }
}

/**
 * Serializes NMZP join/leave for one home. This lock does not coordinate other programs.
 * A lock is removed only when its dev/ino and owner nonce still match the file we judged.
 * An uncertain owner is not treated as dead.
 */
export async function withCooperatingInstallLock<T>(
  home: string,
  fn: () => Promise<T>,
  timeoutMs = 20_000,
): Promise<T> {
  const key = resolve(home);
  const dir = join(key, ".nmzp");
  const lockPath = join(dir, "install.lock");
  assertDirectoryAncestry(dir);
  assertDirectoryAncestry(lockPath);
  mkdirSync(dir, { recursive: true });
  const prev = installChains.get(key) ?? Promise.resolve();
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolveGate) => {
    release = resolveGate;
  });
  installChains.set(key, gate);
  await prev;
  const started = Date.now();
  const nonce = randomBytes(16).toString("hex");
  let fd: number | undefined;
  let owned: { dev: number; ino: number } | undefined;
  try {
    while (fd === undefined) {
      try {
        assertDirectoryAncestry(lockPath);
        fd = openSync(lockPath, "wx", 0o600);
        const held = fstatSync(fd);
        owned = { dev: held.dev, ino: held.ino };
      } catch (error) {
        if (error instanceof Error && error.message === "unsafe_symlink") throw error;
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (Date.now() - started > timeoutMs) throw new Error("install_lock_timeout");
        reclaimDeadInstallLock(lockPath);
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    const body = JSON.stringify({ pid: process.pid, nonce, startedAt: Date.now() });
    writeSync(fd, body);
    return await fn();
  } finally {
    if (fd !== undefined && owned) releaseOwnedLock(fd, lockPath, owned, nonce);
    release();
    if (installChains.get(key) === gate) installChains.delete(key);
  }
}

function releaseOwnedLock(fd: number, lockPath: string, owned: { dev: number; ino: number }, nonce: string): void {
  try {
    const still = fstatSync(fd);
    const named = lstatSync(lockPath);
    const same =
      named.isFile() &&
      !named.isSymbolicLink() &&
      still.dev === named.dev &&
      still.ino === named.ino &&
      still.dev === owned.dev &&
      still.ino === owned.ino;
    if (same) {
      const raw = readFileSync(lockPath, "utf8");
      const rec = parseLockRecord(raw);
      const ours = rec !== null && rec.nonce === nonce && rec.pid === process.pid;
      const unpublished = rec === null && raw.length === 0;
      if (ours || unpublished) unlinkSync(lockPath);
    }
  } catch {
    /* A renamed or replaced lock stays on disk. */
  }
  try {
    closeSync(fd);
  } catch {
    /* The identity check already decided whether the name is ours. */
  }
}

function reclaimDeadInstallLock(lockPath: string): void {
  let st;
  try {
    st = lstatSync(lockPath);
  } catch {
    return;
  }
  if (st.isSymbolicLink() || !st.isFile()) return;
  let raw: string;
  try {
    raw = readFileSync(lockPath, "utf8");
  } catch {
    return;
  }
  const rec = parseLockRecord(raw);
  if (!rec || pidState(rec.pid) !== "dead") return;
  let again;
  try {
    again = lstatSync(lockPath);
  } catch {
    return;
  }
  if (again.isSymbolicLink() || !again.isFile() || again.dev !== st.dev || again.ino !== st.ino) return;
  let againRaw: string;
  try {
    againRaw = readFileSync(lockPath, "utf8");
  } catch {
    return;
  }
  const againRec = parseLockRecord(againRaw);
  if (!againRec || againRec.pid !== rec.pid || againRec.nonce !== rec.nonce) return;
  try {
    unlinkSync(lockPath);
  } catch {
    /* Lost the race. The next pass reads whatever is there now. */
  }
}
