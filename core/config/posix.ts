import { lstatSync, type Stats } from "node:fs";
import { constants, open, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";

const REPARSE_POINT = 0x400;

export function isReparseOrSymlink(st: Stats): boolean {
  if (st.isSymbolicLink()) return true;
  const attrs = (st as Stats & { attributes?: number }).attributes;
  return typeof attrs === "number" && (attrs & REPARSE_POINT) !== 0;
}

/**
 * Symlink / reparse ancestry of an absolute path. Missing components are skipped.
 * POSIX: a non-final symlink is trusted only when the link itself is root-owned,
 * its parent directory is root-owned, and that parent is not group- or other-writable.
 * The final path component is never allowed to be a symlink. Windows rejects every
 * symlink and reparse point.
 */
export function pathHasSymlinkAncestry(
  target: string,
  lstat: (path: string) => Stats = lstatSync,
): { ok: true; found: boolean } | { ok: false; reason: string } {
  if (!isAbsolute(target)) return { ok: true, found: false };
  const abs = resolve(target);
  let cur = abs;
  let leaf = true;
  const seen = new Set<string>();
  while (!seen.has(cur)) {
    seen.add(cur);
    try {
      const st = lstat(cur);
      if (isReparseOrSymlink(st) && (leaf || !trustedRootSymlink(cur, st, lstat))) {
        return { ok: true, found: true };
      }
    } catch (error) {
      const code = errno(error);
      if (code !== "ENOENT") return { ok: false, reason: `cannot stat ${cur}: ${code ?? "error"}` };
    }
    leaf = false;
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return { ok: true, found: false };
}

function trustedRootSymlink(path: string, st: Stats, lstat: (path: string) => Stats): boolean {
  if (process.platform === "win32") return false;
  if (st.uid !== 0) return false;
  let parent: Stats;
  try {
    parent = lstat(dirname(path));
  } catch (error) {
    const code = errno(error);
    if (code === "ENOENT") return false;
    throw error;
  }
  if (isReparseOrSymlink(parent) || !parent.isDirectory()) return false;
  if (parent.uid !== 0) return false;
  return (parent.mode & 0o022) === 0;
}

const SENSITIVE_RELATIVE = [
  "admin.token",
  "policy.json",
  "meta.json",
  "nmzp.db",
  "nmzp.db-wal",
  "nmzp.db-shm",
  join("tls", "server.key"),
] as const;

export interface TightenHooks {
  lstat?: (path: string) => Stats;
  open?: (path: string, flags: number) => Promise<FileHandle>;
  getuid?: () => number | undefined;
  /** Runs after child checks, while the data-directory handle is still open. */
  beforeFinalDataDirCheck?: () => void | Promise<void>;
}

function errno(error: unknown): string | undefined {
  const code = (error as NodeJS.ErrnoException).code;
  return typeof code === "string" ? code : undefined;
}

function openFlags(kind: "file" | "dir"): number | null {
  if (typeof constants.O_NOFOLLOW !== "number") return null;
  if (kind === "dir") {
    if (typeof constants.O_DIRECTORY !== "number") return null;
    return constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  }
  return constants.O_RDONLY | constants.O_NOFOLLOW;
}

/** Permission bits outside `want` (0400/0500 are stricter and therefore fine). */
function widerThan(mode: number, want: number): boolean {
  return (mode & ~want & 0o777) !== 0;
}

type Step = { ok: true } | { ok: false; reason: string };

async function chmodIfWider(
  handle: FileHandle,
  pinned: { dev: number; ino: number },
  path: string,
  want: number,
  uid: number | undefined,
): Promise<Step> {
  let opened;
  try {
    opened = await handle.stat();
  } catch (error) {
    return { ok: false, reason: `cannot stat ${path}: ${errno(error) ?? "error"}` };
  }
  if (opened.dev !== pinned.dev || opened.ino !== pinned.ino) {
    return { ok: false, reason: `inode changed at ${path}` };
  }
  if (widerThan(opened.mode, want)) {
    try {
      await handle.chmod(want);
    } catch (error) {
      const who = typeof uid === "number" ? String(uid) : "unknown";
      return { ok: false, reason: `cannot chmod ${path}: ${errno(error) ?? "error"} (uid ${who})` };
    }
  }
  let after;
  try {
    after = await handle.stat();
  } catch (error) {
    return { ok: false, reason: `cannot stat ${path}: ${errno(error) ?? "error"}` };
  }
  if (after.dev !== pinned.dev || after.ino !== pinned.ino) {
    return { ok: false, reason: `inode changed at ${path}` };
  }
  if (widerThan(after.mode, want)) return { ok: false, reason: `${path} mode still too wide` };
  return { ok: true };
}

interface Fs {
  lstat: (path: string) => Stats;
  open: (path: string, flags: number) => Promise<FileHandle>;
}

async function openChecked(fs: Fs, path: string, kind: "file" | "dir", pinned: Stats): Promise<
  { ok: true; handle: FileHandle } | { ok: false; reason: string }
> {
  const flags = openFlags(kind);
  if (flags === null) return { ok: false, reason: "O_NOFOLLOW unavailable" };
  let handle: FileHandle;
  try {
    handle = await fs.open(path, flags);
  } catch (error) {
    const code = errno(error);
    if (code === "ELOOP") return { ok: false, reason: `${path} is a symlink` };
    return { ok: false, reason: `cannot open ${path}: ${code ?? "error"}` };
  }
  try {
    const opened = await handle.stat();
    if (opened.dev !== pinned.dev || opened.ino !== pinned.ino) {
      await handle.close();
      return { ok: false, reason: `inode changed at ${path}` };
    }
    return { ok: true, handle };
  } catch (error) {
    await handle.close();
    return { ok: false, reason: `cannot stat ${path}: ${errno(error) ?? "error"}` };
  }
}

/** lstat each component, refuse a symlink, then O_NOFOLLOW open and compare dev/ino. */
async function tightenRelative(fs: Fs, dataDir: string, rel: string, uid: number | undefined): Promise<Step> {
  const parts = rel.split(/[\\/]/).filter(Boolean);
  let acc = dataDir;
  for (let i = 0; i < parts.length; i += 1) {
    acc = join(acc, parts[i] ?? "");
    const last = i === parts.length - 1;
    const kind: "file" | "dir" = last ? "file" : "dir";
    let st: Stats;
    try {
      st = fs.lstat(acc);
    } catch (error) {
      const code = errno(error);
      if (code === "ENOENT") return { ok: true };
      return { ok: false, reason: `cannot stat ${acc}: ${code ?? "error"}` };
    }
    if (isReparseOrSymlink(st)) return { ok: false, reason: `${acc} is a symlink` };
    if (kind === "dir" && !st.isDirectory()) return { ok: false, reason: `${acc} is not a directory` };
    if (kind === "file" && !st.isFile()) return { ok: false, reason: `${acc} is not a file` };
    const opened = await openChecked(fs, acc, kind, st);
    if (!opened.ok) return opened;
    try {
      if (kind === "file") {
        const tightened = await chmodIfWider(opened.handle, st, acc, 0o600, uid);
        if (!tightened.ok) return tightened;
      }
    } finally {
      await opened.handle.close();
    }
  }
  return { ok: true };
}

/**
 * POSIX-only. When the data directory already exists, keep a directory fd open
 * for the whole tighten/recheck, then lstat the path again and compare dev/ino.
 * Windows callers skip (WP-60).
 */
export async function tightenExistingDataDir(dataDir: string, hooks: TightenHooks = {}): Promise<Step> {
  if (process.platform === "win32") return { ok: true };
  const fs: Fs = {
    lstat: hooks.lstat ?? lstatSync,
    open: hooks.open ?? open,
  };
  const uid = (hooks.getuid ?? (() => process.getuid?.()))();
  let st: Stats;
  try {
    st = fs.lstat(dataDir);
  } catch (error) {
    const code = errno(error);
    if (code === "ENOENT") return { ok: true };
    return { ok: false, reason: `cannot stat ${dataDir}: ${code ?? "error"}` };
  }
  if (isReparseOrSymlink(st)) return { ok: false, reason: `${dataDir} is a symlink` };
  if (!st.isDirectory()) return { ok: false, reason: `${dataDir} is not a directory` };
  const opened = await openChecked(fs, dataDir, "dir", st);
  if (!opened.ok) return opened;
  try {
    const dirMode = await chmodIfWider(opened.handle, st, dataDir, 0o700, uid);
    if (!dirMode.ok) return dirMode;
    for (const rel of SENSITIVE_RELATIVE) {
      const step = await tightenRelative(fs, dataDir, rel, uid);
      if (!step.ok) return step;
    }
    await hooks.beforeFinalDataDirCheck?.();
    let again: Stats;
    try {
      again = fs.lstat(dataDir);
    } catch (error) {
      return { ok: false, reason: `cannot stat ${dataDir}: ${errno(error) ?? "error"}` };
    }
    const held = await opened.handle.stat();
    if (held.dev !== again.dev || held.ino !== again.ino) {
      return { ok: false, reason: `data directory inode changed at ${dataDir}` };
    }
    return { ok: true };
  } finally {
    await opened.handle.close();
  }
}

export { SENSITIVE_RELATIVE };
