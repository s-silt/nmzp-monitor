import { existsSync, lstatSync, type Stats } from "node:fs";
import { constants, open } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";

const REPARSE_POINT = 0x400;

export function isReparseOrSymlink(st: Stats): boolean {
  if (st.isSymbolicLink()) return true;
  const attrs = (st as Stats & { attributes?: number }).attributes;
  return typeof attrs === "number" && (attrs & REPARSE_POINT) !== 0;
}

/**
 * True when `target` or any existing ancestor is a symlink / reparse point.
 * Missing components are skipped so a not-yet-created data dir can still be checked.
 */
export function pathHasSymlinkAncestry(target: string): { ok: true; found: boolean } | { ok: false; reason: string } {
  if (!isAbsolute(target)) return { ok: true, found: false };
  const abs = resolve(target);
  let cur = abs;
  const seen = new Set<string>();
  while (!seen.has(cur)) {
    seen.add(cur);
    try {
      const st = lstatSync(cur);
      if (isReparseOrSymlink(st)) return { ok: true, found: true };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") return { ok: false, reason: `cannot stat ${cur}: ${code ?? "error"}` };
    }
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return { ok: true, found: false };
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

function posixFlags(kind: "file" | "dir"): number {
  const nofollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  if (kind === "dir") {
    const directory = typeof constants.O_DIRECTORY === "number" ? constants.O_DIRECTORY : 0;
    return constants.O_RDONLY | directory | nofollow;
  }
  return constants.O_RDONLY | nofollow;
}

function tooWide(mode: number, kind: "file" | "dir"): boolean {
  if (kind === "dir") return (mode & 0o077) !== 0;
  return (mode & 0o077) !== 0;
}

async function tightenOwned(path: string, kind: "file" | "dir", want: number): Promise<{ ok: true } | { ok: false; reason: string }> {
  let st;
  try {
    st = lstatSync(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { ok: true };
    return { ok: false, reason: `cannot stat ${path}: ${code ?? "error"}` };
  }
  if (isReparseOrSymlink(st)) return { ok: false, reason: `${path} is a symlink` };
  if (kind === "dir" && !st.isDirectory()) return { ok: false, reason: `${path} is not a directory` };
  if (kind === "file" && !st.isFile()) return { ok: false, reason: `${path} is not a file` };
  const uid = process.getuid?.();
  if (typeof uid !== "number") return { ok: false, reason: `cannot stat ${path}: no uid` };
  let handle;
  try {
    handle = await open(path, posixFlags(kind));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return { ok: false, reason: `cannot open ${path}: ${code ?? "error"}` };
  }
  try {
    const opened = await handle.stat();
    if (opened.dev !== st.dev || opened.ino !== st.ino) return { ok: false, reason: `inode changed at ${path}` };
    if (opened.uid === uid && (opened.mode & 0o777) !== want) {
      try {
        await handle.chmod(want);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        return { ok: false, reason: `cannot chmod ${path}: ${code ?? "error"}` };
      }
    }
    const after = await handle.stat();
    if (after.dev !== st.dev || after.ino !== st.ino) return { ok: false, reason: `inode changed at ${path}` };
    if (tooWide(after.mode, kind)) return { ok: false, reason: `${path} mode still too wide` };
    return { ok: true };
  } finally {
    await handle.close();
  }
}

/**
 * POSIX-only. When the data directory already exists, tighten it to 0700 and
 * sensitive files to 0600 via handle.chmod, then re-check. Windows callers skip.
 */
export async function tightenExistingDataDir(
  dataDir: string,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (process.platform === "win32") return { ok: true };
  if (!existsSync(dataDir)) return { ok: true };
  const dir = await tightenOwned(dataDir, "dir", 0o700);
  if (!dir.ok) return dir;
  for (const rel of SENSITIVE_RELATIVE) {
    const result = await tightenOwned(join(dataDir, rel), "file", 0o600);
    if (!result.ok) return result;
  }
  return { ok: true };
}

export { SENSITIVE_RELATIVE };
