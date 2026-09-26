import { closeSync, fsyncSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

/** Rename finished, but durability of that directory entry is unknown. Do not retry. */
export class AtomicWriteOutcomeUnknownError extends Error {
  readonly code = "atomic_write_outcome_unknown" as const;

  constructor(cause: unknown) {
    super("atomic_write_outcome_unknown", { cause });
    this.name = "AtomicWriteOutcomeUnknownError";
  }
}

/** Filesystem calls used by atomic writes. `platform` is the test override for directory sync. */
export interface AtomicFileIo {
  open: (path: string, flags: string, mode: number) => number;
  write: (fd: number, data: Buffer) => number;
  fsync: (fd: number) => void;
  close: (fd: number) => void;
  rename: (from: string, to: string) => void;
  unlink: (path: string) => void;
  openDirectory: (path: string) => number;
  platform: NodeJS.Platform;
}

const defaultIo: AtomicFileIo = {
  open: (path, flags, mode) => openSync(path, flags, mode),
  write: (fd, data) => writeSync(fd, data),
  fsync: (fd) => {
    fsyncSync(fd);
  },
  close: (fd) => {
    closeSync(fd);
  },
  rename: (from, to) => {
    renameSync(from, to);
  },
  unlink: (path) => {
    unlinkSync(path);
  },
  openDirectory: (path) => openSync(path, "r"),
  platform: process.platform,
};

let ioOverride: Partial<AtomicFileIo> | undefined;

/** Test-only. Production code never calls this. Pass no argument to restore node:fs. */
export function setAtomicFileIoForTesting(io?: Partial<AtomicFileIo>): void {
  ioOverride = io;
}

function io(): AtomicFileIo {
  const over = ioOverride;
  if (!over) return defaultIo;
  return {
    open: over.open ?? defaultIo.open,
    write: over.write ?? defaultIo.write,
    fsync: over.fsync ?? defaultIo.fsync,
    close: over.close ?? defaultIo.close,
    rename: over.rename ?? defaultIo.rename,
    unlink: over.unlink ?? defaultIo.unlink,
    openDirectory: over.openDirectory ?? defaultIo.openDirectory,
    platform: over.platform ?? process.platform,
  };
}

function directorySyncUnsupported(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = (error as { code?: unknown }).code;
  return code === "EINVAL" || code === "ENOTSUP";
}

function discardOwnTemp(fileIo: AtomicFileIo, temporary: string): void {
  try {
    fileIo.unlink(temporary);
  } catch {
    // Only the temp we created. Never unlink the destination.
  }
}

function writeAll(fileIo: AtomicFileIo, fd: number, data: Buffer): void {
  let offset = 0;
  while (offset < data.length) {
    const wrote = fileIo.write(fd, data.subarray(offset));
    if (!Number.isSafeInteger(wrote) || wrote < 1 || offset + wrote > data.length) {
      throw new Error("atomic_write_failed");
    }
    offset += wrote;
  }
}

function syncDirectory(fileIo: AtomicFileIo, filePath: string): void {
  // win32: skipping directory fsync is a platform limitation, not a successful sync.
  if (fileIo.platform === "win32") return;
  const directory = dirname(filePath);
  let dirFd: number;
  try {
    dirFd = fileIo.openDirectory(directory);
  } catch (error) {
    throw new AtomicWriteOutcomeUnknownError(error);
  }
  let syncError: unknown;
  try {
    fileIo.fsync(dirFd);
  } catch (error) {
    if (!directorySyncUnsupported(error)) syncError = error;
  }
  let closeError: unknown;
  try {
    fileIo.close(dirFd);
  } catch (error) {
    closeError = error;
  }
  // The rename is already visible. Do not retry and do not remove the destination.
  if (syncError !== undefined) throw new AtomicWriteOutcomeUnknownError(syncError);
  if (closeError !== undefined) throw new AtomicWriteOutcomeUnknownError(closeError);
}

function replaceAtomically(path: string, data: string, mode: number): void {
  const fileIo = io();
  const temporary = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  let fd: number | undefined;
  let opened = false;
  try {
    fd = fileIo.open(temporary, "wx", mode);
    opened = true;
    writeAll(fileIo, fd, Buffer.from(data, "utf8"));
    fileIo.fsync(fd);
    fileIo.close(fd);
    fd = undefined;
  } catch (error) {
    // Close before unlinking. Windows cannot remove an open file.
    if (fd !== undefined) {
      try {
        fileIo.close(fd);
      } catch {
        // Keep the original error. The destination is unchanged.
      }
    }
    if (opened) discardOwnTemp(fileIo, temporary);
    throw error;
  }
  try {
    fileIo.rename(temporary, path);
  } catch (error) {
    discardOwnTemp(fileIo, temporary);
    throw error;
  }
  syncDirectory(fileIo, path);
}

export async function atomicWrite(path: string, data: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  replaceAtomically(path, data, mode);
}

export function atomicReplaceSync(path: string, data: string, mode = 0o600): void {
  replaceAtomically(path, data, mode);
}
