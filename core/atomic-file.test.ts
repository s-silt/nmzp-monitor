import assert from "node:assert/strict";
import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, it, type TestContext } from "node:test";
import { atomicReplaceSync, atomicWrite } from "./atomic-file.ts";
import * as atomic from "./atomic-file.ts";

const DIR_FD = 2_100_000_001;

interface Recording {
  order: string[];
  renames: number;
  unlinked: string[];
  flags: string[];
  mode: number | undefined;
}

function requireSeam(): void {
  assert.equal(typeof atomic.setAtomicFileIoForTesting, "function", "seam missing");
}

function resetSeam(): void {
  if (typeof atomic.setAtomicFileIoForTesting === "function") atomic.setAtomicFileIoForTesting(undefined);
}

function ioError(code: string): NodeJS.ErrnoException {
  const error = new Error(code) as NodeJS.ErrnoException;
  error.code = code;
  return error;
}

function writer(sync: boolean): (path: string, data: string) => Promise<void> {
  return async (path, data) => {
    if (sync) atomicReplaceSync(path, data);
    else await atomicWrite(path, data);
  };
}

function installRecording(options: {
  platform?: NodeJS.Platform;
  onDirectoryFsync?: () => void;
  onTempFsync?: () => void;
  write?: (fd: number, data: Buffer) => number;
}): Recording {
  requireSeam();
  const state: Recording = { order: [], renames: 0, unlinked: [], flags: [], mode: undefined };
  atomic.setAtomicFileIoForTesting({
    ...(options.platform ? { platform: options.platform } : {}),
    open: (path, flags, mode) => {
      state.order.push("open");
      state.flags.push(flags);
      state.mode = mode;
      return openSync(path, flags, mode);
    },
    write: (fd, data) => {
      state.order.push("write");
      return options.write ? options.write(fd, data) : writeSync(fd, data);
    },
    fsync: (fd) => {
      if (fd === DIR_FD) {
        state.order.push("dirfsync");
        options.onDirectoryFsync?.();
        return;
      }
      state.order.push("fsync");
      options.onTempFsync?.();
      fsyncSync(fd);
    },
    close: (fd) => {
      state.order.push("close");
      if (fd === DIR_FD) return;
      closeSync(fd);
    },
    rename: (from, to) => {
      state.order.push("rename");
      state.renames += 1;
      renameSync(from, to);
    },
    unlink: (path) => {
      state.order.push("unlink");
      state.unlinked.push(path);
      unlinkSync(path);
    },
    openDirectory: () => {
      state.order.push("openDirectory");
      return DIR_FD;
    },
  });
  return state;
}

async function withDir(body: (dir: string) => Promise<void>): Promise<void> {
  requireSeam();
  const dir = await mkdtemp(join(tmpdir(), "nmzp-atomic-"));
  try {
    await body(dir);
  } finally {
    resetSeam();
    await rm(dir, { recursive: true, force: true });
  }
}

function assertOutcomeUnknown(error: unknown, causeCode: string): void {
  const cause =
    error instanceof atomic.AtomicWriteOutcomeUnknownError ? error.cause : undefined;
  const code = cause && typeof cause === "object" ? (cause as { code?: unknown }).code : undefined;
  assert.equal(
    error instanceof atomic.AtomicWriteOutcomeUnknownError &&
      error.code === "atomic_write_outcome_unknown" &&
      code === causeCode,
    true,
    "atomic_write_outcome_unknown",
  );
}

async function assertTempFsyncBeforeRename(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    const state = installRecording({ platform: "win32" });
    const dest = join(dir, "state.json");
    await writer(sync)(dest, "NEW");
    const fsyncAt = state.order.indexOf("fsync");
    const renameAt = state.order.indexOf("rename");
    assert.ok(fsyncAt !== -1 && renameAt !== -1 && fsyncAt < renameAt, "temp fsync before rename");
    assert.equal(readFileSync(dest, "utf8"), "NEW");
  });
}

async function assertDirectoryFsyncAfterRename(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    const state = installRecording({ platform: "linux" });
    const dest = join(dir, "state.json");
    await writer(sync)(dest, "NEW");
    const renameAt = state.order.indexOf("rename");
    const openDirAt = state.order.indexOf("openDirectory");
    const dirFsyncAt = state.order.indexOf("dirfsync");
    const closeAt = state.order.lastIndexOf("close");
    assert.ok(
      renameAt !== -1 && openDirAt > renameAt && dirFsyncAt > openDirAt && closeAt > dirFsyncAt,
      "directory fsync after rename",
    );
    assert.equal(readFileSync(dest, "utf8"), "NEW");
  });
}

async function assertFailureBeforeRename(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    const dest = join(dir, "devices.json");
    const unrelated = `${dest}.tmp.unrelated`;
    writeFileSync(dest, "OLD");
    writeFileSync(unrelated, "KEEP");
    const state = installRecording({
      onTempFsync: () => {
        throw ioError("EIO");
      },
    });
    let thrown: unknown;
    try {
      await writer(sync)(dest, "NEW");
    } catch (error) {
      thrown = error;
    }
    assert.equal(thrown instanceof atomic.AtomicWriteOutcomeUnknownError, false, "destination untouched");
    assert.equal((thrown as { code?: string } | undefined)?.code, "EIO", "destination untouched");
    assert.equal(state.renames, 0, "destination untouched");
    assert.equal(readFileSync(dest, "utf8"), "OLD", "destination untouched");
    assert.equal(readFileSync(unrelated, "utf8"), "KEEP", "destination untouched");
    assert.equal(state.unlinked.includes(dest), false, "destination untouched");
    assert.equal(state.unlinked.includes(unrelated), false, "destination untouched");
    assert.equal(state.unlinked.length, 1, "destination untouched");
    assert.deepEqual(
      readdirSync(dir)
        .filter((name) => name.includes(".tmp."))
        .sort(),
      [basename(unrelated)],
    );
  });
}

async function assertFailureAfterRename(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    const dest = join(dir, "devices.json");
    writeFileSync(dest, "OLD");
    const state = installRecording({
      platform: "linux",
      onDirectoryFsync: () => {
        throw ioError("EIO");
      },
    });
    let thrown: unknown;
    try {
      await writer(sync)(dest, "NEW");
    } catch (error) {
      thrown = error;
    }
    assertOutcomeUnknown(thrown, "EIO");
    assert.equal(state.renames, 1, "rename once");
    assert.deepEqual(state.unlinked, [], "rename once");
    const dirAt = state.order.indexOf("dirfsync");
    assert.ok(dirAt !== -1 && state.order.lastIndexOf("close") > dirAt, "rename once");
    assert.equal(readFileSync(dest, "utf8"), "NEW");
  });
}

async function assertDirectoryCode(
  dir: string,
  sync: boolean,
  code: string,
  tolerated: boolean,
): Promise<void> {
  const dest = join(dir, `${code}.json`);
  writeFileSync(dest, "OLD");
  const state = installRecording({
    platform: "linux",
    onDirectoryFsync: () => {
      throw ioError(code);
    },
  });
  let thrown: unknown;
  try {
    await writer(sync)(dest, "NEW");
  } catch (error) {
    thrown = error;
  }
  if (tolerated) {
    assert.equal(thrown, undefined, `${code} directory fsync still publishes`);
    assert.equal(readFileSync(dest, "utf8"), "NEW", `${code} directory fsync still publishes`);
  } else {
    assertOutcomeUnknown(thrown, code);
    assert.equal(readFileSync(dest, "utf8"), "NEW");
  }
  assert.equal(state.renames, 1, "rename once");
}

async function assertUnsupportedDirectoryFsync(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    await assertDirectoryCode(dir, sync, "EINVAL", true);
    await assertDirectoryCode(dir, sync, "ENOTSUP", true);
    await assertDirectoryCode(dir, sync, "EACCES", false);
  });
}

async function assertExclusiveCreate(sync: boolean): Promise<void> {
  await withDir(async (dir) => {
    const state = installRecording({ platform: "win32" });
    const dest = join(dir, "state.json");
    await writer(sync)(dest, "payload");
    assert.deepEqual(state.flags, ["wx"], "exclusive create");
    assert.equal(state.mode, 0o600, "exclusive create");
    assert.equal(readFileSync(dest, "utf8"), "payload");
  });
}

async function assertSymlinkReplaced(
  t: TestContext,
  dir: string,
  sync: boolean,
  name: string,
): Promise<void> {
  const target = join(dir, `${name}-target.json`);
  const link = join(dir, `${name}-link.json`);
  writeFileSync(target, "TARGET");
  try {
    symlinkSync(target, link, "file");
  } catch (error) {
    const code = (error as { code?: string }).code ?? "unknown";
    t.skip(`symlinks cannot be created (${code})`);
    return;
  }
  assert.equal(lstatSync(link).isSymbolicLink(), true);
  await writer(sync)(link, "NEW");
  assert.equal(readFileSync(target, "utf8"), "TARGET");
  assert.equal(lstatSync(link).isSymbolicLink(), false);
  assert.equal(readFileSync(link, "utf8"), "NEW");
}

describe("atomic file durability", { concurrency: false }, () => {
  afterEach(() => {
    resetSeam();
  });

  it("atomic write syncs the temp file before rename", async () => {
    await assertTempFsyncBeforeRename(false);
  });

  it("posix directory sync follows rename", async () => {
    await assertDirectoryFsyncAfterRename(false);
  });

  it("failure before rename leaves the destination untouched and removes only our temp", async () => {
    await assertFailureBeforeRename(false);
  });

  it("failure after rename reports outcome unknown and is not retried", async () => {
    await assertFailureAfterRename(false);
  });

  it("unsupported directory fsync is tolerated only for EINVAL/ENOTSUP", async () => {
    await assertUnsupportedDirectoryFsync(false);
  });

  it("temp creation is exclusive", async () => {
    await assertExclusiveCreate(false);
  });

  it("sync variant has the same ordering and failure semantics", async () => {
    await assertTempFsyncBeforeRename(true);
    await assertDirectoryFsyncAfterRename(true);
    await assertFailureBeforeRename(true);
    await assertFailureAfterRename(true);
    await assertUnsupportedDirectoryFsync(true);
    await assertExclusiveCreate(true);
    await withDir(async (dir) => {
      const dest = join(dir, "short.json");
      installRecording({
        platform: "win32",
        write: (fd, data) => writeSync(fd, data.subarray(0, 1)),
      });
      atomicReplaceSync(dest, "ABCDEFGH");
      assert.equal(readFileSync(dest, "utf8"), "ABCDEFGH", "short write is completed");
    });
  });

  it("rename replaces a symlinked destination without modifying its target", async (t) => {
    await withDir(async (dir) => {
      await assertSymlinkReplaced(t, dir, false, "async");
      await assertSymlinkReplaced(t, dir, true, "sync");
    });
  });
});
