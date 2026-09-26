import { randomUUID } from "node:crypto";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { mkdir } from "node:fs/promises";
import { hostname as osHostname } from "node:os";
import { join } from "node:path";

const MAX_LOCK_BYTES = 4096;
const MANUAL =
  "unverifiable — remove manually after confirming no nmzp hook is running";

export type FileLockProbe = {
  bootId(): string | null;
  startTime(pid: number): string | null;
  alive(pid: number): "alive" | "dead" | "unknown";
  hostname(): string;
};

type ReclaimReason = "dead" | "reboot" | "pid_reused";

type ParsedLock = {
  formatVersion: 2;
  pid: number;
  hostname: string;
  bootId: string | null;
  startTime: string | null;
  nonce: string;
};

type FileIdentity = { dev: number; ino: number };

type Inspection = FileIdentity & { parsed: ParsedLock; reason: ReclaimReason };

type Reclaimed = { archive: string; pid: number; reason: ReclaimReason };

/**
 * Cross-process lock held for the full callback. Never removes a replacement lock.
 *
 * A new lock is formatVersion 2 with pid, hostname, bootId, startTime, and nonce.
 * On EEXIST, reclaim one regular file of at most 4096 bytes when this host proves the
 * owner is dead: the Linux boot id changed, the pid is ESRCH, or the pid was reused and
 * its start time differs. Reclaim holds `<path>.recover` and renames the residue to
 * `<path>.stale-<ms>-<uuid>`; the archive is never unlinked. The same residue identity
 * is inspected at most once per call. Legacy, malformed, symlink, foreign-host, live,
 * and a held recover guard keep the existing lock_timeout wait. `opts.probe` is a test seam.
 */
export async function withFileLock<T>(
  dir: string,
  fn: () => Promise<T>,
  opts?: { timeoutMs?: number; probe?: FileLockProbe },
): Promise<T> {
  await mkdir(dir, { recursive: true });
  const lockPath = join(dir, ".lock");
  const timeoutMs = opts?.timeoutMs ?? 12_000;
  const start = Date.now();
  const probe = opts?.probe ?? realProbe;
  let checked: FileIdentity | null = null;
  while (true) {
    let fd: number;
    try {
      fd = openSync(lockPath, "wx");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (Date.now() - start > timeoutMs) throw new Error("lock_timeout");
      const current = safeStat(lockPath);
      if (current && !sameIdentity(checked, current)) {
        checked = { dev: current.dev, ino: current.ino };
        if (isRegular(current)) {
          const outcome = reclaimResidue(lockPath, probe, start, timeoutMs);
          if (outcome === "deadline") throw new Error("lock_timeout");
          if (outcome) {
            try {
              process.stderr.write(
                `nmzp_lock_reclaimed ${outcome.archive} pid=${outcome.pid} reason=${outcome.reason}\n`,
              );
            } catch {
              // The residue is already archived. Logging must not strand acquisition.
            }
            continue;
          }
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 15 + Math.random() * 40));
      continue;
    }
    try {
      const body = Buffer.from(JSON.stringify(lockBody(probe)));
      let offset = 0;
      while (offset < body.length) offset += writeSync(fd, body, offset);
      return await fn();
    } finally {
      try {
        const held = fstatSync(fd);
        const named = lstatSync(lockPath);
        if (named.isFile() && !named.isSymbolicLink() && held.dev === named.dev && held.ino === named.ino) {
          unlinkSync(lockPath);
        }
      } catch {
        /* Never unlink a replacement lock. */
      }
      closeSync(fd);
    }
  }
}

/** Read-only description of `~/.nmzp/.lock`. Does not rename or remove it. */
export function deviceLockStatusLine(lockPath: string): string | null {
  const parsed = readParsed(lockPath);
  if (parsed === "absent") return null;
  const described = describe(parsed, realProbe);
  const owner = described.pid === null ? "unknown" : String(described.pid);
  const state = described.state === "unverifiable" ? MANUAL : described.state;
  return `lock: present (owner pid ${owner}, ${state})`;
}

const realProbe: FileLockProbe = {
  bootId: readBootId,
  startTime: readStartTime,
  alive: readAlive,
  hostname: osHostname,
};

function lockBody(probe: FileLockProbe): ParsedLock {
  return {
    formatVersion: 2,
    pid: process.pid,
    hostname: probe.hostname(),
    bootId: probe.bootId(),
    startTime: probe.startTime(process.pid),
    nonce: randomUUID(),
  };
}

function reclaimResidue(
  lockPath: string,
  probe: FileLockProbe,
  start: number,
  timeoutMs: number,
): Reclaimed | null | "deadline" {
  const past = () => Date.now() - start > timeoutMs;
  if (past()) return "deadline";
  const first = inspect(lockPath, probe);
  if (!first) return null;
  if (past()) return "deadline";
  const guardPath = `${lockPath}.recover`;
  let guardFd: number;
  try {
    guardFd = openSync(guardPath, "wx");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "EISDIR") return null;
    throw error;
  }
  let guardIdentity: FileIdentity | null = null;
  try {
    try {
      const guardStat = fstatSync(guardFd);
      guardIdentity = { dev: guardStat.dev, ino: guardStat.ino };
    } catch {
      return null;
    }
    if (past()) return "deadline";
    const again = inspect(lockPath, probe);
    if (!again || again.dev !== first.dev || again.ino !== first.ino) return null;
    let current;
    try {
      current = lstatSync(lockPath);
    } catch {
      return null;
    }
    if (!isRegular(current) || current.dev !== again.dev || current.ino !== again.ino) return null;
    const archive = `${lockPath}.stale-${Date.now()}-${randomUUID()}`;
    try {
      renameSync(lockPath, archive);
    } catch {
      return null;
    }
    let archived;
    try {
      archived = lstatSync(archive);
    } catch {
      return null;
    }
    if (!isRegular(archived) || archived.dev !== again.dev || archived.ino !== again.ino) return null;
    return { archive, pid: again.parsed.pid, reason: again.reason };
  } finally {
    try {
      closeSync(guardFd);
    } catch {
      // Closing the guard must not hide the reclaim result.
    }
    if (guardIdentity) {
      try {
        const now = lstatSync(guardPath);
        if (isRegular(now) && now.dev === guardIdentity.dev && now.ino === guardIdentity.ino) {
          unlinkSync(guardPath);
        }
      } catch {
        // A missing or replaced guard stays for manual review.
      }
    }
  }
}

function inspect(lockPath: string, probe: FileLockProbe): Inspection | null {
  const read = readStable(lockPath);
  if (read === "absent" || read === null || read.parsed === null) return null;
  const reason = reclaimDecision(read.parsed, probe);
  if (!reason) return null;
  return { dev: read.dev, ino: read.ino, parsed: read.parsed, reason };
}

function readParsed(lockPath: string): ParsedLock | null | "absent" {
  const read = readStable(lockPath);
  if (read === "absent") return "absent";
  if (read === null) return null;
  return read.parsed;
}

function readStable(
  lockPath: string,
): { dev: number; ino: number; parsed: ParsedLock | null } | "absent" | null {
  let before;
  try {
    before = lstatSync(lockPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    return null;
  }
  if (!isRegular(before) || before.size > MAX_LOCK_BYTES) return { dev: before.dev, ino: before.ino, parsed: null };
  const raw = readSameFile(lockPath, before);
  if (!raw) return null;
  let after;
  try {
    after = lstatSync(lockPath);
  } catch {
    return null;
  }
  if (
    !isRegular(after) ||
    after.dev !== before.dev ||
    after.ino !== before.ino ||
    after.size !== raw.length ||
    after.size > MAX_LOCK_BYTES
  ) {
    return null;
  }
  return { dev: after.dev, ino: after.ino, parsed: parseLock(raw.toString("utf8")) };
}

function readSameFile(lockPath: string, expected: FileIdentity & { size: number }): Buffer | null {
  let fd: number;
  try {
    fd = openSync(lockPath, "r");
  } catch {
    return null;
  }
  try {
    const stat = fstatSync(fd);
    if (!isRegular(stat) || stat.dev !== expected.dev || stat.ino !== expected.ino || stat.size > MAX_LOCK_BYTES) {
      return null;
    }
    const buf = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buf.length) {
      const n = readSync(fd, buf, offset, buf.length - offset, offset);
      if (n === 0) return null;
      offset += n;
    }
    const after = fstatSync(fd);
    if (after.dev !== expected.dev || after.ino !== expected.ino || after.size !== buf.length) return null;
    return buf;
  } catch {
    return null;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // The bytes are already copied. Closing must not hide them.
    }
  }
}

function describe(
  parsed: ParsedLock | null,
  probe: FileLockProbe,
): { pid: number | null; state: "reclaimable" | "held" | "unverifiable" } {
  if (!parsed) return { pid: null, state: "unverifiable" };
  if (reclaimDecision(parsed, probe)) return { pid: parsed.pid, state: "reclaimable" };
  if (parsed.hostname === probe.hostname() && probe.alive(parsed.pid) === "alive") {
    return { pid: parsed.pid, state: "held" };
  }
  return { pid: parsed.pid, state: "unverifiable" };
}

function reclaimDecision(parsed: ParsedLock, probe: FileLockProbe): ReclaimReason | null {
  if (parsed.hostname !== probe.hostname()) return null;
  if (parsed.pid === process.pid) return null;
  return reclaimReason(parsed, probe);
}

function reclaimReason(parsed: ParsedLock, probe: FileLockProbe): ReclaimReason | null {
  const bootId = probe.bootId();
  if (parsed.bootId !== null && bootId !== null && parsed.bootId !== bootId) return "reboot";
  const life = probe.alive(parsed.pid);
  if (life === "dead") return "dead";
  if (life !== "alive") return null;
  if (parsed.startTime === null) return null;
  const startTime = probe.startTime(parsed.pid);
  if (startTime === null || startTime === parsed.startTime) return null;
  return "pid_reused";
}

function parseLock(text: string): ParsedLock | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const pid = row.pid;
  const host = row.hostname;
  const bootId = row.bootId;
  const startTime = row.startTime;
  const nonce = row.nonce;
  if (row.formatVersion !== 2) return null;
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0) return null;
  if (typeof host !== "string") return null;
  if (!nullableText(bootId) || !nullableText(startTime)) return null;
  if (typeof nonce !== "string" || nonce.length === 0) return null;
  return { formatVersion: 2, pid, hostname: host, bootId, startTime, nonce };
}

function nullableText(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && value.length > 0);
}

function sameIdentity(checked: FileIdentity | null, stat: FileIdentity): boolean {
  return checked !== null && checked.dev === stat.dev && checked.ino === stat.ino;
}

function isRegular(stat: { isFile(): boolean; isSymbolicLink(): boolean }): boolean {
  return stat.isFile() && !stat.isSymbolicLink();
}

function safeStat(lockPath: string) {
  try {
    return lstatSync(lockPath);
  } catch {
    return null;
  }
}

function readBootId(): string | null {
  if (process.platform !== "linux") return null;
  try {
    const text = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

function readStartTime(pid: number): string | null {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const text = readFileSync(`/proc/${pid}/stat`, "utf8");
    const end = text.lastIndexOf(")");
    if (end < 0) return null;
    // starttime is field 22. pid and comm precede the final ')', so index 19 follows it.
    const fields = text.slice(end + 1).trim().split(/\s+/);
    const start = fields[19];
    return fields.length >= 20 && start !== undefined && /^\d+$/.test(start) ? start : null;
  } catch {
    return null;
  }
}

function readAlive(pid: number): "alive" | "dead" | "unknown" {
  if (!Number.isSafeInteger(pid) || pid <= 0) return "unknown";
  try {
    process.kill(pid, 0);
    return "alive";
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return "dead";
    if (code === "EPERM") return "alive";
    return "unknown";
  }
}
