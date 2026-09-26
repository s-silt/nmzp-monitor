import { randomUUID } from "node:crypto";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";

const MAX_LEASE_BYTES = 4096;
const OFFLINE_REVIEW =
  "offline review required; see docs/policy-runtime.md (Policy publication and recovery)";

type WriterLeaseProbe = {
  bootId(): string | null;
  startTime(pid: number): string | null;
  alive(pid: number): "alive" | "dead" | "unknown";
  hostname(): string;
};

type ReclaimReason = "reboot" | "dead" | "pid_reused";

type ParsedLease = {
  formatVersion: 2;
  pid: number;
  owner: string;
  hostname: string;
  bootId: string | null;
  startTime: string | null;
};

type Inspection = {
  dev: number;
  ino: number;
  lease: ParsedLease;
  reason: ReclaimReason;
};

type Reclaimed = {
  archive: string;
  pid: number;
  reason: ReclaimReason;
};

/**
 * Exclusive policy writer lease.
 *
 * A new lease records formatVersion 2 with pid, owner, hostname, bootId, and startTime.
 * On EEXIST, reclaim only a regular file of at most 4096 bytes whose formatVersion 2 owner
 * is proved dead on this same host: the boot id changed, the pid is gone on that boot, or
 * the pid was reused and its start time differs. Reclaim holds `<path>.recover` and renames
 * the old lease to `<path>.stale-<ms>-<uuid>`; the archive is never unlinked. Legacy,
 * malformed, symlink, foreign-host, unknown-boot, live, and stale-guard states throw
 * policy_writer_busy for offline review. `opts.probe` is a test seam; production callers omit it.
 */
export class PolicyWriterLease {
  readonly #path: string;
  readonly #fd: number;
  #closed = false;
  readonly #exit = () => {
    this.close();
  };

  constructor(path: string, opts?: { probe?: WriterLeaseProbe }) {
    this.#path = path;
    const probe = opts?.probe ?? realProbe;
    const opened = openLease(path, probe);
    this.#fd = opened.fd;
    try {
      writeSync(this.#fd, JSON.stringify(leaseBody(probe)));
    } catch {
      this.close();
      throw new Error("policy_writer_unavailable");
    }
    if (opened.reclaimed) {
      const { archive, pid, reason } = opened.reclaimed;
      try {
        process.stderr.write(
          `policy_writer_lease_reclaimed ${archive} pid=${pid} reason=${reason}\n`,
        );
      } catch {
        // The new lease is already held. Logging must not strand it.
      }
    }
    process.once("exit", this.#exit);
  }

  assertOwned(): void {
    if (this.#closed) throw new Error("policy_writer_closed");
    try {
      const held = fstatSync(this.#fd);
      const named = lstatSync(this.#path);
      if (!named.isFile() || named.isSymbolicLink() || held.dev !== named.dev || held.ino !== named.ino) {
        throw new Error("identity");
      }
    } catch {
      throw new Error("policy_recovery_required");
    }
  }

  close(): void {
    if (this.#closed) return;
    process.off("exit", this.#exit);
    try {
      this.assertOwned();
      unlinkSync(this.#path);
    } catch {
      /* Never remove a replacement owner's lock. */
    }
    this.#closed = true;
    closeSync(this.#fd);
  }
}

const realProbe: WriterLeaseProbe = {
  bootId: readBootId,
  startTime: readStartTime,
  alive: readAlive,
  hostname,
};

function leaseBody(probe: WriterLeaseProbe): ParsedLease {
  return {
    formatVersion: 2,
    pid: process.pid,
    owner: randomUUID(),
    hostname: probe.hostname(),
    bootId: probe.bootId(),
    startTime: probe.startTime(process.pid),
  };
}

function openLease(path: string, probe: WriterLeaseProbe): { fd: number; reclaimed?: Reclaimed } {
  try {
    return { fd: openSync(path, "wx", 0o600) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new Error("policy_writer_unavailable");
  }
  return recover(path, probe);
}

function recover(path: string, probe: WriterLeaseProbe): { fd: number; reclaimed: Reclaimed } {
  const first = inspect(path, probe);
  if (!first) throw writerBusy();
  const guardPath = `${path}.recover`;
  const guardFd = openGuard(guardPath);
  let guardIdentity: { dev: number; ino: number } | null = null;
  try {
    try {
      const guardStat = fstatSync(guardFd);
      guardIdentity = { dev: guardStat.dev, ino: guardStat.ino };
    } catch {
      throw new Error("policy_writer_unavailable");
    }
    const again = inspect(path, probe);
    if (!again || again.dev !== first.dev || again.ino !== first.ino) throw writerBusy();
    let current;
    try {
      current = lstatSync(path);
    } catch {
      throw writerBusy();
    }
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== again.dev ||
      current.ino !== again.ino
    ) {
      throw writerBusy();
    }
    const archive = `${path}.stale-${Date.now()}-${randomUUID()}`;
    try {
      renameSync(path, archive);
    } catch {
      throw writerBusy();
    }
    let archived;
    try {
      archived = lstatSync(archive);
    } catch {
      throw new Error("policy_recovery_required");
    }
    if (
      !archived.isFile() ||
      archived.isSymbolicLink() ||
      archived.dev !== again.dev ||
      archived.ino !== again.ino
    ) {
      throw new Error("policy_recovery_required");
    }
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw writerBusy();
      throw new Error("policy_writer_unavailable");
    }
    return {
      fd,
      reclaimed: { archive, pid: again.lease.pid, reason: again.reason },
    };
  } finally {
    try {
      closeSync(guardFd);
    } catch {
      // Closing the guard must not hide the reclaim result.
    }
    if (guardIdentity) {
      try {
        const now = lstatSync(guardPath);
        if (
          now.isFile() &&
          !now.isSymbolicLink() &&
          now.dev === guardIdentity.dev &&
          now.ino === guardIdentity.ino
        ) {
          unlinkSync(guardPath);
        }
      } catch {
        // A missing or replaced guard stays for offline review.
      }
    }
  }
}

function openGuard(guardPath: string): number {
  try {
    return openSync(guardPath, "wx", 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "EISDIR") throw writerBusy();
    throw new Error("policy_writer_unavailable");
  }
}

function inspect(path: string, probe: WriterLeaseProbe): Inspection | null {
  let before;
  try {
    before = lstatSync(path);
  } catch {
    return null;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.size > MAX_LEASE_BYTES) return null;
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    return null;
  }
  let after;
  try {
    after = lstatSync(path);
  } catch {
    return null;
  }
  if (
    !after.isFile() ||
    after.isSymbolicLink() ||
    after.dev !== before.dev ||
    after.ino !== before.ino ||
    after.size > MAX_LEASE_BYTES ||
    raw.length > MAX_LEASE_BYTES
  ) {
    return null;
  }
  const lease = parseLease(raw.toString("utf8"));
  if (!lease) return null;
  const reason = reclaimReason(lease, probe);
  if (!reason) return null;
  return { dev: after.dev, ino: after.ino, lease, reason };
}

function reclaimReason(lease: ParsedLease, probe: WriterLeaseProbe): ReclaimReason | null {
  const bootId = probe.bootId();
  if (bootId === null || lease.bootId === null || lease.hostname !== probe.hostname()) return null;
  if (lease.bootId !== bootId) return "reboot";
  const life = probe.alive(lease.pid);
  if (life === "dead") return "dead";
  if (life !== "alive") return null;
  if (lease.startTime === null) return null;
  const startTime = probe.startTime(lease.pid);
  if (startTime === null || startTime === lease.startTime) return null;
  return "pid_reused";
}

function parseLease(text: string): ParsedLease | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const pid = row.pid;
  const owner = row.owner;
  const host = row.hostname;
  const bootId = row.bootId;
  const startTime = row.startTime;
  if (row.formatVersion !== 2) return null;
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0) return null;
  if (typeof owner !== "string" || owner.length === 0) return null;
  if (typeof host !== "string") return null;
  if (!nullableText(bootId) || !nullableText(startTime)) return null;
  return { formatVersion: 2, pid, owner, hostname: host, bootId, startTime };
}

function nullableText(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && value.length > 0);
}

function writerBusy(): Error {
  return new Error("policy_writer_busy", { cause: OFFLINE_REVIEW });
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
