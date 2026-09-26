import { randomUUID } from "node:crypto";
import { open, lstat, rename, unlink } from "node:fs/promises";
import { FilePolicyStore, type PolicyFileOperations } from "./file-store.ts";
import { PolicyHistory } from "./history.ts";
import type { CommitOutcome } from "./publisher.ts";
import type { PolicyRevision, PolicySnapshot } from "./snapshot.ts";

const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;

/** Primary SQLITE_BUSY/SQLITE_LOCKED from a node:sqlite error. Extended codes use the low byte. */
export function isSqliteContention(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { code?: unknown; errcode?: unknown };
  if (candidate.code !== "ERR_SQLITE_ERROR" || typeof candidate.errcode !== "number" || !Number.isInteger(candidate.errcode)) {
    return false;
  }
  const primary = candidate.errcode & 0xff;
  return primary === SQLITE_BUSY || primary === SQLITE_LOCKED;
}

function isHistoryContention(error: unknown): boolean {
  return (error instanceof Error && error.message === "policy_history_busy") || isSqliteContention(error);
}

/**
 * SQLite's transaction is the sole commit point. policy.json is a compatibility
 * projection. A failed projection after the transaction fences the process;
 * startup requires explicit reconciliation and never guesses from temp files.
 * SQLITE_BUSY/LOCKED before that transaction is a known miss, not an unknown commit.
 */
export class HistoricalCommit<T extends PolicyRevision> {
  readonly #path: string;
  readonly #file: FilePolicyStore<T>;
  readonly #history: PolicyHistory<T>;
  readonly #fs: PolicyFileOperations;
  readonly #rulesHash: string;
  readonly #engineVersion: string;

  constructor(path: string, file: FilePolicyStore<T>, history: PolicyHistory<T>, rulesHash: string, engineVersion: string,
    operations?: PolicyFileOperations) {
    this.#path = path;
    this.#file = file;
    this.#history = history;
    this.#rulesHash = rulesHash;
    this.#engineVersion = engineVersion;
    this.#fs = operations ?? {open,lstat,rename,unlink};
  }

  async verifyProjection(): Promise<void> {
    try {
      const current = this.#history.current();
      const projected = await this.#file.read();
      if (current.hash !== projected.hash) throw new Error("policy_recovery_required");
    } catch (error) {
      if (isSqliteContention(error)) throw new Error("policy_history_busy", { cause: error });
      throw new Error("policy_recovery_required");
    }
  }

  readonly persist = async (next: PolicySnapshot<T>, previous: PolicySnapshot<T>): Promise<CommitOutcome> => {
    const temporary = `${this.#path}.tmp.${process.pid}.${randomUUID()}`;
    let file: Awaited<ReturnType<typeof open>> | undefined;
    let ownsTemporary = false;
    let commitStarted = false;
    try {
      try {
        await this.verifyProjection();
        if (this.#history.current().hash !== previous.hash) throw new Error("policy_recovery_required");
        file = await this.#fs.open(temporary, "wx", 0o600);
        ownsTemporary = true;
        await file.writeFile(`${JSON.stringify(next.policy)}\n`);
        await file.sync();
        await file.close();
        file = undefined;
      } catch {
        // A failed precommit preparation is retryable only while both authorities
        // still match the expected old revision.
        await this.verifyProjection();
        if (this.#history.current().hash !== previous.hash) throw new Error("policy_recovery_required");
        return {kind:"not_committed"};
      }
      // Check both again just before the transaction. Old binaries that ignore
      // the writer lease cannot be made safe; the deployment gate excludes them.
      await this.verifyProjection();
      commitStarted = true;
      const outcome = this.#history.commit(next, previous, this.#rulesHash, this.#engineVersion);
      if (outcome === "capacity") {
        await this.verifyProjection();
        return {kind:"not_committed"};
      }
      if (outcome !== "committed") throw new Error("policy_recovery_required");
      await this.#fs.rename(temporary, this.#path);
      ownsTemporary = false;
      await this.verifyProjection();
      return {kind:"committed"};
    } catch (error) {
      // Before commitStarted, BUSY/LOCKED means no durable write began.
      // After it, the same codes stay an unknown outcome and must fence.
      if (!commitStarted && isHistoryContention(error)) return {kind:"not_committed"};
      // COMMIT/rename outcomes may be uncertain. Never return not_committed here.
      throw new Error("policy_recovery_required");
    } finally {
      await file?.close().catch(() => undefined);
      if (ownsTemporary) await this.#fs.unlink(temporary).catch(() => undefined);
    }
  };
}
