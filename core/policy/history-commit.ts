import { randomUUID } from "node:crypto";
import { open, lstat, rename, unlink } from "node:fs/promises";
import { FilePolicyStore, type PolicyFileOperations } from "./file-store.ts";
import { PolicyHistory } from "./history.ts";
import type { CommitOutcome } from "./publisher.ts";
import type { PolicyRevision, PolicySnapshot } from "./snapshot.ts";

/**
 * SQLite's transaction is the sole commit point. policy.json is a compatibility
 * projection. A failed projection after the transaction fences the process;
 * startup requires explicit reconciliation and never guesses from temp files.
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
    } catch { throw new Error("policy_recovery_required"); }
  }

  readonly persist = async (next: PolicySnapshot<T>, previous: PolicySnapshot<T>): Promise<CommitOutcome> => {
    const temporary = `${this.#path}.tmp.${process.pid}.${randomUUID()}`;
    let file: Awaited<ReturnType<typeof open>> | undefined;
    let ownsTemporary = false;
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
    } catch {
      // COMMIT/rename outcomes may be uncertain. Never return not_committed here.
      throw new Error("policy_recovery_required");
    } finally {
      await file?.close().catch(() => undefined);
      if (ownsTemporary) await this.#fs.unlink(temporary).catch(() => undefined);
    }
  };
}
