import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { TextDecoder } from "node:util";
import type { CommitOutcome } from "./publisher.ts";
import {
  createPolicySnapshot,
  type PolicyRevision,
  type PolicySnapshot,
  type SnapshotLimits,
} from "./snapshot.ts";

/**
 * file: sync the new file before rename; does not promise directory-entry durability.
 * file-and-directory: additionally sync the parent directory before/after rename.
 * Directory sync is filesystem/platform-dependent: no silent downgrade is allowed.
 */
export type PolicyFileDurability = "file" | "file-and-directory";

/** Explicit filesystem port for deterministic fault tests; never accept it from HTTP/config JSON. */
export interface PolicyFileOperations {
  open: typeof open;
  lstat: typeof lstat;
  rename: typeof rename;
  unlink: typeof unlink;
}

export interface FilePolicyStoreOptions {
  /** Existing policy.json in an application-owned directory. No implicit HOME/default path. */
  path: string;
  /** Required, so a caller cannot mistake file-only sync for a power-loss guarantee. */
  durability: PolicyFileDurability;
  /** Raw file limit, including whitespace. Defaults to 1 MiB; hard maximum is 16 MiB. */
  maxFileBytes?: number;
  limits?: SnapshotLimits;
  operations?: PolicyFileOperations;
}

export type PolicyFileErrorCode =
  | "policy_file_options"
  | "policy_file_read_failed"
  | "policy_file_invalid"
  | "policy_file_too_large"
  | "policy_file_not_regular"
  | "policy_file_transition"
  | "policy_file_busy"
  | "policy_file_recovery_required";

export class PolicyFileError extends Error {
  readonly code: PolicyFileErrorCode;

  constructor(code: PolicyFileErrorCode) {
    super(code);
    this.name = "PolicyFileError";
    this.code = code;
  }
}

const REAL_OPERATIONS: PolicyFileOperations = { open, lstat, rename, unlink };
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;

/**
 * Plain policy.json persistence for ONE cooperating writer/coordinator.
 *
 * This is not a lock or a distributed compare-and-swap. A pre-write hash check
 * detects already-stale state, not a second writer racing after that check.
 * All runtime/CLI writes must be routed through one owner before integration.
 * The directory must be trusted; this is not protection against a local admin
 * swapping parent directories or otherwise writing concurrently.
 *
 * Opening never bootstraps, repairs, deletes or chooses a .tmp file. After an
 * ambiguous commit this instance fences further writes. Inspection remains
 * possible via read(); recovery requires a new instance + domain validation.
 */
export class FilePolicyStore<T extends PolicyRevision> {
  readonly #path: string;
  readonly #directory: string;
  readonly #durability: PolicyFileDurability;
  readonly #maxFileBytes: number;
  readonly #limits: Readonly<SnapshotLimits>;
  readonly #fs: Readonly<PolicyFileOperations>;
  #busy = false;
  #recoveryRequired = false;

  private constructor(options: FilePolicyStoreOptions) {
    if (typeof options.path !== "string" || !isAbsolute(options.path) || options.path.includes("\0")) {
      throw new PolicyFileError("policy_file_options");
    }
    if (options.durability !== "file" && options.durability !== "file-and-directory") {
      throw new PolicyFileError("policy_file_options");
    }
    const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > MAX_FILE_BYTES) {
      throw new PolicyFileError("policy_file_options");
    }
    this.#path = resolve(options.path);
    this.#directory = dirname(this.#path);
    this.#durability = options.durability;
    this.#maxFileBytes = maxFileBytes;
    this.#limits = Object.freeze({ ...options.limits });
    this.#fs = Object.freeze({ ...(options.operations ?? REAL_OPERATIONS) });
    for (const operation of [this.#fs.open, this.#fs.lstat, this.#fs.rename, this.#fs.unlink]) {
      if (typeof operation !== "function") throw new PolicyFileError("policy_file_options");
    }
  }

  /** Read/structure-check existing state only. Domain validation belongs to publisher.prepare. */
  static async open<T extends PolicyRevision>(options: FilePolicyStoreOptions): Promise<FilePolicyStore<T>> {
    const store = new FilePolicyStore<T>(options);
    await store.read();
    return store;
  }

  get recoveryRequired(): boolean {
    return this.#recoveryRequired;
  }

  get durability(): PolicyFileDurability {
    return this.#durability;
  }

  /** Strict UTF-8 and bounded reads, even when the file grows after stat(). */
  async read(): Promise<PolicySnapshot<T>> {
    let handle: FileHandle | undefined;
    try {
      const entry = await this.#fs.lstat(this.#path);
      if (!entry.isFile() || entry.isSymbolicLink()) throw new PolicyFileError("policy_file_not_regular");
      handle = await this.#fs.open(this.#path, "r");
      const opened = await handle.stat();
      if (!opened.isFile()) throw new PolicyFileError("policy_file_not_regular");
      if (opened.size > this.#maxFileBytes) throw new PolicyFileError("policy_file_too_large");
      const chunks: Buffer[] = [];
      let total = 0;
      while (true) {
        const buffer = Buffer.alloc(Math.min(8192, this.#maxFileBytes + 1 - total));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (!bytesRead) break;
        total += bytesRead;
        if (total > this.#maxFileBytes) throw new PolicyFileError("policy_file_too_large");
        chunks.push(buffer.subarray(0, bytesRead));
      }
      let snapshot: PolicySnapshot<T>;
      try {
        // Preserve a BOM so JSON.parse rejects it instead of silently changing the bytes.
        const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks, total));
        snapshot = createPolicySnapshot(JSON.parse(text) as T, this.#limits);
      } catch {
        throw new PolicyFileError("policy_file_invalid");
      }
      await handle.close();
      handle = undefined;
      return snapshot;
    } catch (error) {
      if (error instanceof PolicyFileError) throw error;
      throw new PolicyFileError("policy_file_read_failed");
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  #checked(snapshot: PolicySnapshot<T>): PolicySnapshot<T> {
    const checked = createPolicySnapshot(snapshot.policy as T, this.#limits);
    if (checked.hash !== snapshot.hash) throw new PolicyFileError("policy_file_transition");
    return checked;
  }

  #fence(): never {
    this.#recoveryRequired = true;
    throw new PolicyFileError("policy_file_recovery_required");
  }

  async #matches(expected: PolicySnapshot<T>): Promise<boolean> {
    return (await this.read()).hash === expected.hash;
  }

  /** Bound arrow is safe to pass directly as PolicyPublisherOptions.persist. */
  readonly persist = async (
    candidate: PolicySnapshot<T>,
    previous: PolicySnapshot<T>,
  ): Promise<CommitOutcome> => {
    if (this.#recoveryRequired) throw new PolicyFileError("policy_file_recovery_required");
    if (this.#busy) throw new PolicyFileError("policy_file_busy");
    this.#busy = true;
    let temporary: string | undefined;
    let file: FileHandle | undefined;
    let directory: FileHandle | undefined;
    let ownsTemporary = false;
    let renameAttempted = false;
    try {
      let next: PolicySnapshot<T>;
      let old: PolicySnapshot<T>;
      try {
        next = this.#checked(candidate);
        old = this.#checked(previous);
        if (next.policy.version !== old.policy.version + 1 || next.policy.updatedAt < old.policy.updatedAt) {
          throw new PolicyFileError("policy_file_transition");
        }
      } catch {
        throw new PolicyFileError("policy_file_transition");
      }
      const bytes = Buffer.from(`${JSON.stringify(next.policy)}\n`, "utf8");
      // No persistence has been attempted. An impossible candidate is a programming/config error.
      if (bytes.length > this.#maxFileBytes) throw new PolicyFileError("policy_file_too_large");
      try {
        if (!(await this.#matches(old))) this.#fence();
      } catch {
        this.#fence();
      }
      try {
        if (this.#durability === "file-and-directory") {
          directory = await this.#fs.open(this.#directory, "r");
          // Probe support before changing the authoritative file. Do not silently downgrade.
          await directory.sync();
        }
        temporary = `${this.#path}.tmp.${process.pid}.${randomUUID()}`;
        file = await this.#fs.open(temporary, "wx", 0o600);
        ownsTemporary = true;
        await file.writeFile(bytes);
        await file.sync();
        await file.close();
        file = undefined;
        // Detect an already-changed authority again just before replacement.
        // This is still not a cross-process lock or atomic filesystem CAS.
        if (!(await this.#matches(old))) this.#fence();
        renameAttempted = true;
        await this.#fs.rename(temporary, this.#path);
        ownsTemporary = false;
        await directory?.sync();
        await directory?.close();
        directory = undefined;
        if (!(await this.#matches(next))) this.#fence();
        return { kind: "committed" };
      } catch {
        if (renameAttempted || this.#recoveryRequired) this.#fence();
        // Before rename, and only when old state is still readable and authoritative,
        // a failed temp write/sync/close is a known non-commit and may be retried.
        try {
          if (!(await this.#matches(old))) this.#fence();
        } catch {
          this.#fence();
        }
        return { kind: "not_committed" };
      }
    } finally {
      await file?.close().catch(() => undefined);
      await directory?.close().catch(() => undefined);
      if (ownsTemporary && temporary) {
        // Never unlink policy.json, another writer's file or a glob of old temporaries.
        await this.#fs.unlink(temporary).catch(() => undefined);
      }
      this.#busy = false;
    }
  };
}
