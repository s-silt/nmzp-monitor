import {
  capturePolicyData,
  createPolicySnapshot,
  type PolicyRevision,
  type PolicySnapshot,
  type SnapshotLimits,
} from "./snapshot.ts";

export type PolicyBody<T extends PolicyRevision> = Omit<T, keyof PolicyRevision>;
export type CommitOutcome = { kind: "committed" } | { kind: "not_committed" };
export type PublishResult<T extends PolicyRevision> =
  | { conflict: true; version: number }
  | { conflict: false; snapshot: PolicySnapshot<T> };

export interface PolicyPublisherOptions<T extends PolicyRevision> {
  /** Mandatory schema/rule validation; may prepare compilation, but must not activate it. */
  prepare: (candidate: PolicySnapshot<T>) => void | Promise<void>;
  /**
   * The adapter owns the durable commit point. Return not_committed ONLY when the
   * old durable revision is known to remain authoritative. A throw/unknown result
   * fences this publisher until the durable state is inspected and reopened.
   */
  persist: (candidate: PolicySnapshot<T>, previous: PolicySnapshot<T>) => Promise<CommitOutcome>;
  now?: () => number;
  maxPending?: number;
  limits?: SnapshotLimits;
}

export type PolicyPublishErrorCode =
  | "invalid_expected_version"
  | "managed_revision_fields"
  | "invalid_policy_body"
  | "invalid_policy_clock"
  | "policy_version_exhausted"
  | "policy_queue_full"
  | "policy_not_committed"
  | "policy_recovery_required"
  | "invalid_restore_snapshot";

export class PolicyPublishError extends Error {
  readonly code: PolicyPublishErrorCode;

  constructor(code: PolicyPublishErrorCode) {
    super(code);
    this.name = "PolicyPublishError";
    this.code = code;
  }
}

/**
 * A single-process, single-writer coordinator. No disk, HTTP, model or timers.
 * Capture once per evaluation and keep that immutable snapshot for the whole call.
 * This is NOT a database transaction, cross-process lock, historical store or
 * complete hot-update integration. Domain checks and durability are mandatory ports.
 */
export class PolicyPublisher<T extends PolicyRevision> {
  #active: PolicySnapshot<T>;
  readonly #options: PolicyPublisherOptions<T>;
  readonly #maxPending: number;
  #pending = 0;
  #tail: Promise<void> = Promise.resolve();
  #recoveryRequired = false;

  private constructor(initial: PolicySnapshot<T>, options: PolicyPublisherOptions<T>) {
    this.#active = initial;
    this.#options = options;
    this.#maxPending = options.maxPending ?? 32;
  }

  /** Initialize from a caller-verified durable policy. Does not write it again. */
  static async open<T extends PolicyRevision>(
    initial: T,
    options: PolicyPublisherOptions<T>,
  ): Promise<PolicyPublisher<T>> {
    if (typeof options.prepare !== "function" || typeof options.persist !== "function") {
      throw new TypeError("prepare and persist are required");
    }
    const maxPending = options.maxPending ?? 32;
    if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 1024) {
      throw new RangeError("maxPending must be an integer between 1 and 1024");
    }
    const ownedOptions = Object.freeze({
      ...options,
      limits: Object.freeze({ ...options.limits }),
    });
    const snapshot = createPolicySnapshot(initial, ownedOptions.limits);
    await ownedOptions.prepare(snapshot);
    return new PolicyPublisher(snapshot, ownedOptions);
  }

  capture(): PolicySnapshot<T> {
    if (this.#recoveryRequired) throw new PolicyPublishError("policy_recovery_required");
    return this.#active;
  }

  get pendingCount(): number {
    return this.#pending;
  }

  get recoveryRequired(): boolean {
    return this.#recoveryRequired;
  }

  /** Full candidate body, not an HTTP patch. The transport/application layer merges patches. */
  async publish(expectedVersion: number, body: PolicyBody<T>): Promise<PublishResult<T>> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw new PolicyPublishError("invalid_expected_version");
    }
    this.capture();
    if (this.#pending >= this.#maxPending) throw new PolicyPublishError("policy_queue_full");
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new PolicyPublishError("invalid_policy_body");
    }
    if (Object.hasOwn(body, "version") || Object.hasOwn(body, "updatedAt")) {
      throw new PolicyPublishError("managed_revision_fields");
    }
    // Capture BEFORE waiting in the queue: later caller mutation must not edit this request.
    const ownedBody = capturePolicyData(body, this.#options.limits);
    this.#pending++;
    const run = this.#tail.then(async (): Promise<PublishResult<T>> => {
      const previous = this.capture();
      if (expectedVersion !== previous.policy.version) {
        return { conflict: true, version: previous.policy.version };
      }
      if (previous.policy.version >= Number.MAX_SAFE_INTEGER) {
        throw new PolicyPublishError("policy_version_exhausted");
      }
      const now = (this.#options.now ?? Date.now)();
      if (!Number.isSafeInteger(now) || now < 0) throw new PolicyPublishError("invalid_policy_clock");
      const next = createPolicySnapshot({
        ...ownedBody,
        version: previous.policy.version + 1,
        updatedAt: Math.max(now, previous.policy.updatedAt),
      // T is a JSON policy shape; the coordinator owns these two numeric fields.
      // The mandatory prepare port validates the completed application document.
      } as unknown as T, this.#options.limits);
      await this.#options.prepare(next);
      let outcome: CommitOutcome["kind"] | undefined;
      try {
        // Reading an invalid/accessor return value can itself fail; that is unknown too.
        outcome = (await this.#options.persist(next, previous))?.kind;
      } catch {
        this.#recoveryRequired = true;
        // Do not leak policy contents, paths or backend error strings to callers.
        throw new PolicyPublishError("policy_recovery_required");
      }
      if (outcome === "not_committed") throw new PolicyPublishError("policy_not_committed");
      if (outcome !== "committed") {
        this.#recoveryRequired = true;
        throw new PolicyPublishError("policy_recovery_required");
      }
      this.#active = next;
      return { conflict: false, snapshot: next };
    });
    this.#tail = run.then(() => undefined, () => undefined);
    try {
      return await run;
    } finally {
      this.#pending--;
    }
  }

  /** Reuse validated old CONTENT as a NEW revision; never rewind version numbers. */
  async restore(expectedVersion: number, source: PolicySnapshot<T>): Promise<PublishResult<T>> {
    const checked = createPolicySnapshot(source.policy as T, this.#options.limits);
    if (source.hash !== checked.hash || checked.policy.version > expectedVersion) {
      throw new PolicyPublishError("invalid_restore_snapshot");
    }
    const { version: _version, updatedAt: _updatedAt, ...body } = checked.policy;
    return this.publish(expectedVersion, body as PolicyBody<T>);
  }
}
