import { archivePolicy, githubPolicy } from "../egress-schema.ts";
import { createHash } from "node:crypto";
import { NMZP_VERSION } from "../constants.ts";
import { policyExemptions, policyOverrides } from "../policy-schema.ts";
import type { PolicyState } from "../schema.ts";
import { FilePolicyStore, type FilePolicyStoreOptions } from "./file-store.ts";
import { PolicyHistory, type PolicyHistoryRow } from "./history.ts";
import { HistoricalCommit } from "./history-commit.ts";
import {
  createNmzpPolicyDomain,
  type NmzpPolicyDomain,
  type NmzpPolicyPatch,
  type NmzpPolicySource,
} from "./nmzp-domain.ts";
import { PolicyPublishError, PolicyPublisher, type PolicyBody, type PublishResult } from "./publisher.ts";
import { createPolicySnapshot, type DeepReadonly, type PolicySnapshot, type SnapshotLimits } from "./snapshot.ts";

export type NmzpPolicyResult = PolicyState | { conflict: true; version: number };

export interface NmzpPolicyServiceOptions<Rule extends { id: string }> {
  file: FilePolicyStoreOptions;
  /** Trusted source modules from loadMonitor(coreDir); no custom no-op prepare callback. */
  source: NmzpPolicySource<Rule>;
  now?: () => number;
  maxPending?: number;
  history?: PolicyHistory<PolicyState>;
}

export function policyRulesHash<Rule extends { id: string }>(source: NmzpPolicySource<Rule>): string {
  return createHash("sha256").update(JSON.stringify(source.RULES), "utf8").digest("hex");
}

function writable(policy: DeepReadonly<PolicyState>): PolicyState {
  // Snapshots are bounded JSON data; structuredClone never shares arrays with readers.
  return structuredClone(policy) as PolicyState;
}

function publicPolicy(policy: DeepReadonly<PolicyState>): PolicyState {
  const out = writable(policy);
  return {
    ...out,
    githubUpload: githubPolicy(out.githubUpload),
    archiveUpload: archivePolicy(out.archiveUpload),
    overrides: policyOverrides(out.overrides),
    exemptions: policyExemptions(out.exemptions),
  };
}

function mergePatch(policy: DeepReadonly<PolicyState>, patch: NmzpPolicyPatch): PolicyBody<PolicyState> {
  const next = writable(policy);
  // Preserve supported legacy stop/resume + mode precedence (including retained previousMode).
  if (patch.mode) {
    if (patch.stopped) next.previousMode = patch.mode;
    next.mode = patch.mode;
  }
  for (const key of ["customRules", "overrides", "exemptions", "archiveUpload", "githubUpload"] as const) {
    if (patch[key] !== undefined) Object.assign(next, { [key]: patch[key] });
  }
  if (typeof patch.stopped === "boolean") {
    if (patch.stopped && !next.stopped) next.previousMode = next.mode;
    if (!patch.stopped && next.stopped) next.mode = next.previousMode ?? next.mode;
    next.stopped = patch.stopped;
    if (patch.stopped) next.mode = "off";
  }
  const { version: _version, updatedAt: _updatedAt, ...body } = next;
  return body;
}

/**
 * Composes domain validation -> revision coordinator -> real plain policy.json storage.
 * For one coordinated writer only; no automatic bootstrap, locks, watchers, HTTP or timers.
 * NmzpStore owns the runtime writer lease; HTTP and CLI enter through that store.
 * This low-level open() is for caller-owned files, not a second writer on a live path.
 * Caller authorization and exclusive ownership remain mandatory.
 */
export class NmzpPolicyService {
  readonly #domain: NmzpPolicyDomain;
  readonly #publisher: PolicyPublisher<PolicyState>;
  readonly #history?: PolicyHistory<PolicyState>;
  readonly #limits: SnapshotLimits;

  private constructor(domain: NmzpPolicyDomain, publisher: PolicyPublisher<PolicyState>, history?: PolicyHistory<PolicyState>, limits: SnapshotLimits = {}) {
    this.#domain = domain;
    this.#publisher = publisher;
    this.#history = history;
    this.#limits = { ...limits };
  }

  static async open<Rule extends { id: string }>(
    options: NmzpPolicyServiceOptions<Rule>,
  ): Promise<NmzpPolicyService> {
    // Bind validation first; never create files or initialize default policy on an invalid input.
    const domain = createNmzpPolicyDomain(options.source, options.file.limits);
    const disk = await FilePolicyStore.open<PolicyState>(options.file);
    const initial = await disk.read();
    const historical = options.history === undefined ? undefined : new HistoricalCommit(
      options.file.path, disk, options.history, policyRulesHash(options.source), NMZP_VERSION, options.file.operations,
    );
    await historical?.verifyProjection();
    const publisher = await PolicyPublisher.open(writable(initial.policy), {
      prepare: domain.prepare,
      persist: historical?.persist ?? disk.persist,
      limits: options.file.limits,
      now: options.now,
      maxPending: options.maxPending,
    });
    return new NmzpPolicyService(domain, publisher, options.history, options.file.limits);
  }

  capture(): PolicySnapshot<PolicyState> {
    return this.#publisher.capture();
  }

  getPolicy(): PolicyState {
    return publicPolicy(this.capture().policy);
  }

  get recoveryRequired(): boolean {
    return this.#publisher.recoveryRequired;
  }

  get pendingCount(): number {
    return this.#publisher.pendingCount;
  }

  #result(result: PublishResult<PolicyState>): NmzpPolicyResult {
    // Project THIS commit's snapshot, not a subsequent writer's active revision.
    return result.conflict ? result : publicPolicy(result.snapshot.policy);
  }

  async casPolicy(expectedVersion: number, rawPatch: NmzpPolicyPatch): Promise<NmzpPolicyResult> {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw new PolicyPublishError("invalid_expected_version");
    }
    const previous = this.capture();
    if (expectedVersion !== previous.policy.version) return { conflict: true, version: previous.policy.version };
    const patch = this.#domain.normalizePatch(rawPatch);
    // No await before publish captures the merged body; caller mutation cannot alter queued work.
    return this.#result(await this.#publisher.publish(expectedVersion, mergePatch(previous.policy, patch)));
  }

  /** Read-only check against the same domain and snapshot limits used by publication. */
  previewPatch(expectedVersion: number, rawPatch: NmzpPolicyPatch): { conflict: true; version: number } | { conflict: false } {
    const previous = this.capture();
    if (expectedVersion !== previous.policy.version) return { conflict: true, version: previous.policy.version };
    const patch = this.#domain.normalizePatch(rawPatch);
    const body = mergePatch(previous.policy, patch);
    const candidate = createPolicySnapshot({
      ...body,
      version: expectedVersion + 1,
      updatedAt: Math.max(Date.now(), previous.policy.updatedAt),
    } as PolicyState, this.#limits);
    this.#domain.prepare(candidate);
    return { conflict: false };
  }

  async stop(): Promise<PolicyState> {
    const result = await this.casPolicy(this.capture().policy.version, { stopped: true });
    if ("conflict" in result) throw new Error("policy cas conflict");
    return result;
  }

  async resume(): Promise<PolicyState> {
    const result = await this.casPolicy(this.capture().policy.version, { stopped: false });
    if ("conflict" in result) throw new Error("policy cas conflict");
    return result;
  }

  /** Source comes from an explicit caller-held snapshot, NOT an implemented history repository. */
  async restore(expectedVersion: number, source: PolicySnapshot<PolicyState>): Promise<NmzpPolicyResult> {
    return this.#result(await this.#publisher.restore(expectedVersion, source));
  }

  getHistorical(version: number) { return this.#history?.get(version); }

  listHistory(beforeVersion?: number, limit?: number): PolicyHistoryRow[] {
    if (!this.#history) throw new Error("policy_history_unavailable");
    return this.#history.list(beforeVersion, limit);
  }

  async restoreVersion(expectedVersion: number, sourceVersion: number): Promise<NmzpPolicyResult> {
    if (!this.#history) throw new Error("policy_history_unavailable");
    const source = this.#history.get(sourceVersion);
    if (!source) throw new Error("policy_history_missing");
    return this.#result(await this.#publisher.restore(expectedVersion, source));
  }
}
