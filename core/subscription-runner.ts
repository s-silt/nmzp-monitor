import { newEventId } from "./auth.ts";
import type { NmzpStore } from "./persist.ts";
import type { CustomPrivacyRule, StoredEvent } from "./schema.ts";
import { fetchSubscription, type SubscriptionFetchResult } from "./subscription-fetch.ts";
import { applyFetchOutcome, subscriptionRules, type FetchApplication, type FetchOutcome } from "./subscription-state.ts";
import type { PolicySubscription } from "./subscription-schema.ts";

const TICK_MS = 60_000;
const FIRST_TICK_MS = 5_000;
const APPLY_ATTEMPTS = 3;

export type SubscriptionFetcher = (url: string, options: { etag?: string; signal: AbortSignal }) => Promise<SubscriptionFetchResult>;

export interface SubscriptionRunnerOptions {
  store: NmzpStore;
  privacy: {
    sanitizeCustomRules: (raw: unknown) => CustomPrivacyRule[] | undefined;
    MAX_CUSTOM_RULES: number;
  };
  /** Trusted test seams. */
  fetch?: SubscriptionFetcher;
  now?: () => number;
}

export interface RefreshResult extends Omit<FetchApplication, "patch"> {
  version?: number;
}

export interface SubscriptionRuntime {
  lastCheckedAt?: number;
  inFlight: boolean;
}

/**
 * Core-side refresh loop. Due = last attempt (or stored lastFetchedAt after a restart) plus the
 * feed's interval, never below 60 minutes. Feeds refresh one at a time. Manual refresh joins an
 * in-flight attempt instead of starting a second request.
 */
export class SubscriptionRunner {
  readonly #store: NmzpStore;
  readonly #privacy: SubscriptionRunnerOptions["privacy"];
  readonly #fetch: SubscriptionFetcher;
  readonly #now: () => number;
  readonly #checked = new Map<string, number>();
  readonly #inFlight = new Map<string, Promise<RefreshResult>>();
  readonly #abort = new AbortController();
  /** Digest changes already published whose audit row could not be written yet. */
  readonly #pendingAudit: StoredEvent[] = [];
  #flushing: Promise<void> | undefined;
  /** Fetched results that lost every CAS attempt. Retried on the next tick without refetching. */
  readonly #pendingApply = new Map<string, { url: string; outcome: FetchOutcome }>();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #ticking: Promise<void> | undefined;
  #closed = false;

  constructor(options: SubscriptionRunnerOptions) {
    this.#store = options.store;
    this.#privacy = options.privacy;
    this.#fetch = options.fetch ?? ((url, fetchOptions) => fetchSubscription(url, fetchOptions));
    this.#now = options.now ?? Date.now;
  }

  start(): void {
    if (!this.#closed) this.#schedule(FIRST_TICK_MS);
  }

  #schedule(delay: number): void {
    if (this.#closed) return;
    this.#timer = setTimeout(() => {
      this.#ticking = this.#tick().finally(() => {
        this.#ticking = undefined;
        this.#schedule(TICK_MS);
      });
    }, delay);
    this.#timer.unref();
  }

  #due(sub: PolicySubscription, now: number): boolean {
    if (!sub.enabled) return false;
    const last = this.#checked.get(sub.id) ?? sub.lastFetchedAt;
    return last === undefined || now >= last + sub.intervalMinutes * 60_000;
  }

  async #tick(): Promise<void> {
    await this.#flushAudit();
    let subscriptions: PolicySubscription[];
    try { subscriptions = this.#store.getPolicy().subscriptions ?? []; }
    catch { return; }
    for (const sub of subscriptions) {
      if (this.#closed) return;
      const pending = this.#pendingApply.get(sub.id);
      if (!pending && !this.#due(sub, this.#now())) continue;
      try {
        if (pending && !this.#inFlight.has(sub.id)) await this.#track(sub.id, () => this.#apply(sub.id, pending.url, pending.outcome));
        else await this.refresh(sub.id);
      }
      catch (error) {
        process.stderr.write(`subscription_refresh_failed ${sub.id} ${error instanceof Error ? error.message : "unknown"}\n`);
      }
    }
  }

  status(): Map<string, SubscriptionRuntime> {
    const out = new Map<string, SubscriptionRuntime>();
    for (const [id, at] of this.#checked) out.set(id, { lastCheckedAt: at, inFlight: this.#inFlight.has(id) });
    for (const id of this.#inFlight.keys()) if (!out.has(id)) out.set(id, { inFlight: true });
    return out;
  }

  refresh(id: string): Promise<RefreshResult> {
    if (this.#closed) return Promise.reject(new Error("subscription_runner_closed"));
    const existing = this.#inFlight.get(id);
    if (existing) return existing;
    return this.#track(id, () => this.#refreshOnce(id));
  }

  #track(id: string, work: () => Promise<RefreshResult>): Promise<RefreshResult> {
    const run = work().finally(() => this.#inFlight.delete(id));
    this.#inFlight.set(id, run);
    return run;
  }

  async #outcome(sub: PolicySubscription): Promise<FetchOutcome> {
    // An ETag is only worth sending while the matching content is still stored.
    const etag = sub.lastDigest !== undefined ? sub.lastEtag : undefined;
    const fetched = await this.#fetch(sub.url, { etag, signal: this.#abort.signal });
    if (fetched.kind !== "ok") return fetched;
    const parsed = subscriptionRules(sub.id, fetched.body, this.#privacy.sanitizeCustomRules, this.#privacy.MAX_CUSTOM_RULES);
    if (!parsed.ok) return { kind: "error", code: parsed.code };
    return { kind: "ok", rules: parsed.rules, digest: parsed.digest, ...(fetched.etag ? { etag: fetched.etag } : {}) };
  }

  async #refreshOnce(id: string): Promise<RefreshResult> {
    await this.#flushAudit();
    const sub = this.#store.getPolicy().subscriptions?.find((row) => row.id === id);
    if (!sub) return { result: "missing" };
    this.#checked.set(id, this.#now());
    // A fresh fetch supersedes a result still waiting for its write.
    this.#pendingApply.delete(id);
    const outcome = await this.#outcome(sub);
    if (this.#closed) return { result: "error", error: "aborted" };
    return this.#apply(id, sub.url, outcome);
  }

  async #apply(id: string, url: string, outcome: FetchOutcome): Promise<RefreshResult> {
    this.#pendingApply.delete(id);
    for (let attempt = 0; attempt < APPLY_ATTEMPTS; attempt++) {
      const policy = this.#store.getPolicy();
      // A feed deleted, or deleted and re-added, while the request was out does not take its result.
      const live = policy.subscriptions?.find((row) => row.id === id);
      if (!live || live.url !== url) return { result: "missing" };
      const { patch, ...applied } = applyFetchOutcome(policy, id, outcome, this.#now(), this.#privacy.MAX_CUSTOM_RULES);
      if (!patch) return { ...applied, version: policy.version };
      const written = await this.#store.casSubscriptions(policy.version, patch);
      if ("conflict" in written) continue;
      if (applied.result === "updated") await this.#audit(live, applied, written.version);
      return { ...applied, version: written.version };
    }
    // Busy policy writers: keep the fetched result and retry only the write on the next tick,
    // so a conflict neither waits a full interval nor refetches every minute.
    this.#pendingApply.set(id, { url, outcome });
    return { result: "error", error: "policy_conflict" };
  }

  /**
   * One management audit row per content-digest change. Never carries rule match text or the
   * feed URL/host (the LAN viewer projects events). A failed append is retried on every tick;
   * an exit before that loses only the row, the version itself stays in policy history.
   */
  async #audit(sub: PolicySubscription, applied: Omit<FetchApplication, "patch">, version: number): Promise<void> {
    const summary = JSON.stringify({
      subscriptionId: sub.id,
      previousDigest: applied.previousDigest ?? null,
      digest: applied.digest,
      ruleCount: applied.ruleCount,
    });
    this.#pendingAudit.push({
      id: newEventId(),
      ts: this.#now(),
      machineId: "nmzp-core",
      agent: "nmzp",
      sessionId: "",
      layer: "policy",
      tool: "PolicySubscription",
      nativeTool: "policy_subscription",
      input: summary,
      redacted: summary,
      risk: "info",
      decision: "log",
      evaluation: "log",
      category: "other",
      workdirScope: "other",
      source: "policy_subscription",
      enforcement: "delivered",
      policyVersion: version,
    });
    await this.#flushAudit();
  }

  /** Single consumer: concurrent callers share one drain, so shift() always removes the row it wrote. */
  #flushAudit(): Promise<void> {
    this.#flushing ??= this.#drainAudit().finally(() => { this.#flushing = undefined; });
    return this.#flushing;
  }

  async #drainAudit(): Promise<void> {
    while (this.#pendingAudit.length) {
      try {
        await this.#store.appendEvent(this.#pendingAudit[0]!);
      } catch (error) {
        process.stderr.write(`subscription_audit_failed ${error instanceof Error ? error.message : "unknown"}\n`);
        return;
      }
      this.#pendingAudit.shift();
    }
  }

  /** Trusted test seam: one scheduler pass now, without the timer. */
  async runDueNow(): Promise<void> {
    await this.#tick();
  }

  /** Audit rows published but not yet stored. */
  get pendingAuditCount(): number {
    return this.#pendingAudit.length;
  }

  async close(): Promise<void> {
    this.#closed = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#abort.abort();
    await Promise.allSettled([this.#ticking, ...this.#inFlight.values()]);
  }
}
