import { createHash } from "node:crypto";
import { PolicyDomainError } from "./policy/nmzp-domain.ts";
import { MAX_CUSTOM_SETS, resolvedCustomSets, type CustomPrivacyRule, type CustomRuleSet, type PolicyState } from "./schema.ts";
import { MAX_SUBSCRIPTIONS, type PolicySubscription } from "./subscription-schema.ts";

type PolicyView = Readonly<Pick<PolicyState, "customRules" | "customSets" | "subscriptions">>;

/** The three fields a subscription write replaces together. Nothing else is reachable from here. */
export interface SubscriptionPatch {
  customRules: CustomPrivacyRule[];
  customSets: CustomRuleSet[];
  subscriptions: PolicySubscription[];
}

export type SubscriptionStateErrorCode =
  | "subscription_limit"
  | "subscription_not_found"
  | "custom_set_limit"
  | "subscription_id_taken";

export class SubscriptionStateError extends Error {
  readonly code: SubscriptionStateErrorCode;
  constructor(code: SubscriptionStateErrorCode) {
    super(code);
    this.name = "SubscriptionStateError";
    this.code = code;
  }
}

function subscriptionSource(set: CustomRuleSet): string | undefined {
  return set.source === "local" ? undefined : set.source.subscriptionId;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

/**
 * One set per subscription: set.id === subscription id and its source names that id.
 * A subscription-sourced set without a stored subscription is inconsistent too.
 */
export function subscriptionsConsistent(policy: Pick<PolicyView, "customSets" | "subscriptions">): boolean {
  const subscriptions = policy.subscriptions ?? [];
  const remote = resolvedCustomSets(policy.customSets).filter((set) => set.source !== "local");
  if (remote.length !== subscriptions.length) return false;
  const enabled = new Map(subscriptions.map((sub) => [sub.id, sub.enabled]));
  const seen = new Set<string>();
  for (const set of remote) {
    const owner = subscriptionSource(set);
    // The feed's enabled flag drives both refresh and evaluation; they never diverge.
    if (owner === undefined || owner !== set.id || enabled.get(owner) !== set.enabled || seen.has(owner)) return false;
    seen.add(owner);
  }
  return true;
}

/**
 * Admin writes own local sets and local rules only. Subscription sets may be echoed back with a
 * different name; enabled stays with the feed (PATCH the subscription). Subscription rules may be
 * echoed back unchanged. Anything the
 * admin omitted is carried over, so a client that only knows local sets cannot drop a feed.
 * Adding, re-pointing, or editing subscription content through the generic PUT is rejected.
 */
export function reconcileAdminWrite<T extends Pick<PolicyState, "customRules" | "customSets">>(previous: PolicyView, body: T): T {
  const previousRemote = resolvedCustomSets(previous.customSets).filter((set) => set.source !== "local");
  const bodySets = body.customSets;
  if (previousRemote.length === 0) {
    if (bodySets?.some((set) => set.source !== "local")) throw new PolicyDomainError("invalid_policy_custom_sets");
    return body;
  }
  const remoteById = new Map(previousRemote.map((set) => [set.id, set]));
  const sets = [...(bodySets ?? resolvedCustomSets(previous.customSets))];
  const echoed = new Set<string>();
  for (const set of sets) {
    if (set.source === "local") {
      if (remoteById.has(set.id)) throw new PolicyDomainError("invalid_policy_custom_sets");
      continue;
    }
    const prior = remoteById.get(set.id);
    if (!prior || subscriptionSource(prior) !== subscriptionSource(set) || prior.enabled !== set.enabled || echoed.has(set.id)) {
      throw new PolicyDomainError("invalid_policy_custom_sets");
    }
    echoed.add(set.id);
  }
  for (const set of previousRemote) if (!echoed.has(set.id)) sets.push(clone(set));

  const remoteIds = new Set(remoteById.keys());
  const priorRules = new Map<string, string>();
  const carried: CustomPrivacyRule[] = [];
  for (const rule of previous.customRules) {
    if (rule.setId === undefined || !remoteIds.has(rule.setId)) continue;
    priorRules.set(rule.id, canonical(rule));
    carried.push(rule);
  }
  const rules = [...body.customRules];
  const kept = new Set<string>();
  for (const rule of rules) {
    if (rule.setId === undefined || !remoteIds.has(rule.setId)) continue;
    if (priorRules.get(rule.id) !== canonical(rule) || kept.has(rule.id)) throw new PolicyDomainError("invalid_custom_rules");
    kept.add(rule.id);
  }
  for (const rule of carried) if (!kept.has(rule.id)) rules.push(clone(rule));
  return { ...body, customSets: sets, customRules: rules };
}

function patchFrom(policy: PolicyView): SubscriptionPatch {
  return {
    customRules: clone([...policy.customRules]),
    customSets: clone([...resolvedCustomSets(policy.customSets)]),
    subscriptions: clone([...(policy.subscriptions ?? [])]),
  };
}

export interface NewSubscription {
  id: string;
  url: string;
  name: string;
  intervalMinutes: number;
}

/** New feed starts enabled, with an enabled empty set. The first fetch fills it. */
export function addSubscription(policy: PolicyView, input: NewSubscription): SubscriptionPatch {
  const next = patchFrom(policy);
  if (next.subscriptions.length >= MAX_SUBSCRIPTIONS) throw new SubscriptionStateError("subscription_limit");
  if (next.customSets.length >= MAX_CUSTOM_SETS) throw new SubscriptionStateError("custom_set_limit");
  if (next.customSets.some((set) => set.id === input.id) || next.subscriptions.some((sub) => sub.id === input.id)) {
    throw new SubscriptionStateError("subscription_id_taken");
  }
  next.subscriptions.push({ id: input.id, url: input.url, enabled: true, intervalMinutes: input.intervalMinutes });
  next.customSets.push({ id: input.id, name: input.name, enabled: true, source: { subscriptionId: input.id } });
  return next;
}

export interface SubscriptionUpdate {
  enabled?: boolean;
  intervalMinutes?: number;
  name?: string;
}

/** enabled switches both the refresh and whether the feed's rules apply. */
export function updateSubscription(policy: PolicyView, id: string, update: SubscriptionUpdate): SubscriptionPatch {
  const next = patchFrom(policy);
  const sub = next.subscriptions.find((row) => row.id === id);
  const set = next.customSets.find((row) => row.id === id && subscriptionSource(row) === id);
  if (!sub || !set) throw new SubscriptionStateError("subscription_not_found");
  if (update.enabled !== undefined) {
    sub.enabled = update.enabled;
    set.enabled = update.enabled;
  }
  if (update.intervalMinutes !== undefined) sub.intervalMinutes = update.intervalMinutes;
  if (update.name !== undefined) set.name = update.name;
  return next;
}

/** Drops the feed, its set and every rule it produced. */
export function removeSubscription(policy: PolicyView, id: string): SubscriptionPatch {
  const next = patchFrom(policy);
  if (!next.subscriptions.some((row) => row.id === id)) throw new SubscriptionStateError("subscription_not_found");
  next.subscriptions = next.subscriptions.filter((row) => row.id !== id);
  next.customSets = next.customSets.filter((row) => !(row.id === id && subscriptionSource(row) === id));
  next.customRules = next.customRules.filter((rule) => rule.setId !== id);
  return next;
}

export type SubscriptionRulesResult =
  | { ok: true; rules: CustomPrivacyRule[]; digest: string }
  | { ok: false; code: "invalid_format" | "too_many_rules" | "invalid_rules" };

/**
 * Body is `{ "rules": [...] }` or a bare array of custom privacy rules. Upstream setId is ignored;
 * every rule lands in the feed's own set with an id namespaced by the feed. Any row the existing
 * sanitizer would drop fails the whole snapshot instead of silently shrinking it.
 */
export function subscriptionRules(
  id: string,
  body: unknown,
  sanitize: (raw: unknown) => CustomPrivacyRule[] | undefined,
  maxRules: number,
): SubscriptionRulesResult {
  const rows = Array.isArray(body) ? body
    : body !== null && typeof body === "object" && Array.isArray((body as { rules?: unknown }).rules) ? (body as { rules: unknown[] }).rules
    : undefined;
  if (!rows) return { ok: false, code: "invalid_format" };
  if (rows.length > maxRules) return { ok: false, code: "too_many_rules" };
  const owned: Record<string, unknown>[] = [];
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row === null || typeof row !== "object" || Array.isArray(row)) return { ok: false, code: "invalid_rules" };
    const { setId: _setId, id: upstreamId, ...rest } = row as Record<string, unknown>;
    const local = typeof upstreamId === "string" && upstreamId.length > 0 ? upstreamId : `r${index}`;
    owned.push({ ...rest, id: `${id}_${local}`.slice(0, 40), setId: id });
  }
  let rules: CustomPrivacyRule[] | undefined;
  try { rules = sanitize(owned); }
  catch { return { ok: false, code: "invalid_rules" }; }
  if (!rules || rules.length !== owned.length) return { ok: false, code: "invalid_rules" };
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length) return { ok: false, code: "invalid_rules" };
  return { ok: true, rules, digest: createHash("sha256").update(canonical(rules), "utf8").digest("hex") };
}

export type FetchOutcome =
  | { kind: "ok"; rules: CustomPrivacyRule[]; digest: string; etag?: string }
  | { kind: "not_modified" }
  | { kind: "error"; code: string };

export interface FetchApplication {
  /** Undefined when nothing needs to be published. */
  patch?: SubscriptionPatch;
  result: "updated" | "unchanged" | "error" | "missing";
  error?: string;
  previousDigest?: string;
  digest?: string;
  ruleCount?: number;
}

/**
 * Publishes only on a content change or an error-state change. An unchanged hourly fetch does not
 * bump the policy version, so devices are not told to re-download and history is not flooded.
 * A failure keeps the last good rules and records lastError.
 */
export function applyFetchOutcome(policy: PolicyView, id: string, outcome: FetchOutcome, now: number, maxRules: number): FetchApplication {
  const current = (policy.subscriptions ?? []).find((row) => row.id === id);
  if (!current) return { result: "missing" };
  const fail = (code: string): FetchApplication => {
    if (current.lastError === code) return { result: "error", error: code };
    const next = patchFrom(policy);
    next.subscriptions.find((row) => row.id === id)!.lastError = code;
    return { patch: next, result: "error", error: code };
  };
  if (outcome.kind === "error") return fail(outcome.code);
  if (outcome.kind === "not_modified" || outcome.digest === current.lastDigest) {
    if (current.lastError === undefined) return { result: "unchanged", digest: current.lastDigest };
    const next = patchFrom(policy);
    const sub = next.subscriptions.find((row) => row.id === id)!;
    delete sub.lastError;
    sub.lastFetchedAt = now;
    return { patch: next, result: "unchanged", digest: current.lastDigest };
  }
  const others = policy.customRules.filter((rule) => rule.setId !== id);
  if (others.length + outcome.rules.length > maxRules) return fail("rule_limit");
  const taken = new Set(others.map((rule) => rule.match.toLowerCase()));
  if (outcome.rules.some((rule) => taken.has(rule.match.toLowerCase()))) return fail("duplicate_match");
  const takenIds = new Set(others.map((rule) => rule.id));
  if (outcome.rules.some((rule) => takenIds.has(rule.id))) return fail("duplicate_rule_id");
  const next = patchFrom(policy);
  next.customRules = [...clone(others), ...clone(outcome.rules)];
  const sub = next.subscriptions.find((row) => row.id === id)!;
  sub.lastDigest = outcome.digest;
  sub.lastFetchedAt = now;
  if (outcome.etag !== undefined) sub.lastEtag = outcome.etag;
  else delete sub.lastEtag;
  delete sub.lastError;
  return {
    patch: next,
    result: "updated",
    previousDigest: current.lastDigest,
    digest: outcome.digest,
    ruleCount: outcome.rules.length,
  };
}
