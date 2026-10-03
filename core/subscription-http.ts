import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { failJson, json, readLimited } from "./http-util.ts";
import type { NmzpStore } from "./persist.ts";
import { parseCustomSets, resolvedCustomSets, type PolicyState } from "./schema.ts";
import {
  DEFAULT_SUBSCRIPTION_INTERVAL_MINUTES,
  parseSubscriptionInterval,
  parseSubscriptionUrl,
} from "./subscription-schema.ts";
import type { SubscriptionRunner } from "./subscription-runner.ts";
import {
  addSubscription,
  removeSubscription,
  SubscriptionStateError,
  updateSubscription,
  type SubscriptionPatch,
} from "./subscription-state.ts";

interface SubscriptionHttpContext {
  store: NmzpStore;
  runner: SubscriptionRunner | undefined;
  requireAdmin: (req: IncomingMessage, res: ServerResponse) => boolean;
}

const LIST = "/api/v1/policy/subscriptions";
const ITEM_RE = /^\/api\/v1\/policy\/subscriptions\/([a-z][a-z0-9_]{0,63})(\/refresh)?$/;

function nameOk(value: unknown): value is string {
  // Same bounds as a custom set name; parseCustomSets owns them.
  return typeof value === "string" && parseCustomSets([{ id: "probe", name: value, enabled: true, source: "local" }]) !== undefined;
}

function view(policy: PolicyState, runner: SubscriptionRunner | undefined) {
  const sets = resolvedCustomSets(policy.customSets);
  const runtime = runner?.status();
  return (policy.subscriptions ?? []).map((sub) => {
    const set = sets.find((row) => row.id === sub.id);
    return {
      ...sub,
      name: set?.name ?? sub.id,
      rulesEnabled: set?.enabled ?? false,
      ruleCount: policy.customRules.filter((rule) => rule.setId === sub.id).length,
      lastCheckedAt: runtime?.get(sub.id)?.lastCheckedAt ?? null,
      inFlight: runtime?.get(sub.id)?.inFlight ?? false,
    };
  });
}

async function readJson(req: IncomingMessage, res: ServerResponse): Promise<Record<string, unknown> | undefined> {
  const body = await readLimited(req);
  if (!body.ok) {
    json(res, 413, { ok: false, error: "payload_too_large" });
    return undefined;
  }
  let parsed: unknown;
  try { parsed = JSON.parse(body.text || "{}"); }
  catch {
    json(res, 400, { ok: false, error: "bad_json" });
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    json(res, 400, { ok: false, error: "bad_json" });
    return undefined;
  }
  return parsed as Record<string, unknown>;
}

function newSubscriptionId(policy: PolicyState): string {
  const taken = new Set([...resolvedCustomSets(policy.customSets).map((set) => set.id), ...(policy.subscriptions ?? []).map((sub) => sub.id)]);
  for (;;) {
    const id = `sub_${randomBytes(6).toString("hex")}`;
    if (!taken.has(id)) return id;
  }
}

/**
 * WP-26d admin routes. Adding, changing, deleting and manually refreshing a feed are admin-only.
 * Writes are CAS on expectedVersion, like PUT /api/v1/policy; the runner's own writes are not.
 */
export async function handleSubscriptionHttp(req: IncomingMessage, res: ServerResponse, pathname: string,
  context: SubscriptionHttpContext): Promise<boolean> {
  const item = ITEM_RE.exec(pathname);
  if (pathname !== LIST && !item) return false;
  if (!context.requireAdmin(req, res)) return true;
  const { store, runner } = context;
  const method = req.method ?? "GET";
  const fail = (status: number, code: string): true => {
    failJson(res, status, code);
    return true;
  };

  if (pathname === LIST && method === "GET") {
    const policy = store.getPolicy();
    json(res, 200, { ok: true, version: policy.version, subscriptions: view(policy, runner) });
    return true;
  }

  if (item?.[2] === "/refresh") {
    if (method !== "POST") {
      json(res, 405, { ok: false, error: "method_not_allowed" });
      return true;
    }
    const id = item[1]!;
    if (!store.getPolicy().subscriptions?.some((sub) => sub.id === id)) {
      failJson(res, 404, "subscription_not_found");
      return true;
    }
    if (!runner) {
      failJson(res, 503, "subscription_runner_unavailable");
      return true;
    }
    const outcome = await runner.refresh(id);
    if (outcome.result === "missing") {
      failJson(res, 404, "subscription_not_found");
      return true;
    }
    json(res, 200, { ok: true, ...outcome });
    return true;
  }

  const allowed = pathname === LIST ? method === "POST" : method === "PATCH" || method === "DELETE";
  if (!allowed) {
    json(res, 405, { ok: false, error: "method_not_allowed" });
    return true;
  }
  const body = await readJson(req, res);
  if (!body) return true;
  const expectedVersion = body.expectedVersion;
  const policy = store.getPolicy();
  if (!Number.isSafeInteger(expectedVersion) || (expectedVersion as number) < 1) {
    json(res, 409, { ok: false, error: "cas_conflict", version: policy.version });
    return true;
  }

  let patch: SubscriptionPatch;
  let id: string;
  try {
    if (pathname === LIST) {
      const url = parseSubscriptionUrl(body.url);
      if (!url) return fail(400, "invalid_subscription_url");
      const interval = body.intervalMinutes === undefined ? DEFAULT_SUBSCRIPTION_INTERVAL_MINUTES : parseSubscriptionInterval(body.intervalMinutes);
      if (interval === undefined) return fail(400, "invalid_subscription_interval");
      const name = body.name === undefined ? new URL(url).hostname : body.name;
      if (!nameOk(name)) return fail(400, "invalid_subscription_name");
      id = newSubscriptionId(policy);
      patch = addSubscription(policy, { id, url, name, intervalMinutes: interval });
    } else {
      id = item![1]!;
      if (method === "DELETE") patch = removeSubscription(policy, id);
      else {
        for (const key of Object.keys(body)) {
          if (!["expectedVersion", "enabled", "intervalMinutes", "name"].includes(key)) return fail(400, "invalid_subscription_patch");
        }
        if (body.enabled !== undefined && typeof body.enabled !== "boolean") return fail(400, "invalid_subscription_patch");
        const interval = body.intervalMinutes === undefined ? undefined : parseSubscriptionInterval(body.intervalMinutes);
        if (body.intervalMinutes !== undefined && interval === undefined) return fail(400, "invalid_subscription_interval");
        if (body.name !== undefined && !nameOk(body.name)) return fail(400, "invalid_subscription_name");
        patch = updateSubscription(policy, id, {
          enabled: body.enabled as boolean | undefined,
          intervalMinutes: interval,
          name: body.name as string | undefined,
        });
      }
    }
  } catch (error) {
    if (!(error instanceof SubscriptionStateError)) throw error;
    failJson(res, error.code === "subscription_not_found" ? 404 : 400, error.code);
    return true;
  }

  const written = await store.casSubscriptions(expectedVersion as number, patch);
  if ("conflict" in written) {
    json(res, 409, { ok: false, error: "cas_conflict", version: written.version });
    return true;
  }
  const after = view(written, runner).find((sub) => sub.id === id);
  if (pathname === LIST && runner) {
    // First fetch runs in the background; its outcome lands in lastError/lastDigest.
    void runner.refresh(id).catch((error: unknown) => {
      process.stderr.write(`subscription_refresh_failed ${id} ${error instanceof Error ? error.message : "unknown"}\n`);
    });
  }
  json(res, 200, { ok: true, version: written.version, subscription: after ?? null });
  return true;
}
