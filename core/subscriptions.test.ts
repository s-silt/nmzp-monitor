import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { sha256Hex } from "./auth.ts";
import { pinnedHttps } from "./https-client.ts";
import { NmzpStore } from "./persist.ts";
import { PolicyDomainError } from "./policy/nmzp-domain.ts";
import type { CustomPrivacyRule, PolicyState, StoredEvent } from "./schema.ts";
import { startServer, type RunningServer } from "./serve.ts";
import { fetchSubscription, isPublicAddress } from "./subscription-fetch.ts";
import { SubscriptionRunner, type SubscriptionFetcher } from "./subscription-runner.ts";
import { MAX_SUBSCRIPTIONS, parsePolicySubscriptions, parseSubscriptionUrl, type PolicySubscription } from "./subscription-schema.ts";
import { addSubscription, applyFetchOutcome, subscriptionRules, subscriptionsConsistent } from "./subscription-state.ts";
import { loadOrCreateTls } from "./tls.ts";
import { MAX_CUSTOM_RULES, sanitizeCustomRules } from "../src/lib/monitor/privacy.ts";

const coreDir = import.meta.dirname;
const ONE = "ZWSPSUBONE";
const TWO = "ZWSPSUBTWO";
const LOCAL = "ZWSPSUBLOCAL";
const FEED = "https://rules.example.com/feed.json";

function sub(id: string, extra: Partial<PolicySubscription> = {}): PolicySubscription {
  return { id, url: FEED, enabled: true, intervalMinutes: 60, ...extra };
}

function localRule(id: string, match: string, setId?: string): CustomPrivacyRule {
  return sanitizeCustomRules([{ id, match, mode: "block", ...(setId ? { setId } : {}) }])![0]!;
}

function isDomainError(code: string) {
  return (error: unknown) => error instanceof PolicyDomainError && error.code === code;
}

describe("subscription schema", () => {
  it("accepts only normalized https urls without credentials or fragments", () => {
    assert.equal(parseSubscriptionUrl("https://Rules.Example.com/a?b=1"), "https://rules.example.com/a?b=1");
    for (const bad of ["http://rules.example.com/", "https://u:p@rules.example.com/", "https://rules.example.com/#x",
      "file:///etc/passwd", "https://", "", 7, "https://rules.example.com/é"]) {
      assert.equal(parseSubscriptionUrl(bad), undefined, String(bad));
    }
  });

  it("parses the stored shape and rejects anything else", () => {
    const full = sub("sub_a", { lastFetchedAt: 5, lastEtag: "W/\"x\"", lastDigest: "a".repeat(64), lastError: "http_404" });
    assert.deepEqual(parsePolicySubscriptions([full]), [full]);
    const bad: unknown[] = [
      [{ ...sub("sub_a"), extra: 1 }],
      [sub("Sub")],
      [sub("sub_a"), sub("sub_a")],
      [sub("sub_a", { intervalMinutes: 59 })],
      [sub("sub_a", { intervalMinutes: 60.5 })],
      [sub("sub_a", { url: "https://Rules.example.com/" })],
      [sub("sub_a", { lastDigest: "xyz" })],
      [sub("sub_a", { lastError: "Bad Code" })],
      [sub("sub_a", { lastEtag: "a\nb" })],
      Array.from({ length: MAX_SUBSCRIPTIONS + 1 }, (_, i) => sub(`sub_${i}`)),
      {},
    ];
    for (const raw of bad) assert.equal(parsePolicySubscriptions(raw), undefined, JSON.stringify(raw).slice(0, 80));
  });
});

describe("subscription address guard", () => {
  it("allows only public unicast", () => {
    for (const ok of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001:80e::200e"]) assert.equal(isPublicAddress(ok), true, ok);
    for (const bad of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
      "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1",
      "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
      "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:db8::1", "2001::1", "fe80::1%eth0", "not-an-ip"]) {
      assert.equal(isPublicAddress(bad), false, bad);
    }
  });
});

describe("subscription content", () => {
  it("namespaces ids, pins the feed set and ignores upstream setId", () => {
    const parsed = subscriptionRules("sub_a", { rules: [{ id: "one", match: ONE, setId: "default" }, { match: TWO, mode: "replace" }] }, sanitizeCustomRules, MAX_CUSTOM_RULES);
    assert.ok(parsed.ok);
    assert.deepEqual(parsed.rules.map((rule) => [rule.id, rule.setId, rule.mode]), [["sub_a_one", "sub_a", "block"], ["sub_a_r1", "sub_a", "replace"]]);
    const bare = subscriptionRules("sub_a", [{ match: TWO, mode: "replace" }, { match: ONE, id: "one" }].reverse(), sanitizeCustomRules, MAX_CUSTOM_RULES);
    assert.ok(bare.ok);
    // Digest is over normalized rules, so key order and whitespace in the body do not matter.
    const reordered = subscriptionRules("sub_a", [{ id: "one", match: ONE }, { mode: "replace", match: TWO }], sanitizeCustomRules, MAX_CUSTOM_RULES);
    assert.ok(reordered.ok);
    assert.equal(bare.digest, parsed.digest);
    assert.equal(reordered.digest, parsed.digest);
    assert.match(bare.digest, /^[0-9a-f]{64}$/);
    const changed = subscriptionRules("sub_a", [{ id: "one", match: ONE }], sanitizeCustomRules, MAX_CUSTOM_RULES);
    assert.ok(changed.ok);
    assert.notEqual(changed.digest, parsed.digest);
  });

  it("fails the whole snapshot on any row the sanitizer would drop", () => {
    const codes = [
      subscriptionRules("sub_a", { nope: [] }, sanitizeCustomRules, 64),
      subscriptionRules("sub_a", [{ match: ONE }, { match: "x" }], sanitizeCustomRules, 64),
      subscriptionRules("sub_a", [{ match: ONE }, { match: ONE.toLowerCase() }], sanitizeCustomRules, 64),
      subscriptionRules("sub_a", [{ match: ONE }, "str"], sanitizeCustomRules, 64),
      subscriptionRules("sub_a", [{ match: ONE }, { match: TWO }], sanitizeCustomRules, 1),
    ].map((row) => (row.ok ? "ok" : row.code));
    assert.deepEqual(codes, ["invalid_format", "invalid_rules", "invalid_rules", "invalid_rules", "too_many_rules"]);
  });

  it("publishes only on content or error-state changes and keeps rules on failure", () => {
    const base = addSubscription({ customRules: [localRule("p_local", LOCAL)] }, { id: "sub_a", url: FEED, name: "Feed", intervalMinutes: 60 });
    assert.ok(subscriptionsConsistent(base));
    const parsed = subscriptionRules("sub_a", [{ id: "one", match: ONE }], sanitizeCustomRules, 64);
    assert.ok(parsed.ok);
    const first = applyFetchOutcome(base, "sub_a", { kind: "ok", rules: parsed.rules, digest: parsed.digest, etag: "\"e1\"" }, 10, 64);
    assert.equal(first.result, "updated");
    assert.equal(first.previousDigest, undefined);
    const after = first.patch!;
    assert.deepEqual(after.customRules.map((rule) => rule.id), ["p_local", "sub_a_one"]);
    assert.deepEqual(after.subscriptions[0], { ...sub("sub_a"), lastDigest: parsed.digest, lastEtag: "\"e1\"", lastFetchedAt: 10 });

    assert.equal(applyFetchOutcome(after, "sub_a", { kind: "ok", rules: parsed.rules, digest: parsed.digest }, 20, 64).patch, undefined);
    assert.equal(applyFetchOutcome(after, "sub_a", { kind: "not_modified" }, 20, 64).patch, undefined);

    const failed = applyFetchOutcome(after, "sub_a", { kind: "error", code: "http_500" }, 30, 64);
    assert.equal(failed.result, "error");
    assert.deepEqual(failed.patch!.customRules, after.customRules);
    assert.equal(failed.patch!.subscriptions[0]!.lastError, "http_500");
    assert.equal(failed.patch!.subscriptions[0]!.lastFetchedAt, 10);
    assert.equal(applyFetchOutcome(failed.patch!, "sub_a", { kind: "error", code: "http_500" }, 40, 64).patch, undefined);
    const healed = applyFetchOutcome(failed.patch!, "sub_a", { kind: "not_modified" }, 50, 64);
    assert.equal(healed.patch!.subscriptions[0]!.lastError, undefined);
    assert.equal(healed.patch!.subscriptions[0]!.lastFetchedAt, 50);

    const clash = subscriptionRules("sub_a", [{ match: LOCAL.toLowerCase() }], sanitizeCustomRules, 64);
    assert.ok(clash.ok);
    assert.equal(applyFetchOutcome(after, "sub_a", { kind: "ok", rules: clash.rules, digest: clash.digest }, 60, 64).error, "duplicate_match");
    const two = subscriptionRules("sub_a", [{ match: ONE }, { match: TWO }], sanitizeCustomRules, 64);
    assert.ok(two.ok);
    assert.equal(applyFetchOutcome(after, "sub_a", { kind: "ok", rules: two.rules, digest: two.digest }, 60, 2).error, "rule_limit");
    assert.equal(applyFetchOutcome(after, "sub_missing", { kind: "not_modified" }, 60, 64).result, "missing");
  });
});

describe("subscription writes through the policy service", () => {
  it("keeps feed state out of reach of admin writes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-subs-store-"));
    const store = new NmzpStore(dir);
    try {
      await store.load();
      const v1 = store.getPolicy();
      await assert.rejects(store.casPolicy(v1.version, { subscriptions: [sub("sub_a")] } as never), isDomainError("invalid_policy_subscriptions"));
      const added = await store.casSubscriptions(v1.version, addSubscription(v1, { id: "sub_a", url: FEED, name: "Feed", intervalMinutes: 60 }));
      assert.ok(!("conflict" in added));
      const parsed = subscriptionRules("sub_a", [{ id: "one", match: ONE }], sanitizeCustomRules, 64);
      assert.ok(parsed.ok);
      const fetched = applyFetchOutcome(added, "sub_a", { kind: "ok", rules: parsed.rules, digest: parsed.digest }, 1, 64);
      const withRules = await store.casSubscriptions(added.version, fetched.patch!);
      assert.ok(!("conflict" in withRules));
      const feedRule = withRules.customRules.find((rule) => rule.setId === "sub_a")!;

      // A client that only knows local rules and sets cannot drop the feed.
      const local = await store.casPolicy(withRules.version, {
        customRules: [localRule("p_local", LOCAL)],
        customSets: [{ id: "default", name: "default", enabled: true, source: "local" }],
      });
      assert.ok(!("conflict" in local));
      assert.deepEqual(local.customRules.map((rule) => rule.id), ["p_local", "sub_a_one"]);
      assert.deepEqual(local.customSets!.map((set) => set.id), ["default", "sub_a"]);
      assert.deepEqual(local.subscriptions!.map((row) => row.id), ["sub_a"]);

      // Echoing a feed set may rename it; echoing its rules unchanged is fine. enabled stays with the feed.
      await assert.rejects(store.casPolicy(local.version, {
        customSets: local.customSets!.map((set) => (set.id === "sub_a" ? { ...set, enabled: false } : set)),
      }), isDomainError("invalid_policy_custom_sets"));
      const toggled = await store.casPolicy(local.version, {
        customRules: local.customRules,
        customSets: local.customSets!.map((set) => (set.id === "sub_a" ? { ...set, name: "Renamed" } : set)),
      });
      assert.ok(!("conflict" in toggled));
      assert.equal(toggled.customSets!.find((set) => set.id === "sub_a")!.name, "Renamed");
      assert.equal(subscriptionsConsistent({ ...toggled, subscriptions: [{ ...toggled.subscriptions![0]!, enabled: false }] }), false);

      await assert.rejects(store.casPolicy(toggled.version, {
        customRules: [localRule("p_local", LOCAL), { ...feedRule, mode: "replace" }],
      }), isDomainError("invalid_custom_rules"));
      await assert.rejects(store.casPolicy(toggled.version, {
        customRules: [localRule("p_local", LOCAL), localRule("p_sneak", TWO, "sub_a")],
      }), isDomainError("invalid_custom_rules"));
      await assert.rejects(store.casPolicy(toggled.version, {
        customSets: [...toggled.customSets!, { id: "sub_b", name: "Fake", enabled: true, source: { subscriptionId: "sub_b" } }],
      }), isDomainError("invalid_policy_custom_sets"));
      await assert.rejects(store.casPolicy(toggled.version, {
        customSets: toggled.customSets!.map((set) => (set.id === "sub_a" ? { ...set, source: "local" as const } : set)),
      }), isDomainError("invalid_policy_custom_sets"));
      // The trusted writer still checks one set per feed.
      await assert.rejects(store.casSubscriptions(toggled.version, {
        customRules: toggled.customRules, customSets: toggled.customSets!, subscriptions: [],
      }), isDomainError("invalid_policy_subscriptions"));

      await store.close();
      const reopened = new NmzpStore(dir);
      await reopened.load();
      assert.deepEqual(reopened.getPolicy().subscriptions, toggled.subscriptions);
      await reopened.close();
    } finally {
      await store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

interface Route {
  status: number;
  headers?: Record<string, string>;
  body?: string;
  delayMs?: number;
}

async function feedServer(dir: string, routes: Record<string, (headers: Record<string, string | string[] | undefined>) => Route>) {
  const tls = await loadOrCreateTls(dir, ["127.0.0.1", "localhost"]);
  const server: Server = createServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
    const route = routes[req.url ?? ""]?.(req.headers) ?? { status: 404 };
    const send = () => {
      res.writeHead(route.status, route.headers ?? {});
      res.end(route.body ?? "");
    };
    if (route.delayMs) setTimeout(send, route.delayMs);
    else send();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    tls,
    port,
    close: () => new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
}

describe("subscription fetch", () => {
  it("refuses private targets before connecting, including mixed DNS answers", async () => {
    assert.deepEqual(await fetchSubscription("https://127.0.0.1:1/feed"), { kind: "error", code: "address_blocked" });
    assert.deepEqual(await fetchSubscription("https://[::1]:1/feed"), { kind: "error", code: "address_blocked" });
    const mixed = async () => [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }];
    assert.deepEqual(await fetchSubscription("https://rules.example.com/feed", { resolve: mixed }), { kind: "error", code: "address_blocked" });
    const none = async () => [];
    assert.deepEqual(await fetchSubscription("https://rules.example.com/feed", { resolve: none }), { kind: "error", code: "dns_failed" });
    assert.deepEqual(await fetchSubscription("http://rules.example.com/feed"), { kind: "error", code: "invalid_url" });
  });

  it("handles etag, size cap, redirects, encoding and the deadline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-subs-fetch-"));
    const body = JSON.stringify({ rules: [{ id: "one", match: ONE }] });
    const srv = await feedServer(dir, {
      "/feed": (headers) => (headers["if-none-match"] === "\"e1\"" ? { status: 304 } : { status: 200, headers: { etag: "\"e1\"", "content-type": "application/json" }, body }),
      "/big": () => ({ status: 200, body: "[" + " ".repeat(300 * 1024) + "]" }),
      "/same": () => ({ status: 302, headers: { location: "/feed" } }),
      "/loop": () => ({ status: 302, headers: { location: "/loop" } }),
      "/cross": () => ({ status: 302, headers: { location: `https://127.0.0.1:${srv.port}/feed` } }),
      "/plain": () => ({ status: 302, headers: { location: "http://localhost/feed" } }),
      "/gzip": () => ({ status: 200, headers: { "content-encoding": "gzip" }, body: "x" }),
      "/bad": () => ({ status: 200, body: "{nope" }),
      "/gone": () => ({ status: 410 }),
      "/bigredirect": () => ({ status: 302, headers: { location: "/feed" }, body: " ".repeat(2 * 1024 * 1024) }),
      "/bigerror": () => ({ status: 500, body: " ".repeat(2 * 1024 * 1024) }),
      "/slow": () => ({ status: 200, body, delayMs: 2_000 }),
    });
    const seams = {
      ca: srv.tls.certPem,
      addressAllowed: () => true,
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
    };
    const at = (path: string) => `https://localhost:${srv.port}${path}`;
    try {
      assert.deepEqual(await fetchSubscription(at("/feed"), seams), { kind: "ok", body: JSON.parse(body), etag: "\"e1\"" });
      assert.deepEqual(await fetchSubscription(at("/feed"), { ...seams, etag: "\"e1\"" }), { kind: "not_modified" });
      assert.equal((await fetchSubscription(at("/same"), seams)).kind, "ok");
      assert.equal((await fetchSubscription(at("/bigredirect"), seams)).kind, "ok");
      const codes = await Promise.all(["/big", "/loop", "/cross", "/plain", "/gzip", "/bad", "/gone", "/bigerror"].map(async (path) => {
        const result = await fetchSubscription(at(path), seams);
        return result.kind === "error" ? result.code : result.kind;
      }));
      assert.deepEqual(codes, ["too_large", "redirect_limit", "redirect_cross_host", "redirect_invalid", "unsupported_encoding", "invalid_json", "http_410", "http_500"]);
      const started = Date.now();
      assert.deepEqual(await fetchSubscription(at("/slow"), { ...seams, timeoutMs: 300 }), { kind: "error", code: "timeout" });
      assert.ok(Date.now() - started < 1_500);
      // Default CA store does not trust the fixture certificate.
      assert.deepEqual(await fetchSubscription(at("/feed"), { ...seams, ca: undefined }), { kind: "error", code: "tls_error" });
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("subscription routes", () => {
  it("adds, refreshes, disables and removes a feed; devices only see projected rules", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-subs-http-"));
    let feed: { kind: "ok"; body: unknown; etag?: string } | { kind: "error"; code: string } = {
      kind: "ok", body: { rules: [{ id: "one", match: ONE }] }, etag: "\"e1\"",
    };
    const calls: Array<{ url: string; etag?: string }> = [];
    const fetcher: SubscriptionFetcher = async (url, options) => {
      calls.push({ url, etag: options.etag });
      if (options.etag === "\"e1\"" && feed.kind === "ok" && feed.etag === "\"e1\"") return { kind: "not_modified" };
      return feed;
    };
    const srv: RunningServer = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null, storageMode: "sqlite", subscriptionFetch: fetcher });
    const deviceToken = "synthetic-subs-device";
    const call = (path: string, token: string, body?: unknown, method?: string) => pinnedHttps({
      url: srv.url + path,
      caPem: srv.tls.certPem,
      fingerprintSha256: srv.tls.fingerprintSha256,
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const parsed = async (path: string, token: string, body?: unknown, method?: string) => {
      const res = await call(path, token, body, method);
      return { status: res.status, body: JSON.parse(res.body) as Record<string, unknown> };
    };
    const until = async (check: () => boolean) => {
      for (let i = 0; i < 500 && !check(); i++) await new Promise((resolve) => setTimeout(resolve, 20));
      assert.ok(check());
    };
    try {
      await srv.store.putDevice({
        id: "a", tokenHash: sha256Hex(deviceToken), hostname: "fixture", user: "fixture", ip: "127.0.0.1",
        os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [],
      });
      assert.equal((await call("/api/v1/policy/subscriptions", deviceToken)).status, 401);
      assert.equal((await call("/api/v1/policy/subscriptions", deviceToken, { expectedVersion: 1, url: FEED })).status, 401);
      const badUrl = await parsed("/api/v1/policy/subscriptions", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, url: "http://x.example/" });
      assert.deepEqual([badUrl.status, badUrl.body.error], [400, "invalid_subscription_url"]);
      const badInterval = await parsed("/api/v1/policy/subscriptions", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, url: FEED, intervalMinutes: 30 });
      assert.deepEqual([badInterval.status, badInterval.body.error], [400, "invalid_subscription_interval"]);
      const viaPut = await parsed("/api/v1/policy", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, subscriptions: [sub("sub_a")] }, "PUT");
      assert.deepEqual([viaPut.status, viaPut.body.error], [400, "invalid_policy_subscriptions"]);

      const created = await parsed("/api/v1/policy/subscriptions", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, url: FEED, name: "Team feed" });
      assert.equal(created.status, 200, JSON.stringify(created.body));
      const id = (created.body.subscription as { id: string }).id;
      assert.match(id, /^sub_[0-9a-f]{12}$/);
      // The first fetch runs in the background and appends its audit row after publishing,
      // so wait for the row itself, not just the rules (slow runners see the gap).
      const auditRows = () => srv.store.listEvents().filter((event) => event.source === "policy_subscription").length;
      await until(() => srv.store.getPolicy().customRules.some((rule) => rule.setId === id) && auditRows() === 1);
      const afterFirst = srv.store.getPolicy();
      assert.equal(afterFirst.subscriptions![0]!.lastEtag, "\"e1\"");
      assert.deepEqual(afterFirst.customSets!.find((set) => set.id === id), { id, name: "Team feed", enabled: true, source: { subscriptionId: id } });

      const device = await parsed("/api/v1/policy", deviceToken);
      assert.equal(device.body.subscriptions, undefined);
      const fromFeed = (rules: CustomPrivacyRule[]) => rules.filter((rule) => rule.id.startsWith(`${id}_`));
      assert.deepEqual(fromFeed(device.body.customRules as CustomPrivacyRule[]).map((rule) => [rule.id, rule.setId]), [[`${id}_one`, undefined]]);
      const state = await parsed("/api/v1/state", srv.adminToken);
      assert.equal((state.body.subscriptions as PolicySubscription[])[0]!.id, id);
      const audit = srv.store.listEvents().filter((event) => event.source === "policy_subscription");
      assert.equal(audit.length, 1);
      assert.equal(JSON.parse(audit[0]!.redacted).subscriptionId, id);
      assert.equal(audit[0]!.redacted.includes(ONE), false);
      // Neither the feed URL nor its host reaches events, which the LAN viewer projects.
      assert.equal(audit[0]!.dest, undefined);
      assert.equal(JSON.stringify(audit[0]).includes("rules.example.com"), false);

      // Unchanged: 304 via the stored ETag, no new policy version.
      const unchanged = await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {});
      assert.deepEqual([unchanged.status, unchanged.body.result, unchanged.body.version], [200, "unchanged", afterFirst.version]);
      assert.equal(calls.at(-1)!.etag, "\"e1\"");

      // Failure keeps the last good rules and records the code once.
      feed = { kind: "error", code: "http_503" };
      const failed = await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {});
      assert.deepEqual([failed.body.result, failed.body.error], ["error", "http_503"]);
      assert.equal(srv.store.getPolicy().subscriptions![0]!.lastError, "http_503");
      assert.ok(srv.store.getPolicy().customRules.some((rule) => rule.id === `${id}_one`));
      const failedVersion = srv.store.getPolicy().version;
      await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {});
      assert.equal(srv.store.getPolicy().version, failedVersion);

      // New content replaces the feed's rules. The audit row survives a failed append and is
      // written on the next refresh.
      const append = srv.store.appendEvent.bind(srv.store);
      srv.store.appendEvent = async () => { throw new Error("audit_storage_unavailable"); };
      feed = { kind: "ok", body: [{ id: "two", match: TWO }], etag: "\"e2\"" };
      const updated = await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {});
      assert.equal(updated.body.result, "updated");
      assert.deepEqual(fromFeed(srv.store.getPolicy().customRules).map((rule) => rule.id), [`${id}_two`]);
      assert.equal(srv.store.getPolicy().subscriptions![0]!.lastError, undefined);
      assert.equal(auditRows(), 1);
      srv.store.appendEvent = append;
      assert.equal((await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {})).body.result, "unchanged");
      assert.equal(auditRows(), 2);

      const list = await parsed("/api/v1/policy/subscriptions", srv.adminToken);
      const row = (list.body.subscriptions as Array<Record<string, unknown>>)[0]!;
      assert.deepEqual([row.name, row.ruleCount, row.rulesEnabled, row.inFlight], ["Team feed", 1, true, false]);
      assert.equal(typeof row.lastCheckedAt, "number");

      const stale = await parsed(`/api/v1/policy/subscriptions/${id}`, srv.adminToken, { expectedVersion: 1, enabled: false }, "PATCH");
      assert.equal(stale.status, 409);
      const disabled = await parsed(`/api/v1/policy/subscriptions/${id}`, srv.adminToken, { expectedVersion: srv.store.getPolicy().version, enabled: false, intervalMinutes: 120 }, "PATCH");
      assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
      assert.deepEqual(fromFeed((await parsed("/api/v1/policy", deviceToken)).body.customRules as CustomPrivacyRule[]), []);
      assert.equal(srv.store.getPolicy().subscriptions![0]!.intervalMinutes, 120);

      const removed = await parsed(`/api/v1/policy/subscriptions/${id}`, srv.adminToken, { expectedVersion: srv.store.getPolicy().version }, "DELETE");
      assert.equal(removed.status, 200, JSON.stringify(removed.body));
      const end = srv.store.getPolicy();
      assert.deepEqual([end.subscriptions, end.customRules.filter((rule) => rule.setId === id), end.customSets!.map((set) => set.id)], [[], [], ["default"]]);
      const missing = await parsed(`/api/v1/policy/subscriptions/${id}/refresh`, srv.adminToken, {});
      assert.deepEqual([missing.status, missing.body.error], [404, "subscription_not_found"]);
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("subscription runner", () => {
  function stubStore(initial: PolicyState) {
    let policy = initial;
    const stub = {
      conflicts: 0,
      appendFails: false,
      appended: [] as StoredEvent[],
      getPolicy: () => structuredClone(policy),
      casSubscriptions: async (expected: number, patch: Pick<PolicyState, "customRules" | "customSets" | "subscriptions">) => {
        await new Promise((resolve) => setImmediate(resolve));
        if (stub.conflicts > 0 || expected !== policy.version) {
          stub.conflicts = Math.max(0, stub.conflicts - 1);
          return { conflict: true as const, version: policy.version };
        }
        policy = { ...policy, ...structuredClone(patch), version: policy.version + 1 };
        return structuredClone(policy);
      },
      appendEvent: async (event: StoredEvent) => {
        await new Promise((resolve) => setImmediate(resolve));
        if (stub.appendFails) throw new Error("audit_storage_unavailable");
        stub.appended.push(event);
        return event;
      },
    };
    return stub;
  }

  function twoFeeds(): PolicyState {
    const base: PolicyState = { version: 1, mode: "enforcing", customRules: [], stopped: false, updatedAt: 0 };
    const one = addSubscription(base, { id: "sub_a", url: FEED, name: "A", intervalMinutes: 60 });
    const two = addSubscription({ ...base, ...one }, { id: "sub_b", url: FEED + "?b", name: "B", intervalMinutes: 60 });
    return { ...base, ...two };
  }

  const privacy = { sanitizeCustomRules, MAX_CUSTOM_RULES };

  it("retries only the write after CAS conflicts, without refetching", async () => {
    const store = stubStore(twoFeeds());
    let fetches = 0;
    let now = 1_000;
    const runner = new SubscriptionRunner({
      store: store as never, privacy, now: () => now,
      fetch: async (url) => { fetches++; return { kind: "ok", body: [{ id: "x", match: url.endsWith("?b") ? TWO : ONE }] }; },
    });
    try {
      store.conflicts = 3;
      assert.deepEqual(await runner.refresh("sub_a"), { result: "error", error: "policy_conflict" });
      assert.equal(fetches, 1);
      now += 60_000;
      await runner.runDueNow();
      // sub_a: pending write applied, no new request. sub_b: never fetched, so due now.
      assert.equal(fetches, 2);
      assert.deepEqual(store.getPolicy().customRules.map((rule) => rule.id).sort(), ["sub_a_x", "sub_b_x"]);
      await runner.runDueNow();
      assert.equal(fetches, 2);
    } finally {
      await runner.close();
    }
  });

  it("drains queued audit rows once each under concurrent refreshes", async () => {
    const store = stubStore(twoFeeds());
    const bodies: Record<string, unknown> = { [FEED]: [{ match: ONE }], [FEED + "?b"]: [{ match: TWO }] };
    const runner = new SubscriptionRunner({ store: store as never, privacy, fetch: async (url) => ({ kind: "ok", body: bodies[url] }) });
    try {
      store.appendFails = true;
      await runner.refresh("sub_a");
      await runner.refresh("sub_b");
      assert.equal(runner.pendingAuditCount, 2);
      store.appendFails = false;
      bodies[FEED] = [{ match: ONE }, { match: LOCAL }];
      bodies[FEED + "?b"] = [{ match: TWO }, { match: "ZWSPSUBTHREE" }];
      await Promise.all([runner.refresh("sub_a"), runner.refresh("sub_b"), runner.runDueNow()]);
      assert.equal(runner.pendingAuditCount, 0);
      const ids = store.appended.map((event) => event.id);
      assert.equal(new Set(ids).size, ids.length);
      assert.deepEqual(store.appended.map((event) => JSON.parse(event.redacted).subscriptionId).sort(), ["sub_a", "sub_a", "sub_b", "sub_b"]);
    } finally {
      await runner.close();
    }
  });
});
