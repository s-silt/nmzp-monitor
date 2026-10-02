import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { TLSSocket } from "node:tls";
import { describe, it } from "node:test";
import { sha256Hex } from "./auth.ts";
import { assertPin, pinnedHttps } from "./https-client.ts";
import { readPolicyCache, writePolicyCache } from "./policy-cache.ts";
import { ENGINE_REVISION } from "./policy/engine-revision.ts";
import { createNmzpPolicyDomain, PolicyDomainError } from "./policy/nmzp-domain.ts";
import { policyRulesHash, REWRITE_SEMANTICS_REVISION } from "./policy/nmzp-service.ts";
import { createPolicySnapshot } from "./policy/snapshot.ts";
import { NmzpStore } from "./persist.ts";
import { prepareHookTransport } from "./protocol/evaluate-ingress.ts";
import {
  customSetsAreLocal,
  defaultCustomSet,
  effectiveCustomRules as coreEffectiveCustomRules,
  MAX_CUSTOM_SETS,
  migratePolicyRead,
  parseCustomSets,
  projectDeviceCustomRules,
  type CustomRuleSet,
} from "./schema.ts";
import { startServer, type RunningServer } from "./serve.ts";
import { evaluate, type EvalInput } from "../src/lib/monitor/engine.ts";
import { replayPolicy } from "../src/lib/monitor/policy-replay.ts";
import { effectiveCustomRules as engineEffectiveCustomRules, sanitizeCustomRules } from "../src/lib/monitor/privacy.ts";
import { RULES } from "../src/lib/monitor/rules.ts";
import type { AuditEvent, CustomPrivacyRule } from "../src/lib/monitor/types.ts";

const coreDir = import.meta.dirname;
const TOKEN = "ZWSPSETTOKEN";
const OFF_TOKEN = "ZWSPOFFTOKEN";
const RULE_OFF = "ZWSPRULEOFF";
const DRY = "ZWSPDRYTOKEN";
const KEEP = "ZWSPKEEPTOKEN";

function sha256(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

function catalogHash(rules: readonly unknown[]): string {
  return sha256(JSON.stringify({ rules, rewriteRevision: REWRITE_SEMANTICS_REVISION, engineRevision: ENGINE_REVISION }));
}

function localSet(id: string, enabled = true, name = id): CustomRuleSet {
  return { id, name, enabled, source: "local" };
}

function rule(id: string, match: string, extra: Partial<CustomPrivacyRule> = {}): CustomPrivacyRule {
  return { id, enabled: true, mode: "block", match, kind: "k", replaceWith: "<标签>", ...extra };
}

function bash(command: string): EvalInput {
  return { nativeTool: "Bash", command, agent: "claude", source: "hook" };
}

function domainSource() {
  return {
    RULES: [{ id: "fixture_read" }],
    privacy: {
      MAX_CUSTOM_RULES: 64,
      sanitizeCustomRules,
      compileMatch: (match: string) => {
        try { return new RegExp(match, "i"); } catch { return null; }
      },
    },
    isProtectedRule: () => false,
    protectedDowngrades: () => [] as string[],
  };
}

function devicePolicy(srv: RunningServer, path: string, token: string): Promise<{ status: number; etag?: string; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(new URL(path, srv.url), {
      method: "GET",
      ca: srv.tls.certPem,
      rejectUnauthorized: true,
      agent: false,
      headers: { authorization: `Bearer ${token}` },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        clearTimeout(timer);
        const header = res.headers.etag;
        resolve({
          status: res.statusCode ?? 0,
          etag: Array.isArray(header) ? header[0] : header,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    const timer = setTimeout(() => req.destroy(new Error("test_request_timeout")), 10_000);
    req.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    req.on("socket", (socket) => {
      socket.once("secureConnect", () => {
        try {
          assertPin(socket as TLSSocket, srv.tls.fingerprintSha256);
        } catch (error) {
          clearTimeout(timer);
          req.destroy(error instanceof Error ? error : new Error("tls pin"));
          return;
        }
        req.end();
      });
    });
  });
}

describe("custom set parser", () => {
  it("accepts 64 local sets, unicode names, and a subscription source shape", () => {
    const sets = Array.from({ length: MAX_CUSTOM_SETS }, (_, i) => localSet(`s_${i}`, i % 2 === 0, i === 0 ? "默认" : `n${i}`));
    sets[1] = { ...sets[1]!, name: " " };
    sets[2] = { ...sets[2]!, name: "a".repeat(80) };
    const parsed = parseCustomSets(sets);
    assert.equal(parsed?.length, 64);
    assert.equal(parsed?.[0]?.name, "默认");
    assert.equal(parsed?.[1]?.name, " ");
    assert.equal(parsed?.[2]?.name.length, 80);
    assert.equal(customSetsAreLocal(parsed!), true);

    const remote = parseCustomSets([{ id: "sub", name: " alpha", enabled: false, source: { subscriptionId: "sub_1" } }]);
    assert.deepEqual(remote, [{ id: "sub", name: " alpha", enabled: false, source: { subscriptionId: "sub_1" } }]);
    assert.equal(customSetsAreLocal(remote!), false);
    assert.equal(parseCustomSets([{ id: "sub", name: "n", enabled: true, source: { subscriptionId: "x".repeat(128) } }])?.length, 1);
  });

  it("rejects limits and bad shapes, including a subscription object that is not exactly one string", () => {
    const one = localSet("alpha", true, "Alpha");
    const bad: unknown[] = [
      null,
      {},
      "local",
      Array.from({ length: MAX_CUSTOM_SETS + 1 }, (_, i) => localSet(`s_${i}`)),
      [one, localSet("alpha")],
      [{ ...one, id: "Bad" }],
      [{ ...one, id: "1abc" }],
      [{ ...one, id: "" }],
      [{ ...one, name: "" }],
      [{ ...one, name: "a".repeat(81) }],
      [{ ...one, name: "bad\nname" }],
      [{ ...one, name: "bad\u007fname" }],
      [{ ...one, enabled: "yes" }],
      [{ ...one, source: "remote" }],
      [{ ...one, source: {} }],
      [{ ...one, source: { subscriptionId: "" } }],
      [{ ...one, source: { subscriptionId: "x".repeat(129) } }],
      [{ ...one, source: { subscriptionId: 1 } }],
      [{ ...one, source: { subscriptionId: "ok", extra: 1 } }],
      [{ ...one, source: { subscriptionId: "bad\nid" } }],
      [{ ...one, extra: 1 }],
      [{ id: "alpha", name: "n", enabled: true }],
    ];
    for (const row of bad) assert.equal(parseCustomSets(row), undefined, JSON.stringify(row)?.slice(0, 120));
    const kept = sanitizeCustomRules([rule("p_a", TOKEN, { setId: "alpha" })])!;
    assert.equal(kept[0]?.setId, "alpha");
    assert.equal(kept[0]?.enabled, true);
    assert.equal(sanitizeCustomRules([rule("p_a", TOKEN, { setId: "Bad" })])!.length, 0);
    assert.equal(Object.hasOwn(sanitizeCustomRules([rule("p_a", TOKEN)])![0]!, "setId"), false);
  });

  it("parses a subscription set on read and rejects it on write", () => {
    const domain = createNmzpPolicyDomain(domainSource());
    const sub = { id: "remote", name: "Remote", enabled: true, source: { subscriptionId: "sub_1" } };
    const doc = { version: 1, updatedAt: 1, mode: "enforcing" as const, stopped: false, customRules: [], customSets: [sub] };
    domain.prepare(createPolicySnapshot(doc));
    assert.throws(() => domain.normalizePatch({ customSets: [sub] }), (error: unknown) => error instanceof PolicyDomainError && error.code === "invalid_policy_custom_sets");
    const local = domain.normalizePatch({ customSets: [localSet("alpha", true, "本地")] });
    assert.equal(local.customSets?.[0]?.name, "本地");
    assert.equal(local.customSets?.[0]?.source, "local");
  });
});

describe("custom set migration and policyRulesHash", () => {
  const source = { RULES: [{ id: "synthetic_rule", action: "log" }] };
  const old: { customRules: CustomPrivacyRule[]; customSets?: CustomRuleSet[] } = { customRules: [rule("p_old", TOKEN)] };

  it("migrates a missing customSets field to the default set without rewriting the input", () => {
    const migrated = migratePolicyRead(old);
    assert.equal(old.customSets, undefined);
    assert.deepEqual(migrated.customSets, [defaultCustomSet()]);
    assert.equal(migratePolicyRead(migrated), migrated);
  });

  it("policyRulesHash(source) equals the catalog formula", () => {
    assert.equal(policyRulesHash(source), catalogHash(source.RULES));
    assert.equal(policyRulesHash(source), sha256(JSON.stringify({
      rules: source.RULES,
      rewriteRevision: REWRITE_SEMANTICS_REVISION,
      engineRevision: ENGINE_REVISION,
    })));
  });

  it("toggling a set changes the stored policy hash, policy.version, and the device ETag", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sets-hash-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null, storageMode: "sqlite" });
    const deviceToken = "synthetic-sets-hash";
    const put = (body: unknown) => pinnedHttps({
      url: srv.url + "/api/v1/policy",
      caPem: srv.tls.certPem,
      fingerprintSha256: srv.tls.fingerprintSha256,
      method: "PUT",
      headers: { authorization: `Bearer ${srv.adminToken}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    try {
      await srv.store.putDevice({
        id: "a", tokenHash: sha256Hex(deviceToken), hostname: "fixture", user: "fixture", ip: "127.0.0.1",
        os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [],
      });
      const customRules = [rule("p_on", TOKEN, { setId: "alpha" })];
      const enabled = await put({
        expectedVersion: srv.store.getPolicy().version,
        customRules,
        customSets: [localSet("alpha", true, "Alpha")],
      });
      assert.equal(enabled.status, 200, enabled.body);
      const before = srv.store.capturePolicy();
      const beforeRow = srv.store.getHistoricalPolicy(before.policy.version);
      assert.equal(beforeRow?.hash, before.hash);
      const beforeDevice = await devicePolicy(srv, "/api/v2/policy", deviceToken);
      assert.equal(beforeDevice.status, 200, beforeDevice.body);
      const beforeBody = JSON.parse(beforeDevice.body) as { version: number; rulesHash: string; engineRevision: number };
      const catalog = `sha256:${policyRulesHash({ RULES })}`;
      assert.equal(beforeBody.rulesHash, catalog);
      assert.equal(beforeRow?.rulesHash, policyRulesHash({ RULES }));
      assert.equal(before.policy.version, beforeBody.version);
      assert.equal(srv.store.getPolicy().version, before.policy.version);
      assert.equal(beforeDevice.etag, `"p${beforeBody.version}.${beforeBody.rulesHash.slice(7)}.e${beforeBody.engineRevision}"`);

      const disabled = await put({
        expectedVersion: before.policy.version,
        customSets: [localSet("alpha", false, "Alpha")],
      });
      assert.equal(disabled.status, 200, disabled.body);
      const after = srv.store.capturePolicy();
      const afterRow = srv.store.getHistoricalPolicy(after.policy.version);
      assert.equal(afterRow?.hash, after.hash);
      const afterDevice = await devicePolicy(srv, "/api/v2/policy", deviceToken);
      assert.equal(afterDevice.status, 200, afterDevice.body);
      const afterBody = JSON.parse(afterDevice.body) as { version: number; rulesHash: string; engineRevision: number };
      assert.notEqual(after.hash, before.hash);
      assert.notEqual(after.policy.version, before.policy.version);
      assert.equal(srv.store.getPolicy().version, after.policy.version);
      assert.equal(afterBody.version, after.policy.version);
      assert.equal(afterBody.rulesHash, catalog);
      assert.equal(afterRow?.rulesHash, beforeRow?.rulesHash);
      assert.equal(afterDevice.etag, `"p${afterBody.version}.${afterBody.rulesHash.slice(7)}.e${afterBody.engineRevision}"`);
      assert.notEqual(afterDevice.etag, beforeDevice.etag);
      assert.equal(JSON.parse(disabled.body).customSets[0].enabled, false);
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("shows the default set from JSON and SQLite without rewriting stored bytes", async () => {
    const windowDir = await mkdtemp(join(tmpdir(), "nmzp-sets-json-"));
    const sqliteDir = await mkdtemp(join(tmpdir(), "nmzp-sets-sql-"));
    try {
      const windowStore = new NmzpStore(windowDir);
      await windowStore.load();
      const before = await readFile(windowStore.policyPath());
      assert.equal(JSON.parse(before.toString()).customSets, undefined);
      assert.deepEqual(windowStore.getPolicy().customSets, [defaultCustomSet()]);
      await windowStore.casPolicy(1, { mode: "permissive" });
      const after = await readFile(windowStore.policyPath(), "utf8");
      assert.equal(JSON.parse(after).customSets, undefined);
      assert.equal(windowStore.getPolicy().mode, "permissive");
      await windowStore.close();

      const sqliteStore = new NmzpStore(sqliteDir);
      await sqliteStore.load({ storageMode: "sqlite" });
      assert.deepEqual(sqliteStore.getPolicy().customSets, [defaultCustomSet()]);
      const policyText = await readFile(sqliteStore.policyPath(), "utf8");
      assert.equal(JSON.parse(policyText).customSets, undefined);
      await sqliteStore.close();
      const db = new DatabaseSync(join(sqliteDir, "nmzp.db"), { readOnly: true });
      try {
        const row = db.prepare("SELECT policy_json FROM policy_revisions").get() as { policy_json: string };
        assert.equal(JSON.parse(row.policy_json).customSets, undefined);
      } finally {
        db.close();
      }
    } finally {
      await rm(windowDir, { recursive: true, force: true });
      await rm(sqliteDir, { recursive: true, force: true });
    }
  });
});

describe("custom set evaluation, projection, and cache", () => {
  it("engine and core effectiveCustomRules agree on every set and rule state", async () => {
    const rules = [undefined, "", "default", "on", "off", "missing"].flatMap((setId, i) =>
      [{}, { enabled: false }, { enabled: false, dryRun: true }].map((state, j) => ({ match: `m${i}${j}`, ...(setId === undefined ? {} : { setId }), ...state })));
    for (const sets of [undefined, [], [defaultCustomSet()], [{ id: "default", enabled: false }, { id: "on", enabled: true }, { id: "off", enabled: false }],
      [{ id: "on", enabled: true }, { id: "on", enabled: false }]]) {
      assert.deepEqual(engineEffectiveCustomRules(rules, sets), coreEffectiveCustomRules(rules, sets), JSON.stringify(sets));
    }
    // The policy-compat guard runs the live engine on an older core tree, so the engine must not need newer core exports.
    const privacySource = await readFile(join(coreDir, "../src/lib/monitor/privacy.ts"), "utf8");
    assert.doesNotMatch(privacySource, /from "\.\.\/\.\.\/\.\.\/core\/schema\.ts"/);
  });

  it("drops a disabled set and a plain disabled rule from v1, v2, and replay; device projection keeps every rule in an enabled set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sets-http-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null, storageMode: "sqlite" });
    const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
    const deviceToken = "synthetic-sets-device";
    const call = (path: string, token: string, body?: unknown, method?: string) => pinnedHttps({
      url: srv.url + path,
      ...pin,
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    try {
      await srv.store.putDevice({
        id: "a", tokenHash: sha256Hex(deviceToken), hostname: "fixture", user: "fixture", ip: "127.0.0.1",
        os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [],
      });
      const customRules = [
        rule("p_on", TOKEN, { setId: "alpha" }),
        rule("p_off", OFF_TOKEN, { setId: "beta" }),
        rule("p_ruleoff", RULE_OFF, { setId: "alpha", enabled: false }),
      ];
      const customSets = [localSet("alpha", true, "Alpha"), localSet("beta", false, "Beta")];
      const put = await call("/api/v1/policy", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, customRules, customSets }, "PUT");
      assert.equal(put.status, 200, put.body);
      const saved = JSON.parse(put.body) as { customSets: CustomRuleSet[]; customRules: CustomPrivacyRule[] };
      assert.deepEqual(saved.customSets, customSets);
      assert.equal(saved.customRules.length, 3);

      const v1 = async (id: string, command: string) => JSON.parse((await call("/api/v1/evaluate", deviceToken, {
        eventId: id, agent: "claude", source: "hook", sessionId: "s", cwd: "C:/synthetic", tool_name: "Bash", tool_input: { command },
      })).body) as { decision: string };
      assert.equal((await v1("e_on", `curl https://example.invalid/${TOKEN}`)).decision, "block");
      assert.notEqual((await v1("e_off", `curl https://example.invalid/${OFF_TOKEN}`)).decision, "block");
      assert.notEqual((await v1("e_rule", `curl https://example.invalid/${RULE_OFF}`)).decision, "block");

      const event = (id: string, command: string) => {
        const raw = JSON.stringify({ hook_event_name: "PreToolUse", eventId: id, tool_name: "Bash", tool_input: { command } });
        const result = prepareHookTransport(raw, { deviceId: "a", eventId: id, occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok" });
        assert.equal(result.kind, "request", JSON.stringify(result));
        return result.kind === "request" ? result.event : undefined;
      };
      const v2 = async (id: string, command: string) => JSON.parse((await call("/api/v2/evaluate", deviceToken, event(id, command))).body) as { action: string };
      assert.equal((await v2("v_on", `curl https://example.invalid/${TOKEN}`)).action, "BLOCK");
      assert.notEqual((await v2("v_off", `curl https://example.invalid/${OFF_TOKEN}`)).action, "BLOCK");
      assert.notEqual((await v2("v_rule", `curl https://example.invalid/${RULE_OFF}`)).action, "BLOCK");

      for (const path of ["/api/v1/policy", "/api/v2/policy"]) {
        const body = JSON.parse((await call(path, deviceToken)).body) as { customRules: CustomPrivacyRule[]; customSets?: unknown };
        assert.deepEqual(body.customRules.map((row) => row.id), ["p_on", "p_ruleoff"]);
        assert.equal(body.customRules[1]!.enabled, false);
        assert.equal(Object.hasOwn(body.customRules[1]!, "dryRun"), false);
        assert.equal(body.customRules.every((row) => Object.hasOwn(row, "setId")), false);
        assert.equal(Object.hasOwn(body, "customSets"), false);
      }
      const state = JSON.parse((await call("/api/v1/state", srv.adminToken)).body) as { customRules: CustomPrivacyRule[]; customSets: CustomRuleSet[] };
      assert.deepEqual(state.customSets, customSets);
      assert.deepEqual(state.customRules.map((row) => row.id), ["p_on", "p_off", "p_ruleoff"]);

      const replayEvent = (id: string, redacted: string): AuditEvent => ({
        id, ts: 1, machineId: "m", agent: "claude", sessionId: "s", layer: "app_pre", tool: "Bash", nativeTool: "Bash",
        input: "", risk: "info", decision: "log", category: "shell", workdirScope: "project", redacted,
      });
      const current = { mode: "enforcing" as const, overrides: { rules: {}, families: {} }, customRules: [] as CustomPrivacyRule[], exemptions: [] };
      const hits = (rules: CustomPrivacyRule[], sets?: CustomRuleSet[]) => replayPolicy(
        [replayEvent("e", `curl https://example.invalid/${TOKEN}`)],
        { ...current, customRules: rules, customSets: sets },
        current,
        RULES,
        1,
      ).summary.customHits;
      assert.equal(hits([rule("p_on", TOKEN, { setId: "beta" })], [localSet("beta", false)]), 0);
      assert.equal(hits([rule("p_on", TOKEN, { setId: "alpha" })], [localSet("alpha", true)]), 1);
      assert.equal(hits([rule("p_on", TOKEN, { enabled: false })]), 0);
      assert.equal(replayPolicy(
        [replayEvent("dry", "echo 内部代号=X")],
        { ...current, customRules: [rule("p_dry", "内部代号", { enabled: false, dryRun: true })] },
        current,
        RULES,
        1,
      ).summary.customHits, 1);

      const dangling = await call("/api/v1/policy", srv.adminToken, {
        expectedVersion: srv.store.getPolicy().version,
        customRules: [rule("p_miss", TOKEN, { setId: "missing" })],
      }, "PUT");
      assert.equal(dangling.status, 400, dangling.body);
      assert.equal(JSON.parse(dangling.body).error, "invalid_policy_custom_sets");
      const remote = await call("/api/v1/policy", srv.adminToken, {
        expectedVersion: srv.store.getPolicy().version,
        customSets: [{ id: "sub", name: "Sub", enabled: true, source: { subscriptionId: "sub_1" } }],
      }, "PUT");
      assert.equal(remote.status, 400);
      assert.equal(JSON.parse(remote.body).error, "invalid_policy_custom_sets");
      const still = JSON.parse((await call("/api/v1/policy", deviceToken)).body) as { customRules: CustomPrivacyRule[] };
      assert.deepEqual(still.customRules.map((row) => row.id), ["p_on", "p_ruleoff"]);
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("projects a pre-26c on, plain-off, and dry-run rule unchanged on device GET v1 and v2", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sets-pre-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null, storageMode: "sqlite" });
    const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
    const deviceToken = "synthetic-sets-pre";
    const call = (path: string, token: string, body?: unknown, method?: string) => pinnedHttps({
      url: srv.url + path,
      ...pin,
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    try {
      await srv.store.putDevice({
        id: "a", tokenHash: sha256Hex(deviceToken), hostname: "fixture", user: "fixture", ip: "127.0.0.1",
        os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [],
      });
      const stored = [
        rule("p_on", TOKEN),
        rule("p_off", OFF_TOKEN, { enabled: false }),
        rule("p_dry", DRY, { enabled: false, dryRun: true }),
      ];
      const put = await call("/api/v1/policy", srv.adminToken, { expectedVersion: srv.store.getPolicy().version, customRules: stored }, "PUT");
      assert.equal(put.status, 200, put.body);
      const disk = JSON.parse(await readFile(srv.store.policyPath(), "utf8")) as { customRules: CustomPrivacyRule[]; customSets?: unknown };
      assert.equal(disk.customSets, undefined);
      assert.deepEqual(disk.customRules, stored);
      for (const path of ["/api/v1/policy", "/api/v2/policy"]) {
        const body = JSON.parse((await call(path, deviceToken)).body) as { customRules: CustomPrivacyRule[]; customSets?: unknown };
        assert.deepEqual(body.customRules, disk.customRules);
        assert.equal(Object.hasOwn(body, "customSets"), false);
      }
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("loads a dangling setId without failing and does not evaluate it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sets-dangling-"));
    try {
      const first = new NmzpStore(dir);
      await first.load();
      await first.close();
      const path = first.policyPath();
      const stored = JSON.parse(await readFile(path, "utf8")) as { customRules: CustomPrivacyRule[]; customSets?: unknown };
      stored.customRules = [rule("p_miss", TOKEN, { setId: "missing" }), rule("p_keep", KEEP)];
      delete stored.customSets;
      const bytes = JSON.stringify(stored, null, 2);
      await writeFile(path, bytes);
      const second = new NmzpStore(dir);
      await second.load();
      assert.equal(await readFile(path, "utf8"), bytes);
      const policy = second.getPolicy();
      assert.deepEqual(policy.customSets, [defaultCustomSet()]);
      const miss = evaluate(bash(`curl https://example.invalid/${TOKEN}`), policy.mode, policy.customRules, { customSets: policy.customSets });
      const keep = evaluate(bash(`curl https://example.invalid/${KEEP}`), policy.mode, policy.customRules, { customSets: policy.customSets });
      assert.notEqual(miss.decision, "block");
      assert.equal(keep.decision, "block");
      await second.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("migrates a cache on read, leaves the file unchanged, and the projected cache agrees with core evaluate", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sets-cache-"));
    try {
      const file = join(dir, "cache.json");
      const old = { version: 1, mode: "enforcing" as const, stopped: false, updatedAt: 1, customRules: [rule("p_keep", KEEP), rule("p_miss", TOKEN, { setId: "missing" })] };
      await writePolicyCache(file, old);
      const before = await readFile(file);
      const read = await readPolicyCache(file);
      assert.deepEqual(await readFile(file), before);
      assert.deepEqual(read?.customSets, [defaultCustomSet()]);
      assert.equal(JSON.parse(before.toString()).policy.customSets, undefined);
      const dangling = evaluate(bash(`curl https://example.invalid/${TOKEN}`), "enforcing", read!.customRules, { customSets: read!.customSets });
      assert.notEqual(dangling.decision, "block");

      const sets = [localSet("alpha", true), localSet("beta", false)];
      const full = {
        version: 2, mode: "enforcing" as const, stopped: false, updatedAt: 2, customSets: sets,
        customRules: [
          rule("p_on", TOKEN, { setId: "alpha" }),
          rule("p_plain", RULE_OFF, { setId: "alpha", enabled: false }),
          rule("p_dry", DRY, { setId: "alpha", enabled: false, dryRun: true }),
          rule("p_off", OFF_TOKEN, { setId: "beta" }),
        ],
      };
      await writePolicyCache(file, full);
      const round = await readPolicyCache(file);
      assert.deepEqual(round?.customSets, sets);
      const projected = projectDeviceCustomRules(full.customRules, full.customSets);
      assert.deepEqual(projected.map((row) => row.id), ["p_on", "p_plain", "p_dry"]);
      assert.equal(projected.every((row) => Object.hasOwn(row, "setId")), false);
      const agree = (command: string) => {
        const input = bash(command);
        const core = evaluate(input, "enforcing", full.customRules, { customSets: full.customSets });
        const offline = evaluate(input, "enforcing", projected);
        assert.equal(offline.decision, core.decision);
        assert.deepEqual(offline.dryRunKinds, core.dryRunKinds);
        assert.equal(offline.redacted, core.redacted);
        return core;
      };
      assert.equal(agree(`curl https://example.invalid/${TOKEN}`).decision, "block");
      const plain = agree(`curl https://example.invalid/${RULE_OFF}`);
      assert.notEqual(plain.decision, "block");
      assert.equal(plain.dryRunKinds, undefined);
      const hidden = agree(`curl https://example.invalid/${OFF_TOKEN}`);
      assert.notEqual(hidden.decision, "block");
      const dry = agree(`echo ${DRY}`);
      assert.notEqual(dry.decision, "block");
      assert.deepEqual(dry.dryRunKinds, ["k"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
