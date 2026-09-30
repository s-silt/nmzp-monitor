import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadMonitor } from "./paths.ts";
import { NmzpStore } from "./persist.ts";
import { startServer } from "./serve.ts";
import { pinnedHttps } from "./https-client.ts";
import { policyRulesHash, REWRITE_SEMANTICS_REVISION } from "./policy/nmzp-service.ts";
import { ENGINE_REVISION } from "./policy/engine-revision.ts";
import { evaluationBinding, evaluateDurably } from "./evaluation-application.ts";
import { prepareHookTransport, prepareCanonicalEvaluation } from "./protocol/evaluate-ingress.ts";
import { RULES, RULE_BY_ID } from "../src/lib/monitor/rules.ts";
import { evaluate } from "../src/lib/monitor/engine.ts";
import { activeExemption } from "../src/lib/monitor/overrides.ts";
import { exemptionSubjects } from "../src/lib/monitor/exemption-scope.ts";

const core = dirname(fileURLToPath(import.meta.url)), root = dirname(core);
const monitor = await loadMonitor(core);
const formula = rules => createHash("sha256").update(JSON.stringify({ rules, rewriteRevision: REWRITE_SEMANTICS_REVISION, engineRevision: ENGINE_REVISION })).digest("hex");
const input = command => ({ agent: "grok", nativeTool: "Bash", command });
const device = { id: "snapshot_device", tokenHash: "fixture", hostname: "fixture", ip: "127.0.0.1", user: "fixture", os: "linux", attachedAt: 0, lastSeen: 0, lastPolicyVersion: 1, capabilities: [], agents: [] };
const exemption = { id: "snapshot_exemption", ruleId: "sudo_usage", match: "fixture_snapshot_action", tools: ["Bash"], createdAt: 1 };
function request(id, command = "sudo echo fixture") {
  const raw = JSON.stringify({ eventId: id, agent: "grok", tool_name: "Bash", tool_input: { command } });
  const p = prepareHookTransport(raw, { deviceId: device.id, eventId: id, occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1, agentFlag: "grok" });
  assert.equal(p.kind, "request"); const ready = prepareCanonicalEvaluation(p.event, device.id); assert.equal(ready.ok, true);
  return { event: p.event, prepared: ready.prepared };
}
async function storeAt(t, dir, source) {
  const store = new NmzpStore(dir);
  await store.load({ storageMode: "sqlite", policySource: source, auditRetention: { minFreeBytes: 0 } });
  t.after(() => store.close()); return store;
}
const run = (store, source, windows, req, extra = {}) => evaluateDurably({ store, monitor: source, windows, ...req, deviceId: device.id, snapshot: store.capturePolicy(), project: ({ record }) => record.outcome, ...extra });

test("all builtin consumers share deep immutable rule data and the loaded runtime cannot be partly replaced", async () => {
  assert.equal(monitor.RULES, RULES); assert.equal(monitor.RULE_BY_ID, RULE_BY_ID); assert.equal(monitor.evaluate, evaluate);
  assert.ok(Object.isFrozen(monitor)); assert.ok(Object.isFrozen(RULES)); assert.ok(Object.isFrozen(RULE_BY_ID));
  for (const rule of RULES) { assert.ok(Object.isFrozen(rule)); assert.ok(Object.isFrozen(rule.tools)); assert.equal(RULE_BY_ID[rule.id], rule); }
  const before = policyRulesHash(monitor), judged = monitor.evaluate(input("sudo echo fixture"), "enforcing");
  assert.equal(judged.rule, RULE_BY_ID.sudo_usage);
  for (const mutate of [
    () => RULES.push(RULES[0]), () => RULES.reverse(), () => { RULES[0] = RULES[1]; },
    () => { RULE_BY_ID.sudo_usage.action = "block"; }, () => RULE_BY_ID.sudo_usage.tools.push("*"),
    () => { judged.rule.pattern = "different"; }, () => { delete RULE_BY_ID.sudo_usage; },
    () => { monitor.RULES = []; }, () => { monitor.RULE_BY_ID = {}; }, () => { monitor.evaluate = () => null; },
  ]) assert.throws(mutate, TypeError);
  assert.equal(policyRulesHash(monitor), before); assert.equal(before, formula(RULES));
  assert.deepEqual(monitor.evaluate(input("sudo echo fixture"), "enforcing"), judged);
  assert.equal(activeExemption("credential_file_upload", "x", "Bash", [{ ...exemption, ruleId: "credential_file_upload", match: "x" }], 10, { subjects: ["x"] }), undefined);
});

test("fingerprint serialization happens once for immutable catalogs; mutable and shallow-frozen inputs keep drift detection", async () => {
  // Fresh function module gives this test a private empty cache, independent of test order.
  const { policyRulesHash: hash } = await import(`./policy/nmzp-service.ts?catalog-count=${Date.now()}`);
  const original = JSON.stringify; let count = 0;
  JSON.stringify = function(value, ...args) { if (value?.rules === RULES && value?.engineRevision === ENGINE_REVISION) count++; return original.call(this, value, ...args); };
  try { for (let n = 0; n < 25; n++) assert.equal(hash(monitor), formulaWithoutInstrumentation()); }
  finally { JSON.stringify = original; }
  assert.equal(count, 1);
  function formulaWithoutInstrumentation() { return createHash("sha256").update(original({ rules: RULES, rewriteRevision: REWRITE_SEMANTICS_REVISION, engineRevision: ENGINE_REVISION })).digest("hex"); }
  for (const shallow of [false, true]) {
    const rule = { id: "fixture", action: "log", tools: ["Bash"] }, rules = [rule]; if (shallow) Object.freeze(rules);
    const source = { RULES: rules }, before = hash(source); rule.action = "block";
    assert.notEqual(hash(source), before); const next = hash(source); rule.tools.push("Read"); assert.notEqual(hash(source), next);
    source.RULES = [{ id: "replacement" }]; assert.equal(hash(source), formula(source.RULES));
  }
  let action = "log";
  const getter = Object.freeze({ id: "getter", get action() { return action; } }), source = { RULES: Object.freeze([getter]) };
  const before = hash(source); action = "block"; assert.notEqual(hash(source), before);
  for (const proxyRoot of [false, true]) {
    let current = "log";
    const target = proxyRoot ? Object.freeze([Object.freeze({ id: "proxy", action: "log" })]) : Object.freeze({ id: "proxy", action: "log" });
    const proxy = new Proxy(target, { get(object, key, receiver) {
      if (key === "toJSON") return () => proxyRoot ? [{ id: "proxy", action: current }] : { id: "proxy", action: current };
      return Reflect.get(object, key, receiver);
    } });
    const injected = { RULES: proxyRoot ? proxy : Object.freeze([proxy]) };
    const first = hash(injected); current = "block"; assert.notEqual(hash(injected), first);
  }
});

test("explicit runtime replacement rebuilds engine, overrides, exemption scope and history together; old replay fails closed", async t => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-rule-replacement-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const replacement = join(dir, "runtime");
  const filter = path => !/\.(test|spec)\.[^.]+$/.test(path);
  await cp(join(root, "core"), join(replacement, "core"), { recursive: true, filter });
  await cp(join(root, "src/lib/monitor"), join(replacement, "src/lib/monitor"), { recursive: true, filter });
  await writeFile(join(replacement, "package.json"), '{"type":"module"}');
  await symlink(join(root, "node_modules"), join(replacement, "node_modules"), "junction");
  const file = join(replacement, "src/lib/monitor/rules.ts"), text = await readFile(file, "utf8");
  const matches = text.match(/ {2}\{\r?\n {4}id: "sudo_usage",[\s\S]*?\r?\n {2}\},/g);
  assert.equal(matches?.length, 1, "exactly one LF/CRLF-compatible built-in replacement anchor");
  const changed = { ...RULE_BY_ID.sudo_usage, pattern: "\\bfixture_snapshot_action\\b", risk: "high", action: "block", family: "secret" };
  await writeFile(file, text.replace(matches[0], `  ${JSON.stringify(changed)},`));
  const { loadMonitor: loadReplacement } = await import(pathToFileURL(join(replacement, "core/paths.ts")).href);
  const next = await loadReplacement(join(replacement, "core"));
  const nextOverrides = await import(pathToFileURL(join(replacement, "src/lib/monitor/overrides.ts")).href);
  const nextScope = await import(pathToFileURL(join(replacement, "src/lib/monitor/exemption-scope.ts")).href);
  assert.notEqual(next.RULES, monitor.RULES); assert.notEqual(policyRulesHash(next), policyRulesHash(monitor));
  assert.equal(policyRulesHash(next), formula(next.RULES));
  assert.equal(next.evaluate(input("fixture_snapshot_action"), "enforcing").rule, next.RULE_BY_ID.sudo_usage);
  assert.equal(next.evaluate(input("fixture_snapshot_action"), "enforcing", [], { overrides: { rules: { sudo_usage: "off" }, families: {} }, exemptions: [exemption] }).decision, "block");
  assert.equal(nextOverrides.activeExemption("sudo_usage", "fixture_snapshot_action", "Bash", [exemption], 10, { subjects: ["fixture_snapshot_action"] }), undefined);
  assert.equal(activeExemption("sudo_usage", "fixture_snapshot_action", "Bash", [exemption], 10, { subjects: ["fixture_snapshot_action"] })?.id, exemption.id);
  assert.deepEqual(nextScope.exemptionSubjects("fixture_snapshot_action", "sudo_usage"), ["fixture_snapshot_action"]);
  assert.deepEqual(exemptionSubjects("fixture_snapshot_action", "sudo_usage"), []);
  assert.equal(monitor.evaluate(input("sudo echo fixture"), "enforcing").rule, RULE_BY_ID.sudo_usage);
  assert.notEqual(next.evaluate(input("sudo echo fixture"), "enforcing").rule?.id, "sudo_usage");
  const data = join(dir, "data"), previousStore = await storeAt(t, data, monitor);
  await previousStore.putDevice(device); await previousStore.casPolicy(previousStore.getPolicy().version, { mode: "enforcing" });
  const oldRequest = request("old_runtime"), oldWindows = new monitor.SessionWindows();
  const old = await run(previousStore, monitor, oldWindows, oldRequest);
  assert.equal(old.record.binding.rulesHash, `sha256:${policyRulesHash(monitor)}`);
  const oldVersion = old.record.policyVersion; await previousStore.close();
  const nextStore = await storeAt(t, data, next), windows = new next.SessionWindows();
  const newRequest = request("new_runtime", "fixture_snapshot_action");
  await assert.rejects(run(nextStore, next, windows, oldRequest), { code: "evaluation_replay_unavailable" });
  await assert.rejects(run(nextStore, next, windows, newRequest), { code: "evaluation_replay_unavailable" });
  assert.equal(windows.size, 0); assert.equal(await nextStore.lookupEvaluationIdentityUnlocked(device.id, newRequest.event.eventId), undefined);
  assert.equal(nextStore.getHistoricalPolicy(oldVersion).rulesHash, policyRulesHash(monitor));
  // Explicit restore publishes a NEW version with this runtime's binding; no historical rows are rewritten.
  const restored = await nextStore.restorePolicy(nextStore.getPolicy().version, oldVersion);
  assert.equal(restored.version, oldVersion + 1);
  assert.equal(nextStore.getHistoricalPolicy(restored.version).rulesHash, policyRulesHash(next));
  const current = await run(nextStore, next, windows, newRequest);
  assert.equal(current.record.outcome.decision, "block"); assert.equal(current.record.binding.rulesHash, `sha256:${policyRulesHash(next)}`);
  assert.equal(current.record.binding.policyHash, `sha256:${nextStore.capturePolicy().hash}`);
  assert.equal((await run(nextStore, next, windows, newRequest)).duplicate, true);
  await assert.rejects(run(nextStore, next, windows, oldRequest), { code: "evaluation_replay_unavailable" });
  await nextStore.close();
  const oldAgain = await storeAt(t, data, monitor);
  assert.equal((await run(oldAgain, monitor, oldWindows, oldRequest)).duplicate, true);
  await assert.rejects(run(oldAgain, monitor, oldWindows, newRequest), { code: "evaluation_replay_unavailable" });
  const finalRequest = request("old_runtime_rebound");
  await assert.rejects(run(oldAgain, monitor, oldWindows, finalRequest), { code: "evaluation_replay_unavailable" });
  const published = await oldAgain.casPolicy(oldAgain.getPolicy().version, { mode: "enforcing" });
  assert.equal(oldAgain.getHistoricalPolicy(published.version).rulesHash, policyRulesHash(monitor));
  assert.equal((await run(oldAgain, monitor, oldWindows, finalRequest)).record.policyVersion, published.version);
});

test("in-flight capture keeps its immutable catalog and policy through mutex waits and later policy publication", async t => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-snapshot-inflight-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = await storeAt(t, dir, monitor); await store.putDevice(device); await store.casPolicy(store.getPolicy().version, { mode: "enforcing" });
  const snapshot = store.capturePolicy(), windows = new monitor.SessionWindows();
  let release, entered;
  const ready = new Promise(resolve => { entered = resolve; });
  const held = store.withMutex(async () => { entered(); await new Promise(resolve => { release = resolve; }); });
  await ready;
  const req = request("inflight"), pending = run(store, monitor, windows, req, { snapshot });
  assert.throws(() => { monitor.RULES = []; }, TypeError);
  await store.casPolicy(snapshot.policy.version, { mode: "off" });
  release(); await held;
  const result = await pending;
  assert.equal(result.record.policyVersion, snapshot.policy.version);
  assert.equal(result.record.binding.rulesHash, `sha256:${policyRulesHash(monitor)}`);
  assert.deepEqual(result.record.binding, evaluationBinding(snapshot.hash, monitor));
  assert.equal(result.record.outcome.decision, "log");
  assert.equal((await run(store, monitor, windows, req)).duplicate, true);
});


test("fresh V2 mismatch returns a fixed HTTP refusal before writes and keeps V1 behavior", async t => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-snapshot-http-"));
  const srv = await startServer({ dataDir: dir, coreDir: core, host: "127.0.0.1", port: 0, uiDir: null, storageMode: "sqlite" });
  t.after(async () => { await srv.close(); await rm(dir, { recursive: true, force: true }); });
  const token = "snapshot-http-token";
  await srv.store.putDevice({ ...device, tokenHash: createHash("sha256").update(token).digest("hex") });
  await srv.store.casPolicy(srv.store.getPolicy().version, { mode: "enforcing" });
  const db = new DatabaseSync(srv.store.policyHistoryPath());
  db.prepare("UPDATE policy_revisions SET rules_hash=? WHERE version=?").run("0".repeat(64), srv.store.getPolicy().version); db.close();
  const call = async (version, body) => {
    const result = await pinnedHttps({ url: `${srv.url}/api/${version}/evaluate`, method: "POST", caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: result.status, body: JSON.parse(result.body) };
  };
  const req = request("http_mismatch");
  const refused = await call("v2", req.event);
  assert.equal(refused.status, 409); assert.equal(refused.body.error.code, "evaluation_replay_unavailable");
  assert.equal(refused.body.error.message, "The historical evaluation cannot be replayed.");
  assert.equal(refused.body.error.data, undefined);
  assert.equal(await srv.store.lookupEvaluationIdentityUnlocked(device.id, req.event.eventId), undefined);
  const v1 = await call("v1", { eventId: "http_v1_unchanged", agent: "grok", tool_name: "Bash", tool_input: { command: "sudo echo fixture" } });
  assert.equal(v1.status, 200); assert.equal(v1.body.decision, "log");
  await srv.store.casPolicy(srv.store.getPolicy().version, { mode: "enforcing" });
  assert.equal((await call("v2", req.event)).status, 200);
});
