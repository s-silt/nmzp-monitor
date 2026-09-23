import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { loadMonitor } from "../../core/paths.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import { createNmzpPolicyDomain } from "../../core/policy/nmzp-domain.ts";
import { createPolicySnapshot } from "../../core/policy/snapshot.ts";
import { NmzpPolicyService } from "../../core/policy/nmzp-service.ts";
import { parseApiState } from "../../src/lib/monitor/api.ts";

const coreDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../core");
const expectedCode = (code) => (error) => error?.code === code;

function comparable(policy) {
  const { updatedAt: _updatedAt, ...rest } = policy;
  // HTTP JSON omits undefined keys. No normalization of mode/version/boolean types.
  return JSON.parse(JSON.stringify(rest));
}

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-policy-parity-"));
  let server;
  t.after(async () => {
    try { await server?.close(); }
    finally { await rm(dir, { recursive: true, force: true }); }
  });
  const monitor = await loadMonitor(coreDir);
  server = await startServer({ dataDir: join(dir, "legacy-core"), coreDir, host: "127.0.0.1", port: 0, uiDir: null });
  const pin = { caPem: server.tls.certPem, fingerprintSha256: server.tls.fingerprintSha256 };
  const headers = { authorization: `Bearer ${server.adminToken}`, "content-type": "application/json" };
  // NEVER let old and new writers use the same path: this is a comparison, not runtime wiring.
  const path = join(dir, "candidate-policy.json");
  await writeFile(path, await readFile(server.store.policyPath()), { mode: 0o600 });
  const options = { file: { path, durability: "file" }, source: monitor };
  const service = await NmzpPolicyService.open(options);
  const put = (expectedVersion, patch) => pinnedHttps({
    url: `${server.url}/api/v1/policy`, method: "PUT", headers, ...pin,
    body: JSON.stringify({ expectedVersion, ...patch }),
  });
  return { dir, server, monitor, path, service, options, pin, headers, put };
}

describe("candidate NMZP policy service versus existing v1 HTTP (separate files)", { concurrency: false }, () => {
  it("binds the full real rule catalog and preserves the default durable policy", async (t) => {
    const f = await fixture(t);
    assert.deepEqual(comparable(f.service.getPolicy()), comparable(f.server.store.getPolicy()));
    const domain = createNmzpPolicyDomain(f.monitor);
    domain.prepare(f.service.capture());
    const protectedRules = f.monitor.RULES.filter(f.monitor.isProtectedRule);
    assert.ok(protectedRules.length > 0);
    for (const rule of protectedRules) {
      assert.throws(() => domain.normalizePatch({ overrides: { rules: { [rule.id]: "off" } } }), expectedCode("protected_rule_override"));
      assert.throws(() => domain.normalizePatch({ exemptions: [{
        id: "x_parity", ruleId: rule.id, match: "parity_fixture", createdAt: 1,
      }] }), expectedCode("protected_rule_exemption"));
    }
  });

  it("matches supported partial edits, pause/resume, and paused mode edits without changing HTTP", async (t) => {
    const f = await fixture(t);
    const ordinary = f.monitor.RULES.find((rule) => !f.monitor.isProtectedRule(rule));
    assert.ok(ordinary);
    const patches = [
      { mode: "permissive" }, { stopped: true }, { mode: "enforcing" },
      { customRules: [{ match: "parity_fixture", dryRun: true, enabled: true }] },
      { stopped: false }, { mode: "enforcing", stopped: true },
      { stopped: false },
      { archiveUpload: { thresholdMiB: 256, action: "warn" }, githubUpload: { mode: "selected", agents: ["codex"] } },
      { overrides: { rules: { [ordinary.id]: "block" } }, exemptions: [] },
    ];
    for (const patch of patches) {
      const version = f.service.capture().policy.version;
      const reply = await f.put(version, patch);
      assert.equal(reply.status, 200, reply.body);
      const result = await f.service.casPolicy(version, patch);
      assert.equal(result.version, version + 1);
      assert.deepEqual(comparable(result), comparable(f.server.store.getPolicy()));
      assert.equal(result.version, JSON.parse(reply.body).version);
      const stateReply = await pinnedHttps({ url: `${f.server.url}/api/v1/state`, headers: f.headers, ...f.pin });
      assert.equal(stateReply.status, 200);
      const state = parseApiState(JSON.parse(stateReply.body));
      assert.ok(state);
      assert.equal(state.mode, result.stopped ? "off" : result.mode);
      assert.equal(state.policyVersion, result.version);
    }
  });

  it("matches protected override/family/exemption rejection codes and neither file changes", async (t) => {
    const f = await fixture(t);
    const rule = f.monitor.RULES.find(f.monitor.isProtectedRule);
    assert.ok(rule);
    const beforeNew = await readFile(f.path, "utf8");
    const beforeOld = await readFile(f.server.store.policyPath(), "utf8");
    const cases = [
      [{ overrides: { rules: { [rule.id]: "off" }, families: {} } }, "protected_rule_override"],
      [{ overrides: { families: { secret: "log" } } }, "protected_rule_override"],
      [{ exemptions: [{ id: "x_parity", ruleId: rule.id, match: "parity_fixture", createdAt: 1 }] }, "protected_rule_exemption"],
      [{ customRules: [{ match: "(a+)+" }] }, "invalid_custom_rules"],
    ];
    for (const [patch, error] of cases) {
      const reply = await f.put(f.service.capture().policy.version, patch);
      assert.equal(reply.status, 400);
      assert.equal(JSON.parse(reply.body).error, error);
      await assert.rejects(f.service.casPolicy(f.service.capture().policy.version, patch), expectedCode(error));
    }
    assert.equal(await readFile(f.path, "utf8"), beforeNew);
    assert.equal(await readFile(f.server.store.policyPath(), "utf8"), beforeOld);
  });

  it("concurrent same-version edits on each isolated implementation give one winner", async (t) => {
    const f = await fixture(t);
    const version = f.service.capture().policy.version;
    const replies = await Promise.all([f.put(version, { mode: "permissive" }), f.put(version, { stopped: true })]);
    assert.deepEqual(replies.map((r) => r.status).sort(), [200, 409]);
    const results = await Promise.all([
      f.service.casPolicy(version, { mode: "permissive" }), f.service.casPolicy(version, { stopped: true }),
    ]);
    assert.equal(results.filter((r) => "conflict" in r).length, 1);
    assert.equal(results.filter((r) => !("conflict" in r) && r.version === version + 1).length, 1);
    assert.equal(f.server.store.getPolicy().version, version + 1);
  });

  it("reopened candidate accepts normal saved policy and rejects a protected downgrade on disk", async (t) => {
    const f = await fixture(t);
    const saved = await f.service.casPolicy(f.service.capture().policy.version, { mode: "permissive" });
    const reopened = await NmzpPolicyService.open(f.options);
    assert.deepEqual(reopened.getPolicy(), saved);
    const rule = f.monitor.RULES.find(f.monitor.isProtectedRule);
    const malformed = { ...JSON.parse(await readFile(f.path, "utf8")), overrides: { rules: { [rule.id]: "off" }, families: {} } };
    const bytes = JSON.stringify(malformed);
    await writeFile(f.path, bytes);
    await assert.rejects(NmzpPolicyService.open(f.options), expectedCode("protected_rule_override"));
    assert.equal(await readFile(f.path, "utf8"), bytes);
  });

  it("records the strict-load compatibility gate rather than silently rewriting a legacy file", async (t) => {
    const f = await fixture(t);
    const raw = JSON.parse(await readFile(f.path, "utf8"));
    // Legacy custom rule normalization supplies omitted fields on edit; durable open must not repair.
    raw.customRules = [{ match: "parity_fixture" }];
    const bytes = JSON.stringify(raw);
    await writeFile(f.path, bytes);
    await assert.rejects(NmzpPolicyService.open(f.options), expectedCode("invalid_custom_rules"));
    assert.equal(await readFile(f.path, "utf8"), bytes);
    // This explicit domain requirement is NOT proof all historical production files can migrate.
    const domain = createNmzpPolicyDomain(f.monitor);
    const normalized = domain.normalizePatch({ customRules: raw.customRules });
    domain.prepare(createPolicySnapshot({ ...raw, ...normalized }));
  });
});
