import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtemp, readFile, rm, writeFile, open, lstat, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as privacy from "../../src/lib/monitor/privacy.ts";
import { isProtectedRule, protectedDowngrades } from "../../src/lib/monitor/overrides.ts";
import { createPolicySnapshot } from "./snapshot.ts";
import { createNmzpPolicyDomain, PolicyDomainError } from "./nmzp-domain.ts";
import { NmzpPolicyService } from "./nmzp-service.ts";

// Real NMZP helper implementations, but an explicitly SYNTHETIC rule catalog.
// The full repository catalog/HTTP comparison is in tests/compat/policy-domain-v1.test.mjs.
function source() {
  return {
    RULES: [
      { id: "fixture_exfil", action: "block", family: "exfil" },
      { id: "fixture_secret", action: "block", family: "secret" },
      { id: "fixture_delete", action: "log", family: "destructive" },
      { id: "fixture_read", action: "log", family: "recon" },
    ],
    privacy, isProtectedRule, protectedDowngrades,
  };
}
function policy(patch = {}) {
  return { version: 1, updatedAt: 1, mode: "enforcing", stopped: false, customRules: [], ...patch };
}
function custom(patch = {}) {
  return {
    id: "p_fixture", enabled: true, mode: "replace", match: "internal\\.example",
    kind: "fixture", replaceWith: "<标签>", ...patch,
  };
}
function exemption(patch = {}) {
  return { id: "x_fixture", ruleId: "fixture_read", match: "fixture", createdAt: 1, ...patch };
}
const code = (value) => (error) => error?.code === value;
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
async function fixture(t, initial = policy(), operations) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-policy-domain-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "policy.json");
  await writeFile(path, `${JSON.stringify(initial)}\n`, { mode: 0o600 });
  const options = { file: { path, durability: "file", ...(operations ? { operations } : {}) }, source: source(), now: () => 20 };
  const service = await NmzpPolicyService.open(options);
  return { dir, path, service, options, bytes: () => readFile(path, "utf8") };
}

describe("NMZP domain validation with real helpers and synthetic catalog", () => {
  it("accepts minimal and existing suggested privacy policy snapshots", () => {
    const domain = createNmzpPolicyDomain(source());
    domain.prepare(createPolicySnapshot(policy()));
    domain.prepare(createPolicySnapshot(policy({ customRules: privacy.SUGGESTED_PRIVACY })));
  });
  it("normalizes editable custom rules using the existing sanitizer and dry-run semantics", () => {
    const input = { customRules: [{ match: "employee", dryRun: true, enabled: true }] };
    const before = structuredClone(input);
    const output = createNmzpPolicyDomain(source()).normalizePatch(input);
    assert.deepEqual(output.customRules, privacy.sanitizeCustomRules(input.customRules));
    assert.equal(output.customRules[0].dryRun, true);
    assert.equal(output.customRules[0].enabled, false);
    assert.deepEqual(input, before);
  });
  it("supports ordinary overrides and explicit block on a protected rule", () => {
    const patch = { overrides: { rules: { fixture_delete: "off", fixture_exfil: "block" }, families: { recon: "log" } } };
    assert.deepEqual(createNmzpPolicyDomain(source()).normalizePatch(patch), patch);
  });
  it("rejects individual protected-rule downgrades with only identifier metadata", () => {
    const domain = createNmzpPolicyDomain(source());
    for (const action of ["log", "off"]) {
      assert.throws(() => domain.normalizePatch({ overrides: { rules: { fixture_exfil: action }, families: {} } }),
        (error) => error instanceof PolicyDomainError && error.code === "protected_rule_override"
          && error.message === "protected_rule_override" && error.ruleIds.join() === "fixture_exfil");
    }
  });
  it("rejects protected family downgrades even when that family has no entry in the fixture catalog", () => {
    for (const family of ["exfil", "secret", "tamper", "isolate", "poison"]) {
      assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch({ overrides: { families: { [family]: "log" } } }),
        code("protected_rule_override"));
    }
  });
  it("rejects unknown rule override identifiers rather than silently ignoring them", () => {
    assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch({ overrides: { rules: { not_in_catalog: "off" } } }),
      code("unknown_rule_override"));
  });
  it("rejects protected exemptions, including expired ones", () => {
    const domain = createNmzpPolicyDomain(source());
    for (const entry of [exemption({ ruleId: "fixture_secret" }), exemption({ ruleId: "fixture_secret", expiresAt: 2 })]) {
      assert.throws(() => domain.normalizePatch({ exemptions: [entry] }), code("protected_rule_exemption"));
    }
  });
  it("validates exemption pattern compilation, scope, uniqueness, and expiry bounds", () => {
    const domain = createNmzpPolicyDomain(source());
    for (const exemptions of [
      [exemption({ match: "(a+)+" })], [exemption({ tools: ["not_a_tool"] })],
      [exemption(), exemption()], [exemption({ expiresAt: 1 })],
    ]) assert.throws(() => domain.normalizePatch({ exemptions }), code("invalid_policy_exemptions"));
  });
  it("preserves current server acceptance of custom/unknown exemption targets", () => {
    const patch = { exemptions: [exemption({ ruleId: "custom_target" })] };
    assert.deepEqual(createNmzpPolicyDomain(source()).normalizePatch(patch), patch);
  });
  it("rejects invalid, duplicate-match, and excessive custom rules before truncation", () => {
    for (const customRules of [
      [custom({ match: "(a+)+" })], [custom(), custom()],
      [custom({ scope: { tools: ["bogus"] } })], null,
      Array.from({ length: privacy.MAX_CUSTOM_RULES + 1 }, (_, i) => custom({ id: `p_${i}`, match: `fixture${i}` })),
    ]) assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch({ customRules }), code("invalid_custom_rules"));
  });
  it("preserves the existing literal fallback for a malformed regex; does not invent a new compiler", () => {
    const patch = { customRules: [custom({ match: "[invalid" })] };
    assert.ok(privacy.compileMatch("[invalid"));
    assert.deepEqual(createNmzpPolicyDomain(source()).normalizePatch(patch), patch);
  });
  it("rejects mode/type confusion and invalid upload settings", () => {
    for (const [patch, expected] of [
      [{ mode: "observe" }, "invalid_policy_mode"], [{ stopped: "false" }, "invalid_policy_stopped"],
      [{ githubUpload: { mode: "selected", agents: ["unknown"] } }, "invalid_github_policy"],
      [{ archiveUpload: { thresholdMiB: 0, action: "warn" } }, "invalid_archive_policy"],
      [{ overrides: { extra: true } }, "invalid_policy_overrides"],
    ]) assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch(patch), code(expected));
  });
  it("does not let patches edit revision fields, previousMode, or smuggle unknown fields", () => {
    for (const key of ["version", "updatedAt", "previousMode", "expectedVersion", "schema", "extra"]) {
      assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch({ [key]: 1 }), code("invalid_policy_patch"));
    }
  });
  it("does not invoke accessors and rejects executable/non-JSON inputs", () => {
    let touched = false;
    const input = { get mode() { touched = true; return "off"; } };
    assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch(input));
    assert.equal(touched, false);
    assert.throws(() => createNmzpPolicyDomain(source()).normalizePatch({ run: () => {} }));
  });
  it("requires full documents to have valid required fields and matching identity", () => {
    const domain = createNmzpPolicyDomain(source());
    for (const key of ["mode", "stopped", "customRules"]) {
      const p = policy(); delete p[key];
      assert.throws(() => domain.prepare(createPolicySnapshot(p)), code("invalid_policy_schema"));
    }
    const snapshot = createPolicySnapshot(policy());
    assert.throws(() => domain.prepare({ ...snapshot, hash: "a".repeat(64) }), code("invalid_policy_schema"));
    assert.throws(() => domain.prepare(createPolicySnapshot(policy({ unexpected: true }))), code("invalid_policy_schema"));
  });
  it("does not silently normalize durable policy documents on open or restore", () => {
    const domain = createNmzpPolicyDomain(source());
    assert.throws(() => domain.prepare(createPolicySnapshot(policy({ customRules: [{ match: "employee" }] }))), code("invalid_custom_rules"));
    assert.throws(() => domain.prepare(createPolicySnapshot(policy({ overrides: { rules: {} } }))), code("invalid_policy_overrides"));
    assert.throws(() => domain.prepare(createPolicySnapshot(policy({ archiveUpload: { thresholdMiB: 200, action: "warn", unexpected: true } }))), code("invalid_archive_policy"));
  });
  it("retains v1 paused raw mode combinations; stopped must still gate evaluation", () => {
    const domain = createNmzpPolicyDomain(source());
    domain.prepare(createPolicySnapshot(policy({ stopped: true })));
    assert.throws(() => domain.prepare(createPolicySnapshot(policy({ previousMode: "observe" }))), code("invalid_previous_mode"));
    domain.prepare(createPolicySnapshot(policy({ stopped: true, mode: "off", previousMode: "permissive" })));
  });
  it("binds catalog facts against later caller mutation and requires real dependency ports", () => {
    const input = source();
    const domain = createNmzpPolicyDomain(input);
    input.RULES[0].action = "log";
    input.RULES.push({ id: "new_id", action: "log" });
    assert.throws(() => domain.normalizePatch({ overrides: { rules: { fixture_exfil: "off" } } }), code("protected_rule_override"));
    assert.throws(() => domain.normalizePatch({ overrides: { rules: { new_id: "log" } } }), code("unknown_rule_override"));
    for (const bad of [null, {}, { ...source(), RULES: [] }, { ...source(), RULES: [source().RULES[0], source().RULES[0]] }]) {
      assert.throws(() => createNmzpPolicyDomain(bad), code("policy_domain_options"));
    }
  });
});

describe("NMZP domain + publisher + real file service", { concurrency: false }, () => {
  it("opens without rewriting and returns detached legacy-shaped policy values", async (t) => {
    const f = await fixture(t);
    const before = await f.bytes();
    const read = f.service.getPolicy();
    assert.deepEqual(read.archiveUpload, { thresholdMiB: 200, action: "warn" });
    assert.deepEqual(read.overrides, { rules: {}, families: {} });
    read.githubUpload.agents.length = 0;
    assert.ok(f.service.getPolicy().githubUpload.agents.length > 0);
    assert.equal(await f.bytes(), before);
  });
  it("partial publication commits real plain JSON and changes only requested fields plus revision", async (t) => {
    const f = await fixture(t, policy({ customRules: [custom()], archiveUpload: { thresholdMiB: 256, action: "warn" } }));
    const old = f.service.capture();
    const next = await f.service.casPolicy(1, { overrides: { rules: { fixture_read: "log" } } });
    assert.equal(next.version, 2);
    const saved = JSON.parse(await f.bytes());
    assert.equal(saved.version, 2);
    assert.equal(saved.updatedAt, 20);
    assert.deepEqual(saved.customRules, [custom()]);
    assert.equal(saved.archiveUpload.thresholdMiB, 256);
    assert.equal(saved.codec, undefined);
    assert.equal(saved.policy, undefined);
    assert.equal(old.policy.version, 1);
    assert.ok(Object.isFrozen(old.policy.customRules[0]));
  });
  it("normalizes then persists custom rules without sharing caller references", async (t) => {
    const f = await fixture(t);
    const patch = { customRules: [{ match: "employee", dryRun: true, enabled: true }] };
    const pending = f.service.casPolicy(1, patch);
    patch.customRules[0].match = "different";
    const result = await pending;
    assert.equal(result.customRules[0].match, "employee");
    assert.equal(result.customRules[0].enabled, false);
    assert.equal(result.customRules[0].dryRun, true);
    result.customRules[0].match = "consumer mutation";
    assert.equal(f.service.capture().policy.customRules[0].match, "employee");
  });
  it("concurrent same-version edits have exactly one committed winner and one conflict", async (t) => {
    const f = await fixture(t);
    const results = await Promise.all([
      f.service.casPolicy(1, { mode: "permissive" }), f.service.casPolicy(1, { stopped: true }),
    ]);
    assert.equal(results.filter((r) => r.version === 2 && !("conflict" in r)).length, 1);
    assert.deepEqual(results.find((r) => "conflict" in r), { conflict: true, version: 2 });
    assert.equal(JSON.parse(await f.bytes()).version, 2);
  });
  it("rejected protected overrides and exemptions never reach a temp write or change disk", async (t) => {
    let writes = 0;
    const operations = { open: async (...args) => { if (args[1] === "wx") writes++; return open(...args); }, lstat, rename, unlink };
    const f = await fixture(t, policy(), operations);
    const before = await f.bytes();
    await assert.rejects(f.service.casPolicy(1, { overrides: { rules: { fixture_exfil: "off" } } }), code("protected_rule_override"));
    await assert.rejects(f.service.casPolicy(1, { exemptions: [exemption({ ruleId: "fixture_secret" })] }), code("protected_rule_exemption"));
    assert.equal(writes, 0);
    assert.equal(await f.bytes(), before);
    assert.equal(f.service.capture().policy.version, 1);
    assert.equal(f.service.recoveryRequired, false);
  });
  it("invalid pattern and duplicate custom rules are rejected without changing the file", async (t) => {
    const f = await fixture(t);
    const before = await f.bytes();
    await assert.rejects(f.service.casPolicy(1, { customRules: [custom({ match: "(a+)+" })] }), code("invalid_custom_rules"));
    await assert.rejects(f.service.casPolicy(1, { customRules: [custom(), custom()] }), code("invalid_custom_rules"));
    assert.equal(await f.bytes(), before);
  });
  it("stop/resume preserves previous mode and advances revision for each accepted edit", async (t) => {
    const f = await fixture(t, policy({ mode: "permissive" }));
    const stopped = await f.service.stop();
    assert.equal(stopped.version, 2);
    assert.equal(stopped.mode, "off");
    assert.equal(stopped.previousMode, "permissive");
    const edited = await f.service.casPolicy(2, { customRules: [custom()] });
    assert.equal(edited.mode, "off");
    assert.equal(edited.stopped, true);
    const resumed = await f.service.resume();
    assert.equal(resumed.version, 4);
    assert.equal(resumed.mode, "permissive");
    assert.equal(resumed.stopped, false);
  });
  it("combined mode/stop edits retain legacy precedence on supported transitions", async (t) => {
    const f = await fixture(t);
    const stopped = await f.service.casPolicy(1, { mode: "permissive", stopped: true });
    assert.equal(stopped.previousMode, "permissive");
    const resumed = await f.service.casPolicy(2, { mode: "enforcing", stopped: false });
    assert.equal(resumed.mode, "permissive");
  });
  it("mode-only edit while stopped preserves v1 fields without implicitly resuming", async (t) => {
    const f = await fixture(t, policy({ mode: "off", stopped: true, previousMode: "enforcing" }));
    const result = await f.service.casPolicy(1, { mode: "permissive" });
    assert.equal(result.stopped, true);
    assert.equal(result.mode, "permissive");
    assert.equal(result.previousMode, "enforcing");
    const resumed = await f.service.resume();
    assert.equal(resumed.mode, "enforcing");
    assert.equal(resumed.stopped, false);
  });
  it("restore revalidates old content and publishes a new revision, not a new history store", async (t) => {
    const f = await fixture(t);
    const old = f.service.capture();
    await f.service.casPolicy(1, { mode: "permissive" });
    const restored = await f.service.restore(2, old);
    assert.equal(restored.version, 3);
    assert.equal(restored.mode, "enforcing");
    assert.equal(JSON.parse(await f.bytes()).version, 3);
  });
  it("restore cannot import a forged historical protected-rule downgrade", async (t) => {
    const f = await fixture(t);
    const before = await f.bytes();
    const bad = createPolicySnapshot(policy({ overrides: { rules: { fixture_exfil: "off" }, families: {} } }));
    await assert.rejects(f.service.restore(1, bad), code("protected_rule_override"));
    assert.equal(await f.bytes(), before);
  });
  it("invalid durable input fails open() without repair or byte changes", async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-invalid-policy-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "policy.json");
    const bytes = JSON.stringify(policy({ overrides: { rules: { fixture_exfil: "off" }, families: {} } }));
    await writeFile(path, bytes);
    await assert.rejects(NmzpPolicyService.open({ file: { path, durability: "file" }, source: source() }), code("protected_rule_override"));
    assert.equal(await readFile(path, "utf8"), bytes);
  });
  it("known temp-write failure leaves old revision readable and a retry can commit", async (t) => {
    let fail = true;
    const operations = { open: async (...args) => {
      if (args[1] === "wx" && fail) throw new Error("synthetic unavailable");
      return open(...args);
    }, lstat, rename, unlink };
    const f = await fixture(t, policy(), operations);
    await assert.rejects(f.service.casPolicy(1, { mode: "permissive" }), code("policy_not_committed"));
    assert.equal(f.service.capture().policy.version, 1);
    assert.equal(f.service.recoveryRequired, false);
    fail = false;
    assert.equal((await f.service.casPolicy(1, { mode: "permissive" })).version, 2);
  });
  it("ambiguous rename fences service capture and future publication", async (t) => {
    const operations = { open, lstat, unlink, rename: async (...args) => { await rename(...args); throw new Error("synthetic post-rename error"); } };
    const f = await fixture(t, policy(), operations);
    await assert.rejects(f.service.casPolicy(1, { mode: "permissive" }), code("policy_recovery_required"));
    assert.equal(JSON.parse(await f.bytes()).version, 2);
    assert.equal(f.service.recoveryRequired, true);
    assert.throws(() => f.service.getPolicy(), code("policy_recovery_required"));
    await assert.rejects(f.service.casPolicy(1, {}), code("policy_recovery_required"));
  });
  it("delayed disk write keeps active old snapshot until a confirmed commit", async (t) => {
    const entered = deferred(); const release = deferred();
    t.after(() => release.resolve());
    const operations = { open, lstat, unlink, rename: async (...args) => {
      entered.resolve(); await release.promise; return rename(...args);
    } };
    const f = await fixture(t, policy(), operations);
    const pending = f.service.casPolicy(1, { mode: "permissive" });
    await entered.promise;
    assert.equal(f.service.capture().policy.version, 1);
    assert.equal(JSON.parse(await f.bytes()).version, 1);
    release.resolve();
    assert.equal((await pending).version, 2);
    assert.equal(f.service.capture().policy.mode, "permissive");
  });
  it("external authority change is not overwritten and requires explicit recovery", async (t) => {
    const f = await fixture(t);
    const changed = JSON.stringify(policy({ version: 2, mode: "off" }));
    await writeFile(f.path, changed);
    await assert.rejects(f.service.casPolicy(1, { mode: "permissive" }), code("policy_recovery_required"));
    assert.equal(await f.bytes(), changed);
  });
  it("reopen reads a committed file through the domain checks", async (t) => {
    const f = await fixture(t);
    const next = await f.service.casPolicy(1, { customRules: [custom()] });
    const reopened = await NmzpPolicyService.open(f.options);
    assert.deepEqual(reopened.getPolicy(), next);
  });
  it("stale expected versions conflict and invalid versions do not write", async (t) => {
    const f = await fixture(t);
    const before = await f.bytes();
    assert.deepEqual(await f.service.casPolicy(9, { mode: "off" }), { conflict: true, version: 1 });
    for (const value of [0, -1, 1.5, "1", NaN]) {
      await assert.rejects(f.service.casPolicy(value, {}), code("invalid_expected_version"));
    }
    assert.equal(await f.bytes(), before);
  });
});
