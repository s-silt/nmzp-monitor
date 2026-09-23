import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../../core/serve.ts";
import { pinnedHttps } from "../../core/https-client.ts";

for (const storageMode of ["window", "sqlite"]) it(`a versioned JSON proposal validates and publishes through the ${storageMode} policy writer`, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "nmzp-proposal-runtime-"));
  let server;
  t.after(async () => {
    await server?.close();
    await rm(root, { recursive: true, force: true });
  });
  server = await startServer({
    dataDir: join(root, "ct"),
    host: "127.0.0.1",
    port: 0,
    coreDir: fileURLToPath(new URL("../../core/", import.meta.url)),
    uiDir: null,
    storageMode,
  });
  const request = async (path, method = "GET", body, token = server.adminToken) => {
    const response = await pinnedHttps({
      url: server.url + path,
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      caPem: server.tls.certPem,
      fingerprintSha256: server.tls.fingerprintSha256,
      timeoutMs: 5000,
    });
    return { status: response.status, body: JSON.parse(response.body) };
  };

  const path = "/api/v1/policy/proposals";
  const denied = await request(`${path}/capabilities`, "GET", undefined, "bad-token");
  assert.equal(denied.status, 401);
  const capabilities = await request(`${path}/capabilities`);
  assert.equal(capabilities.status, 200);
  assert.equal(capabilities.body.schema, "nmzp-policy-proposal/1");
  assert.equal(capabilities.body.policyVersion, 1);
  assert.match(capabilities.body.rulesHash, /^[a-f0-9]{64}$/);
  assert.equal(capabilities.body.newCustomRulesDefaultDryRun, true);
  assert.equal(capabilities.body.explicitActivationAllowed, true);
  const startingRules = (await request("/api/v1/state")).body.customRules.length;

  const proposal = {
    schema: "nmzp-policy-proposal/1",
    basePolicyVersion: capabilities.body.policyVersion,
    baseRulesHash: capabilities.body.rulesHash,
    customRules: [{ match: "SYNTHETIC_PATCH_TOKEN_123", mode: "block", dryRun: false }],
    rationale: "synthetic fixture",
  };
  assert.equal((await request(`${path}/apply`, "POST", proposal, "bad-token")).status, 401);
  const preview = await request(`${path}/validate`, "POST", proposal);
  assert.equal(preview.status, 200);
  assert.equal(preview.body.ok, true);
  assert.equal((await request("/api/v1/state")).body.policyVersion, 1, "validation is read only");
  const applied = await request(`${path}/apply`, "POST", proposal);
  assert.equal(applied.status, 200);
  assert.equal(applied.body.version, 2);
  const state = await request("/api/v1/state");
  assert.equal(state.body.policyVersion, 2);
  assert.equal(state.body.customRules.length, startingRules + 1);
  const added = state.body.customRules.find((rule) => rule.match === "SYNTHETIC_PATCH_TOKEN_123");
  assert.equal(added?.dryRun, undefined, "an explicit dryRun:false may activate a reviewed rule");
  assert.equal(added?.enabled, true);

  assert.equal((await request(`${path}/apply`, "POST", proposal)).status, 409, "stale retry cannot publish twice");
  assert.equal((await request(`${path}/validate`, "POST", { ...proposal, baseRulesHash: "0".repeat(64), basePolicyVersion: 2 })).body.error, "rules_changed");
  assert.equal((await request(`${path}/validate`, "POST", { ...proposal, basePolicyVersion: 2, baseRulesHash: undefined })).body.error, "proposal_base_required");
  assert.equal((await request(`${path}/validate`, "POST", { schema: proposal.schema, basePolicyVersion: 2, baseRulesHash: proposal.baseRulesHash })).body.error, "proposal_no_changes");
  const invalidExpiry = await request(`${path}/validate`, "POST", {
    schema: proposal.schema, basePolicyVersion: 2, baseRulesHash: proposal.baseRulesHash,
    exemptions: [{ ruleId: "download_operation", match: "valid_secret", expiresAt: 1 }],
  });
  assert.equal(invalidExpiry.status, 400);
  assert.equal(invalidExpiry.body.ok, false);
  assert.equal(invalidExpiry.body.error, "invalid_proposal");
  assert.equal((await request(`${path}/validate`, "POST", { ...proposal, basePolicyVersion: 2, mode: "off" })).status, 400);
  assert.equal((await request(`${path}/apply`, "POST", { ...proposal, basePolicyVersion: 2, customRules: [{ match: "SYNTHETIC_TYPO", mode: "block", enabled: true }] })).status, 400);
  const duplicate = await request(`${path}/apply`, "POST", {
    schema: proposal.schema, basePolicyVersion: 2, baseRulesHash: proposal.baseRulesHash,
    customRules: [{ match: "SYNTHETIC_PATCH_TOKEN_123", mode: "replace", dryRun: true }],
    overrides: { rules: { download_operation: "block" }, families: {} },
  });
  assert.equal(duplicate.status, 400, "a duplicate match may not be silently skipped while other changes publish");
  assert.equal(duplicate.body.error, "proposal_existing_item");
  const replacementPreview = await request(`${path}/validate`, "POST", {
    schema: proposal.schema, basePolicyVersion: 2, baseRulesHash: proposal.baseRulesHash,
    remove: { customRuleIds: [added.id] },
    customRules: [{ match: "SYNTHETIC_PATCH_TOKEN_123", mode: "replace", dryRun: true }],
  });
  assert.equal(replacementPreview.status, 200, "explicit remove plus add is a valid replacement");
  assert.equal((await request("/api/v1/state")).body.policyVersion, 2, "replacement preview does not publish");
  assert.equal((await request(`${path}/apply`, "POST", { ...proposal, basePolicyVersion: 2, customRules: [], overrides: { rules: { nonexistent_rule: "off" }, families: {} } })).status, 400);
  assert.equal((await request(`${path}/apply`, "POST", { ...proposal, basePolicyVersion: 2, customRules: [], overrides: { rules: { pack_pipe_upload: "off" }, families: {} } })).status, 400);
  assert.equal((await request("/api/v1/state")).body.policyVersion, 2);

  const defaultDry = await request(`${path}/apply`, "POST", {
    schema: proposal.schema, basePolicyVersion: 2, baseRulesHash: proposal.baseRulesHash,
    customRules: [{ match: "SYNTHETIC_DEFAULT_DRY_RUN", mode: "replace" }],
  });
  assert.equal(defaultDry.status, 200);
  const defaultRule = (await request("/api/v1/state")).body.customRules.find((rule) => rule.match === "SYNTHETIC_DEFAULT_DRY_RUN");
  assert.equal(defaultRule?.dryRun, true, "omitting dryRun keeps the existing default");
  assert.equal(defaultRule?.enabled, false);

  await server.close();
  server = await startServer({
    dataDir: join(root, "ct"), host: "127.0.0.1", port: 0,
    coreDir: fileURLToPath(new URL("../../core/", import.meta.url)), uiDir: null, storageMode,
  });
  assert.equal((await request("/api/v1/state")).body.policyVersion, 3, "published revision survives restart");
  assert.equal((await request(`${path}/capabilities`)).body.policyVersion, 3);
});
