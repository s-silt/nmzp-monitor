import assert from "node:assert/strict";
import { it, type TestContext } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer, type RunningServer } from "./serve.ts";
import { pinnedHttps } from "./https-client.ts";

// Hard-coded 10 minute review lifetime. This file must not import symbols added by the fix.
const REVIEW_TTL_MS = 10 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

type HttpResult = { status: number; body: any };
type RequestFn = (path: string, method?: string, body?: unknown) => Promise<HttpResult>;

function hasMatch(body: { customRules?: { match?: string }[] }, match: string): boolean {
  return Array.isArray(body.customRules) && body.customRules.some((rule) => rule.match === match);
}

async function withServer(t: TestContext, run: (request: RequestFn) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-proposal-bind-"));
  const server: RunningServer = await startServer({
    dataDir: join(root, "ct"),
    host: "127.0.0.1",
    port: 0,
    coreDir: fileURLToPath(new URL("./", import.meta.url)),
    uiDir: null,
  }).catch(async (error: unknown) => {
    await rm(root, { recursive: true, force: true });
    throw error;
  });
  t.after(async () => {
    await server.close();
    await rm(root, { recursive: true, force: true });
  });
  const running = server;
  const request: RequestFn = async (path, method = "GET", body) => {
    const response = await pinnedHttps({
      url: running.url + path,
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: { authorization: `Bearer ${running.adminToken}`, "content-type": "application/json" },
      caPem: running.tls.certPem,
      fingerprintSha256: running.tls.fingerprintSha256,
      timeoutMs: 5000,
    });
    return { status: response.status, body: JSON.parse(response.body) };
  };
  await run(request);
}

function boundProposal(caps: { schema: string; policyVersion: number; rulesHash: string }, match: string) {
  return {
    schema: caps.schema,
    basePolicyVersion: caps.policyVersion,
    baseRulesHash: caps.rulesHash,
    customRules: [{ match, mode: "block", dryRun: false }],
  };
}

it("apply without a server review is rejected without a write", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    assert.equal(caps.status, 200);
    const proposal = boundProposal(caps.body, "SYNTHETIC_UNBOUND_APPLY");
    const before = await request("/api/v1/state");
    const applied = await request("/api/v1/policy/proposals/apply", "POST", proposal);
    assert.equal(applied.status, 400, "proposal_review_required");
    assert.equal(applied.body.error, "proposal_review_required", "proposal_review_required");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, before.body.policyVersion);
    assert.equal(hasMatch(after.body, "SYNTHETIC_UNBOUND_APPLY"), false);
  });
});

it("apply of a different proposal than the reviewed one returns 409 without a write", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const reviewed = boundProposal(caps.body, "SYNTHETIC_REVIEWED_A");
    const changed = boundProposal(caps.body, "SYNTHETIC_UNREVIEWED_B");
    const previewA = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal: reviewed, forceDryRun: false });
    assert.equal(previewA.status, 200);
    const previewB = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal: changed, forceDryRun: false });
    assert.equal(previewB.status, 200);
    assert.deepEqual(previewA.body.candidateTotals, previewB.body.candidateTotals);
    const before = await request("/api/v1/state");
    const applied = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal: changed,
      forceDryRun: previewA.body.forceDryRun,
      validatedAt: previewA.body.validatedAt,
      candidateDigest: previewA.body.candidateDigest,
    });
    assert.equal(applied.status, 409, "different proposal must not publish");
    assert.equal(applied.body.error, "proposal_preview_mismatch");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, before.body.policyVersion);
    assert.equal(hasMatch(after.body, "SYNTHETIC_REVIEWED_A"), false);
    assert.equal(hasMatch(after.body, "SYNTHETIC_UNREVIEWED_B"), false);
  });
});

it("apply with a tampered digest or forceDryRun returns 409", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const proposal = boundProposal(caps.body, "SYNTHETIC_TAMPER_RULE");
    const validated = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal, forceDryRun: false });
    assert.equal(validated.status, 200);
    const digest = String(validated.body.candidateDigest);
    const flipped = `${digest[0] === "a" ? "b" : "a"}${digest.slice(1)}`;
    const before = await request("/api/v1/state");
    const tamperedDigest = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: validated.body.forceDryRun,
      validatedAt: validated.body.validatedAt,
      candidateDigest: flipped,
    });
    assert.equal(tamperedDigest.status, 409, "tampered review must not publish");
    assert.equal(tamperedDigest.body.error, "proposal_preview_mismatch");
    const tamperedDryRun = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: !validated.body.forceDryRun,
      validatedAt: validated.body.validatedAt,
      candidateDigest: validated.body.candidateDigest,
    });
    assert.equal(tamperedDryRun.status, 409, "tampered review must not publish");
    assert.equal(tamperedDryRun.body.error, "proposal_preview_mismatch");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, before.body.policyVersion);
    assert.equal(hasMatch(after.body, "SYNTHETIC_TAMPER_RULE"), false);
  });
});

it("expired review is rejected", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const proposal = boundProposal(caps.body, "SYNTHETIC_EXPIRED_RULE");
    const validated = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal, forceDryRun: false });
    assert.equal(validated.status, 200);
    const before = await request("/api/v1/state");
    const applied = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: validated.body.forceDryRun,
      validatedAt: validated.body.validatedAt - (REVIEW_TTL_MS + 1),
      candidateDigest: validated.body.candidateDigest,
    });
    assert.equal(applied.status, 409, "proposal_review_expired");
    assert.equal(applied.body.error, "proposal_review_expired", "proposal_review_expired");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, before.body.policyVersion);
    assert.equal(hasMatch(after.body, "SYNTHETIC_EXPIRED_RULE"), false);
  });
});

it("exact reviewed candidate publishes one version and keeps mode and stopped", async (t) => {
  await withServer(t, async (request) => {
    const primed = await request("/api/v1/policy", "PUT", { expectedVersion: 1, mode: "permissive", stopped: false });
    assert.equal(primed.status, 200);
    assert.equal(primed.body.mode, "permissive");
    assert.equal(primed.body.stopped, false);
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const proposal = {
      schema: caps.body.schema,
      basePolicyVersion: caps.body.policyVersion,
      baseRulesHash: caps.body.rulesHash,
      overrides: { rules: { download_operation: "block" }, families: {} },
      customRules: [{ match: "SYNTHETIC_BOUND_RULE", mode: "block", dryRun: false }],
      exemptions: [{ ruleId: "download_operation", match: "synthetic_exempt" }],
    };
    const validated = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal, forceDryRun: false });
    assert.equal(validated.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const applied = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: validated.body.forceDryRun,
      validatedAt: validated.body.validatedAt,
      candidateDigest: validated.body.candidateDigest,
    });
    assert.equal(applied.status, 200, "reviewed candidate published");
    assert.equal(applied.body.version, primed.body.version + 1, "reviewed candidate published");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, primed.body.version + 1);
    assert.equal(after.body.mode, "permissive");
    assert.equal(after.body.stopped, false);
    assert.deepEqual(after.body.overrides, validated.body.candidate.overrides);
    assert.deepEqual(after.body.customRules, validated.body.candidate.customRules);
    assert.deepEqual(after.body.exemptions, validated.body.candidate.exemptions, "reviewed candidate published");
    const stored = after.body.exemptions.find((row: { match?: string }) => row.match === "synthetic_exempt");
    assert.equal(stored.createdAt, validated.body.validatedAt, "reviewed candidate published");
    assert.equal(stored.expiresAt, validated.body.validatedAt + 30 * DAY_MS, "reviewed candidate published");
  });
});

it("digest covers semantics, not counts", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const left = await request("/api/v1/policy/proposals/validate", "POST", boundProposal(caps.body, "SYNTHETIC_COUNT_LEFT"));
    const right = await request("/api/v1/policy/proposals/validate", "POST", boundProposal(caps.body, "SYNTHETIC_COUNT_RIGHT"));
    assert.equal(left.status, 200);
    assert.equal(right.status, 200);
    assert.deepEqual(left.body.candidateTotals, right.body.candidateTotals);
    assert.equal(typeof left.body.candidateDigest, "string");
    assert.equal(typeof right.body.candidateDigest, "string");
    assert.notEqual(left.body.candidateDigest, right.body.candidateDigest);
  });
});

it("policy change between validate and apply still returns cas_conflict", async (t) => {
  await withServer(t, async (request) => {
    const caps = await request("/api/v1/policy/proposals/capabilities");
    const proposal = boundProposal(caps.body, "SYNTHETIC_STALE_BASE");
    const validated = await request("/api/v1/policy/proposals/validate", "POST", { envelopeVersion: 1, proposal, forceDryRun: false });
    assert.equal(validated.status, 200);
    const changed = await request("/api/v1/policy", "PUT", { expectedVersion: validated.body.policyVersion, mode: "permissive" });
    assert.equal(changed.status, 200);
    const applied = await request("/api/v1/policy/proposals/apply", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: validated.body.forceDryRun,
      validatedAt: validated.body.validatedAt,
      candidateDigest: validated.body.candidateDigest,
    });
    assert.equal(applied.status, 409);
    assert.equal(applied.body.error, "cas_conflict");
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, changed.body.version);
    assert.equal(hasMatch(after.body, "SYNTHETIC_STALE_BASE"), false);
  });
});

it("server rejects removal of a missing item with invalid_proposal and no write", async (t) => {
  await withServer(t, async (request) => {
    const before = await request("/api/v1/state");
    assert.equal(before.status, 200);
    const caps = await request("/api/v1/policy/proposals/capabilities");
    assert.equal(caps.status, 200);
    const missing = "p_missing";
    const proposal = {
      schema: caps.body.schema,
      basePolicyVersion: caps.body.policyVersion,
      baseRulesHash: caps.body.rulesHash,
      remove: { customRuleIds: [missing] },
      exemptions: [{ ruleId: "download_operation", match: "synthetic_missing_rm" }],
    };
    const validated = await request("/api/v1/policy/proposals/validate", "POST", {
      envelopeVersion: 1,
      proposal,
      forceDryRun: false,
    });
    if (validated.status === 200) {
      const applied = await request("/api/v1/policy/proposals/apply", "POST", {
        envelopeVersion: 1,
        proposal,
        forceDryRun: validated.body.forceDryRun,
        validatedAt: validated.body.validatedAt,
        candidateDigest: validated.body.candidateDigest,
      });
      assert.equal(applied.status, 400, "invalid_proposal");
      assert.equal(applied.body.error, "invalid_proposal");
      assert.ok(
        Array.isArray(applied.body.issues) && applied.body.issues.includes(`remove_missing_custom_rule:${missing}`),
        `remove_missing_custom_rule:${missing}`,
      );
    } else {
      assert.equal(validated.status, 400, "invalid_proposal");
      assert.equal(validated.body.error, "invalid_proposal");
      assert.ok(
        Array.isArray(validated.body.issues) && validated.body.issues.includes(`remove_missing_custom_rule:${missing}`),
        `remove_missing_custom_rule:${missing}`,
      );
    }
    const after = await request("/api/v1/state");
    assert.equal(after.body.policyVersion, before.body.policyVersion);
    assert.equal(
      Array.isArray(after.body.exemptions) && after.body.exemptions.some((row: { match?: string }) => row.match === "synthetic_missing_rm"),
      false,
    );
  });
});
