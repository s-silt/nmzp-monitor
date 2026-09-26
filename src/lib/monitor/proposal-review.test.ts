import assert from "node:assert/strict";
import { it, type TestContext } from "node:test";
import { applyCurrentReview, validateProposalApi } from "./api.ts";
import { PROPOSAL_SCHEMA, type PolicyProposal } from "./policy-proposal.ts";
import { buildApplyEnvelope, isReviewCurrent, proposalReviewFromValidation, type ProposalReview } from "./proposal-review.ts";

const proposal: PolicyProposal = {
  schema: PROPOSAL_SCHEMA,
  basePolicyVersion: 2,
  baseRulesHash: "a".repeat(64),
  rationale: "synthetic",
  customRules: [{ match: "SYNTHETIC_CLIENT", mode: "block", dryRun: false }],
};

function reviewFixture(expiresAt = Date.now() + 60_000): ProposalReview {
  return {
    proposal,
    forceDryRun: true,
    validatedAt: 1_700_000_000_000,
    engineVersion: "0.2.5",
    candidate: {
      overrides: { rules: {}, families: {} },
      customRules: [],
      exemptions: [],
    },
    candidateDigest: "b".repeat(64),
    reviewExpiresAt: expiresAt,
    policyVersion: 2,
    rulesHash: "a".repeat(64),
    candidateTotals: { overrideRules: 0, customRules: 1, exemptions: 0 },
    newCustomRulesDefaultDryRun: true,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

it("validate request is followed by the exact apply envelope", async (t) => {
  const calls: { url: string; method: string; body: string; credentials?: RequestCredentials }[] = [];
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = typeof init?.body === "string" ? init.body : "";
    calls.push({ url, method: init?.method ?? "GET", body, credentials: init?.credentials });
    const parsed = body ? JSON.parse(body) as { forceDryRun?: boolean } : {};
    if (url.endsWith("/api/v1/policy/proposals/validate")) {
      return jsonResponse(200, {
        ok: true,
        policyVersion: 2,
        rulesHash: "a".repeat(64),
        candidateTotals: { overrideRules: 0, customRules: 1, exemptions: 0 },
        newCustomRulesDefaultDryRun: true,
        validatedAt: 1_700_000_000_000,
        forceDryRun: parsed.forceDryRun,
        engineVersion: "0.2.5",
        candidate: { overrides: { rules: {}, families: {} }, customRules: [], exemptions: [] },
        candidateDigest: "b".repeat(64),
        reviewExpiresAt: Date.now() + 60_000,
      });
    }
    return jsonResponse(200, { ok: true, version: 3, rulesHash: "a".repeat(64), newCustomRulesDefaultDryRun: true });
  }) as typeof fetch;

  const validated = await validateProposalApi(proposal, true);
  assert.equal(validated.ok, true);
  if (!validated.ok) return;
  const review = proposalReviewFromValidation(proposal, validated);
  const applied = await applyCurrentReview(review, proposal, true);
  assert.equal(applied.ok, true);
  assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), [
    "POST /api/v1/policy/proposals/validate",
    "POST /api/v1/policy/proposals/apply",
  ]);
  assert.equal(calls[0]?.credentials, "include");
  assert.equal(calls[1]?.credentials, "include");
  assert.deepEqual(JSON.parse(calls[0]!.body), { envelopeVersion: 1, proposal, forceDryRun: true });
  assert.deepEqual(JSON.parse(calls[1]!.body), buildApplyEnvelope(review));
});

it("isReviewCurrent is false after forceDryRun toggle, proposal edit, or expiry", () => {
  const review = reviewFixture();
  assert.equal(isReviewCurrent(review, proposal, true), true);
  assert.equal(isReviewCurrent(review, proposal, false), false);
  assert.equal(isReviewCurrent(review, { ...proposal, rationale: "edited" }, true), false);
  const now = Date.now();
  assert.equal(isReviewCurrent({ ...review, reviewExpiresAt: now }, proposal, true), false);
  assert.equal(isReviewCurrent({ ...review, reviewExpiresAt: now - 1 }, proposal, true), false);
});

it("applyCurrentReview does not call applyProposalApi for a stale review", async (t: TestContext) => {
  let applyCalls = 0;
  let lastApplyBody = "";
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith("/api/v1/policy/proposals/apply")) {
      applyCalls += 1;
      lastApplyBody = typeof init?.body === "string" ? init.body : "";
    }
    return jsonResponse(200, { ok: true, version: 4, rulesHash: "a".repeat(64), newCustomRulesDefaultDryRun: true });
  }) as typeof fetch;

  const review = reviewFixture();
  const expired = await applyCurrentReview({ ...review, reviewExpiresAt: Date.now() - 1000 }, proposal, true);
  const edited = await applyCurrentReview(review, { ...proposal, rationale: "edited" }, true);
  const toggled = await applyCurrentReview(review, proposal, false);
  assert.equal(expired.ok, false);
  assert.equal(edited.ok, false);
  assert.equal(toggled.ok, false);
  assert.equal(applyCalls, 0);
  const current = await applyCurrentReview(review, proposal, true);
  assert.equal(current.ok, true);
  assert.equal(applyCalls, 1);
  assert.deepEqual(JSON.parse(lastApplyBody), buildApplyEnvelope(review));
});
