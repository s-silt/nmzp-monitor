import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { applyProposalApi, validateProposalApi } from "./api.ts";
import { PROPOSAL_SCHEMA, type PolicyProposal } from "./policy-proposal.ts";
import { buildApplyEnvelope, proposalReviewFromValidation, type ProposalReview } from "./proposal-review.ts";

const here = dirname(fileURLToPath(import.meta.url));
const bound: PolicyProposal = {
  schema: PROPOSAL_SCHEMA,
  basePolicyVersion: 2,
  baseRulesHash: "a".repeat(64),
  rationale: "synthetic",
  customRules: [{ match: "SYNTHETIC_CLIENT", mode: "block", dryRun: false }],
};

function unbound(partial: Partial<PolicyProposal> = {}): PolicyProposal {
  return {
    schema: PROPOSAL_SCHEMA,
    rationale: "legacy",
    customRules: [{ match: "SYNTHETIC_CLIENT", mode: "block", dryRun: false }],
    ...partial,
  };
}

const unboundSamples = [
  unbound(),
  unbound({ baseRulesHash: "a".repeat(64) }),
  unbound({ basePolicyVersion: 2 }),
];

function reviewFor(proposal: PolicyProposal): ProposalReview {
  return {
    proposal,
    forceDryRun: false,
    validatedAt: 1_700_000_000_000,
    engineVersion: "0.2.5",
    candidate: { overrides: { rules: {}, families: {} }, customRules: [], exemptions: [] },
    candidateDigest: "b".repeat(64),
    reviewExpiresAt: Date.now() + 60_000,
    policyVersion: 2,
    rulesHash: "c".repeat(64),
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

function installFetch(t: TestContext, respond: (url: string, body: string) => Response) {
  const calls: { url: string; method: string; body: string; credentials?: RequestCredentials }[] = [];
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = typeof init?.body === "string" ? init.body : "";
    calls.push({ url, method: init?.method ?? "GET", body, credentials: init?.credentials });
    return respond(url, body);
  }) as typeof fetch;
  return calls;
}

function assertUnboundRejected(result: { ok: boolean; status?: number; error?: string; outcome?: string }) {
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.error, "proposal_base_required");
  assert.equal(result.status, 0);
  assert.equal(result.outcome, "rejected");
}

it("unbound proposal is never sent to the server", async (t: TestContext) => {
  const calls = installFetch(t, () => jsonResponse(400, { ok: false, error: "should_not_be_called" }));
  for (const proposal of unboundSamples) {
    const before = structuredClone(proposal);
    calls.length = 0;
    const result = await validateProposalApi(proposal, false);
    assert.equal(calls.length, 0, "unbound proposal must not be sent");
    assert.deepEqual(proposal, before);
    assertUnboundRejected(result);
  }
});

it("unbound proposal cannot be applied", async (t: TestContext) => {
  const calls = installFetch(t, () =>
    jsonResponse(200, { ok: true, version: 99, rulesHash: "d".repeat(64), newCustomRulesDefaultDryRun: true }),
  );
  for (const proposal of unboundSamples) {
    const review = reviewFor(proposal);
    const before = structuredClone(review);
    calls.length = 0;
    const result = await applyProposalApi(review);
    assert.equal(calls.length, 0, "unbound proposal must not be applied");
    assert.deepEqual(review, before);
    assertUnboundRejected(result);
  }
});

it("bound proposal still goes through validate then apply", async (t: TestContext) => {
  const calls = installFetch(t, (url, body) => {
    const parsed = body ? (JSON.parse(body) as { forceDryRun?: boolean }) : {};
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
  });

  const validated = await validateProposalApi(bound, true);
  assert.equal(validated.ok, true);
  if (!validated.ok) return;
  const review = proposalReviewFromValidation(bound, validated);
  const applied = await applyProposalApi(review);
  assert.equal(applied.ok, true);
  assert.deepEqual(
    calls.map((call) => `${call.method} ${call.url}`),
    ["POST /api/v1/policy/proposals/validate", "POST /api/v1/policy/proposals/apply"],
  );
  assert.equal(calls[0]?.credentials, "include");
  assert.equal(calls[1]?.credentials, "include");
  assert.deepEqual(JSON.parse(calls[0]!.body), { envelopeVersion: 1, proposal: bound, forceDryRun: true });
  assert.deepEqual(JSON.parse(calls[1]!.body), buildApplyEnvelope(review));
});

it("proposal modal disables validate and apply for unbound proposals", () => {
  const modalSource = readFileSync(join(here, "../../components/policy/proposal-modal.tsx"), "utf8");
  const disabled = [...modalSource.matchAll(/disabled=\{([^}]*)\}/g)].map((match) => match[1] ?? "");
  assert.equal(
    disabled.filter((expr) => expr.includes("proposalBindingIssue")).length,
    2,
    "source evidence only: proposalBindingIssue must appear in the validate and apply disabled expressions",
  );
  assert.equal(
    modalSource.includes("disabled={busy || proposalBindingIssue(proposal) !== null}"),
    true,
    "source evidence only: validate disabled expression must reference proposalBindingIssue",
  );
  assert.equal(
    modalSource.includes(
      "disabled={busy || proposalBindingIssue(proposal) !== null || !serverCandidate}",
    ),
    true,
    "source evidence only: apply disabled expression must reference proposalBindingIssue",
  );
  assert.equal(
    modalSource.includes(
      "该提案缺少 basePolicyVersion / baseRulesHash 基线绑定（旧格式），不能应用。请用最新能力信息重新生成。",
    ),
    true,
  );
  assert.equal(
    modalSource.includes(
      "This proposal has no basePolicyVersion / baseRulesHash binding (old format) and cannot be applied. Regenerate it from current capabilities.",
    ),
    true,
  );
});

it("store applyProposal rejects unbound proposals before applyProposalApi", () => {
  const source = readFileSync(join(here, "store.ts"), "utf8");
  const start = source.indexOf("applyProposal: async (review) => {");
  const end = source.indexOf("addPrivacyDraft:", start);
  const body = source.slice(start, end);
  const guardAt = body.indexOf("proposalBindingIssue(review.proposal)");
  const outcomeAt = body.indexOf('error: "proposal_base_required"');
  const callAt = body.indexOf("applyProposalApi(review)");
  assert.ok(
    guardAt >= 0 && outcomeAt > guardAt && callAt > outcomeAt,
    "source evidence only: proposalBindingIssue must reject with proposal_base_required before applyProposalApi",
  );
});
