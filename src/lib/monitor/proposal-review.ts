import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";
import type { PolicyProposal } from "./policy-proposal.ts";
import type { CustomPrivacyRule } from "./types.ts";

export interface ProposalCandidate {
  overrides: PolicyOverrides;
  customRules: CustomPrivacyRule[];
  exemptions: PolicyExemption[];
}

export interface ProposalReview {
  proposal: PolicyProposal;
  forceDryRun: boolean;
  validatedAt: number;
  engineVersion: string;
  candidate: ProposalCandidate;
  candidateDigest: string;
  reviewExpiresAt: number;
  policyVersion: number;
  rulesHash: string;
  candidateTotals: { overrideRules: number; customRules: number; exemptions: number };
  newCustomRulesDefaultDryRun: boolean;
}

export interface ApplyEnvelope {
  envelopeVersion: 1;
  proposal: PolicyProposal;
  forceDryRun: boolean;
  validatedAt: number;
  candidateDigest: string;
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (typeof left !== "object" || typeof right !== "object" || left === null || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    for (let i = 0; i < left.length; i += 1) if (!deepEqual(left[i], right[i])) return false;
    return true;
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord);
  if (leftKeys.length !== Object.keys(rightRecord).length) return false;
  for (const key of leftKeys) {
    if (!Object.hasOwn(rightRecord, key) || !deepEqual(leftRecord[key], rightRecord[key])) return false;
  }
  return true;
}

export function proposalReviewFromValidation(proposal: PolicyProposal, fields: Omit<ProposalReview, "proposal">): ProposalReview {
  return {
    proposal,
    forceDryRun: fields.forceDryRun,
    validatedAt: fields.validatedAt,
    engineVersion: fields.engineVersion,
    candidate: fields.candidate,
    candidateDigest: fields.candidateDigest,
    reviewExpiresAt: fields.reviewExpiresAt,
    policyVersion: fields.policyVersion,
    rulesHash: fields.rulesHash,
    candidateTotals: fields.candidateTotals,
    newCustomRulesDefaultDryRun: fields.newCustomRulesDefaultDryRun,
  };
}

export function buildApplyEnvelope(review: ProposalReview): ApplyEnvelope {
  return {
    envelopeVersion: 1,
    proposal: review.proposal,
    forceDryRun: review.forceDryRun,
    validatedAt: review.validatedAt,
    candidateDigest: review.candidateDigest,
  };
}

export function isReviewCurrent(review: ProposalReview, proposal: PolicyProposal, forceDryRun: boolean): boolean {
  return review.forceDryRun === forceDryRun && Date.now() < review.reviewExpiresAt && deepEqual(review.proposal, proposal);
}

/** Old proposals omit the base binding. Callers must regenerate them and must not fill the missing fields. */
export function proposalBindingIssue(
  proposal: PolicyProposal,
): "missing_base_policy_version" | "missing_base_rules_hash" | null {
  if (proposal.basePolicyVersion === undefined) return "missing_base_policy_version";
  if (proposal.baseRulesHash === undefined) return "missing_base_rules_hash";
  return null;
}
