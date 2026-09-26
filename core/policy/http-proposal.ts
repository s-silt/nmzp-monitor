import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isDeepStrictEqual } from "node:util";
import { NMZP_VERSION } from "../constants.ts";
import { json, readLimited } from "../http-util.ts";
import { PolicyDomainError } from "./nmzp-domain.ts";
import type { loadPolicyProposal, MonitorMods } from "../paths.ts";
import type { NmzpStore } from "../persist.ts";
import { policyRulesHash } from "./nmzp-service.ts";
import { InvalidPolicySnapshot } from "./snapshot.ts";

const ROOT = "/api/v1/policy/proposals";
/** Review envelopes older than this are rejected and never written. */
export const PROPOSAL_REVIEW_TTL_MS = 10 * 60 * 1000;
const VALIDATE_ENVELOPE_KEYS = new Set(["envelopeVersion", "proposal", "forceDryRun"]);
const APPLY_ENVELOPE_KEYS = new Set(["envelopeVersion", "proposal", "forceDryRun", "validatedAt", "candidateDigest"]);

interface ProposalHttpContext {
  store: NmzpStore;
  monitor: MonitorMods;
  proposalParser: Awaited<ReturnType<typeof loadPolicyProposal>>;
  requireAdmin: (req: IncomingMessage, res: ServerResponse) => boolean;
}

type ProposalParser = ProposalHttpContext["proposalParser"];
type ReviewedPatch = Extract<ReturnType<ProposalParser["mergeProposal"]>, { ok: true }>["next"];

interface PreparedCandidate {
  ok: true;
  current: ReturnType<NmzpStore["getPolicy"]>;
  rulesHash: string;
  patch: ReviewedPatch;
}

interface ProposalHttpFailure {
  ok: false;
  status: number;
  body: Record<string, unknown>;
}

interface ApplyReview {
  proposal: unknown;
  forceDryRun: boolean;
  validatedAt: number;
  candidateDigest: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.size && keys.every((key) => allowed.has(key));
}

/** Recursively sorted object keys, arrays in order, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const body = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",");
  return `{${body}}`;
}

export function proposalCandidateDigest(input: {
  basePolicyVersion: number;
  rulesHash: string;
  engineVersion: string;
  validatedAt: number;
  forceDryRun: boolean;
  candidate: unknown;
}): string {
  return createHash("sha256").update(canonicalJson({
    v: 1,
    basePolicyVersion: input.basePolicyVersion,
    rulesHash: input.rulesHash,
    engineVersion: input.engineVersion,
    validatedAt: input.validatedAt,
    forceDryRun: input.forceDryRun,
    candidate: input.candidate,
  })).digest("hex");
}

function failure(status: number, body: Record<string, unknown>): ProposalHttpFailure {
  return { ok: false, status, body };
}

function openValidateRequest(raw: unknown): { ok: true; proposal: unknown; forceDryRun: boolean } | { ok: false } {
  if (isRecord(raw) && Object.hasOwn(raw, "envelopeVersion")) {
    if (raw.envelopeVersion !== 1 || !exactKeys(raw, VALIDATE_ENVELOPE_KEYS) || typeof raw.forceDryRun !== "boolean") {
      return { ok: false };
    }
    return { ok: true, proposal: raw.proposal, forceDryRun: raw.forceDryRun };
  }
  return { ok: true, proposal: raw, forceDryRun: false };
}

function readApplyReview(raw: unknown): ApplyReview | undefined {
  if (!isRecord(raw) || raw.envelopeVersion !== 1 || !exactKeys(raw, APPLY_ENVELOPE_KEYS)) return undefined;
  if (typeof raw.forceDryRun !== "boolean" || typeof raw.candidateDigest !== "string") return undefined;
  if (typeof raw.validatedAt !== "number" || !Number.isSafeInteger(raw.validatedAt)) return undefined;
  return {
    proposal: raw.proposal,
    forceDryRun: raw.forceDryRun,
    validatedAt: raw.validatedAt,
    candidateDigest: raw.candidateDigest,
  };
}

function prepareCandidate(context: ProposalHttpContext, rawProposal: unknown, now: number, forceDryRun: boolean): PreparedCandidate | ProposalHttpFailure {
  const rulesHash = policyRulesHash(context.monitor);
  const parsed = context.proposalParser.parsePolicyProposal(rawProposal, { rules: [...context.monitor.RULES] });
  if (!parsed.ok) {
    return failure(400, { ok: false, error: "invalid_proposal", issues: parsed.errors.slice(0, 16).map((issue: string) => issue.slice(0, 128)) });
  }
  const proposal = parsed.proposal;
  if (proposal.basePolicyVersion === undefined || proposal.baseRulesHash === undefined) {
    return failure(400, { ok: false, error: "proposal_base_required" });
  }
  // Recheck after reading the body; no old request can bypass recovery or current revisions.
  const current = context.store.getPolicy();
  if (proposal.basePolicyVersion !== current.version) {
    return failure(409, { ok: false, error: "cas_conflict", version: current.version });
  }
  if (proposal.baseRulesHash !== rulesHash) {
    return failure(409, { ok: false, error: "rules_changed", rulesHash });
  }
  // The shared UI merge intentionally skips duplicate matches. On this direct
  // publish path, a partial success would misrepresent what the caller asked for.
  const removedCustom = new Set(proposal.remove?.customRuleIds ?? []);
  const customMatches = new Set(current.customRules.filter((row) => !removedCustom.has(row.id))
    .map((row) => row.match.toLowerCase()));
  for (const row of proposal.customRules ?? []) {
    const match = row.match.toLowerCase();
    if (customMatches.has(match)) return failure(400, { ok: false, error: "proposal_existing_item" });
    customMatches.add(match);
  }
  const removedExemptions = new Set(proposal.remove?.exemptionIds ?? []);
  const exemptionMatches = new Set((current.exemptions ?? []).filter((row) => !removedExemptions.has(row.id))
    .map((row) => `${row.ruleId}\0${row.match.toLowerCase()}`));
  for (const row of proposal.exemptions ?? []) {
    const match = `${row.ruleId}\0${row.match.toLowerCase()}`;
    if (exemptionMatches.has(match)) return failure(400, { ok: false, error: "proposal_existing_item" });
    exemptionMatches.add(match);
  }
  const merged = context.proposalParser.mergeProposal({
    overrides: current.overrides,
    customRules: current.customRules,
    exemptions: current.exemptions,
  }, proposal, { now, forceDryRun });
  if (!merged.ok) {
    return failure(400, { ok: false, error: "invalid_proposal", issues: merged.errors.slice(0, 16).map((issue: string) => issue.slice(0, 128)) });
  }
  const patch = merged.next;
  if (isDeepStrictEqual(patch, {
    overrides: current.overrides, customRules: current.customRules, exemptions: current.exemptions,
  })) {
    return failure(400, { ok: false, error: "proposal_no_changes" });
  }
  let preview: ReturnType<NmzpStore["previewPolicyPatch"]>;
  try { preview = context.store.previewPolicyPatch(current.version, patch); }
  catch (error) {
    if (!(error instanceof InvalidPolicySnapshot) && !(error instanceof PolicyDomainError)) throw error;
    return failure(400, { ok: false, error: "invalid_proposal", ...(error instanceof PolicyDomainError ? { issues: [error.code] } : {}) });
  }
  if (preview.conflict) return failure(409, { ok: false, error: "cas_conflict", version: preview.version });
  return { ok: true, current, rulesHash, patch };
}

/** Grok and other producers submit data proposals, never executable code or a policy file replacement. */
export async function handlePolicyProposalHttp(req: IncomingMessage, res: ServerResponse,
  pathname: string, context: ProposalHttpContext): Promise<boolean> {
  const capabilities = req.method === "GET" && pathname === `${ROOT}/capabilities`;
  const validate = req.method === "POST" && pathname === `${ROOT}/validate`;
  const apply = req.method === "POST" && pathname === `${ROOT}/apply`;
  if (!capabilities && !validate && !apply) return false;
  if (!context.requireAdmin(req, res)) return true;

  if (capabilities) {
    json(res, 200, {
      schema: context.proposalParser.PROPOSAL_SCHEMA,
      policyVersion: context.store.capturePolicy().policy.version,
      rulesHash: policyRulesHash(context.monitor),
      engineVersion: NMZP_VERSION,
      requiredBindings: ["basePolicyVersion", "baseRulesHash"],
      newCustomRulesDefaultDryRun: true,
      explicitActivationAllowed: true,
      requiredReview: ["validatedAt", "candidateDigest"],
      reviewTtlMs: PROPOSAL_REVIEW_TTL_MS,
    });
    return true;
  }

  const body = await readLimited(req);
  if (!body.ok) { json(res, 413, { ok: false, error: "payload_too_large" }); return true; }
  let raw: unknown;
  try { raw = JSON.parse(body.text); }
  catch { json(res, 400, { ok: false, error: "bad_json" }); return true; }

  if (validate) {
    const opened = openValidateRequest(raw);
    if (!opened.ok) { json(res, 400, { ok: false, error: "invalid_envelope" }); return true; }
    const validatedAt = Date.now();
    const prepared = prepareCandidate(context, opened.proposal, validatedAt, opened.forceDryRun);
    if (!prepared.ok) { json(res, prepared.status, prepared.body); return true; }
    const candidateDigest = proposalCandidateDigest({
      basePolicyVersion: prepared.current.version,
      rulesHash: prepared.rulesHash,
      engineVersion: NMZP_VERSION,
      validatedAt,
      forceDryRun: opened.forceDryRun,
      candidate: prepared.patch,
    });
    json(res, 200, {
      ok: true,
      policyVersion: prepared.current.version,
      rulesHash: prepared.rulesHash,
      candidateTotals: {
        overrideRules: Object.keys(prepared.patch.overrides.rules).length,
        customRules: prepared.patch.customRules.length,
        exemptions: prepared.patch.exemptions.length,
      },
      newCustomRulesDefaultDryRun: true,
      validatedAt,
      forceDryRun: opened.forceDryRun,
      engineVersion: NMZP_VERSION,
      candidate: prepared.patch,
      candidateDigest,
      reviewExpiresAt: validatedAt + PROPOSAL_REVIEW_TTL_MS,
    });
    return true;
  }

  const review = readApplyReview(raw);
  if (!review) {
    json(res, 400, { ok: false, error: "proposal_review_required" });
    return true;
  }
  const nowMs = Date.now();
  if (review.validatedAt > nowMs || nowMs - review.validatedAt > PROPOSAL_REVIEW_TTL_MS) {
    json(res, 409, { ok: false, error: "proposal_review_expired" });
    return true;
  }
  const prepared = prepareCandidate(context, review.proposal, review.validatedAt, review.forceDryRun);
  if (!prepared.ok) { json(res, prepared.status, prepared.body); return true; }
  const candidateDigest = proposalCandidateDigest({
    basePolicyVersion: prepared.current.version,
    rulesHash: prepared.rulesHash,
    engineVersion: NMZP_VERSION,
    validatedAt: review.validatedAt,
    forceDryRun: review.forceDryRun,
    candidate: prepared.patch,
  });
  if (candidateDigest !== review.candidateDigest) {
    json(res, 409, { ok: false, error: "proposal_preview_mismatch" });
    return true;
  }
  const result = await context.store.casPolicy(prepared.current.version, prepared.patch);
  if ("conflict" in result) {
    json(res, 409, { ok: false, error: "cas_conflict", version: result.version });
    return true;
  }
  json(res, 200, { ok: true, version: result.version, rulesHash: prepared.rulesHash, newCustomRulesDefaultDryRun: true });
  return true;
}
