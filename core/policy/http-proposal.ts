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

interface ProposalHttpContext {
  store: NmzpStore;
  monitor: MonitorMods;
  proposalParser: Awaited<ReturnType<typeof loadPolicyProposal>>;
  requireAdmin: (req: IncomingMessage, res: ServerResponse) => boolean;
}

/** Grok and other producers submit data proposals, never executable code or a policy file replacement. */
export async function handlePolicyProposalHttp(req: IncomingMessage, res: ServerResponse,
  pathname: string, context: ProposalHttpContext): Promise<boolean> {
  const capabilities = req.method === "GET" && pathname === `${ROOT}/capabilities`;
  const validate = req.method === "POST" && pathname === `${ROOT}/validate`;
  const apply = req.method === "POST" && pathname === `${ROOT}/apply`;
  if (!capabilities && !validate && !apply) return false;
  if (!context.requireAdmin(req, res)) return true;

  const rulesHash = policyRulesHash(context.monitor);
  const version = context.store.capturePolicy().policy.version;
  if (capabilities) {
    json(res, 200, {
      schema: context.proposalParser.PROPOSAL_SCHEMA,
      policyVersion: version,
      rulesHash,
      engineVersion: NMZP_VERSION,
      requiredBindings: ["basePolicyVersion", "baseRulesHash"],
      newCustomRulesDefaultDryRun: true,
      explicitActivationAllowed: true,
    });
    return true;
  }

  const body = await readLimited(req);
  if (!body.ok) { json(res, 413, { ok: false, error: "payload_too_large" }); return true; }
  let raw: unknown;
  try { raw = JSON.parse(body.text); }
  catch { json(res, 400, { ok: false, error: "bad_json" }); return true; }
  const parsed = context.proposalParser.parsePolicyProposal(raw, { rules: [...context.monitor.RULES] });
  if (!parsed.ok) { json(res, 400, { ok: false, error: "invalid_proposal", issues: parsed.errors.slice(0, 16).map((issue: string) => issue.slice(0, 128)) }); return true; }
  const proposal = parsed.proposal;
  if (proposal.basePolicyVersion === undefined || proposal.baseRulesHash === undefined) {
    json(res, 400, { ok: false, error: "proposal_base_required" }); return true;
  }
  // Recheck after reading the body; no old request can bypass recovery or current revisions.
  const current = context.store.getPolicy();
  if (proposal.basePolicyVersion !== current.version) {
    json(res, 409, { ok: false, error: "cas_conflict", version: current.version }); return true;
  }
  if (proposal.baseRulesHash !== rulesHash) {
    json(res, 409, { ok: false, error: "rules_changed", rulesHash }); return true;
  }
  // The shared UI merge intentionally skips duplicate matches. On this direct
  // publish path, a partial success would misrepresent what the caller asked for.
  const removedCustom = new Set(proposal.remove?.customRuleIds ?? []);
  const customMatches = new Set(current.customRules.filter((row) => !removedCustom.has(row.id))
    .map((row) => row.match.toLowerCase()));
  for (const row of proposal.customRules ?? []) {
    const match = row.match.toLowerCase();
    if (customMatches.has(match)) {
      json(res, 400, { ok: false, error: "proposal_existing_item" }); return true;
    }
    customMatches.add(match);
  }
  const removedExemptions = new Set(proposal.remove?.exemptionIds ?? []);
  const exemptionMatches = new Set((current.exemptions ?? []).filter((row) => !removedExemptions.has(row.id))
    .map((row) => `${row.ruleId}\0${row.match.toLowerCase()}`));
  for (const row of proposal.exemptions ?? []) {
    const match = `${row.ruleId}\0${row.match.toLowerCase()}`;
    if (exemptionMatches.has(match)) {
      json(res, 400, { ok: false, error: "proposal_existing_item" }); return true;
    }
    exemptionMatches.add(match);
  }
  const merged = context.proposalParser.mergeProposal({
    overrides: current.overrides,
    customRules: current.customRules,
    exemptions: current.exemptions,
  }, proposal, { now: Date.now(), forceDryRun: false });
  if (!merged.ok) {
    json(res, 400, { ok: false, error: "invalid_proposal", issues: merged.errors.slice(0, 16).map((issue: string) => issue.slice(0, 128)) }); return true;
  }
  const patch = merged.next;
  if (isDeepStrictEqual(patch, {
    overrides: current.overrides, customRules: current.customRules, exemptions: current.exemptions,
  })) {
    json(res, 400, { ok: false, error: "proposal_no_changes" }); return true;
  }
  let preview: ReturnType<NmzpStore["previewPolicyPatch"]>;
  try { preview = context.store.previewPolicyPatch(current.version, patch); }
  catch (error) {
    if (!(error instanceof InvalidPolicySnapshot) && !(error instanceof PolicyDomainError)) throw error;
    json(res, 400, { ok: false, error: "invalid_proposal",
      ...(error instanceof PolicyDomainError ? { issues: [error.code] } : {}) });
    return true;
  }
  if (preview.conflict) {
    json(res, 409, { ok: false, error: "cas_conflict", version: preview.version }); return true;
  }
  if (validate) {
    json(res, 200, { ok: true, policyVersion: current.version, rulesHash,
      candidateTotals: { overrideRules: Object.keys(patch.overrides.rules).length, customRules: patch.customRules.length,
        exemptions: patch.exemptions.length }, newCustomRulesDefaultDryRun: true });
    return true;
  }
  const result = await context.store.casPolicy(current.version, patch);
  if ("conflict" in result) {
    json(res, 409, { ok: false, error: "cas_conflict", version: result.version }); return true;
  }
  json(res, 200, { ok: true, version: result.version, rulesHash, newCustomRulesDefaultDryRun: true });
  return true;
}
