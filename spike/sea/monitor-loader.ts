/**
 * Spike-only replacement for core/paths.ts.
 * Provenance: statically imports the same monitor modules loadMonitor() would
 * dynamic-import from src/lib/monitor via file URL. No filesystem probe of the
 * source tree; coreDir is ignored at runtime because SEA __filename is execPath.
 */
import { dirname } from "node:path";
import * as engine from "../../src/lib/monitor/engine.ts";
import * as session from "../../src/lib/monitor/session-window.ts";
import * as privacy from "../../src/lib/monitor/privacy.ts";
import * as rights from "../../src/lib/monitor/rights.ts";
import * as ingest from "../../src/lib/monitor/ingest.ts";
import * as trust from "../../src/lib/monitor/trust.ts";
import * as agents from "../../src/lib/monitor/agents.ts";
import * as cli from "../../src/lib/monitor/cli.ts";
import * as watch from "../../src/lib/monitor/watch.ts";
import * as correlate from "../../src/lib/monitor/correlate.ts";
import * as rules from "../../src/lib/monitor/rules.ts";
import * as overrides from "../../src/lib/monitor/overrides.ts";
import * as policyProposal from "../../src/lib/monitor/policy-proposal.ts";

function seaRoot(): string {
  return dirname(process.execPath);
}

export function coreDirFrom(_metaUrl: string): string {
  return seaRoot();
}

export function resolveMonitorDir(_coreDir: string): string {
  return seaRoot();
}

export function resolveUiDir(_coreDir: string): string | null {
  return null;
}

export function resolveRepoRoot(_coreDir: string): string {
  return seaRoot();
}

export function monitorFileUrl(_coreDir: string, file: string): string {
  return `nmzp-sea:monitor/${file}`;
}

export async function loadMonitor(_coreDir: string) {
  return {
    evaluate: engine.evaluate,
    RULES: rules.RULES,
    RULE_BY_ID: rules.RULE_BY_ID,
    isProtectedRule: overrides.isProtectedRule,
    protectedDowngrades: overrides.protectedDowngrades,
    unknownRuleIds: overrides.unknownRuleIds,
    protectedRuleIds: overrides.protectedRuleIds,
    SUGGESTED_OVERRIDES: overrides.SUGGESTED_OVERRIDES,
    SessionWindows: session.SessionWindows,
    applySessionCorrelate: session.applySessionCorrelate,
    INGEST_MAX_RAW: ingest.INGEST_MAX_RAW,
    ingestObservation: trust.ingestObservation,
    privacy,
    rights,
    agents,
    parseNmzpCli: cli.parseNmzpCli,
    compilePrivacyDraft: privacy.compilePrivacyDraft,
    isWatchedProcess: watch.isWatchedProcess,
    normalizeTool: agents.normalizeTool,
    isAgentId: agents.isAgentId,
    correlate: correlate.correlate,
    markFrom: correlate.markFrom,
    pushHit: correlate.pushHit,
  };
}

export type MonitorMods = Awaited<ReturnType<typeof loadMonitor>>;

export async function loadPolicyProposal(_coreDir: string) {
  return policyProposal;
}
