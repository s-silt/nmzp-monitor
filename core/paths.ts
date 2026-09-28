import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isBundledRuntime } from "./runtime-layout.ts";

export function coreDirFrom(metaUrl: string): string {
  return dirname(fileURLToPath(metaUrl));
}

/**
 * Source tree: repo/core → repo/src/lib/monitor
 * Release tree: /opt/nmzp/monitor (copied next to nmzp)
 */
export function resolveMonitorDir(coreDir: string): string {
  const release = join(coreDir, "monitor");
  if (existsSync(join(release, "engine.ts"))) return release;
  const source = join(coreDir, "..", "src", "lib", "monitor");
  if (existsSync(join(source, "engine.ts"))) return source;
  throw new Error("monitor modules not found (engine.ts)");
}

export function resolveUiDir(coreDir: string): string | null {
  const candidates = [join(coreDir, "ui"), join(coreDir, "..", "ui"), join(coreDir, "..", "dist")];
  for (const dir of candidates) {
    if (existsSync(join(dir, "index.html"))) return dir;
  }
  return null;
}

export function resolveRepoRoot(coreDir: string): string {
  const parent = join(coreDir, "..");
  if (existsSync(join(parent, "package.json"))) return parent;
  return coreDir;
}

export function monitorFileUrl(coreDir: string, file: string): string {
  return pathToFileURL(join(resolveMonitorDir(coreDir), file)).href;
}

type EngineMod = typeof import("../src/lib/monitor/engine.ts");
type SessionMod = typeof import("../src/lib/monitor/session-window.ts");
type PrivacyMod = typeof import("../src/lib/monitor/privacy.ts");
type RightsMod = typeof import("../src/lib/monitor/rights.ts");
type IngestMod = typeof import("../src/lib/monitor/ingest.ts");
type TrustMod = typeof import("../src/lib/monitor/trust.ts");
type AgentsMod = typeof import("../src/lib/monitor/agents.ts");
type CliMod = typeof import("../src/lib/monitor/cli.ts");
type WatchMod = typeof import("../src/lib/monitor/watch.ts");
type CorrelateMod = typeof import("../src/lib/monitor/correlate.ts");
type RulesMod = typeof import("../src/lib/monitor/rules.ts");
type OverridesMod = typeof import("../src/lib/monitor/overrides.ts");

export type LoadedMonitor = {
  evaluate: EngineMod["evaluate"];
  RULES: RulesMod["RULES"];
  RULE_BY_ID: RulesMod["RULE_BY_ID"];
  isProtectedRule: OverridesMod["isProtectedRule"];
  protectedDowngrades: OverridesMod["protectedDowngrades"];
  unknownRuleIds: OverridesMod["unknownRuleIds"];
  protectedRuleIds: OverridesMod["protectedRuleIds"];
  SUGGESTED_OVERRIDES: OverridesMod["SUGGESTED_OVERRIDES"];
  SessionWindows: SessionMod["SessionWindows"];
  applySessionCorrelate: SessionMod["applySessionCorrelate"];
  INGEST_MAX_RAW: IngestMod["INGEST_MAX_RAW"];
  ingestObservation: TrustMod["ingestObservation"];
  privacy: PrivacyMod;
  rights: RightsMod;
  agents: AgentsMod;
  parseNmzpCli: CliMod["parseNmzpCli"];
  compilePrivacyDraft: PrivacyMod["compilePrivacyDraft"];
  isWatchedProcess: WatchMod["isWatchedProcess"];
  normalizeTool: AgentsMod["normalizeTool"];
  isAgentId: AgentsMod["isAgentId"];
  correlate: CorrelateMod["correlate"];
  markFrom: CorrelateMod["markFrom"];
  pushHit: CorrelateMod["pushHit"];
};

export async function loadMonitor(coreDir: string): Promise<LoadedMonitor> {
  if (!isBundledRuntime()) resolveMonitorDir(coreDir);
  const [engine, session, privacy, rights, ingest, trust, agents, cli, watch, correlate, rules, overrides] = await Promise.all([
    import("../src/lib/monitor/engine.ts"),
    import("../src/lib/monitor/session-window.ts"),
    import("../src/lib/monitor/privacy.ts"),
    import("../src/lib/monitor/rights.ts"),
    import("../src/lib/monitor/ingest.ts"),
    import("../src/lib/monitor/trust.ts"),
    import("../src/lib/monitor/agents.ts"),
    import("../src/lib/monitor/cli.ts"),
    import("../src/lib/monitor/watch.ts"),
    import("../src/lib/monitor/correlate.ts"),
    import("../src/lib/monitor/rules.ts"),
    import("../src/lib/monitor/overrides.ts"),
  ]);
  return {
    evaluate: engine.evaluate as (typeof engine)["evaluate"],
    RULES: rules.RULES as (typeof rules)["RULES"],
    RULE_BY_ID: rules.RULE_BY_ID as (typeof rules)["RULE_BY_ID"],
    isProtectedRule: overrides.isProtectedRule as (typeof overrides)["isProtectedRule"],
    protectedDowngrades: overrides.protectedDowngrades as (typeof overrides)["protectedDowngrades"],
    unknownRuleIds: overrides.unknownRuleIds as (typeof overrides)["unknownRuleIds"],
    protectedRuleIds: overrides.protectedRuleIds as (typeof overrides)["protectedRuleIds"],
    SUGGESTED_OVERRIDES: overrides.SUGGESTED_OVERRIDES as (typeof overrides)["SUGGESTED_OVERRIDES"],
    SessionWindows: session.SessionWindows as (typeof session)["SessionWindows"],
    applySessionCorrelate: session.applySessionCorrelate as (typeof session)["applySessionCorrelate"],
    INGEST_MAX_RAW: ingest.INGEST_MAX_RAW,
    ingestObservation: trust.ingestObservation as (typeof trust)["ingestObservation"],
    privacy,
    rights,
    agents,
    parseNmzpCli: cli.parseNmzpCli as (typeof cli)["parseNmzpCli"],
    compilePrivacyDraft: privacy.compilePrivacyDraft as (typeof privacy)["compilePrivacyDraft"],
    isWatchedProcess: watch.isWatchedProcess as (typeof watch)["isWatchedProcess"],
    normalizeTool: agents.normalizeTool as (typeof agents)["normalizeTool"],
    isAgentId: agents.isAgentId as (typeof agents)["isAgentId"],
    correlate: correlate.correlate as (typeof correlate)["correlate"],
    markFrom: correlate.markFrom as (typeof correlate)["markFrom"],
    pushHit: correlate.pushHit as (typeof correlate)["pushHit"],
  };
}

export type MonitorMods = Awaited<ReturnType<typeof loadMonitor>>;

/** Proposal parsing is an admin HTTP concern and must not enter the Hook loader. */
export async function loadPolicyProposal(coreDir: string): Promise<typeof import("../src/lib/monitor/policy-proposal.ts")> {
  if (!isBundledRuntime()) resolveMonitorDir(coreDir);
  return import("../src/lib/monitor/policy-proposal.ts");
}
