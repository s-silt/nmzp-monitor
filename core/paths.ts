import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

export async function loadMonitor(coreDir: string) {
  const url = (file: string) => monitorFileUrl(coreDir, file);
  const [engine, session, privacy, rights, ingest, trust, agents, cli, watch, correlate, rules, overrides] = await Promise.all([
    import(url("engine.ts")),
    import(url("session-window.ts")),
    import(url("privacy.ts")),
    import(url("rights.ts")),
    import(url("ingest.ts")),
    import(url("trust.ts")),
    import(url("agents.ts")),
    import(url("cli.ts")),
    import(url("watch.ts")),
    import(url("correlate.ts")),
    import(url("rules.ts")),
    import(url("overrides.ts")),
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
    INGEST_MAX_RAW: ingest.INGEST_MAX_RAW as number,
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
export async function loadPolicyProposal(coreDir: string) {
  return import(monitorFileUrl(coreDir, "policy-proposal.ts"));
}
