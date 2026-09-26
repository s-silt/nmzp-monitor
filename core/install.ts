import { codexHookConfiguredRaw, codexHookEntry, codexHookTrust, mergeCodexHooks, type CodexHookTrustStatus } from "./codex-hooks.ts";
import {
  antigravityHookConfiguredRaw,
  antigravityHookDoc,
  antigravityHooksPath,
  mergeAntigravityHooks,
} from "./antigravity-hooks.ts";
import {
  EXTRA_HOOK_AGENTS,
  hostHookConfiguredRaw,
  hostHookStrip,
  hostHookTargets,
  hostHookWrite,
  isExtraHookAgent,
  type ExtraHookAgent,
} from "./host-adapters.ts";
import { mergeZcodeConfig, zcodeConfigPath, zcodeHookConfiguredRaw, zcodeHookGroup } from "./zcode-hooks.ts";
/**
 * Join / leave. Tests pass a temp home and temp startup dir. Never touch the real profile from tests.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { cp } from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { basename, join } from "node:path";
import { GROK_HOOK_FILE, NMZP_VERSION, TASK_NAME } from "./constants.ts";
import { pinnedHttps } from "./https-client.ts";
import {
  FileRollback,
  atomicWriteFile,
  restrictPath,
  sha256Text,
  snapshotPath,
  snapshotsMatch,
  withCooperatingInstallLock,
  type FileSnap,
  type RollbackReport,
} from "./install-fs.ts";
import {
  defaultLauncherRunner,
  defaultProbeController,
  hiddenProbeTr,
  isOurScheduledTask,
  probeLockMatchesRequested,
  readProbeLock,
  schtasksCreateArgs,
  schtasksRunner,
  STARTUP_LAUNCHER_NAME,
  startupLauncherBody,
  taskLooksPresent,
  userStartupDir,
  type AutostartKind,
  type LauncherRunner,
  type ProbeController,
  type ProbeStartTransaction,
  type TaskRunner,
} from "./install-autostart.ts";
import {
  hookCommand,
  inspectClaudeSettings,
  inspectGrokHookFile,
  isNmzpLikeHook,
  isNmzpOwnedHook,
  mergeClaudeSettings,
  mergeGrokHookFile,
  parseJsonObjectOrThrow,
} from "./install-hooks.ts";
import { writePolicyCache } from "./policy-cache.ts";
import type { PolicyState, SnapshotGuardReport } from "./schema.ts";
import { adaptSnapshotGuardLibraryStatus } from "./schema.ts";
import { collectSnapshotGuardStatus } from "./snapshot-status-collector.ts";

export type { AutostartKind, LauncherRunner, ProbeController, TaskRunner };
export {
  defaultProbeController,
  hiddenProbeTr,
  schtasksCreateArgs,
  schtasksRunner,
  STARTUP_LAUNCHER_NAME,
  startupLauncherBody,
  userStartupDir,
};
export { hookCommand, mergeClaudeSettings, stripClaudeSettings } from "./install-hooks.ts";
export { restrictPath } from "./install-fs.ts";

export interface JoinBundle {
  url: string;
  caPem: string;
  fingerprintSha256: string;
  ticket: string;
}

export interface JoinTransport {
  join(req: { ticket: string; hostname: string; os: string; user: string }): Promise<{ status: number; body: string }>;
  policy(token: string): Promise<{ status: number; body: string }>;
}

export interface JoinOpts {
  home: string;
  bundle: JoinBundle;
  nodePath: string;
  coreDir: string;
  skipRegister?: boolean;
  skipStartup?: boolean;
  skipProbe?: boolean;
  taskRunner?: TaskRunner;
  launcherRunner?: LauncherRunner;
  startupDir?: string;
  probeController?: ProbeController;
  transport?: JoinTransport;
  copyRuntime?: (coreDir: string, dest: string) => Promise<void>;
  hostname?: string;
  user?: string;
  os?: "win32" | "linux" | "darwin";
  /** Explicit hosts that may be created even when their directory is absent. Not a discovery scan. */
  requestedHosts?: Array<"grok" | "claude" | "codex">;
  /** Injected status reader. Join never applies ACL. */
  snapshotGuardStatus?: (opts: { home: string }) => Promise<unknown>;
}

export type SnapshotGuardJoinApply = "cli" | "skipped_external" | "degraded";

export interface JoinResult {
  deviceId: string;
  runtimeDir: string;
  /** True only when an NMZP-owned scheduled task is actually registered. Never true on Access is denied. */
  taskOk: boolean | "skipped";
  autostart: AutostartKind;
  autostartPath?: string;
  files: string[];
  snapshotGuard?: SnapshotGuardReport;
  /** ACL apply is not part of the join rollback transaction. */
  snapshotGuardApply?: SnapshotGuardJoinApply;
  snapshotGuardError?: string;
  /** Primary hosts whose directory was absent and that were not carried from an earlier join. */
  skippedHosts?: Array<"grok" | "claude" | "codex">;
  /** Codex trust after this join. `skipped` means Codex was not configured. Read errors are `unknown`. */
  codexTrust?: CodexHookTrustStatus | "skipped";
  /** Manual /hooks instruction when Codex is configured and not already trusted. */
  codexNotice?: string;
  warnings?: string[];
}

interface InstallManifest {
  version: string;
  deviceId: string;
  grokPath: string;
  claudePath: string;
  codexPath?: string;
  zcodePath?: string;
  antigravityPath?: string;
  runtimeDir: string;
  task: string;
  taskOwned: boolean;
  taskTr?: string;
  autostart: AutostartKind;
  autostartPath?: string;
  files: string[];
  grok: { created: boolean; originalSha256: string | null; writtenSha256: string };
  claude: { originalSha256: string | null; writtenSha256: string };
  antigravity?: { created: boolean; writtenSha256: string };
  hostFiles?: Array<{ agent: string; path: string; created: boolean; writtenSha256: string }>;
  launcher?: { created: boolean; originalSha256: string | null; writtenSha256: string; path: string };
}

function sepOf(home: string): "\\" | "/" {
  return home.includes("\\") && !home.includes("/") ? "\\" : "/";
}

function p(home: string, ...parts: string[]): string {
  const s = sepOf(home);
  return [home.replace(/[\\/]$/, ""), ...parts].join(s);
}

export function parseCtPin(raw: string): { url: string; caPem: string; fingerprintSha256: string } | null {
  try {
    const j = JSON.parse(raw) as Partial<JoinBundle>;
    if (typeof j.url !== "string" || !j.url.startsWith("https://")) return null;
    if (typeof j.caPem !== "string" || !j.caPem.includes("BEGIN CERTIFICATE")) return null;
    if (typeof j.fingerprintSha256 !== "string" || j.fingerprintSha256.length < 32) return null;
    return {
      url: j.url.replace(/\/$/, ""),
      caPem: j.caPem,
      fingerprintSha256: j.fingerprintSha256.toLowerCase(),
    };
  } catch {
    return null;
  }
}

export function parseJoinBundle(raw: string): JoinBundle | null {
  const pin = parseCtPin(raw);
  if (!pin) return null;
  try {
    const j = JSON.parse(raw) as Partial<JoinBundle>;
    if (typeof j.ticket !== "string" || j.ticket.length < 8) return null;
    return { ...pin, ticket: j.ticket };
  } catch {
    return null;
  }
}

/** Official Grok: matcher is a regex on the tool name; omit/empty matches every tool. */
export function grokPreToolUseMatches(toolName: string, matcher?: string | null): boolean {
  if (matcher == null || matcher === "") return true;
  try {
    return new RegExp(matcher).test(toolName);
  } catch {
    return false;
  }
}

export function grokHookDoc(
  runtimeEntry: string,
  nodePath: string,
  os: string = process.platform,
): Record<string, unknown> {
  const command = hookCommand(nodePath, runtimeEntry, "grok", os);
  return {
    hooks: {
      PreToolUse: [
        {
          hooks: [{ type: "command", command, timeout: 8 }],
        },
      ],
    },
  };
}

function claudeHookEntry(
  runtimeEntry: string,
  nodePath: string,
  os: string = process.platform,
): Record<string, unknown> {
  const command = hookCommand(nodePath, runtimeEntry, "claude", os);
  return {
    matcher: "*",
    hooks: [{ type: "command", command }],
  };
}

async function copyUiIntoRuntime(coreDir: string, dest: string): Promise<void> {
  const destUi = join(dest, "ui");
  const packed = join(coreDir, "ui");
  const dist = join(coreDir, "..", "dist");
  if (existsSync(join(packed, "index.html"))) {
    await cp(packed, destUi, { recursive: true });
    return;
  }
  if (existsSync(join(dist, "index.html"))) {
    await cp(dist, destUi, { recursive: true });
    return;
  }
  if (existsSync(join(destUi, "index.html"))) return;
  throw new Error("install_missing_ui");
}

export async function copyRuntime(coreDir: string, dest: string): Promise<void> {
  mkdirSync(dest, { recursive: true });
  await cp(coreDir, dest, {
    recursive: true,
    filter: (src) => {
      const base = src.replace(/\\/g, "/");
      if (base.endsWith(".test.ts")) return false;
      if (/\/(native-[^/]+|model-gateway[^/]*|protected-session[^/]*|model-response[^/]*)(\/|$)/.test(base)) return false;
      return true;
    },
  });
  const monitorSrc = existsSync(join(coreDir, "monitor", "engine.ts"))
    ? join(coreDir, "monitor")
    : join(coreDir, "..", "src", "lib", "monitor");
  if (existsSync(monitorSrc)) {
    await cp(monitorSrc, join(dest, "monitor"), { recursive: true, filter: (s) => !s.endsWith(".test.ts") });
  }
  for (const name of ["response-evidence", "evidence-window", "agent-discovery-schema", "agent-catalog"]) {
    const file=join(dest,"monitor",name+".ts");
    if (existsSync(file)) writeFileSync(file,readFileSync(file,"utf8").replaceAll("../../../core/"+name+".ts","../"+name+".ts"));
  }
  const bridge = join(dest,"monitor","network-evidence.ts");
  if (existsSync(bridge)) writeFileSync(bridge,readFileSync(bridge,"utf8").replaceAll('"../../../core/network-evidence.ts"','"../network-evidence.ts"').replaceAll('"../../../core/schema.ts"','"../schema.ts"'));
  await copyUiIntoRuntime(coreDir, dest);
}

function defaultTransport(bundle: JoinBundle): JoinTransport {
  return {
    async join(req) {
      return pinnedHttps({
        url: `${bundle.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify(req),
        headers: { "content-type": "application/json" },
        caPem: bundle.caPem,
        fingerprintSha256: bundle.fingerprintSha256,
      });
    },
    async policy(token) {
      return pinnedHttps({
        url: `${bundle.url}/api/v1/policy`,
        method: "GET",
        headers: { authorization: `Bearer ${token}` },
        caPem: bundle.caPem,
        fingerprintSha256: bundle.fingerprintSha256,
      });
    },
  };
}

function readCredsFile(home: string): {
  deviceId: string;
  token: string;
  url: string;
  caPem: string;
  fingerprintSha256: string;
} | null {
  try {
    const j = JSON.parse(readFileSync(p(home, ".nmzp", "credentials.json"), "utf8")) as {
      deviceId?: string;
      token?: string;
      url?: string;
      caPem?: string;
      fingerprintSha256?: string;
    };
    if (!j.deviceId || !j.token || !j.url || !j.caPem || !j.fingerprintSha256) return null;
    return j as { deviceId: string; token: string; url: string; caPem: string; fingerprintSha256: string };
  } catch {
    return null;
  }
}

function readManifest(home: string): InstallManifest | null {
  try {
    return JSON.parse(readFileSync(p(home, ".nmzp", "manifest.json"), "utf8")) as InstallManifest;
  } catch {
    return null;
  }
}

async function defaultSnapshotGuardStatus(opts: { home: string }): Promise<unknown> {
  return collectSnapshotGuardStatus({ home: opts.home });
}

async function defaultSnapshotGuardApply(opts: { home: string }): Promise<unknown> {
  const mod = await import("./snapshot-guard.ts");
  return mod.snapshotGuardApply({ home: opts.home });
}

function snapshotGuardJoinNoteFromStatus(st: SnapshotGuardReport): Pick<
  JoinResult,
  "snapshotGuard" | "snapshotGuardApply" | "snapshotGuardError"
> {
  if (st.error === "external_restriction" || (st.writeBlocked && !st.managed)) {
    return { snapshotGuard: st, snapshotGuardApply: "skipped_external", snapshotGuardError: st.error ?? "external_restriction" };
  }
  if (!st.supported) {
    return { snapshotGuard: st, snapshotGuardApply: "degraded", snapshotGuardError: st.error ?? "unsupported_platform" };
  }
  if (!st.targetPresent) {
    return { snapshotGuard: st, snapshotGuardApply: "degraded", snapshotGuardError: st.error ?? "target_missing" };
  }
  if (st.error === "zcode_running" || st.error === "process_list_failed") {
    return { snapshotGuard: st, snapshotGuardApply: "degraded", snapshotGuardError: st.error };
  }
  return { snapshotGuard: st, snapshotGuardApply: "cli" };
}

/** Read-only. Never throws into join rollback. Never apply/restore. */
async function snapshotGuardJoinNote(
  home: string,
  collect?: (opts: { home: string }) => Promise<unknown>,
): Promise<Pick<JoinResult, "snapshotGuard" | "snapshotGuardApply" | "snapshotGuardError">> {
  try {
    const raw = await (collect ?? defaultSnapshotGuardStatus)({ home });
    const st = adaptSnapshotGuardLibraryStatus(raw);
    if (!st) return { snapshotGuardApply: "degraded", snapshotGuardError: "status_failed" };
    return snapshotGuardJoinNoteFromStatus(st);
  } catch {
    return { snapshotGuardApply: "degraded", snapshotGuardError: "status_failed" };
  }
}

export type SnapshotGuardApplyAction = "applied" | "skipped_external" | "degraded" | "noop";

export interface SnapshotGuardApplyResult {
  action: SnapshotGuardApplyAction;
  status?: SnapshotGuardReport;
  error?: string;
}

/**
 * Independent of join FileRollback. LAN/root CLI should call this, not fold ACL into join.
 * Never restores, never deletes archives, never unlocks an external restriction.
 */
export async function applySnapshotGuardStandalone(opts: {
  home: string;
  now?: number;
  status?: (opts: { home: string }) => Promise<unknown>;
  apply?: (opts: { home: string }) => Promise<unknown>;
  restore?: (opts: { home: string }) => Promise<unknown>;
}): Promise<SnapshotGuardApplyResult> {
  const statusFn = opts.status ?? defaultSnapshotGuardStatus;
  let raw: unknown;
  try {
    raw = await statusFn({ home: opts.home });
  } catch {
    return { action: "degraded", error: "status_failed" };
  }
  const st = adaptSnapshotGuardLibraryStatus(raw);
  if (!st) return { action: "degraded", error: "status_failed" };
  if (st.error === "external_restriction" || (st.writeBlocked && !st.managed)) {
    return { action: "skipped_external", status: st, error: st.error ?? "external_restriction" };
  }
  if (!st.supported) return { action: "degraded", status: st, error: st.error ?? "unsupported_platform" };
  if (!st.targetPresent) return { action: "degraded", status: st, error: st.error ?? "target_missing" };
  if (st.error === "zcode_running" || st.error === "process_list_failed") {
    return { action: "degraded", status: st, error: st.error };
  }
  if (st.active && st.managed) return { action: "noop", status: st };
  void opts.restore;
  const applyFn = opts.apply ?? defaultSnapshotGuardApply;
  let applied: unknown;
  try {
    applied = await applyFn({ home: opts.home });
  } catch {
    return { action: "degraded", status: st, error: "apply_failed" };
  }
  const next = adaptSnapshotGuardLibraryStatus(applied);
  if (!next) return { action: "degraded", status: st, error: "apply_failed" };
  if (next.error === "external_restriction") {
    return { action: "skipped_external", status: next, error: next.error };
  }
  if (!next.active) {
    return { action: "degraded", status: next, error: next.error ?? "apply_failed" };
  }
  return { action: "applied", status: next };
}

type PrimaryHost = "grok" | "claude" | "codex";

function codexNoticeFor(status: CodexHookTrustStatus | "skipped"): string | undefined {
  if (status === "skipped" || status === "not_configured" || status === "trusted") return undefined;
  if (status === "modified") return "codex trust modified: /hooks approve NMZP PreToolUse v1";
  if (status === "unknown") return "codex trust unknown: /hooks approve NMZP PreToolUse v1";
  return "codex=/hooks approve NMZP PreToolUse v1";
}

function publishSnap(path: string, body: string, snap: FileSnap, rb: FileRollback): void {
  if (!snapshotsMatch(path, snap)) throw new Error("host_config_conflict");
  rb.noteMissingParents(path);
  if (snap.absent) rb.noteCreated(path, body);
  else rb.notePrior(path, snap.text ?? "", body);
  atomicWriteFile(path, body, 0o600);
}

function publishRestricted(path: string, body: string, snap: FileSnap, rb: FileRollback): void {
  publishSnap(path, body, snap, rb);
  restrictPath(path);
}

async function rememberPolicy(
  path: string,
  snap: FileSnap,
  token: string,
  transport: JoinTransport,
  rb: FileRollback,
): Promise<void> {
  if (!snapshotsMatch(path, snap)) throw new Error("host_config_conflict");
  const pol = await transport.policy(token);
  if (pol.status !== 200) return;
  let policy: PolicyState;
  try {
    policy = JSON.parse(pol.body) as PolicyState;
  } catch {
    return;
  }
  if (!policy?.version) return;
  if (!snapshotsMatch(path, snap)) throw new Error("host_config_conflict");
  await writePolicyCache(path, policy);
  const written = readFileSync(path, "utf8");
  if (snap.absent) rb.noteCreated(path, written);
  else rb.notePrior(path, snap.text ?? "", written);
}

export async function joinDevice(opts: JoinOpts): Promise<JoinResult> {
  return withCooperatingInstallLock(opts.home, () => joinDeviceLocked(opts));
}

async function joinDeviceLocked(opts: JoinOpts): Promise<JoinResult> {
  const home = opts.home;
  const os = opts.os ?? (process.platform as "win32" | "linux" | "darwin");
  const nmzp = p(home, ".nmzp");
  const runtimeDir = p(nmzp, "runtime", NMZP_VERSION);
  const backupDir = p(nmzp, "backups", String(Date.now()));
  const grokPath = p(home, ".grok", "hooks", GROK_HOOK_FILE);
  const claudePath = p(home, ".claude", "settings.json");
  const codexPath = p(home, ".codex", "hooks.json");
  const zcodePath = zcodeConfigPath(home);
  const antigravityPath = antigravityHooksPath(home);
  const zcodeCli = join(home, ".zcode", "cli");
  const antigravityHome = join(home, ".gemini", "antigravity");
  const requested = new Set(opts.requestedHosts ?? []);
  const writeZcode = existsSync(zcodeCli);
  const writeAntigravity = existsSync(antigravityHome);
  const writeGrok = existsSync(p(home, ".grok")) || requested.has("grok");
  const writeClaude = existsSync(p(home, ".claude")) || requested.has("claude");
  const writeCodex = existsSync(p(home, ".codex")) || requested.has("codex");
  const entry = join(runtimeDir, "nmzp.mjs");
  const prevManifest = readManifest(home);
  const carryGrok = !writeGrok && !!prevManifest?.grokPath && existsSync(prevManifest.grokPath);
  const carryClaude = !writeClaude && !!prevManifest?.claudePath && existsSync(prevManifest.claudePath);
  const carryCodex = !writeCodex && !!prevManifest?.codexPath && existsSync(prevManifest.codexPath);
  const skippedHosts: PrimaryHost[] = [];
  if (!writeGrok && !carryGrok) skippedHosts.push("grok");
  if (!writeClaude && !carryClaude) skippedHosts.push("claude");
  if (!writeCodex && !carryCodex) skippedHosts.push("codex");

  const credPath = p(nmzp, "credentials.json");
  const corePath = p(nmzp, "core.json");
  const manifestPath = p(nmzp, "manifest.json");
  const policyPath = p(nmzp, "policy-cache.json");
  const credSnap = snapshotPath(credPath);
  const coreSnap = snapshotPath(corePath);
  const manifestSnap = snapshotPath(manifestPath);
  const policySnap = snapshotPath(policyPath);
  const grokSnap = writeGrok ? snapshotPath(grokPath) : undefined;
  const claudeSnap = writeClaude ? snapshotPath(claudePath) : undefined;
  const codexSnap = writeCodex ? snapshotPath(codexPath) : undefined;
  const zcodeSnap = writeZcode ? snapshotPath(zcodePath) : undefined;
  const antigravitySnap = writeAntigravity ? snapshotPath(antigravityPath) : undefined;
  const prevGrok = grokSnap?.text ?? null;
  const prevClaude = claudeSnap?.text ?? null;
  const prevCodex = codexSnap ? codexSnap.text : null;
  const prevZcode = zcodeSnap ? zcodeSnap.text : null;
  const prevAntigravity = antigravitySnap ? antigravitySnap.text : null;
  if (writeCodex) mergeCodexHooks(prevCodex);
  if (writeZcode) mergeZcodeConfig(prevZcode);
  if (writeAntigravity) mergeAntigravityHooks(prevAntigravity);
  if (prevClaude && prevClaude.trim()) parseJsonObjectOrThrow(prevClaude, "claude_settings_corrupt");
  if (prevGrok && prevGrok.trim()) parseJsonObjectOrThrow(prevGrok, "grok_hook_corrupt");
  const hostJobs: Array<{ agent: ExtraHookAgent; path: string; prev: string | null; next: string; snap: FileSnap }> = [];
  for (const agent of EXTRA_HOOK_AGENTS) {
    for (const path of hostHookTargets(agent, home)) {
      const snap = snapshotPath(path);
      const prev = snap.text;
      const next = hostHookWrite(agent, prev, opts.nodePath, entry, os);
      hostJobs.push({ agent, path, prev, next, snap });
    }
  }
  const grokMerged = writeGrok ? mergeGrokHookFile(prevGrok, grokHookDoc(entry, opts.nodePath, os)) : undefined;
  const claudeMerged = writeClaude ? mergeClaudeSettings(prevClaude, claudeHookEntry(entry, opts.nodePath, os)) : undefined;
  const codexBody = writeCodex ? mergeCodexHooks(prevCodex, codexHookEntry(opts.nodePath, entry, os)) : undefined;
  const zcodeBody = writeZcode ? mergeZcodeConfig(prevZcode, zcodeHookGroup(opts.nodePath, entry)) : undefined;
  const antigravityBody = writeAntigravity
    ? mergeAntigravityHooks(prevAntigravity, antigravityHookDoc(opts.nodePath, entry, os))
    : undefined;

  const transport = opts.transport ?? defaultTransport(opts.bundle);
  const hostname = opts.hostname ?? "host";
  const user = opts.user ?? "user";
  let deviceId: string;
  let token: string;
  const probe = opts.probeController ?? defaultProbeController();
  let legacyStartedNew = false;
  let probeTxn: ProbeStartTransaction | undefined;
  let rb: FileRollback | undefined;
  try {
    mkdirSync(nmzp, { recursive: true });
    restrictPath(nmzp);
    rb = new FileRollback(backupDir);
    const existing = readCredsFile(home);
    const reusable =
      existing &&
      existing.url === opts.bundle.url &&
      existing.fingerprintSha256.toLowerCase() === opts.bundle.fingerprintSha256.toLowerCase();
    if (reusable) {
      const pol = await transport.policy(existing.token);
      if (pol.status === 200) {
        deviceId = existing.deviceId;
        token = existing.token;
      } else {
        const res = await transport.join({ ticket: opts.bundle.ticket, hostname, os, user });
        if (res.status !== 200) throw new Error(`join_http_${res.status}`);
        const payload = JSON.parse(res.body) as { deviceId?: string; deviceToken?: string };
        if (!payload.deviceId || !payload.deviceToken) throw new Error("join_bad_response");
        deviceId = payload.deviceId;
        token = payload.deviceToken;
      }
    } else {
      const res = await transport.join({ ticket: opts.bundle.ticket, hostname, os, user });
      if (res.status !== 200) throw new Error(`join_http_${res.status}`);
      const payload = JSON.parse(res.body) as { deviceId?: string; deviceToken?: string };
      if (!payload.deviceId || !payload.deviceToken) throw new Error("join_bad_response");
      deviceId = payload.deviceId;
      token = payload.deviceToken;
    }

    const running = await probe.isOwnRunning(home);
    const runtimeExisted = existsSync(runtimeDir);
    const probeLock = readProbeLock(home);
    const verifiedDifferent =
      probeLock !== null && running && !probeLockMatchesRequested(probeLock, { nodePath: opts.nodePath, entry });
    if (verifiedDifferent || !(runtimeExisted && running)) {
      if (!runtimeExisted) rb.noteCreatedTree(runtimeDir);
      await (opts.copyRuntime ?? copyRuntime)(opts.coreDir, runtimeDir);
    }

    if (writeGrok && grokSnap && grokMerged) publishSnap(grokPath, grokMerged.body, grokSnap, rb);
    if (writeClaude && claudeSnap && claudeMerged) publishSnap(claudePath, claudeMerged.body, claudeSnap, rb);
    if (writeCodex && codexSnap && codexBody) publishSnap(codexPath, codexBody, codexSnap, rb);
    if (writeZcode && zcodeSnap && zcodeBody) publishSnap(zcodePath, zcodeBody, zcodeSnap, rb);
    if (writeAntigravity && antigravitySnap && antigravityBody) {
      publishSnap(antigravityPath, antigravityBody, antigravitySnap, rb);
    }
    for (const job of hostJobs) publishSnap(job.path, job.next, job.snap, rb);

    publishRestricted(
      credPath,
      JSON.stringify({
        deviceId,
        token,
        url: opts.bundle.url,
        caPem: opts.bundle.caPem,
        fingerprintSha256: opts.bundle.fingerprintSha256,
      }),
      credSnap,
      rb,
    );
    publishRestricted(
      corePath,
      JSON.stringify({ url: opts.bundle.url, fingerprintSha256: opts.bundle.fingerprintSha256 }),
      coreSnap,
      rb,
    );
    await rememberPolicy(policyPath, policySnap, token, transport, rb);

    let taskOk: boolean | "skipped" = "skipped";
    let taskOwned = false;
    let taskTr: string | undefined;
    let autostart: AutostartKind = "skipped";
    let autostartPath: string | undefined;
    let launcherMeta: InstallManifest["launcher"];

    if (os === "win32") {
      if (process.env.NODE_TEST_CONTEXT && !opts.startupDir && !opts.skipStartup) {
        throw new Error("startupDir_required_in_tests");
      }
      let startupOk = false;
      let startupError: string | undefined;
      if (!opts.skipStartup) {
        const startupDir = opts.startupDir ?? userStartupDir();
        const launcherPath = join(startupDir, STARTUP_LAUNCHER_NAME);
        const launcherSnap = snapshotPath(launcherPath);
        const prev = readManifest(home);
        const launcher = opts.launcherRunner ?? defaultLauncherRunner();
        const inst = await launcher.install({
          startupDir,
          nodePath: opts.nodePath,
          entry,
          home,
          previousWrittenSha256: prev?.launcher?.writtenSha256,
        });
        if (inst.ok && inst.path && inst.sha256) {
          const written = readFileSync(inst.path, "utf8");
          if (launcherSnap.absent) rb.noteCreated(inst.path, written);
          else rb.notePrior(inst.path, launcherSnap.text ?? "", written);
          startupOk = true;
          autostart = "user_startup";
          autostartPath = inst.path;
          launcherMeta = {
            created: !!inst.created,
            originalSha256: inst.originalSha256 ?? null,
            writtenSha256: inst.sha256,
            path: inst.path,
          };
        } else {
          startupError = inst.error ?? "startup_failed";
        }
      }

      if (!opts.skipRegister) {
        const runner = opts.taskRunner ?? schtasksRunner();
        const tr = hiddenProbeTr(opts.nodePath, entry, home, autostartPath);
        taskTr = tr;
        const queried = await runner.query(TASK_NAME);
        if (queried.ok && isOurScheduledTask(queried.output, tr)) {
          taskOk = true;
          taskOwned = true;
        } else if (taskLooksPresent(queried.output, queried.ok)) {
          taskOk = false;
        } else {
          const created = await runner.create(tr, TASK_NAME);
          if (created.ok) {
            const q2 = await runner.query(TASK_NAME);
            if (q2.ok && isOurScheduledTask(q2.output, tr)) {
              taskOk = true;
              taskOwned = true;
            } else {
              taskOk = false;
            }
          } else {
            taskOk = false;
          }
        }
      }

      const needAutostart = !opts.skipStartup || !opts.skipRegister;
      if (needAutostart && !startupOk && taskOk !== true) {
        throw new Error(startupError === "startup_owned_by_other" ? "startup_owned_by_other" : "autostart_failed");
      }
      if (taskOk === true && !startupOk) autostart = "scheduled_task";
    }

    if (!opts.skipProbe) {
      const runningBefore = await probe.isOwnRunning(home);
      const started = await probe.start({ nodePath: opts.nodePath, entry, home, hidden: true, transactional: true });
      if (started.transaction) probeTxn = started.transaction;
      if (!started.ok) throw new Error("probe_start_failed");
      if (!started.transaction) {
        const lockAfter = readProbeLock(home);
        legacyStartedNew =
          !runningBefore || (!!lockAfter && !probeLockMatchesRequested(lockAfter, { nodePath: opts.nodePath, entry }));
      }
    }

    const files = [credPath, corePath, runtimeDir];
    if (writeGrok || carryGrok) files.push(carryGrok ? prevManifest!.grokPath : grokPath);
    if (writeClaude || carryClaude) files.push(carryClaude ? prevManifest!.claudePath : claudePath);
    if (writeCodex || carryCodex) files.push(carryCodex ? prevManifest!.codexPath! : codexPath);
    if (writeZcode) files.push(zcodePath);
    if (writeAntigravity) files.push(antigravityPath);
    for (const job of hostJobs) files.push(job.path);
    if (autostartPath) files.push(autostartPath);
    const hostJobPaths = new Set(hostJobs.map((job) => job.path));
    const hostFiles: NonNullable<InstallManifest["hostFiles"]> = hostJobs.map((job) => ({
      agent: job.agent,
      path: job.path,
      created: job.prev === null || prevManifest?.hostFiles?.some((h) => h.path === job.path && h.created) === true,
      writtenSha256: sha256Text(existsSync(job.path) ? readFileSync(job.path, "utf8") : ""),
    }));
    for (const h of prevManifest?.hostFiles ?? []) {
      if (hostJobPaths.has(h.path) || !existsSync(h.path)) continue;
      hostFiles.push({ agent: h.agent, path: h.path, created: h.created, writtenSha256: h.writtenSha256 });
      files.push(h.path);
    }
    const carryZcode = !writeZcode && !!prevManifest?.zcodePath && existsSync(prevManifest.zcodePath);
    const carryAntigravity = !writeAntigravity && !!prevManifest?.antigravityPath && existsSync(prevManifest.antigravityPath);
    if (carryZcode && prevManifest?.zcodePath) files.push(prevManifest.zcodePath);
    if (carryAntigravity && prevManifest?.antigravityPath) files.push(prevManifest.antigravityPath);
    const grokRecord = writeGrok
      ? {
          created: !prevGrok,
          originalSha256: prevGrok ? sha256Text(prevGrok) : null,
          writtenSha256: sha256Text(readFileSync(grokPath, "utf8")),
        }
      : carryGrok && prevManifest?.grok
        ? prevManifest.grok
        : { created: false, originalSha256: null, writtenSha256: "" };
    const claudeRecord = writeClaude
      ? {
          originalSha256: prevClaude ? sha256Text(prevClaude) : null,
          writtenSha256: sha256Text(readFileSync(claudePath, "utf8")),
        }
      : carryClaude && prevManifest?.claude
        ? prevManifest.claude
        : { originalSha256: null, writtenSha256: "" };
    const manifest: InstallManifest = {
      version: NMZP_VERSION,
      deviceId,
      grokPath: carryGrok ? prevManifest!.grokPath : grokPath,
      claudePath: carryClaude ? prevManifest!.claudePath : claudePath,
      ...(writeCodex || carryCodex ? { codexPath: carryCodex ? prevManifest!.codexPath : codexPath } : {}),
      ...(writeZcode ? { zcodePath } : carryZcode ? { zcodePath: prevManifest!.zcodePath } : {}),
      ...(writeAntigravity ? { antigravityPath } : carryAntigravity ? { antigravityPath: prevManifest!.antigravityPath } : {}),
      runtimeDir,
      task: TASK_NAME,
      taskOwned,
      taskTr,
      autostart,
      autostartPath,
      files,
      grok: grokRecord,
      claude: claudeRecord,
      ...(writeAntigravity
        ? {
            antigravity: {
              created: prevAntigravity === null || prevManifest?.antigravity?.created === true,
              writtenSha256: sha256Text(existsSync(antigravityPath) ? readFileSync(antigravityPath, "utf8") : ""),
            },
          }
        : carryAntigravity && prevManifest?.antigravity
          ? { antigravity: prevManifest.antigravity }
          : {}),
      ...(hostFiles.length ? { hostFiles } : {}),
      launcher: launcherMeta,
    };
    publishRestricted(manifestPath, JSON.stringify(manifest, null, 2), manifestSnap, rb);
    let codexTrust: CodexHookTrustStatus | "skipped" = "skipped";
    if (writeCodex || carryCodex) {
      try {
        codexTrust = codexHookTrust(home).status;
      } catch {
        codexTrust = "unknown";
      }
    }
    const codexNotice = codexNoticeFor(codexTrust);
    const warnings = skippedHosts.length
      ? [`no host directory detected for ${skippedHosts.join(",")}; hooks were not written`]
      : undefined;
    const note = await snapshotGuardJoinNote(home, opts.snapshotGuardStatus);
    return {
      deviceId,
      runtimeDir,
      taskOk,
      autostart,
      autostartPath,
      files,
      skippedHosts,
      codexTrust,
      ...(codexNotice ? { codexNotice } : {}),
      ...(warnings ? { warnings } : {}),
      ...note,
    };
  } catch (e) {
    const probeErrors: string[] = [];
    let report: RollbackReport = { ok: true, restored: [], removed: [], preservedExternal: [], failed: [] };
    const rollbackFiles = (): { ok: boolean } => {
      report = rb ? rb.rollback() : report;
      return { ok: report.ok };
    };
    if (probeTxn && probeTxn.disposition !== "reused") {
      if (!probe.rollbackStart) {
        probeErrors.push("probe_rollback_unavailable");
      } else {
        try {
          const rolled = await probe.rollbackStart(home, probeTxn, rollbackFiles);
          if (!rolled.ok) {
            const code = rolled.error && /^probe_[a-z0-9_]+$/.test(rolled.error) ? rolled.error : "probe_rollback_failed";
            probeErrors.push(code);
          }
        } catch {
          probeErrors.push("probe_rollback_failed");
        }
      }
    } else {
      if (!probeTxn && legacyStartedNew) {
        try {
          await probe.stopOwn(home);
        } catch {
          probeErrors.push("probe_stop_failed");
        }
      }
      rollbackFiles();
    }
    if (!report.ok || probeErrors.length > 0) {
      const origin = e instanceof Error ? e.message : "join_failed";
      const details = [...report.failed.map((item) => item.path), ...probeErrors];
      throw new Error(`${origin}; rollback_incomplete: ${details.join(",")}`);
    }
    throw e;
  }
}

export interface LeaveHostFailure {
  target: string;
  reason: string;
}

export interface LeaveUnresolved {
  target: string;
  command: string;
}

export interface LeaveResult {
  ok: boolean;
  removed: string[];
  failed: LeaveHostFailure[];
  /** Like NMZP, but not the generated command shape. Preserved; does not fail leave. */
  unresolved: LeaveUnresolved[];
}

function leaveTarget(host: string, path: string): string {
  return `${host}:${basename(path)}`;
}

function leaveIoOrCorrupt(e: unknown): "config_corrupt" | "write_failed" {
  if (e instanceof Error && e.message === "atomic_write_failed") return "write_failed";
  if (typeof e === "object" && e !== null && "code" in e && typeof (e as { code?: unknown }).code === "string") {
    return "write_failed";
  }
  return "config_corrupt";
}

function planOwnedStrip(hadOwned: boolean, stillOwned: boolean): "fail" | "skip" | "write" {
  if (stillOwned) return "fail";
  if (!hadOwned) return "skip";
  return "write";
}

function applyOwnedFile(
  failed: LeaveHostFailure[],
  removed: string[],
  target: string,
  removedLabel: string,
  path: string,
  hadOwned: boolean,
  next: string,
  stillOwned: boolean,
): void {
  const plan = planOwnedStrip(hadOwned, stillOwned);
  if (plan === "fail") {
    failed.push({ target, reason: "config_corrupt" });
    return;
  }
  if (plan === "write") {
    atomicWriteFile(path, next, 0o600);
    removed.push(removedLabel);
  }
}

const UNRESOLVED_COMMAND_LIMIT = 80;

function walkHookCommands(value: unknown, found: string[]): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walkHookCommands(item, found);
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (key === "command" && typeof child === "string") found.push(child);
    else walkHookCommands(child, found);
  }
}

function tomlScalar(raw: string): string | undefined {
  const text = raw.trim();
  if (text.startsWith("'")) {
    const end = text.indexOf("'", 1);
    if (end < 0) return undefined;
    return text.slice(1, end);
  }
  if (!text.startsWith('"')) return undefined;
  let out = "";
  for (let i = 1; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\\") {
      const next = text[++i];
      if (next === undefined) return undefined;
      out += next;
      continue;
    }
    if (ch === '"') return out;
    out += ch;
  }
  return undefined;
}

function commandsInHostText(raw: string): string[] {
  const found: string[] = [];
  try {
    walkHookCommands(JSON.parse(raw) as unknown, found);
    return found;
  } catch {
    // Kimi stores the hook in TOML. Other non-JSON text has no command field to keep.
  }
  for (const line of raw.split(/\r?\n/)) {
    const matched = /^\s*command\s*=\s*(.*)$/.exec(line);
    if (!matched?.[1]) continue;
    const value = tomlScalar(matched[1]);
    if (value !== undefined) found.push(value);
  }
  return found;
}

function rememberUnresolved(unresolved: LeaveUnresolved[], target: string, raw: string): void {
  for (const command of commandsInHostText(raw)) {
    const hook = { command };
    if (!isNmzpLikeHook(hook) || isNmzpOwnedHook(hook)) continue;
    unresolved.push({ target, command: command.slice(0, UNRESOLVED_COMMAND_LIMIT) });
  }
}

async function leaveDeviceBody(opts: {
  home: string;
  skipRegister?: boolean;
  taskRunner?: TaskRunner;
  launcherRunner?: LauncherRunner;
  os?: string;
  probeController?: ProbeController;
}): Promise<LeaveResult> {
  const home = opts.home;
  const nmzp = p(home, ".nmzp");
  const removed: string[] = [];
  const failed: LeaveHostFailure[] = [];
  const unresolved: LeaveUnresolved[] = [];
  const manifest = readManifest(home);
  const probe = opts.probeController ?? defaultProbeController();
  await probe.stopOwn(home);

  const codexPath = manifest?.codexPath;
  if (codexPath && existsSync(codexPath)) {
    const target = leaveTarget("codex", codexPath);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(codexPath, "utf8");
      surviving = raw;
      const next = mergeCodexHooks(raw);
      const hadOwned = codexHookConfiguredRaw(raw);
      const stillOwned = codexHookConfiguredRaw(next);
      applyOwnedFile(failed, removed, target, "codex:nmzp-entry", codexPath, hadOwned, next, stillOwned);
      if (planOwnedStrip(hadOwned, stillOwned) === "write") surviving = next;
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }
  const zcodePath = manifest?.zcodePath;
  if (zcodePath && existsSync(zcodePath)) {
    const target = leaveTarget("zcode", zcodePath);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(zcodePath, "utf8");
      surviving = raw;
      const next = mergeZcodeConfig(raw);
      const hadOwned = zcodeHookConfiguredRaw(raw).configured;
      const stillOwned = zcodeHookConfiguredRaw(next).configured;
      applyOwnedFile(failed, removed, target, "zcode:nmzp-entry", zcodePath, hadOwned, next, stillOwned);
      if (planOwnedStrip(hadOwned, stillOwned) === "write") surviving = next;
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }
  const antigravityPath = manifest?.antigravityPath;
  if (antigravityPath && existsSync(antigravityPath)) {
    const target = leaveTarget("antigravity", antigravityPath);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(antigravityPath, "utf8");
      const currentSha = sha256Text(raw);
      if (manifest?.antigravity?.created && manifest.antigravity.writtenSha256 === currentSha) {
        rmSync(antigravityPath);
        removed.push(antigravityPath);
      } else {
        surviving = raw;
        const next = mergeAntigravityHooks(raw);
        const hadOwned = antigravityHookConfiguredRaw(raw).configured;
        const stillOwned = antigravityHookConfiguredRaw(next).configured;
        applyOwnedFile(
          failed,
          removed,
          target,
          "antigravity:nmzp-entry",
          antigravityPath,
          hadOwned,
          next,
          stillOwned,
        );
        if (planOwnedStrip(hadOwned, stillOwned) === "write") surviving = next;
      }
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }
  for (const hf of manifest?.hostFiles ?? []) {
    if (!existsSync(hf.path) || !isExtraHookAgent(hf.agent)) continue;
    const target = leaveTarget(hf.agent, hf.path);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(hf.path, "utf8");
      if (hf.created && sha256Text(raw) === hf.writtenSha256) {
        rmSync(hf.path);
        removed.push(hf.path);
      } else {
        surviving = raw;
        const next = hostHookStrip(hf.agent, raw);
        const hadOwned = hostHookConfiguredRaw(hf.agent, raw);
        const stillOwned = hostHookConfiguredRaw(hf.agent, next);
        applyOwnedFile(
          failed,
          removed,
          target,
          `${hf.agent}:nmzp-entry`,
          hf.path,
          hadOwned,
          next,
          stillOwned,
        );
        if (planOwnedStrip(hadOwned, stillOwned) === "write") surviving = next;
      }
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }
  const grokPath = manifest?.grokPath ?? p(home, ".grok", "hooks", GROK_HOOK_FILE);
  if (existsSync(grokPath)) {
    const target = leaveTarget("grok", grokPath);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(grokPath, "utf8");
      const currentSha = sha256Text(raw);
      if (manifest?.grok.created && manifest.grok.writtenSha256 === currentSha) {
        rmSync(grokPath);
        removed.push(grokPath);
      } else {
        surviving = raw;
        const inspected = inspectGrokHookFile(raw);
        if (!inspected.ok) {
          failed.push({ target, reason: "config_corrupt" });
        } else if (inspected.hadOwned) {
          atomicWriteFile(grokPath, inspected.next, 0o600);
          removed.push("grok:nmzp-entry");
          surviving = inspected.next;
        }
      }
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }

  const claudePath = manifest?.claudePath ?? p(home, ".claude", "settings.json");
  if (existsSync(claudePath)) {
    const target = leaveTarget("claude", claudePath);
    let surviving: string | null = null;
    try {
      const raw = readFileSync(claudePath, "utf8");
      surviving = raw;
      const inspected = inspectClaudeSettings(raw);
      if (!inspected.ok) {
        failed.push({ target, reason: "config_corrupt" });
      } else if (inspected.hadOwned) {
        atomicWriteFile(claudePath, inspected.next, 0o600);
        removed.push("claude:nmzp-entry");
        surviving = inspected.next;
      }
    } catch (e) {
      failed.push({ target, reason: leaveIoOrCorrupt(e) });
    }
    if (surviving !== null) rememberUnresolved(unresolved, target, surviving);
  }

  // Leftover hooks still need these; a later retry needs the manifest.
  if (failed.length === 0) {
    if (manifest?.launcher?.path) {
      const runner = opts.launcherRunner ?? defaultLauncherRunner();
      const r = await runner.removeIfUnmodified({
        path: manifest.launcher.path,
        writtenSha256: manifest.launcher.writtenSha256,
      });
      if (r.removed) removed.push(manifest.launcher.path);
    }

    for (const f of ["credentials.json", "core.json", "policy-cache.json", "manifest.json"]) {
      const path = p(nmzp, f);
      if (existsSync(path)) {
        rmSync(path);
        removed.push(path);
      }
    }

    if (!opts.skipRegister && (opts.os ?? process.platform) === "win32" && manifest?.taskOwned && manifest.taskTr) {
      const runner = opts.taskRunner ?? schtasksRunner();
      const q = await runner.query(TASK_NAME);
      if (q.ok && isOurScheduledTask(q.output, manifest.taskTr)) {
        await runner.remove(TASK_NAME);
        removed.push(`task:${TASK_NAME}`);
      }
    }
  }
  return { ok: failed.length === 0, removed, failed, unresolved };
}

export function leaveDevice(opts: Parameters<typeof leaveDeviceBody>[0]): Promise<LeaveResult> {
  return withCooperatingInstallLock(opts.home, () => leaveDeviceBody(opts));
}

export function defaultHome(): string {
  return process.env.NMZP_HOME || homedir();
}

export function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "nmzp-home-"));
}

export { userInfo };
