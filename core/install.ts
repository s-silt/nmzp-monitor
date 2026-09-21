import {codexHookEntry,mergeCodexHooks} from "./codex-hooks.ts";
import { antigravityHookDoc, antigravityHooksPath, mergeAntigravityHooks } from "./antigravity-hooks.ts";
import {
  EXTRA_HOOK_AGENTS,
  hostHookStrip,
  hostHookTargets,
  hostHookWrite,
  isExtraHookAgent,
  type ExtraHookAgent,
} from "./host-adapters.ts";
import { mergeZcodeConfig, zcodeConfigPath, zcodeHookGroup } from "./zcode-hooks.ts";
/**
 * Join / leave. Tests pass a temp home and temp startup dir. Never touch the real profile from tests.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { cp } from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { GROK_HOOK_FILE, NMZP_VERSION, TASK_NAME } from "./constants.ts";
import { pinnedHttps } from "./https-client.ts";
import { FileRollback, atomicWriteFile, restrictPath, sha256Text } from "./install-fs.ts";
import {
  defaultLauncherRunner,
  defaultProbeController,
  hiddenProbeTr,
  isOurScheduledTask,
  schtasksCreateArgs,
  schtasksRunner,
  STARTUP_LAUNCHER_NAME,
  startupLauncherBody,
  taskLooksPresent,
  userStartupDir,
  type AutostartKind,
  type LauncherRunner,
  type ProbeController,
  type TaskRunner,
} from "./install-autostart.ts";
import {
  hookCommand,
  mergeClaudeSettings,
  mergeGrokHookFile,
  parseJsonObjectOrThrow,
  stripClaudeSettings,
  stripGrokHookFile,
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

function writeRestricted(path: string, body: string): void {
  atomicWriteFile(path, body, 0o600);
  restrictPath(path);
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

export async function joinDevice(opts: JoinOpts): Promise<JoinResult> {
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
  const writeZcode = existsSync(zcodeCli);
  const writeAntigravity = existsSync(antigravityHome);
  const entry = join(runtimeDir, "nmzp.mjs");
  const prevCodex = existsSync(codexPath) ? readFileSync(codexPath, "utf8") : null;
  mergeCodexHooks(prevCodex); // Validate before any install mutation.
  const prevZcode = writeZcode && existsSync(zcodePath) ? readFileSync(zcodePath, "utf8") : null;
  if (writeZcode) mergeZcodeConfig(prevZcode);
  const prevAntigravity = writeAntigravity && existsSync(antigravityPath) ? readFileSync(antigravityPath, "utf8") : null;
  if (writeAntigravity) mergeAntigravityHooks(prevAntigravity);
  const prevClaude = existsSync(claudePath) ? readFileSync(claudePath, "utf8") : null;
  const prevGrok = existsSync(grokPath) ? readFileSync(grokPath, "utf8") : null;
  if (prevClaude && prevClaude.trim()) parseJsonObjectOrThrow(prevClaude, "claude_settings_corrupt");
  if (prevGrok && prevGrok.trim()) parseJsonObjectOrThrow(prevGrok, "grok_hook_corrupt");
  const hostJobs: Array<{ agent: ExtraHookAgent; path: string; prev: string | null; next: string }> = [];
  for (const agent of EXTRA_HOOK_AGENTS) {
    for (const path of hostHookTargets(agent, home)) {
      const prev = existsSync(path) ? readFileSync(path, "utf8") : null;
      const next = hostHookWrite(agent, prev, opts.nodePath, entry, os);
      hostJobs.push({ agent, path, prev, next });
    }
  }

  mkdirSync(nmzp, { recursive: true });
  restrictPath(nmzp);
  mkdirSync(backupDir, { recursive: true });
  restrictPath(backupDir);

  const transport = opts.transport ?? defaultTransport(opts.bundle);
  const hostname = opts.hostname ?? "host";
  const user = opts.user ?? "user";
  let deviceId: string;
  let token: string;
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
      try {
        const policy = JSON.parse(pol.body) as PolicyState;
        if (policy?.version) await writePolicyCache(p(nmzp, "policy-cache.json"), policy);
      } catch {
        /* keep prior cache */
      }
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

  const probe = opts.probeController ?? defaultProbeController();
  const running = await probe.isOwnRunning(home);
  if (!(existsSync(runtimeDir) && running)) {
    await (opts.copyRuntime ?? copyRuntime)(opts.coreDir, runtimeDir);
  }

  const rb = new FileRollback(backupDir);
  try {
    if (prevGrok) rb.backupExisting(grokPath);
    if (prevClaude) rb.backupExisting(claudePath);
    if (prevCodex !== null) rb.backupExisting(codexPath);
    else rb.noteCreated(codexPath);
    if (writeZcode) {
      if (prevZcode !== null) rb.backupExisting(zcodePath);
      else rb.noteCreated(zcodePath);
    }
    if (writeAntigravity) {
      if (prevAntigravity !== null) rb.backupExisting(antigravityPath);
      else rb.noteCreated(antigravityPath);
    }
    for (const job of hostJobs) {
      if (job.prev !== null) rb.backupExisting(job.path);
      else rb.noteCreated(job.path);
    }
    mkdirSync(dirname(grokPath), { recursive: true });
    mkdirSync(dirname(claudePath), { recursive: true });
    const grokMerged = mergeGrokHookFile(prevGrok, grokHookDoc(entry, opts.nodePath, os));
    if (!prevGrok) rb.noteCreated(grokPath);
    atomicWriteFile(grokPath, grokMerged.body, 0o600);
    const claudeMerged = mergeClaudeSettings(prevClaude, claudeHookEntry(entry, opts.nodePath, os));
    atomicWriteFile(claudePath, claudeMerged.body, 0o600);
    mkdirSync(dirname(codexPath), {recursive:true});
    atomicWriteFile(codexPath, mergeCodexHooks(prevCodex, codexHookEntry(opts.nodePath,entry,os)), 0o600);
    if (writeZcode) {
      atomicWriteFile(zcodePath, mergeZcodeConfig(prevZcode, zcodeHookGroup(opts.nodePath, entry)), 0o600);
    }
    if (writeAntigravity) {
      mkdirSync(dirname(antigravityPath), { recursive: true });
      atomicWriteFile(antigravityPath, mergeAntigravityHooks(prevAntigravity, antigravityHookDoc(opts.nodePath, entry, os)), 0o600);
    }
    for (const job of hostJobs) {
      mkdirSync(dirname(job.path), { recursive: true });
      atomicWriteFile(job.path, job.next, 0o600);
    }

    writeRestricted(
      p(nmzp, "credentials.json"),
      JSON.stringify({
        deviceId,
        token,
        url: opts.bundle.url,
        caPem: opts.bundle.caPem,
        fingerprintSha256: opts.bundle.fingerprintSha256,
      }),
    );
    writeRestricted(
      p(nmzp, "core.json"),
      JSON.stringify({ url: opts.bundle.url, fingerprintSha256: opts.bundle.fingerprintSha256 }),
    );
    const pol = await transport.policy(token);
    if (pol.status === 200) {
      try {
        const policy = JSON.parse(pol.body) as PolicyState;
        if (policy?.version) await writePolicyCache(p(nmzp, "policy-cache.json"), policy);
      } catch {
        /* ignore */
      }
    }

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
      const started = await probe.start({ nodePath: opts.nodePath, entry, home, hidden: true });
      if (!started.ok) throw new Error("probe_start_failed");
    }

    const files = [p(nmzp, "credentials.json"), p(nmzp, "core.json"), grokPath, claudePath, codexPath, runtimeDir];
    if (writeZcode) files.push(zcodePath);
    if (writeAntigravity) files.push(antigravityPath);
    for (const job of hostJobs) files.push(job.path);
    if (autostartPath) files.push(autostartPath);
    const prevManifest = readManifest(home);
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
    const manifest: InstallManifest = {
      version: NMZP_VERSION,
      deviceId,
      grokPath,
      claudePath,
      codexPath,
      ...(writeZcode ? { zcodePath } : carryZcode ? { zcodePath: prevManifest!.zcodePath } : {}),
      ...(writeAntigravity ? { antigravityPath } : carryAntigravity ? { antigravityPath: prevManifest!.antigravityPath } : {}),
      runtimeDir,
      task: TASK_NAME,
      taskOwned,
      taskTr,
      autostart,
      autostartPath,
      files,
      grok: {
        created: !prevGrok,
        originalSha256: prevGrok ? sha256Text(prevGrok) : null,
        writtenSha256: sha256Text(existsSync(grokPath) ? readFileSync(grokPath, "utf8") : ""),
      },
      claude: {
        originalSha256: prevClaude ? sha256Text(prevClaude) : null,
        writtenSha256: sha256Text(existsSync(claudePath) ? readFileSync(claudePath, "utf8") : ""),
      },
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
    writeRestricted(p(nmzp, "manifest.json"), JSON.stringify(manifest, null, 2));
    const note = await snapshotGuardJoinNote(home, opts.snapshotGuardStatus);
    return { deviceId, runtimeDir, taskOk, autostart, autostartPath, files, ...note };
  } catch (e) {
    rb.rollback();
    throw e;
  }
}

export async function leaveDevice(opts: {
  home: string;
  skipRegister?: boolean;
  taskRunner?: TaskRunner;
  launcherRunner?: LauncherRunner;
  os?: string;
  probeController?: ProbeController;
}): Promise<{ ok: true; removed: string[] }> {
  const home = opts.home;
  const nmzp = p(home, ".nmzp");
  const removed: string[] = [];
  const manifest = readManifest(home);
  const probe = opts.probeController ?? defaultProbeController();
  await probe.stopOwn(home);

  const codexPath = manifest?.codexPath;
  if (codexPath && existsSync(codexPath)) {
    atomicWriteFile(codexPath,mergeCodexHooks(readFileSync(codexPath,"utf8")),0o600);
    removed.push("codex:nmzp-entry");
  }
  const zcodePath = manifest?.zcodePath;
  if (zcodePath && existsSync(zcodePath)) {
    atomicWriteFile(zcodePath, mergeZcodeConfig(readFileSync(zcodePath, "utf8")), 0o600);
    removed.push("zcode:nmzp-entry");
  }
  const antigravityPath = manifest?.antigravityPath;
  if (antigravityPath && existsSync(antigravityPath)) {
    const raw = readFileSync(antigravityPath, "utf8");
    const currentSha = sha256Text(raw);
    if (manifest?.antigravity?.created && manifest.antigravity.writtenSha256 === currentSha) {
      rmSync(antigravityPath);
      removed.push(antigravityPath);
    } else {
      atomicWriteFile(antigravityPath, mergeAntigravityHooks(raw), 0o600);
      removed.push("antigravity:nmzp-entry");
    }
  }
  for (const hf of manifest?.hostFiles ?? []) {
    if (!existsSync(hf.path) || !isExtraHookAgent(hf.agent)) continue;
    const raw = readFileSync(hf.path, "utf8");
    if (hf.created && sha256Text(raw) === hf.writtenSha256) {
      rmSync(hf.path);
      removed.push(hf.path);
    } else {
      atomicWriteFile(hf.path, hostHookStrip(hf.agent, raw), 0o600);
      removed.push(`${hf.agent}:nmzp-entry`);
    }
  }
  const grokPath = manifest?.grokPath ?? p(home, ".grok", "hooks", GROK_HOOK_FILE);
  if (existsSync(grokPath)) {
    const raw = readFileSync(grokPath, "utf8");
    const currentSha = sha256Text(raw);
    if (manifest?.grok.created && manifest.grok.writtenSha256 === currentSha) {
      rmSync(grokPath);
      removed.push(grokPath);
    } else {
      writeFileSync(grokPath, stripGrokHookFile(raw), { encoding: "utf8" });
      removed.push("grok:nmzp-entry");
    }
  }

  const claudePath = manifest?.claudePath ?? p(home, ".claude", "settings.json");
  if (existsSync(claudePath)) {
    const next = stripClaudeSettings(readFileSync(claudePath, "utf8"));
    writeFileSync(claudePath, next);
    removed.push("claude:nmzp-entry");
  }

  if (manifest?.launcher?.path) {
    const runner = opts.launcherRunner ?? defaultLauncherRunner();
    const r = await runner.removeIfUnmodified({ path: manifest.launcher.path, writtenSha256: manifest.launcher.writtenSha256 });
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
  return { ok: true, removed };
}

export function defaultHome(): string {
  return process.env.NMZP_HOME || homedir();
}

export function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "nmzp-home-"));
}

export { userInfo };
