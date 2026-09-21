import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { NMZP_VERSION, TASK_NAME } from "./constants.ts";
import { atomicWriteFile, restrictPath, sha256Text } from "./install-fs.ts";

export const STARTUP_LAUNCHER_NAME = "NMZP-probe.vbs";
export const STARTUP_LAUNCHER_MARK = "NMZP_PROBE_LAUNCHER";
export const NMZP_PROBE_NONCE_ENV = "NMZP_PROBE_NONCE";

export type AutostartKind = "user_startup" | "scheduled_task" | "skipped";

export interface TaskRunner {
  create(tr: string, name: string): Promise<{ ok: boolean; output: string }>;
  query(name: string): Promise<{ ok: boolean; output: string }>;
  remove(name: string): Promise<{ ok: boolean; output: string }>;
}

export interface LauncherInstallResult {
  ok: boolean;
  path?: string;
  sha256?: string;
  created?: boolean;
  originalSha256?: string | null;
  error?: string;
}

export interface LauncherRunner {
  install(opts: {
    startupDir: string;
    nodePath: string;
    entry: string;
    home: string;
    previousWrittenSha256?: string;
  }): Promise<LauncherInstallResult>;
  removeIfUnmodified(opts: { path: string; writtenSha256: string }): Promise<{ removed: boolean }>;
}

export interface ProbeController {
  start(opts: { nodePath: string; entry: string; home: string; hidden: boolean }): Promise<{ ok: boolean; pid?: number }>;
  stopOwn(home: string): Promise<{ ok: boolean; stopped: boolean; pid?: number }>;
  isOwnRunning(home: string): Promise<boolean>;
}

export interface ProbeIdentity {
  pid: number;
  exe?: string;
  cmdline?: string;
  createdAt?: number;
}

export interface ProbeLock {
  pid: number;
  marker: "nmzp-probe";
  version: string;
  startedAt: number;
  nonce: string;
  nodePath: string;
  entry: string;
}

export interface ProbeReady {
  pid: number;
  nonce: string;
  readyAt: number;
}

export interface ProbeControllerDeps {
  inspectPid?: (pid: number) => Promise<ProbeIdentity | null>;
  spawnProbe?: (opts: {
    nodePath: string;
    entry: string;
    home: string;
    hidden: boolean;
    nonce: string;
  }) => { pid?: number; kill: () => void };
  readyTimeoutMs?: number;
  randomNonce?: () => string;
}

function psSingle(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

export function winQuote(s: string): string {
  if (!/[\s"]/.test(s)) return s;
  return `"${s.replace(/"/g, '\\"')}"`;
}

export function probeArgumentList(entry: string): string {
  return `--experimental-strip-types ${winQuote(entry)} probe`;
}

export function schtasksCreateArgs(tr: string, name: string): string[] {
  return ["/create", "/tn", name, "/sc", "onlogon", "/rl", "limited", "/tr", tr];
}

export function hiddenProbeTr(nodePath: string, entry: string, home: string, launcherPath?: string): string {
  if (launcherPath) {
    return `wscript.exe //nologo //B ${winQuote(launcherPath)}`;
  }
  const args = probeArgumentList(entry);
  const ps = `$env:NMZP_HOME=${psSingle(home)}; Start-Process -WindowStyle Hidden -FilePath ${psSingle(nodePath)} -ArgumentList ${psSingle(args)}`;
  return `powershell.exe -NoProfile -WindowStyle Hidden -Command ${psSingle(ps)}`;
}

function normalizeTr(s: string): string {
  return s.trim().replace(/^"+|"+$/g, "").replace(/\s+/g, " ").toLowerCase();
}

export function isOurScheduledTask(output: string, expectedTr: string): boolean {
  const m = /Task To Run:\s*(.+)/i.exec(output);
  if (!m) return false;
  return normalizeTr(m[1]!) === normalizeTr(expectedTr);
}

/** @deprecated use isOurScheduledTask with this install's exact TR */
export function isNmzpTaskOutput(output: string, expectedTr?: string): boolean {
  if (!expectedTr) return false;
  return isOurScheduledTask(output, expectedTr);
}

export function taskLooksPresent(output: string, queryOk: boolean): boolean {
  if (!queryOk) return false;
  return /TaskName:/i.test(output) || /Task To Run:/i.test(output) || output.trim().length > 0;
}

export function userStartupDir(): string {
  const roaming = process.env.APPDATA || join(homedir(), "AppData", "Roaming");
  return join(roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
}

function vbsStr(s: string): string {
  return `"${s.replace(/"/g, '""')}"`;
}

export function startupLauncherBody(nodePath: string, entry: string, home: string): string {
  const cmd = `"${nodePath}" --experimental-strip-types "${entry}" probe`;
  return [
    `' ${STARTUP_LAUNCHER_MARK}`,
    "Option Explicit",
    "Dim sh, cmd",
    'Set sh = CreateObject("WScript.Shell")',
    `sh.Environment("Process")("NMZP_HOME") = ${vbsStr(home)}`,
    `cmd = ${vbsStr(cmd)}`,
    "sh.Run cmd, 0, False",
    "",
  ].join("\r\n");
}

export function defaultLauncherRunner(): LauncherRunner {
  return {
    async install(opts) {
      mkdirSync(opts.startupDir, { recursive: true });
      const path = join(opts.startupDir, STARTUP_LAUNCHER_NAME);
      let originalSha256: string | null = null;
      const existed = existsSync(path);
      if (existed) {
        const prev = readFileSync(path, "utf8");
        originalSha256 = sha256Text(prev);
        if (!opts.previousWrittenSha256) {
          return { ok: false, error: "startup_owned_by_other", path, originalSha256 };
        }
        if (originalSha256 !== opts.previousWrittenSha256) {
          return { ok: false, error: "startup_conflict", path, originalSha256 };
        }
      }
      const body = startupLauncherBody(opts.nodePath, opts.entry, opts.home);
      atomicWriteFile(path, body, 0o600);
      restrictPath(path);
      return {
        ok: true,
        path,
        sha256: sha256Text(body),
        created: !existed,
        originalSha256,
      };
    },
    async removeIfUnmodified(opts) {
      if (!existsSync(opts.path)) return { removed: false };
      const current = sha256Text(readFileSync(opts.path, "utf8"));
      if (current !== opts.writtenSha256) return { removed: false };
      rmSync(opts.path);
      return { removed: true };
    },
  };
}

export function schtasksRunner(): TaskRunner {
  const run = (args: string[]) =>
    new Promise<{ ok: boolean; output: string }>((resolve) => {
      const child = spawn("schtasks", args, { windowsHide: true });
      let out = "";
      child.stdout?.on("data", (c) => {
        out += String(c);
      });
      child.stderr?.on("data", (c) => {
        out += String(c);
      });
      child.on("error", () => resolve({ ok: false, output: "spawn_error" }));
      child.on("close", (code) => resolve({ ok: code === 0, output: out.slice(0, 800) }));
    });
  return {
    create: (tr, name) => run(schtasksCreateArgs(tr, name)),
    query: (name) => run(["/query", "/tn", name, "/fo", "list", "/v"]),
    remove: (name) => run(["/delete", "/tn", name, "/f"]),
  };
}

export function probeLockPath(home: string): string {
  return join(home, ".nmzp", "probe.pid");
}

export function probeReadyPath(home: string): string {
  return join(home, ".nmzp", "probe.ready");
}

export function probeMutexPath(home: string): string {
  return join(home, ".nmzp", "probe.mutex");
}

export async function withProbeMutex<T>(home: string, fn: () => Promise<T>, timeoutMs = 8000): Promise<T> {
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  const path = probeMutexPath(home);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let fd: number | undefined;
    try {
      fd = openSync(path, "wx");
      writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
      try {
        return await fn();
      } finally {
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
        fd = undefined;
        try {
          unlinkSync(path);
        } catch {
          /* ignore */
        }
      }
    } catch (e) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
      }
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw new Error("probe_mutex_failed");
      let stale = false;
      try {
        const j = JSON.parse(readFileSync(path, "utf8")) as { pid?: number };
        if (typeof j.pid === "number" && !isPidAlive(j.pid)) stale = true;
      } catch {
        stale = false;
      }
      if (stale) {
        try {
          unlinkSync(path);
        } catch {
          /* ignore */
        }
        continue;
      }
      await sleep(20);
    }
  }
  throw new Error("probe_mutex_timeout");
}

export function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function readProbeLock(home: string): ProbeLock | null {
  try {
    const j = JSON.parse(readFileSync(probeLockPath(home), "utf8")) as Partial<ProbeLock>;
    if (j.marker !== "nmzp-probe" || typeof j.pid !== "number") return null;
    if (typeof j.nonce !== "string" || typeof j.nodePath !== "string" || typeof j.entry !== "string") return null;
    return j as ProbeLock;
  } catch {
    return null;
  }
}

export function writeProbeLock(home: string, lock: ProbeLock): void {
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  writeFileSync(probeLockPath(home), JSON.stringify(lock), { encoding: "utf8", mode: 0o600 });
}

export function readProbeReady(home: string): ProbeReady | null {
  try {
    const j = JSON.parse(readFileSync(probeReadyPath(home), "utf8")) as ProbeReady;
    if (typeof j.pid !== "number" || typeof j.nonce !== "string") return null;
    return j;
  } catch {
    return null;
  }
}

export function writeProbeReady(home: string, ready: { pid: number; nonce: string }): void {
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  writeFileSync(
    probeReadyPath(home),
    JSON.stringify({ pid: ready.pid, nonce: ready.nonce, readyAt: Date.now() }),
    { encoding: "utf8", mode: 0o600 },
  );
}

export function windowsInspectPidScript(pid: number): string {
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 0) throw new Error("invalid_pid");
  return `Get-CimInstance Win32_Process -Filter "ProcessId=${n}" | Select-Object ProcessId,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress`;
}

/** ConvertTo-Json of CIM DateTime is typically /Date(ms)/ or ISO, not DMTF yyyymmdd. */
export function parseCimCreationDate(raw: unknown): number | undefined {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return raw;
  if (raw && typeof raw === "object") {
    const o = raw as Record<string, unknown>;
    if (o.value !== undefined) return parseCimCreationDate(o.value);
    if (o.DateTime !== undefined) return parseCimCreationDate(o.DateTime);
    return undefined;
  }
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  const normalized = raw.replace(/\\\//g, "/");
  const ms = /\/Date\((-?\d+)\)\//.exec(normalized);
  if (ms) {
    const n = Number(ms[1]);
    return Number.isFinite(n) ? n : undefined;
  }
  const iso = Date.parse(normalized);
  if (!Number.isNaN(iso)) return iso;
  const dmtf = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(raw);
  if (!dmtf) return undefined;
  return Date.UTC(
    Number(dmtf[1]),
    Number(dmtf[2]) - 1,
    Number(dmtf[3]),
    Number(dmtf[4]),
    Number(dmtf[5]),
    Number(dmtf[6]),
  );
}

export function parseWmiDate(s: string): number | undefined {
  return parseCimCreationDate(s);
}

function samePath(a?: string, b?: string): boolean {
  if (!a || !b) return false;
  return a.replace(/\\/g, "/").toLowerCase() === b.replace(/\\/g, "/").toLowerCase();
}

function cmdlineHasToken(cmd: string, token: string): boolean {
  const want = token.replace(/\\/g, "/").toLowerCase();
  const parts = cmd.match(/"[^"]+"|[^\s"]+/g) ?? [];
  return parts.some((p) => p.replace(/"/g, "").replace(/\\/g, "/").toLowerCase() === want);
}

export function verifyNmzpProbe(
  inspected: ProbeIdentity | null,
  expected: { nodePath: string; entry: string; nonce?: string; readyNonce?: string; startedAt?: number },
): boolean {
  if (!inspected) return false;
  if (!samePath(inspected.exe, expected.nodePath)) return false;
  const cmd = inspected.cmdline ?? "";
  if (!cmdlineHasToken(cmd, expected.entry)) return false;
  if (!cmdlineHasToken(cmd, "probe")) return false;
  if (expected.nonce && expected.readyNonce && expected.nonce === expected.readyNonce) return true;
  if (expected.startedAt && inspected.createdAt && Math.abs(inspected.createdAt - expected.startedAt) < 120_000) {
    return true;
  }
  return false;
}

export async function inspectPid(pid: number): Promise<ProbeIdentity | null> {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (process.platform === "win32") {
    const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", windowsInspectPidScript(pid)], {
      encoding: "utf8",
      windowsHide: true,
    });
    if (r.status !== 0 || !r.stdout?.trim()) return null;
    try {
      const o = JSON.parse(r.stdout) as Record<string, unknown>;
      return {
        pid: Number(o.ProcessId) || pid,
        exe: typeof o.ExecutablePath === "string" ? o.ExecutablePath : undefined,
        cmdline: typeof o.CommandLine === "string" ? o.CommandLine : undefined,
        createdAt: parseCimCreationDate(o.CreationDate),
      };
    } catch {
      return null;
    }
  }
  const r = spawnSync("ps", ["-p", String(pid), "-o", "args="], { encoding: "utf8", windowsHide: true });
  if (r.status !== 0) return null;
  return { pid, cmdline: (r.stdout || "").trim() };
}

function defaultSpawn(opts: {
  nodePath: string;
  entry: string;
  home: string;
  hidden: boolean;
  nonce: string;
}): { pid?: number; kill: () => void } {
  const child = spawn(opts.nodePath, ["--experimental-strip-types", opts.entry, "probe"], {
    detached: true,
    windowsHide: opts.hidden,
    stdio: "ignore",
    env: {
      ...process.env,
      NMZP_HOME: opts.home,
      [NMZP_PROBE_NONCE_ENV]: opts.nonce,
      NMZP_PROBE_NODE: opts.nodePath,
      NMZP_PROBE_ENTRY: opts.entry,
    },
  });
  child.unref();
  return {
    pid: child.pid,
    kill: () => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function lockIsOurs(
  home: string,
  lock: ProbeLock,
  inspect: (pid: number) => Promise<ProbeIdentity | null>,
): Promise<boolean> {
  if (!isPidAlive(lock.pid)) return false;
  const id = await inspect(lock.pid);
  const ready = readProbeReady(home);
  return verifyNmzpProbe(id, {
    nodePath: lock.nodePath,
    entry: lock.entry,
    nonce: lock.nonce,
    readyNonce: ready?.nonce,
    startedAt: lock.startedAt,
  });
}

export function createProbeController(deps: ProbeControllerDeps = {}): ProbeController {
  const inspect = deps.inspectPid ?? inspectPid;
  const timeout = deps.readyTimeoutMs ?? 8000;
  const spawnProbe = deps.spawnProbe ?? defaultSpawn;
  const randomNonce = deps.randomNonce ?? (() => randomBytes(16).toString("hex"));
  return {
    async start(opts) {
      const existing = readProbeLock(opts.home);
      if (existing && isPidAlive(existing.pid)) {
        if (await lockIsOurs(opts.home, existing, inspect)) return { ok: true, pid: existing.pid };
        const ready = readProbeReady(opts.home);
        if (ready && ready.pid === existing.pid && ready.nonce === existing.nonce) {
          return { ok: true, pid: existing.pid };
        }
        return { ok: false };
      }
      const nonce = randomNonce();
      const child = spawnProbe({
        nodePath: opts.nodePath,
        entry: opts.entry,
        home: opts.home,
        hidden: opts.hidden,
        nonce,
      });
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        const ready = readProbeReady(opts.home);
        if (ready && ready.nonce === nonce && (child.pid === undefined || ready.pid === child.pid)) {
          writeProbeLock(opts.home, {
            pid: ready.pid,
            marker: "nmzp-probe",
            version: NMZP_VERSION,
            startedAt: Date.now(),
            nonce,
            nodePath: opts.nodePath,
            entry: opts.entry,
          });
          return { ok: true, pid: ready.pid };
        }
        const other = readProbeLock(opts.home);
        if (other && other.nonce !== nonce && isPidAlive(other.pid)) {
          const otherReady = readProbeReady(opts.home);
          const adopted =
            (otherReady && otherReady.pid === other.pid && otherReady.nonce === other.nonce) ||
            (await lockIsOurs(opts.home, other, inspect));
          if (adopted) {
            child.kill();
            return { ok: true, pid: other.pid };
          }
        }
        await sleep(20);
      }
      child.kill();
      const winner = readProbeLock(opts.home);
      if (winner && isPidAlive(winner.pid)) {
        const winnerReady = readProbeReady(opts.home);
        if (
          (winnerReady && winnerReady.pid === winner.pid && winnerReady.nonce === winner.nonce) ||
          (await lockIsOurs(opts.home, winner, inspect))
        ) {
          return { ok: true, pid: winner.pid };
        }
      }
      return { ok: false };
    },
    async stopOwn(home) {
      const lock = readProbeLock(home);
      if (!lock) return { ok: true, stopped: false };
      if (!(await lockIsOurs(home, lock, inspect))) {
        return { ok: true, stopped: false, pid: lock.pid };
      }
      try {
        process.kill(lock.pid);
      } catch {
        return { ok: true, stopped: false, pid: lock.pid };
      }
      try {
        rmSync(probeLockPath(home), { force: true });
        rmSync(probeReadyPath(home), { force: true });
      } catch {
        /* ignore */
      }
      return { ok: true, stopped: true, pid: lock.pid };
    },
    async isOwnRunning(home) {
      const lock = readProbeLock(home);
      if (!lock) return false;
      return lockIsOurs(home, lock, inspect);
    },
  };
}

export function defaultProbeController(): ProbeController {
  return createProbeController();
}

export async function announceProbeReady(
  home: string,
  coreDir: string,
): Promise<{ tookLock: boolean; pid?: number; error?: string }> {
  const nonce = process.env[NMZP_PROBE_NONCE_ENV];
  const nodePath = process.env.NMZP_PROBE_NODE || process.execPath;
  const entry = process.env.NMZP_PROBE_ENTRY || join(coreDir, "nmzp.mjs");
  try {
    return await withProbeMutex(home, async () => {
      const existing = readProbeLock(home);
      if (existing && existing.pid !== process.pid && isPidAlive(existing.pid)) {
        const ready = readProbeReady(home);
        if (ready && ready.pid === existing.pid && ready.nonce === existing.nonce) {
          return { tookLock: false, pid: existing.pid };
        }
        if (await lockIsOurs(home, existing, inspectPid)) return { tookLock: false, pid: existing.pid };
        return { tookLock: false, error: "probe_unverified" };
      }
      const useNonce = nonce || randomBytes(16).toString("hex");
      writeProbeLock(home, {
        pid: process.pid,
        marker: "nmzp-probe",
        version: NMZP_VERSION,
        startedAt: Date.now(),
        nonce: useNonce,
        nodePath,
        entry,
      });
      writeProbeReady(home, { pid: process.pid, nonce: useNonce });
      return { tookLock: true, pid: process.pid };
    });
  } catch (e) {
    const error = e instanceof Error && e.message.startsWith("probe_") ? e.message : "probe_mutex_failed";
    return { tookLock: false, error };
  }
}
