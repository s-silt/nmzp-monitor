#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const NPM_BIN = join("node_modules", "npm", "bin");
const cliCache = new Map();
const owned = new Set();
const CANCEL_SIGNALS = Object.freeze(["SIGINT", "SIGTERM"]);
let stopChecks = false;
let cancellationHooks = null;

// Checks against the dependency tree already present in this checkout.
export const RELEASE_CHECKS = Object.freeze([
  Object.freeze(["npm", Object.freeze(["run", "typecheck"])]),
  Object.freeze(["npm", Object.freeze(["run", "lint"])]),
  Object.freeze(["npm", Object.freeze(["test"])]),
  Object.freeze(["npm", Object.freeze(["run", "build"])]),
]);

const FIXED_NPM_ARGS = Object.freeze([
  Object.freeze(["--version"]),
  ...RELEASE_CHECKS.map((entry) => entry[1]),
]);

export function npmArgsAllowed(args) {
  return FIXED_NPM_ARGS.some(
    (allowed) => allowed.length === args.length && allowed.every((part, index) => part === args[index]),
  );
}

function isRegularFile(path) {
  try {
    const info = lstatSync(path);
    return info.isFile() && !info.isSymbolicLink();
  } catch {
    return false;
  }
}

function isNpmBinFile(path, name) {
  if (!isAbsolute(path) || !isRegularFile(path)) return false;
  const folded = path.replaceAll("/", "\\").toLowerCase();
  return folded.endsWith(`\\node_modules\\npm\\bin\\${name.toLowerCase()}`);
}

function pathDirs(env) {
  return (env.Path ?? env.PATH ?? "").split(delimiter).filter(Boolean);
}

export function ownedSignalTarget(pid, platform = process.platform) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  if (platform === "win32") return { pid, direct: true };
  return { pid: -pid, direct: false };
}

export function cancellationStatus(_unfinished) {
  return 1;
}

function taskkillExe() {
  const rootDir = process.env.SystemRoot || process.env.windir;
  return rootDir ? join(rootDir, "System32", "taskkill.exe") : null;
}

function stopOwnedTree(pid, signal, platform = process.platform) {
  const target = ownedSignalTarget(pid, platform);
  if (!target) return;
  if (target.direct) {
    const file = taskkillExe();
    if (!file) return;
    try {
      spawnSync(file, ["/PID", String(target.pid), "/T", "/F"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
        timeout: 2_000,
      });
    } catch {
      // The owned tree was not confirmed stopped.
    }
    return;
  }
  try {
    process.kill(target.pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      // The owned process has already exited.
    }
  }
}

function recordClosed(record) {
  return record.child.exitCode != null || record.child.signalCode != null;
}

function waitClosed(records, deadlineMs) {
  const pending = new Set(records.filter((record) => !recordClosed(record)));
  if (pending.size === 0) return Promise.resolve([]);
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      resolve([...pending].filter((record) => !recordClosed(record)));
    };
    const timer = setTimeout(finish, deadlineMs);
    for (const record of pending) {
      record.child.once("close", () => {
        pending.delete(record);
        if (pending.size === 0) finish();
      });
    }
  });
}

export async function cancelOwnedChildren(signal = "SIGTERM", deadlineMs = 2_000) {
  const pending = [...owned];
  for (const record of pending) record.state.cancelled = true;
  for (const record of pending) stopOwnedTree(record.child.pid, signal);
  let unfinished = await waitClosed(pending, deadlineMs);
  if (process.platform !== "win32" && unfinished.length > 0) {
    for (const record of unfinished) stopOwnedTree(record.child.pid, "SIGKILL");
    unfinished = await waitClosed(unfinished, 1_000);
  }
  return cancellationStatus(unfinished);
}

export function removeCancellationListeners() {
  if (!cancellationHooks) return;
  for (const [signal, handler] of cancellationHooks.handlers) {
    cancellationHooks.target.off(signal, handler);
  }
  cancellationHooks.handlers.clear();
}

export function whenCancellationSettled() {
  return cancellationHooks?.done ?? Promise.resolve();
}

export function installCancellation(options = {}) {
  if (cancellationHooks) return;
  const target = options.process ?? process;
  const exitImpl = options.exit ?? ((status) => process.exit(status));
  const handlers = new Map();
  cancellationHooks = { target, handlers, running: false, done: null };
  const run = (signal) => {
    if (!cancellationHooks || cancellationHooks.running) return;
    cancellationHooks.running = true;
    stopChecks = true;
    cancellationHooks.done = (async () => {
      removeCancellationListeners();
      const code = await cancelOwnedChildren(signal);
      exitImpl(code);
      stopChecks = false;
      if (cancellationHooks) cancellationHooks.running = false;
    })();
  };
  for (const signal of CANCEL_SIGNALS) {
    const handler = () => run(signal);
    handlers.set(signal, handler);
    target.on(signal, handler);
  }
}

export function spawnOwned(file, args, options = {}) {
  const child = spawn(file, args, {
    cwd: options.cwd ?? root,
    env: options.env ?? process.env,
    shell: false,
    windowsHide: true,
    stdio: options.stdio ?? "inherit",
    detached: process.platform !== "win32",
  });
  options.onChild?.(child);
  const state = { timedOut: false, cancelled: false };
  const record = { child, state };
  owned.add(record);
  const drop = () => owned.delete(record);
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    if (child.stdout) {
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
    }
    if (child.stderr) {
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
    }
    let settled = false;
    const onParentExit = () => stopOwnedTree(child.pid, "SIGTERM");
    process.once("exit", onParentExit);
    const timer = options.timeoutMs == null
      ? null
      : setTimeout(() => {
          state.timedOut = true;
          stopOwnedTree(child.pid, "SIGTERM");
        }, options.timeoutMs);
    if (timer) timer.unref();
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      drop();
      if (timer) clearTimeout(timer);
      process.off("exit", onParentExit);
      fn();
    };
    child.once("error", (error) => {
      stopOwnedTree(child.pid, "SIGTERM");
      finish(() => reject(error));
    });
    child.once("close", (code, signal) => {
      let status = code;
      let outSignal = signal;
      if (state.timedOut || state.cancelled) {
        if (outSignal == null) outSignal = "SIGTERM";
        if (status === 0 || status == null) status = 1;
      }
      finish(() => resolve({ status, signal: outSignal, stdout, stderr, timedOut: state.timedOut }));
    });
  });
}

async function readNpmPrefix(prefixJs, options) {
  const result = await spawnOwned(options.execPath ?? process.execPath, [prefixJs], {
    ...options,
    stdio: "pipe",
    timeoutMs: 10_000,
  });
  if (result.signal || result.status !== 0) return null;
  const lines = result.stdout.replace(/^\uFEFF/, "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length !== 1 || !isAbsolute(lines[0])) return null;
  return lines[0];
}

async function cliForShim(shim, options) {
  const binDir = join(dirname(shim), NPM_BIN);
  const adjacent = join(binDir, "npm-cli.js");
  const prefixJs = join(binDir, "npm-prefix.js");
  if (!isNpmBinFile(adjacent, "npm-cli.js")) return null;
  if (!isNpmBinFile(prefixJs, "npm-prefix.js")) return adjacent;
  try {
    const prefix = await readNpmPrefix(prefixJs, options);
    if (prefix) {
      const selected = join(prefix, NPM_BIN, "npm-cli.js");
      if (isNpmBinFile(selected, "npm-cli.js")) return selected;
    }
  } catch {
    // npm.cmd keeps the shim-adjacent CLI when prefix lookup fails.
  }
  return adjacent;
}

export async function resolveNpmLaunch(args, options = {}) {
  if (!npmArgsAllowed(args)) throw new Error("npm arguments are not in the fixed preflight set");
  const platform = options.platform ?? process.platform;
  if (platform !== "win32") return { file: "npm", args: [...args] };
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? root;
  const execPath = options.execPath ?? process.execPath;
  const cacheKey = `${cwd}\0${env.npm_config_prefix ?? ""}\0${env.Path ?? env.PATH ?? ""}`;
  let cli = cliCache.get(cacheKey) ?? null;
  if (!cli) {
    for (const dir of pathDirs(env)) {
      const exe = join(dir, "npm.exe");
      if (isRegularFile(exe)) return { file: exe, args: [...args] };
      const shim = join(dir, "npm.cmd");
      if (!isRegularFile(shim)) continue;
      cli = await cliForShim(shim, { ...options, cwd, env, execPath });
      if (cli) break;
    }
    if (!cli) throw new Error("configured npm CLI was not found");
    cliCache.set(cacheKey, cli);
  }
  return { file: execPath, args: [cli, ...args] };
}

export function statusOf(result) {
  if (!result || typeof result !== "object") return 1;
  if (result.signal) return 1;
  if (typeof result.status !== "number" || !Number.isInteger(result.status)) return 1;
  return result.status;
}

// Windows cannot spawn npm.cmd with shell false (EINVAL). The launch above
// uses the CLI that npm.cmd would select, or npm.exe when PATH has one.
export async function defaultSpawn(command, args, options = {}) {
  if (command === "npm") {
    const launch = await resolveNpmLaunch(args, options);
    return spawnOwned(launch.file, launch.args, options);
  }
  return spawnOwned(command, args, options);
}

// Direct execution only. A node:test import must not start these checks.
export async function runReleasePreflight(options = {}) {
  const spawnImpl = options.spawnImpl ?? defaultSpawn;
  const cwd = options.cwd ?? root;
  const env = options.env ?? process.env;
  const stderr = options.stderr ?? process.stderr;
  for (const [command, args] of RELEASE_CHECKS) {
    if (stopChecks) return 1;
    let status;
    try {
      const result = await spawnImpl(command, args, { cwd, env });
      status = statusOf(result);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "spawn failed";
      stderr.write(`release-preflight: ${command} ${args.join(" ")} failed: ${detail}\n`);
      return 1;
    }
    if (status !== 0) {
      stderr.write(`release-preflight: ${command} ${args.join(" ")} exited ${status}\n`);
      return status;
    }
  }
  return 0;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return import.meta.url === pathToFileURL(entry).href;
  }
}

if (invokedDirectly()) {
  if (process.env.NODE_TEST_CONTEXT) {
    process.stderr.write("release-preflight: refused inside a node:test process\n");
    process.exit(1);
  }
  installCancellation();
  try {
    const code = await runReleasePreflight();
    removeCancellationListeners();
    process.exit(code);
  } catch (error) {
    removeCancellationListeners();
    process.stderr.write(`${error instanceof Error ? error.message : "release preflight failed"}\n`);
    process.exit(1);
  }
}
