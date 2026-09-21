import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HEARTBEAT_INTERVAL_MS } from "./constants.ts";

export const SNAPSHOT_STATUS_MAX_STDOUT = 65_536;
/** Real child deadline. Must stay below HEARTBEAT_INTERVAL_MS. */
export const SNAPSHOT_GUARD_PROBE_MS = Math.min(8_000, Math.max(1_000, HEARTBEAT_INTERVAL_MS - 22_000));

const defaultWorkerPath = join(dirname(fileURLToPath(import.meta.url)), "snapshot-status-worker.ts");

const inFlight = new Map<string, Promise<unknown>>();

export function snapshotStatusHomeKey(home: string): string {
  try {
    return resolve(home).replace(/\\/g, "/").toLowerCase();
  } catch {
    return home;
  }
}

export function snapshotGuardPlatformSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32";
}

function unsupportedStatus(): Record<string, unknown> {
  return {
    supported: false,
    active: false,
    managed: false,
    targetPresent: false,
    writeBlocked: false,
    existingArchiveCoverage: "none",
    error: "unsupported_platform",
    lastVerified: 0,
  };
}

function killOwnedProcessTree(pid: number, useGroup: boolean): void {
  if (!pid) return;
  if (process.platform === "win32") {
    spawn("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    return;
  }
  try {
    process.kill(useGroup ? -pid : pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  }
}

function runStatusChild(opts: { home: string; timeoutMs: number; workerPath: string }): Promise<unknown> {
  const useGroup = process.platform !== "win32";
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", opts.workerPath, "--home", opts.home],
      {
        windowsHide: true,
        detached: useGroup,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const pid = child.pid ?? 0;
    const finish = (value: unknown, kill: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (kill) killOwnedProcessTree(pid, useGroup);
      child.stdout?.destroy();
      child.stderr?.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => finish({ error: "timeout" }, true), opts.timeoutMs);
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (c: string) => {
      stdout += c;
      if (stdout.length > SNAPSHOT_STATUS_MAX_STDOUT) {
        stdout = stdout.slice(0, SNAPSHOT_STATUS_MAX_STDOUT);
        finish({ error: "status_failed" }, true);
      }
    });
    child.stderr?.resume();
    child.on("error", () => finish({ error: "status_failed" }, true));
    child.on("close", (code) => {
      if (settled) return;
      if (code !== 0) {
        finish({ error: "status_failed" }, false);
        return;
      }
      try {
        finish(JSON.parse(stdout.trim()) as unknown, false);
      } catch {
        finish({ error: "status_failed" }, false);
      }
    });
  });
}

/**
 * Production default: async child running read-only snapshotGuardStatus.
 * Timeout kills the owned worker (and Windows process tree). In-flight is per home.
 */
export function collectSnapshotGuardStatus(opts: {
  home: string;
  timeoutMs?: number;
  workerPath?: string;
}): Promise<unknown> {
  if (typeof opts.home !== "string" || !opts.home || opts.home.includes("\0")) {
    return Promise.resolve({ error: "path_invalid" });
  }
  const timeoutMs = opts.timeoutMs ?? SNAPSHOT_GUARD_PROBE_MS;
  if (!opts.workerPath && !snapshotGuardPlatformSupported()) {
    return Promise.resolve(unsupportedStatus());
  }
  const key = `${snapshotStatusHomeKey(opts.home)}::${opts.workerPath ?? defaultWorkerPath}`;
  const existing = inFlight.get(key);
  if (existing) return existing;
  const pending = runStatusChild({
    home: opts.home,
    timeoutMs,
    workerPath: opts.workerPath ?? defaultWorkerPath,
  }).finally(() => {
    if (inFlight.get(key) === pending) inFlight.delete(key);
  });
  inFlight.set(key, pending);
  return pending;
}
