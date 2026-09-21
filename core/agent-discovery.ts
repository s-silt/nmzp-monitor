import { spawn } from "node:child_process";
import { Worker } from "node:worker_threads";
import { homedir, platform } from "node:os";
import { join, delimiter, isAbsolute, resolve } from "node:path";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  openSync,
  closeSync,
  unlinkSync,
  lstatSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { atomicWriteFile } from "./install-fs.ts";
import { windowsDiscoveryScript } from "./agent-discovery-windows.ts";
import { type ManualPath, type OsMetadata, type ScanInput } from "./agent-discovery-scan.ts";
import {
  DISCOVERY_INTERVAL_MS,
  DISCOVERY_SOURCES,
  mergeDiscovery,
  parseDiscovery,
  type DiscoverySnapshot,
  type ScanStatus,
} from "./agent-discovery-schema.ts";
const pending = new Map<string, Promise<DiscoverySnapshot>>();
const emptyOs: OsMetadata = { records: [], files: [], processes: [], states: {} };
function failure(status: ScanStatus, at = Date.now()): DiscoverySnapshot {
  return {
    schemaVersion: 1,
    platform: platform() === "win32" ? "win32" : "unsupported",
    checkedAt: at,
    completedAt: Date.now(),
    status,
    sources: DISCOVERY_SOURCES.map((id) => ({ id, status })),
    items: [],
  };
}
export const discoveryHome = () => process.env.NMZP_HOME || homedir();
export function readDiscovery(home: string): DiscoverySnapshot | undefined {
  try {
    return parseDiscovery(JSON.parse(readFileSync(join(home, ".nmzp", "discovery.json"), "utf8")));
  } catch {
    return;
  }
}
export function readManualPaths(home: string): ManualPath[] {
  try {
    const a = JSON.parse(readFileSync(join(home, ".nmzp", "discovery-paths.json"), "utf8"));
    return validateManualPaths(a);
  } catch {
    return [];
  }
}
export function validateManualPaths(raw: unknown): ManualPath[] {
  if (!Array.isArray(raw) || raw.length > 24) throw Error("invalid_paths");
  return raw.map((r) => {
    if (
      !r ||
      typeof r !== "object" ||
      !["executable", "npm-prefix", "extensions", "python-env"].includes(r.kind) ||
      typeof r.path !== "string" ||
      r.path.length > 500 ||
      !isAbsolute(r.path) ||
      /^(\\\\|\/\/)/.test(r.path) ||
      // eslint-disable-next-line no-control-regex -- Reject control bytes in user-supplied filesystem paths.
      /[\x00-\x1f]/.test(r.path) ||
      /(^|[\\/])node_modules([\\/]|$)/i.test(r.path) ||
      r.path.includes("..")
    )
      throw Error("invalid_paths");
    return { kind: r.kind, path: resolve(r.path) };
  });
}
export function setManualPaths(home: string, raw: unknown): void {
  const paths = validateManualPaths(raw);
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  atomicWriteFile(join(home, ".nmzp", "discovery-paths.json"), JSON.stringify(paths));
  writeFileSync(join(home, ".nmzp", "discovery-refresh"), "1");
}
export function requestDiscoveryRefresh(home: string): void {
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  writeFileSync(join(home, ".nmzp", "discovery-refresh"), "1");
}
/** OS process is ours and held until close. Bounded stdout, no stderr/paths in errors. */
export function runDiscoveryOs(script: string, timeout = 8000): Promise<OsMetadata> {
  return new Promise((resolveResult) => {
    const systemRoot = process.env.SystemRoot || "C:\\Windows";
    const child = spawn(
      join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        Buffer.from(script, "utf16le").toString("base64"),
      ],
      { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] },
    );
    let buf = "";
    let status: ScanStatus | undefined;
    const kill = (s: ScanStatus) => {
      status = s;
      child.kill();
    };
    const timer = setTimeout(() => kill("timeout"), timeout);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (s) => {
      if (buf.length + s.length > 1_500_000) kill("partial");
      else buf += s;
    });
    child.on("error", () => {
      clearTimeout(timer);
      resolveResult({
        ...emptyOs,
        states: Object.fromEntries(DISCOVERY_SOURCES.map((s) => [s, "error"])),
      });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      try {
        const lines = buf.trim().split(/\r?\n/);
        // A killed writer can leave a final partial JSON line. Recover only a complete checkpoint.
        let o;
        for (const line of lines.reverse()) {
          try { o = JSON.parse(line); break; }
          catch { /* A killed writer may leave a partial final line; try the previous checkpoint. */ }
        }
        if(!o)throw Error("no_checkpoint");
        if (
          Array.isArray(o.records) &&
          Array.isArray(o.files) &&
          Array.isArray(o.processes) &&
          o.states
        ) {
          if (status || code !== 0) {
            // Completed phases remain evidence; unfinished phases must not report success.
            o.states = Object.fromEntries(["registry","appx","path","processes"].map(source =>
              [source, o.states[source] === "ok" || o.states[source] === "permission" ? o.states[source] : status ?? "error"]));
            o.states.processes = status ?? "error";
            o.processes = [];
          }
          resolveResult(o);
          return;
        }
      } catch { /* Invalid or missing checkpoints are reported as error/partial below. */ }
      resolveResult({
        ...emptyOs,
        states: Object.fromEntries(DISCOVERY_SOURCES.map((s) => [s, status ?? "error"])),
      });
    });
  });
}
export function scanWorker(input: ScanInput, timeout = 5000): Promise<DiscoverySnapshot> {
  return new Promise((resolveResult) => {
    const worker = new Worker(new URL("./agent-discovery-worker.ts", import.meta.url), {
      workerData: input,
      execArgv: ["--experimental-strip-types"],
      resourceLimits: { maxOldGenerationSizeMb: 64 },
    });
    let done = false;
    const finish = (s: DiscoverySnapshot) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      void worker.terminate();
      resolveResult(s);
    };
    const timer = setTimeout(() => finish(failure("timeout", input.now)), timeout);
    worker.on("message", (m) => finish(parseDiscovery(m) ?? failure("error", input.now)));
    worker.on("error", () => finish(failure("error", input.now)));
    worker.on("exit", () => {
      if (!done) finish(failure("error", input.now));
    });
  });
}
export interface DiscoveryDeps {
  os?: (script: string) => Promise<OsMetadata>;
  scan?: (input: ScanInput) => Promise<DiscoverySnapshot>;
  platform?: string;
}
export async function refreshDiscovery(
  home: string,
  force = false,
  deps: DiscoveryDeps = {},
): Promise<DiscoverySnapshot> {
  const key = resolve(home).toLowerCase();
  const existing = pending.get(key);
  if (existing) return existing;
  const task = (async () => {
    const previous = readDiscovery(home);
    const dir = join(home, ".nmzp");
    mkdirSync(dir, { recursive: true });
    const marker = join(dir, "discovery-refresh");
    const requested = existsSync(marker);
    if (
      !force &&
      !requested &&
      previous &&
      Date.now() - previous.completedAt < DISCOVERY_INTERVAL_MS
    )
      return previous;
    if ((deps.platform ?? platform()) !== "win32") return failure("unsupported");
    const lock = join(dir, "discovery.lock");
    const token = randomBytes(16).toString("hex");
    try {
      const fd = openSync(lock, "wx");
      writeFileSync(fd, token);
      closeSync(fd);
    } catch {
      // A crash cannot leave a permanent lock. All work is bounded below 15 s; validate lease before publish.
      try {
        if (Date.now() - lstatSync(lock).mtimeMs > 60_000) unlinkSync(lock);
      } catch { /* A concurrent scanner may already have removed the stale lock. */ }
      return previous ? mergeDiscovery(previous, failure("partial")) : failure("partial");
    }
    const owns = () => {
      try {
        return readFileSync(lock, "utf8") === token;
      } catch {
        return false;
      }
    };
    try {
      if (requested) unlinkSync(marker);
      const salt = join(dir, "discovery.key");
      let secret: string;
      try {
        secret = readFileSync(salt, "utf8");
      } catch {
        secret = randomBytes(32).toString("hex");
        writeFileSync(salt, secret, { flag: "wx", mode: 0o600 });
      }
      const manual = readManualPaths(home);
      const at = Date.now();
      const os = await (deps.os ?? runDiscoveryOs)(
        windowsDiscoveryScript(
          manual.filter((m) => m.kind === "executable").map((m) => m.path),
          home,
        ),
      );
      const pathDirs = (process.env.PATH ?? "")
        .split(delimiter)
        .filter((p) => isAbsolute(p) && !p.startsWith("\\\\"))
        .slice(0, 128);
      const input: ScanInput = {
        home,
        key: secret,
        now: at,
        os,
        manual,
        pathDirs,
        packageRoots: [
          join(home, "AppData", "Roaming", "npm"),
          ...(process.env.NPM_CONFIG_PREFIX ? [process.env.NPM_CONFIG_PREFIX] : []),
        ],
        extensionRoots: [
          join(home, ".vscode", "extensions"),
          join(home, ".vscode-insiders", "extensions"),
          ...(process.env.VSCODE_EXTENSIONS ? [process.env.VSCODE_EXTENSIONS] : []),
        ],
        pythonRoots: [
          join(home, ".local", "share", "pipx", "venvs", "aider-chat"),
          join(home, "pipx", "venvs", "aider-chat"),
          join(home, "AppData", "Roaming", "uv", "tools", "aider-chat"),
        ],
      };
      const current = await (deps.scan ?? scanWorker)(input);
      const merged = mergeDiscovery(previous, current);
      if (owns()) atomicWriteFile(join(dir, "discovery.json"), JSON.stringify(merged));
      return merged;
    } catch {
      const failed = mergeDiscovery(previous, failure("error"));
      try {
        if (owns()) atomicWriteFile(join(dir, "discovery.json"), JSON.stringify(failed));
      } catch {
        /* Heartbeat still reports the failed attempt. */
      }
      return failed;
    } finally {
      if (owns()) unlinkSync(lock);
    }
  })().catch(() => mergeDiscovery(readDiscovery(home), failure("error")));
  pending.set(key, task);
  try {
    return await task;
  } finally {
    pending.delete(key);
  }
}
