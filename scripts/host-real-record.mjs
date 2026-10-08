// Human-only HOST_REAL draft writer. Bots must not run this file or sign its output.
// Pure helpers below are safe to import. main() is the only path that reads the machine.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const VERSION_TOKEN =
  /(?:^|[^\d.])v?((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?![\d.A-Za-z+-])/g;
const SHOT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.(png|jpg|jpeg|webp)$/;
const FORBIDDEN_BASE = new Set(["settings.json", "hooks.json", "credentials.json"]);

export const REWRITE_ADOPTED = "NMZPHRSAFE";
export const REWRITE_IGNORED = "NMZPHRCANARY";

export function repoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function sha256Hex(bytes) {
  const buf = typeof bytes === "string" ? Buffer.from(bytes) : bytes;
  return createHash("sha256").update(buf).digest("hex");
}

export function versionRangeFor(hostVersion) {
  if (typeof hostVersion !== "string") return null;
  const match = EXACT_VERSION.exec(hostVersion);
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), minPatch: Number(match[3]) };
}

export function versionRangeMatches(hostVersion, range) {
  const derived = versionRangeFor(hostVersion);
  if (!derived || !range || typeof range !== "object") return false;
  return (
    derived.major === range.major && derived.minor === range.minor && derived.minPatch === range.minPatch
  );
}

export function parseExactVersion(text) {
  if (typeof text !== "string") return null;
  const found = [];
  for (const match of text.matchAll(VERSION_TOKEN)) found.push(match[1]);
  if (found.length !== 1) return null;
  return versionRangeFor(found[0]) ? found[0] : null;
}

export function verdictBlock(observation) {
  if (observation.exists) return "FAIL";
  if (observation.uiDenied === true) return "PASS";
  return "INCONCLUSIVE";
}

export function normalizeResultText(text) {
  return String(text ?? "")
    .replace(/\r\n/g, "\n")
    .replace(/\n$/, "");
}

export function verdictRewrite(observation) {
  if (!observation.exists) return "INCONCLUSIVE";
  const text = normalizeResultText(observation.text);
  if (text === REWRITE_ADOPTED) return "PASS";
  if (text === REWRITE_IGNORED) return "FAIL";
  return "INCONCLUSIVE";
}

export function assertReadableTarget(file) {
  if (typeof file !== "string" || file.trim() === "") throw new Error("missing path");
  const base = path.win32.basename(path.posix.basename(file));
  const lower = base.toLowerCase();
  if (lower.startsWith(".env") || lower.endsWith(".token") || FORBIDDEN_BASE.has(lower)) {
    throw new Error(`refusing to read ${base}`);
  }
  const parts = path.resolve(file).split(/[\\/]+/);
  if (parts.includes(".nmzp") || parts.includes(".ssh")) throw new Error("refusing to read a protected directory");
}

export function assembleArtifact(input) {
  const versionRange = versionRangeFor(input.hostVersion);
  if (!versionRange) throw new Error("hostVersion is not an exact x.y.z");
  if (input.host !== "claude" && input.host !== "codex") throw new Error("host must be claude or codex");
  if (!/^[0-9a-f]{40}$/.test(input.nmzpCommit)) throw new Error("nmzpCommit must be 40 hex chars");
  if (!Array.isArray(input.actions) || input.actions.length < 1 || input.actions.length > 2) {
    throw new Error("actions must contain one or two items");
  }
  if (!Array.isArray(input.trustSteps) || input.trustSteps.length < 1) throw new Error("trustSteps required");
  return {
    schemaVersion: 1,
    host: input.host,
    hostVersion: input.hostVersion,
    versionRange,
    os: {
      platform: input.os.platform,
      release: input.os.release,
      arch: input.os.arch,
    },
    adapterRevision: input.adapterRevision,
    nmzpVersion: input.nmzpVersion,
    nmzpCommit: input.nmzpCommit,
    actions: input.actions,
    trustSteps: input.trustSteps,
    recordedAt: input.recordedAt,
    recordedBy: "human",
    ref: `artifact:host-real/${input.host}/${input.hostVersion}`,
  };
}

function observedRewriteText(text) {
  const normalized = normalizeResultText(text);
  if (normalized.length > 200 || normalized.includes("AKIA")) return null;
  return normalized;
}

function evidenceOf(screenshots, logs) {
  return {
    logSha256: logs.map((file) => {
      assertReadableTarget(file);
      const st = lstatSync(file);
      if (st.isSymbolicLink() || !st.isFile()) throw new Error(`refusing to read ${file}`);
      return sha256Hex(readFileSync(file));
    }),
    screenshots,
  };
}

function hookStatusOf(exitCode, summary) {
  if (exitCode === undefined && summary === undefined) return undefined;
  if (exitCode === undefined || summary === undefined || summary === "") {
    throw new Error("hook status needs both an exit code and a summary");
  }
  return { exitCode: Number(exitCode), summary };
}

function readResult(file) {
  assertReadableTarget(file);
  if (!existsSync(file)) return { exists: false, text: null };
  const st = lstatSync(file);
  if (st.isSymbolicLink()) throw new Error("refusing to follow a symlink");
  if (!st.isFile()) throw new Error("result path is not a file");
  return { exists: true, text: readFileSync(file, "utf8") };
}

function readScenario(root, host, action) {
  const file = path.join(root, "policy-spec", "host-real", host, action, "scenario.json");
  const bytes = readFileSync(file);
  return { scenario: JSON.parse(bytes.toString("utf8")), sha256: sha256Hex(bytes) };
}

function screenshotList(values) {
  for (const name of values) {
    if (!SHOT_NAME.test(name)) throw new Error(`screenshot filename is not allowed: ${name}`);
  }
  return values;
}

function usage() {
  return [
    "usage: node --experimental-strip-types scripts/host-real-record.mjs \\",
    "  --host claude|codex --exe <name> --out <draft.json> \\",
    "  --block-file <path> --rewrite-file <path> --ui-denied yes|no \\",
    "  --trust-step <text> [--trust-step <text>] \\",
    "  [--block-screenshot <file.png>] [--rewrite-screenshot <file.png>] \\",
    "  [--block-log <path>] [--rewrite-log <path>] \\",
    "  [--block-hook-exit <n> --block-hook-summary <text>] \\",
    "  [--rewrite-hook-exit <n> --rewrite-hook-summary <text>] \\",
    "  [--recorded-at <RFC3339>]",
    "Writes an unsigned draft. Does not git add or git commit.",
  ].join("\n");
}

function parseArgs(argv) {
  const out = {
    trustStep: [],
    blockScreenshot: [],
    rewriteScreenshot: [],
    blockLog: [],
    rewriteLog: [],
  };
  const flags = {
    "--host": "host",
    "--exe": "exe",
    "--out": "out",
    "--block-file": "blockFile",
    "--rewrite-file": "rewriteFile",
    "--ui-denied": "uiDenied",
    "--block-hook-exit": "blockHookExit",
    "--block-hook-summary": "blockHookSummary",
    "--rewrite-hook-exit": "rewriteHookExit",
    "--rewrite-hook-summary": "rewriteHookSummary",
    "--recorded-at": "recordedAt",
  };
  const lists = {
    "--trust-step": "trustStep",
    "--block-screenshot": "blockScreenshot",
    "--rewrite-screenshot": "rewriteScreenshot",
    "--block-log": "blockLog",
    "--rewrite-log": "rewriteLog",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help") {
      out.help = true;
      continue;
    }
    const key = flags[arg] ?? lists[arg];
    if (!key) throw new Error(`unknown argument ${arg}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${arg}`);
    if (lists[arg]) out[key].push(value);
    else out[key] = value;
    index += 1;
  }
  return out;
}

function parseUiDenied(value) {
  if (value === "yes" || value === "true") return true;
  if (value === "no" || value === "false") return false;
  throw new Error("--ui-denied must be yes or no");
}

async function promptMissing(args) {
  const missing = ["host", "exe", "out", "blockFile", "rewriteFile", "uiDenied"].filter((key) => !args[key]);
  if (args.trustStep.length === 0) missing.push("trustStep");
  if (missing.length === 0) return args;
  if (!stdin.isTTY) {
    throw new Error(`${usage()}\nmissing ${missing.join(", ")}`);
  }
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    if (!args.host) args.host = (await rl.question("host (claude|codex): ")).trim();
    if (!args.exe) args.exe = (await rl.question("executable name: ")).trim();
    if (!args.out) args.out = (await rl.question("output json path: ")).trim();
    if (!args.blockFile) args.blockFile = (await rl.question("BLOCK result file: ")).trim();
    if (!args.rewriteFile) args.rewriteFile = (await rl.question("REWRITE result file: ")).trim();
    if (!args.uiDenied) args.uiDenied = (await rl.question("BLOCK ui denied? yes|no: ")).trim();
    if (args.trustStep.length === 0) {
      const step = (await rl.question("trust step: ")).trim();
      if (step) args.trustStep.push(step);
    }
  } finally {
    rl.close();
  }
  return args;
}

function hostVersionFromExe(exe) {
  if (typeof exe !== "string" || exe.trim() === "" || exe.includes("/") || exe.includes("\\")) {
    throw new Error("pass an executable name, not a path");
  }
  const base = path.basename(exe);
  if (base.startsWith(".env") || base.endsWith(".token")) throw new Error("refusing that executable name");
  const result = execFileSync(exe, ["--version"], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const version = parseExactVersion(result);
  if (!version) throw new Error("version output did not contain one exact x.y.z");
  return version;
}

function gitHead(root) {
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", windowsHide: true });
  if (result.status !== 0) throw new Error("git rev-parse HEAD failed");
  const sha = result.stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error("git HEAD is not 40 hex chars");
  return sha;
}

function buildActions(root, host, args) {
  const block = readScenario(root, host, "block");
  const rewrite = readScenario(root, host, "rewrite");
  const blockFile = readResult(args.blockFile);
  const rewriteFile = readResult(args.rewriteFile);
  const uiDenied = parseUiDenied(args.uiDenied);
  const blockEvidence = evidenceOf(screenshotList(args.blockScreenshot), args.blockLog);
  const rewriteEvidence = evidenceOf(screenshotList(args.rewriteScreenshot), args.rewriteLog);
  const rewriteText = rewriteFile.exists ? observedRewriteText(rewriteFile.text) : null;
  const rewriteVerdict =
    rewriteFile.exists && rewriteText === null
      ? "INCONCLUSIVE"
      : verdictRewrite({ exists: rewriteFile.exists, text: rewriteFile.text });
  const blockHook = hookStatusOf(args.blockHookExit, args.blockHookSummary);
  const rewriteHook = hookStatusOf(args.rewriteHookExit, args.rewriteHookSummary);
  return [
    {
      action: "BLOCK",
      scenarioId: block.scenario.id,
      scenarioSha256: block.sha256,
      expected: { decision: block.scenario.expected.decision, ruleId: block.scenario.expected.ruleId },
      observed: { resultFile: blockFile.exists ? "present" : "missing", resultText: null, uiDenied },
      verdict: verdictBlock({ exists: blockFile.exists, uiDenied }),
      evidence: blockEvidence,
      ...(blockHook ? { hookStatus: blockHook } : {}),
    },
    {
      action: "REWRITE",
      scenarioId: rewrite.scenario.id,
      scenarioSha256: rewrite.sha256,
      expected: { decision: rewrite.scenario.expected.decision, ruleId: rewrite.scenario.expected.ruleId },
      observed: {
        resultFile: rewriteFile.exists ? "present" : "missing",
        resultText: rewriteText,
        uiDenied: null,
      },
      verdict: rewriteVerdict,
      evidence: rewriteEvidence,
      ...(rewriteHook ? { hookStatus: rewriteHook } : {}),
    },
  ];
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const args = await promptMissing(parsed);
  if (!args.host || !args.exe || !args.out || !args.blockFile || !args.rewriteFile || !args.uiDenied) {
    throw new Error(usage());
  }
  if (args.trustStep.length === 0) throw new Error("at least one --trust-step is required");
  const root = repoRoot();
  const hostVersion = hostVersionFromExe(args.exe);
  const { NMZP_VERSION } = await import("../core/constants.ts");
  const { SERVER_ADAPTER_REVISION } = await import("../core/protocol/v2-context.ts");
  const recordedAt = args.recordedAt ?? new Date().toISOString();
  const artifact = assembleArtifact({
    host: args.host,
    hostVersion,
    os: { platform: os.platform(), release: os.release(), arch: os.arch() },
    adapterRevision: SERVER_ADAPTER_REVISION,
    nmzpVersion: NMZP_VERSION,
    nmzpCommit: gitHead(root),
    actions: buildActions(root, args.host, args),
    trustSteps: args.trustStep,
    recordedAt,
  });
  assertReadableTarget(args.out);
  if (existsSync(args.out)) throw new Error("output already exists; refusing to overwrite");
  mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  writeFileSync(args.out, `${JSON.stringify(artifact, null, 2)}\n`, { flag: "wx" });
  const emptyShots = artifact.actions.some((action) => action.evidence.screenshots.length === 0);
  process.stdout.write(`未签名草稿已写入 ${args.out}\n`);
  process.stdout.write(`hostVersion ${artifact.hostVersion} versionRange ${artifact.versionRange.major}.${artifact.versionRange.minor}.${artifact.versionRange.minPatch}\n`);
  process.stdout.write("产物未签名。请自行检查后执行：\n");
  process.stdout.write(`git add -- ${args.out}\n`);
  process.stdout.write("git commit -S\n");
  process.stdout.write("产物文件不加 minisign。本脚本不执行 git add 或 git commit。\n");
  if (emptyShots) process.stdout.write("截图文件名为空。签名提交前应补上，并重新记录到新路径。\n");
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync.native(fileURLToPath(import.meta.url)) === realpathSync.native(entry);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = message.startsWith("usage:") ? 2 : 1;
  });
}
