// Loopback-only synthetic Hook latency.
// Legacy numeric argv: same-process runHook + receipt settlement (window + sqlite).
// --subprocess: actual core/nmzp.mjs hook --agent grok in an owned temp fixture.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { dirname, join, parse as parsePath } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startServer } from "../core/serve.ts";
import { pinnedHttps } from "../core/https-client.ts";
import { runHook, settleHookAfterStdout } from "../core/hook.ts";
import { readPolicyCache, writePolicyCache } from "../core/policy-cache.ts";

export const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const repoRoot = REPO_ROOT;
const coreDir = fileURLToPath(new URL("../core/", import.meta.url));
const hookEntry = join(coreDir, "nmzp.mjs");
const thisFile = fileURLToPath(import.meta.url);

export const SAMPLE_MIN = 1;
export const SAMPLE_MAX = 100;
export const DEFAULT_SAMPLES = 30;
export const TIMEOUT_MIN_MS = 1_000;
export const TIMEOUT_MAX_MS = 60_000;
export const DEFAULT_TIMEOUT_MS = 15_000;
export const EXIT_WAIT_MS = 500;
export const EXIT_ESCALATE_WAIT_MS = 500;
export const AUTHORIZED_BASELINE_SHA = "0ea8f6eac4457c5e13b22b7130f64d48e3613927";

export const MODE_LEGACY = "legacy-same-process-loopback-warm";
export const MODE_SUBPROCESS = "subprocess-fresh-process";
export const MODE_ALL = "all";

export const LIMITATION_LEGACY =
  "Same-process runHook plus receipt settlement on loopback; not subprocess startup.";
export const LIMITATION_FRESH_PROCESS = "Fresh process is NOT after-reboot cold.";
export const LIMITATION_HOST_REAL = "Windows local synthetic measurement is not HOST_REAL tool enforcement.";
export const LIMITATION_EMPTY_ALLOW =
  "Grok ordinary Read allow is empty stdout; protocol-return is stdout end and may coincide with process exit after settlement.";
export const LIMITATION_OFFLINE =
  "Offline uses the same valid locally cached policy after the owned loopback server is closed.";
export const LIMITATION_ONLINE_PROOF =
  "Online success requires GET /api/v1/state event id match plus decision allow|log and enforcement delivered. Fallback is classified separately and excluded from online percentiles.";
export const LIMITATION_OFFLINE_PROOF =
  "Offline success requires a fresh same-event outbox item (tool/decision/policyVersion) and hook-status ok for that eventId. Cache existence and no-cache low-risk allow are insufficient. Server receipts are absent because the owned server is closed.";

export const USAGE = `Loopback-only synthetic hook bench. Never uses ~/.nmzp or non-loopback network.

Legacy (default; existing numeric samples argument):
  node --experimental-strip-types scripts/bench-hook.mjs
  node --experimental-strip-types scripts/bench-hook.mjs 10

Subprocess startup (actual core/nmzp.mjs hook --agent grok):
  node --experimental-strip-types scripts/bench-hook.mjs --subprocess 10
  node --experimental-strip-types scripts/bench-hook.mjs --all 10

Flags: --legacy | --subprocess | --all | --mode legacy|subprocess|all
       --samples N | N   (1..100, default 30)
       --timeout-ms N    (1000..60000, default 15000, subprocess only)
       --report PATH     (default bench/REPORT.md)
       --help

Legacy label: legacy-same-process-loopback-warm. Subprocess is a fresh process, not reboot-first cold.
Linux cells are NOT_RUN when this process is not linux. HOST_REAL and reboot-first remain NOT_RUN.
`;

export function percentile(sorted, q) {
  if (!sorted.length) return undefined;
  return sorted[Math.ceil(sorted.length * q) - 1];
}

function parseSamples(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < SAMPLE_MIN || n > SAMPLE_MAX) throw new Error("samples must be 1..100");
  return n;
}

function parseTimeout(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < TIMEOUT_MIN_MS || n > TIMEOUT_MAX_MS) {
    throw new Error(`timeout-ms must be ${TIMEOUT_MIN_MS}..${TIMEOUT_MAX_MS}`);
  }
  return n;
}

export function parseBenchArgs(argv) {
  let samples;
  let mode = MODE_LEGACY;
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  let reportPath = null;
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") return { help: true, samples: DEFAULT_SAMPLES, mode, timeoutMs, reportPath };
    if (a === "--subprocess") {
      mode = MODE_SUBPROCESS;
      continue;
    }
    if (a === "--legacy") {
      mode = MODE_LEGACY;
      continue;
    }
    if (a === "--all") {
      mode = MODE_ALL;
      continue;
    }
    if (a === "--mode") {
      const v = argv[++i];
      if (v === "legacy" || v === "same-process") mode = MODE_LEGACY;
      else if (v === "subprocess" || v === "spawn") mode = MODE_SUBPROCESS;
      else if (v === "all") mode = MODE_ALL;
      else throw new Error(`unknown --mode ${v}`);
      continue;
    }
    if (a === "--samples") {
      samples = parseSamples(argv[++i]);
      continue;
    }
    if (a === "--timeout-ms") {
      timeoutMs = parseTimeout(argv[++i]);
      continue;
    }
    if (a === "--report") {
      reportPath = argv[++i];
      if (!reportPath) throw new Error("missing --report path");
      continue;
    }
    if (a.startsWith("-")) throw new Error(`unknown flag ${a}`);
    positional.push(a);
  }
  if (positional.length > 1) throw new Error("unexpected extra arguments");
  if (positional.length === 1) {
    if (samples !== undefined) throw new Error("samples specified twice");
    samples = parseSamples(positional[0]);
  }
  if (samples === undefined) samples = DEFAULT_SAMPLES;
  return { help: false, samples, mode, timeoutMs, reportPath };
}

export function redact(text) {
  if (!text) return "";
  return String(text)
    .replace(/Bearer\s+\S+/gi, "Bearer [redacted]")
    .replace(/"(token|deviceToken|adminToken|caPem)"\s*:\s*"[^"]*"/gi, '"$1":"[redacted]"');
}

export function syntheticReadPayload(i, prefix = "wp04-read") {
  return JSON.stringify({
    eventId: `${prefix}-${i}`,
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: `synthetic-wp04-${i}.txt` },
  });
}

export function eventIdFor(i, prefix = "wp04-read") {
  return `${prefix}-${i}`;
}

export function classifyHookOutput(stdout, exitCode) {
  const text = stdout ?? "";
  const trimmed = text.trim();
  if (exitCode !== 0) {
    return { ok: false, decision: "unexpected", error: `exit_${exitCode}`, content: redact(trimmed).slice(0, 200) };
  }
  if (trimmed.includes("nmzp_hook_bootstrap_failed")) {
    return { ok: false, decision: "deny", error: "bootstrap_failed", content: "nmzp_hook_bootstrap_failed" };
  }
  if (!trimmed) return { ok: true, decision: "allow", content: "" };
  try {
    const parsed = JSON.parse(trimmed);
    const deny =
      parsed?.decision === "deny" ||
      parsed?.permission === "deny" ||
      parsed?.hookSpecificOutput?.permissionDecision === "deny";
    if (deny) {
      const reason =
        parsed.reason ||
        parsed.hookSpecificOutput?.permissionDecisionReason ||
        parsed.user_message ||
        "deny";
      return { ok: false, decision: "deny", error: `deny:${reason}`, content: redact(String(reason)).slice(0, 200) };
    }
    return { ok: false, decision: "unexpected", error: "non_empty_allow_stdout", content: redact(trimmed).slice(0, 200) };
  } catch {
    return { ok: false, decision: "unexpected", error: "non_json_stdout", content: redact(trimmed).slice(0, 200) };
  }
}

export function proveOnlineEvent(eventId, events, expected = {}) {
  if (typeof eventId !== "string" || !eventId) return { ok: false, class: "failed", error: "missing_event_id" };
  const list = Array.isArray(events) ? events : [];
  const matches = list.filter((e) => e && e.id === eventId);
  if (expected.beforeIds instanceof Set && expected.beforeIds.has(eventId)) {
    return { ok: false, class: "failed", error: "stale_server_event" };
  }
  if (matches.length === 0) return { ok: false, class: "fallback", error: "online_fallback" };
  if (matches.length !== 1) return { ok: false, class: "failed", error: "duplicate_event_id" };
  const e = matches[0];
  const wantTool = expected.tool ?? "Read";
  if (e.tool !== wantTool && e.nativeTool !== wantTool) return { ok: false, class: "failed", error: "unexpected_tool" };
  if (e.decision !== "allow" && e.decision !== "log") return { ok: false, class: "failed", error: "unexpected_decision" };
  if (expected.policyVersion !== undefined && e.policyVersion !== expected.policyVersion) {
    return { ok: false, class: "failed", error: "unexpected_policy_version" };
  }
  if (e.enforcement !== "delivered") return { ok: false, class: "failed", error: "online_receipt_missing" };
  return {
    ok: true,
    class: "success",
    eventId,
    decision: e.decision,
    enforcement: e.enforcement,
    policyVersion: e.policyVersion,
    tool: e.tool,
  };
}

export function outboxItemKey(item) {
  if (!item) return "";
  return `${item.kind}:${item.eventId}:${item.payloadHash ?? ""}`;
}

export function proveOfflineOutbox(opts) {
  const eventId = opts.eventId;
  if (typeof eventId !== "string" || !eventId) return { ok: false, class: "failed", error: "missing_event_id" };
  const before = new Set((opts.beforeItems ?? []).map(outboxItemKey));
  const fresh = (opts.afterItems ?? []).filter(
    (item) => item && item.kind === "event" && item.eventId === eventId && !before.has(outboxItemKey(item)),
  );
  if (fresh.length === 0) return { ok: false, class: "failed", error: "offline_eval_unproven" };
  if (fresh.length !== 1) return { ok: false, class: "failed", error: "duplicate_outbox_event" };
  const item = fresh[0];
  const payload = item.payload ?? {};
  if (payload.eventId !== eventId) return { ok: false, class: "failed", error: "outbox_event_mismatch" };
  const wantTool = opts.expected?.tool ?? "Read";
  if (payload.tool !== wantTool) return { ok: false, class: "failed", error: "unexpected_tool" };
  if (payload.decision !== "allow" && payload.decision !== "log") {
    return { ok: false, class: "failed", error: "unexpected_decision" };
  }
  if (opts.expected?.policyVersion !== undefined && payload.policyVersion !== opts.expected.policyVersion) {
    return { ok: false, class: "failed", error: "unexpected_policy_version" };
  }
  if (
    Number.isFinite(opts.expected?.sampleStartedAt) &&
    Number.isFinite(item.createdAt) &&
    item.createdAt < opts.expected.sampleStartedAt - 1000
  ) {
    return { ok: false, class: "failed", error: "stale_outbox_event" };
  }
  const grok = opts.hookStatus?.hooks?.grok;
  if (!grok || grok.ok !== true || grok.eventId !== eventId) {
    return { ok: false, class: "failed", error: "hook_status_unproven" };
  }
  return {
    ok: true,
    class: "success",
    eventId,
    decision: payload.decision,
    policyVersion: payload.policyVersion,
    tool: payload.tool,
    hookStatusOk: true,
  };
}

export function summarizeScenario(name, samples, extra = {}) {
  const okSamples = samples.filter((s) => s.ok === true);
  const fallback = samples.filter((s) => s.class === "fallback");
  const failed = samples.filter((s) => s.ok !== true && s.class !== "fallback");
  const rawProtocolMs = okSamples.map((s) => s.protocolMs).filter((n) => Number.isFinite(n));
  const rawExitMs = okSamples.map((s) => s.exitMs).filter((n) => Number.isFinite(n));
  rawProtocolMs.sort((a, b) => a - b);
  rawExitMs.sort((a, b) => a - b);
  const ok = failed.length === 0 && fallback.length === 0 && samples.length > 0 && okSamples.length === samples.length;
  return {
    scenario: name,
    ok,
    n: samples.length,
    nSuccess: okSamples.length,
    nFailed: failed.length,
    nFallback: fallback.length,
    failedErrors: failed.map((s) => s.error).filter(Boolean),
    fallbackErrors: fallback.map((s) => s.error).filter(Boolean),
    rawProtocolMs,
    rawExitMs,
    p50ProtocolMs: rawProtocolMs.length ? percentile(rawProtocolMs, 0.5) : null,
    p95ProtocolMs: rawProtocolMs.length ? percentile(rawProtocolMs, 0.95) : null,
    maxProtocolMs: rawProtocolMs.length ? rawProtocolMs.at(-1) : null,
    p50ExitMs: rawExitMs.length ? percentile(rawExitMs, 0.5) : null,
    p95ExitMs: rawExitMs.length ? percentile(rawExitMs, 0.95) : null,
    maxExitMs: rawExitMs.length ? rawExitMs.at(-1) : null,
    ...extra,
  };
}

export function isolatedChildEnv(home, baseEnv = process.env) {
  const env = { ...baseEnv };
  for (const key of Object.keys(env)) {
    if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|ANTHROPIC_|OPENAI_)/i.test(key)) delete env[key];
    if (key.startsWith("NMZP_") && key !== "NMZP_HOME") delete env[key];
    if (key.startsWith("NODE_TEST_")) delete env[key];
  }
  delete env.NODE_CHANNEL_FD;
  delete env.NODE_TEST_CONTEXT;
  delete env.HTTP_PROXY;
  delete env.HTTPS_PROXY;
  delete env.ALL_PROXY;
  delete env.http_proxy;
  delete env.https_proxy;
  delete env.all_proxy;
  env.NODE_OPTIONS = "";
  env.NMZP_HOME = home;
  env.HOME = home;
  env.USERPROFILE = home;
  env.APPDATA = join(home, "AppData", "Roaming");
  env.LOCALAPPDATA = join(home, "AppData", "Local");
  env.XDG_CONFIG_HOME = join(home, ".config");
  env.XDG_DATA_HOME = join(home, ".local", "share");
  env.XDG_CACHE_HOME = join(home, ".cache");
  const tmp = join(home, "tmp");
  env.TEMP = tmp;
  env.TMP = tmp;
  env.TMPDIR = tmp;
  const parsed = parsePath(home);
  if (parsed.root) {
    env.HOMEDRIVE = parsed.root.slice(0, 2);
    env.HOMEPATH = "\\" + home.slice(parsed.root.length).replace(/\//g, "\\");
  }
  return env;
}

export function scriptSourceSha256(file = thisFile) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

export function sourceMeta() {
  return {
    timestamp: new Date().toISOString(),
    node: process.version,
    os: process.platform,
    arch: process.arch,
    baselineSha: AUTHORIZED_BASELINE_SHA,
    scriptSha256: scriptSourceSha256(),
    checkout: repoRoot,
    priorPacket: "WP-04_EVIDENCE.md provisional superseded",
  };
}

export function unavailableCells(platform = process.platform) {
  const cells = [
    {
      scenario: "reboot-first-sample",
      status: "NOT_RUN",
      reason: "Fresh process is not after-reboot cold. A human must run the supplied instructions after a real reboot.",
    },
    {
      scenario: "HOST_REAL-tool-enforcement",
      status: "NOT_RUN",
      reason: LIMITATION_HOST_REAL,
    },
  ];
  if (platform !== "linux") {
    cells.push({
      scenario: "linux-subprocess-online",
      status: "NOT_RUN",
      reason: `Linux environment absent (platform=${platform}); no fabricated data.`,
    });
    cells.push({
      scenario: "linux-subprocess-offline",
      status: "NOT_RUN",
      reason: `Linux environment absent (platform=${platform}); no fabricated data.`,
    });
  }
  return cells;
}

function emptyFailedScenario(name, error) {
  return summarizeScenario(name, [], { failedErrors: [error], ok: false });
}

export function renderReport(out) {
  const meta = out.meta ?? {};
  const lines = [
    "# WP-04 hook startup baseline",
    "",
    `- timestamp: ${meta.timestamp ?? ""}`,
    `- baselineSha: ${meta.baselineSha ?? ""}`,
    `- scriptSha256: ${meta.scriptSha256 ?? ""}`,
    `- node: ${meta.node ?? ""}`,
    `- os: ${meta.os ?? ""}`,
    `- arch: ${meta.arch ?? ""}`,
    `- checkout: ${meta.checkout ?? ""}`,
    `- priorPacket: ${meta.priorPacket ?? "WP-04_EVIDENCE.md provisional superseded"}`,
    `- ${LIMITATION_FRESH_PROCESS}`,
    `- ${LIMITATION_HOST_REAL}`,
    `- ${LIMITATION_ONLINE_PROOF}`,
    `- ${LIMITATION_OFFLINE_PROOF}`,
    "",
  ];
  const emitScenario = (block, title) => {
    if (!block) return;
    lines.push(`## ${title}`);
    lines.push("");
    lines.push(`- scenario: ${block.scenario ?? block.label ?? title}`);
    lines.push(`- ok: ${block.ok === true ? "true" : "false"}`);
    if (block.mode) lines.push(`- storageMode: ${block.mode}`);
    if (block.label) lines.push(`- label: ${block.label}`);
    if (block.n !== undefined) lines.push(`- n: ${block.n}`);
    if (block.samples !== undefined) lines.push(`- samples: ${block.samples}`);
    if (block.nSuccess !== undefined) lines.push(`- nSuccess: ${block.nSuccess}`);
    if (block.nFailed !== undefined) lines.push(`- nFailed: ${block.nFailed}`);
    if (block.nFallback !== undefined) lines.push(`- nFallback: ${block.nFallback}`);
    if (block.cacheProven !== undefined) lines.push(`- cacheProven: ${block.cacheProven}`);
    if (block.cleanupIncomplete !== undefined) lines.push(`- cleanupIncomplete: ${block.cleanupIncomplete}`);
    if (block.rawMs) lines.push(`- rawMs: ${JSON.stringify(block.rawMs)}`);
    if (block.p50Ms !== undefined) lines.push(`- p50Ms: ${block.p50Ms}`);
    if (block.p95Ms !== undefined) lines.push(`- p95Ms: ${block.p95Ms}`);
    if (block.maxMs !== undefined) lines.push(`- maxMs: ${block.maxMs}`);
    if (block.rawProtocolMs) lines.push(`- rawProtocolMs: ${JSON.stringify(block.rawProtocolMs)}`);
    if (block.p50ProtocolMs !== undefined) lines.push(`- p50ProtocolMs: ${block.p50ProtocolMs}`);
    if (block.p95ProtocolMs !== undefined) lines.push(`- p95ProtocolMs: ${block.p95ProtocolMs}`);
    if (block.maxProtocolMs !== undefined) lines.push(`- maxProtocolMs: ${block.maxProtocolMs}`);
    if (block.rawExitMs) lines.push(`- rawExitMs: ${JSON.stringify(block.rawExitMs)}`);
    if (block.p50ExitMs !== undefined) lines.push(`- p50ExitMs: ${block.p50ExitMs}`);
    if (block.p95ExitMs !== undefined) lines.push(`- p95ExitMs: ${block.p95ExitMs}`);
    if (block.maxExitMs !== undefined) lines.push(`- maxExitMs: ${block.maxExitMs}`);
    if (block.failedErrors?.length) lines.push(`- failedErrors: ${JSON.stringify(block.failedErrors)}`);
    if (block.fallbackErrors?.length) lines.push(`- fallbackErrors: ${JSON.stringify(block.fallbackErrors)}`);
    if (block.limitations) lines.push(`- limitations: ${block.limitations}`);
    lines.push("");
  };
  emitScenario(out.window, MODE_LEGACY + " / window");
  emitScenario(out.sqlite, MODE_LEGACY + " / sqlite");
  emitScenario(out.subprocessOnline, "subprocess-fresh-process-online-loopback");
  emitScenario(out.subprocessOffline, "subprocess-fresh-process-offline-cached-policy");
  if (out.fixtureRemoved !== undefined) {
    lines.push(`- fixtureRemoved: ${out.fixtureRemoved}`);
    lines.push("");
  }
  if (out.cleanupIncomplete !== undefined) {
    lines.push(`- cleanupIncomplete: ${out.cleanupIncomplete}`);
    lines.push("");
  }
  lines.push("## Unavailable cells");
  lines.push("");
  for (const cell of out.notRun ?? []) {
    lines.push(`- scenario: ${cell.scenario}`);
    lines.push(`  status: ${cell.status}`);
    lines.push(`  reason: ${cell.reason}`);
  }
  lines.push("");
  lines.push("## Reboot-first-sample instructions (human only)");
  lines.push("");
  lines.push("This script never reboots the host. After a real OS reboot, before other NMZP processes:");
  lines.push("");
  lines.push("```");
  lines.push("node --experimental-strip-types scripts/bench-hook.mjs --subprocess 1 --timeout-ms 15000");
  lines.push("```");
  lines.push("");
  lines.push("Record only the first sample as reboot-first-sample. Until a human does that, status is NOT_RUN.");
  lines.push("");
  return lines.join("\n");
}

export function ownedClosed(child) {
  return !child || child.exitCode !== null || child.signalCode !== null;
}

export function killOwned(child) {
  if (ownedClosed(child)) return;
  try {
    child.kill();
  } catch {
    /* already gone */
  }
}

function waitOwnedClose(child, waitMs) {
  if (ownedClosed(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.removeListener("close", onClose);
      resolve(ownedClosed(child));
    }, waitMs);
    const onClose = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once("close", onClose);
  });
}

export async function confirmOwnedExit(child, opts = {}) {
  const waitMs = opts.waitMs ?? EXIT_WAIT_MS;
  const escalateWaitMs = opts.escalateWaitMs ?? EXIT_ESCALATE_WAIT_MS;
  const kill = opts.kill ?? killOwned;
  if (ownedClosed(child)) return { exited: true, escalated: false, cleanupIncomplete: false };
  kill(child);
  if (await waitOwnedClose(child, waitMs)) return { exited: true, escalated: false, cleanupIncomplete: false };
  kill(child);
  if (await waitOwnedClose(child, escalateWaitMs)) return { exited: true, escalated: true, cleanupIncomplete: false };
  return { exited: false, escalated: true, cleanupIncomplete: true };
}

export async function collectOwnedSamples(n, runOne) {
  const samples = [];
  let cleanupIncomplete = false;
  for (let i = 0; i < n; i++) {
    const sample = await runOne(i);
    samples.push(sample);
    if (sample?.cleanupIncomplete) {
      cleanupIncomplete = true;
      break;
    }
  }
  return { samples, cleanupIncomplete, abortedRemaining: cleanupIncomplete };
}

export async function spawnHookSample(opts) {
  const {
    entry,
    home,
    env,
    stdin,
    timeoutMs,
    children,
    spawnImpl = spawn,
    kill = killOwned,
    waitMs = EXIT_WAIT_MS,
    escalateWaitMs = EXIT_ESCALATE_WAIT_MS,
  } = opts;
  const start = performance.now();
  let stdout = "";
  let stderr = "";
  let protocolMs;
  const child = spawnImpl(process.execPath, ["--experimental-strip-types", entry, "hook", "--agent", "grok"], {
    env,
    cwd: home,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  children.add(child);
  let timedOut = false;
  const timeout = new Promise((resolve) => {
    const timer = setTimeout(() => {
      timedOut = true;
      resolve("timeout");
    }, timeoutMs);
    child.once("close", () => {
      clearTimeout(timer);
      resolve("close");
    });
    child.once("error", () => {
      clearTimeout(timer);
      resolve("error");
    });
  });
  if (child.stdout) {
    child.stdout.setEncoding?.("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (protocolMs === undefined) protocolMs = performance.now() - start;
    });
    child.stdout.on("end", () => {
      if (protocolMs === undefined) protocolMs = performance.now() - start;
    });
  }
  if (child.stderr) {
    child.stderr.setEncoding?.("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
  }
  let spawnError;
  child.once("error", (err) => {
    spawnError = err;
  });
  let flushed = false;
  const flush = () => {
    if (flushed) return;
    flushed = true;
    try {
      child.stdin.write(stdin);
      child.stdin.end();
    } catch {
      /* close handler records the failure */
    }
  };
  child.once("spawn", flush);
  if (child.pid) flush();
  const reason = await timeout;
  if ((timedOut || reason === "timeout") && !ownedClosed(child)) {
    const confirmation = await confirmOwnedExit(child, { waitMs, escalateWaitMs, kill });
    const exitMs = performance.now() - start;
    if (!confirmation.exited) {
      return {
        ok: false,
        class: "failed",
        error: "cleanup_incomplete",
        cleanupIncomplete: true,
        protocolMs,
        exitMs,
        exitCode: child.exitCode,
        decision: "unexpected",
      };
    }
    children.delete(child);
    return {
      ok: false,
      class: "failed",
      error: "timeout",
      protocolMs,
      exitMs,
      exitCode: child.exitCode,
      decision: "unexpected",
    };
  }
  if (!ownedClosed(child)) {
    const confirmation = await confirmOwnedExit(child, { waitMs, escalateWaitMs, kill });
    if (!confirmation.exited) {
      return {
        ok: false,
        class: "failed",
        error: "cleanup_incomplete",
        cleanupIncomplete: true,
        protocolMs,
        exitMs: performance.now() - start,
        exitCode: child.exitCode,
        decision: "unexpected",
      };
    }
  }
  children.delete(child);
  const exitMs = performance.now() - start;
  if (protocolMs === undefined) protocolMs = exitMs;
  if (spawnError) {
    return {
      ok: false,
      class: "failed",
      error: redact(spawnError.message),
      protocolMs,
      exitMs,
      exitCode: child.exitCode,
      decision: "unexpected",
    };
  }
  const classified = classifyHookOutput(stdout, child.exitCode ?? 1);
  return {
    ok: classified.ok,
    class: classified.ok ? "protocol_allow" : "failed",
    error: classified.ok ? undefined : classified.error,
    decision: classified.decision,
    exitCode: child.exitCode ?? 1,
    protocolMs,
    exitMs,
    stderr: classified.ok ? undefined : redact(stderr).slice(0, 200),
  };
}

async function proveCache(cachePath) {
  if (!existsSync(cachePath)) return null;
  return readPolicyCache(cachePath);
}

export async function readOutboxItems(home) {
  try {
    const raw = await readFile(join(home, ".nmzp", "audit-outbox.json"), "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed?.items) ? parsed.items : [];
  } catch {
    return [];
  }
}

export async function readHookStatusFile(home) {
  try {
    const raw = await readFile(join(home, ".nmzp", "hook-status.json"), "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function requestJson(server, path, body, token) {
  const r = await pinnedHttps({
    url: server.url + path,
    method: body === undefined ? "GET" : "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    caPem: server.tls.certPem,
    fingerprintSha256: server.tls.fingerprintSha256,
    timeoutMs: 5000,
  });
  if (r.status !== 200) throw new Error(`${path} status ${r.status}`);
  return JSON.parse(r.body);
}

async function listStateEvents(server) {
  const state = await requestJson(server, "/api/v1/state", undefined, server.adminToken);
  return Array.isArray(state.events) ? state.events : [];
}

function attachProof(sample, proof) {
  if (proof.ok) {
    return {
      ...sample,
      ok: true,
      class: "success",
      error: undefined,
      proof: { eventId: proof.eventId, decision: proof.decision, enforcement: proof.enforcement, policyVersion: proof.policyVersion, tool: proof.tool, hookStatusOk: proof.hookStatusOk },
    };
  }
  return {
    ...sample,
    ok: false,
    class: proof.class ?? "failed",
    error: proof.error,
  };
}

export async function runLegacy(mode, samples) {
  const root = await mkdtemp(join(tmpdir(), `nmzp-hook-bench-${mode}-`));
  let server;
  const measured = [];
  try {
    server = await startServer({
      dataDir: join(root, "ct"),
      host: "127.0.0.1",
      port: 0,
      coreDir,
      uiDir: null,
      storageMode: mode,
    });
    if (!String(server.url).includes("127.0.0.1")) throw new Error("server is not loopback");
    const ticket = await requestJson(server, "/api/v1/ticket", {}, server.adminToken);
    const joined = await requestJson(
      server,
      "/api/v1/join",
      { ticket: ticket.ticket, hostname: "synthetic", os: "win32", user: "fixture" },
      server.adminToken,
    );
    const home = join(root, "device");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    await writeFile(
      join(home, ".nmzp", "credentials.json"),
      JSON.stringify({
        deviceId: joined.deviceId,
        token: joined.deviceToken,
        url: server.url,
        caPem: server.tls.certPem,
        fingerprintSha256: server.tls.fingerprintSha256,
      }),
    );
    const policy = await requestJson(server, "/api/v1/policy", undefined, joined.deviceToken);
    for (let i = 0; i < samples; i++) {
      const eventId = eventIdFor(i);
      const beforeEvents = await listStateEvents(server);
      const beforeIds = new Set(beforeEvents.map((e) => e.id));
      const start = performance.now();
      let sample;
      try {
        const result = await runHook({
          home,
          coreDir,
          argv: ["--agent", "grok"],
          stdin: syntheticReadPayload(i),
        });
        await settleHookAfterStdout({ home, result });
        const ms = performance.now() - start;
        const classified = classifyHookOutput(result.stdout, result.exitCode);
        sample = {
          ok: classified.ok,
          class: classified.ok ? "protocol_allow" : "failed",
          error: classified.ok ? undefined : classified.error,
          exitMs: ms,
          protocolMs: ms,
          decision: classified.decision,
        };
      } catch (err) {
        sample = {
          ok: false,
          class: "failed",
          error: redact(err instanceof Error ? err.message : String(err)),
          exitMs: performance.now() - start,
          protocolMs: performance.now() - start,
        };
      }
      if (sample.ok) {
        const afterEvents = await listStateEvents(server);
        sample = attachProof(
          sample,
          proveOnlineEvent(eventId, afterEvents, { beforeIds, tool: "Read", policyVersion: policy.version }),
        );
      }
      measured.push(sample);
    }
    const summary = summarizeScenario(`${MODE_LEGACY}/${mode}`, measured, {
      mode,
      label: MODE_LEGACY,
      samples,
      limitations: `${LIMITATION_LEGACY} ${LIMITATION_ONLINE_PROOF} ${LIMITATION_FRESH_PROCESS} ${LIMITATION_HOST_REAL}`,
    });
    const rawMs = summary.rawExitMs;
    return {
      ...summary,
      rawMs,
      p50Ms: summary.p50ExitMs,
      p95Ms: summary.p95ExitMs,
      maxMs: summary.maxExitMs,
    };
  } catch (err) {
    const failed = emptyFailedScenario(`${MODE_LEGACY}/${mode}`, redact(err instanceof Error ? err.message : String(err)));
    return {
      ...failed,
      mode,
      label: MODE_LEGACY,
      samples,
      rawMs: [],
      p50Ms: null,
      p95Ms: null,
      maxMs: null,
      ok: false,
      limitations: `${LIMITATION_LEGACY} ${LIMITATION_FRESH_PROCESS} ${LIMITATION_HOST_REAL}`,
    };
  } finally {
    try {
      await server?.close();
    } catch {
      /* close is best-effort */
    }
    await rm(root, { recursive: true, force: true });
  }
}

export async function runSubprocessScenarios(opts) {
  const samples = opts.samples;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const entry = opts.entry ?? hookEntry;
  const root = await mkdtemp(join(tmpdir(), "nmzp-hook-bench-spawn-"));
  const home = join(root, "device");
  const cachePath = join(home, ".nmzp", "policy-cache.json");
  const children = opts.children ?? new Set();
  let server;
  let result;
  let cleanupIncomplete = false;
  const spawnOpts = {
    spawnImpl: opts.spawnImpl,
    kill: opts.kill,
    waitMs: opts.waitMs ?? EXIT_WAIT_MS,
    escalateWaitMs: opts.escalateWaitMs ?? EXIT_ESCALATE_WAIT_MS,
  };
  const limitationsOnline = `${LIMITATION_FRESH_PROCESS} Loopback own server. ${LIMITATION_EMPTY_ALLOW} ${LIMITATION_ONLINE_PROOF} ${LIMITATION_HOST_REAL}`;
  const limitationsOffline = `${LIMITATION_FRESH_PROCESS} ${LIMITATION_OFFLINE} ${LIMITATION_EMPTY_ALLOW} ${LIMITATION_OFFLINE_PROOF} ${LIMITATION_HOST_REAL}`;
  try {
    await mkdir(join(home, ".nmzp"), { recursive: true });
    await mkdir(join(home, "tmp"), { recursive: true });
    await mkdir(join(home, "AppData", "Roaming"), { recursive: true });
    await mkdir(join(home, "AppData", "Local"), { recursive: true });
    server = await startServer({
      dataDir: join(root, "ct"),
      host: "127.0.0.1",
      port: 0,
      coreDir,
      uiDir: null,
      storageMode: "sqlite",
    });
    if (!String(server.url).includes("127.0.0.1")) throw new Error("server is not loopback");
    const ticket = await requestJson(server, "/api/v1/ticket", {}, server.adminToken);
    const joined = await requestJson(
      server,
      "/api/v1/join",
      { ticket: ticket.ticket, hostname: "synthetic", os: "win32", user: "fixture" },
      server.adminToken,
    );
    await writeFile(
      join(home, ".nmzp", "credentials.json"),
      JSON.stringify({
        deviceId: joined.deviceId,
        token: joined.deviceToken,
        url: server.url,
        caPem: server.tls.certPem,
        fingerprintSha256: server.tls.fingerprintSha256,
      }),
    );
    const policy = await requestJson(server, "/api/v1/policy", undefined, joined.deviceToken);
    await writePolicyCache(cachePath, {
      version: policy.version,
      mode: policy.mode,
      stopped: !!policy.stopped,
      customRules: Array.isArray(policy.customRules) ? policy.customRules : [],
      archiveUpload: policy.archiveUpload,
      githubUpload: policy.githubUpload,
      overrides: policy.overrides,
      exemptions: policy.exemptions,
      updatedAt: Date.now(),
    });
    const seeded = await proveCache(cachePath);
    if (!seeded) throw new Error("policy cache missing after API seed");
    const env = isolatedChildEnv(home);
    if (env.NMZP_HOME !== home) throw new Error("NMZP_HOME was not isolated");
    if (env.USERPROFILE === homedir()) throw new Error("USERPROFILE was not isolated");
    const onlineCollected = await collectOwnedSamples(samples, async (i) => {
      const eventId = eventIdFor(i, "wp04-on");
      const beforeEvents = await listStateEvents(server);
      const beforeIds = new Set(beforeEvents.map((e) => e.id));
      const hooked = await spawnHookSample({
        entry,
        home,
        env,
        stdin: syntheticReadPayload(i, "wp04-on"),
        timeoutMs,
        children,
        ...spawnOpts,
      });
      if (hooked.cleanupIncomplete) return hooked;
      if (!hooked.ok) return hooked;
      const afterEvents = await listStateEvents(server);
      return attachProof(hooked, proveOnlineEvent(eventId, afterEvents, { beforeIds, tool: "Read", policyVersion: policy.version }));
    });
    cleanupIncomplete = onlineCollected.cleanupIncomplete;
    const online = summarizeScenario("subprocess-fresh-process-online-loopback", onlineCollected.samples, {
      cacheProvenBefore: true,
      network: "127.0.0.1",
      cleanupIncomplete,
      limitations: limitationsOnline,
    });
    if (cleanupIncomplete) {
      result = {
        online,
        offline: {
          ...emptyFailedScenario("subprocess-fresh-process-offline-cached-policy", "not_run_after_cleanup_incomplete"),
          cacheProven: false,
          limitations: limitationsOffline,
        },
        cleanupIncomplete: true,
      };
      return result;
    }
    await server.close();
    server = undefined;
    const cacheAfterClose = await proveCache(cachePath);
    const cacheProven = !!cacheAfterClose;
    let offlineCollected = { samples: [], cleanupIncomplete: false };
    if (cacheProven) {
      offlineCollected = await collectOwnedSamples(samples, async (i) => {
        const eventId = eventIdFor(i, "wp04-off");
        const beforeItems = await readOutboxItems(home);
        const sampleStartedAt = Date.now();
        const hooked = await spawnHookSample({
          entry,
          home,
          env,
          stdin: syntheticReadPayload(i, "wp04-off"),
          timeoutMs,
          children,
          ...spawnOpts,
        });
        if (hooked.cleanupIncomplete) return hooked;
        if (!hooked.ok) return hooked;
        const afterItems = await readOutboxItems(home);
        const hookStatus = await readHookStatusFile(home);
        return attachProof(
          hooked,
          proveOfflineOutbox({
            eventId,
            beforeItems,
            afterItems,
            hookStatus,
            expected: { tool: "Read", policyVersion: policy.version, sampleStartedAt },
          }),
        );
      });
      cleanupIncomplete = offlineCollected.cleanupIncomplete;
    }
    const offline = summarizeScenario("subprocess-fresh-process-offline-cached-policy", offlineCollected.samples, {
      cacheProven,
      network: "server-closed",
      cleanupIncomplete,
      limitations: limitationsOffline,
    });
    if (!cacheProven) {
      offline.ok = false;
      offline.failedErrors = ["policy_cache_missing_after_server_close"];
    }
    result = { online, offline, cleanupIncomplete };
  } catch (err) {
    result = {
      online: {
        ...emptyFailedScenario(
          "subprocess-fresh-process-online-loopback",
          redact(err instanceof Error ? err.message : String(err)),
        ),
        limitations: limitationsOnline,
      },
      offline: {
        ...emptyFailedScenario("subprocess-fresh-process-offline-cached-policy", "not_run_after_setup_failure"),
        cacheProven: false,
        limitations: limitationsOffline,
      },
      cleanupIncomplete,
    };
  } finally {
    if (cleanupIncomplete) {
      for (const child of children) killOwned(child);
      try {
        await server?.close();
      } catch {
        /* close is best-effort */
      }
      if (!result) {
        result = {
          online: emptyFailedScenario("subprocess-fresh-process-online-loopback", "cleanup_incomplete"),
          offline: emptyFailedScenario("subprocess-fresh-process-offline-cached-policy", "cleanup_incomplete"),
        };
      }
      result.cleanupIncomplete = true;
      result.fixtureRemoved = false;
      result.fixturePreserved = true;
    } else {
      for (const child of children) {
        const confirmation = await confirmOwnedExit(child, {
          waitMs: spawnOpts.waitMs,
          escalateWaitMs: spawnOpts.escalateWaitMs,
          kill: spawnOpts.kill ?? killOwned,
        });
        if (!confirmation.exited) cleanupIncomplete = true;
      }
      try {
        await server?.close();
      } catch {
        /* close is best-effort */
      }
      if (cleanupIncomplete) {
        if (!result) {
          result = {
            online: emptyFailedScenario("subprocess-fresh-process-online-loopback", "cleanup_incomplete"),
            offline: emptyFailedScenario("subprocess-fresh-process-offline-cached-policy", "cleanup_incomplete"),
          };
        }
        result.cleanupIncomplete = true;
        result.fixtureRemoved = false;
        result.fixturePreserved = true;
      } else {
        await rm(root, { recursive: true, force: true });
        let fixtureRemoved = !existsSync(root);
        if (!fixtureRemoved) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          await rm(root, { recursive: true, force: true });
          fixtureRemoved = !existsSync(root);
        }
        if (!result) {
          result = {
            online: emptyFailedScenario("subprocess-fresh-process-online-loopback", "setup_aborted"),
            offline: emptyFailedScenario("subprocess-fresh-process-offline-cached-policy", "setup_aborted"),
          };
        }
        result.fixtureRemoved = fixtureRemoved;
        result.cleanupIncomplete = false;
      }
    }
  }
  return result;
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseBenchArgs(argv);
  if (args.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const out = { meta: sourceMeta(), notRun: unavailableCells() };
  let anyFail = false;
  if (args.mode === MODE_LEGACY || args.mode === MODE_ALL) {
    out.window = await runLegacy("window", args.samples);
    out.sqlite = await runLegacy("sqlite", args.samples);
    if (!out.window.ok || !out.sqlite.ok) anyFail = true;
  }
  if (args.mode === MODE_SUBPROCESS || args.mode === MODE_ALL) {
    const spawned = await runSubprocessScenarios({
      samples: args.samples,
      timeoutMs: args.timeoutMs,
      entry: hookEntry,
    });
    out.subprocessOnline = spawned.online;
    out.subprocessOffline = spawned.offline;
    out.fixtureRemoved = spawned.fixtureRemoved === true;
    out.cleanupIncomplete = spawned.cleanupIncomplete === true;
    if (!spawned.online.ok || !spawned.offline.ok || spawned.cleanupIncomplete) anyFail = true;
  }
  const reportPath = args.reportPath ?? join(repoRoot, "bench", "REPORT.md");
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, renderReport(out));
  out.reportPath = reportPath;
  process.stdout.write(`${JSON.stringify(out)}\n`);
  return anyFail ? 1 : 0;
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
  try {
    process.exit(await main());
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  }
}
