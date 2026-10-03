import { AsyncLocalStorage } from "node:async_hooks";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test as defineTest } from "node:test";
import { fileURLToPath } from "node:url";
import { expectedDigest } from "./spec-run.mjs";
import {
  BOOTSTRAP_BUNDLE_ANCHOR,
  BOOTSTRAP_CASE_COUNT,
  BOOTSTRAP_COMMIT,
  BOOTSTRAP_ENGINE_REVISION,
  BOOTSTRAP_EXPECTED_DIGEST,
  BOOTSTRAP_METADATA,
  bundleAnchor,
  digestExpected,
  parseIntendedChanges,
} from "./policy-compat-guard.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Admission fixtures read this commit, not the worktree. The worktree may move
// ENGINE_REVISION and the corpus digest after the admission was pinned.
const ADMISSION_COMMIT = "6e0c1b565297432dfb94c59d450dd4dbd2d70fe1";
let admissionRoot = "";
const CASE_FILES = ["input.json", "policy.json", "context.json", "expected.json"];
const MINI_ID = "normal/alpha";
const MINI_EXPECTED = Buffer.from('{"compare":{"decision":"log"}}\n');
const MINI_INPUT = Buffer.from('{"command":"true"}\n');
const MINI_POLICY = Buffer.from("{}\n");
const MINI_CONTEXT = Buffer.from("{}\n");
const MINI_DIGEST = digestExpected([{ id: MINI_ID, bytes: MINI_EXPECTED }]);
const ZERO_SHA = "0".repeat(40);
const ANCHOR_A = "a".repeat(64);
const ANCHOR_B = "b".repeat(64);
const ANCHOR_C = "c".repeat(64);
const COMPACT_CASE_COUNT = 10;
const COMPACT_EXPECTED_DIGEST = "c90f95d800ab2edebc87842c0ae11a5f912b5c6a8784e59628305b7d10864416";
const COMPACT_BUNDLE_ANCHOR = "320eccbe86441e4a6263bf2fff2ebbd55097859a9a8d642553915f5e93cfa878";
const ADDITION_CASE_ID = "privacy/area-extension/02";
const ADDITION_CASE_COUNT = 11;
const ADDITION_EXPECTED_DIGEST = "5a2700b1534176d2106e99d0b50ea0585748ee116f8fea2d4951ce78e9447b4e";
const ADDITION_BUNDLE_ANCHOR = "7986d24f5a0a4e7a83e6b5778ca10ebf32aa9fec2cf25b6b501f9ba08057ebcd";
const UNCHANGED_TARGET_ID = "risky/a1-archive-upload";
const COMPACT_CASE_IDS = [
  "boundaries/a1-off",
  "exemptions/delete-active",
  "historical/echo-dd-text",
  "host-normalization/antigravity",
  "normal/ls",
  "privacy/area-extension/01",
  "proposal/custom-block",
  "protected/agent_hook_disable/disable",
  "rewrite/persona-cloak",
  "risky/a1-archive-upload",
];
const COMPACT_SOURCE_HASHES = {
  "boundaries/a1-off/context.json": "2aff4a56690c5ac1b0c7476837144b466b2ee7c6a81a2132a96f613a893911e0",
  "boundaries/a1-off/expected.json": "4d41f8bd9fb65f83ed4854dd3eaa931eafa44b2ecb41893a6ded2dbd992dc6ec",
  "boundaries/a1-off/input.json": "6c26d2ed7450e646c5fc5c7dc44ed1165301d9993af1324a452123afc2d68a72",
  "boundaries/a1-off/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "exemptions/delete-active/context.json": "521bbc81c94fa2a092f07634ea8a93ea0dc6fa6e4b2942803ee86b4f1eea735d",
  "exemptions/delete-active/expected.json": "2c04aec286d6d8403e8302ba76d2641637d122641fba485c1a4e3e6c94eeeb3c",
  "exemptions/delete-active/input.json": "cf63c1c870f0a3440b58f93cc6b45a4eaf5f4dc1b2c4c76bb6dc0b2b75bda43c",
  "exemptions/delete-active/policy.json": "79796e75c16ab52d1c110dd15473c65aa0e16b394a4afc64119e4f77ab2c13b3",
  "historical/echo-dd-text/context.json": "a18d1e5838684df50b69a7ce410118f9ada22f90b54820fcaeef7c17b0cf7648",
  "historical/echo-dd-text/expected.json": "790b142ac3cdf9e3b2346f7ed891ef0baa06193fe0592c0d2a0723e222f7feef",
  "historical/echo-dd-text/input.json": "d5305d8c7d344350fb15841d6f5d95a7c5a466af340bf855493308bc76336223",
  "historical/echo-dd-text/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "host-normalization/antigravity/context.json": "af0584635b6415ad7054d76ef0b9199840260de88257da2c4fa9168ad10128c4",
  "host-normalization/antigravity/expected.json": "eb09a63708de0ae127e24ae30b4ff1d7f05a1c7c55d0a9fb87954b885cb9066a",
  "host-normalization/antigravity/input.json": "473cb95716b273c06565a11a1db8c002883a289d57eab46f697a3e8810a26a93",
  "host-normalization/antigravity/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "normal/ls/context.json": "f270220333187cc5d4ead371644f07cab3f2e070c240ecbf221e30a64461b953",
  "normal/ls/expected.json": "564b647082c3ce7b6cbd6dc6f7ed8ce1d074c652b1999e3f1edf7397d092cd9d",
  "normal/ls/input.json": "af625dab75408dc9d801522e16d90f2185326a5b327942069e1e56ba2455dbc6",
  "normal/ls/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "privacy/area-extension/01/context.json": "772d669e9ca12aef93ba21c993036b57c451224b2c64c39d695ae9092220e382",
  "privacy/area-extension/01/expected.json": "9b06ba61daf48e5ca38fb1d92de8b563102ba9b6f0710f94cfc534416d9d6d35",
  "privacy/area-extension/01/input.json": "85dfe7e7bb1677abcc47b371cb70a1e6e3e6e9a6c6d85290e0ea4ca3d61fe991",
  "privacy/area-extension/01/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "proposal/custom-block/context.json": "435c751890d39c9742bcd95bb3a52fadd1a918e21345dee64f293ea4b8eb66ba",
  "proposal/custom-block/expected.json": "ff44a7b31ac952bd97cbbecba553891285ebd7b98b9bf129e300716463df735b",
  "proposal/custom-block/input.json": "9690a521e723efc18c46a6899635ef5242393b8f5f43c1da97691f999a510cee",
  "proposal/custom-block/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "protected/agent_hook_disable/disable/context.json": "753c20b6acdd7e1d0e99cf68121c00cebb689b4cc9a6ac1dd1f37fae4989085c",
  "protected/agent_hook_disable/disable/expected.json": "ee2e72dc70cd501b535f235c9cb407052c6b03503ff22d9fbc35b84158092bea",
  "protected/agent_hook_disable/disable/input.json": "5fc2f09d44b5ce92f4d7c868c8e080ced29827fe56ecd8cb6e2b5799d844279f",
  "protected/agent_hook_disable/disable/policy.json": "080ed9116ecf55904e4e5e269b1245c305792e6011a397cf8fa5590257b2b4d6",
  "rewrite/persona-cloak/context.json": "c30480c0fc7ec03d543349ee924704fc30394290f3e6f900cf9f4e83ce9ac412",
  "rewrite/persona-cloak/expected.json": "32124b9b7373f3e8594b867287bcf430f5777ce77b8a9eea3e9f7dd787cb6aff",
  "rewrite/persona-cloak/input.json": "cff360c2d9fff91636f4241e16ea3044fa5e3e5e1e82b720261fd04efc779b65",
  "rewrite/persona-cloak/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
  "risky/a1-archive-upload/context.json": "8bf001aeee43b7f906d377177b6b46f5bd5931004384612f23333b5d37b72826",
  "risky/a1-archive-upload/expected.json": "386ca980382e73ba4ecb74a1728e218ab9d581dae8152b65588ca7ad8becf023",
  "risky/a1-archive-upload/input.json": "6c26d2ed7450e646c5fc5c7dc44ed1165301d9993af1324a452123afc2d68a72",
  "risky/a1-archive-upload/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
};
const ADDITION_SOURCE_HASHES = {
  "privacy/area-extension/02/context.json": "772d669e9ca12aef93ba21c993036b57c451224b2c64c39d695ae9092220e382",
  "privacy/area-extension/02/expected.json": "578e05b6c44defe05bd65e2e18acba0e7d9fd055e1ef066a86c7c0ba1a2f1bbc",
  "privacy/area-extension/02/input.json": "a1af83c22ba7a0a90471c143e8b8ac570712e40b6934e1d4b455f8cb28c91944",
  "privacy/area-extension/02/policy.json": "2d1e578ea7f429f5329a11bc9628c9ba56b6cc6f1c480ac01222e3dd5f431861",
};
const keep = [];
const phaseTiming = {};
let lightTemplate;
let heavyTemplate;
let historyTemplate;
let compactProposedText = "";
let emptyTemplate;
let emptyHooks;
let seals = [];
let gitSnapshots = [];
let p0Head = "";
const headOf = new Map();

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function cancelledWork() {
  const error = new Error("work cancelled");
  error.code = "ABORT_ERR";
  return error;
}

function createLimiter(max) {
  let active = 0;
  const queue = [];
  function rejectQueued() {
    const dropped = queue.splice(0);
    for (const item of dropped) item.reject(cancelledWork());
  }
  function pump() {
    if (cleanupStarted) {
      rejectQueued();
      return;
    }
    while (active < max && queue.length > 0) {
      active += 1;
      const { fn, resolve, reject } = queue.shift();
      Promise.resolve()
        .then(() => {
          if (cleanupStarted) throw cancelledWork();
          return fn();
        })
        .then(resolve, reject)
        .finally(() => {
          active -= 1;
          pump();
        });
    }
  }
  const limit = (fn) =>
    new Promise((resolve, reject) => {
      if (cleanupStarted) {
        reject(cancelledWork());
        return;
      }
      queue.push({ fn, resolve, reject });
      pump();
    });
  limit.cancelQueued = rejectQueued;
  return limit;
}

const linkLimit = createLimiter(256);
const copyLimit = createLimiter(64);
const testSignals = new AsyncLocalStorage();
const owned = new Set();
const tasks = new Set();
let cleanupStarted = false;
let cancelTrace = null;
const DRAIN_DEADLINE_MS = 5_000;
const PROBE_DRAIN_DEADLINE_MS = 800;
const CANCEL_PROBE_TIMEOUT_MS = 1_500;
const CANCEL_PROBE_READY_MARGIN_MS = 250;
const CANCEL_PROBE_AFTER_TIMEOUT_MS = 500;
const CANCEL_PROBE_SLOW_GAP_MS = 800;

function drainDeadlineMs() {
  // The suite budget stays DRAIN_DEADLINE_MS. Only the deadline probe uses a shorter wait.
  if (process.env.NMZP_GUARD_CANCEL_PROBE === "deadline") return PROBE_DRAIN_DEADLINE_MS;
  return DRAIN_DEADLINE_MS;
}

function beginWork() {
  if (cleanupStarted) throw cancelledWork();
}

function traceCancel(event) {
  if (cancelTrace) cancelTrace(`${Date.now()} ${event}`);
}

function installCancelTrace() {
  const marker = process.env.NMZP_GUARD_CANCEL_MARKER;
  if (!marker) return;
  cancelTrace = (line) => {
    fs.appendFileSync(marker, `${line}\n`);
  };
}

function trackTask(promise) {
  const settled = Promise.resolve(promise).finally(() => {
    tasks.delete(settled);
  });
  tasks.add(settled);
  return settled;
}

async function allJoined(promises) {
  let firstError;
  const jobs = promises.map((promise) =>
    trackTask(promise).then(
      (value) => value,
      (error) => {
        if (firstError === undefined) firstError = error;
        throw error;
      },
    ),
  );
  const settled = await Promise.allSettled(jobs);
  if (firstError !== undefined) throw firstError;
  return settled.map((item) => item.value);
}

function test(name, options, fn) {
  if (typeof options === "function") {
    fn = options;
    options = {};
  }
  return defineTest(name, options, (t) => {
    let body;
    try {
      body = testSignals.run(t.signal, () => fn(t));
    } catch (error) {
      body = Promise.reject(error);
    }
    const tracked = trackTask(body);
    tracked.catch(() => {});
    return tracked;
  });
}

function cancelledSpawn(code, message) {
  const error = new Error(message);
  error.code = code;
  return {
    status: null,
    signal: null,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    error,
    pid: undefined,
  };
}

// Guard runs a revision probe as its own child. Killing only the direct pid leaves that grandchild.
function killTree(child) {
  if (!child?.pid || child.exitCode !== null) return;
  if (process.platform === "win32") {
    const killer = spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
    const killDirect = () => {
      try {
        child.kill();
      } catch {
        /* already gone */
      }
    };
    killer.on("error", killDirect);
    killer.on("exit", (code) => {
      if (code !== 0) killDirect();
    });
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }
}

// A timed-out test can resume after after() starts. Drain that task and any
// parallel file work first, and clear the deadline timer when the queue is idle.
function drainOwned() {
  cleanupStarted = true;
  linkLimit.cancelQueued();
  const children = [...owned];
  for (const job of children) job.stop("abort");
  const deadline = Date.now() + drainDeadlineMs();
  const pending = () => [
    ...children.filter((job) => !job.finished).map((job) => job.done),
    ...tasks,
  ];
  if (pending().length === 0) return Promise.resolve();
  let timer;
  const settle = (promise) => Promise.resolve(promise).then(() => {}, () => {});
  const timedOut = () => {
    const error = new Error("owned work still running at drain deadline");
    error.code = "ERR_DRAIN_TIMEOUT";
    return error;
  };
  const wait = async () => {
    try {
      while (pending().length > 0) {
        const left = deadline - Date.now();
        if (left <= 0) throw timedOut();
        const batch = pending();
        let expired = false;
        await Promise.race([
          Promise.all(batch.map(settle)),
          new Promise((resolve) => {
            timer = setTimeout(() => {
              expired = true;
              resolve();
            }, left);
          }),
        ]);
        clearTimeout(timer);
        timer = undefined;
        if (expired && pending().length > 0) throw timedOut();
      }
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  return wait();
}

function spawnCollected(command, args, { cwd, env, input, timeout, maxBuffer, signal }) {
  const cancelSignal = signal ?? testSignals.getStore();
  if (cancelSignal?.aborted || (cleanupStarted && cancelSignal)) {
    return Promise.resolve(cancelledSpawn("ABORT_ERR", "spawn cancelled"));
  }
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let settled = false;
    let stopReason = null;
    let timer;
    const job = { stop: null, done: null, resolveDone: null, finished: false };
    job.done = new Promise((resolveDone) => {
      job.resolveDone = resolveDone;
    });
    const stop = (reason) => {
      if (stopReason || settled) return;
      stopReason = reason;
      if (timer) clearTimeout(timer);
      killTree(child);
    };
    job.stop = stop;
    owned.add(job);
    if (child.pid) traceCancel(`child-pid:${child.pid}`);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (cancelSignal) cancelSignal.removeEventListener("abort", onAbort);
      owned.delete(job);
      job.finished = true;
      if (stopReason === "abort") traceCancel("child-exit");
      job.resolveDone();
      resolve(result);
    };
    const onAbort = () => stop("abort");
    timer = setTimeout(() => stop("timeout"), timeout);
    if (cancelSignal) {
      if (cancelSignal.aborted) stop("abort");
      else cancelSignal.addEventListener("abort", onAbort, { once: true });
    }
    const take = (which) => (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (which === "out") {
        stdoutLen += buf.length;
        stdoutChunks.push(buf);
        if (stdoutLen > maxBuffer) stop("overflow");
      } else {
        stderrLen += buf.length;
        stderrChunks.push(buf);
        if (stderrLen > maxBuffer) stop("overflow");
      }
    };
    child.stdout.on("data", take("out"));
    child.stderr.on("data", take("err"));
    child.stdin.on("error", () => {});
    child.on("error", (error) => {
      if (stopReason) return;
      finish({
        status: null,
        signal: null,
        stdout: Buffer.concat(stdoutChunks),
        stderr: Buffer.concat(stderrChunks),
        error,
        pid: child.pid,
      });
    });
    child.on("close", (status, closeSignal) => {
      const stdout = Buffer.concat(stdoutChunks);
      const stderr = Buffer.concat(stderrChunks);
      let error;
      if (stopReason === "timeout") {
        error = new Error(`spawn timed out after ${timeout}ms`);
        error.code = "ETIMEDOUT";
      } else if (stopReason === "abort") {
        error = new Error("spawn cancelled");
        error.code = "ABORT_ERR";
      } else if (stopReason === "overflow") {
        error = new Error("spawn output exceeded maxBuffer");
        error.code = "ENOBUFS";
      }
      finish({ status, signal: closeSignal, stdout, stderr, error, pid: child.pid });
    });
    if (input == null) child.stdin.end();
    else child.stdin.end(input);
  });
}

function gitEnv() {
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: emptyGitConfigPath(),
    GIT_CONFIG_SYSTEM: emptyGitConfigPath(),
    GIT_TERMINAL_PROMPT: "0",
    GIT_ALLOW_PROTOCOL: "file",
    GIT_AUTHOR_NAME: "guard",
    GIT_AUTHOR_EMAIL: "guard@example.com",
    GIT_COMMITTER_NAME: "guard",
    GIT_COMMITTER_EMAIL: "guard@example.com",
  };
}

let emptyGitConfig = "";
let compileCache = "";

function emptyGitConfigPath() {
  if (!emptyGitConfig) throw new Error("git config sandbox is not ready");
  return emptyGitConfig;
}

async function gitRaw(cwd, args, input) {
  if (!emptyHooks) throw new Error("git hooks sandbox is not ready");
  const result = await spawnCollected(
    "git",
    [
      "--no-optional-locks",
      "-c",
      "core.autocrlf=false",
      "-c",
      "maintenance.auto=false",
      "-c",
      "gc.auto=0",
      "-c",
      `core.hooksPath=${emptyHooks.replaceAll("\\", "/")}`,
      "-C",
      cwd,
      ...args,
    ],
    {
      cwd,
      env: gitEnv(),
      input,
      timeout: 60_000,
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (result.error || result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed: ${result.stderr.toString("utf8") || result.error?.message || result.status}`,
    );
  }
  return result.stdout;
}

async function git(cwd, args, input) {
  return (await gitRaw(cwd, args, input)).toString("utf8").trim();
}

function parseFixtureRevision(text) {
  const matches = [...text.matchAll(/^export const ENGINE_REVISION = (\d+);[ \t]*$/gm)];
  if (matches.length !== 1) throw new Error(`expected one ENGINE_REVISION export, found ${matches.length}`);
  const raw = matches[0][1];
  if (!/^(0|[1-9]\d*)$/.test(raw)) throw new Error(`ENGINE_REVISION ${raw} is not canonical`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw new Error(`ENGINE_REVISION ${raw} is not a safe integer`);
  return value;
}

async function extractAdmissionTree() {
  beginWork();
  const parent = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-admit-"));
  keep.push(parent);
  const dir = path.join(parent, "tree");
  await fsp.mkdir(dir);
  const tar = await gitRaw(root, [
    "archive",
    "--format=tar",
    ADMISSION_COMMIT,
    "policy-spec",
    "core",
    "src",
    "INTENDED_CHANGES.md",
  ]);
  const tarPath = path.join(parent, "admission.tar");
  await fsp.writeFile(tarPath, tar);
  // Windows bsdtar treats "C:" as a remote host. Stay on relative names;
  // older runner bsdtar builds reject --force-local, so do not pass it.
  const extracted = await spawnCollected("tar", ["-xf", "admission.tar", "-C", "tree"], {
    cwd: parent,
    timeout: 60_000,
    maxBuffer: 1024 * 1024,
  });
  if (extracted.error || extracted.status !== 0) {
    throw new Error(
      `tar extract failed: ${extracted.stderr.toString("utf8") || extracted.error?.message || extracted.status}`,
    );
  }
  await fsp.rm(tarPath, { force: true });
  const revisionText = await fsp.readFile(path.join(dir, "core", "policy", "engine-revision.ts"), "utf8");
  if (parseFixtureRevision(revisionText) !== BOOTSTRAP_ENGINE_REVISION) {
    throw new Error(`admission commit ENGINE_REVISION is not ${BOOTSTRAP_ENGINE_REVISION}`);
  }
  admissionRoot = dir;
}

function emptyBlock() {
  return "# fixture\n\n```policy-compat-v1\n```\n";
}

function entry(spec) {
  for (const key of ["oldBundleAnchor", "newBundleAnchor"]) {
    if (typeof spec[key] !== "string" || !/^[0-9a-f]{64}$/.test(spec[key])) {
      throw new Error(`entry requires ${key}`);
    }
  }
  return [
    "entry",
    `oldDigest=${spec.oldDigest}`,
    `newDigest=${spec.newDigest}`,
    `oldRevision=${spec.oldRevision}`,
    `newRevision=${spec.newRevision}`,
    `oldBundleAnchor=${spec.oldBundleAnchor}`,
    `newBundleAnchor=${spec.newBundleAnchor}`,
    `reason=${spec.reason}`,
    ...(spec.cases ?? []).map((id) => `case=${id}`),
  ].join("\n");
}

function miniBundleAnchor(input = MINI_INPUT) {
  return bundleAnchor([
    { path: `${MINI_ID}/context.json`, bytes: MINI_CONTEXT },
    { path: `${MINI_ID}/expected.json`, bytes: MINI_EXPECTED },
    { path: `${MINI_ID}/input.json`, bytes: input },
    { path: `${MINI_ID}/policy.json`, bytes: MINI_POLICY },
  ]);
}

function removeSingleHashBinding(text) {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  const field = /^[ \t]*engineRevision:[ \t]*ENGINE_REVISION,[ \t]*$/;
  const indexes = lines.flatMap((line, index) => (field.test(line) ? [index] : []));
  if (indexes.length !== 1) return { ok: false, count: indexes.length, text, removed: "" };
  const removed = lines[indexes[0]];
  const nextLines = lines.filter((_line, index) => index !== indexes[0]);
  const next = nextLines.join(eol);
  const still = nextLines.filter((line) => field.test(line)).length;
  if (still !== 0 || next === text) return { ok: false, count: indexes.length, text: next, removed };
  return { ok: true, count: 1, text: next, removed };
}

function block(entries) {
  const body = entries.length === 0 ? "" : `${entries.join("\n\n")}\n`;
  return `# fixture\n\n\`\`\`policy-compat-v1\n${body}\`\`\`\n`;
}

function guardEnv(extra = {}) {
  const env = { ...process.env, FORCE_COLOR: "0" };
  if (compileCache) env.NODE_COMPILE_CACHE = compileCache;
  for (const key of ["GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_SHA"]) delete env[key];
  return { ...env, ...extra };
}

async function runCli(cwd, args = [], env = {}, script = path.join(cwd, "scripts", "policy-compat-guard.mjs")) {
  const result = await spawnCollected(process.execPath, ["--experimental-strip-types", script, ...args], {
    cwd,
    env: guardEnv(env),
    timeout: 90_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  const stdout = result.stdout.toString("utf8");
  const stderr = result.stderr.toString("utf8");
  let parsed = null;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    parsed = null;
  }
  return {
    status: result.status,
    signal: result.signal,
    stdout,
    stderr,
    parsed,
    error: result.error,
  };
}

// Hardlinked clone paths share the template inode. Unlink the clone path first
// so a later write cannot truncate the template or the P0 tree it was copied from.
async function writeNewFile(file, data) {
  beginWork();
  await fsp.writeFile(file, data);
}

async function replaceFile(file, data) {
  beginWork();
  await fsp.rm(file, { force: true });
  await writeNewFile(file, data);
}

function assertRejected(run, stage, code) {
  assert.equal(run.error, undefined, run.error?.message || "spawn failed");
  assert.equal(run.status, 1, `${run.stderr}\n${run.stdout}`);
  assert.ok(run.parsed, run.stdout || run.stderr);
  assert.equal(run.parsed.ok, false);
  assert.equal(run.parsed.stage, stage, JSON.stringify(run.parsed));
  assert.equal(run.parsed.code, code, JSON.stringify(run.parsed));
  assert.equal(run.parsed.corpusRan, false);
  for (const banned of ["import_error", "probe_timeout", "unexpected"]) {
    assert.notEqual(run.parsed.code, banned);
  }
}

function junctionType() {
  return process.platform === "win32" ? "junction" : "dir";
}

// A directory symlink is a git file. Trailing-slash rules such as `src/` do not match it.
const FIXTURE_GITIGNORE = "/node_modules\n/src\n/.empty-hooks\n";

async function windowsShortDirectory(dir) {
  const command = `(New-Object -ComObject Scripting.FileSystemObject).GetFolder(${JSON.stringify(dir)}).ShortPath`;
  const result = await spawnCollected(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", command],
    { timeout: 30_000, maxBuffer: 1024 * 1024 },
  );
  const stderr = result.stderr.toString("utf8").trim();
  if (result.error || result.status !== 0) {
    return {
      ok: false,
      reason: `8.3 short name unavailable: ${stderr || result.error?.message || `powershell exit ${result.status}`}`,
    };
  }
  const short = result.stdout.toString("utf8").replace(/^\uFEFF/, "").trim().split(/\r?\n/).filter(Boolean).at(-1) ?? "";
  if (!short) return { ok: false, reason: "8.3 short name unavailable: ShortPath was empty" };
  const folded = (value) => path.normalize(value).replaceAll("/", "\\").toLowerCase();
  if (folded(short) === folded(dir)) {
    return { ok: false, reason: "8.3 short name unavailable: ShortPath equals the long path" };
  }
  let shortReal;
  let dirReal;
  try {
    shortReal = fs.realpathSync.native(short);
    dirReal = fs.realpathSync.native(dir);
  } catch (error) {
    return { ok: false, reason: `8.3 short name unavailable: ${error.message}` };
  }
  if (folded(shortReal) !== folded(dirReal)) {
    return { ok: false, reason: `8.3 short name unavailable: ShortPath resolves to ${shortReal}` };
  }
  return { ok: true, short };
}

async function linkNodeModules(dir) {
  beginWork();
  await fsp.symlink(path.join(root, "node_modules"), path.join(dir, "node_modules"), junctionType());
}

async function linkDeps(dir, template = null) {
  await linkNodeModules(dir);
  beginWork();
  let target = path.join(root, "src");
  if (template) {
    const candidate = path.join(template, "src");
    try {
      const st = await fsp.lstat(candidate);
      if (st.isSymbolicLink() || st.isDirectory()) target = candidate;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  await fsp.symlink(target, path.join(dir, "src"), junctionType());
}

async function writeRepoConfig(dir) {
  beginWork();
  await fsp.appendFile(
    path.join(dir, ".git", "config"),
    [
      "",
      "[core]",
      "\thooksPath = .empty-hooks",
      "\tautocrlf = false",
      "\tfsync = none",
      "[commit]",
      "\tgpgsign = false",
      "[user]",
      "\temail = guard@example.com",
      "\tname = guard",
      "[maintenance]",
      "\tauto = false",
      "[gc]",
      "\tauto = 0",
      "",
    ].join("\n"),
  );
}

async function initRepo(dir) {
  beginWork();
  await fsp.mkdir(path.join(dir, ".empty-hooks"), { recursive: true });
  await git(dir, ["init", "-q", "-b", "guard", "--template", emptyTemplate]);
  await writeRepoConfig(dir);
}

async function listWorktreeFiles(dir) {
  const rels = [];
  async function walk(current) {
    const entries = await fsp.readdir(current, { withFileTypes: true });
    const nested = [];
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === ".empty-hooks") continue;
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`unexpected symlink in template: ${full}`);
      if (entry.isDirectory()) nested.push(walk(full));
      else rels.push(path.relative(dir, full).split(path.sep).join("/"));
    }
    await allJoined(nested);
  }
  await walk(dir);
  rels.sort();
  for (const rel of rels) {
    if (!/^[A-Za-z0-9._+/-]+$/.test(rel)) throw new Error(`unsafe git path ${rel}`);
  }
  return rels;
}

async function commitFastImport(dir) {
  const rels = await listWorktreeFiles(dir);
  const blobs = new Array(rels.length);
  await allJoined(
    rels.map((rel, index) =>
      linkLimit(async () => {
        blobs[index] = await fsp.readFile(path.join(dir, ...rel.split("/")));
      }),
    ),
  );
  const chunks = [Buffer.from("reset refs/heads/guard\n")];
  rels.forEach((_rel, index) => {
    const bytes = blobs[index];
    chunks.push(Buffer.from(`blob\nmark :${index + 1}\ndata ${bytes.length}\n`));
    chunks.push(bytes);
    chunks.push(Buffer.from("\n"));
  });
  const message = Buffer.from("baseline\n");
  const when = "1700000000 +0000";
  chunks.push(
    Buffer.from(`commit refs/heads/guard\ncommitter guard <guard@example.com> ${when}\ndata ${message.length}\n`),
  );
  chunks.push(message);
  rels.forEach((rel, index) => {
    chunks.push(Buffer.from(`M 100644 :${index + 1} ${rel}\n`));
  });
  chunks.push(Buffer.from("done\n"));
  await git(dir, ["fast-import", "--quiet", "--done"], Buffer.concat(chunks));
  const head = await git(dir, ["rev-parse", "--verify", "HEAD"]);
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error(`baseline commit missing: ${head}`);
}

// One owned fast-import. Parents stay on the repo's existing HEAD. Does not checkout.
function typedBaselineStream(branch, parent, revisionPath) {
  assert.match(branch, /^refs\/heads\/[A-Za-z0-9._/-]+$/);
  assert.match(parent, /^[0-9a-f]{40}$/);
  assert.match(revisionPath, /^[A-Za-z0-9._+/-]+$/);
  const value = Buffer.from("export const ENGINE_REVISION = 2;\n");
  const chunks = [Buffer.from(`blob\nmark :1\ndata ${value.length}\n`), value, Buffer.from("\n")];
  const commits = [
    [2, parent, "export const ENGINE_REVISION = 2;", ""],
    [3, ":2", "gitlink baseline", `M 160000 :2 ${revisionPath}\n`],
    [4, ":3", "symlink baseline", `M 120000 :1 ${revisionPath}\n`],
    [5, ":4", "directory baseline", `D ${revisionPath}\nM 100644 :1 ${revisionPath}/child\n`],
    [6, ":5", "missing baseline", `D ${revisionPath}\n`],
  ];
  for (const [mark, from, message, operations] of commits) {
    const msg = Buffer.from(message);
    chunks.push(
      Buffer.from(
        `commit ${branch}\nmark :${mark}\ncommitter guard <guard@example.com> 1700000000 +0000\ndata ${msg.length}\n`,
      ),
    );
    chunks.push(msg, Buffer.from(`\nfrom ${from}\n${operations}\n`));
  }
  chunks.push(Buffer.from("done\n"));
  return Buffer.concat(chunks);
}

function typedBaselineMarks(text) {
  const marks = {};
  for (const raw of text.split("\n")) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (!line) continue;
    assert.match(line, /^:[1-6] [0-9a-f]{40}$/);
    const space = line.indexOf(" ");
    const id = line.slice(0, space);
    assert.equal(marks[id], undefined);
    marks[id] = line.slice(space + 1);
  }
  assert.equal(Object.keys(marks).length, 6);
  for (const id of [":1", ":2", ":3", ":4", ":5", ":6"]) assert.match(marks[id], /^[0-9a-f]{40}$/);
  return marks;
}

function fromRel(rootDir, rel) {
  return rel ? path.join(rootDir, ...rel.split("/")) : rootDir;
}

function listCopyFiles(src, skipUnimportedTests, rel = "", files = []) {
  const names = fs.readdirSync(fromRel(src, rel)).sort();
  for (const name of names) {
    const child = rel ? `${rel}/${name}` : name;
    const full = fromRel(src, child);
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink()) throw new Error(`refusing to copy symlink ${full}`);
    if (st.isDirectory()) {
      listCopyFiles(src, skipUnimportedTests, child, files);
      continue;
    }
    if (!st.isFile()) throw new Error(`refusing to copy special file ${full}`);
    if (skipUnimportedTests && name.endsWith(".test.ts")) continue;
    files.push(child);
  }
  return files;
}

// Independent copyFile bytes. Never hardlink the template back to P0.
async function copyTemplateTree(src, dest, skipUnimportedTests) {
  beginWork();
  const files = listCopyFiles(src, skipUnimportedTests);
  const dirRels = new Set();
  for (const rel of files) {
    const parts = rel.split("/");
    parts.pop();
    if (parts.length > 0) dirRels.add(parts.join("/"));
  }
  fs.mkdirSync(dest, { recursive: true });
  for (const dirRel of [...dirRels].sort()) fs.mkdirSync(fromRel(dest, dirRel), { recursive: true });
  await allJoined(
    files.map((rel) =>
      copyLimit(async () => {
        beginWork();
        await fsp.copyFile(fromRel(src, rel), fromRel(dest, rel));
      }),
    ),
  );
}

async function createSeededRepo() {
  beginWork();
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-src-"));
  keep.push(dir);
  await initRepo(dir);
  await replaceFile(path.join(dir, ".gitignore"), FIXTURE_GITIGNORE);
  await copyTemplateTree(path.join(admissionRoot, "core"), path.join(dir, "core"), true);
  await fsp.mkdir(path.join(dir, "scripts"), { recursive: true });
  await fsp.copyFile(path.join(root, "scripts", "policy-compat-guard.mjs"), path.join(dir, "scripts", "policy-compat-guard.mjs"));
  await fsp.copyFile(path.join(root, "scripts", "spec-run.mjs"), path.join(dir, "scripts", "spec-run.mjs"));
  await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), emptyBlock());
  return dir;
}

async function assertRepoHead(dir) {
  const head = await git(dir, ["rev-parse", "--verify", "HEAD"]);
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error(`baseline commit missing: ${head}`);
  return head;
}

// unpack-objects skips objects that are still reachable from a pack in this repo.
async function explodePackToLoose(dir) {
  const packDir = path.join(dir, ".git", "objects", "pack");
  const names = await fsp.readdir(packDir);
  const packName = names.find((name) => name.endsWith(".pack"));
  if (!packName) throw new Error(`pack missing in ${dir}`);
  const bytes = await fsp.readFile(path.join(packDir, packName));
  await allJoined(
    names
      .filter((name) => [".pack", ".idx", ".rev", ".keep"].some((suffix) => name.endsWith(suffix)))
      .map((name) => fsp.rm(path.join(packDir, name), { force: true })),
  );
  await git(dir, ["unpack-objects", "-q"], bytes);
  const tree = await git(dir, ["rev-parse", "--verify", "HEAD^{tree}"]);
  await fsp.lstat(path.join(dir, ".git", "objects", tree.slice(0, 2), tree.slice(2)));
}

async function makeRepo(policy) {
  beginWork();
  const dir = await createSeededRepo();
  if (policy === "mini") {
    const caseDir = path.join(dir, "policy-spec", "normal", "alpha");
    await fsp.mkdir(caseDir, { recursive: true });
    await replaceFile(path.join(caseDir, "input.json"), MINI_INPUT);
    await replaceFile(path.join(caseDir, "policy.json"), MINI_POLICY);
    await replaceFile(path.join(caseDir, "context.json"), MINI_CONTEXT);
    await replaceFile(path.join(caseDir, "expected.json"), MINI_EXPECTED);
    // Loose objects: one test deletes HEAD^{tree} by its loose path.
    await commitFastImport(dir);
    await explodePackToLoose(dir);
  } else {
    await copyTemplateTree(path.join(admissionRoot, "policy-spec"), path.join(dir, "policy-spec"), false);
    await commitFastImport(dir);
  }
  await assertRepoHead(dir);
  return dir;
}

async function makeFullAndHistory() {
  beginWork();
  const dir = await createSeededRepo();
  const historyPromise = makeHistoryRepo(dir);
  try {
    await copyTemplateTree(path.join(admissionRoot, "policy-spec"), path.join(dir, "policy-spec"), false);
    await commitFastImport(dir);
    await assertRepoHead(dir);
    await copyTemplateTree(path.join(admissionRoot, "src"), path.join(dir, "src"), true);
    await linkNodeModules(dir);
  } catch (error) {
    await historyPromise.catch(() => {});
    throw error;
  }
  return [dir, await historyPromise];
}

async function linkWorktree(src, dest, skipTop = []) {
  beginWork();
  const skipped = new Set(skipTop);
  async function walk(from, to, top) {
    beginWork();
    await fsp.mkdir(to, { recursive: true });
    const entries = await fsp.readdir(from, { withFileTypes: true });
    await allJoined(
      entries.map(async (entry) => {
        beginWork();
        // Heavy template deps are junctions. Clones attach their own and must not walk them.
        if (entry.name === ".git" || (top && (skipped.has(entry.name) || entry.name === "node_modules" || entry.name === "src"))) {
          return;
        }
        const srcPath = path.join(from, entry.name);
        const destPath = path.join(to, entry.name);
        if (entry.isSymbolicLink()) throw new Error(`refusing to link symlink ${srcPath}`);
        if (entry.isDirectory()) {
          await walk(srcPath, destPath, false);
          return;
        }
        await linkLimit(() => fsp.link(srcPath, destPath));
      }),
    );
  }
  await walk(src, dest, true);
}

async function attachCore(src, dest, ownCore) {
  if (ownCore) return;
  beginWork();
  const type = process.platform === "win32" ? "junction" : "dir";
  await fsp.symlink(path.join(src, "core"), path.join(dest, "core"), type);
}

function repoHead(repo) {
  let pending = headOf.get(repo);
  if (!pending) {
    pending = git(repo, ["rev-parse", "HEAD"]);
    headOf.set(repo, pending);
  }
  return pending;
}

async function linkGitObjects(src, dest) {
  beginWork();
  const srcObjects = path.join(src, ".git", "objects");
  const destObjects = path.join(dest, ".git", "objects");
  const names = await fsp.readdir(srcObjects, { withFileTypes: true });
  await allJoined(
    names.map(async (entry) => {
      beginWork();
      if (entry.name === "info") return;
      const from = path.join(srcObjects, entry.name);
      const to = path.join(destObjects, entry.name);
      if (!entry.isDirectory()) return;
      await fsp.mkdir(to, { recursive: true });
      const files = await fsp.readdir(from, { withFileTypes: true });
      await allJoined(
        files.map(async (file) => {
          beginWork();
          if (!file.isFile()) return;
          if (file.name.endsWith(".keep") || file.name.includes(".tmp")) return;
          await linkLimit(() => fsp.link(path.join(from, file.name), path.join(to, file.name)));
        }),
      );
    }),
  );
}

async function cloneRepo(src, options = {}) {
  beginWork();
  const ownCore = options.ownCore === true;
  const seedIndex = options.seedIndex === true;
  const ownSrc = options.ownSrc === true;
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-"));
  keep.push(dir);
  await initRepo(dir);
  await linkGitObjects(src, dir);
  await git(dir, ["update-ref", "HEAD", await repoHead(src)]);
  if (seedIndex) await git(dir, ["read-tree", "HEAD"]);
  await linkWorktree(src, dir, ownCore ? [] : ["core"]);
  await attachCore(src, dir, ownCore);
  const templateSentinel = path.join(src, "core", "policy", "engine-revision.ts");
  const cloneSentinel = path.join(dir, "core", "policy", "engine-revision.ts");
  const [templateStat, cloneStat] = await Promise.all([fsp.stat(templateSentinel), fsp.stat(cloneSentinel)]);
  assert.equal(cloneStat.ino, templateStat.ino);
  assert.equal(cloneStat.dev, templateStat.dev);
  assert.equal(fs.existsSync(path.join(dir, ".git")), true);
  if (ownSrc) {
    // src must not exist yet. Copy it; do not create or swap a junction to P0.
    await assert.rejects(fsp.lstat(path.join(dir, "src")), (error) => error.code === "ENOENT");
    await copyTemplateTree(path.join(root, "src"), path.join(dir, "src"), true);
    await linkNodeModules(dir);
    await assertOwnedSrc(dir);
  } else {
    await linkDeps(dir, src);
  }
  return dir;
}

function withProposedCount(text, caseCount, digest) {
  if (!text.startsWith("status=PROPOSED\n") || !text.includes("\nhumanAccept=false\n") || !text.includes("\nfrozen=false\n")) {
    throw new Error("compact metadata must stay PROPOSED");
  }
  const counted = text.replace(/^caseCount=\d+$/m, `caseCount=${caseCount}`);
  if (counted === text) throw new Error("caseCount field missing");
  const next = counted.replace(/^expectedDigest=[0-9a-f]{64}$/m, `expectedDigest=${digest}`);
  if (next === counted) throw new Error("expectedDigest field missing");
  if ((next.match(/^caseCount=/gm) || []).length !== 1) throw new Error("caseCount field drifted");
  return next;
}

async function copyLockedCase(corpus, id, hashes) {
  beginWork();
  const caseDir = path.join(corpus, ...id.split("/"));
  await fsp.mkdir(caseDir, { recursive: true });
  for (const name of CASE_FILES) {
    beginWork();
    const rel = `${id}/${name}`;
    const locked = hashes[rel];
    assert.match(locked, /^[0-9a-f]{64}$/, rel);
    const source = path.join(admissionRoot, "policy-spec", ...id.split("/"), name);
    const bytes = await fsp.readFile(source);
    assert.equal(sha256(bytes), locked, rel);
    const dest = path.join(caseDir, name);
    await fsp.copyFile(source, dest);
    const copied = await fsp.readFile(dest);
    assert.equal(sha256(copied), locked, rel);
    if (name !== "context.json") continue;
    const sourceBundle = JSON.parse(bytes.toString("utf8"));
    const copiedBundle = JSON.parse(copied.toString("utf8"));
    assert.equal(copiedBundle.provenance.status, sourceBundle.provenance.status, rel);
    assert.equal(copiedBundle.provenance.acceptance, sourceBundle.provenance.acceptance, rel);
  }
}

async function writeCompactCorpus(dir) {
  const corpus = path.join(dir, "policy-spec");
  await fsp.mkdir(corpus, { recursive: true });
  const admitted = await fsp.readFile(path.join(admissionRoot, "policy-spec", "PROPOSED_DIGEST.txt"));
  assert.equal(sha256(admitted), BOOTSTRAP_METADATA["PROPOSED_DIGEST.txt"]);
  const admittedText = admitted.toString("utf8");
  assert.match(admittedText, /^caseCount=443$/m);
  assert.match(admittedText, new RegExp(`^expectedDigest=${BOOTSTRAP_EXPECTED_DIGEST}$`, "m"));
  compactProposedText = withProposedCount(admittedText, COMPACT_CASE_COUNT, COMPACT_EXPECTED_DIGEST);
  assert.equal(compactProposedText.includes("caseCount=443"), false);
  assert.equal(compactProposedText.includes(BOOTSTRAP_EXPECTED_DIGEST), false);
  await replaceFile(path.join(corpus, "PROPOSED_DIGEST.txt"), compactProposedText);
  assert.equal(Object.keys(COMPACT_SOURCE_HASHES).length, COMPACT_CASE_COUNT * 4);
  const categories = new Set();
  for (const id of COMPACT_CASE_IDS) {
    categories.add(id.split("/")[0]);
    await copyLockedCase(corpus, id, COMPACT_SOURCE_HASHES);
  }
  assert.equal(COMPACT_CASE_IDS.length, COMPACT_CASE_COUNT);
  assert.equal(categories.size, COMPACT_CASE_COUNT);
  const files = await walkCaseFiles(corpus);
  assert.equal(files.length, COMPACT_CASE_COUNT * 4);
  const official = await expectedDigest(corpus);
  assert.equal(official.count, COMPACT_CASE_COUNT);
  assert.equal(official.digest, COMPACT_EXPECTED_DIGEST);
  assert.equal(await worktreeAnchor(dir), COMPACT_BUNDLE_ANCHOR);
}

async function makeHistoryRepo(coreSource) {
  beginWork();
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-src-"));
  keep.push(dir);
  await initRepo(dir);
  await replaceFile(path.join(dir, ".gitignore"), FIXTURE_GITIGNORE);
  await linkWorktree(path.join(coreSource, "core"), path.join(dir, "core"));
  await fsp.mkdir(path.join(dir, "scripts"), { recursive: true });
  await fsp.copyFile(path.join(root, "scripts", "policy-compat-guard.mjs"), path.join(dir, "scripts", "policy-compat-guard.mjs"));
  await fsp.copyFile(path.join(root, "scripts", "spec-run.mjs"), path.join(dir, "scripts", "spec-run.mjs"));
  await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), emptyBlock());
  await writeCompactCorpus(dir);
  await commitFastImport(dir);
  await copyTemplateTree(path.join(admissionRoot, "src"), path.join(dir, "src"), true);
  // Package resolution walks from the real src path, not from the clone that links it.
  await linkNodeModules(dir);
  return dir;
}

async function assertOwnedSrc(dir) {
  const srcDir = path.join(dir, "src");
  const srcStat = await fsp.lstat(srcDir);
  assert.equal(srcStat.isSymbolicLink(), false, srcDir);
  assert.equal(srcStat.isDirectory(), true, srcDir);
  const repoReal = await fsp.realpath(dir);
  for (const rel of ["src/lib/monitor/rules.ts", "src/lib/monitor/engine.ts"]) {
    const file = path.join(dir, ...rel.split("/"));
    const lst = await fsp.lstat(file);
    assert.equal(lst.isSymbolicLink(), false, file);
    assert.equal(lst.isFile(), true, file);
    assert.equal(lst.nlink, 1, file);
    const real = await fsp.realpath(file);
    const relToRepo = path.relative(repoReal, real);
    assert.equal(relToRepo.startsWith("..") || path.isAbsolute(relToRepo), false, real);
    const origin = path.join(root, ...rel.split("/"));
    assert.notEqual(lst.ino, (await fsp.stat(origin)).ino, rel);
    assert.notEqual(real, await fsp.realpath(origin), rel);
  }
}

async function bumpEngineRevision(dir) {
  const file = path.join(dir, "core", "policy", "engine-revision.ts");
  const text = await fsp.readFile(file, "utf8");
  const from = parseFixtureRevision(text);
  const to = from + 1;
  const needle = `ENGINE_REVISION = ${from};`;
  assert.equal(text.split(needle).length - 1, 1);
  const rewritten = text.replace(needle, `ENGINE_REVISION = ${to};`);
  assert.equal(rewritten.includes(needle), false);
  await replaceFile(file, rewritten);
  return { from, to };
}

async function enumeratedCaseIds(corpus) {
  const files = await walkCaseFiles(corpus);
  const ids = [];
  for (const file of files) {
    if (!file.path.endsWith("/expected.json")) continue;
    ids.push(file.path.slice(0, -"/expected.json".length));
  }
  ids.sort((a, b) => a.localeCompare(b, "en"));
  assert.equal(new Set(ids).size, ids.length);
  return ids;
}

async function runCopiedSpec(cwd, resultsPath) {
  const script = path.join(cwd, "scripts", "spec-run.mjs");
  assert.equal(fs.existsSync(resultsPath), false, resultsPath);
  const scriptStat = await fsp.lstat(script);
  assert.equal(scriptStat.isSymbolicLink(), false, script);
  const real = await fsp.realpath(script);
  const rel = path.relative(await fsp.realpath(cwd), real);
  assert.equal(rel.startsWith("..") || path.isAbsolute(rel), false, real);
  const production = path.join(root, "scripts", "spec-run.mjs");
  assert.equal(sha256(await fsp.readFile(script)), sha256(await fsp.readFile(production)));
  assert.notEqual(scriptStat.ino, (await fsp.stat(production)).ino);
  const result = await spawnCollected(
    process.execPath,
    ["--experimental-strip-types", script, "run", "--corpus", path.join(cwd, "policy-spec"), "--results", resultsPath],
    {
      cwd,
      env: guardEnv(),
      timeout: 90_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  return {
    status: result.status,
    stdout: result.stdout.toString("utf8"),
    stderr: result.stderr.toString("utf8"),
    error: result.error,
  };
}

async function writeEvent(payload) {
  beginWork();
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-event-"));
  keep.push(dir);
  const file = path.join(dir, "event.json");
  await replaceFile(file, JSON.stringify(payload));
  return file;
}

async function objectsDirectory(repo) {
  const printed = await git(repo, ["rev-parse", "--git-path", "objects"]);
  return path.resolve(repo, printed);
}

async function makeBootstrapOverlay() {
  beginWork();
  const parent = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-boot-"));
  keep.push(parent);
  const dir = path.join(parent, "wt");
  await fsp.mkdir(dir);
  await linkWorktree(heavyTemplate, dir, ["core"]);
  await attachCore(heavyTemplate, dir, false);
  await initRepo(dir);
  const alternates = path.join(dir, ".git", "objects", "info", "alternates");
  await fsp.mkdir(path.dirname(alternates), { recursive: true });
  await replaceFile(alternates, `${(await objectsDirectory(root)).replaceAll("\\", "/")}\n`);
  const tree = await git(dir, ["rev-parse", `${BOOTSTRAP_COMMIT}^{tree}`]);
  const commit = await git(dir, ["commit-tree", tree, "-p", BOOTSTRAP_COMMIT, "-m", "overlay"]);
  await git(dir, ["update-ref", "HEAD", commit]);
  const templateSentinel = path.join(heavyTemplate, "policy-spec", "normal", "ls", "expected.json");
  const cloneSentinel = path.join(dir, "policy-spec", "normal", "ls", "expected.json");
  const [templateStat, cloneStat] = await Promise.all([fsp.stat(templateSentinel), fsp.stat(cloneSentinel)]);
  assert.equal(cloneStat.ino, templateStat.ino);
  assert.equal(cloneStat.dev, templateStat.dev);
  await linkDeps(dir, heavyTemplate);
  return dir;
}

async function sealFile(file, lockNlink) {
  const st = await fsp.stat(file);
  return {
    file,
    ino: st.ino,
    hash: sha256(await fsp.readFile(file)),
    nlink: lockNlink ? st.nlink : undefined,
  };
}

async function snapshotGit(repo) {
  const head = await git(repo, ["rev-parse", "HEAD"]);
  const ref = path.join(repo, ".git", "refs", "heads", "guard");
  const refStat = await fsp.stat(ref);
  const packDir = path.join(repo, ".git", "objects", "pack");
  const names = await fsp.readdir(packDir).catch(() => []);
  const packs = [];
  for (const name of names) {
    if (!name.endsWith(".pack") && !name.endsWith(".idx")) continue;
    const file = path.join(packDir, name);
    const st = await fsp.stat(file);
    packs.push({ file, ino: st.ino, size: st.size, hash: sha256(await fsp.readFile(file)) });
  }
  return {
    repo,
    head,
    ref,
    refIno: refStat.ino,
    refNlink: refStat.nlink,
    refHash: sha256(await fsp.readFile(ref)),
    packs,
  };
}

async function walkCaseFiles(corpus) {
  const files = [];
  async function walk(dir) {
    const names = await fsp.readdir(dir);
    await allJoined(
      names.map(async (name) => {
        const full = path.join(dir, name);
        const st = await fsp.lstat(full);
        if (st.isSymbolicLink()) return;
        if (st.isDirectory()) {
          await walk(full);
          return;
        }
        if (!CASE_FILES.includes(name)) return;
        const bytes = await linkLimit(() => fsp.readFile(full));
        files.push({
          path: path.relative(corpus, full).split(path.sep).join("/"),
          bytes,
        });
      }),
    );
  }
  await walk(corpus);
  return files;
}

async function prewarmModules() {
  const importer = path.join(path.dirname(compileCache), "prewarm.mjs");
  await writeNewFile(
    importer,
    [
      'import path from "node:path";',
      'import { pathToFileURL } from "node:url";',
      "const root = process.argv[2];",
      "const core = process.argv[3];",
      "const rootFiles = [",
      '  "src/lib/monitor/engine.ts",',
      '  "src/lib/monitor/rules.ts",',
      '  "src/lib/monitor/overrides.ts",',
      '  "src/lib/monitor/privacy.ts",',
      '  "src/lib/monitor/agents.ts",',
      '  "src/lib/monitor/exemption-scope.ts",',
      "];",
      "const coreFiles = [",
      '  "hook-protocol.ts",',
      '  "policy-schema.ts",',
      '  "policy/engine-revision.ts",',
      '  "policy/nmzp-service.ts",',
      "];",
      "await Promise.all([",
      "  ...rootFiles.map((rel) => import(pathToFileURL(path.join(root, rel)).href)),",
      "  ...coreFiles.map((rel) => import(pathToFileURL(path.join(core, rel)).href)),",
      "]);",
      "",
    ].join("\n"),
  );
  const result = await spawnCollected(
    process.execPath,
    ["--experimental-strip-types", importer, root, path.join(heavyTemplate, "core")],
    {
      cwd: root,
      env: { ...process.env, FORCE_COLOR: "0", NODE_COMPILE_CACHE: compileCache },
      timeout: 60_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  if (result.error || result.status !== 0) {
    throw new Error(`module prewarm failed: ${result.stderr.toString("utf8") || result.error?.message || result.status}`);
  }
}

async function worktreeAnchor(dir) {
  return bundleAnchor(await walkCaseFiles(path.join(dir, "policy-spec")));
}

async function removeOwnedTemp(dir) {
  const resolved = path.resolve(dir);
  const tmp = path.resolve(os.tmpdir());
  const relToTmp = path.relative(tmp, resolved);
  if (!relToTmp || relToTmp.startsWith("..") || path.isAbsolute(relToTmp)) {
    throw new Error(`refusing to remove outside temp: ${resolved}`);
  }
  const repo = path.resolve(root);
  const relToRepo = path.relative(repo, resolved);
  if (relToRepo === "" || (!relToRepo.startsWith("..") && !path.isAbsolute(relToRepo))) {
    throw new Error(`refusing to remove repo path: ${resolved}`);
  }
  if (!resolved.split(path.sep).some((part) => part.startsWith("nmzp-guard-"))) {
    throw new Error(`refusing to remove unexpected path: ${resolved}`);
  }
  let st;
  try {
    st = fs.lstatSync(resolved);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (st.isSymbolicLink()) throw new Error(`refusing to remove symlink: ${resolved}`);
  if (!st.isDirectory()) throw new Error(`refusing to remove non-directory: ${resolved}`);
  await fsp.rm(resolved, { recursive: true, force: true });
}

function installCleanup(validate) {
  after(async () => {
    const afterStart = Date.now();
    traceCancel("after-start");
    await drainOwned();
    traceCancel("drain-done");
    let failure;
    const validateStart = Date.now();
    if (validate) {
      try {
        await validate();
      } catch (error) {
        failure = error;
      }
    }
    const validateMs = Date.now() - validateStart;
    const deleteStart = Date.now();
    let deleteError;
    try {
      await Promise.all([...keep].map((dir) => removeOwnedTemp(dir)));
      traceCancel("deleted");
    } catch (error) {
      deleteError = error;
    }
    const deleteMs = Date.now() - deleteStart;
    if (!process.env.NMZP_GUARD_CANCEL_PROBE && phaseTiming.bodyStart) {
      process.stderr.write(
        `WP03_PHASE ${JSON.stringify({
          beforeMs: phaseTiming.beforeMs,
          bodyMs: afterStart - phaseTiming.bodyStart,
          validateMs,
          deleteMs,
        })}\n`,
      );
    }
    if (deleteError) throw deleteError;
    if (failure) throw failure;
  });
}

function cancelMarkerEvents(text) {
  const events = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const space = line.indexOf(" ");
    if (space <= 0 || !/^\d+$/.test(line.slice(0, space))) throw new Error(`bad cancel marker: ${line}`);
    events.push({ at: Number(line.slice(0, space)), event: line.slice(space + 1) });
  }
  return events;
}

function markerAt(events, name) {
  const found = events.findIndex((item) => item.event === name);
  assert.notEqual(found, -1, `${name} missing from ${events.map((item) => item.event).join(",")}`);
  return found;
}

function runCancelProbe(mode, marker, dir) {
  const env = {
    ...process.env,
    FORCE_COLOR: "0",
    NMZP_GUARD_CANCEL_PROBE: mode,
    NMZP_GUARD_CANCEL_MARKER: marker,
  };
  // Parent node --test sets this. Leaving it in makes the nested runner skip the file.
  delete env.NODE_TEST_CONTEXT;
  if (dir) env.NMZP_GUARD_CANCEL_DIR = dir;
  return spawnCollected(
    process.execPath,
    ["--test", "--test-concurrency=1", "--test-timeout=60000", fileURLToPath(import.meta.url)],
    {
      env,
      timeout: 20_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
}

function registerCancelProbe() {
  installCancelTrace();
  const mode = process.env.NMZP_GUARD_CANCEL_PROBE;
  describe("policy compatibility guard cancel probe", () => {
    installCleanup(null);
    if (mode === "empty") {
      test("an empty owned set drains immediately", () => {
        traceCancel("empty-test");
      });
      return;
    }
    if (mode === "deadline") {
      test("a drain deadline leaves the temp directory in place", () => {
        const dir = process.env.NMZP_GUARD_CANCEL_DIR;
        if (!dir) throw new Error("NMZP_GUARD_CANCEL_DIR is required");
        fs.mkdirSync(dir, { recursive: true });
        keep.push(dir);
        trackTask(
          new Promise((resolve) => {
            const timer = setTimeout(resolve, 8_000);
            timer.unref();
          }),
        );
        traceCancel("scheduled");
      });
      return;
    }
    test("a cancelled test drains before its directory is removed", { timeout: CANCEL_PROBE_TIMEOUT_MS }, async (t) => {
      const testStart = Date.now();
      const dir = process.env.NMZP_GUARD_CANCEL_DIR;
      if (!dir) throw new Error("NMZP_GUARD_CANCEL_DIR is required");
      traceCancel("test-start");
      t.signal.addEventListener("abort", () => traceCancel("signal-abort"), { once: true });
      await fsp.mkdir(dir, { recursive: true });
      keep.push(dir);
      const src = path.join(dir, "src");
      await fsp.mkdir(src);
      await fsp.writeFile(path.join(src, "a.txt"), "a");
      await fsp.writeFile(path.join(src, "b.txt"), "b");
      const linking = linkWorktree(src, path.join(dir, "linked"));
      const child = spawnCollected(process.execPath, ["-e", "setInterval(() => {}, 1000);"], {
        timeout: 30_000,
        maxBuffer: 1024 * 1024,
      });
      const marker = process.env.NMZP_GUARD_CANCEL_MARKER;
      if (!/child-pid:[1-9][0-9]*/.test(fs.readFileSync(marker, "utf8"))) {
        throw new Error("cancel probe child was not ready");
      }
      await linking;
      traceCancel("work-started");
      const readyAt = Date.now();
      const untilTimeout = testStart + CANCEL_PROBE_TIMEOUT_MS - readyAt;
      if (untilTimeout < CANCEL_PROBE_READY_MARGIN_MS) {
        throw new Error(`cancel probe ready too late (${readyAt - testStart}ms)`);
      }
      const continuationDelay = untilTimeout + CANCEL_PROBE_AFTER_TIMEOUT_MS;
      const slowDelay = continuationDelay + CANCEL_PROBE_SLOW_GAP_MS;
      const slow = trackTask(
        new Promise((resolve) => setTimeout(resolve, slowDelay)).then(() => linkWorktree(src, path.join(dir, "slow"))).then(
          () => traceCancel("slow-wrote"),
          (error) => {
            if (error?.code === "ABORT_ERR") traceCancel("slow-blocked");
            else traceCancel(`slow-error:${error?.code || error?.message || "error"}`);
          },
        ),
      );
      void slow;
      void child;
      await new Promise((resolve) => setTimeout(resolve, continuationDelay));
      traceCancel("continuation");
      try {
        await linkWorktree(src, path.join(dir, "late"));
        traceCancel("continuation-wrote");
      } catch (error) {
        if (error?.code === "ABORT_ERR") traceCancel("continuation-blocked");
        else traceCancel(`continuation-error:${error?.code || error?.message || "error"}`);
      }
    });
  });
}

if (process.env.NMZP_GUARD_CANCEL_PROBE) registerCancelProbe();
else {
// Every case spawns node and git children. Above the CPU count they only contend, and the per-test
// timeout counts the wait: a 2-CPU run at 8 took the merge-base case 33 s against 8 s at 2.
const GUARD_CONCURRENCY = Math.max(1, Math.min(8, os.availableParallelism()));

describe("policy compatibility guard", { concurrency: GUARD_CONCURRENCY }, (suite) => {
  suite.signal.addEventListener("abort", () => {
    for (const job of owned) job.stop("abort");
  });

  before(async () => {
    const beforeStarted = Date.now();
    const scratch = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-meta-"));
    keep.push(scratch);
    emptyTemplate = path.join(scratch, "template");
    emptyHooks = path.join(scratch, "empty-hooks");
    emptyGitConfig = path.join(scratch, "gitconfig");
    compileCache = path.join(scratch, "compile-cache");
    await fsp.mkdir(emptyTemplate);
    await fsp.mkdir(emptyHooks);
    await fsp.mkdir(compileCache);
    await replaceFile(emptyGitConfig, "");
    await extractAdmissionTree();
    [lightTemplate, [heavyTemplate, historyTemplate]] = await allJoined([makeRepo("mini"), makeFullAndHistory()]);
    const p0Sentinel = path.join(root, "core", "policy", "engine-revision.ts");
    const heavySentinel = path.join(heavyTemplate, "core", "policy", "engine-revision.ts");
    const [p0Stat, heavyStat] = await Promise.all([fsp.stat(p0Sentinel), fsp.stat(heavySentinel)]);
    assert.notEqual(p0Stat.ino, heavyStat.ino);
    assert.equal(p0Stat.nlink, 1);
    const p0Files = [
      "core/policy/engine-revision.ts",
      "core/policy/nmzp-service.ts",
      "policy-spec/ADMISSION.json",
      "policy-spec/normal/ls/expected.json",
      "policy-spec/normal/ls/context.json",
      "policy-spec/normal/ls/input.json",
      "INTENDED_CHANGES.md",
      "scripts/policy-compat-guard.mjs",
      "scripts/spec-run.mjs",
      "src/lib/monitor/rules.ts",
      "src/lib/monitor/engine.ts",
    ];
    seals = await allJoined(p0Files.map((rel) => sealFile(path.join(root, rel), true)));
    seals.push(
      ...(await allJoined([
        sealFile(path.join(heavyTemplate, "policy-spec", "normal", "ls", "expected.json"), false),
        sealFile(path.join(heavyTemplate, "core", "policy", "engine-revision.ts"), false),
        sealFile(path.join(heavyTemplate, "core", "policy", "nmzp-service.ts"), false),
        sealFile(path.join(heavyTemplate, "INTENDED_CHANGES.md"), false),
        sealFile(path.join(lightTemplate, "core", "policy", "engine-revision.ts"), false),
        sealFile(path.join(lightTemplate, "policy-spec", "normal", "alpha", "expected.json"), false),
        sealFile(path.join(lightTemplate, "INTENDED_CHANGES.md"), false),
        sealFile(path.join(historyTemplate, "policy-spec", "risky", "a1-archive-upload", "expected.json"), false),
        sealFile(path.join(historyTemplate, "policy-spec", "normal", "ls", "context.json"), false),
        sealFile(path.join(historyTemplate, "core", "policy", "engine-revision.ts"), false),
        sealFile(path.join(historyTemplate, "INTENDED_CHANGES.md"), false),
      ])),
    );
    gitSnapshots = await allJoined([snapshotGit(lightTemplate), snapshotGit(heavyTemplate), snapshotGit(historyTemplate)]);
    p0Head = await git(root, ["rev-parse", "HEAD"]);
    await prewarmModules();
    phaseTiming.beforeMs = Date.now() - beforeStarted;
    phaseTiming.bodyStart = Date.now();
  });

  installCleanup(async () => {
      for (const item of seals) {
        const now = await fsp.stat(item.file);
        const hash = sha256(await fsp.readFile(item.file));
        assert.equal(hash, item.hash, item.file);
        assert.equal(now.ino, item.ino, item.file);
        if (item.nlink !== undefined) assert.equal(now.nlink, item.nlink, item.file);
      }
      for (const snap of gitSnapshots) {
        const head = await git(snap.repo, ["rev-parse", "HEAD"]);
        assert.equal(head, snap.head, snap.repo);
        const refStat = await fsp.stat(snap.ref);
        assert.equal(refStat.ino, snap.refIno, snap.ref);
        assert.equal(refStat.nlink, snap.refNlink, snap.ref);
        assert.equal(sha256(await fsp.readFile(snap.ref)), snap.refHash, snap.ref);
        for (const pack of snap.packs) {
          const st = await fsp.stat(pack.file);
          assert.equal(st.ino, pack.ino, pack.file);
          assert.equal(st.size, pack.size, pack.file);
          assert.equal(sha256(await fsp.readFile(pack.file)), pack.hash, pack.file);
        }
      }
      assert.equal(await git(root, ["rev-parse", "HEAD"]), p0Head);
  });

  test("admitted bytes match the fixed digest and case anchor", async () => {
    const corpus = path.join(admissionRoot, "policy-spec");
    const files = await walkCaseFiles(corpus);
    assert.equal(files.length, BOOTSTRAP_CASE_COUNT * 4);
    assert.equal(bundleAnchor(files), BOOTSTRAP_BUNDLE_ANCHOR);
    const official = await expectedDigest(corpus);
    assert.equal(official.digest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(official.count, BOOTSTRAP_CASE_COUNT);
    const expected = files.filter((file) => file.path.endsWith("/expected.json"));
    assert.equal(
      digestExpected(expected.map((file) => ({ id: file.path.slice(0, -"/expected.json".length), bytes: file.bytes }))),
      official.digest,
    );
    const asciiParts = [];
    for (const file of [...expected].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
      asciiParts.push(Buffer.from(`${file.path}\n`), file.bytes);
    }
    assert.notEqual(sha256(Buffer.concat(asciiParts)), official.digest);
    const text = await fsp.readFile(path.join(admissionRoot, "INTENDED_CHANGES.md"), "utf8");
    const parsed = parseIntendedChanges(text);
    assert.equal(parsed.ok, true, parsed.detail);
    assert.deepEqual(parsed.entries, []);
  });

  test("parser rejects empty reasons, duplicate cases, and duplicate blocks", () => {
    const good = block([
      entry({
        oldDigest: MINI_DIGEST,
        newDigest: MINI_DIGEST,
        oldRevision: 2,
        newRevision: 3,
        oldBundleAnchor: ANCHOR_A,
        newBundleAnchor: ANCHOR_B,
        reason: "version only",
      }),
    ]);
    assert.equal(parseIntendedChanges(good).ok, true);
    const emptyReason = good.replace("reason=version only", "reason=");
    assert.equal(parseIntendedChanges(emptyReason).code, "empty_reason");
    const duplicateCase = block([
      entry({
        oldDigest: MINI_DIGEST,
        newDigest: MINI_DIGEST,
        oldRevision: 2,
        newRevision: 2,
        oldBundleAnchor: ANCHOR_A,
        newBundleAnchor: ANCHOR_B,
        reason: "twice",
        cases: [MINI_ID, MINI_ID],
      }),
    ]);
    assert.equal(parseIntendedChanges(duplicateCase).code, "duplicate_case");
    assert.equal(parseIntendedChanges(`${good}\n${good}`).code, "duplicate_block");
    assert.equal(parseIntendedChanges("# no block\n").code, "missing_block");
    const sameTransition = entry({
      oldDigest: MINI_DIGEST,
      newDigest: MINI_DIGEST,
      oldRevision: 2,
      newRevision: 2,
      oldBundleAnchor: ANCHOR_A,
      newBundleAnchor: ANCHOR_B,
      reason: "anchor pair",
      cases: [MINI_ID],
    });
    const otherAnchor = entry({
      oldDigest: MINI_DIGEST,
      newDigest: MINI_DIGEST,
      oldRevision: 2,
      newRevision: 2,
      oldBundleAnchor: ANCHOR_A,
      newBundleAnchor: ANCHOR_C,
      reason: "other anchor pair",
      cases: [MINI_ID],
    });
    assert.equal(parseIntendedChanges(block([sameTransition, otherAnchor])).ok, true);
    assert.equal(
      parseIntendedChanges(block([sameTransition, sameTransition.replace("reason=anchor pair", "reason=same anchors")])).code,
      "duplicate_entry",
    );
    assert.equal(parseIntendedChanges(good.replace(/\noldBundleAnchor=[0-9a-f]{64}/, "")).code, "malformed_entry");
    assert.equal(
      parseIntendedChanges(good.replace(`oldBundleAnchor=${ANCHOR_A}`, `oldBundleAnchor=${"A".repeat(64)}`)).code,
      "digest_syntax",
    );
  });

  test("current checkout bootstraps from the pinned commit and runs the corpus", { timeout: 120_000 }, async () => {
    const sample = path.join(root, "policy-spec", "normal", "ls", "expected.json");
    const beforeHash = sha256(fs.readFileSync(sample));
    const admission = sha256(fs.readFileSync(path.join(root, "policy-spec", "ADMISSION.json")));
    const started = Date.now();
    const dir = await makeBootstrapOverlay();
    const run = await runCli(dir, ["--base", BOOTSTRAP_COMMIT]);
    assert.equal(run.error, undefined, run.error?.message);
    assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
    assert.equal(run.parsed.ok, true);
    assert.equal(run.parsed.bootstrap, true);
    assert.equal(run.parsed.mode, "bootstrap");
    assert.equal(run.parsed.stage, "ok");
    assert.equal(run.parsed.baseline, BOOTSTRAP_COMMIT);
    assert.equal(run.parsed.bootstrapFrom, BOOTSTRAP_COMMIT);
    assert.equal(run.parsed.baselineSource, "cli --base");
    assert.equal(run.parsed.engineRevision, BOOTSTRAP_ENGINE_REVISION);
    assert.equal(run.parsed.expectedDigest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(run.parsed.caseCount, BOOTSTRAP_CASE_COUNT);
    assert.equal(run.parsed.bundleAnchor, BOOTSTRAP_BUNDLE_ANCHOR);
    assert.equal(run.parsed.corpusRan, true);
    assert.equal(run.parsed.corpusOk, true);
    assert.equal(run.parsed.collationWitness, true);
    assert.equal(run.parsed.sortContract, "icu-en");
    assert.equal(run.parsed.hashBinding.changed, true);
    assert.equal(run.parsed.hashBinding.bumpedRevision, BOOTSTRAP_ENGINE_REVISION + 1);
    assert.deepEqual(run.parsed.changedCases, []);
    assert.ok(run.parsed.elapsedMs < 30_000, `elapsed ${run.parsed.elapsedMs}`);
    assert.ok(Date.now() - started < 30_000);
    assert.equal(sha256(fs.readFileSync(sample)), beforeHash);
    assert.equal(sha256(fs.readFileSync(path.join(root, "policy-spec", "ADMISSION.json"))), admission);
  });

  test("omitted local baseline does not fall back to HEAD", async () => {
    const run = await runCli(root, []);
    assertRejected(run, "baseline", "baseline_required");
    assert.equal(run.parsed.bootstrap, false);
  });

  test("CI rejects a baseline argument and an unresolved zero push", async () => {
    const override = await runCli(root, ["--base", BOOTSTRAP_COMMIT], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: BOOTSTRAP_COMMIT }),
    });
    assertRejected(override, "baseline", "baseline_override");
    const zero = await runCli(root, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA }),
    });
    assertRejected(zero, "baseline", "default_branch_missing");
    assert.equal(zero.parsed.bootstrap, false);
    assert.equal(zero.parsed.bootstrapFrom, null);
    const missing = await runCli(root, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: {} }),
    });
    assertRejected(missing, "baseline", "default_branch_missing");
    const explicitZero = await runCli(root, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: ZERO_SHA } }),
    });
    assertRejected(explicitZero, "baseline", "zero_baseline");
    const head = await runCli(root, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: "HEAD" } }),
    });
    assertRejected(head, "baseline", "baseline_not_sha");
    const candidate = await runCli(root, ["--candidate", root]);
    assertRejected(candidate, "baseline", "candidate_override");
    const unsupported = await runCli(root, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "pull_request_target",
      GITHUB_EVENT_PATH: await writeEvent({}),
    });
    assertRejected(unsupported, "baseline", "unsupported_event");
  });

  test("zero before and an empty dispatch baseline use merge-base", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(lightTemplate, { seedIndex: true });
    const base = await git(dir, ["rev-parse", "HEAD"]);
    await git(dir, ["update-ref", "refs/remotes/origin/guard", base]);
    await replaceFile(path.join(dir, "policy-spec", "normal", "alpha", "expected.json"), '{"compare":{"decision":"block"}}\n');
    await git(dir, ["add", "-A"]);
    await git(dir, ["commit", "-q", "-m", "change expected"]);
    const head = await git(dir, ["rev-parse", "HEAD"]);
    assert.notEqual(head, base);
    const repository = { default_branch: "guard" };
    const zero = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA, repository }),
    });
    assertRejected(zero, "revision", "revision_not_increased");
    assert.equal(zero.parsed.baseline, base);
    assert.notEqual(zero.parsed.baseline, head);
    assert.equal(zero.parsed.baselineSource, "push.before=zero→merge-base:origin/guard");
    assert.equal(zero.parsed.bootstrap, false);
    assert.equal(zero.parsed.bootstrapFrom, null);
    assert.equal(zero.parsed.mode, "compare");

    const blank = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: "  " }, repository }),
    });
    assertRejected(blank, "revision", "revision_not_increased");
    assert.equal(blank.parsed.baseline, base);
    assert.equal(blank.parsed.baselineSource, "workflow_dispatch.inputs.baseline=empty→merge-base:origin/guard");

    const omitted = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: {}, repository }),
    });
    assertRejected(omitted, "revision", "revision_not_increased");
    assert.equal(omitted.parsed.baseline, base);
    assert.equal(omitted.parsed.baselineSource, "workflow_dispatch.inputs.baseline=empty→merge-base:origin/guard");

    const explicit = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: `  ${base}  ` }, repository }),
    });
    assertRejected(explicit, "revision", "revision_not_increased");
    assert.equal(explicit.parsed.baseline, base);
    assert.equal(explicit.parsed.baselineSource, "workflow_dispatch.inputs.baseline");

    const bad = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: "abc" }, repository }),
    });
    assertRejected(bad, "baseline", "baseline_not_sha");
    const headName = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: "HEAD" }, repository }),
    });
    assertRejected(headName, "baseline", "baseline_not_sha");
    const typedZero = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_EVENT_PATH: await writeEvent({ inputs: { baseline: ZERO_SHA }, repository }),
    });
    assertRejected(typedZero, "baseline", "zero_baseline");

    const kept = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: base, repository }),
    });
    assertRejected(kept, "revision", "revision_not_increased");
    assert.equal(kept.parsed.baseline, base);
    assert.equal(kept.parsed.baselineSource, "push.before");

    const prZero = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "pull_request",
      GITHUB_EVENT_PATH: await writeEvent({
        before: ZERO_SHA,
        repository,
        pull_request: { base: { sha: ZERO_SHA }, head: { sha: head } },
      }),
    });
    assertRejected(prZero, "baseline", "zero_baseline");

    const noBranch = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA, repository: {} }),
    });
    assertRejected(noBranch, "baseline", "default_branch_missing");
    const badBranch = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA, repository: { default_branch: "feature/../main" } }),
    });
    assertRejected(badBranch, "baseline", "default_branch_missing");
    const absent = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA, repository: { default_branch: "main" } }),
    });
    assertRejected(absent, "baseline", "merge_base_unavailable");
    assert.equal(absent.parsed.baselineSource, "push.before=zero→merge-base:origin/main");
    assert.match(absent.parsed.detail, /origin\/main is not available/);

    const unrelatedTree = await git(dir, ["mktree"], "");
    const unrelated = await git(dir, ["commit-tree", unrelatedTree, "-m", "unrelated"]);
    await git(dir, ["update-ref", "refs/remotes/origin/side", unrelated]);
    const noBase = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ before: ZERO_SHA, repository: { default_branch: "side" } }),
    });
    assertRejected(noBase, "baseline", "merge_base_unavailable");
    assert.match(noBase.parsed.detail, /no merge-base for HEAD and origin\/side/);

    const skipped = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ deleted: true, before: base, repository }),
    });
    assert.equal(skipped.error, undefined, skipped.error?.message);
    assert.equal(skipped.status, 0, `${skipped.stderr}\n${skipped.stdout}`);
    assert.equal(skipped.parsed.ok, true);
    assert.equal(skipped.parsed.code, "push_deleted");
    assert.equal(skipped.parsed.mode, "skipped");
    assert.equal(skipped.parsed.corpusRan, false);
    assert.equal(skipped.parsed.bootstrap, false);
    assert.match(skipped.parsed.detail, /deleted branch push skipped/);
    const notDeleted = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "push",
      GITHUB_EVENT_PATH: await writeEvent({ deleted: "true", before: ZERO_SHA }),
    });
    assertRejected(notDeleted, "baseline", "default_branch_missing");
  });

  test("changed expected without a revision increase is rejected", async () => {
    const dir = await cloneRepo(lightTemplate);
    await replaceFile(path.join(dir, "policy-spec", "normal", "alpha", "expected.json"), '{"compare":{"decision":"block"}}\n');
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "revision", "revision_not_increased");
    assert.equal(run.parsed.bootstrap, false);
  });

  test("revision increase without an entry is rejected", async () => {
    const dir = await cloneRepo(lightTemplate, { ownCore: true });
    const bumped = await bumpEngineRevision(dir);
    assert.equal(bumped.to, bumped.from + 1);
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "intended_changes", "missing_entry");
  });

  test("input-only change and a wrong case id are rejected", async () => {
    const dir = await cloneRepo(lightTemplate);
    const changedInput = Buffer.from('{"command":"changed"}\n');
    await replaceFile(path.join(dir, "policy-spec", "normal", "alpha", "input.json"), changedInput);
    const missing = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(missing, "intended_changes", "missing_entry");
    await replaceFile(
      path.join(dir, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: MINI_DIGEST,
          newDigest: MINI_DIGEST,
          oldRevision: 2,
          newRevision: 2,
          oldBundleAnchor: miniBundleAnchor(),
          newBundleAnchor: miniBundleAnchor(changedInput),
          reason: "input byte change",
          cases: ["normal/wrong"],
        }),
      ]),
    );
    const wrong = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(wrong, "intended_changes", "case_set_mismatch");
    assert.match(wrong.parsed.detail, /normal\/alpha/);
  });

  test("deleting a case without a revision increase is rejected", async () => {
    const dir = await cloneRepo(lightTemplate);
    await fsp.rm(path.join(dir, "policy-spec", "normal", "alpha"), { recursive: true });
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "revision", "revision_not_increased");
    assert.deepEqual(run.parsed.changedCases, [MINI_ID]);
  });

  test("removing the hash binding is rejected by the live function", async () => {
    const dir = await cloneRepo(lightTemplate, { ownCore: true });
    const file = path.join(dir, "core", "policy", "nmzp-service.ts");
    const text = await fsp.readFile(file, "utf8");
    const mutated = removeSingleHashBinding(text);
    assert.equal(mutated.ok, true, `binding mutation missed the field (count ${mutated.count})`);
    assert.equal(mutated.count, 1);
    assert.match(mutated.removed, /^[ \t]*engineRevision:[ \t]*ENGINE_REVISION,[ \t]*$/);
    assert.equal(text.split(/\r?\n/).length - mutated.text.split(/\r?\n/).length, 1);
    assert.equal(mutated.text.includes("engineRevision: ENGINE_REVISION"), false);
    assert.match(mutated.text, /engine-revision\.ts/);
    await replaceFile(file, mutated.text);
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "hash_binding", "revision_unbound");
  });

  test("a tampered admission file cannot hide an expected change", async () => {
    const dir = await cloneRepo(lightTemplate);
    await replaceFile(path.join(dir, "policy-spec", "normal", "alpha", "expected.json"), '{"compare":{"decision":"block"}}\n');
    await replaceFile(
      path.join(dir, "policy-spec", "ADMISSION.json"),
      JSON.stringify({ expectedDigest: MINI_DIGEST, caseCount: 1, unchanged: true }),
    );
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "revision", "revision_not_increased");
    assert.equal(run.parsed.bootstrap, false);
  });

  test("missing, unrelated, and unreadable baselines do not bootstrap", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(lightTemplate);
    const missing = await runCli(dir, ["--base", "0123456789abcdef0123456789abcdef01234567"]);
    assertRejected(missing, "baseline", "git_read_failed");
    assert.equal(missing.parsed.bootstrap, false);
    assert.match(missing.parsed.detail, /bootstrap not applied/);
    const side = await git(dir, ["commit-tree", await git(dir, ["rev-parse", "HEAD^{tree}"]), "-m", "side"]);
    const unrelated = await runCli(dir, ["--base", side]);
    assertRejected(unrelated, "baseline", "not_ancestor");
    assert.equal(unrelated.parsed.bootstrap, false);
    const tree = await git(dir, ["rev-parse", "HEAD^{tree}"]);
    await fsp.rm(path.join(dir, ".git", "objects", tree.slice(0, 2), tree.slice(2)));
    const broken = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(broken, "baseline", "git_read_failed");
    assert.equal(broken.parsed.bootstrap, false);
    assert.notEqual(broken.parsed.code, "baseline_without_corpus");

    const typed = await cloneRepo(lightTemplate);
    const revisionFile = path.join(typed, "core", "policy", "engine-revision.ts");
    const beforeStat = await fsp.lstat(revisionFile);
    const beforeText = await fsp.readFile(revisionFile, "utf8");
    assert.equal(beforeStat.isSymbolicLink(), false);
    assert.match(beforeText, /^export const ENGINE_REVISION = 2;$/m);
    assert.match(await git(typed, ["ls-tree", "HEAD", "--", "core/policy/engine-revision.ts"]), /^100644 blob /);

    const parent = await git(typed, ["rev-parse", "HEAD"]);
    assert.match(parent, /^[0-9a-f]{40}$/);
    const branch = await git(typed, ["symbolic-ref", "--quiet", "HEAD"]);
    const revisionRel = "core/policy/engine-revision.ts";
    const marksFile = path.join(typed, ".git", "nmzp-baseline-marks");
    await git(
      typed,
      ["fast-import", "--quiet", "--done", `--export-marks=${marksFile.replaceAll("\\", "/")}`],
      typedBaselineStream(branch, parent, revisionRel),
    );
    const marks = typedBaselineMarks(await fsp.readFile(marksFile, "utf8"));
    const payload = marks[":2"];
    const gitlink = marks[":3"];
    const symlink = marks[":4"];
    const treeBaseline = marks[":5"];
    const missingBaseline = marks[":6"];
    for (const sha of [payload, gitlink, symlink, treeBaseline, missingBaseline]) {
      assert.match(sha, /^[0-9a-f]{40}$/);
    }
    const historyLines = (await git(typed, ["rev-list", "--parents", "HEAD"])).split(/\r?\n/).filter(Boolean);
    assert.equal(historyLines[0].split(" ")[0], missingBaseline);
    const history = {};
    for (const line of historyLines) {
      const [sha, ...older] = line.split(" ");
      assert.match(sha, /^[0-9a-f]{40}$/);
      history[sha] = older;
    }
    assert.deepEqual(history[missingBaseline], [treeBaseline]);
    assert.deepEqual(history[treeBaseline], [symlink]);
    assert.deepEqual(history[symlink], [gitlink]);
    assert.deepEqual(history[gitlink], [payload]);
    assert.deepEqual(history[payload], [parent]);

    assert.match(await git(typed, ["ls-tree", gitlink, "--", revisionRel]), /^160000 commit /);
    const gitlinkRun = await runCli(typed, ["--base", gitlink]);
    assertRejected(gitlinkRun, "revision", "baseline_revision_type");
    assert.equal(gitlinkRun.parsed.hashBinding, undefined);
    assert.match(gitlinkRun.parsed.detail, /160000 commit/);

    assert.match(await git(typed, ["ls-tree", symlink, "--", revisionRel]), /^120000 blob /);
    const symlinkRun = await runCli(typed, ["--base", symlink]);
    assertRejected(symlinkRun, "revision", "baseline_revision_type");
    assert.equal(symlinkRun.parsed.hashBinding, undefined);
    assert.match(symlinkRun.parsed.detail, /120000 blob/);

    assert.match(await git(typed, ["ls-tree", treeBaseline, "--", revisionRel]), /^040000 tree /);
    const treeRun = await runCli(typed, ["--base", treeBaseline]);
    assertRejected(treeRun, "revision", "baseline_revision_type");
    assert.equal(treeRun.parsed.hashBinding, undefined);
    assert.match(treeRun.parsed.detail, /040000 tree/);

    assert.equal(await git(typed, ["ls-tree", missingBaseline, "--", revisionRel]), "");
    const removed = await runCli(typed, ["--base", missingBaseline]);
    assertRejected(removed, "revision", "baseline_revision_missing");
    assert.equal(removed.parsed.hashBinding, undefined);

    const afterStat = await fsp.lstat(revisionFile);
    assert.equal(afterStat.isSymbolicLink(), false);
    assert.equal(afterStat.ino, beforeStat.ino);
    assert.equal(await fsp.readFile(revisionFile, "utf8"), beforeText);
  });

  test("an existing empty baseline is not the bootstrap commit", async () => {
    const dir = await cloneRepo(lightTemplate);
    const tree = await git(dir, ["mktree"], "");
    const commit = await git(dir, ["commit-tree", tree, "-m", "empty"]);
    await git(dir, ["update-ref", "HEAD", commit]);
    const run = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(run, "baseline", "baseline_without_corpus");
    assert.equal(run.parsed.bootstrap, false);
    assert.equal(run.parsed.bootstrapFrom, null);
  });

  test("an empty baseline that is not a descendant of the bootstrap commit stays baseline_without_corpus", async () => {
    const dir = await cloneRepo(lightTemplate);
    const parent = await git(dir, ["rev-parse", "HEAD"]);
    assert.notEqual(parent, BOOTSTRAP_COMMIT);
    const tree = await git(dir, ["mktree"], "");
    const commit = await git(dir, ["commit-tree", tree, "-p", parent, "-m", "no corpus"]);
    await git(dir, ["update-ref", "HEAD", commit]);
    const run = await runCli(dir, ["--base", commit]);
    assertRejected(run, "baseline", "baseline_without_corpus");
    assert.equal(run.parsed.bootstrap, false);
    assert.equal(run.parsed.bootstrapFrom, null);
    assert.match(run.parsed.detail, /empty-corpus descendant/);
  });

  test("pull_request compares the event base rather than HEAD", async () => {
    const dir = await cloneRepo(lightTemplate, { seedIndex: true });
    const base = await git(dir, ["rev-parse", "HEAD"]);
    await replaceFile(path.join(dir, "policy-spec", "normal", "alpha", "expected.json"), '{"compare":{"decision":"block"}}\n');
    await git(dir, ["add", "-A"]);
    await git(dir, ["commit", "-q", "-m", "change expected"]);
    const head = await git(dir, ["rev-parse", "HEAD"]);
    assert.notEqual(head, base);
    const run = await runCli(dir, [], {
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: "pull_request",
      GITHUB_EVENT_PATH: await writeEvent({
        pull_request: { base: { sha: base }, head: { sha: head } },
      }),
    });
    assertRejected(run, "revision", "revision_not_increased");
    assert.equal(run.parsed.baseline, base);
  });

  test("nested cases, orphan expected files, missing parts, and links are rejected", { timeout: 120_000 }, async () => {
    const nested = await cloneRepo(lightTemplate);
    const child = path.join(nested, "policy-spec", "normal", "alpha", "child");
    await fsp.mkdir(child, { recursive: true });
    for (const name of CASE_FILES) await replaceFile(path.join(child, name), "{}\n");
    assertRejected(await runCli(nested, ["--base", "HEAD"]), "enumeration", "nested_shadow");

    const orphan = await cloneRepo(lightTemplate);
    const orphanDir = path.join(orphan, "policy-spec", "normal", "orphan");
    await fsp.mkdir(orphanDir, { recursive: true });
    await replaceFile(path.join(orphanDir, "expected.json"), "{}\n");
    assertRejected(await runCli(orphan, ["--base", "HEAD"]), "enumeration", "orphan_expected");

    const partial = await cloneRepo(lightTemplate);
    const partialDir = path.join(partial, "policy-spec", "normal", "partial");
    await fsp.mkdir(partialDir, { recursive: true });
    await replaceFile(path.join(partialDir, "input.json"), MINI_INPUT);
    await replaceFile(path.join(partialDir, "expected.json"), MINI_EXPECTED);
    assertRejected(await runCli(partial, ["--base", "HEAD"]), "enumeration", "missing_part");

    const linked = await cloneRepo(lightTemplate);
    const target = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-link-"));
    keep.push(target);
    const type = process.platform === "win32" ? "junction" : "dir";
    await fsp.symlink(target, path.join(linked, "policy-spec", "linked"), type);
    assertRejected(await runCli(linked, ["--base", "HEAD"]), "enumeration", "symlink");
  });

  test("bootstrap rejects an expected change and an input-only change", { timeout: 120_000 }, async () => {
    const changedExpected = await makeBootstrapOverlay();
    const expected = path.join(changedExpected, "policy-spec", "normal", "ls", "expected.json");
    const original = await fsp.readFile(expected);
    await replaceFile(expected, Buffer.concat([original, Buffer.from("\n")]));
    await replaceFile(
      path.join(changedExpected, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: BOOTSTRAP_EXPECTED_DIGEST,
          newDigest: "a".repeat(64),
          oldRevision: 2,
          newRevision: 3,
          oldBundleAnchor: BOOTSTRAP_BUNDLE_ANCHOR,
          newBundleAnchor: ANCHOR_B,
          reason: "this entry must not authorize bootstrap drift",
          cases: ["normal/ls"],
        }),
      ]),
    );
    const digestRun = await runCli(changedExpected, ["--base", BOOTSTRAP_COMMIT]);
    assertRejected(digestRun, "bootstrap", "bootstrap_digest_mismatch");
    assert.equal(digestRun.parsed.bootstrap, true);
    assert.equal(digestRun.parsed.mode, "bootstrap");
    assert.equal(digestRun.parsed.baseline, BOOTSTRAP_COMMIT);
    assert.equal(digestRun.parsed.bootstrapFrom, BOOTSTRAP_COMMIT);

    const changedInput = await makeBootstrapOverlay();
    const input = path.join(changedInput, "policy-spec", "normal", "ls", "input.json");
    await replaceFile(input, Buffer.concat([await fsp.readFile(input), Buffer.from("\n")]));
    const anchorRun = await runCli(changedInput, ["--base", BOOTSTRAP_COMMIT]);
    assertRejected(anchorRun, "bootstrap", "bootstrap_anchor_mismatch");
    assert.equal(anchorRun.parsed.bootstrap, true);
    assert.equal(anchorRun.parsed.expectedDigest, BOOTSTRAP_EXPECTED_DIGEST);
  });

  test("an empty descendant admits the pinned corpus and rejects drift", { timeout: 120_000 }, async () => {
    const dir = await makeBootstrapOverlay();
    const head = await git(dir, ["rev-parse", "HEAD"]);
    assert.notEqual(head, BOOTSTRAP_COMMIT);
    assert.equal(await git(dir, ["merge-base", "--is-ancestor", BOOTSTRAP_COMMIT, head]), "");
    assert.equal(await git(dir, ["ls-tree", "-r", "--name-only", head, "--", "policy-spec"]), "");

    const admitted = await runCli(dir, ["--base", head]);
    assert.equal(admitted.error, undefined, admitted.error?.message);
    assert.equal(admitted.status, 0, `${admitted.stderr}\n${admitted.stdout}`);
    assert.equal(admitted.parsed.ok, true);
    assert.equal(admitted.parsed.bootstrap, true);
    assert.equal(admitted.parsed.mode, "bootstrap");
    assert.equal(admitted.parsed.baseline, head);
    assert.equal(admitted.parsed.bootstrapFrom, BOOTSTRAP_COMMIT);
    assert.equal(admitted.parsed.caseCount, BOOTSTRAP_CASE_COUNT);
    assert.equal(admitted.parsed.expectedDigest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(admitted.parsed.engineRevision, BOOTSTRAP_ENGINE_REVISION);
    assert.equal(admitted.parsed.bundleAnchor, BOOTSTRAP_BUNDLE_ANCHOR);
    assert.equal(admitted.parsed.corpusRan, true);
    assert.equal(admitted.parsed.corpusOk, true);

    const expected = path.join(dir, "policy-spec", "normal", "ls", "expected.json");
    const original = await fsp.readFile(expected);
    await replaceFile(expected, Buffer.concat([original, Buffer.from("\n")]));
    const driftedCorpus = await runCli(dir, ["--base", head]);
    assertRejected(driftedCorpus, "bootstrap", "bootstrap_digest_mismatch");
    assert.equal(driftedCorpus.parsed.baseline, head);
    assert.equal(driftedCorpus.parsed.bootstrapFrom, BOOTSTRAP_COMMIT);
    assert.equal(driftedCorpus.parsed.corpusRan, false);

    const revisionText = (await fsp.readFile(path.join(dir, "core", "policy", "engine-revision.ts"), "utf8")).replaceAll("\r\n", "\n");
    const from = parseFixtureRevision(revisionText);
    assert.equal(from, BOOTSTRAP_ENGINE_REVISION);
    const needle = `ENGINE_REVISION = ${from};`;
    assert.equal(revisionText.split(needle).length - 1, 1);
    const to = from + 1;
    const rewritten = revisionText.replace(needle, `ENGINE_REVISION = ${to};`);
    assert.equal(rewritten.includes(needle), false);
    const blob = await git(dir, ["hash-object", "-w", "--stdin"], Buffer.from(rewritten));
    await git(dir, ["read-tree", BOOTSTRAP_COMMIT]);
    await git(dir, ["update-index", "--add", "--cacheinfo", `100644,${blob},core/policy/engine-revision.ts`]);
    const tree = await git(dir, ["write-tree"]);
    const driftedCommit = await git(dir, ["commit-tree", tree, "-p", BOOTSTRAP_COMMIT, "-m", "revision drift"]);
    await git(dir, ["update-ref", "HEAD", driftedCommit]);
    const driftedRevision = await runCli(dir, ["--base", driftedCommit]);
    assertRejected(driftedRevision, "revision", "bootstrap_baseline_revision_mismatch");
    assert.equal(driftedRevision.parsed.baseline, driftedCommit);
    assert.equal(driftedRevision.parsed.bootstrapFrom, BOOTSTRAP_COMMIT);
    assert.equal(driftedRevision.parsed.bootstrap, true);
    assert.equal(driftedRevision.parsed.corpusRan, false);
    assert.match(
      driftedRevision.parsed.detail,
      new RegExp(`baseline ENGINE_REVISION ${to} differs from ${BOOTSTRAP_COMMIT} ENGINE_REVISION absent`),
    );
  });

  test("a clean admitted corpus passes compare mode", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(heavyTemplate);
    const run = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
    assert.equal(run.parsed.ok, true);
    assert.equal(run.parsed.mode, "compare");
    assert.equal(run.parsed.bootstrap, false);
    assert.equal(run.parsed.corpusRan, true);
    assert.equal(run.parsed.corpusOk, true);
    assert.deepEqual(run.parsed.changedCases, []);
    assert.equal(run.parsed.oldDigest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(run.parsed.newDigest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(run.parsed.expectedDigest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(run.parsed.caseCount, BOOTSTRAP_CASE_COUNT);
    assert.equal(run.parsed.collationWitness, true);
    assert.equal(run.parsed.oldRevision, 2);
    assert.equal(run.parsed.newRevision, 2);
    const corpus = path.join(dir, "policy-spec");
    const enumerated = await enumeratedCaseIds(corpus);
    assert.equal(enumerated.length, BOOTSTRAP_CASE_COUNT);
    const resultsPath = path.join(dir, "owned-spec-results.json");
    const spec = await runCopiedSpec(dir, resultsPath);
    assert.equal(spec.error, undefined, spec.error?.message);
    assert.equal(spec.status, 0, `${spec.stderr}\n${spec.stdout}`);
    const result = JSON.parse(await fsp.readFile(resultsPath, "utf8"));
    assert.equal(result.ok, true);
    assert.equal(result.digest.count, BOOTSTRAP_CASE_COUNT);
    assert.equal(result.digest.digest, BOOTSTRAP_EXPECTED_DIGEST);
    assert.equal(result.cases.length, BOOTSTRAP_CASE_COUNT);
    const ids = result.cases.map((row) => row.id);
    assert.equal(new Set(ids).size, BOOTSTRAP_CASE_COUNT);
    ids.sort((a, b) => a.localeCompare(b, "en"));
    assert.deepEqual(ids, enumerated);
  });

  test("version increase with an empty case list passes and reruns the corpus", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(historyTemplate, { ownCore: true });
    const bumped = await bumpEngineRevision(dir);
    const anchor = await worktreeAnchor(dir);
    assert.equal(anchor, COMPACT_BUNDLE_ANCHOR);
    await replaceFile(
      path.join(dir, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: COMPACT_EXPECTED_DIGEST,
          newDigest: COMPACT_EXPECTED_DIGEST,
          oldRevision: bumped.from,
          newRevision: bumped.to,
          oldBundleAnchor: anchor,
          newBundleAnchor: anchor,
          reason: "Record the engine revision binding without a fixture byte change.",
        }),
      ]),
    );
    const run = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
    assert.equal(run.parsed.ok, true);
    assert.equal(run.parsed.corpusRan, true);
    assert.equal(run.parsed.corpusOk, true);
    assert.equal(run.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.equal(run.parsed.oldDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(run.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(run.parsed.newRevision, bumped.to);
    assert.deepEqual(run.parsed.changedCases, []);
    assert.equal(run.parsed.hashBinding.bumpedRevision, bumped.to + 1);
    assert.notEqual(run.parsed.hashBinding.liveHash, run.parsed.hashBinding.bumpedHash);
  });

  test("a context byte change with its exact case passes the corpus", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(historyTemplate);
    const context = path.join(dir, "policy-spec", "normal", "ls", "context.json");
    const text = await fsp.readFile(context, "utf8");
    assert.match(text, /"note": "列目录。"/);
    const status = JSON.parse(text).provenance.status;
    const oldAnchor = await worktreeAnchor(dir);
    assert.equal(oldAnchor, COMPACT_BUNDLE_ANCHOR);
    const updated = text.replace('"note": "列目录。"', '"note": "列目录。guard"');
    assert.equal(JSON.parse(updated).provenance.status, status);
    await replaceFile(context, updated);
    const newAnchor = await worktreeAnchor(dir);
    assert.notEqual(newAnchor, oldAnchor);
    await replaceFile(
      path.join(dir, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: COMPACT_EXPECTED_DIGEST,
          newDigest: COMPACT_EXPECTED_DIGEST,
          oldRevision: 2,
          newRevision: 2,
          oldBundleAnchor: oldAnchor,
          newBundleAnchor: newAnchor,
          reason: "Record a non-expected context note change.",
          cases: ["normal/ls"],
        }),
      ]),
    );
    const run = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
    assert.equal(run.parsed.ok, true);
    assert.equal(run.parsed.corpusRan, true);
    assert.equal(run.parsed.corpusOk, true);
    assert.equal(run.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(run.parsed.changedCases, ["normal/ls"]);
    assert.equal(run.parsed.oldDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(run.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
  });

  test("an accurate entry does not waive an engine mismatch", { timeout: 120_000 }, async () => {
    const dir = await cloneRepo(heavyTemplate, { ownCore: true });
    const expected = path.join(dir, "policy-spec", "normal", "ls", "expected.json");
    const text = await fsp.readFile(expected, "utf8");
    assert.match(text, /"decision": "log"/);
    const oldAnchor = await worktreeAnchor(dir);
    await replaceFile(expected, text.replace('"decision": "log"', '"decision": "block"'));
    const newAnchor = await worktreeAnchor(dir);
    assert.notEqual(newAnchor, oldAnchor);
    const bumped = await bumpEngineRevision(dir);
    const first = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(first, "intended_changes", "missing_entry");
    assert.equal(first.parsed.corpusRan, false);
    assert.match(first.parsed.newDigest, /^[0-9a-f]{64}$/);
    assert.notEqual(first.parsed.newDigest, BOOTSTRAP_EXPECTED_DIGEST);
    await replaceFile(
      path.join(dir, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: BOOTSTRAP_EXPECTED_DIGEST,
          newDigest: first.parsed.newDigest,
          oldRevision: bumped.from,
          newRevision: bumped.to,
          oldBundleAnchor: oldAnchor,
          newBundleAnchor: newAnchor,
          reason: "Claim the directory listing blocks.",
          cases: ["normal/ls"],
        }),
      ]),
    );
    const second = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(second.error, undefined, second.error?.message);
    assert.equal(second.status, 1, second.stdout);
    assert.equal(second.parsed.stage, "corpus");
    assert.equal(second.parsed.code, "result_mismatch");
    assert.equal(second.parsed.corpusRan, true);
    assert.equal(second.parsed.corpusOk, false);
    assert.notEqual(second.parsed.code, "import_error");
  });

  test("a committed context entry does not cover the next unchanged tree or the same case", { timeout: 180_000 }, async () => {
    const dir = await cloneRepo(historyTemplate, { seedIndex: true });
    const context = path.join(dir, "policy-spec", "normal", "ls", "context.json");
    const original = await fsp.readFile(context, "utf8");
    assert.match(original, /"note": "列目录。"/);
    const oldAnchor = await worktreeAnchor(dir);
    assert.equal(oldAnchor, COMPACT_BUNDLE_ANCHOR);
    await replaceFile(context, original.replace('"note": "列目录。"', '"note": "列目录。guard"'));
    const midAnchor = await worktreeAnchor(dir);
    assert.notEqual(midAnchor, oldAnchor);
    const firstEntry = entry({
      oldDigest: COMPACT_EXPECTED_DIGEST,
      newDigest: COMPACT_EXPECTED_DIGEST,
      oldRevision: 2,
      newRevision: 2,
      oldBundleAnchor: oldAnchor,
      newBundleAnchor: midAnchor,
      reason: "Record a non-expected context note change.",
      cases: ["normal/ls"],
    });
    await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), block([firstEntry]));
    const first = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(first.status, 0, `${first.stderr}\n${first.stdout}`);
    assert.equal(first.parsed.corpusOk, true);
    assert.equal(first.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(first.parsed.changedCases, ["normal/ls"]);

    await git(dir, ["add", "--", "INTENDED_CHANGES.md", "policy-spec"]);
    await git(dir, ["commit", "-q", "-m", "context note"]);
    const unchanged = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(unchanged.status, 0, `${unchanged.stderr}\n${unchanged.stdout}`);
    assert.equal(unchanged.parsed.corpusOk, true);
    assert.equal(unchanged.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(unchanged.parsed.changedCases, []);

    const midText = await fsp.readFile(context, "utf8");
    await replaceFile(context, midText.replace('"note": "列目录。guard"', '"note": "列目录。guard-2"'));
    const newAnchor = await worktreeAnchor(dir);
    assert.notEqual(newAnchor, midAnchor);
    const stale = await runCli(dir, ["--base", "HEAD"]);
    assertRejected(stale, "intended_changes", "missing_entry");

    const secondEntry = entry({
      oldDigest: COMPACT_EXPECTED_DIGEST,
      newDigest: COMPACT_EXPECTED_DIGEST,
      oldRevision: 2,
      newRevision: 2,
      oldBundleAnchor: midAnchor,
      newBundleAnchor: newAnchor,
      reason: "Record the next context note change.",
      cases: ["normal/ls"],
    });
    await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), block([firstEntry, secondEntry]));
    const fresh = await runCli(dir, ["--base", "HEAD"]);
    assert.equal(fresh.status, 0, `${fresh.stderr}\n${fresh.stdout}`);
    assert.equal(fresh.parsed.corpusOk, true);
    assert.equal(fresh.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(fresh.parsed.changedCases, ["normal/ls"]);
  });

  test("an owned rule mutation mismatches an unchanged compact case", { timeout: 120_000 }, async () => {
    const protectedRels = [
      "src/lib/monitor/rules.ts",
      "src/lib/monitor/engine.ts",
      "core/policy/engine-revision.ts",
    ];
    const protectedHashes = new Map();
    for (const rel of protectedRels) {
      protectedHashes.set(rel, sha256(await fsp.readFile(path.join(root, ...rel.split("/")))));
    }
    const dir = await cloneRepo(historyTemplate, { ownSrc: true, ownCore: true });
    const revisionFile = path.join(dir, "core", "policy", "engine-revision.ts");
    const revisionStat = await fsp.lstat(revisionFile);
    assert.equal(revisionStat.isSymbolicLink(), false);
    const revisionReal = await fsp.realpath(revisionFile);
    const revisionRel = path.relative(await fsp.realpath(dir), revisionReal);
    assert.equal(revisionRel.startsWith("..") || path.isAbsolute(revisionRel), false, revisionReal);
    assert.notEqual(revisionStat.ino, (await fsp.stat(path.join(root, "core", "policy", "engine-revision.ts"))).ino);
    const targetDir = path.join(dir, "policy-spec", ...UNCHANGED_TARGET_ID.split("/"));
    const targetHashes = new Map();
    for (const name of CASE_FILES) {
      const hash = sha256(await fsp.readFile(path.join(targetDir, name)));
      assert.equal(hash, COMPACT_SOURCE_HASHES[`${UNCHANGED_TARGET_ID}/${name}`]);
      targetHashes.set(name, hash);
    }
    const contextPath = path.join(dir, "policy-spec", "normal", "ls", "context.json");
    const originalContext = await fsp.readFile(contextPath, "utf8");
    const originalStatus = JSON.parse(originalContext).provenance.status;
    assert.match(originalContext, /"note": "列目录。"/);
    const oldAnchor = await worktreeAnchor(dir);
    assert.equal(oldAnchor, COMPACT_BUNDLE_ANCHOR);
    const updatedContext = originalContext.replace('"note": "列目录。"', '"note": "列目录。unchanged-case"');
    assert.notEqual(updatedContext, originalContext);
    const updatedBundle = JSON.parse(updatedContext);
    assert.equal(updatedBundle.provenance.status, originalStatus);
    assert.equal(updatedBundle.provenance.note, "列目录。unchanged-case");
    await replaceFile(contextPath, updatedContext);
    for (const name of ["input.json", "policy.json", "expected.json"]) {
      assert.equal(
        sha256(await fsp.readFile(path.join(dir, "policy-spec", "normal", "ls", name))),
        COMPACT_SOURCE_HASHES[`normal/ls/${name}`],
      );
    }
    const newAnchor = await worktreeAnchor(dir);
    assert.notEqual(newAnchor, oldAnchor);
    const official = await expectedDigest(path.join(dir, "policy-spec"));
    assert.equal(official.count, COMPACT_CASE_COUNT);
    assert.equal(official.digest, COMPACT_EXPECTED_DIGEST);
    await replaceFile(
      path.join(dir, "INTENDED_CHANGES.md"),
      block([
        entry({
          oldDigest: COMPACT_EXPECTED_DIGEST,
          newDigest: COMPACT_EXPECTED_DIGEST,
          oldRevision: 2,
          newRevision: 2,
          oldBundleAnchor: oldAnchor,
          newBundleAnchor: newAnchor,
          reason: "Only normal context changed; target fixture remains unchanged.",
          cases: ["normal/ls"],
        }),
      ]),
    );
    const record = parseIntendedChanges(await fsp.readFile(path.join(dir, "INTENDED_CHANGES.md"), "utf8"));
    assert.equal(record.ok, true, record.detail);
    assert.deepEqual(record.entries[0].cases, ["normal/ls"]);
    assert.equal(record.entries[0].oldBundleAnchor, oldAnchor);
    assert.equal(record.entries[0].newBundleAnchor, newAnchor);
    assert.equal(record.entries[0].oldRevision, 2);
    assert.equal(record.entries[0].newRevision, 2);
    const baseline = await git(dir, ["rev-parse", "HEAD"]);
    const control = await runCli(dir, ["--base", baseline]);
    assert.equal(control.status, 0, `${control.stderr}\n${control.stdout}`);
    assert.equal(control.parsed.ok, true);
    assert.equal(control.parsed.corpusRan, true);
    assert.equal(control.parsed.corpusOk, true);
    assert.equal(control.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(control.parsed.changedCases, ["normal/ls"]);
    assert.equal(control.parsed.oldDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(control.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(control.parsed.oldRevision, 2);
    assert.equal(control.parsed.newRevision, 2);
    const rulesPath = path.join(dir, "src", "lib", "monitor", "rules.ts");
    await assertOwnedSrc(dir);
    const rulesText = await fsp.readFile(rulesPath, "utf8");
    assert.match(rulesText, /id: "curl_post_local_file"/);
    // Mutate the owned source before its immutable catalog is published. Editing
    // RULES after publication must now throw; an import error is not this test's oracle.
    // Deleting the id fails the protection partition during import, so the pattern is
    // neutered and the id stays in the catalog.
    const publication = "export const RULES: readonly RuleDef[] = freezeRuleData(BUILTIN_RULES);";
    assert.equal(rulesText.split(publication).length - 1, 1, "unique immutable publication anchor");
    const ownedPattern = 'pattern: "\\\\bcurl\\\\b[^\\\\n]*(\\\\s-d\\\\s+@|--data(-binary|-raw|-ascii)?\\\\s+@|--data-urlencode\\\\s+@)",';
    assert.equal(rulesText.split(ownedPattern).length - 1, 1, "unique curl_post_local_file pattern");
    assert.ok(rulesText.indexOf(ownedPattern) < rulesText.indexOf(publication), "pattern mutation stays before publication");
    beginWork();
    await replaceFile(rulesPath, rulesText.replace(ownedPattern, 'pattern: "\\\\bowned_mutant_no_match\\\\b",'));
    const mutant = await runCli(dir, ["--base", baseline]);
    assert.equal(mutant.error, undefined, mutant.error?.message);
    assert.equal(mutant.status, 1, mutant.stdout);
    assert.equal(mutant.parsed.stage, "corpus");
    assert.equal(mutant.parsed.code, "result_mismatch");
    assert.equal(mutant.parsed.corpusRan, true);
    assert.equal(mutant.parsed.corpusOk, false);
    assert.equal(mutant.parsed.detail.startsWith(`${UNCHANGED_TARGET_ID} `), true, mutant.parsed.detail);
    assert.match(mutant.parsed.detail, /"expectedRuleId": "curl_post_local_file"/);
    assert.match(mutant.parsed.detail, /"observedRuleId": "archive_project_root"/);
    assert.deepEqual(mutant.parsed.changedCases, ["normal/ls"]);
    assert.equal(mutant.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.equal(mutant.parsed.oldDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(mutant.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(mutant.parsed.oldRevision, 2);
    assert.equal(mutant.parsed.newRevision, 2);
    await replaceFile(rulesPath, rulesText);
    assert.equal(await fsp.readFile(rulesPath, "utf8"), rulesText, "restore exact original catalog source");
    const restored = await runCli(dir, ["--base", baseline]);
    assert.equal(restored.status, 0, `${restored.stderr}\n${restored.stdout}`);
    assert.equal(restored.parsed.ok, true);
    assert.equal(restored.parsed.corpusRan, true);
    assert.equal(restored.parsed.corpusOk, true);
    assert.equal(restored.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(restored.parsed.changedCases, ["normal/ls"]);
    assert.equal(restored.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
    for (const name of CASE_FILES) {
      assert.equal(sha256(await fsp.readFile(path.join(targetDir, name))), targetHashes.get(name));
    }
    for (const rel of protectedRels) {
      assert.equal(sha256(await fsp.readFile(path.join(root, ...rel.split("/")))), protectedHashes.get(rel), rel);
    }
  });

  test("a later privacy case can be added and deleted with exact anchors", { timeout: 120_000 }, async () => {
    assert.equal(ADDITION_CASE_ID.split("/").length, 3);
    assert.equal("privacy/area-extension/01".localeCompare(ADDITION_CASE_ID, "en") < 0, true);
    const dir = await cloneRepo(historyTemplate, { ownCore: true, seedIndex: true });
    const corpus = path.join(dir, "policy-spec");
    const baseline = await git(dir, ["rev-parse", "HEAD"]);
    const oldAnchor = await worktreeAnchor(dir);
    assert.equal(oldAnchor, COMPACT_BUNDLE_ANCHOR);
    await copyLockedCase(corpus, ADDITION_CASE_ID, ADDITION_SOURCE_HASHES);
    const added = await expectedDigest(corpus);
    assert.equal(added.count, ADDITION_CASE_COUNT);
    assert.equal(added.digest, ADDITION_EXPECTED_DIGEST);
    const addedAnchor = await worktreeAnchor(dir);
    assert.equal(addedAnchor, ADDITION_BUNDLE_ANCHOR);
    const metaPath = path.join(corpus, "PROPOSED_DIGEST.txt");
    const originalMeta = await fsp.readFile(metaPath, "utf8");
    assert.equal(originalMeta, compactProposedText);
    await replaceFile(metaPath, withProposedCount(originalMeta, ADDITION_CASE_COUNT, ADDITION_EXPECTED_DIGEST));
    const addedBump = await bumpEngineRevision(dir);
    const addEntry = entry({
      oldDigest: COMPACT_EXPECTED_DIGEST,
      newDigest: ADDITION_EXPECTED_DIGEST,
      oldRevision: addedBump.from,
      newRevision: addedBump.to,
      oldBundleAnchor: oldAnchor,
      newBundleAnchor: addedAnchor,
      reason: "Add a second approved privacy area-extension case.",
      cases: [ADDITION_CASE_ID],
    });
    await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), block([addEntry]));
    const addition = await runCli(dir, ["--base", baseline]);
    assert.equal(addition.status, 0, `${addition.stderr}\n${addition.stdout}`);
    assert.equal(addition.parsed.ok, true);
    assert.equal(addition.parsed.corpusRan, true);
    assert.equal(addition.parsed.corpusOk, true);
    assert.equal(addition.parsed.caseCount, ADDITION_CASE_COUNT);
    assert.deepEqual(addition.parsed.changedCases, [ADDITION_CASE_ID]);
    assert.equal(addition.parsed.oldDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(addition.parsed.newDigest, ADDITION_EXPECTED_DIGEST);
    assert.equal(addition.parsed.oldRevision, addedBump.from);
    assert.equal(addition.parsed.newRevision, addedBump.to);
    assert.equal(addition.parsed.hashBinding.bumpedRevision, addedBump.to + 1);
    await git(dir, ["add", "--", "INTENDED_CHANGES.md", "policy-spec", "core/policy/engine-revision.ts"]);
    await git(dir, ["commit", "-q", "-m", "add privacy area-extension 02"]);
    const middle = await git(dir, ["rev-parse", "HEAD"]);
    assert.notEqual(middle, baseline);
    const addedDir = path.join(corpus, ...ADDITION_CASE_ID.split("/"));
    await fsp.rm(addedDir, { recursive: true });
    assert.equal(fs.existsSync(addedDir), false);
    await replaceFile(metaPath, originalMeta);
    const removed = await expectedDigest(corpus);
    assert.equal(removed.count, COMPACT_CASE_COUNT);
    assert.equal(removed.digest, COMPACT_EXPECTED_DIGEST);
    const removedAnchor = await worktreeAnchor(dir);
    assert.equal(removedAnchor, COMPACT_BUNDLE_ANCHOR);
    const removedBump = await bumpEngineRevision(dir);
    assert.equal(removedBump.from, addedBump.to);
    const deleteEntry = entry({
      oldDigest: ADDITION_EXPECTED_DIGEST,
      newDigest: COMPACT_EXPECTED_DIGEST,
      oldRevision: removedBump.from,
      newRevision: removedBump.to,
      oldBundleAnchor: addedAnchor,
      newBundleAnchor: removedAnchor,
      reason: "Delete the added privacy case and keep the category member.",
      cases: [ADDITION_CASE_ID],
    });
    await replaceFile(path.join(dir, "INTENDED_CHANGES.md"), block([addEntry, deleteEntry]));
    const record = parseIntendedChanges(await fsp.readFile(path.join(dir, "INTENDED_CHANGES.md"), "utf8"));
    assert.equal(record.ok, true, record.detail);
    assert.equal(record.entries.length, 2);
    assert.deepEqual(record.entries[0].cases, [ADDITION_CASE_ID]);
    assert.deepEqual(record.entries[1].cases, [ADDITION_CASE_ID]);
    assert.equal(record.entries[0].oldBundleAnchor, COMPACT_BUNDLE_ANCHOR);
    assert.equal(record.entries[0].newBundleAnchor, ADDITION_BUNDLE_ANCHOR);
    assert.equal(record.entries[1].oldBundleAnchor, ADDITION_BUNDLE_ANCHOR);
    assert.equal(record.entries[1].newBundleAnchor, COMPACT_BUNDLE_ANCHOR);
    assert.equal(record.entries[0].newRevision, addedBump.to);
    assert.equal(record.entries[1].newRevision, removedBump.to);
    const deletion = await runCli(dir, ["--base", middle]);
    assert.equal(deletion.status, 0, `${deletion.stderr}\n${deletion.stdout}`);
    assert.equal(deletion.parsed.ok, true);
    assert.equal(deletion.parsed.corpusRan, true);
    assert.equal(deletion.parsed.corpusOk, true);
    assert.equal(deletion.parsed.caseCount, COMPACT_CASE_COUNT);
    assert.deepEqual(deletion.parsed.changedCases, [ADDITION_CASE_ID]);
    assert.equal(deletion.parsed.oldDigest, ADDITION_EXPECTED_DIGEST);
    assert.equal(deletion.parsed.newDigest, COMPACT_EXPECTED_DIGEST);
    assert.equal(deletion.parsed.oldRevision, removedBump.from);
    assert.equal(deletion.parsed.newRevision, removedBump.to);
    assert.equal(deletion.parsed.hashBinding.bumpedRevision, removedBump.to + 1);
    for (const name of CASE_FILES) {
      const rel = `privacy/area-extension/01/${name}`;
      assert.equal(sha256(await fsp.readFile(path.join(corpus, "privacy", "area-extension", "01", name))), COMPACT_SOURCE_HASHES[rel]);
    }
    await git(dir, ["add", "--", "INTENDED_CHANGES.md", "policy-spec", "core/policy/engine-revision.ts"]);
    await git(dir, ["commit", "-q", "-m", "delete privacy area-extension 02"]);
    assert.equal(await git(dir, ["status", "--porcelain"]), "");
  });

  test("a timed out owned child exits before its directory is removed", async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-cancel-"));
    keep.push(dir);
    // Keep ownership evidence outside the directory whose deletion we test.
    const ownerDir = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-owner-"));
    keep.push(ownerDir);
    const pidFile = path.join(ownerDir, "grandchild.pid");
    const marker = path.join(dir, "marker.txt");
    const stopFile = path.join(ownerDir, "stop");
    const stoppedFile = path.join(ownerDir, "stopped");
    const grandchild = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const marker = process.argv[1];",
      "const stopFile = process.argv[2];",
      "const stoppedFile = process.argv[3];",
      "const ownerDir = path.dirname(stopFile);",
      "let timer;",
      "const stop = () => {",
      "  clearInterval(timer);",
      "  if (fs.existsSync(ownerDir)) fs.writeFileSync(stoppedFile, 'stopped');",
      "  process.exit(0);",
      "};",
      // Bound the fixture lifetime even if killTree is mutated. No cleanup
      // ever signals a historical PID: the private stop file is authoritative.
      "setTimeout(stop, 15_000);",
      "const write = () => {",
      "  if (fs.existsSync(stopFile) || !fs.existsSync(ownerDir)) return stop();",
      "  fs.mkdirSync(path.dirname(marker), { recursive: true });",
      "  fs.appendFileSync(marker, 'x');",
      "};",
      "write();",
      "timer = setInterval(write, 30);",
    ].join("");
    const parent = [
      "const fs = require('node:fs');",
      "const { spawn } = require('node:child_process');",
      "const marker = process.argv[1];",
      "const code = process.argv[2];",
      "const pidFile = process.argv[3];",
      "const stopFile = process.argv[4];",
      "const stoppedFile = process.argv[5];",
      "setTimeout(() => process.exit(0), 15_000);",
      "const child = spawn(process.execPath, ['-e', code, marker, stopFile, stoppedFile], { windowsHide: true, stdio: 'ignore', detached: process.platform === 'win32' });",
      "if (child.pid) fs.writeFileSync(pidFile, String(child.pid));",
      "const poll = setInterval(() => {",
      "  if (!fs.existsSync(marker) || fs.statSync(marker).size === 0) return;",
      "  clearInterval(poll);",
      "  process.stdout.write('ready\\n');",
      "}, 10);",
    ].join("");
    try {
      const started = Date.now();
      const result = await spawnCollected(process.execPath, ["-e", parent, marker, grandchild, pidFile, stopFile, stoppedFile], {
        timeout: 5_000,
        maxBuffer: 1024 * 1024,
      });
      const exitedAt = Date.now();
      assert.equal(result.error?.code, "ETIMEDOUT");
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout.toString("utf8"), "ready\n", "grandchild must write before timeout");
      assert.ok(result.pid);
      let alive = true;
      try {
        process.kill(result.pid, 0);
      } catch {
        alive = false;
      }
      assert.equal(alive, false);
      assert.equal(fs.existsSync(stoppedFile), false, "fixture fallback must not establish death");
      const size = fs.existsSync(marker) ? (await fsp.stat(marker)).size : 0;
      assert.ok(size > 0);
      await new Promise((resolve) => setTimeout(resolve, 150));
      const later = fs.existsSync(marker) ? (await fsp.stat(marker)).size : 0;
      assert.equal(later, size);
      assert.ok(exitedAt >= started);
      const cleanedAt = Date.now();
      assert.ok(cleanedAt >= exitedAt);
      await fsp.rm(dir, { recursive: true, force: true });
      await new Promise((resolve) => setTimeout(resolve, 200));
      assert.equal(fs.existsSync(dir), false);
      assert.equal(fs.existsSync(marker), false);
      assert.equal(fs.existsSync(stoppedFile), false, "fixture fallback must not establish stability");
    } finally {
      // Written only after the death/growth/deletion assertions. The fixture
      // clears its writer before acknowledging, so mutant cleanup cannot hide
      // a surviving grandchild. A historical PID is observation only.
      await fsp.writeFile(stopFile, "stop");
      const writerGone = async () => {
        if (!fs.existsSync(pidFile)) return false;
        const pid = Number(await fsp.readFile(pidFile, "utf8"));
        assert.ok(Number.isSafeInteger(pid) && pid > 0, "recorded owned grandchild pid");
        try {
          process.kill(pid, 0);
        } catch (error) {
          assert.equal(error.code, "ESRCH", "unexpected owned writer observation error");
          return true;
        }
        if (process.platform === "linux") {
          // Container init may leave an already-dead orphan as a zombie.
          // This is read-only; PID reuse can never cause an unrelated kill.
          try {
            const stat = await fsp.readFile(`/proc/${pid}/stat`, "utf8");
            return /^[ZX] /.test(stat.slice(stat.lastIndexOf(")") + 2));
          } catch (error) {
            assert.equal(error.code, "ENOENT", "unexpected process status observation error");
            return true;
          }
        }
        return false;
      };
      const cleanupDeadline = Date.now() + 20_000;
      while (!fs.existsSync(stoppedFile) && !(await writerGone())) {
        assert.ok(Date.now() < cleanupDeadline, "owned writer did not acknowledge stop or exit");
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await fsp.rm(dir, { recursive: true, force: true });
      await fsp.rm(ownerDir, { recursive: true, force: true });
    }
  });

  test("node:test cancellation drains owned work before deleting temp directories", { timeout: 60_000 }, async () => {
    const scratch = await fsp.mkdtemp(path.join(os.tmpdir(), "nmzp-guard-cancel-probe-"));
    keep.push(scratch);
    const emptyMarker = path.join(scratch, "empty.txt");
    const cancelMarker = path.join(scratch, "cancel.txt");
    const deadlineMarker = path.join(scratch, "deadline.txt");
    const cancelDir = path.join(scratch, "cancel-work");
    const deadlineDir = path.join(scratch, "deadline-work");
    await fsp.writeFile(emptyMarker, "");
    await fsp.writeFile(cancelMarker, "");
    await fsp.writeFile(deadlineMarker, "");

    const empty = await runCancelProbe("empty", emptyMarker);
    const emptyReturnedAt = Date.now();
    const emptyOut = `${empty.stdout.toString("utf8")}\n${empty.stderr.toString("utf8")}`;
    assert.equal(empty.status, 0, emptyOut);
    assert.match(emptyOut, /pass 1/);
    assert.match(emptyOut, /fail 0/);
    assert.match(emptyOut, /cancelled 0/);
    assert.match(emptyOut, /skipped 0/);
    const emptyEvents = cancelMarkerEvents(await fsp.readFile(emptyMarker, "utf8"));
    assert.ok(markerAt(emptyEvents, "empty-test") < markerAt(emptyEvents, "after-start"));
    assert.ok(markerAt(emptyEvents, "after-start") < markerAt(emptyEvents, "drain-done"));
    assert.ok(markerAt(emptyEvents, "drain-done") < markerAt(emptyEvents, "deleted"));
    assert.equal(emptyEvents.at(-1).event, "deleted");
    const emptyDrainMs =
      emptyEvents.find((item) => item.event === "drain-done").at -
      emptyEvents.find((item) => item.event === "after-start").at;
    assert.ok(emptyDrainMs < 1_000, `empty drain took ${emptyDrainMs}ms`);
    assert.ok(emptyReturnedAt - emptyEvents.at(-1).at < 2_500, `empty probe lingered ${emptyReturnedAt - emptyEvents.at(-1).at}ms`);

    const cancel = await runCancelProbe("1", cancelMarker, cancelDir);
    const cancelReturnedAt = Date.now();
    const cancelOut = `${cancel.stdout.toString("utf8")}\n${cancel.stderr.toString("utf8")}`;
    assert.equal(cancel.status, 1, cancelOut);
    assert.match(cancelOut, /cancelled 1/);
    assert.match(cancelOut, /skipped 0/);
    assert.match(cancelOut, /test timed out/);
    assert.doesNotMatch(cancelOut, /skipped [1-9]/);
    const cancelEvents = cancelMarkerEvents(await fsp.readFile(cancelMarker, "utf8"));
    const pos = (name) => markerAt(cancelEvents, name);
    assert.ok(pos("test-start") < pos("work-started"));
    assert.ok(pos("work-started") < pos("signal-abort"));
    assert.ok(pos("signal-abort") < pos("after-start"));
    assert.ok(pos("after-start") < pos("continuation"));
    assert.ok(pos("continuation") < pos("continuation-blocked"));
    assert.ok(pos("continuation-blocked") < pos("slow-blocked"));
    assert.ok(pos("slow-blocked") < pos("drain-done"));
    assert.ok(pos("drain-done") < pos("deleted"));
    assert.ok(pos("child-exit") < pos("drain-done"));
    assert.equal(cancelEvents.at(-1).event, "deleted");
    assert.equal(
      cancelEvents.some((item) => item.event === "slow-wrote" || item.event === "continuation-wrote"),
      false,
    );
    const pidEvents = cancelEvents.filter((item) => item.event.startsWith("child-pid:"));
    assert.equal(pidEvents.length, 1, pidEvents.map((item) => item.event).join(","));
    const pid = Number(pidEvents[0].event.slice("child-pid:".length));
    assert.equal(Number.isInteger(pid) && pid > 0, true);
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch {
      alive = false;
    }
    assert.equal(alive, false);
    assert.equal(fs.existsSync(cancelDir), false);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(fs.existsSync(cancelDir), false);
    assert.equal(fs.existsSync(path.join(cancelDir, "late")), false);
    assert.equal(fs.existsSync(path.join(cancelDir, "slow")), false);
    assert.equal(fs.existsSync(path.join(cancelDir, "linked")), false);
    assert.ok(
      cancelReturnedAt - cancelEvents.at(-1).at < 2_500,
      `cancel probe lingered ${cancelReturnedAt - cancelEvents.at(-1).at}ms after delete`,
    );

    const deadline = await runCancelProbe("deadline", deadlineMarker, deadlineDir);
    const deadlineOut = `${deadline.stdout.toString("utf8")}\n${deadline.stderr.toString("utf8")}`;
    assert.equal(deadline.status, 1, deadlineOut);
    assert.match(deadlineOut, /owned work still running at drain deadline/);
    assert.match(deadlineOut, /skipped 0/);
    assert.doesNotMatch(deadlineOut, /skipped [1-9]/);
    const deadlineEvents = cancelMarkerEvents(await fsp.readFile(deadlineMarker, "utf8"));
    assert.ok(markerAt(deadlineEvents, "scheduled") < markerAt(deadlineEvents, "after-start"));
    assert.equal(
      deadlineEvents.some((item) => item.event === "deleted" || item.event === "drain-done"),
      false,
    );
    assert.equal(fs.existsSync(deadlineDir), true);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(fs.existsSync(deadlineDir), true);
    assert.equal(fs.existsSync(path.join(deadlineDir, "late")), false);
  });

  test("win32 8.3 short path is the same tree and another directory is not", { timeout: 120_000 }, async (t) => {
    if (process.platform !== "win32") {
      t.skip("8.3 short-name root check is win32-only");
      return;
    }
    const dir = await cloneRepo(lightTemplate);
    const alias = await windowsShortDirectory(dir);
    if (!alias.ok) {
      t.skip(alias.reason);
      return;
    }
    const run = await runCli(alias.short, ["--base", "HEAD"]);
    assert.equal(run.error, undefined, run.error?.message);
    assert.ok(run.parsed, `${run.stderr}\n${run.stdout}`);
    assert.notEqual(run.parsed.code, "root_mismatch", JSON.stringify(run.parsed));
    assert.match(run.parsed.baseline, /^[0-9a-f]{40}$/, JSON.stringify(run.parsed));

    const other = await cloneRepo(lightTemplate);
    assert.notEqual(fs.realpathSync.native(other).toLowerCase(), fs.realpathSync.native(alias.short).toLowerCase());
    const script = path.join(alias.short, "scripts", "policy-compat-guard.mjs");
    const mismatch = await runCli(other, ["--base", "HEAD"], {}, script);
    assertRejected(mismatch, "baseline", "root_mismatch");
    assert.equal(mismatch.parsed.detail, "guard script and git toplevel are different trees");
  });
});
}
