import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  AUTHORIZED_BASELINE_SHA,
  LIMITATION_FRESH_PROCESS,
  LIMITATION_HOST_REAL,
  LIMITATION_LEGACY,
  MODE_ALL,
  MODE_LEGACY,
  MODE_SUBPROCESS,
  REPO_ROOT,
  classifyHookOutput,
  collectOwnedSamples,
  isolatedChildEnv,
  ownedClosed,
  parseBenchArgs,
  percentile,
  proveOfflineOutbox,
  proveOnlineEvent,
  redact,
  renderReport,
  runSubprocessScenarios,
  spawnHookSample,
  summarizeScenario,
  syntheticReadPayload,
  unavailableCells,
} from "./bench-hook.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const script = join(root, "scripts", "bench-hook.mjs");

function isolatedSpawnEnv() {
  const env = { ...process.env };
  delete env.NODE_CHANNEL_FD;
  delete env.NODE_TEST_CONTEXT;
  for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
  return env;
}

function runCli(args) {
  return spawnSync(process.execPath, ["--experimental-strip-types", script, ...args], {
    cwd: root,
    env: isolatedSpawnEnv(),
    encoding: "utf8",
    windowsHide: true,
  });
}

describe("bench-hook argument bounds", () => {
  it("keeps a lone numeric argument as labeled legacy mode", () => {
    assert.deepEqual(parseBenchArgs(["10"]), {
      help: false,
      samples: 10,
      mode: MODE_LEGACY,
      timeoutMs: 15_000,
      reportPath: null,
    });
    assert.equal(parseBenchArgs([]).samples, 30);
    assert.equal(parseBenchArgs([]).mode, MODE_LEGACY);
  });

  it("accepts --subprocess and --all with the same sample bounds", () => {
    assert.equal(parseBenchArgs(["--subprocess", "10"]).mode, MODE_SUBPROCESS);
    assert.equal(parseBenchArgs(["--subprocess", "10"]).samples, 10);
    assert.equal(parseBenchArgs(["--all", "10"]).mode, MODE_ALL);
    assert.equal(parseBenchArgs(["--mode", "spawn", "--samples", "7"]).samples, 7);
    assert.equal(parseBenchArgs(["--mode", "same-process"]).mode, MODE_LEGACY);
  });

  it("rejects out-of-range and non-integer samples with the legacy error text", () => {
    assert.throws(() => parseBenchArgs(["0"]), { message: "samples must be 1..100" });
    assert.throws(() => parseBenchArgs(["101"]), { message: "samples must be 1..100" });
    assert.throws(() => parseBenchArgs(["1.5"]), { message: "samples must be 1..100" });
    assert.throws(() => parseBenchArgs(["--subprocess", "foo"]), { message: "samples must be 1..100" });
    assert.throws(() => parseBenchArgs(["--samples", "0"]), { message: "samples must be 1..100" });
  });

  it("rejects unknown flags and timeout bounds", () => {
    assert.throws(() => parseBenchArgs(["--nope"]), { message: "unknown flag --nope" });
    assert.throws(() => parseBenchArgs(["--mode", "framework"]), { message: "unknown --mode framework" });
    assert.throws(() => parseBenchArgs(["--timeout-ms", "10"]), { message: "timeout-ms must be 1000..60000" });
    assert.throws(() => parseBenchArgs(["--timeout-ms", "60001"]), { message: "timeout-ms must be 1000..60000" });
  });

  it("CLI exits 2 on invalid samples and 0 on --help", () => {
    const bad = runCli(["0"]);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /samples must be 1\.\.100/);
    const help = runCli(["--help"]);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /legacy-same-process-loopback-warm/);
    assert.match(help.stdout, /core\/nmzp\.mjs hook --agent/);
  });
});

describe("bench-hook percentile and failed-sample accounting", () => {
  it("uses ceil(n*q)-1 on sorted successful samples", () => {
    assert.equal(percentile([10, 20, 30, 40, 50], 0.5), 30);
    assert.equal(percentile([10, 20, 30, 40, 50], 0.95), 50);
    assert.equal(percentile([10, 20], 0.5), 10);
    assert.equal(percentile([10, 20], 0.95), 20);
    assert.equal(percentile([7], 0.5), 7);
    assert.equal(percentile([], 0.5), undefined);
  });

  it("does not fold failed durations into percentiles and marks the scenario failed", () => {
    const mixed = summarizeScenario("subprocess-fresh-process-online-loopback", [
      { ok: true, protocolMs: 5, exitMs: 6 },
      { ok: false, error: "timeout", protocolMs: 15_000, exitMs: 15_000 },
      { ok: true, protocolMs: 20, exitMs: 22 },
    ]);
    assert.equal(mixed.ok, false);
    assert.equal(mixed.n, 3);
    assert.equal(mixed.nSuccess, 2);
    assert.equal(mixed.nFailed, 1);
    assert.deepEqual(mixed.rawProtocolMs, [5, 20]);
    assert.deepEqual(mixed.rawExitMs, [6, 22]);
    assert.equal(mixed.p50ProtocolMs, 5);
    assert.equal(mixed.p95ProtocolMs, 20);
    assert.equal(mixed.maxProtocolMs, 20);
    assert.equal(mixed.p50ExitMs, 6);
    assert.equal(mixed.maxExitMs, 22);
    assert.deepEqual(mixed.failedErrors, ["timeout"]);
    assert.equal(mixed.rawProtocolMs.includes(15_000), false);
    assert.equal(mixed.rawExitMs.includes(15_000), false);
  });

  it("all-failed scenarios have null percentiles and nonzero meaning", () => {
    const failed = summarizeScenario("subprocess-fresh-process-offline-cached-policy", [
      { ok: false, error: "exit_2", protocolMs: 8, exitMs: 9 },
    ]);
    assert.equal(failed.ok, false);
    assert.equal(failed.nFailed, 1);
    assert.deepEqual(failed.rawProtocolMs, []);
    assert.equal(failed.p50ProtocolMs, null);
    assert.equal(failed.p95ProtocolMs, null);
    assert.equal(failed.maxProtocolMs, null);
    assert.equal(failed.p50ExitMs, null);
    assert.deepEqual(failed.failedErrors, ["exit_2"]);
  });
});

describe("bench-hook classify and report semantics", () => {
  it("accepts grok empty-stdout allow and rejects deny or nonzero exit", () => {
    assert.deepEqual(classifyHookOutput("", 0), { ok: true, decision: "allow", content: "" });
    assert.equal(classifyHookOutput('{"decision":"deny","reason":"no_policy_cache"}\n', 2).ok, false);
    assert.equal(classifyHookOutput('{"decision":"deny","reason":"no_policy_cache"}\n', 2).error, "exit_2");
    assert.equal(classifyHookOutput('{"decision":"deny","reason":"no_policy_cache"}', 0).error, "deny:no_policy_cache");
    assert.equal(classifyHookOutput("hello", 0).error, "non_json_stdout");
    assert.equal(classifyHookOutput('{"decision":"allow"}', 0).error, "non_empty_allow_stdout");
    assert.equal(classifyHookOutput('{"hookSpecificOutput":{"permissionDecision":"deny"}}\n', 0).error, "deny:deny");
  });

  it("renderReport keeps literal labels and NOT_RUN cells", () => {
    const mixed = summarizeScenario("subprocess-fresh-process-online-loopback", [
      { ok: true, protocolMs: 5, exitMs: 6 },
      { ok: false, error: "timeout", protocolMs: 15_000, exitMs: 15_000 },
    ]);
    const md = renderReport({
      meta: {
        timestamp: "2026-09-27T00:00:00.000Z",
        node: "v24.15.0",
        os: "win32",
        arch: "arm64",
        baselineSha: AUTHORIZED_BASELINE_SHA,
        checkout: "C:\\repo",
      },
      window: {
        scenario: `${MODE_LEGACY}/window`,
        label: MODE_LEGACY,
        mode: "window",
        ok: true,
        samples: 2,
        nSuccess: 2,
        nFailed: 0,
        rawMs: [10, 20],
        p50Ms: 10,
        p95Ms: 20,
        maxMs: 20,
        limitations: LIMITATION_LEGACY,
      },
      subprocessOnline: mixed,
      subprocessOffline: {
        scenario: "subprocess-fresh-process-offline-cached-policy",
        ok: false,
        n: 0,
        nSuccess: 0,
        nFailed: 0,
        cacheProven: false,
        rawProtocolMs: [],
        p50ProtocolMs: null,
        failedErrors: ["policy_cache_missing_after_server_close"],
      },
      fixtureRemoved: true,
      notRun: unavailableCells("win32"),
    });
    assert.match(md, /legacy-same-process-loopback-warm/);
    assert.match(md, /subprocess-fresh-process-online-loopback/);
    assert.match(md, /subprocess-fresh-process-offline-cached-policy/);
    assert.match(md, /cacheProven: false/);
    assert.match(md, /ok: false/);
    assert.match(md, /nFailed: 1/);
    assert.match(md, /fixtureRemoved: true/);
    assert.match(md, new RegExp(LIMITATION_FRESH_PROCESS));
    assert.match(md, /HOST_REAL-tool-enforcement/);
    assert.match(md, /status: NOT_RUN/);
    assert.match(md, /linux-subprocess-online/);
    assert.match(md, /reboot-first-sample/);
    assert.match(md, new RegExp(AUTHORIZED_BASELINE_SHA));
    assert.match(md, /rawProtocolMs: \[5\]/);
    assert.equal(md.includes("p50ProtocolMs: 15000"), false);
    assert.equal(md.includes("maxProtocolMs: 15000"), false);
    assert.equal(md.includes("rawProtocolMs: [5,15000]"), false);
    assert.match(md, new RegExp(LIMITATION_HOST_REAL));
  });

  it("unavailable linux cells are omitted on linux and present otherwise", () => {
    const win = unavailableCells("win32");
    assert.equal(
      win.some((c) => c.scenario === "linux-subprocess-online" && c.status === "NOT_RUN"),
      true,
    );
    const linux = unavailableCells("linux");
    assert.equal(
      linux.some((c) => c.scenario.startsWith("linux-")),
      false,
    );
    assert.equal(
      linux.some((c) => c.scenario === "reboot-first-sample" && c.status === "NOT_RUN"),
      true,
    );
  });
});

describe("bench-hook checkout paths", () => {
  it("keeps default report and checkout inside this P0 tree", () => {
    assert.equal(REPO_ROOT, root);
    assert.equal(parseBenchArgs(["--report", join(root, "bench", "REPORT.md")]).reportPath, join(root, "bench", "REPORT.md"));
  });
});

describe("bench-hook isolation helpers", () => {
  it("points NMZP_HOME/HOME/USERPROFILE at the fixture and drops host/proxy vars", () => {
    const home = "C:\\tmp\\fx-home";
    const env = isolatedChildEnv(home, {
      USERPROFILE: "C:\\Users\\real",
      HOME: "C:\\Users\\real",
      NMZP_HOME: "C:\\Users\\real\\.nmzp-not-used",
      GROK_SESSION_ID: "sess",
      HTTP_PROXY: "http://example.invalid:1",
      NODE_OPTIONS: "--require leak",
      PATH: "C:\\Windows\\System32",
    });
    assert.equal(env.NMZP_HOME, home);
    assert.equal(env.USERPROFILE, home);
    assert.equal(env.HOME, home);
    assert.equal(env.GROK_SESSION_ID, undefined);
    assert.equal(env.HTTP_PROXY, undefined);
    assert.equal(env.NODE_OPTIONS, "");
    assert.equal(env.PATH, "C:\\Windows\\System32");
    assert.notEqual(env.USERPROFILE, homedir());
    assert.equal(env.TEMP, join(home, "tmp"));
  });

  it("synthetic payload is a harmless Read and redact strips bearer tokens", () => {
    const payload = syntheticReadPayload(3);
    assert.match(payload, /"tool_name":"Read"/);
    assert.match(payload, /synthetic-wp04-3\.txt/);
    assert.equal(payload.includes("Bash"), false);
    assert.equal(redact("Bearer abc.def Authorization"), "Bearer [redacted] Authorization");
    assert.match(redact('{"token":"secret","ok":true}'), /"token":"\[redacted\]"/);
  });
});

describe("bench-hook online and offline proof", () => {
  it("requires a new server event with delivered receipt and excludes fallback from percentiles", () => {
    const eventId = "wp04-on-1";
    const missing = proveOnlineEvent(eventId, [], { beforeIds: new Set(), tool: "Read", policyVersion: 1 });
    assert.equal(missing.ok, false);
    assert.equal(missing.class, "fallback");
    assert.equal(missing.error, "online_fallback");
    const stale = proveOnlineEvent(eventId, [{ id: eventId, tool: "Read", decision: "allow", enforcement: "delivered", policyVersion: 1 }], {
      beforeIds: new Set([eventId]),
    });
    assert.equal(stale.ok, false);
    assert.equal(stale.error, "stale_server_event");
    const pending = proveOnlineEvent(eventId, [{ id: eventId, tool: "Read", decision: "allow", enforcement: "pending_verify", policyVersion: 1 }], {
      beforeIds: new Set(),
      policyVersion: 1,
    });
    assert.equal(pending.ok, false);
    assert.equal(pending.error, "online_receipt_missing");
    const delivered = proveOnlineEvent(eventId, [{ id: eventId, tool: "Read", nativeTool: "Read", decision: "allow", enforcement: "delivered", policyVersion: 1 }], {
      beforeIds: new Set(),
      tool: "Read",
      policyVersion: 1,
    });
    assert.equal(delivered.ok, true);
    assert.equal(delivered.enforcement, "delivered");
    const mixed = summarizeScenario("subprocess-fresh-process-online-loopback", [
      { ok: true, class: "success", protocolMs: 5, exitMs: 6 },
      { ok: false, class: "fallback", error: "online_fallback", protocolMs: 100, exitMs: 110 },
    ]);
    assert.equal(mixed.ok, false);
    assert.equal(mixed.nFallback, 1);
    assert.equal(mixed.nSuccess, 1);
    assert.deepEqual(mixed.rawProtocolMs, [5]);
    assert.equal(mixed.rawProtocolMs.includes(100), false);
  });

  it("requires a fresh outbox event and matching hook-status; cache-only is unproven", () => {
    const eventId = "wp04-off-1";
    const unproven = proveOfflineOutbox({
      eventId,
      beforeItems: [],
      afterItems: [],
      hookStatus: { hooks: { grok: { ok: true, eventId } } },
      expected: { tool: "Read", policyVersion: 1, sampleStartedAt: 1000 },
    });
    assert.equal(unproven.ok, false);
    assert.equal(unproven.error, "offline_eval_unproven");
    const stale = proveOfflineOutbox({
      eventId,
      beforeItems: [{ kind: "event", eventId, payloadHash: "abc", payload: { eventId, tool: "Read", decision: "allow", policyVersion: 1 }, createdAt: 50 }],
      afterItems: [{ kind: "event", eventId, payloadHash: "abc", payload: { eventId, tool: "Read", decision: "allow", policyVersion: 1 }, createdAt: 50 }],
      hookStatus: { hooks: { grok: { ok: true, eventId } } },
      expected: { tool: "Read", policyVersion: 1, sampleStartedAt: 1000 },
    });
    assert.equal(stale.ok, false);
    assert.equal(stale.error, "offline_eval_unproven");
    const noStatus = proveOfflineOutbox({
      eventId,
      beforeItems: [],
      afterItems: [
        {
          kind: "event",
          eventId,
          payloadHash: "new",
          payload: { eventId, tool: "Read", decision: "allow", policyVersion: 1 },
          createdAt: 1500,
        },
      ],
      hookStatus: null,
      expected: { tool: "Read", policyVersion: 1, sampleStartedAt: 1000 },
    });
    assert.equal(noStatus.ok, false);
    assert.equal(noStatus.error, "hook_status_unproven");
    const ok = proveOfflineOutbox({
      eventId,
      beforeItems: [],
      afterItems: [
        {
          kind: "event",
          eventId,
          payloadHash: "new",
          payload: { eventId, tool: "Read", decision: "allow", policyVersion: 1 },
          createdAt: 1500,
        },
      ],
      hookStatus: { hooks: { grok: { ok: true, eventId, tool: "Read" } } },
      expected: { tool: "Read", policyVersion: 1, sampleStartedAt: 1000 },
    });
    assert.equal(ok.ok, true);
    assert.equal(ok.hookStatusOk, true);
    assert.equal(ok.policyVersion, 1);
  });
});

function fakeStdio() {
  const stream = new EventEmitter();
  stream.setEncoding = () => undefined;
  return stream;
}

function makeFakeChild({ delayCloseMs = null, neverClose = false } = {}) {
  const child = new EventEmitter();
  const order = [];
  child.stdin = {
    write() {
      return true;
    },
    end() {},
    on() {},
  };
  child.stdout = fakeStdio();
  child.stderr = fakeStdio();
  child.pid = 4242;
  child.exitCode = null;
  child.signalCode = null;
  child.killCalls = 0;
  child.order = order;
  child.kill = () => {
    child.killCalls += 1;
    order.push("kill");
    if (neverClose) return;
    const finish = () => {
      if (ownedClosed(child)) return;
      child.exitCode = 0;
      child.stdout.emit("end");
      order.push("close");
      child.emit("close", 0);
    };
    if (delayCloseMs == null) queueMicrotask(finish);
    else setTimeout(finish, delayCloseMs);
  };
  queueMicrotask(() => {
    order.push("spawn");
    child.emit("spawn");
  });
  return child;
}

describe("bench-hook owned child termination", () => {
  it("keeps a delayed-exit child tracked until close before resolving the sample", async () => {
    const children = new Set();
    const child = makeFakeChild({ delayCloseMs: 40 });
    const sample = await spawnHookSample({
      entry: "fake-entry.mjs",
      home: "C:\\tmp\\fx",
      env: { NMZP_HOME: "C:\\tmp\\fx" },
      stdin: "{}",
      timeoutMs: 20,
      children,
      spawnImpl: () => child,
      waitMs: 200,
      escalateWaitMs: 50,
    });
    assert.equal(sample.ok, false);
    assert.equal(sample.error, "timeout");
    assert.equal(sample.cleanupIncomplete, undefined);
    assert.equal(child.killCalls >= 1, true);
    assert.equal(ownedClosed(child), true);
    assert.equal(children.size, 0);
    assert.deepEqual(child.order.filter((s) => s === "kill" || s === "close").slice(0, 2), ["kill", "close"]);
  });

  it("failed termination aborts remaining samples and reports cleanup incomplete", async () => {
    const children = new Set();
    const hung = makeFakeChild({ neverClose: true });
    let second = 0;
    const collected = await collectOwnedSamples(2, async (i) => {
      if (i === 1) {
        second += 1;
        return { ok: true, class: "success", protocolMs: 1, exitMs: 1 };
      }
      return spawnHookSample({
        entry: "fake-entry.mjs",
        home: "C:\\tmp\\fx",
        env: { NMZP_HOME: "C:\\tmp\\fx" },
        stdin: "{}",
        timeoutMs: 20,
        children,
        spawnImpl: () => hung,
        waitMs: 30,
        escalateWaitMs: 30,
      });
    });
    assert.equal(collected.cleanupIncomplete, true);
    assert.equal(collected.abortedRemaining, true);
    assert.equal(collected.samples.length, 1);
    assert.equal(collected.samples[0].error, "cleanup_incomplete");
    assert.equal(collected.samples[0].cleanupIncomplete, true);
    assert.equal(second, 0);
    assert.equal(children.has(hung), true);
    assert.equal(ownedClosed(hung), false);
  });
});

describe("bench-hook sham negative control", () => {
  it("counts a zero-exit fake executable as failed online and offline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-wp04-sham-"));
    try {
      const entry = join(dir, "sham-hook.mjs");
      await writeFile(entry, "process.stdin.resume();process.stdin.on('end',()=>process.exit(0));");
      const result = await runSubprocessScenarios({ samples: 1, timeoutMs: 8000, entry });
      assert.equal(result.online.ok, false);
      assert.equal(result.offline.ok, false);
      assert.equal(result.online.nSuccess, 0);
      assert.equal(result.offline.nSuccess, 0);
      assert.equal(result.online.rawProtocolMs.length, 0);
      assert.equal(result.offline.rawProtocolMs.length, 0);
      const onlineErr = [...(result.online.fallbackErrors ?? []), ...(result.online.failedErrors ?? [])];
      const offlineErr = [...(result.offline.fallbackErrors ?? []), ...(result.offline.failedErrors ?? [])];
      assert.equal(onlineErr.includes("online_fallback") || onlineErr.length > 0, true);
      assert.equal(offlineErr.includes("offline_eval_unproven") || offlineErr.length > 0, true);
      assert.equal(result.fixtureRemoved, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
