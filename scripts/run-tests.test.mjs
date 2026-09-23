import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const WATCHDOG_MS = 20_000;
const OWNED_WATCHDOG_MS = 300;
const CLEANUP_BOUND_MS = 5_000;
const sink = { write() {} };
const runnerPath = fileURLToPath(new URL("./run-tests.mjs", import.meta.url));

function isolatedRunnerEnv() {
  // A parent node:test process exports NODE_TEST_CONTEXT. A nested --test then
  // exits 0 without running files, which would hide a real child failure.
  const env = { ...process.env };
  delete env.NODE_CHANNEL_FD;
  delete env.NODE_TEST_CONTEXT;
  for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
  return env;
}

function stripComments(source) {
  let out = "";
  let quote = "";
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    const next = source[i + 1];
    if (quote) {
      out += ch;
      if (ch === "\\" && i + 1 < source.length) {
        out += source[i + 1];
        i++;
        continue;
      }
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) i++;
      i++;
      continue;
    }
    out += ch;
  }
  return out;
}

function launchArgs(source) {
  const stripped = stripComments(source);
  const arrays = [...stripped.matchAll(/\[([^[\]]*)\]/g)].map((match) => match[1]);
  const launch = arrays.find((body) => body.includes("\"--experimental-strip-types\"") && body.includes("\"--test\""));
  assert.ok(launch, "runner launch arguments are present");
  return [...launch.matchAll(/"(?:[^"\\]|\\.)*"/g)].map((match) => JSON.parse(match[0]));
}

function ownedClosed(child) {
  return !child || child.exitCode !== null || child.signalCode !== null;
}

function terminateOwned(child) {
  if (ownedClosed(child)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.removeListener("close", onClose);
      reject(new Error("owned child did not exit"));
    }, CLEANUP_BOUND_MS);
    const onClose = () => {
      clearTimeout(timer);
      resolve();
    };
    child.once("close", onClose);
    try {
      child.kill();
    } catch (error) {
      clearTimeout(timer);
      child.removeListener("close", onClose);
      reject(error);
    }
  });
}

function waitForOwnedExit(child, watchdogMs) {
  const state = { timedOut: false, closeDuringTimeout: false };
  const done = new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      state.timedOut = true;
      terminateOwned(child).then(
        () => finish(() => reject(new Error("child watchdog"))),
        (error) => finish(() => reject(error)),
      );
    }, watchdogMs);
    child.once("error", (error) => {
      if (state.timedOut) return;
      finish(() => reject(error));
    });
    child.once("close", () => {
      if (state.timedOut) {
        state.closeDuringTimeout = true;
        return;
      }
      finish(() => resolve());
    });
  });
  return { done, state };
}

async function releaseOwnedFixture(dir, child) {
  if (!ownedClosed(child)) {
    try {
      await terminateOwned(child);
    } catch {
      return;
    }
  }
  if (ownedClosed(child)) await rm(dir, { recursive: true, force: true });
}

async function loadRunner() {
  // Baseline run-tests.mjs launches the suite at import time. Do not import it.
  const source = await readFile(runnerPath, "utf8");
  const canImport = /export\s+function\s+runTests\b/.test(source) && /function\s+invokedDirectly\b/.test(source);
  assert.equal(canImport, true, "runner behavior seam is available without launching the suite");
  return import("./run-tests.mjs");
}

test("runner declares file concurrency bound 1", async () => {
  const args = launchArgs(await readFile(runnerPath, "utf8"));
  assert.ok(args.includes("--test-concurrency=1"), "file concurrency is bounded to 1");
});

test("real runner bounds file concurrency and keeps every collected file sorted", async () => {
  const { collectTestFiles, runTests } = await loadRunner();
  const dir = await mkdtemp(join(tmpdir(), "nmzp-run-tests-"));
  try {
    await mkdir(join(dir, "nested"));
    await mkdir(join(dir, "node_modules"));
    await writeFile(join(dir, "b.test.js"), "import test from 'node:test'; test('b', () => {});\n");
    await writeFile(join(dir, "a.test.ts"), "import test from 'node:test'; test('a', () => {});\n");
    await writeFile(join(dir, "nested", "c.spec.mjs"), "import test from 'node:test'; test('c', () => {});\n");
    await writeFile(join(dir, "d.spec.cjs"), "import test from 'node:test'; test('d', () => {});\n");
    await writeFile(join(dir, "e.test.mts"), "import test from 'node:test'; test('e', () => {});\n");
    await writeFile(join(dir, "note.md"), "not a test\n");
    await writeFile(join(dir, "plain.js"), "export {}\n");
    await writeFile(join(dir, ".secret.test.js"), "import test from 'node:test'; test('hidden', () => {});\n");
    await writeFile(join(dir, "node_modules", "dep.test.js"), "import test from 'node:test'; test('dep', () => {});\n");

    const collected = await collectTestFiles(dir);
    const expected = [
      join(dir, "a.test.ts"),
      join(dir, "b.test.js"),
      join(dir, "d.spec.cjs"),
      join(dir, "e.test.mts"),
      join(dir, "nested", "c.spec.mjs"),
    ];
    assert.deepEqual(collected, expected, "collected files stay complete and sorted");

    const calls = [];
    const child = new EventEmitter();
    runTests(collected, {
      spawnImpl(execPath, args, options) {
        calls.push({ execPath, args, options });
        return child;
      },
      exit() {},
      kill() {},
      stdout: sink,
      stderr: sink,
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].execPath, process.execPath);
    assert.equal(calls[0].options.stdio, "inherit");
    assert.equal(calls[0].options.windowsHide, true);
    const args = calls[0].args;
    assert.ok(args.includes("--test-concurrency=1"), "file concurrency is bounded to 1");
    const timeoutAt = args.indexOf("--test-timeout=60000");
    assert.deepEqual(args.slice(timeoutAt + 1), collected, "runner keeps every collected file in sort order");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("real runner propagates a failing child exit", async () => {
  const { runTests } = await loadRunner();
  const child = new EventEmitter();
  let exited = null;
  let killed = null;
  runTests(["fixture.test.mjs"], {
    spawnImpl() {
      return child;
    },
    exit(code) {
      exited = code;
    },
    kill(signal) {
      killed = signal;
    },
    stdout: sink,
    stderr: sink,
  });
  child.emit("exit", 3, null);
  assert.equal(killed, null);
  assert.equal(exited, 3, "failing child exit is propagated");

  const signaled = new EventEmitter();
  exited = null;
  runTests(["fixture.test.mjs"], {
    spawnImpl() {
      return signaled;
    },
    exit(code) {
      exited = code;
    },
    kill(signal) {
      killed = signal;
    },
    stdout: sink,
    stderr: sink,
  });
  signaled.emit("exit", null, "SIGTERM");
  assert.equal(killed, "SIGTERM");
  assert.equal(exited, 1, "signaled child exit is propagated");
});

test("real runner process forwards a failing test child status", async () => {
  const { runTests } = await loadRunner();
  const dir = await mkdtemp(join(tmpdir(), "nmzp-run-tests-child-"));
  let child;
  try {
    const file = join(dir, "fail.test.mjs");
    await writeFile(
      file,
      "import { test } from 'node:test'; import assert from 'node:assert/strict'; test('fails on purpose', () => { assert.equal(1, 2); });\n",
    );
    let status;
    child = runTests([file], {
      env: isolatedRunnerEnv(),
      stdio: "ignore",
      exit(code) {
        status = code;
      },
      kill() {},
      stdout: sink,
      stderr: sink,
    });
    await waitForOwnedExit(child, WATCHDOG_MS).done;
    assert.equal(status, 1, "failing child exit is propagated");
  } finally {
    await releaseOwnedFixture(dir, child);
  }
});

test("owned child watchdog records timeout and closes that child before cleanup", async () => {
  const { runTests } = await loadRunner();
  const dir = await mkdtemp(join(tmpdir(), "nmzp-run-tests-watchdog-"));
  let child;
  const watch = { state: { timedOut: false, closeDuringTimeout: false } };
  try {
    const file = join(dir, "pending.test.mjs");
    await writeFile(file, "import { test } from 'node:test'; test('stays pending', () => new Promise(() => {}));\n");
    child = runTests([file], {
      env: isolatedRunnerEnv(),
      stdio: "ignore",
      exit() {},
      kill() {},
      stdout: sink,
      stderr: sink,
    });
    const owned = waitForOwnedExit(child, OWNED_WATCHDOG_MS);
    watch.state = owned.state;
    let failure = null;
    try {
      await owned.done;
    } catch (error) {
      failure = error;
    }
    assert.equal(watch.state.timedOut, true, "timeout is recorded before termination");
    assert.equal(watch.state.closeDuringTimeout, true, "close does not resolve the waiter during timeout");
    assert.equal(ownedClosed(child), true, "owned child is closed before cleanup");
    assert.equal(failure instanceof Error ? failure.message : "", "child watchdog");
  } finally {
    await releaseOwnedFixture(dir, child);
  }
});
