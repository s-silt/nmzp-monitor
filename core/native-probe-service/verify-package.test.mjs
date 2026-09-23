import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { lstatSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptPath = join(dirname(fileURLToPath(import.meta.url)), "verify-package.test.ps1");
const FIXTURE_NAME = /^nmzp-service-package-test-[0-9a-f]{32}$/i;
const DEFAULT_TIMEOUT_MS = 45_000;

function decodeOutput(buf) {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString("utf16le");
  const sample = Math.min(buf.length, 80);
  for (let i = 0; i < sample; i++) if (buf[i] === 0) return buf.toString("utf16le");
  return buf.toString("utf8");
}

function ownedFixturePath(stdout) {
  const line = String(stdout ?? "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
    .at(-1);
  if (!line || line.includes("..")) return null;
  const root = resolve(tmpdir());
  const target = resolve(line);
  if (dirname(target).toLowerCase() !== root.toLowerCase()) return null;
  if (!FIXTURE_NAME.test(basename(target))) return null;
  return target;
}

function fixtureHasSymlink(dir) {
  const stack = [dir];
  let seen = 0;
  while (stack.length) {
    const current = stack.pop();
    let names;
    try {
      names = readdirSync(current);
    } catch {
      return true;
    }
    for (const name of names) {
      if (++seen > 64) return true;
      let st;
      try {
        st = lstatSync(join(current, name));
      } catch {
        return true;
      }
      if (st.isSymbolicLink()) return true;
      if (st.isDirectory()) stack.push(join(current, name));
    }
  }
  return false;
}

function cleanupOwnedFixture(stdout) {
  const target = ownedFixturePath(stdout);
  if (!target) return;
  let st;
  try {
    st = lstatSync(target);
  } catch {
    return;
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return;
  if (fixtureHasSymlink(target)) return;
  rmSync(target, { recursive: true, force: false });
}

function terminateChild(child) {
  if (!child || child.killed || typeof child.kill !== "function") return;
  try {
    child.kill();
  } catch {
    /* this child already exited */
  }
}

export async function runVerifyPackageTest(options = {}) {
  const platform = options.platform ?? process.platform;
  if (platform !== "win32") throw new Error("verify-package.test.ps1 requires Windows PowerShell");
  const target = options.scriptPath ?? scriptPath;
  if (basename(target) !== "verify-package.test.ps1") {
    throw new Error("refusing to launch any script other than verify-package.test.ps1");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error("verify-package timeout is out of bounds");
  const spawnImpl = options.spawnImpl ?? spawn;
  // A PowerShell 7 PSModulePath hides Windows PowerShell cmdlets such as Get-FileHash.
  const env = { ...process.env };
  delete env.PSModulePath;
  let child;
  try {
    child = spawnImpl("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", target], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env,
    });
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
  }
  if (!child || typeof child.on !== "function") throw new Error("verify-package spawn returned no child process");
  const stdoutChunks = [];
  const stderrChunks = [];
  child.stdout?.on?.("data", (chunk) => stdoutChunks.push(Buffer.from(chunk)));
  child.stderr?.on?.("data", (chunk) => stderrChunks.push(Buffer.from(chunk)));
  return await new Promise((resolvePromise, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      terminateChild(child);
      reject(new Error(`verify-package.test.ps1 timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err instanceof Error ? err : new Error(String(err)));
    };
    child.on("error", fail);
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const stdout = decodeOutput(Buffer.concat(stdoutChunks));
      const stderr = decodeOutput(Buffer.concat(stderrChunks));
      if (code === 0) resolvePromise({ code, stdout, stderr, signal });
      else reject(new Error(`verify-package.test.ps1 exited ${code ?? signal}: ${stderr || stdout}`));
    });
  });
}

function fakeChild({ code = 0, signal = null, error = null, stdout = "", stderr = "" } = {}) {
  return () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    queueMicrotask(() => {
      if (stdout) child.stdout.emit("data", stdout);
      if (stderr) child.stderr.emit("data", stderr);
      if (error) child.emit("error", error);
      else child.emit("close", code, signal);
    });
    return child;
  };
}

describe("verify-package.test.ps1", () => {
  it("runs pure verify-package.test.ps1", {
    timeout: 60_000,
    skip: process.platform === "win32" ? false : "requires Windows PowerShell",
  }, async () => {
    let result;
    try {
      result = await runVerifyPackageTest();
      assert.equal(result.code, 0);
      assert.match(result.stdout, /PASS:/);
    } finally {
      if (result) cleanupOwnedFixture(result.stdout);
    }
  });

  it("propagates injected spawn failures", async () => {
    await assert.rejects(
      () => runVerifyPackageTest({
        platform: "win32",
        spawnImpl() {
          throw new Error("spawn ENOENT");
        },
      }),
      /spawn ENOENT/,
    );
  });

  it("propagates injected non-zero exit", async () => {
    await assert.rejects(
      () => runVerifyPackageTest({ platform: "win32", spawnImpl: fakeChild({ code: 2, stderr: "Modified binary accepted" }) }),
      /exited 2: Modified binary accepted/,
    );
    await assert.rejects(
      () => runVerifyPackageTest({ platform: "win32", spawnImpl: fakeChild({ code: null, signal: "SIGTERM" }) }),
      /exited SIGTERM/,
    );
  });

  it("propagates injected child error events", async () => {
    await assert.rejects(
      () => runVerifyPackageTest({
        platform: "win32",
        spawnImpl: fakeChild({ error: new Error("ENOENT powershell") }),
      }),
      /ENOENT powershell/,
    );
  });

  it("terminates an injected child that never closes", async () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.killed = false;
    child.kill = () => {
      child.killed = true;
    };
    const started = Date.now();
    await assert.rejects(
      () => runVerifyPackageTest({ platform: "win32", timeoutMs: 40, spawnImpl: () => child }),
      /timed out after 40ms/,
    );
    assert.equal(child.killed, true);
    assert.ok(Date.now() - started < 2_000);
  });

  it("copies the child env and omits PSModulePath", async () => {
    const before = process.env.PSModulePath;
    await runVerifyPackageTest({
      platform: "win32",
      spawnImpl(_file, _args, opts) {
        assert.equal(Object.hasOwn(opts.env, "PSModulePath"), false);
        assert.equal(process.env.PSModulePath, before);
        return fakeChild({ code: 0, stdout: "ok\n" })();
      },
    });
    assert.equal(process.env.PSModulePath, before);
  });

  it("refuses to launch any script other than verify-package.test.ps1", async () => {
    let spawned = false;
    await assert.rejects(
      () => runVerifyPackageTest({
        platform: "win32",
        scriptPath: join(tmpdir(), "other-script.ps1"),
        spawnImpl() {
          spawned = true;
          throw new Error("spawned");
        },
      }),
      /refusing to launch any script other than verify-package\.test\.ps1/,
    );
    assert.equal(spawned, false);
  });

  it("returns stdout when the injected child exits 0", async () => {
    const result = await runVerifyPackageTest({
      platform: "win32",
      spawnImpl: fakeChild({ code: 0, stdout: "PASS: synthetic\n" }),
    });
    assert.equal(result.code, 0);
    assert.match(result.stdout, /PASS: synthetic/);
  });
});
