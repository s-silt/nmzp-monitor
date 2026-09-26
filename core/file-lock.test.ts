import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { main } from "./cli.ts";
import { withFileLock, type FileLockProbe } from "./file-lock.ts";

const HOST = "lock-host";
const BOOT = "boot-1";
const PID = 999999;
const LOCK_TIMEOUT_MS = 500;

function lockBytes(fields: Record<string, unknown> = {}): Buffer {
  return Buffer.from(
    JSON.stringify({
      formatVersion: 2,
      pid: PID,
      hostname: HOST,
      bootId: BOOT,
      startTime: "1000",
      nonce: "nonce-fixed",
      ...fields,
    }),
  );
}

function probe(overrides: Partial<FileLockProbe> = {}): FileLockProbe {
  return {
    bootId: () => BOOT,
    startTime: (pid) => (pid === PID ? "1000" : "2000"),
    alive: () => "dead",
    hostname: () => HOST,
    ...overrides,
  };
}

function capture(stream: NodeJS.WriteStream): { text(): string; restore(): void } {
  const chunks: string[] = [];
  const original = stream.write;
  function write(
    chunk: string | Uint8Array,
    encoding?: BufferEncoding | ((error?: Error | null) => void),
    callback?: (error?: Error | null) => void,
  ): boolean {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return original.call(stream, chunk, encoding as BufferEncoding, callback);
  }
  stream.write = write as typeof stream.write;
  return {
    text: () => chunks.join(""),
    restore() {
      stream.write = original;
    },
  };
}

async function tempDir(t: { after(fn: () => Promise<void>): void }, prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function isTimeout(error: unknown): boolean {
  return error instanceof Error && error.message === "lock_timeout";
}

async function expectTimeout(
  dir: string,
  lockPath: string,
  bytes: Buffer,
  lockProbe: FileLockProbe,
  message: string,
): Promise<void> {
  const before = await lstat(lockPath);
  const spy = capture(process.stderr);
  let ran = false;
  const started = Date.now();
  try {
    await assert.rejects(
      () =>
        withFileLock(
          dir,
          async () => {
            ran = true;
          },
          { timeoutMs: LOCK_TIMEOUT_MS, probe: lockProbe },
        ),
      isTimeout,
      message,
    );
  } finally {
    spy.restore();
  }
  assert.equal(ran, false, message);
  assert.equal(spy.text().includes("nmzp_lock_reclaimed"), false, message);
  assert.ok(Date.now() - started < 5_000, message);
  const after = await lstat(lockPath);
  assert.equal(after.dev, before.dev, message);
  assert.equal(after.ino, before.ino, message);
  assert.equal(after.isSymbolicLink(), before.isSymbolicLink(), message);
  assert.deepEqual(await readFile(lockPath), bytes, message);
  const names = await readdir(dir);
  assert.equal(
    names.some((name) => name.includes(".stale-") || name.endsWith(".recover")),
    false,
    message,
  );
}

describe("device file lock", { concurrency: false }, () => {
  it("dead owner lock is reclaimed and the callback runs", { timeout: 10_000 }, async (t) => {
    assert.notEqual(process.pid, PID);
    const dir = await tempDir(t, "nmzp-lock-dead-");
    const lockPath = join(dir, ".lock");
    const original = lockBytes();
    await writeFile(lockPath, original);
    const dead = probe({ alive: () => "dead" });
    const spy = capture(process.stderr);
    const seen: { body?: Record<string, unknown> } = {};
    try {
      await assert.doesNotReject(async () => {
        await withFileLock(
          dir,
          async () => {
            seen.body = JSON.parse(await readFile(lockPath, "utf8")) as Record<string, unknown>;
          },
          { timeoutMs: LOCK_TIMEOUT_MS, probe: dead },
        );
      }, "dead owner lock must be reclaimed");
    } finally {
      spy.restore();
    }
    const body = seen.body;
    if (!body) throw new Error("dead owner lock must be reclaimed");
    assert.deepEqual(Object.keys(body), [
      "formatVersion",
      "pid",
      "hostname",
      "bootId",
      "startTime",
      "nonce",
    ]);
    assert.equal(body.formatVersion, 2);
    assert.equal(body.pid, process.pid);
    assert.equal(body.hostname, dead.hostname());
    assert.equal(body.bootId, dead.bootId());
    assert.equal(body.startTime, dead.startTime(process.pid));
    assert.match(String(body.nonce), /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    const archives = (await readdir(dir)).filter((name) => name.startsWith(".lock.stale-"));
    assert.equal(archives.length, 1, "dead owner lock must be reclaimed");
    const archive = join(dir, archives[0] ?? "");
    assert.deepEqual(await readFile(archive), original, "dead owner lock must be reclaimed");
    assert.equal(spy.text(), `nmzp_lock_reclaimed ${archive} pid=${PID} reason=dead\n`);
    assert.equal((await readdir(dir)).includes(".lock.recover"), false);
    await assert.rejects(readFile(lockPath), { code: "ENOENT" });
  });

  it("live owner lock still times out", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t, "nmzp-lock-live-");
    const lockPath = join(dir, ".lock");
    const original = lockBytes({ startTime: "1000" });
    await writeFile(lockPath, original);
    const before = await lstat(lockPath);
    const spy = capture(process.stderr);
    let ran = false;
    const started = Date.now();
    try {
      await assert.rejects(
        () =>
          withFileLock(
            dir,
            async () => {
              ran = true;
            },
            {
              timeoutMs: LOCK_TIMEOUT_MS,
              probe: probe({ alive: () => "alive", startTime: () => "1000" }),
            },
          ),
        isTimeout,
        "live owner lock must time out",
      );
    } finally {
      spy.restore();
    }
    assert.equal(ran, false, "live owner lock must time out");
    assert.equal(spy.text().includes("nmzp_lock_reclaimed"), false, "live owner lock must time out");
    assert.ok(Date.now() - started < 5_000, "live owner lock must time out");
    const after = await lstat(lockPath);
    assert.equal(after.dev, before.dev, "live owner lock must time out");
    assert.equal(after.ino, before.ino, "live owner lock must time out");
    assert.deepEqual(await readFile(lockPath), original, "live owner lock must time out");
    assert.deepEqual((await readdir(dir)).sort(), [".lock"]);
  });

  it("reused pid is reclaimed only on start time mismatch", { timeout: 15_000 }, async (t) => {
    const root = await tempDir(t, "nmzp-lock-reuse-");
    const reused = join(root, "reused");
    await mkdir(reused);
    const reusedPath = join(reused, ".lock");
    const reusedBytes = lockBytes({ startTime: "1000" });
    await writeFile(reusedPath, reusedBytes);
    const spy = capture(process.stderr);
    let ran = false;
    try {
      await assert.doesNotReject(
        () =>
          withFileLock(
            reused,
            async () => {
              ran = true;
            },
            {
              timeoutMs: LOCK_TIMEOUT_MS,
              probe: probe({ alive: () => "alive", startTime: () => "2000" }),
            },
          ),
        "reused pid must be reclaimed",
      );
    } finally {
      spy.restore();
    }
    assert.equal(ran, true, "reused pid must be reclaimed");
    const archives = (await readdir(reused)).filter((name) => name.startsWith(".lock.stale-"));
    assert.equal(archives.length, 1, "reused pid must be reclaimed");
    const archive = join(reused, archives[0] ?? "");
    assert.deepEqual(await readFile(archive), reusedBytes, "reused pid must be reclaimed");
    assert.equal(spy.text(), `nmzp_lock_reclaimed ${archive} pid=${PID} reason=pid_reused\n`);

    const missing = join(root, "missing-start");
    await mkdir(missing);
    const missingPath = join(missing, ".lock");
    const missingBytes = lockBytes({ startTime: null });
    await writeFile(missingPath, missingBytes);
    await expectTimeout(
      missing,
      missingPath,
      missingBytes,
      probe({ alive: () => "alive", startTime: () => "2000" }),
      "null start time must time out",
    );
  });

  it(
    "legacy, malformed, symlink and foreign-host locks are never reclaimed",
    { timeout: 20_000 },
    async (t) => {
      const root = await tempDir(t, "nmzp-lock-refuse-");
      const dead = probe({ alive: () => "dead" });
      const legacyDir = join(root, "legacy");
      await mkdir(legacyDir);
      const legacyPath = join(legacyDir, ".lock");
      const legacy = Buffer.from("424242");
      await writeFile(legacyPath, legacy);
      await expectTimeout(legacyDir, legacyPath, legacy, dead, "legacy lock must time out");

      const malformedDir = join(root, "malformed");
      await mkdir(malformedDir);
      const malformedPath = join(malformedDir, ".lock");
      const malformed = Buffer.from("{");
      await writeFile(malformedPath, malformed);
      await expectTimeout(malformedDir, malformedPath, malformed, dead, "malformed lock must time out");

      const linkDir = join(root, "symlink");
      await mkdir(linkDir);
      const target = join(linkDir, "target");
      const link = join(linkDir, ".lock");
      const targetBytes = lockBytes();
      await writeFile(target, targetBytes);
      let linked = false;
      try {
        await symlink(target, link, "file");
        linked = true;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EPERM" || code === "EACCES" || code === "ENOTSUP" || code === "ENOSYS") {
          t.diagnostic(`skip symlink sub-case: symlinks cannot be created (${code})`);
        } else {
          throw error;
        }
      }
      if (linked) {
        await expectTimeout(linkDir, link, targetBytes, dead, "symlink lock must time out");
        assert.deepEqual(await readFile(target), targetBytes, "symlink lock must time out");
      }

      const foreignDir = join(root, "foreign");
      await mkdir(foreignDir);
      const foreignPath = join(foreignDir, ".lock");
      const foreign = lockBytes({ hostname: "other-host" });
      await writeFile(foreignPath, foreign);
      await expectTimeout(foreignDir, foreignPath, foreign, dead, "foreign-host lock must time out");
    },
  );

  it("a held recovery guard prevents reclaim", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t, "nmzp-lock-guard-");
    const lockPath = join(dir, ".lock");
    const original = lockBytes();
    await writeFile(lockPath, original);
    const guard = join(dir, ".lock.recover");
    const guardBytes = Buffer.from("guard-held");
    await writeFile(guard, guardBytes);
    const before = await lstat(lockPath);
    const guardBefore = await lstat(guard);
    const spy = capture(process.stderr);
    let ran = false;
    const started = Date.now();
    try {
      await assert.rejects(
        () =>
          withFileLock(
            dir,
            async () => {
              ran = true;
            },
            { timeoutMs: LOCK_TIMEOUT_MS, probe: probe({ alive: () => "dead" }) },
          ),
        isTimeout,
        "held recovery guard must time out",
      );
    } finally {
      spy.restore();
    }
    assert.equal(ran, false, "held recovery guard must time out");
    assert.equal(spy.text().includes("nmzp_lock_reclaimed"), false, "held recovery guard must time out");
    assert.ok(Date.now() - started < 5_000, "held recovery guard must time out");
    const after = await lstat(lockPath);
    assert.equal(after.dev, before.dev, "held recovery guard must time out");
    assert.equal(after.ino, before.ino, "held recovery guard must time out");
    assert.deepEqual(await readFile(lockPath), original, "held recovery guard must time out");
    const guardAfter = await lstat(guard);
    assert.equal(guardAfter.dev, guardBefore.dev, "held recovery guard must time out");
    assert.equal(guardAfter.ino, guardBefore.ino, "held recovery guard must time out");
    assert.deepEqual(await readFile(guard), guardBytes, "held recovery guard must time out");
    assert.deepEqual((await readdir(dir)).sort(), [".lock", ".lock.recover"]);
  });

  it("two concurrent reclaimers never run the callback at the same time", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t, "nmzp-lock-race-");
    await writeFile(join(dir, ".lock"), lockBytes());
    let active = 0;
    let max = 0;
    let runs = 0;
    const body = async () => {
      active += 1;
      max = Math.max(max, active);
      await new Promise((resolve) => setTimeout(resolve, 40));
      assert.equal(active, 1, "callbacks overlapped");
      active -= 1;
      runs += 1;
    };
    const dead = probe({ alive: () => "dead" });
    await Promise.all([
      withFileLock(dir, body, { timeoutMs: 4_000, probe: dead }),
      withFileLock(dir, body, { timeoutMs: 4_000, probe: dead }),
    ]);
    assert.equal(max, 1, "callbacks overlapped");
    assert.equal(runs, 2, "two concurrent reclaimers must both run");
    const archives = (await readdir(dir)).filter((name) => name.startsWith(".lock.stale-"));
    assert.equal(archives.length, 1, "two concurrent reclaimers must both run");
  });

  it("owned child crash residue is reclaimed after the child is killed", { timeout: 30_000 }, async (t) => {
    const dir = await tempDir(t, "nmzp-lock-child-");
    const moduleUrl = pathToFileURL(fileURLToPath(new URL("./file-lock.ts", import.meta.url))).href;
    const source = [
      `import { withFileLock } from ${JSON.stringify(moduleUrl)};`,
      `await withFileLock(${JSON.stringify(dir)}, async () => {`,
      "  process.send({ ready: true });",
      "  await new Promise(() => {});",
      "});",
      "",
    ].join("\n");
    const script = join(dir, "owned-child.mjs");
    await writeFile(script, source);
    const env = { ...process.env };
    delete env.NODE_CHANNEL_FD;
    delete env.NODE_TEST_CONTEXT;
    for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
    const child = spawn(process.execPath, ["--experimental-strip-types", script], {
      env,
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      windowsHide: true,
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    const stop = () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    };
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          cleanup();
          reject(new Error(`child ready timeout stderr=${stderr}`));
        }, 15_000);
        const onMessage = () => {
          cleanup();
          resolve();
        };
        const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
          cleanup();
          reject(new Error(`child exited before ready code=${code} signal=${signal} stderr=${stderr}`));
        };
        function cleanup() {
          clearTimeout(timer);
          child.off("message", onMessage);
          child.off("exit", onExit);
        }
        child.once("message", onMessage);
        child.once("exit", onExit);
      });
      const pid = child.pid;
      if (pid === undefined || pid <= 0) throw new Error("owned child pid missing");
      assert.equal(child.kill("SIGKILL"), true, "owned child must receive SIGKILL");
      const outcome = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("owned child did not exit")), 5_000);
          child.once("exit", (code, signal) => {
            clearTimeout(timer);
            resolve({ code, signal });
          });
        },
      );
      assert.equal(outcome.signal, "SIGKILL");
      const spy = capture(process.stderr);
      let ran = false;
      try {
        await assert.doesNotReject(
          () =>
            withFileLock(dir, async () => {
              ran = true;
            }),
          "owned child crash residue must be reclaimed",
        );
      } finally {
        spy.restore();
      }
      assert.equal(ran, true, "owned child crash residue must be reclaimed");
      const archives = (await readdir(dir)).filter((name) => name.startsWith(".lock.stale-"));
      assert.equal(archives.length, 1, "owned child crash residue must be reclaimed");
      const archived = JSON.parse(await readFile(join(dir, archives[0] ?? ""), "utf8")) as {
        pid?: unknown;
        formatVersion?: unknown;
      };
      assert.equal(archived.pid, pid);
      assert.equal(archived.formatVersion, 2);
      assert.match(spy.text(), new RegExp(`nmzp_lock_reclaimed .+ pid=${pid} reason=dead\\n`));
    } finally {
      stop();
    }
  });

  it("status reports a stale lock without reclaiming it", { timeout: 60_000 }, async (t) => {
    const root = await tempDir(t, "nmzp-lock-status-");
    const home = join(root, "home");
    const data = join(root, "data");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const lockPath = join(home, ".nmzp", ".lock");
    const legacy = Buffer.from("424242");
    await writeFile(lockPath, legacy);
    const before = await lstat(lockPath);
    const prevHome = process.env.NMZP_HOME;
    const prevData = process.env.NMZP_DATA;
    process.env.NMZP_HOME = home;
    process.env.NMZP_DATA = data;
    const out = capture(process.stdout);
    const err = capture(process.stderr);
    try {
      await main(["status"]);
    } finally {
      out.restore();
      err.restore();
      if (prevHome === undefined) delete process.env.NMZP_HOME;
      else process.env.NMZP_HOME = prevHome;
      if (prevData === undefined) delete process.env.NMZP_DATA;
      else process.env.NMZP_DATA = prevData;
    }
    const stdout = out.text();
    let parsedStatus: unknown;
    try { parsedStatus = JSON.parse(stdout); } catch { parsedStatus = undefined; }
    assert.equal(typeof parsedStatus, "object", "status stdout must stay JSON");
    assert.equal(stdout.includes("lock: present"), false, "lock line must not be on stdout");
    assert.match(stdout, /"policyVersion":/);
    assert.deepEqual(
      err.text().match(/lock: present[^\n]*/g),
      [
        "lock: present (owner pid unknown, unverifiable — remove manually after confirming no nmzp hook is running)",
      ],
    );
    assert.equal(err.text().includes("nmzp_lock_reclaimed"), false);
    const after = await lstat(lockPath);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.deepEqual(await readFile(lockPath), legacy);
    const names = await readdir(join(home, ".nmzp"));
    assert.deepEqual(
      names.filter((name) => name.startsWith(".lock.stale-") || name.endsWith(".recover")),
      [],
    );
  });
});
