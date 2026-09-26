import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, lstat, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PolicyWriterLease } from "./writer-lease.ts";

const HOST = "lease-host";
const BOOT = "boot-1";
const PID = 999999;
const LOCK = ".policy-writer.lock";

function leaseBytes(fields = {}) {
  return Buffer.from(
    JSON.stringify({
      formatVersion: 2,
      pid: PID,
      owner: "owner-fixed",
      hostname: HOST,
      bootId: BOOT,
      startTime: "1000",
      ...fields,
    }),
  );
}

function leaseOfSize(size) {
  const head = {
    formatVersion: 2,
    pid: PID,
    owner: "",
    hostname: HOST,
    bootId: BOOT,
    startTime: "1000",
  };
  const extra = size - Buffer.byteLength(JSON.stringify(head));
  if (extra < 0) throw new Error(`lease base exceeds ${size}`);
  const bytes = Buffer.from(JSON.stringify({ ...head, owner: "o".repeat(extra) }));
  if (bytes.length !== size) throw new Error(`lease encoded ${bytes.length}, want ${size}`);
  return bytes;
}

function probe(overrides = {}) {
  return {
    bootId: () => BOOT,
    startTime: (pid) => (pid === PID ? "1000" : "2000"),
    alive: () => "dead",
    hostname: () => HOST,
    ...overrides,
  };
}

function captureStderr() {
  const chunks = [];
  const original = process.stderr.write;
  process.stderr.write = function spy(chunk, encoding, callback) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
    return original.call(process.stderr, chunk, encoding, callback);
  };
  return {
    text() {
      return chunks.join("");
    },
    restore() {
      process.stderr.write = original;
    },
  };
}

async function tempDir(t) {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-writer-lease-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function names(dir) {
  return (await readdir(dir)).sort();
}

function isBusy(error) {
  return error instanceof Error && error.message === "policy_writer_busy";
}

async function expectUntouched(path, leaseProbe, message) {
  const before = await lstat(path);
  const bytes = await readFile(path);
  const dir = dirname(path);
  const beforeNames = await names(dir);
  assert.throws(() => new PolicyWriterLease(path, { probe: leaseProbe }), isBusy, message);
  const after = await lstat(path);
  assert.equal(after.dev, before.dev, message);
  assert.equal(after.ino, before.ino, message);
  assert.equal(after.isSymbolicLink(), before.isSymbolicLink(), message);
  assert.deepEqual(await readFile(path), bytes, message);
  assert.deepEqual(await names(dir), beforeNames, message);
}

async function reclaimed(dir, path, leaseProbe, reason, message) {
  const original = await readFile(path);
  const before = await lstat(path);
  const spy = captureStderr();
  let lease;
  try {
    assert.doesNotThrow(() => {
      lease = new PolicyWriterLease(path, { probe: leaseProbe });
    }, Error, message);
    assert.ok(lease, message);
    lease.assertOwned();
    const found = (await names(dir)).filter((name) => name.startsWith(`${basename(path)}.stale-`));
    assert.equal(found.length, 1, message);
    const archive = join(dir, found[0]);
    const archived = await lstat(archive);
    assert.equal(archived.dev, before.dev, message);
    assert.equal(archived.ino, before.ino, message);
    assert.equal(archived.isSymbolicLink(), false, message);
    assert.deepEqual(await readFile(archive), original, message);
    const old = JSON.parse(original.toString("utf8"));
    assert.equal(
      spy.text(),
      `policy_writer_lease_reclaimed ${archive} pid=${old.pid} reason=${reason}\n`,
      message,
    );
    assert.equal((await names(dir)).includes(`${basename(path)}.recover`), false, message);
    const held = JSON.parse(await readFile(path, "utf8"));
    assert.deepEqual(Object.keys(held), [
      "formatVersion",
      "pid",
      "owner",
      "hostname",
      "bootId",
      "startTime",
    ]);
    assert.equal(held.formatVersion, 2);
    assert.equal(held.pid, process.pid);
    assert.match(held.owner, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    assert.equal(held.hostname, leaseProbe.hostname());
    assert.equal(held.bootId, leaseProbe.bootId());
    assert.equal(held.startTime, leaseProbe.startTime(process.pid));
    lease.close();
    lease = undefined;
    await assert.rejects(readFile(path), { code: "ENOENT" });
    assert.deepEqual(await readFile(archive), original, message);
    return archive;
  } finally {
    spy.restore();
    lease?.close();
  }
}

describe("policy writer lease recovery", { concurrency: false }, () => {
  it("dead owner on the same boot is reclaimed and archived", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t);
    const path = join(dir, LOCK);
    const body = leaseOfSize(4096);
    assert.equal(body.length, 4096);
    await writeFile(path, body);
    await reclaimed(
      dir,
      path,
      probe({ alive: () => "dead", startTime: () => "2000" }),
      "dead",
      "dead owner on the same boot must be reclaimed",
    );
  });

  it("live owner with the same start time is still refused", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t);
    const path = join(dir, LOCK);
    await writeFile(path, leaseBytes({ startTime: "1000" }));
    const spy = captureStderr();
    try {
      await expectUntouched(
        path,
        probe({ alive: () => "alive", startTime: () => "1000" }),
        "live owner must remain policy_writer_busy",
      );
      assert.equal(spy.text().includes("policy_writer_lease_reclaimed"), false);
    } finally {
      spy.restore();
    }
  });

  it("reused pid is reclaimed only when start time differs", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t);
    const reused = join(dir, "reused.lock");
    await writeFile(reused, leaseBytes({ startTime: "1000" }));
    await reclaimed(
      dir,
      reused,
      probe({ alive: () => "alive", startTime: () => "2000" }),
      "pid_reused",
      "reused pid with a different start time must be reclaimed",
    );

    const missingStart = join(dir, "missing-start.lock");
    await writeFile(missingStart, leaseBytes({ startTime: null }));
    await expectUntouched(
      missingStart,
      probe({ alive: () => "alive", startTime: () => "2000" }),
      "null start time must remain policy_writer_busy",
    );

    const unreadable = join(dir, "unreadable-start.lock");
    await writeFile(unreadable, leaseBytes({ startTime: "1000" }));
    await expectUntouched(
      unreadable,
      probe({ alive: () => "alive", startTime: () => null }),
      "unreadable start time must remain policy_writer_busy",
    );
  });

  it(
    "legacy, malformed, symlink, foreign-host and unknown-boot leases are refused",
    { timeout: 10_000 },
    async (t) => {
      const dir = await tempDir(t);
      const dead = probe({ alive: () => "dead" });
      const samples = [
        ["legacy.lock", Buffer.from(JSON.stringify({ pid: PID, owner: "legacy-owner" }))],
        ["truncated.lock", Buffer.from("{")],
        ["array.lock", Buffer.from("[]")],
        ["null.lock", Buffer.from("null")],
        ["empty.lock", Buffer.from("")],
        [
          "version-string.lock",
          Buffer.from(
            JSON.stringify({
              formatVersion: "2",
              pid: PID,
              owner: "owner-fixed",
              hostname: HOST,
              bootId: BOOT,
              startTime: "1000",
            }),
          ),
        ],
        ["version-1.lock", leaseBytes({ formatVersion: 1 })],
        ["pid-zero.lock", leaseBytes({ pid: 0 })],
        ["pid-negative.lock", leaseBytes({ pid: -1 })],
        ["oversize.lock", leaseOfSize(4097)],
        ["foreign.lock", leaseBytes({ hostname: "other-host" })],
        ["null-boot.lock", leaseBytes({ bootId: null })],
      ];
      let probedUnsafePid = false;
      const unsafe = probe({
        alive() {
          probedUnsafePid = true;
          return "dead";
        },
      });
      for (const [name, body] of samples) {
        const path = join(dir, name);
        await writeFile(path, body);
        const leaseProbe = name.startsWith("pid-") ? unsafe : dead;
        await expectUntouched(path, leaseProbe, "ambiguous lease must remain policy_writer_busy");
      }
      assert.equal(probedUnsafePid, false, "pid 0 and negative pid must not be probed");

      const unknownNow = join(dir, "unknown-now.lock");
      await writeFile(unknownNow, leaseBytes());
      await expectUntouched(
        unknownNow,
        probe({ bootId: () => null, alive: () => "dead" }),
        "unknown boot must remain policy_writer_busy",
      );
      const unknownLife = join(dir, "unknown-life.lock");
      await writeFile(unknownLife, leaseBytes());
      await expectUntouched(
        unknownLife,
        probe({ alive: () => "unknown" }),
        "unknown liveness must remain policy_writer_busy",
      );

      const target = join(dir, "symlink-target.lock");
      const link = join(dir, "symlink.lock");
      await writeFile(target, leaseBytes());
      let linked = false;
      try {
        await symlink(target, link, "file");
        linked = true;
      } catch (error) {
        const code = error && error.code;
        if (code === "EPERM" || code === "EACCES" || code === "ENOTSUP" || code === "ENOSYS") {
          t.diagnostic(`skip symlink sub-case: symlinks cannot be created (${code})`);
        } else throw error;
      }
      if (linked) {
        await expectUntouched(link, dead, "symlink lease must remain policy_writer_busy");
        assert.deepEqual(await readFile(target), leaseBytes());
      }
    },
  );

  it("a held recovery guard blocks a concurrent reclaimer", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t);
    const path = join(dir, LOCK);
    await writeFile(path, leaseBytes());
    const guard = `${path}.recover`;
    await writeFile(guard, "guard-held");
    const guardBefore = await lstat(guard);
    const guardBytes = await readFile(guard);
    const spy = captureStderr();
    try {
      await expectUntouched(
        path,
        probe({ alive: () => "dead" }),
        "held recovery guard must remain policy_writer_busy",
      );
      const guardAfter = await lstat(guard);
      assert.equal(guardAfter.dev, guardBefore.dev, "held recovery guard must remain policy_writer_busy");
      assert.equal(guardAfter.ino, guardBefore.ino, "held recovery guard must remain policy_writer_busy");
      assert.deepEqual(await readFile(guard), guardBytes, "held recovery guard must remain policy_writer_busy");
      assert.equal(spy.text().includes("policy_writer_lease_reclaimed"), false);
    } finally {
      spy.restore();
    }
  });

  it("reboot identity allows reclaim", { timeout: 10_000 }, async (t) => {
    const dir = await tempDir(t);
    const path = join(dir, LOCK);
    await writeFile(path, leaseBytes({ bootId: "boot-old", startTime: "1000" }));
    await reclaimed(
      dir,
      path,
      probe({
        bootId: () => "boot-new",
        alive: () => "alive",
        startTime: () => "1000",
      }),
      "reboot",
      "reboot identity must be reclaimed",
    );
  });

  it(
    "owned child crash residue is reclaimed after SIGKILL",
    {
      timeout: 30_000,
      skip: process.platform !== "linux" && "linux procfs only",
    },
    async (t) => {
      const dir = await tempDir(t);
      const leasePath = join(dir, LOCK);
      const moduleUrl = pathToFileURL(fileURLToPath(new URL("./writer-lease.ts", import.meta.url))).href;
      const source = [
        `import { PolicyWriterLease } from ${JSON.stringify(moduleUrl)};`,
        "setInterval(() => {}, 1000);",
        `const lease = new PolicyWriterLease(${JSON.stringify(leasePath)});`,
        "lease.assertOwned();",
        "process.send({ ready: true });",
      ].join("\n");
      const script = join(dir, "owned-child.mjs");
      await writeFile(script, source);
      const env = { ...process.env };
      delete env.NODE_CHANNEL_FD;
      delete env.NODE_TEST_CONTEXT;
      for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
      const child = spawn(process.execPath, ["--experimental-strip-types", script], {
        env,
        stdio: ["ignore", "pipe", "pipe", "ipc"],
        windowsHide: true,
      });
      let stderr = "";
      child.stderr?.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });
      const stopOwnedChild = () => {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      };
      try {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            cleanup();
            reject(new Error(`child ready timeout stderr=${stderr}`));
          }, 15_000);
          const onMessage = () => {
            cleanup();
            resolve();
          };
          const onExit = (code, signal) => {
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
        assert.equal(typeof child.pid, "number");
        assert.equal(child.kill("SIGKILL"), true, "owned child must receive SIGKILL");
        const outcome = await new Promise((resolve) => {
          child.once("exit", (code, signal) => resolve({ code, signal }));
        });
        assert.equal(outcome.signal, "SIGKILL");
        const spy = captureStderr();
        let lease;
        try {
          assert.doesNotThrow(() => {
            lease = new PolicyWriterLease(leasePath);
          }, Error, "owned child crash residue must be reclaimed");
          assert.ok(lease);
          lease.assertOwned();
          const found = (await names(dir)).filter((name) => name.startsWith(`${LOCK}.stale-`));
          assert.equal(found.length, 1, "owned child crash residue must be reclaimed");
          const archived = JSON.parse(await readFile(join(dir, found[0]), "utf8"));
          assert.equal(archived.pid, child.pid);
          assert.equal(archived.formatVersion, 2);
          assert.match(
            spy.text(),
            new RegExp(`policy_writer_lease_reclaimed .+ pid=${child.pid} reason=dead\\n`),
          );
        } finally {
          spy.restore();
          lease?.close();
        }
      } finally {
        stopOwnedChild();
      }
    },
  );
});
