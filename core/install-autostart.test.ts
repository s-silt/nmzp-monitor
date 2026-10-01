import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { NMZP_VERSION } from "./constants.ts";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  STARTUP_LAUNCHER_NAME,
  createProbeController,
  defaultLauncherRunner,
  hiddenProbeTr,
  isOurScheduledTask,
  parseCimCreationDate,
  probeArgumentList,
  probeLockMatchesRequested,
  readProbeLock,
  startupLauncherBody,
  verifyNmzpProbe,
  windowsInspectPidScript,
  writeProbeLock,
  writeProbeReady,
} from "./install-autostart.ts";

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "nmzp-as-"));
}

describe("probe pid ownership", () => {
  it("inspects only the candidate pid and does not list every CommandLine", () => {
    const s = windowsInspectPidScript(4242);
    assert.match(s, /ProcessId=4242/);
    assert.match(s, /Filter/);
    assert.doesNotMatch(s, /Get-CimInstance Win32_Process \| Select-Object/);
  });

  it("refuses to treat a reused or forged pid as our probe", () => {
    const inspected = {
      pid: 9,
      exe: "C:\\Program Files\\nodejs\\node.exe",
      cmdline: "node -e setInterval(()=>{},1000)",
      createdAt: Date.now(),
    };
    assert.equal(
      verifyNmzpProbe(inspected, {
        nodePath: "C:\\Program Files\\nodejs\\node.exe",
        entry: "C:\\nmzp\\nmzp.mjs",
        nonce: "deadbeef",
        readyNonce: "other",
        startedAt: Date.now(),
      }),
      false,
    );
  });

  it("stopOwn does not kill a live pid from a forged lock file", async () => {
    const dir = await tempDir();
    const home = join(dir, "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const victim = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "ignore", windowsHide: true });
    try {
      assert.ok(typeof victim.pid === "number");
      writeProbeLock(home, {
        pid: victim.pid,
        marker: "nmzp-probe",
        version: "0.1.0",
        startedAt: Date.now(),
        nonce: "forged",
        nodePath: "C:\\nmzp-fake\\node.exe",
        entry: "C:\\nmzp-fake\\nmzp.mjs",
      });
      const ctrl = createProbeController({
        inspectPid: async (pid) => ({
          pid,
          exe: process.execPath,
          cmdline: `${process.execPath} -e setInterval(()=>{},1000)`,
          createdAt: Date.now(),
        }),
      });
      const r = await ctrl.stopOwn(home);
      assert.equal(r.stopped, false);
      process.kill(victim.pid, 0);
    } finally {
      try {
        victim.kill();
      } catch {
        /* ignore */
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("start does not report running until the child ready nonce is present", async () => {
    const dir = await tempDir();
    const home = join(dir, "home");
    await mkdir(home, { recursive: true });
    let killed = false;
    try {
      const ctrl = createProbeController({
        readyTimeoutMs: 60,
        randomNonce: () => "nonce-1",
        spawnProbe: () => ({
          pid: 99,
          kill: () => {
            killed = true;
          },
        }),
        inspectPid: async () => null,
      });
      const r = await ctrl.start({
        nodePath: "C:\\n\\node.exe",
        entry: "C:\\e\\nmzp.mjs",
        home,
        hidden: true,
      });
      assert.equal(r.ok, false);
      assert.equal(killed, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("parses ConvertTo-Json CIM CreationDate forms used on this host", () => {
    assert.equal(parseCimCreationDate("/Date(1789830549489)/"), 1789830549489);
    assert.equal(parseCimCreationDate(JSON.parse('"\\/Date(1789830549489)\\/"')), 1789830549489);
    assert.equal(parseCimCreationDate(1789830549489), 1789830549489);
    const iso = parseCimCreationDate("2026-09-19T12:00:00.000Z");
    assert.equal(iso, Date.parse("2026-09-19T12:00:00.000Z"));
    const dmtf = parseCimCreationDate("20260919120000.000000+000");
    assert.equal(typeof dmtf, "number");
    assert.equal(parseCimCreationDate("not-a-date"), undefined);
  });

  it("two real child processes elect a single probe instance under a temp HOME", async () => {
    const dir = await tempDir();
    const home = join(dir, "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const claim = join(dir, "claim.ts");
    const autostartHref = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "install-autostart.ts")).href;
    const coreDir = dirname(fileURLToPath(import.meta.url));
    await writeFile(
      claim,
      `import { announceProbeReady } from ${JSON.stringify(autostartHref)};
const r = await announceProbeReady(process.env.NMZP_HOME, process.env.NMZP_CORE_DIR);
process.stdout.write(JSON.stringify({ tookLock: r.tookLock, pid: process.pid, error: r.error ?? null }) + "\\n");
if (r.tookLock) setInterval(() => {}, 60000);
`,
    );
    const children: Array<ReturnType<typeof spawn>> = [];
    const readChild = (child: ReturnType<typeof spawn>) =>
      new Promise<{ tookLock: boolean; pid: number; error: string | null }>((resolve, reject) => {
        let buf = "";
        const t = setTimeout(() => reject(new Error("claim_timeout")), 8000);
        child.stdout?.setEncoding("utf8");
        child.stdout?.on("data", (c) => {
          buf += c;
          const line = buf.split("\n").find((l) => l.startsWith("{"));
          if (!line) return;
          try {
            const j = JSON.parse(line) as { tookLock: boolean; pid: number; error: string | null };
            clearTimeout(t);
            resolve(j);
          } catch {
            /* wait for a full line */
          }
        });
        child.on("error", (e) => {
          clearTimeout(t);
          reject(e);
        });
      });
    try {
      const env = { ...process.env, NMZP_HOME: home, NMZP_CORE_DIR: coreDir };
      const a = spawn(process.execPath, ["--experimental-strip-types", claim], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      const b = spawn(process.execPath, ["--experimental-strip-types", claim], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      children.push(a, b);
      const results = await Promise.all([readChild(a), readChild(b)]);
      assert.equal(results.filter((r) => r.tookLock).length, 1);
      assert.equal(results.filter((r) => !r.tookLock).length, 1);
      const winner = results.find((r) => r.tookLock);
      assert.ok(winner?.pid);
    } finally {
      for (const c of children) {
        try {
          if (c.pid) process.kill(c.pid);
        } catch {
          /* ignore */
        }
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("start succeeds only after matching ready handshake", async () => {
    const dir = await tempDir();
    const home = join(dir, "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    try {
      const ctrl = createProbeController({
        readyTimeoutMs: 500,
        randomNonce: () => "nonce-ok",
        spawnProbe: ({ home: h, nonce }) => {
          writeProbeReady(h, { pid: 77, nonce });
          return { pid: 77, kill: () => undefined };
        },
        inspectPid: async () => ({
          pid: 77,
          exe: "C:\\n\\node.exe",
          cmdline: `"C:\\n\\node.exe" --experimental-strip-types "C:\\e\\nmzp.mjs" probe`,
          createdAt: Date.now(),
        }),
      });
      const r = await ctrl.start({
        nodePath: "C:\\n\\node.exe",
        entry: "C:\\e\\nmzp.mjs",
        home,
        hidden: true,
      });
      assert.equal(r.ok, true);
      assert.equal(r.pid, 77);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("probe upgrade checks the requested runtime", () => {
  function ownInspect(pid: number, entry: string) {
    return async (asked: number) =>
      asked === pid
        ? {
            pid,
            exe: process.execPath,
            cmdline: `"${process.execPath}" "${entry}" probe`,
            createdAt: Date.now(),
          }
        : null;
  }

  async function livePid(): Promise<{ pid: number; kill: () => void }> {
    const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "ignore", windowsHide: true });
    await new Promise<void>((resolve, reject) => {
      child.once("spawn", () => resolve());
      child.once("error", reject);
    });
    return {
      pid: child.pid!,
      kill: () => {
        try {
          child.kill();
        } catch {
          /* already stopped */
        }
      },
    };
  }

  it("reuses a verified probe on the same runtime and does not spawn", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const entry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const live = await livePid();
    let spawns = 0;
    try {
      writeProbeLock(home, {
        pid: live.pid,
        marker: "nmzp-probe",
        version: NMZP_VERSION,
        startedAt: Date.now(),
        nonce: "same",
        nodePath: process.execPath,
        entry,
      });
      writeProbeReady(home, { pid: live.pid, nonce: "same" });
      const ctrl = createProbeController({
        inspectPid: ownInspect(live.pid, entry),
        spawnProbe: () => {
          spawns += 1;
          return { pid: 1, kill: () => undefined };
        },
      });
      const started = await ctrl.start({ nodePath: process.execPath, entry, home, hidden: true });
      assert.equal(started.ok, true);
      assert.equal(started.pid, live.pid);
      assert.equal(spawns, 0);
      process.kill(live.pid, 0);
    } finally {
      live.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("stops a verified old runtime and starts the requested one", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const live = await livePid();
    const spawned: string[] = [];
    try {
      writeProbeLock(home, {
        pid: live.pid,
        marker: "nmzp-probe",
        version: "0.0.1",
        startedAt: Date.now(),
        nonce: "old",
        nodePath: process.execPath,
        entry: oldEntry,
      });
      writeProbeReady(home, { pid: live.pid, nonce: "old" });
      assert.equal(probeLockMatchesRequested(readProbeLock(home), { nodePath: process.execPath, entry: nextEntry }), false);
      const ctrl = createProbeController({
        inspectPid: ownInspect(live.pid, oldEntry),
        spawnProbe: ({ entry, nonce }) => {
          spawned.push(entry);
          writeProbeReady(home, { pid: 88, nonce });
          return { pid: 88, kill: () => undefined };
        },
      });
      const started = await ctrl.start({ nodePath: process.execPath, entry: nextEntry, home, hidden: true });
      assert.equal(started.ok, true);
      assert.equal(started.pid, 88, "old runtime was reused");
      assert.deepEqual(spawned, [nextEntry]);
      assert.equal(readProbeLock(home)?.entry, nextEntry);
      assert.equal(readProbeLock(home)?.version, NMZP_VERSION);
      let dead = false;
      for (let i = 0; i < 20; i++) {
        try {
          process.kill(live.pid, 0);
        } catch {
          dead = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      assert.equal(dead, true);
    } finally {
      live.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("refuses an unverified pid and does not signal it", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const entry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const live = await livePid();
    let spawns = 0;
    try {
      writeProbeLock(home, {
        pid: live.pid,
        marker: "nmzp-probe",
        version: "0.0.1",
        startedAt: Date.now(),
        nonce: "foreign",
        nodePath: process.execPath,
        entry,
      });
      writeProbeReady(home, { pid: live.pid, nonce: "foreign" });
      const ctrl = createProbeController({
        inspectPid: async (pid) => ({ pid, exe: join(home, "not-node.exe"), cmdline: "not-the-probe" }),
        spawnProbe: () => {
          spawns += 1;
          return { pid: 1, kill: () => undefined };
        },
      });
      const started = await ctrl.start({ nodePath: process.execPath, entry, home, hidden: true });
      assert.equal(started.ok, false);
      assert.equal(spawns, 0);
      process.kill(live.pid, 0);
    } finally {
      live.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("restores the verified old runtime when the requested start never becomes ready", async (t) => {
    const dir = await tempDir();
    const home = join(dir, "home");
    const children: Array<{ child: ReturnType<typeof spawn>; closed: Promise<void> }> = [];
    const childErrors: Error[] = [];
    const spawnOwned = () => {
      const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
        stdio: "ignore",
        windowsHide: true,
      });
      const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
      child.on("error", (error) => childErrors.push(error));
      const owned = { child, closed };
      children.push(owned);
      assert.ok(typeof child.pid === "number", "test-owned child did not start");
      return owned;
    };
    const waitClosed = async ({ closed }: (typeof children)[number]) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          closed,
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error("test-owned child did not close")), 2000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    t.after(async () => {
      const errors: unknown[] = [];
      for (const { child } of children) {
        try {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        } catch (error) {
          errors.push(error);
        }
      }
      const results = await Promise.allSettled(children.map(waitClosed));
      for (const result of results) if (result.status === "rejected") errors.push(result.reason);
      try {
        await rm(dir, { recursive: true, force: true });
      } catch (error) {
        errors.push(error);
      }
      errors.push(...childErrors);
      if (errors.length) throw new AggregateError(errors, "test-owned child cleanup failed");
    });
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const prior = spawnOwned();
    await new Promise<void>((resolve, reject) => {
      prior.child.once("spawn", () => resolve());
      prior.child.once("error", reject);
    });
    let attempt: (typeof children)[number] | undefined;
    let restored: (typeof children)[number] | undefined;
    let attemptKillRequested = false;
    const spawned: string[] = [];
    writeProbeLock(home, {
      pid: prior.child.pid!,
      marker: "nmzp-probe",
      version: "0.0.1",
      startedAt: Date.now(),
      nonce: "old",
      nodePath: process.execPath,
      entry: oldEntry,
    });
    writeProbeReady(home, { pid: prior.child.pid!, nonce: "old" });
    const ctrl = createProbeController({
      readyTimeoutMs: 60,
      inspectPid: async (pid) => {
        if (attempt?.child.pid === pid) {
          // A signal can precede the OS exit; do not mistake that interval for an unknown live process.
          assert.equal(attemptKillRequested, true);
          await waitClosed(attempt);
          return null;
        }
        return ownInspect(prior.child.pid!, oldEntry)(pid);
      },
      spawnProbe: ({ entry, nonce }) => {
        spawned.push(entry);
        if (entry === oldEntry) {
          assert.ok(attempt, "rollback preceded the requested attempt");
          assert.equal(attemptKillRequested, true, "rollback preceded the attempt's kill");
          const attemptedPid = attempt.child.pid!;
          assert.throws(() => process.kill(attemptedPid, 0), { code: "ESRCH" });
          const rollbackChild = spawnOwned();
          restored = rollbackChild;
          writeProbeReady(home, { pid: rollbackChild.child.pid!, nonce });
          return { pid: rollbackChild.child.pid, kill: () => rollbackChild.child.kill() };
        }
        const requestedChild = spawnOwned();
        attempt = requestedChild;
        return {
          pid: requestedChild.child.pid,
          kill: () => {
            attemptKillRequested = true;
            requestedChild.child.kill();
          },
        };
      },
    });
    const started = await ctrl.start({ nodePath: process.execPath, entry: nextEntry, home, hidden: true });
    assert.equal(started.ok, false);
    assert.deepEqual(spawned, [nextEntry, oldEntry]);
    assert.ok(attempt);
    assert.ok(restored);
    await Promise.all([waitClosed(prior), waitClosed(attempt)]);
    assert.equal(attemptKillRequested, true);
    assert.equal(readProbeLock(home)?.pid, restored.child.pid);
    assert.equal(readProbeLock(home)?.entry, oldEntry);
    assert.equal(readProbeLock(home)?.version, "0.0.1");
    process.kill(restored.child.pid!, 0);
  });

  it("P2 child that exits during inspect is settled and can roll back", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const prior = await livePid();
    const child = await livePid();
    const restored = await livePid();
    const order: string[] = [];
    try {
      writeProbeLock(home, {
        pid: prior.pid,
        marker: "nmzp-probe",
        version: "0.0.1",
        startedAt: Date.now(),
        nonce: "prior-nonce",
        nodePath: process.execPath,
        entry: oldEntry,
      });
      writeProbeReady(home, { pid: prior.pid, nonce: "prior-nonce" });
      const ctrl = createProbeController({
        readyTimeoutMs: 30,
        inspectPid: async (pid) => {
          if (pid === child.pid) {
            try {
              process.kill(child.pid);
            } catch {
              /* already exited */
            }
            const deadline = Date.now() + 1000;
            while (Date.now() < deadline) {
              try {
                process.kill(child.pid, 0);
              } catch {
                break;
              }
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            return null;
          }
          if (pid !== prior.pid && pid !== restored.pid) return null;
          const entry = pid === restored.pid ? oldEntry : oldEntry;
          return {
            pid,
            exe: process.execPath,
            cmdline: `"${process.execPath}" "${entry}" probe`,
            createdAt: Date.now(),
          };
        },
        spawnProbe: ({ entry, nonce, home: probeHome }) => {
          order.push(`spawn:${entry}`);
          if (entry === oldEntry) {
            writeProbeReady(probeHome, { pid: restored.pid, nonce });
            return { pid: restored.pid, kill: () => undefined };
          }
          return { pid: child.pid, kill: () => undefined };
        },
      });
      const started = await ctrl.start({
        nodePath: process.execPath,
        entry: nextEntry,
        home,
        hidden: true,
        transactional: true,
      });
      assert.equal(started.ok, false);
      assert.equal(started.transaction?.attemptSettled, true, "exited child stayed unsettled");
      assert.equal(started.transaction?.owned, undefined);
      const rolled = await ctrl.rollbackStart!(home, started.transaction!, () => {
        order.push("files");
        assert.equal(order.includes(`spawn:${oldEntry}`), false, "prior probe started before file rollback");
        return { ok: true };
      });
      assert.equal(rolled.ok, true, rolled.error);
      assert.equal(rolled.restored, true, "prior probe was not restored");
      assert.deepEqual(order, [`spawn:${nextEntry}`, "files", `spawn:${oldEntry}`]);
    } finally {
      prior.kill();
      child.kill();
      restored.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 child that stays alive with an unknown identity stays unsettled", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const prior = await livePid();
    const child = await livePid();
    const spawned: string[] = [];
    try {
      writeProbeLock(home, {
        pid: prior.pid,
        marker: "nmzp-probe",
        version: "0.0.1",
        startedAt: Date.now(),
        nonce: "prior-nonce",
        nodePath: process.execPath,
        entry: oldEntry,
      });
      writeProbeReady(home, { pid: prior.pid, nonce: "prior-nonce" });
      const ctrl = createProbeController({
        readyTimeoutMs: 30,
        inspectPid: async (pid) => {
          if (pid === child.pid) return null;
          if (pid !== prior.pid) return null;
          return {
            pid,
            exe: process.execPath,
            cmdline: `"${process.execPath}" "${oldEntry}" probe`,
            createdAt: Date.now(),
          };
        },
        spawnProbe: ({ entry }) => {
          spawned.push(entry);
          return { pid: child.pid, kill: () => undefined };
        },
      });
      const started = await ctrl.start({
        nodePath: process.execPath,
        entry: nextEntry,
        home,
        hidden: true,
        transactional: true,
      });
      assert.equal(started.ok, false);
      assert.equal(started.transaction?.attemptSettled, false, "unknown live child was settled");
      assert.equal(started.transaction?.owned, undefined);
      let files = false;
      const rolled = await ctrl.rollbackStart!(home, started.transaction!, () => {
        files = true;
        return { ok: true };
      });
      assert.equal(files, false, "files rolled back while an unknown child was alive");
      assert.equal(rolled.restored, false, "prior probe restored while an unknown child was alive");
      assert.match(rolled.error ?? "", /probe_stop_unverified/);
      assert.deepEqual(spawned, [nextEntry]);
      process.kill(child.pid, 0);
    } finally {
      prior.kill();
      child.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 deadline child that publishes its own lock is not adopted", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const prior = await livePid();
    const child = await livePid();
    const restored = await livePid();
    const order: string[] = [];
    try {
      writeProbeLock(home, {
        pid: prior.pid,
        marker: "nmzp-probe",
        version: "0.0.1",
        startedAt: Date.now(),
        nonce: "prior-nonce",
        nodePath: process.execPath,
        entry: oldEntry,
      });
      writeProbeReady(home, { pid: prior.pid, nonce: "prior-nonce" });
      const ctrl = createProbeController({
        readyTimeoutMs: 40,
        inspectPid: async (pid) => {
          const entry = pid === child.pid ? nextEntry : pid === prior.pid || pid === restored.pid ? oldEntry : undefined;
          if (!entry) return null;
          return {
            pid,
            exe: process.execPath,
            cmdline: `"${process.execPath}" "${entry}" probe`,
            createdAt: Date.now(),
          };
        },
        spawnProbe: ({ entry, nonce, home: probeHome }) => {
          order.push(`spawn:${entry}`);
          if (entry === oldEntry) {
            writeProbeReady(probeHome, { pid: restored.pid, nonce });
            return { pid: restored.pid, kill: () => undefined };
          }
          return {
            pid: child.pid,
            kill: () => {
              writeProbeReady(probeHome, { pid: child.pid, nonce });
              writeProbeLock(probeHome, {
                pid: child.pid,
                marker: "nmzp-probe",
                version: NMZP_VERSION,
                startedAt: Date.now(),
                nonce,
                nodePath: process.execPath,
                entry: nextEntry,
              });
            },
          };
        },
      });
      const started = await ctrl.start({ nodePath: process.execPath, entry: nextEntry, home, hidden: true, transactional: true });
      assert.equal(started.ok, false, "deadline child was adopted");
      assert.notEqual(started.transaction?.disposition, "reused");
      assert.equal(started.transaction?.owned?.pid, child.pid);
      const rolled = await ctrl.rollbackStart!(home, started.transaction!, () => {
        order.push("files");
        let alive = true;
        try {
          process.kill(child.pid, 0);
        } catch {
          alive = false;
        }
        assert.equal(alive, false, "file rollback ran while the deadline child was alive");
        assert.equal(order.includes(`spawn:${oldEntry}`), false, "prior probe started before file rollback");
        return { ok: true };
      });
      assert.equal(rolled.restored, true, "prior probe was not restored");
      assert.deepEqual(order, [`spawn:${nextEntry}`, "files", `spawn:${oldEntry}`]);
      assert.equal(readProbeLock(home)?.entry, oldEntry);
      let childAlive = true;
      try {
        process.kill(child.pid, 0);
      } catch {
        childAlive = false;
      }
      assert.equal(childAlive, false, "deadline child stayed alive");
    } finally {
      prior.kill();
      child.kill();
      restored.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 adopts a different verified winner and does not stop it", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const entry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const winner = await livePid();
    const child = await livePid();
    try {
      const ctrl = createProbeController({
        readyTimeoutMs: 200,
        inspectPid: async (pid) => {
          if (pid !== winner.pid && pid !== child.pid) return null;
          return {
            pid,
            exe: process.execPath,
            cmdline: `"${process.execPath}" "${entry}" probe`,
            createdAt: Date.now(),
          };
        },
        spawnProbe: ({ home: probeHome }) => {
          writeProbeReady(probeHome, { pid: winner.pid, nonce: "external-nonce" });
          writeProbeLock(probeHome, {
            pid: winner.pid,
            marker: "nmzp-probe",
            version: NMZP_VERSION,
            startedAt: Date.now(),
            nonce: "external-nonce",
            nodePath: process.execPath,
            entry,
          });
          return {
            pid: child.pid,
            kill: () => {
              try {
                process.kill(child.pid);
              } catch {
                /* already stopped */
              }
            },
          };
        },
      });
      const started = await ctrl.start({
        nodePath: process.execPath,
        entry,
        home,
        hidden: true,
        transactional: true,
      });
      assert.equal(started.ok, true, "external winner was not adopted");
      assert.equal(started.pid, winner.pid);
      assert.equal(started.transaction?.disposition, "reused");
      process.kill(winner.pid, 0);
      let childAlive = true;
      try {
        process.kill(child.pid, 0);
      } catch {
        childAlive = false;
      }
      assert.equal(childAlive, false, "our child stayed alive after adoption");
    } finally {
      winner.kill();
      child.kill();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 rollbackStart does not signal an unverified pid or restore from that lock", async () => {
    const home = join(await tempDir(), "home");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const owned = await livePid();
    const stranger = await livePid();
    let spawns = 0;
    try {
      writeProbeLock(home, {
        pid: stranger.pid,
        marker: "nmzp-probe",
        version: NMZP_VERSION,
        startedAt: Date.now(),
        nonce: "stranger",
        nodePath: process.execPath,
        entry: join(home, "stranger.mjs"),
      });
      const ctrl = createProbeController({
        inspectPid: async (pid) => ({ pid, exe: process.execPath, cmdline: `"${process.execPath}" -e setInterval(()=>{},1000)` }),
        spawnProbe: () => {
          spawns += 1;
          return { pid: 1, kill: () => undefined };
        },
      });
      const rollback = ctrl.rollbackStart;
      assert.equal(typeof rollback, "function", "probe start must expose an ownership rollback");
      if (!rollback) return;
      const result = await rollback(home, {
        disposition: "replaced",
        hidden: true,
        owned: {
          pid: owned.pid,
          nonce: "owned-nonce",
          nodePath: process.execPath,
          entry: join(home, "new.mjs"),
          version: NMZP_VERSION,
          startedAt: Date.now(),
        },
        prior: {
          pid: owned.pid,
          nonce: "prior-nonce",
          nodePath: process.execPath,
          entry: join(home, "old.mjs"),
          version: "0.0.1",
          startedAt: Date.now(),
        },
      });
      assert.equal(result.ok, false);
      assert.match(result.error ?? "", /probe_stop_unverified/);
      assert.equal(spawns, 0, "prior probe was restored from an unverified lock");
      process.kill(owned.pid, 0);
      process.kill(stranger.pid, 0);
      assert.equal(readProbeLock(home)?.pid, stranger.pid, "stranger lock was removed");
    } finally {
      owned.kill();
      stranger.kill();
      await rm(home, { recursive: true, force: true });
    }
  });
});

describe("hidden startup launcher", () => {
  it("uses a vbs hidden entry without ExecutionPolicy Bypass", () => {
    assert.equal(STARTUP_LAUNCHER_NAME.endsWith(".vbs"), true);
    const spaced = "C:\\rt dir\\nmzp.mjs";
    const body = startupLauncherBody("C:\\Program Files\\nodejs\\node.exe", spaced, "C:\\tmp home");
    assert.match(body, /NMZP_PROBE_LAUNCHER/);
    assert.match(body, /WScript\.Shell/);
    assert.match(body, /sh\.Run cmd, 0, False/);
    assert.match(body, /""C:\\rt dir\\nmzp\.mjs""/);
    assert.doesNotMatch(body, /ExecutionPolicy/i);
    assert.doesNotMatch(body, /Bypass/i);
    assert.doesNotMatch(body, /@echo off/i);
  });

  it("quotes spaced entry in Start-Process ArgumentList as one string", () => {
    const args = probeArgumentList("C:\\rt dir\\nmzp.mjs");
    assert.match(args, /--experimental-strip-types/);
    assert.match(args, /"C:\\rt dir\\nmzp\.mjs"/);
    assert.match(args, /\bprobe\b/);
    const tr = hiddenProbeTr("C:\\Program Files\\nodejs\\node.exe", "C:\\rt dir\\nmzp.mjs", "C:\\tmp home");
    assert.doesNotMatch(tr, /ExecutionPolicy/i);
    assert.doesNotMatch(tr, /Bypass/i);
    assert.match(tr, /WindowStyle Hidden/i);
    assert.match(tr, /rt dir/);
  });

  it("does not claim a same-name Startup file by marker when no manifest hash exists", async () => {
    const dir = await tempDir();
    const startupDir = join(dir, "Startup");
    mkdirSync(startupDir, { recursive: true });
    const path = join(startupDir, STARTUP_LAUNCHER_NAME);
    const prev = startupLauncherBody("C:\\old\\node.exe", "C:\\old\\nmzp.mjs", "C:\\old") + "\r\n' user-later\r\n";
    writeFileSync(path, prev);
    try {
      const r = await defaultLauncherRunner().install({
        startupDir,
        nodePath: "C:\\n\\node.exe",
        entry: "C:\\e\\nmzp.mjs",
        home: "C:\\h",
      });
      assert.equal(r.ok, false);
      assert.equal(r.error, "startup_owned_by_other");
      assert.equal(await readFile(path, "utf8"), prev);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not overwrite a user-modified launcher when manifest hash no longer matches", async () => {
    const dir = await tempDir();
    const startupDir = join(dir, "Startup");
    mkdirSync(startupDir, { recursive: true });
    const runner = defaultLauncherRunner();
    try {
      const first = await runner.install({
        startupDir,
        nodePath: "C:\\n\\node.exe",
        entry: "C:\\e\\nmzp.mjs",
        home: "C:\\h",
      });
      assert.equal(first.ok, true);
      const path = first.path!;
      await writeFile(path, (await readFile(path, "utf8")) + "\r\n' user-later\r\n");
      const second = await runner.install({
        startupDir,
        nodePath: "C:\\n\\node.exe",
        entry: "C:\\e\\nmzp.mjs",
        home: "C:\\h",
        previousWrittenSha256: first.sha256,
      });
      assert.equal(second.ok, false);
      assert.equal(second.error, "startup_conflict");
      assert.match(await readFile(path, "utf8"), /user-later/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("task ownership requires this install's exact command", () => {
    const tr = hiddenProbeTr("C:\\n\\node.exe", "C:\\e\\nmzp.mjs", "C:\\h");
    assert.equal(isOurScheduledTask(`TaskName: NMZPProbe\nTask To Run: ${tr}`, tr), true);
    assert.equal(
      isOurScheduledTask("TaskName: NMZPProbe\nTask To Run: node nmzp.mjs probe", tr),
      false,
    );
  });
});
