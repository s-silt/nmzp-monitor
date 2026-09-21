import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
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
