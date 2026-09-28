/**
 * WP-10 executable checks. Driver runs on producer node; product under test is
 * wp10-out/bin/nmzp.exe. Kills only PIDs it spawned. Data/home under wp10-out.
 */
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { spawn } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { request as httpsRequest } from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TLSSocket } from "node:tls";

const HERE = dirname(fileURLToPath(import.meta.url));
const CHECKOUT = join(HERE, "..", "..");
const OUT = "C:\\Users\\sxl\\Desktop\\NMZP\\wp10-out";
const EXE = join(OUT, "bin", "nmzp.exe");
const EXE_NOCACHE = join(OUT, "bin", "nmzp-nocache.exe");
const RESULTS = join(OUT, "results");
const spawned = new Set();

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sha256Text(text) {
  return createHash("sha256").update(text).digest("hex");
}

function save(name, value) {
  mkdirSync(RESULTS, { recursive: true });
  writeFileSync(join(RESULTS, name), JSON.stringify(value, null, 2));
  return value;
}

function isolatedEnv(extra = {}) {
  const home = join(OUT, "home");
  const data = join(OUT, "data");
  const tmp = join(OUT, "tmp");
  mkdirSync(join(home, ".nmzp"), { recursive: true });
  mkdirSync(data, { recursive: true });
  mkdirSync(tmp, { recursive: true });
  mkdirSync(join(home, "AppData", "Roaming"), { recursive: true });
  mkdirSync(join(home, "AppData", "Local"), { recursive: true });
  const env = { ...process.env, ...extra };
  for (const key of Object.keys(env)) {
    if (/^(npm_|NPM_|PNPM_|YARN_)/.test(key)) delete env[key];
  }
  env.NMZP_HOME = home;
  env.NMZP_DATA = data;
  env.NMZP_BIND = "127.0.0.1";
  env.NMZP_PORT = extra.NMZP_PORT ?? "0";
  env.NMZP_STORAGE_MODE = extra.NMZP_STORAGE_MODE ?? "sqlite";
  env.NMZP_AUDIT_MIN_FREE_MB = "0";
  env.HOME = home;
  env.USERPROFILE = home;
  env.HOMEDRIVE = "C:";
  env.HOMEPATH = home.slice(2);
  env.APPDATA = join(home, "AppData", "Roaming");
  env.LOCALAPPDATA = join(home, "AppData", "Local");
  env.XDG_CONFIG_HOME = join(home, ".config");
  env.XDG_DATA_HOME = join(home, ".local", "share");
  env.TEMP = tmp;
  env.TMP = tmp;
  env.TMPDIR = tmp;
  env.NODE_OPTIONS = "";
  env.NODE_PATH = "";
  env.INIT_CWD = OUT;
  env.PATH = `${join(OUT, "bin")};C:\\Windows\\System32;C:\\Windows`;
  env.NO_COLOR = "1";
  return env;
}

function runExe(args, opts = {}) {
  const exe = opts.exe ?? EXE;
  const env = isolatedEnv(opts.env ?? {});
  const cwd = opts.cwd ?? OUT;
  const input = opts.input;
  const timeoutMs = opts.timeoutMs ?? 30_000;
  return new Promise((resolve) => {
    const child = spawn(exe, args, {
      cwd,
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const pid = child.pid;
    if (pid) spawned.add(pid);
    let stdout = "";
    let stderr = "";
    const t0 = process.hrtime.bigint();
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    const finish = (code, signal, error) => {
      if (pid) spawned.delete(pid);
      resolve({
        code: code ?? (error ? 1 : 0),
        signal: signal ?? null,
        stdout,
        stderr,
        pid: pid ?? null,
        ns: Number(process.hrtime.bigint() - t0),
        execPathTried: exe,
        cwd,
        error: error ? String(error) : null,
      });
    };
    const timer = setTimeout(() => {
      try {
        if (pid) child.kill();
      } catch {
        /* owned */
      }
      finish(1, "timeout", "timeout");
    }, timeoutMs);
    child.on("error", (error) => {
      clearTimeout(timer);
      finish(1, null, error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      finish(code, signal, null);
    });
    if (typeof input === "string") child.stdin.end(input);
    else child.stdin.end();
  });
}

function killOwned(pid) {
  if (!pid || !spawned.has(pid)) return;
  try {
    process.kill(pid);
  } catch {
    /* already gone */
  }
  spawned.delete(pid);
}

function fingerprint(cert) {
  if (!cert?.raw) return "";
  return createHash("sha256").update(cert.raw).digest("hex");
}

function pinnedRequest({
  url,
  method = "GET",
  headers = {},
  body,
  caPem,
  fingerprintSha256,
  timeoutMs = 8000,
}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const expected = fingerprintSha256.toLowerCase().replaceAll(":", "");
    const req = httpsRequest(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers,
        ca: caPem,
        rejectUnauthorized: true,
        checkServerIdentity: (_host, cert) => {
          const got = fingerprint(cert);
          if (got !== expected) return new Error(`tls fingerprint mismatch ${got} != ${expected}`);
          return undefined;
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks);
          resolve({ status: res.statusCode ?? 0, body: raw.toString("utf8"), raw });
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function percentileNearestRank(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

async function stepVersionIsolation() {
  const hidden = `${CHECKOUT}.wp10-hidden`;
  let renamed = false;
  let restoreError = null;
  const restore = () => {
    if (!renamed) return;
    try {
      renameSync(hidden, CHECKOUT);
      renamed = false;
    } catch (error) {
      restoreError = String(error);
    }
  };
  let isolation;
  try {
    try {
      renameSync(CHECKOUT, hidden);
      renamed = true;
    } catch (error) {
      isolation = {
        renamed: false,
        renameError: String(error),
        fallback: "hide business sources then run exe; cwd=wp10-out; bundle abs-path scan",
      };
    }
    const version = await runExe(["--version"], { cwd: OUT, timeoutMs: 20_000 });
    const help = await runExe(["help"], { cwd: OUT, timeoutMs: 20_000 });
    const identity = await runExe(["sea-selftest", "identity"], { cwd: OUT, timeoutMs: 20_000 });
    isolation = {
      ...(isolation ?? { renamed: true }),
      checkoutExistsDuringRun: existsSync(CHECKOUT),
      hiddenExistsDuringRun: existsSync(hidden),
      version,
      help,
      identity,
    };
  } finally {
    restore();
  }
  isolation.checkoutRestored = existsSync(CHECKOUT);
  isolation.restoreError = restoreError;
  const sources = [
    join(CHECKOUT, "core", "cli.ts"),
    join(CHECKOUT, "core", "hook.ts"),
    join(CHECKOUT, "core", "audit", "runtime-worker.ts"),
    join(CHECKOUT, "src", "lib", "monitor", "engine.ts"),
  ];
  const hiddenSources = [];
  try {
    for (const file of sources) {
      const dest = `${file}.wp10hide`;
      renameSync(file, dest);
      hiddenSources.push({ file, dest });
    }
    isolation.sourceHide = {
      hidden: hiddenSources.map((row) => row.file),
      version: await runExe(["--version"], { cwd: OUT, timeoutMs: 20_000 }),
      help: await runExe(["help"], { cwd: OUT, timeoutMs: 20_000 }),
      identity: await runExe(["sea-selftest", "identity"], { cwd: OUT, timeoutMs: 20_000 }),
      hook: await runExe(["hook", "--agent", "grok"], {
        input: `${JSON.stringify({
          hookEventName: "pre_tool_use",
          sessionId: "s-hide",
          toolName: "run_terminal_command",
          toolInput: { command: "git status" },
        })}\n`,
        timeoutMs: 15_000,
      }),
    };
  } catch (error) {
    isolation.sourceHideError = String(error);
  } finally {
    for (const row of hiddenSources.reverse()) {
      try {
        renameSync(row.dest, row.file);
      } catch (error) {
        isolation.sourceHideRestoreError = String(error);
      }
    }
  }
  isolation.sourcesRestored = sources.every((file) => existsSync(file));
  return save("01-version-isolation.json", isolation);
}

async function startServe(opts = {}) {
  const dataDir = opts.dataDir ?? join(OUT, "data");
  if (opts.wipe !== false) {
    rmSync(dataDir, { recursive: true, force: true });
  }
  mkdirSync(dataDir, { recursive: true });
  const pointerPath = join(dataDir, "serve.json");
  try {
    rmSync(pointerPath, { force: true });
  } catch {
    /* */
  }
  const env = isolatedEnv({
    NMZP_PORT: "0",
    NMZP_BIND: "127.0.0.1",
    NMZP_STORAGE_MODE: "sqlite",
    NMZP_DATA: dataDir,
  });
  const spawnedAt = Date.now();
  const child = spawn(EXE, ["serve"], {
    cwd: OUT,
    env,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const pid = child.pid;
  if (pid) spawned.add(pid);
  let stdout = "";
  let stderr = "";
  let exitCode = null;
  let exitSignal = null;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c) => {
    stdout += c;
  });
  child.stderr.on("data", (c) => {
    stderr += c;
  });
  child.on("exit", (code, signal) => {
    exitCode = code;
    exitSignal = signal;
  });
  const deadline = Date.now() + 25_000;
  while (Date.now() < deadline) {
    if (exitCode !== null) {
      return {
        ok: false,
        pid,
        stdout,
        stderr,
        error: `serve exited code=${exitCode} signal=${exitSignal}`,
      };
    }
    if (existsSync(pointerPath)) {
      const pointer = JSON.parse(readFileSync(pointerPath, "utf8"));
      if (pointer.pid === pid && pointer.startedAt >= spawnedAt - 2000) break;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  if (!existsSync(pointerPath)) {
    return { ok: false, pid, stdout, stderr, error: "serve.json missing", exitCode, exitSignal };
  }
  const pointer = JSON.parse(readFileSync(pointerPath, "utf8"));
  if (pointer.pid !== pid) {
    return {
      ok: false,
      pid,
      stdout,
      stderr,
      error: `stale serve.json pid=${pointer.pid} spawned=${pid}`,
    };
  }
  const caPem = readFileSync(join(dataDir, "tls", "server.crt"), "utf8");
  const adminToken = readFileSync(join(dataDir, "admin.token"), "utf8").trim();
  await new Promise((r) => setTimeout(r, 200));
  if (exitCode !== null) {
    return {
      ok: false,
      pid,
      stdout,
      stderr,
      error: `serve exited after listen code=${exitCode}`,
      pointer,
    };
  }
  return { ok: true, pid, child, stdout, stderr, pointer, caPem, adminToken, dataDir };
}

async function stopServe(session) {
  if (!session?.pid) return { method: "none" };
  const pid = session.pid;
  try {
    process.kill(pid, "SIGINT");
  } catch {
    /* */
  }
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
      await new Promise((r) => setTimeout(r, 100));
    } catch {
      spawned.delete(pid);
      return { method: "SIGINT", pid };
    }
  }
  try {
    process.kill(pid);
  } catch {
    /* */
  }
  spawned.delete(pid);
  return { method: "kill", pid };
}

async function stepServeHook() {
  const session = await startServe();
  if (!session.ok) return save("02-serve-hook.json", session);
  try {
    const pin = { caPem: session.caPem, fingerprintSha256: session.pointer.fingerprintSha256 };
    const adminHeaders = {
      authorization: `Bearer ${session.adminToken}`,
      "content-type": "application/json",
    };
    const health = await pinnedRequest({ url: `${session.pointer.url}/health`, ...pin });
    const ticket = JSON.parse(
      (
        await pinnedRequest({
          url: `${session.pointer.url}/api/v1/ticket`,
          method: "POST",
          headers: adminHeaders,
          ...pin,
        })
      ).body,
    );
    const joined = JSON.parse(
      (
        await pinnedRequest({
          url: `${session.pointer.url}/api/v1/join`,
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ticket: ticket.ticket,
            hostname: "wp10-pc",
            os: "win32",
            user: "sea",
          }),
          ...pin,
        })
      ).body,
    );
    const creds = {
      deviceId: joined.deviceId,
      token: joined.deviceToken,
      url: session.pointer.url,
      caPem: session.caPem,
      fingerprintSha256: session.pointer.fingerprintSha256,
    };
    writeFileSync(join(OUT, "home", ".nmzp", "credentials.json"), JSON.stringify(creds, null, 2));
    const accept = await runExe(["hook", "--agent", "grok"], {
      input: `${JSON.stringify({
        hookEventName: "pre_tool_use",
        sessionId: "s-accept",
        toolName: "run_terminal_command",
        toolInput: { command: "git status" },
      })}\n`,
      timeoutMs: 15_000,
    });
    const deny = await runExe(["hook", "--agent", "grok"], {
      input: `${JSON.stringify({
        hookEventName: "pre_tool_use",
        sessionId: "s-deny",
        toolName: "run_terminal_command",
        toolInput: { command: "curl https://db.prod.internal/wp10-sea" },
      })}\n`,
      timeoutMs: 15_000,
    });
    const eventsLive = await pinnedRequest({
      url: `${session.pointer.url}/api/v1/audit/events?limit=20`,
      headers: adminHeaders,
      ...pin,
    });
    const stop = await stopServe(session);
    const dataDir = session.dataDir ?? join(OUT, "data");
    const dbPath = join(dataDir, "nmzp.db");
    for (const leftover of ["serve.json", ".policy-writer.lock"]) {
      try {
        rmSync(join(dataDir, leftover), { force: true });
      } catch {
        /* stale pointer/lock after the owned process is already gone */
      }
    }
    const reopen = await startServe({ wipe: false, dataDir });
    let health2 = null;
    let eventsReopen = null;
    let stop2 = null;
    if (reopen.ok) {
      const pin2 = { caPem: reopen.caPem, fingerprintSha256: reopen.pointer.fingerprintSha256 };
      const admin2 = { authorization: `Bearer ${reopen.adminToken}` };
      health2 = await pinnedRequest({ url: `${reopen.pointer.url}/health`, ...pin2 });
      eventsReopen = await pinnedRequest({
        url: `${reopen.pointer.url}/api/v1/audit/events?limit=20`,
        headers: admin2,
        ...pin2,
      });
      stop2 = await stopServe(reopen);
    }
    return save("02-serve-hook.json", {
      servePid: session.pid,
      serveStdout: session.stdout,
      serveStderr: session.stderr.slice(0, 2000),
      pointer: session.pointer,
      health: { status: health.status, body: health.body },
      ticketOk: typeof ticket.ticket === "string",
      joined: { deviceId: joined.deviceId, hasToken: typeof joined.deviceToken === "string" },
      accept,
      deny,
      eventsLive: { status: eventsLive.status, body: eventsLive.body.slice(0, 4000) },
      stop,
      dbExists: existsSync(dbPath),
      dbSha256: existsSync(dbPath) ? sha256File(dbPath) : null,
      reopenOk: reopen.ok,
      reopenError: reopen.error ?? null,
      health2: health2 ? { status: health2.status, body: health2.body } : null,
      eventsReopen: eventsReopen
        ? { status: eventsReopen.status, body: eventsReopen.body.slice(0, 4000) }
        : null,
      stop2,
    });
  } catch (error) {
    await stopServe(session).catch(() => undefined);
    return save("02-serve-hook.json", {
      ok: false,
      error: String(error),
      stack: error instanceof Error ? error.stack : null,
      stdout: session.stdout,
      stderr: session.stderr,
    });
  }
}

async function stepSelftests() {
  const sqlite = await runExe(["sea-selftest", "sqlite"], { timeoutMs: 20_000 });
  const audit = await runExe(["sea-selftest", "audit-worker"], { timeoutMs: 25_000 });
  const respawn = await runExe(["sea-selftest", "respawn"], { timeoutMs: 25_000 });
  return save("03-selftests.json", { sqlite, audit, respawn });
}

async function stepCacheTiming() {
  const n = 20;
  async function dist(exe, args, input) {
    const samples = [];
    for (let i = 0; i < n; i += 1) {
      const r = await runExe(args, { exe, input, timeoutMs: 20_000 });
      samples.push({
        i,
        ns: r.ns,
        ms: r.ns / 1e6,
        code: r.code,
        stdout: r.stdout.slice(0, 120),
        stderr: r.stderr.slice(0, 200),
      });
    }
    const sorted = samples.map((s) => s.ms).sort((a, b) => a - b);
    return {
      n,
      method:
        "spawn exe, wait close, process.hrtime.bigint ns, sequential cold subprocess, nearest-rank p95=ceil(0.95*n)-1",
      firstInSessionMs: samples[0]?.ms ?? null,
      firstAfterReboot: "NOT_RUN",
      min: sorted[0] ?? null,
      median: percentileNearestRank(sorted, 50),
      p95: percentileNearestRank(sorted, 95),
      max: sorted[sorted.length - 1] ?? null,
      samples,
    };
  }
  const cacheFile = join(OUT, "home", ".nmzp", "policy-cache.json");
  const policy = {
    version: 1,
    mode: "enforcing",
    customRules: [],
    stopped: false,
    updatedAt: Date.now(),
  };
  writeFileSync(
    cacheFile,
    JSON.stringify({ policy, sha256: sha256Text(JSON.stringify(policy)), savedAt: Date.now() }),
  );
  const hookInput = `${JSON.stringify({
    hookEventName: "pre_tool_use",
    sessionId: "s-bench",
    toolName: "run_terminal_command",
    toolInput: { command: "git status" },
  })}\n`;
  const result = {
    versionCacheOn: await dist(EXE, ["--version"]),
    versionCacheOff: await dist(EXE_NOCACHE, ["--version"]),
    hookCacheOn: await dist(EXE, ["hook", "--agent", "grok"], hookInput),
    hookCacheOff: await dist(EXE_NOCACHE, ["hook", "--agent", "grok"], hookInput),
  };
  return save("04-cache-timing.json", result);
}

async function stepSigning() {
  const src = EXE;
  const signedCopy = join(OUT, "sign", "nmzp-ed25519-target.exe");
  const mutated = join(OUT, "sign", "nmzp-mutated.exe");
  mkdirSync(join(OUT, "sign"), { recursive: true });
  mkdirSync(join(OUT, "keys"), { recursive: true });
  copyFileSync(src, signedCopy);
  copyFileSync(src, mutated);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = readFileSync(signedCopy);
  const signature = sign(null, payload, privateKey);
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  writeFileSync(join(OUT, "keys", "wp10-test-only-ed25519.pub"), pubDer);
  writeFileSync(join(OUT, "keys", "wp10-test-only-ed25519.pem"), privPem);
  writeFileSync(join(OUT, "sign", "nmzp.exe.ed25519.sig"), signature);
  const ok = verify(null, payload, publicKey, signature);
  const buf = Buffer.from(readFileSync(mutated));
  buf[buf.length - 1] = buf[buf.length - 1] ^ 0x01;
  writeFileSync(mutated, buf);
  const mutatedOk = verify(null, readFileSync(mutated), publicKey, signature);
  const authenticode = {
    attempted: true,
    note: "test-only CurrentUser self-signed; removed after",
  };
  try {
    authenticode.powershell = "see 05-authenticode.json from sidecar if present";
  } catch (error) {
    authenticode.error = String(error);
  }
  return save("05-signing.json", {
    label: "TEST-ONLY disposable Ed25519. NOT production trust.",
    targetSha256: sha256File(signedCopy),
    mutatedSha256: sha256File(mutated),
    signatureSha256: sha256File(join(OUT, "sign", "nmzp.exe.ed25519.sig")),
    verifyOriginal: ok,
    verifyMutatedOneByte: mutatedOk,
    mutationRejected: ok === true && mutatedOk === false,
    authenticode,
  });
}

async function stepLinux() {
  const r = await new Promise((resolve) => {
    const child = spawn("wsl.exe", ["-l", "--quiet"], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    child.on("error", (error) => resolve({ code: 1, error: String(error), stdout, stderr }));
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
  return save("06-linux.json", {
    status: "NOT_RUN",
    reason: "no local Linux distro/Docker; WSL not installed",
    wsl: r,
  });
}

async function main() {
  mkdirSync(RESULTS, { recursive: true });
  const bundle = existsSync(join(RESULTS, "build.json"))
    ? JSON.parse(readFileSync(join(RESULTS, "build.json"), "utf8"))
    : null;
  const out = {
    exe: existsSync(EXE)
      ? { path: EXE, sha256: sha256File(EXE), bytes: readFileSync(EXE).length }
      : null,
    exeNocache: existsSync(EXE_NOCACHE)
      ? {
          path: EXE_NOCACHE,
          sha256: sha256File(EXE_NOCACHE),
          bytes: readFileSync(EXE_NOCACHE).length,
        }
      : null,
    mainScan: bundle?.mainBundle?.scan ?? null,
    workerScan: bundle?.workerBundle?.scan ?? null,
  };
  save("00-artifacts.json", out);
  const only = new Set(process.argv.slice(2));
  const want = (name) => only.size === 0 || only.has(name);
  try {
    if (want("isolation")) out.versionIsolation = await stepVersionIsolation();
    if (want("selftest")) out.selftests = await stepSelftests();
    if (want("serve")) out.serveHook = await stepServeHook();
    if (want("cache")) out.cacheTiming = await stepCacheTiming();
    if (want("sign")) {
      out.signing = await stepSigning();
      out.authenticodeRun = await new Promise((resolve) => {
        const child = spawn(
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          ["-NoProfile", "-NonInteractive", "-File", join(HERE, "authenticode.ps1")],
          {
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (c) => {
          stdout += c;
        });
        child.stderr.on("data", (c) => {
          stderr += c;
        });
        child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
      });
    }
    if (want("linux")) out.linux = await stepLinux();
  } finally {
    for (const pid of [...spawned]) killOwned(pid);
  }
  save("run-checks.json", out);
  process.stdout.write(`${JSON.stringify({ ok: true, wrote: RESULTS }, null, 2)}\n`);
}

await main();
void createHttpsServer;
void TLSSocket;
