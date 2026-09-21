import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createCipheriv } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
  DIR_DENY_RIGHTS,
  FILE_DENY_RIGHTS,
  MAX_GUARD_ENTRIES,
  buildSnapshotGuardPsInvocation,
  isSnapshotGuardSupported,
  parseSnapshotGuardCli,
  powershellExe,
  publicSnapshotGuardStatus,
  resolveGuardPaths,
  snapshotGuardApply,
  snapshotGuardRestore,
  snapshotGuardStatus,
  toSnapshotGuardCapability,
  type SnapshotGuardStatus,
} from "./snapshot-guard.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const realCheckpoints = resolve(homedir(), ".zcode", "v2", "checkpoints");
const win = process.platform === "win32";

function norm(p: string): string {
  return resolve(p).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

function underTmp(p: string): boolean {
  return norm(p) === norm(tmpdir()) || norm(p).startsWith(`${norm(tmpdir())}/`);
}

function assertSafeTempPath(p: string): void {
  assert.ok(underTmp(p), `refusing path outside tmp: ${p}`);
  assert.notEqual(norm(p), norm(realCheckpoints));
  assert.ok(!norm(p).startsWith(norm(realCheckpoints)));
}

function icacls(p: string): string {
  const r = spawnSync("icacls", [p], { encoding: "utf8", windowsHide: true });
  return `${r.stdout || ""}\n${r.stderr || ""}`;
}

function forceResetTempAcl(p: string): void {
  if (!win || !existsSync(p) || !underTmp(p)) return;
  spawnSync("icacls", [p, "/reset", "/T", "/C", "/Q"], { encoding: "utf8", windowsHide: true });
}

async function makeFixture(): Promise<{
  dir: string;
  home: string;
  target: string;
  workspace: string;
  other: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-"));
  const home = join(dir, "home");
  const target = join(home, ".zcode", "v2", "checkpoints");
  const workspace = join(dir, "workspace");
  const other = join(dir, "other");
  await mkdir(target, { recursive: true });
  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(workspace, ".git", "objects", "ab"), { recursive: true });
  await mkdir(other, { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const n = 1;\n");
  await writeFile(join(workspace, ".git", "objects", "ab", "cdef"), Buffer.from("fake-git-object"));
  await writeFile(join(other, "keep.txt"), "ok");
  assertSafeTempPath(target);
  assertSafeTempPath(home);
  return { dir, home, target, workspace, other };
}

async function cleanupFixture(dir: string, home: string, target: string): Promise<void> {
  assertSafeTempPath(dir);
  try {
    await snapshotGuardRestore({ home });
  } catch {
    /* restore best-effort before rm */
  }
  forceResetTempAcl(target);
  forceResetTempAcl(join(home, ".nmzp"));
  forceResetTempAcl(dir);
  await rm(dir, { recursive: true, force: true });
  if (existsSync(dir)) {
    forceResetTempAcl(dir);
    await rm(dir, { recursive: true, force: true });
  }
  assert.equal(existsSync(dir), false, `orphan temp dir ${dir}`);
}

function writeBlockedByFs(dir: string): boolean {
  const p = join(dir, `.nmzp-sg-test-${process.pid}-${Date.now()}`);
  try {
    const fd = openSync(p, "wx");
    closeSync(fd);
    try {
      unlinkSync(p);
    } catch {
      /* test leftover */
    }
    return false;
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    return err.code === "EACCES" || err.code === "EPERM";
  }
}

function tryReadFile(p: string): boolean {
  try {
    readFileSync(p);
    return true;
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    return !(err.code === "EACCES" || err.code === "EPERM");
  }
}

function spawnNode(args: string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, args, { cwd, windowsHide: true });
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
    child.on("close", (code) => resolvePromise({ code: code ?? 1, stdout, stderr }));
  });
}

function startReceiver(): Promise<{
  url: string;
  hits: number;
  bodies: Buffer[];
  close: () => Promise<void>;
}> {
  let hits = 0;
  const bodies: Buffer[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      chunks.push(c);
    });
    req.on("end", () => {
      hits += 1;
      bodies.push(Buffer.concat(chunks));
      res.statusCode = 200;
      res.end("ok");
    });
  });
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("receiver_bind");
      resolvePromise({
        get url() {
          return `http://127.0.0.1:${addr.port}/upload`;
        },
        get hits() {
          return hits;
        },
        bodies,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
          }),
      });
    });
  });
}

const PACKER = `import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { createCipheriv } from "node:crypto";
import http from "node:http";

const mode = process.argv[2];
const workspace = process.argv[3];
const checkpoint = process.argv[4];
const url = process.argv[5];
const pendingName = process.argv[6] || "workspace.tar.gz.enc";

function walk(dir, rel, out) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const r = rel ? rel + "/" + name : name;
    const st = statSync(p);
    if (st.isDirectory()) walk(p, r, out);
    else out.push(Buffer.concat([Buffer.from(r + "\\n"), readFileSync(p)]));
  }
}

function pack() {
  const parts = [];
  walk(workspace, "", parts);
  const gz = gzipSync(Buffer.concat(parts));
  const cipher = createCipheriv("aes-256-ctr", Buffer.alloc(32, 7), Buffer.alloc(16, 3));
  const enc = Buffer.concat([cipher.update(gz), cipher.final()]);
  writeFileSync(join(checkpoint, pendingName), enc);
  return enc;
}

function send(buf) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: u.port,
        path: u.pathname,
        method: "POST",
        headers: { "content-length": String(buf.length), "content-type": "application/octet-stream" },
      },
      (res) => {
        res.resume();
        res.on("end", resolve);
      },
    );
    req.on("error", reject);
    req.end(buf);
  });
}

const run = async () => {
  if (mode === "pack-send") await send(pack());
  else if (mode === "read-send") await send(readFileSync(join(checkpoint, pendingName)));
  else throw new Error("bad_mode");
};
run().catch((e) => {
  const code = e && e.code ? String(e.code) : "fail";
  process.stderr.write(code + "\\n");
  process.exit(1);
});
`;

function fields(s: SnapshotGuardStatus): string[] {
  return [
    "supported",
    "active",
    "managed",
    "targetPresent",
    "writeBlocked",
    "existingArchiveCoverage",
    "error",
    "lastVerified",
  ].filter((k) => k in s || true);
}

describe("snapshot-guard path and platform contract", () => {
  it("pins production target to home/.zcode/v2/checkpoints and rejects other layouts", () => {
    const home = win ? "C:\\Users\\fixture-home" : "/home/fixture";
    const p = resolveGuardPaths(home);
    assert.equal(norm(p.target), norm(join(p.home, ".zcode", "v2", "checkpoints")));
    assert.equal(norm(p.manifest), norm(join(p.home, ".nmzp", "snapshot-guard.json")));
    assert.notEqual(norm(p.manifest), norm(p.target));
    assert.ok(!norm(p.manifest).startsWith(`${norm(p.target)}/`));
    assert.equal(MAX_GUARD_ENTRIES > 0 && MAX_GUARD_ENTRIES <= 1024, true);
    assert.ok((DIR_DENY_RIGHTS & 0x100000) === 0);
    assert.ok((FILE_DENY_RIGHTS & 0x100000) === 0);
  });

  it("does not treat linux/darwin as supported this round", () => {
    assert.equal(isSnapshotGuardSupported("linux"), false);
    assert.equal(isSnapshotGuardSupported("darwin"), false);
    assert.equal(isSnapshotGuardSupported("win32"), true);
  });

  it("status on unsupported platform does not claim protection", async () => {
    if (win) return;
    const st = await snapshotGuardStatus({ home: join(tmpdir(), "nmzp-sg-posix-home") });
    assert.equal(st.supported, false);
    assert.equal(st.active, false);
    assert.equal(st.managed, false);
    assert.equal(st.error, "unsupported_platform");
    const cap = toSnapshotGuardCapability(st);
    assert.equal(cap.supported, false);
    assert.equal(cap.active, false);
  });

  it("CLI parse only accepts status/apply/restore and --home, never a raw target path flag", () => {
    const s = parseSnapshotGuardCli(["status"]);
    assert.equal(s.ok, true);
    if (s.ok) {
      assert.equal(s.cmd, "status");
      assert.equal(norm(s.home), norm(homedir()));
    }
    const a = parseSnapshotGuardCli(["apply", "--home", join(tmpdir(), "h")]);
    assert.equal(a.ok, true);
    if (a.ok) {
      assert.equal(a.cmd, "apply");
      assert.equal(norm(a.home), norm(join(tmpdir(), "h")));
    }
    const bad = parseSnapshotGuardCli(["status", "--target", "C:\\\\Users\\\\dev\\\\.zcode\\\\v2\\\\checkpoints"]);
    assert.equal(bad.ok, false);
  });

  it("public status has the root integration fields and no path inventory", () => {
    const pub = publicSnapshotGuardStatus({
      supported: true,
      active: false,
      managed: false,
      targetPresent: true,
      writeBlocked: true,
      existingArchiveCoverage: "unknown",
      error: "external_restriction",
      lastVerified: 1,
      zcodeRunning: false,
    });
    for (const k of [
      "supported",
      "active",
      "managed",
      "targetPresent",
      "writeBlocked",
      "existingArchiveCoverage",
      "error",
      "lastVerified",
    ]) {
      assert.ok(k in pub);
    }
    assert.equal(JSON.stringify(pub).includes(".zcode"), false);
    assert.equal(JSON.stringify(pub).toLowerCase().includes("checkpoint"), false);
    assert.equal("zcodeRunning" in pub, false);
    const mapped = publicSnapshotGuardStatus({
      supported: true,
      active: false,
      managed: false,
      targetPresent: true,
      writeBlocked: false,
      existingArchiveCoverage: "unprotected",
      lastVerified: 2,
    });
    assert.equal(mapped.existingArchiveCoverage, "partial");
  });
});

describe("snapshot-guard windows helper invocation", () => {
  it("EncodedCommand carries no JSON path payload in argv", () => {
    const input = join(tmpdir(), "nmzp-sg-in.json");
    const inv = buildSnapshotGuardPsInvocation(input);
    assert.equal(inv.args.includes("-EncodedCommand"), true);
    assert.equal(inv.args.some((a) => a.includes(input)), false);
    assert.equal(inv.args.some((a) => /ExecutionPolicy|Bypass/i.test(a)), false);
    assert.equal(inv.env.NMZP_SG_INPUT, input);
    if (win) {
      const exe = powershellExe();
      assert.equal(inv.file, exe);
      assert.match(exe.replace(/\\/g, "/").toLowerCase(), /\/system32\/windowspowershell\/v1\.0\/powershell\.exe$/);
    }
  });
});

describe("snapshot-guard missing target and temp status", { skip: !win }, () => {
  it("reports target_missing without creating the real or temp checkpoints", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-miss-"));
    const home = join(dir, "home");
    try {
      const st = await snapshotGuardStatus({ home });
      assert.equal(st.supported, true);
      assert.equal(st.targetPresent, false);
      assert.equal(st.active, false);
      assert.equal(st.managed, false);
      assert.equal(st.error, "target_missing");
      assert.equal(existsSync(join(home, ".zcode", "v2", "checkpoints")), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("snapshot-guard real NTFS ACL", { skip: !win }, () => {
  it("unprotected temp dir is writable; apply blocks new packs; restore returns write", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const before = await snapshotGuardStatus({ home: fx.home });
      assert.equal(before.supported, true);
      assert.equal(before.targetPresent, true);
      assert.equal(before.managed, false);
      assert.equal(before.writeBlocked, false);
      assert.equal(before.active, false);
      assert.equal(writeBlockedByFs(fx.target), false);

      const parent = join(fx.home, ".zcode", "v2");
      const parentAcl = icacls(parent);
      const beforeTarget = icacls(fx.target);
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.error, undefined, JSON.stringify(applied));
      assert.equal(applied.managed, true);
      assert.equal(applied.writeBlocked, true);
      assert.equal(applied.active, true);
      assert.equal(applied.existingArchiveCoverage, "none");
      assert.equal(writeBlockedByFs(fx.target), true);
      await assert.rejects(() => writeFile(join(fx.target, "workspace.tar.gz.enc"), Buffer.from("x")), /EACCES|EPERM/);
      assert.equal(icacls(parent), parentAcl);
      assert.ok(readdirSync(fx.target));
      assert.equal(DIR_DENY_RIGHTS & 0x100000, 0);
      assert.equal(FILE_DENY_RIGHTS & 0x100000, 0);
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), true);
      assert.ok(!norm(join(fx.home, ".nmzp", "snapshot-guard.json")).startsWith(`${norm(fx.target)}/`));

      const again = await snapshotGuardApply({ home: fx.home });
      assert.equal(again.managed, true);
      assert.equal(again.writeBlocked, true);
      assert.equal(writeBlockedByFs(fx.target), true);

      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, undefined, JSON.stringify(restored));
      assert.equal(restored.managed, false);
      assert.equal(writeBlockedByFs(fx.target), false);
      assert.equal(icacls(fx.target), beforeTarget);
      await writeFile(join(fx.target, "after-restore.txt"), "ok");
      const restoredAgain = await snapshotGuardRestore({ home: fx.home });
      assert.ok(restoredAgain.error === "not_managed" || restoredAgain.error === undefined, JSON.stringify(restoredAgain));
      assert.equal(existsSync(join(fx.target, "after-restore.txt")), true);
      assert.equal(writeBlockedByFs(fx.target), false);
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("blocks independent packer process and loopback upload after lock; control group delivers once", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    const packer = join(fx.dir, "packer.mjs");
    await writeFile(packer, PACKER);
    const receiver = await startReceiver();
    try {
      const unlocked = await spawnNode(
        [packer, "pack-send", fx.workspace, fx.target, receiver.url],
        fx.dir,
      );
      assert.equal(unlocked.code, 0, unlocked.stderr);
      assert.equal(receiver.hits, 1);
      assert.ok(receiver.bodies[0] && receiver.bodies[0].length > 0);
      assert.equal(receiver.bodies[0]!.includes("fake-git-object"), false);
      assert.equal(receiver.bodies[0]!.includes("export const n = 1"), false);
      assert.equal(existsSync(join(fx.workspace, ".git", "objects", "ab", "cdef")), true);
      await rm(join(fx.target, "workspace.tar.gz.enc"), { force: true });

      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.writeBlocked, true, JSON.stringify(applied));
      assert.equal(applied.active, true);

      const locked1 = await spawnNode(
        [packer, "pack-send", fx.workspace, fx.target, receiver.url],
        fx.dir,
      );
      assert.notEqual(locked1.code, 0);
      const locked2 = await spawnNode(
        [packer, "pack-send", fx.workspace, fx.target, receiver.url],
        fx.dir,
      );
      assert.notEqual(locked2.code, 0);
      assert.equal(receiver.hits, 1);
      const names = existsSync(fx.target) ? readdirSync(fx.target) : [];
      assert.equal(
        names.some((n) => n.endsWith(".enc") || n.endsWith(".tar.gz")),
        false,
      );

      await writeFile(join(fx.other, "npm-like.txt"), "from-other-dir");
      const nodeOk = await spawnNode(["-e", "process.stdout.write('ok')"], fx.other);
      assert.equal(nodeOk.code, 0);
      assert.equal(nodeOk.stdout, "ok");
      assert.equal(readFileSync(join(fx.other, "keep.txt"), "utf8"), "ok");
      assert.equal(readFileSync(join(fx.workspace, "src", "app.ts"), "utf8"), "export const n = 1;\n");
    } finally {
      await receiver.close();
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("blocks reading an existing pending archive for upload after lock without deleting it", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    const packer = join(fx.dir, "packer.mjs");
    await writeFile(packer, PACKER);
    const pending = join(fx.target, "pending", "workspace.tar.gz.enc");
    await mkdir(join(fx.target, "pending"), { recursive: true });
    const gz = gzipSync(Buffer.from("fixture-source-and-git"));
    const cipher = createCipheriv("aes-256-ctr", Buffer.alloc(32, 7), Buffer.alloc(16, 3));
    const enc = Buffer.concat([cipher.update(gz), cipher.final()]);
    await writeFile(pending, enc);
    const size = statSync(pending).size;
    const receiver = await startReceiver();
    try {
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      assert.equal(applied.writeBlocked, true);
      assert.ok(applied.existingArchiveCoverage === "protected" || applied.existingArchiveCoverage === "partial");
      assert.equal(existsSync(pending), true);
      assert.equal(statSync(pending).size, size);
      assert.equal(tryReadFile(pending), false);
      const sent = await spawnNode(
        [packer, "read-send", fx.workspace, join(fx.target, "pending"), receiver.url, "workspace.tar.gz.enc"],
        fx.dir,
      );
      assert.notEqual(sent.code, 0);
      assert.equal(receiver.hits, 0);
    } finally {
      await receiver.close();
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("does not follow a junction to change ACL elsewhere", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-junc-"));
    const home = join(dir, "home");
    const realDir = join(dir, "real-cp");
    const target = join(home, ".zcode", "v2", "checkpoints");
    try {
      await mkdir(realDir, { recursive: true });
      await writeFile(join(realDir, "marker.txt"), "keep");
      await mkdir(join(home, ".zcode", "v2"), { recursive: true });
      await symlink(realDir, target, "junction");
      assert.equal(lstatSync(target).isSymbolicLink(), true);
      const before = icacls(realDir);
      const st = await snapshotGuardApply({ home });
      assert.equal(st.error, "reparse_rejected");
      assert.equal(st.managed, false);
      assert.equal(icacls(realDir), before);
      assert.equal(readFileSync(join(realDir, "marker.txt"), "utf8"), "keep");
    } finally {
      forceResetTempAcl(target);
      forceResetTempAcl(realDir);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("treats unmanaged existing deny as external lock: write blocked, coverage unknown, not restored", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      await writeFile(join(fx.target, "pending-old.tar.gz.enc"), Buffer.from("cipher"));
      const sidScript =
        "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value";
      const sid = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", sidScript], {
        encoding: "utf8",
        windowsHide: true,
      });
      assert.equal(sid.status, 0, sid.stderr);
      const userSid = (sid.stdout || "").trim();
      const deny =
        `(DENY;OICI;DCLCDTSD;;;${userSid})`;
      const acl = spawnSync(
        "icacls",
        [fx.target, "/deny", `*${userSid}:(WD,AD,DC,DE,WA,WEA)`],
        { encoding: "utf8", windowsHide: true },
      );
      assert.equal(acl.status === 0 || /successfully/i.test(acl.stdout || ""), true, acl.stdout + acl.stderr);
      const st = await snapshotGuardStatus({ home: fx.home });
      assert.equal(st.managed, false);
      assert.equal(st.writeBlocked, true);
      assert.equal(st.active, false);
      assert.ok(st.existingArchiveCoverage === "unknown" || st.existingArchiveCoverage === "unprotected");
      assert.equal(st.error, "external_restriction");
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), false);

      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, false);
      assert.equal(applied.error, "external_restriction");
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), false);

      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.managed, false);
      assert.equal(restored.error, "not_managed");
      assert.equal(writeBlockedByFs(fx.target), true);
      void deny;
      assert.equal(existsSync(join(fx.target, "pending-old.tar.gz.enc")), true);
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("restore reports conflict and keeps user ACL when identity/ACL changed after apply", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      await writeFile(join(fx.target, "keep.enc"), Buffer.from("abc"));
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      forceResetTempAcl(fx.target);
      await writeFile(join(fx.target, "keep.enc"), Buffer.from("replaced-by-user"));
      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, "conflict");
      assert.equal(readFileSync(join(fx.target, "keep.enc"), "utf8"), "replaced-by-user");
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("does not revoke a pre-opened handle; documents stop-old-client boundary", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    const pending = join(fx.target, "open-handle.enc");
    const fd = openSync(pending, "w");
    try {
      writeSync(fd, Buffer.from("before"));
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.writeBlocked, true, JSON.stringify(applied));
      writeSync(fd, Buffer.from("+after"));
      closeSync(fd);
      assert.ok(statSync(pending).size >= 6);
    } finally {
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("refuses apply when ZCode running cannot be excluded", { timeout: 30_000 }, async () => {
    const fx = await makeFixture();
    try {
      const running = await snapshotGuardApply({
        home: fx.home,
        checkZcode: async () => ({ ok: true, running: true }),
      });
      assert.equal(running.error, "zcode_running");
      assert.equal(running.managed, false);
      assert.equal(writeBlockedByFs(fx.target), false);

      const unknown = await snapshotGuardApply({
        home: fx.home,
        checkZcode: async () => ({ ok: false, running: false }),
      });
      assert.equal(unknown.error, "process_list_failed");
      assert.equal(unknown.managed, false);
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("rolls back earlier ACL mutations when a later target fails", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      await writeFile(join(fx.target, "one.enc"), Buffer.from("a"));
      await mkdir(join(fx.target, "pending"), { recursive: true });
      await writeFile(join(fx.target, "pending", "two.enc"), Buffer.from("b"));
      const before = icacls(fx.target);
      const failed = await snapshotGuardApply({ home: fx.home, failAfter: 1 });
      assert.equal(failed.error, "apply_failed", JSON.stringify(failed));
      assert.equal(failed.managed, false);
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), false);
      assert.equal(writeBlockedByFs(fx.target), false);
      assert.equal(icacls(fx.target), before);
      await writeFile(join(fx.target, "after-fail.txt"), "ok");
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("keeps an external ACE after pending recovery and does not force-overwrite", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      await writeFile(join(fx.target, "one.enc"), Buffer.from("a"));
      const failed = await snapshotGuardApply({ home: fx.home, failAfter: 1, leavePending: true });
      assert.equal(failed.error, "apply_failed", JSON.stringify(failed));
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), true);
      const sid = spawnSync(
        powershellExe(),
        ["-NoProfile", "-NonInteractive", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
        { encoding: "utf8", windowsHide: true },
      );
      const userSid = (sid.stdout || "").trim();
      const extra = spawnSync("icacls", [fx.target, "/deny", `*${userSid}:(R)`], { encoding: "utf8", windowsHide: true });
      assert.ok(extra.status === 0 || /successfully/i.test(extra.stdout || ""), extra.stdout + extra.stderr);
      const afterExtra = icacls(fx.target);
      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, "conflict", JSON.stringify(restored));
      assert.equal(icacls(fx.target), afterExtra);
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), true);
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("does not modify ACL when object identity changes before pending recovery", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const f = join(fx.target, "one.enc");
      await writeFile(f, Buffer.from("a"));
      const failed = await snapshotGuardApply({ home: fx.home, failAfter: 1, leavePending: true });
      assert.equal(failed.error, "apply_failed", JSON.stringify(failed));
      await writeFile(f, Buffer.from("replaced-identity"));
      const afterSwap = icacls(f);
      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, "conflict", JSON.stringify(restored));
      assert.equal(icacls(f), afterSwap);
      assert.equal(readFileSync(f, "utf8"), "replaced-identity");
      assert.equal(existsSync(join(fx.home, ".nmzp", "snapshot-guard.json")), true);
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("does not unlock from a pending journal that lacks expected SDDL", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      const manPath = join(fx.home, ".nmzp", "snapshot-guard.json");
      const man = JSON.parse(readFileSync(manPath, "utf8")) as { phase: string; objects: Array<{ expectedSddl: string }> };
      man.phase = "pending";
      for (const o of man.objects) o.expectedSddl = "";
      await writeFile(manPath, JSON.stringify(man));
      const before = icacls(fx.target);
      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, "conflict", JSON.stringify(restored));
      assert.equal(icacls(fx.target), before);
      assert.equal(writeBlockedByFs(fx.target), true);
      assert.equal(existsSync(manPath), true);
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("refuses apply when .nmzp is a junction and does not change the junction target", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sg-nmzp-junc-"));
    const home = join(dir, "home");
    const elsewhere = join(dir, "elsewhere");
    const target = join(home, ".zcode", "v2", "checkpoints");
    try {
      await mkdir(elsewhere, { recursive: true });
      await writeFile(join(elsewhere, "marker.txt"), "keep");
      await mkdir(target, { recursive: true });
      await symlink(elsewhere, join(home, ".nmzp"), "junction");
      const before = icacls(elsewhere);
      const st = await snapshotGuardApply({ home });
      assert.equal(st.error, "reparse_rejected", JSON.stringify(st));
      assert.equal(st.managed, false);
      assert.equal(icacls(elsewhere), before);
      assert.equal(readFileSync(join(elsewhere, "marker.txt"), "utf8"), "keep");
    } finally {
      forceResetTempAcl(join(home, ".nmzp"));
      forceResetTempAcl(elsewhere);
      forceResetTempAcl(target);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reapply failure rolls back only needAdd and keeps other guarded ACLs", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const keep = join(fx.target, "keep");
      const redo = join(fx.target, "redo");
      await mkdir(keep, { recursive: true });
      await mkdir(redo, { recursive: true });
      await writeFile(join(redo, "x.enc"), Buffer.from("enc"));
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      assert.equal(applied.active, true);
      const rootAcl = icacls(fx.target);
      const keepAcl = icacls(keep);
      const manPath = join(fx.home, ".nmzp", "snapshot-guard.json");
      const man = JSON.parse(readFileSync(manPath, "utf8")) as {
        objects: Array<{ rel: string; originalSddl: string; expectedSddl: string }>;
      };
      const rels = ["redo", "redo/x.enc"];
      const items = rels.map((rel) => {
        const o = man.objects.find((x) => x.rel === rel);
        assert.ok(o, rel);
        return {
          path: join(fx.target, ...rel.split("/")),
          originalSddl: o!.originalSddl,
          expectedSddl: o!.expectedSddl,
        };
      });
      const input = join(fx.home, ".nmzp", "sg-test-in.json");
      writeFileSync(input, JSON.stringify({ action: "restoreSddl", items }));
      const inv = buildSnapshotGuardPsInvocation(input);
      const restoredOne = spawnSync(inv.file, inv.args, {
        encoding: "utf8",
        windowsHide: true,
        env: { ...process.env, ...inv.env },
      });
      assert.equal(restoredOne.status, 0, restoredOne.stderr + restoredOne.stdout);
      unlinkSync(input);
      assert.equal(writeBlockedByFs(redo), false);

      const again = await snapshotGuardApply({ home: fx.home, failAfter: 1 });
      assert.equal(again.active, false, JSON.stringify(again));
      assert.equal(again.managed, true);
      assert.ok(again.error === "apply_failed" || again.error === "rollback_failed", JSON.stringify(again));
      assert.equal(existsSync(manPath), true);
      assert.equal(icacls(fx.target), rootAcl);
      assert.equal(icacls(keep), keepAcl);
      assert.equal(writeBlockedByFs(keep), true);
      assert.equal(writeBlockedByFs(fx.target), true);
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("blocks new archives in nested pending and a second subtree, not only the root", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const pending = join(fx.target, "pending");
      const extra = join(fx.target, "other-tree");
      await mkdir(pending, { recursive: true });
      await mkdir(extra, { recursive: true });
      await writeFile(join(pending, "old.tar.gz.enc"), Buffer.from("enc"));
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      assert.equal(applied.writeBlocked, true);
      await assert.rejects(() => writeFile(join(fx.target, "root.enc"), "x"), /EACCES|EPERM/);
      await assert.rejects(() => writeFile(join(pending, "new.tar.gz.enc"), "x"), /EACCES|EPERM/);
      await assert.rejects(() => writeFile(join(extra, "new.tar.gz.enc"), "x"), /EACCES|EPERM/);
      assert.equal(tryReadFile(join(pending, "old.tar.gz.enc")), false);
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("restore conflicts and keeps an extra external ACE added after apply", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      const f = join(fx.target, "keep.enc");
      await writeFile(f, Buffer.from("abc"));
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.managed, true, JSON.stringify(applied));
      const sid = spawnSync(
        powershellExe(),
        ["-NoProfile", "-NonInteractive", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
        { encoding: "utf8", windowsHide: true },
      );
      const userSid = (sid.stdout || "").trim();
      const extra = spawnSync("icacls", [f, "/deny", `*${userSid}:(R)`], { encoding: "utf8", windowsHide: true });
      assert.ok(extra.status === 0 || /successfully/i.test(extra.stdout || ""), extra.stdout + extra.stderr);
      const afterExtra = icacls(f);
      const restored = await snapshotGuardRestore({ home: fx.home });
      assert.equal(restored.error, "conflict");
      assert.equal(icacls(f), afterExtra);
      assert.equal(existsSync(f), true);
    } finally {
      forceResetTempAcl(fx.target);
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("refuses to overwrite a corrupt manifest and does not adopt it", { timeout: 60_000 }, async () => {
    const fx = await makeFixture();
    try {
      await mkdir(join(fx.home, ".nmzp"), { recursive: true });
      await writeFile(join(fx.home, ".nmzp", "snapshot-guard.json"), "{not-json");
      const applied = await snapshotGuardApply({ home: fx.home });
      assert.equal(applied.error, "manifest_invalid");
      assert.equal(applied.managed, false);
      assert.equal(writeBlockedByFs(fx.target), false);
      const st = await snapshotGuardStatus({ home: fx.home });
      assert.equal(st.error, "manifest_invalid");
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });

  it("CLI status on temp home prints short JSON and does not list archive paths", { timeout: 30_000 }, async () => {
    const fx = await makeFixture();
    try {
      const cli = join(coreDir, "snapshot-guard-cli.ts");
      const r = await spawnNode(
        ["--experimental-strip-types", cli, "status", "--home", fx.home],
        fx.dir,
      );
      assert.equal(r.code, 0, r.stderr);
      const j = JSON.parse(r.stdout.trim()) as SnapshotGuardStatus;
      assert.equal(j.supported, true);
      assert.equal(j.targetPresent, true);
      assert.equal(r.stdout.includes(fx.target), false);
      assert.equal(r.stdout.toLowerCase().includes("tar.gz"), false);
      void fields(j);
    } finally {
      await cleanupFixture(fx.dir, fx.home, fx.target);
    }
  });
});
