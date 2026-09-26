import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { spawn } from "node:child_process";
import { ACL_RESTRICT_PS, atomicWriteFile, restrictPath, withCooperatingInstallLock, type AtomicFs } from "./install-fs.ts";

describe("install-fs safety", () => {
  it("atomic write keeps the previous file if the replacement rename fails", () => {
    const dest = join(tmpdir(), `nmzp-atomic-${process.pid}-${Date.now()}`);
    const files = new Map<string, string>([[dest, "OLD_SECRET_SETTINGS"]]);
    const renamed: Array<[string, string]> = [];
    const io: AtomicFs = {
      mkdirSync: () => undefined,
      writeFileSync: (path, body) => {
        files.set(path, body);
      },
      existsSync: (path) => files.has(path),
      unlinkSync: (path) => {
        files.delete(path);
      },
      renameSync: (from, to) => {
        renamed.push([from, to]);
        if (from === dest) throw new Error("must_not_move_live_path");
        if (to === dest) throw new Error("rename_dest_failed");
        const v = files.get(from);
        if (v === undefined) throw new Error("missing");
        files.delete(from);
        files.set(to, v);
      },
    };
    assert.throws(() => atomicWriteFile(dest, "NEW", 0o600, io), /atomic_write_failed/);
    assert.equal(files.get(dest), "OLD_SECRET_SETTINGS");
    assert.equal(
      renamed.some(([from]) => from === dest),
      false,
    );
    assert.equal([...files.values()].includes("NEW"), false);
  });

  it("atomic write replaces an existing file in one rename onto the live path", () => {
    const dir = join(tmpdir(), `nmzp-atomic-ok-${process.pid}`);
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, "cfg.json");
    writeFileSync(dest, "first");
    try {
      atomicWriteFile(dest, "second");
      assert.equal(readFileSync(dest, "utf8"), "second");
      assert.equal(existsSync(dest), true);
    } finally {
      try {
        writeFileSync(dest, "");
      } catch {
        /* ignore */
      }
    }
  });

  it(
    "restrictPath clears group and other permission bits",
    { skip: process.platform === "win32" && "chmod is not applied on Windows" },
    () => {
      const dir = mkdtempSync(join(tmpdir(), "nmzp-restrict-"));
      try {
        const file = join(dir, "secret");
        writeFileSync(file, "x", { mode: 0o644 });
        restrictPath(file);
        assert.equal(statSync(file).mode & 0o077, 0);
        const sub = join(dir, "sub");
        mkdirSync(sub, { mode: 0o755 });
        restrictPath(sub);
        assert.equal(statSync(sub).mode & 0o077, 0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it("refuses a junction or symlink and leaves the target bytes unchanged", () => {
    const root = mkdtempSync(join(tmpdir(), "nmzp-nofollow-"));
    try {
      const real = join(root, "real");
      const link = join(root, "link");
      mkdirSync(real);
      writeFileSync(join(real, "keep.txt"), "SECRET");
      symlinkSync(real, link, "junction");
      assert.throws(() => atomicWriteFile(join(link, "out.txt"), "NEW"), /unsafe_symlink/);
      assert.equal(readFileSync(join(real, "keep.txt"), "utf8"), "SECRET");
      assert.equal(existsSync(join(real, "out.txt")), false);
      const target = join(root, "target.txt");
      const fileLink = join(root, "link.txt");
      writeFileSync(target, "SECRET");
      try {
        symlinkSync(target, fileLink, "file");
      } catch {
        return;
      }
      assert.throws(() => atomicWriteFile(fileLink, "NEW"), /unsafe_symlink/);
      assert.equal(readFileSync(target, "utf8"), "SECRET");
      assert.equal(lstatSync(fileLink).isSymbolicLink(), true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps a replaced install lock and does not enter when the owner is uncertain or malformed", async () => {
    const root = mkdtempSync(join(tmpdir(), "nmzp-lock-"));
    const home = join(root, "home");
    mkdirSync(home);
    const lock = join(home, ".nmzp", "install.lock");
    const kill = process.kill.bind(process);
    const sleeper = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "ignore", windowsHide: true });
    await new Promise<void>((resolve, reject) => {
      sleeper.once("spawn", () => resolve());
      sleeper.once("error", reject);
    });
    try {
      await withCooperatingInstallLock(home, async () => {
        const moved = `${lock}.moved`;
        renameSync(lock, moved);
        writeFileSync(lock, "REPLACEMENT");
      });
      assert.equal(readFileSync(lock, "utf8"), "REPLACEMENT");
      assert.equal(existsSync(`${lock}.moved`), true);

      const real = join(root, "real");
      const link = join(root, "link");
      mkdirSync(real);
      writeFileSync(join(real, "keep.txt"), "SECRET");
      symlinkSync(real, link, "junction");
      await assert.rejects(() => withCooperatingInstallLock(link, async () => undefined), /unsafe_symlink/);
      assert.equal(readFileSync(join(real, "keep.txt"), "utf8"), "SECRET");
      assert.equal(existsSync(join(real, ".nmzp")), false);

      mkdirSync(join(home, ".nmzp"), { recursive: true });
      const owned = JSON.stringify({ pid: sleeper.pid, nonce: "0123456789abcdef", startedAt: 1 });
      writeFileSync(lock, owned);
      process.kill = ((pid: number, signal?: NodeJS.Signals | number) => {
        if (pid === sleeper.pid && signal === 0) {
          const error = new Error("perm") as NodeJS.ErrnoException;
          error.code = "EPERM";
          throw error;
        }
        return kill(pid, signal);
      }) as typeof process.kill;
      let entered = false;
      await assert.rejects(
        () => withCooperatingInstallLock(home, async () => {
          entered = true;
        }, 250),
        /install_lock_timeout/,
        "eperm lock was reclaimed",
      );
      assert.equal(entered, false, "eperm lock was reclaimed");
      assert.equal(readFileSync(lock, "utf8"), owned);

      process.kill = kill as typeof process.kill;
      const malformed = "{";
      writeFileSync(lock, malformed);
      entered = false;
      await assert.rejects(
        () => withCooperatingInstallLock(home, async () => {
          entered = true;
        }, 250),
        /install_lock_timeout/,
      );
      assert.equal(entered, false);
      assert.equal(readFileSync(lock, "utf8"), malformed);
    } finally {
      process.kill = kill as typeof process.kill;
      try {
        sleeper.kill();
      } catch {
        /* already stopped */
      }
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("ACL script takes the path from env and does not interpolate JSON or invoke subexpressions", () => {
    assert.match(ACL_RESTRICT_PS, /\$env:NMZP_ACL_PATH/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /JSON\.stringify/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /\$\(/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /`/);
  });
});
