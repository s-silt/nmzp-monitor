import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, lchownSync, lstatSync, mkdirSync, renameSync, symlinkSync } from "node:fs";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { prepareServeProcess } from "./serve-start.ts";
import { tightenExistingDataDir } from "./posix.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "..", "nmzp.mjs");

function childEnv(home: string, data: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("NMZP_")) delete env[key];
  }
  return { ...env, NMZP_HOME: home, NMZP_DATA: data, USERPROFILE: home, HOME: home, ...extra };
}

function spawnCli(args: string[], env: NodeJS.ProcessEnv, killOn?: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const done = (code: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    };
    const timer = setTimeout(() => {
      child.kill();
      done(1);
    }, 45_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (killOn && stdout.includes(killOn)) child.kill();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => done(code ?? 1));
  });
}

async function tree(): Promise<{ root: string; home: string; data: string }> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-serve-cfg-"));
  const home = join(root, "home");
  const data = join(root, "data");
  await mkdir(home);
  return { root, home, data };
}

describe("prepareServeProcess", () => {
  it("serve refuses illegal bind without creating files", async () => {
    const { root, home, data } = await tree();
    try {
      const lines: string[] = [];
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "not a host" }), (text) => {
        lines.push(text);
      });
      assert.equal(result.ok, false);
      assert.match(lines.join(""), /NMZP_BIND:/);
      assert.equal(existsSync(data), false);
      const cli = await spawnCli(["serve"], childEnv(home, data, { NMZP_BIND: "not a host" }));
      assert.notEqual(cli.code, 0);
      assert.match(cli.stderr, /NMZP_BIND:/);
      assert.equal(existsSync(data), false);
      assert.deepEqual(await readdir(root), ["home"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("serve refuses relative data dir, bad port, bad CIDR, and bad storage mode", async () => {
    const { root, home, data } = await tree();
    try {
      const rel = await prepareServeProcess(childEnv(home, join(root, "rel-data"), { NMZP_DATA: "rel-data", NMZP_BIND: "127.0.0.1" }), () => undefined);
      assert.equal(rel.ok, false);
      const port = await prepareServeProcess(childEnv(home, data, { NMZP_PORT: "99999", NMZP_BIND: "127.0.0.1" }), () => undefined);
      assert.equal(port.ok, false);
      const cidr = await prepareServeProcess(
        childEnv(home, data, { NMZP_BIND: "127.0.0.1", NMZP_VIEWER_ALLOW_CIDR: "nope/99" }),
        () => undefined,
      );
      assert.equal(cidr.ok, false);
      const mode = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1", NMZP_STORAGE_MODE: "memory" }), () => undefined);
      assert.equal(mode.ok, false);
      assert.equal(existsSync(data), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("serve refuses a symlink data directory", async () => {
    const { root, home, data } = await tree();
    try {
      const real = join(root, "real");
      await mkdir(real);
      try {
        symlinkSync(real, data);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EPERM" || code === "ENOTSUP") return;
        throw error;
      }
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1" }), () => undefined);
      assert.equal(result.ok, false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("serve WARNs on invalid audit retention and 0.0.0.0 without CIDR, then continues", async () => {
    const { root, home, data } = await tree();
    try {
      await mkdir(data);
      const lines: string[] = [];
      const result = await prepareServeProcess(
        childEnv(home, data, { NMZP_BIND: "0.0.0.0", NMZP_PORT: "0", NMZP_AUDIT_MAX_DAYS: "nope" }),
        (text) => {
          lines.push(text);
        },
      );
      assert.equal(result.ok, true);
      if (!result.ok) throw new Error("expected prepareServeProcess to succeed");
      assert.equal(result.port, 0);
      assert.equal(result.host, "0.0.0.0");
      assert.equal(result.auditRetention.maxAgeMs, 30 * 86400_000);
      const text = lines.join("");
      assert.match(text, /WARN NMZP_AUDIT_MAX_DAYS:/);
      assert.match(text, /WARN NMZP_BIND:.*WP-30/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("serve permission tighten", () => {
  it("posix tightens an existing data dir and sensitive files", {
    skip: process.platform === "win32" ? "Windows ACL is WP-60; serve skips chmod" : false,
  }, async () => {
    const { root, home, data } = await tree();
    try {
      await mkdir(data);
      await mkdir(join(data, "tls"));
      await writeFile(join(data, "admin.token"), "token\n");
      await writeFile(join(data, "policy.json"), "{}\n");
      await writeFile(join(data, "meta.json"), "{}\n");
      await writeFile(join(data, "tls", "server.key"), "key\n");
      await writeFile(join(data, "nmzp.db"), "db");
      chmodSync(data, 0o755);
      chmodSync(join(data, "admin.token"), 0o644);
      chmodSync(join(data, "policy.json"), 0o644);
      chmodSync(join(data, "meta.json"), 0o644);
      chmodSync(join(data, "tls", "server.key"), 0o644);
      chmodSync(join(data, "nmzp.db"), 0o644);
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1", NMZP_PORT: "0" }), () => undefined);
      assert.equal(result.ok, true);
      assert.equal(lstatSync(data).mode & 0o777, 0o700);
      assert.equal(lstatSync(join(data, "admin.token")).mode & 0o777, 0o600);
      assert.equal(lstatSync(join(data, "policy.json")).mode & 0o777, 0o600);
      assert.equal(lstatSync(join(data, "meta.json")).mode & 0o777, 0o600);
      assert.equal(lstatSync(join(data, "tls", "server.key")).mode & 0o777, 0o600);
      assert.equal(lstatSync(join(data, "nmzp.db")).mode & 0o777, 0o600);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("posix refuses when the data dir cannot be tightened", {
    skip: process.platform === "win32" ? "Windows ACL is WP-60; serve skips chmod" : false,
  }, async () => {
    const { root, data } = await tree();
    try {
      await writeFile(data, "not-a-dir");
      const tightened = await tightenExistingDataDir(data);
      assert.equal(tightened.ok, false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

const posixSkip = process.platform === "win32" ? "POSIX cases run on CI ubuntu" : false;

describe("posix tighten fixes", () => {
  it("refuses a symlink tls directory and leaves the outside key mode unchanged", { skip: posixSkip }, async () => {
    const { root, home, data } = await tree();
    try {
      const outside = join(root, "outside");
      await mkdir(outside);
      const key = join(outside, "server.key");
      await writeFile(key, "key\n");
      chmodSync(key, 0o644);
      await mkdir(data);
      symlinkSync(outside, join(data, "tls"));
      const lines: string[] = [];
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1" }), (text) => {
        lines.push(text);
      });
      assert.equal(result.ok, false);
      assert.match(lines.join(""), /tls is a symlink/);
      assert.equal(lstatSync(key).mode & 0o777, 0o644);
      assert.equal(lstatSync(join(data, "tls")).isSymbolicLink(), true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("refuses when the data directory is replaced before the final inode check", { skip: posixSkip }, async () => {
    const { root, home, data } = await tree();
    try {
      await mkdir(data);
      chmodSync(data, 0o700);
      const lines: string[] = [];
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1" }), (text) => {
        lines.push(text);
      }, {
        beforeFinalDataDirCheck() {
          renameSync(data, `${data}-old`);
          mkdirSync(data);
        },
      });
      assert.equal(result.ok, false);
      assert.match(lines.join(""), /inode changed/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("refuses when lstat fails with EACCES", { skip: posixSkip }, async () => {
    const { root, home, data } = await tree();
    try {
      await mkdir(data);
      const lines: string[] = [];
      const result = await prepareServeProcess(childEnv(home, data, { NMZP_BIND: "127.0.0.1" }), (text) => {
        lines.push(text);
      }, {
        lstat() {
          const error = new Error("EACCES") as NodeJS.ErrnoException;
          error.code = "EACCES";
          throw error;
        },
      });
      assert.equal(result.ok, false);
      assert.match(lines.join(""), /EACCES/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("root uid tightens a file owned by another uid", { skip: posixSkip }, async () => {
    const { root, data } = await tree();
    try {
      await mkdir(data);
      chmodSync(data, 0o700);
      const file = join(data, "admin.token");
      await writeFile(file, "token\n");
      chmodSync(file, 0o644);
      if ((process.getuid?.() ?? -1) === 0) lchownSync(file, 1, 1);
      assert.notEqual(lstatSync(file).uid, 0);
      const result = await tightenExistingDataDir(data, { getuid: () => 0 });
      assert.equal(result.ok, true);
      assert.equal(lstatSync(file).mode & 0o777, 0o600);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps modes that are stricter than 0700 and 0600", { skip: posixSkip }, async () => {
    const { root, data } = await tree();
    try {
      await mkdir(data);
      const strictFile = join(data, "admin.token");
      const wideFile = join(data, "policy.json");
      await writeFile(strictFile, "token\n");
      await writeFile(wideFile, "{}\n");
      chmodSync(data, 0o500);
      chmodSync(strictFile, 0o400);
      chmodSync(wideFile, 0o644);
      const result = await tightenExistingDataDir(data);
      assert.equal(result.ok, true);
      assert.equal(lstatSync(data).mode & 0o777, 0o500);
      assert.equal(lstatSync(strictFile).mode & 0o777, 0o400);
      assert.equal(lstatSync(wideFile).mode & 0o777, 0o600);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("serve CLI warn continues", () => {
  it("prints WARN then starts on invalid audit retention", async () => {
    const { root, home, data } = await tree();
    try {
      await mkdir(data);
      const cli = await spawnCli(
        ["serve"],
        childEnv(home, data, { NMZP_BIND: "127.0.0.1", NMZP_PORT: "0", NMZP_AUDIT_MAX_DAYS: "nope" }),
        "pinned TLS",
      );
      assert.match(cli.stderr, /WARN NMZP_AUDIT_MAX_DAYS:/);
      assert.match(cli.stdout, /pinned TLS/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
