import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { packRelease } from "../../scripts/release-archive.mjs";

const golden = JSON.parse(readFileSync(new URL("./fixtures/hook-bytes-golden.json", import.meta.url), "utf8"));

function runHook(entry, home, argv, stdin) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NMZP_HOME: home };
    for (const key of Object.keys(env)) {
      if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|NMZP_)/.test(key)) delete env[key];
    }
    env.NMZP_HOME = home;
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...argv], {
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out = [];
    const err = [];
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timeout ${argv.join(" ")}`));
    }, 15000);
    child.stdout.on("data", (data) => out.push(data));
    child.stderr.on("data", (data) => err.push(data));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal) reject(new Error(`${argv.join(" ")}:${signal}`));
      else resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.end(stdin);
  });
}

async function freshHome(root, id) {
  const home = join(root, "homes", id);
  const cache = join(home, ".nmzp", "policy-cache.json");
  await mkdir(join(home, ".nmzp"), { recursive: true });
  await writePolicyCache(cache, { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
  return home;
}

describe("packed bundle matches baseline hook bytes", { concurrency: 1, timeout: 300000 }, () => {
  let packedDir;
  let root;

  before(async () => {
    assert.equal(golden.cases.length, 65);
    root = await mkdtemp(join(tmpdir(), "nmzp-golden-pack-"));
    const source = fileURLToPath(new URL("../../", import.meta.url));
    await cp(join(source, "core"), join(root, "core"), { recursive: true });
    await mkdir(join(root, "src", "lib"), { recursive: true });
    await cp(join(source, "src", "lib", "monitor"), join(root, "src", "lib", "monitor"), { recursive: true });
    await cp(join(source, "dist"), join(root, "dist"), { recursive: true });
    packedDir = (await packRelease(root)).dir;
  });

  after(async () => {
    if (root) await rm(root, { recursive: true, force: true });
  });

  for (const item of golden.cases) {
    test(item.id, async () => {
      assert.ok(packedDir, "bundle was not prepared");
      const home = await freshHome(root, item.id);
      let entry = join(packedDir, "nmzp.mjs");
      let brokenRoot;
      if (item.kind === "bootstrap") {
        brokenRoot = await mkdtemp(join(tmpdir(), "nmzp-golden-boot-"));
        const broken = join(brokenRoot, "nmzp");
        await cp(packedDir, broken, { recursive: true });
        await writeFile(join(broken, "nmzp-main.cjs"), "throw new Error('bootstrap');\n");
        entry = join(broken, "nmzp.mjs");
      }
      try {
        const got = await runHook(entry, home, item.argv, item.stdin);
        assert.equal(got.code, item.exitCode, `${item.id} exit`);
        assert.equal(got.stdout, item.stdout, `${item.id} stdout`);
        assert.equal(got.stderr, item.stderr, `${item.id} stderr`);
      } finally {
        if (brokenRoot) await rm(brokenRoot, { recursive: true, force: true });
      }
    });
  }
});
