import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, lstatSync } from "node:fs";
import { mkdtemp, mkdir, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { validateConfigShow } from "./resolve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "..", "nmzp.mjs");
const SECRET = "nmzp-config-show-secret-c0ffee11";

function childEnv(home: string, data: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("NMZP_")) delete env[key];
  }
  return { ...env, NMZP_HOME: home, NMZP_DATA: data, USERPROFILE: home, HOME: home, ...extra };
}

function spawnCli(
  args: string[],
  env: NodeJS.ProcessEnv,
  timeoutMs = 20_000,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ stdout, stderr, code: 1 });
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

async function treeSnapshot(root: string): Promise<string> {
  const rows: string[] = [];
  async function walk(dir: string): Promise<void> {
    const names = (await readdir(dir)).sort();
    for (const name of names) {
      const path = join(dir, name);
      const st = lstatSync(path);
      const rel = path.slice(root.length);
      if (st.isDirectory()) {
        rows.push(`${rel}\tdir\t${st.size}\t${st.mtimeMs}\t${st.mode}`);
        await walk(path);
      } else {
        const body = await readFile(path);
        const sha = createHash("sha256").update(body).digest("hex");
        rows.push(`${rel}\t${st.size}\t${st.mtimeMs}\t${st.mode}\t${sha}`);
      }
    }
  }
  await walk(root);
  return rows.join("\n");
}

describe("nmzp config show", () => {
  it("prints human lines, json schema, omits secrets, and does not write", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-config-cli-"));
    const home = join(root, "home");
    const data = join(root, "data");
    await mkdir(home);
    await mkdir(data);
    try {
      const help = await spawnCli(["help"], childEnv(home, data));
      assert.equal(help.code, 0);
      assert.match(help.stdout, /nmzp config show \[--json\]/);

      const before = await treeSnapshot(root);
      const human = await spawnCli(
        ["config", "show"],
        childEnv(home, data, { NMZP_UPSTREAM_TOKEN: SECRET, NMZP_VIEWER_CREDENTIAL: SECRET }),
      );
      assert.equal(human.code, 0, human.stderr);
      assert.match(human.stdout, /^NMZP_BIND {2}/m);
      assert.match(human.stdout, / {2}DEFAULT$/m);
      assert.equal(`${human.stdout}\n${human.stderr}`.includes(SECRET), false);
      assert.equal(await treeSnapshot(root), before);

      const json = await spawnCli(
        ["config", "show", "--json"],
        childEnv(home, data, { NMZP_BIND: "127.0.0.1", NMZP_UPSTREAM_TOKEN: SECRET, NMZP_VIEWER_CREDENTIAL: SECRET }),
      );
      assert.equal(json.code, 0, json.stderr);
      assert.equal(`${json.stdout}\n${json.stderr}`.includes(SECRET), false);
      const parsed = JSON.parse(json.stdout) as unknown;
      assert.equal(validateConfigShow(parsed).ok, true, JSON.stringify(validateConfigShow(parsed)));
      assert.equal(await treeSnapshot(root), before);
      assert.equal(existsSync(join(data, "policy.json")), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("redacts NMZP_PUBLIC_URL userinfo in config show, serve stderr, and doctor", { timeout: 60_000 }, async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-config-url-"));
    const home = join(root, "home");
    const data = join(root, "data");
    await mkdir(home);
    const password = "nmzp-puburl-secret-c0ffee11";
    const env = childEnv(home, data, {
      NMZP_BIND: "127.0.0.1",
      NMZP_PUBLIC_URL: `https://nmzp-user:${password}@ct.example/n`,
    });
    try {
      const before = await treeSnapshot(root);
      const human = await spawnCli(["config", "show"], env);
      const json = await spawnCli(["config", "show", "--json"], env);
      const doctor = await spawnCli(["doctor", "--json"], env, 40_000);
      const doctorText = await spawnCli(["doctor"], env, 40_000);
      const serve = await spawnCli(["serve"], env);
      const blob = [human, json, doctor, doctorText, serve].map((item) => `${item.stdout}\n${item.stderr}`).join("\n");
      assert.equal(blob.includes(password), false);
      assert.equal(blob.includes("nmzp-user"), false);
      assert.equal(human.code, 0, human.stderr);
      assert.match(human.stdout, /NMZP_PUBLIC_URL {2}https:\/\/ct\.example\/n {2}ENV {2}problem=/);
      assert.equal(json.code, 0, json.stderr);
      const parsed = JSON.parse(json.stdout) as { items: Array<{ key: string; value: string; problem?: string; valid: boolean }> };
      const row = parsed.items.find((item) => item.key === "NMZP_PUBLIC_URL");
      assert.ok(row);
      assert.equal(row.valid, false);
      assert.equal(row.value, "https://ct.example/n");
      assert.match(row.problem ?? "", /userinfo/);
      assert.equal(validateConfigShow(parsed).ok, true, JSON.stringify(validateConfigShow(parsed)));
      assert.match(doctor.stdout, /https:\/\/ct\.example\/n/);
      assert.match(doctor.stdout, /userinfo/);
      assert.match(doctorText.stdout, /https:\/\/ct\.example\/n/);
      assert.notEqual(serve.code, 0);
      assert.match(serve.stderr, /NMZP_PUBLIC_URL: https:\/\/ct\.example\/n problem=/);
      assert.equal(await treeSnapshot(root), before);
      assert.equal(existsSync(data), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
