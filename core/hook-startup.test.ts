import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const coreSrc = dirname(fileURLToPath(import.meta.url));
const STDIN = '{"tool_name":"Bash","tool_input":{"command":"echo hi"}}\n';

function run(entry: string, args: string[], home: string): Promise<{ code: number; stdout: string; stderr: string; ms: number }> {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      cwd: dirname(entry),
      env: {
        ...process.env,
        NMZP_HOME: home,
        HOME: home,
        USERPROFILE: home,
        NODE_OPTIONS: "",
      },
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(args[0] === "hook" ? STDIN : "");
    child.on("error", () => resolve({ code: 1, stdout, stderr, ms: Date.now() - started }));
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr, ms: Date.now() - started }));
  });
}

async function copyRuntime(omit: string[]): Promise<{ root: string; entry: string }> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-hook-fast-"));
  const core = join(root, "core");
  await cp(coreSrc, core, {
    recursive: true,
    filter: (src) => !src.endsWith(".test.ts") && !src.endsWith(".test.mjs"),
  });
  const monitor = join(root, "src", "lib", "monitor");
  await mkdir(monitor, { recursive: true });
  await cp(join(coreSrc, "..", "src", "lib", "monitor", "zcode-hook-config.ts"), join(monitor, "zcode-hook-config.ts"));
  for (const name of omit) await rm(join(core, name), { force: true });
  return { root, entry: join(core, "nmzp.mjs") };
}

describe("hook fast path", () => {
  it("source contract: cli static imports do not pull the installer or server", () => {
    const src = readFileSync(join(coreSrc, "cli.ts"), "utf8");
    const staticImports = src.split("\n").filter((line) => line.startsWith("import ") && !line.includes("import type"));
    const blob = staticImports.join("\n");
    assert.equal(blob.includes("./serve.ts"), false, "hook fast path statically imports serve");
    assert.equal(blob.includes("./install.ts"), false);
    assert.match(src, /argv\[0\] === "hook"/);
    assert.match(src, /import\("\.\/hook\.ts"\)/);
  });

  it("runs the hook protocol when installer and server modules are absent", async () => {
    const { root, entry } = await copyRuntime(["serve.ts", "install.ts"]);
    try {
      const got = await run(entry, ["hook", "--agent", "grok"], root);
      assert.equal(got.stdout.includes("nmzp_hook_bootstrap_failed"), false);
      assert.match(got.stdout, /no_policy_cache/);
      assert.equal(got.code, 2);
      assert.ok(got.ms < 20_000, `synthetic hook spawn ${got.ms}ms; not an antivirus or production-budget measurement`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("denies through the emergency guard when the hook module is missing", async () => {
    const { root, entry } = await copyRuntime(["hook.ts"]);
    try {
      const got = await run(entry, ["hook", "--agent", "grok"], root);
      assert.match(got.stdout, /nmzp_hook_bootstrap_failed/);
      assert.equal(got.code, 2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("prints help with no arguments without the server module", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-hook-help-"));
    const core = join(root, "core");
    try {
      await mkdir(core, { recursive: true });
      for (const name of ["nmzp.mjs", "cli.ts", "constants.ts", "hook-protocol.ts", "egress-schema.ts", "auth.ts"]) {
        await writeFile(join(core, name), readFileSync(join(coreSrc, name)));
      }
      const got = await run(join(core, "nmzp.mjs"), [], root);
      assert.equal(got.code, 0);
      assert.match(got.stdout, /nmzp hook --agent /);
      assert.match(got.stdout, /kimi/);
      assert.match(got.stdout, /cursor/);
      assert.equal(got.stdout.includes("nmzp_hook_bootstrap_failed"), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
