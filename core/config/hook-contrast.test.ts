import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, symlinkSync } from "node:fs";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { writePolicyCache } from "../policy-cache.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "..", "nmzp.mjs");
const STDIN =
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status --porcelain"},"session_id":"synthetic","eventId":"synthetic"}';

function hookEnv(home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|NMZP_)/.test(key)) delete env[key];
  }
  return { ...env, ...extra, NMZP_HOME: home, HOME: home, USERPROFILE: home };
}

function runHook(home: string, extra: NodeJS.ProcessEnv = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, "hook", "--agent", "grok"], {
      env: hookEnv(home, extra),
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("hook timeout"));
    }, 15_000);
    child.stdout.on("data", (chunk) => out.push(chunk as Buffer));
    child.stderr.on("data", (chunk) => err.push(chunk as Buffer));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
    child.stdin.end(STDIN);
  });
}

describe("hook does not refuse serve-illegal constructions", () => {
  it("symlink home, wide permissions, and illegal NMZP_* keep hook bytes", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-hook-contrast-"));
    try {
      const home = join(root, "home");
      await mkdir(join(home, ".nmzp"), { recursive: true });
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
        version: 1,
        mode: "enforcing",
        stopped: false,
        customRules: [],
        updatedAt: 1,
      });
      const baseline = await runHook(home);
      assert.equal(baseline.code, 0, baseline.stderr);
      assert.equal(baseline.stdout, "");

      const illegal = await runHook(home, {
        NMZP_BIND: "not a host",
        NMZP_PORT: "99999",
        NMZP_DATA: "relative-data",
        NMZP_STORAGE_MODE: "memory",
        NMZP_VIEWER_ALLOW_CIDR: "nope/99",
        NMZP_AUDIT_MAX_DAYS: "nope",
      });
      assert.equal(illegal.code, baseline.code);
      assert.equal(illegal.stdout, baseline.stdout);

      if (process.platform !== "win32") {
        chmodSync(join(home, ".nmzp"), 0o777);
        const wide = await runHook(home, { NMZP_BIND: "0.0.0.0", NMZP_PORT: "not-a-port" });
        assert.equal(wide.code, baseline.code);
        assert.equal(wide.stdout, baseline.stdout);

        const real = join(root, "real-home");
        const link = join(root, "link-home");
        await mkdir(join(real, ".nmzp"), { recursive: true });
        await writePolicyCache(join(real, ".nmzp", "policy-cache.json"), {
          version: 1,
          mode: "enforcing",
          stopped: false,
          customRules: [],
          updatedAt: 1,
        });
        try {
          symlinkSync(real, link);
          const linked = await runHook(link, { NMZP_DATA: join(root, "symlink-data") });
          assert.equal(linked.code, baseline.code);
          assert.equal(linked.stdout, baseline.stdout);
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== "EPERM" && code !== "ENOTSUP") throw error;
        }
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
