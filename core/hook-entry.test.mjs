import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { formatHookResponse, HOOK_AGENTS } from "./hook-protocol.ts";

const REASON = "nmzp_hook_bootstrap_failed";
const MARKER = "nmzp_cli_bootstrap_marker";
const CANARY = "bootstrap-canary";
const STDIN = '{"tool_name":"Read","file_path":"notes.txt","agentHint":"cursor"}\n';
const coreSrc = dirname(fileURLToPath(import.meta.url));

let scratchPromise;

async function createRuntime() {
  const root = await mkdtemp(join(tmpdir(), "nmzp-hook-entry-"));
  const core = join(root, "core");
  await cp(coreSrc, core, { recursive: true });
  await writeFile(join(core, "cli.ts"), `throw new Error(${JSON.stringify(MARKER)});\n`);
  return { root, entry: join(core, "nmzp.mjs") };
}

function run(args, stripTypes) {
  return scratchPromise.then(
    ({ entry, root }) =>
      new Promise((resolve) => {
        const nodeArgs = stripTypes
          ? ["--experimental-strip-types", entry, ...args]
          : [entry, ...args];
        const env = {
          ...process.env,
          NMZP_HOME: root,
          NMZP_DATA: join(root, "data"),
          HOME: root,
          USERPROFILE: root,
          NMZP_BOOTSTRAP_CANARY: CANARY,
          GROK_HOOK_EVENT: "PreToolUse",
          GROK_SESSION_ID: "bootstrap-session",
        };
        if (!stripTypes) env.NODE_OPTIONS = "";
        const child = spawn(process.execPath, nodeArgs, {
          cwd: root,
          env,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 20000,
        });
        let stdout = "";
        let stderr = "";
        let sent = false;
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk) => {
          stdout += chunk;
        });
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        child.stdin.on("error", () => {});
        const send = () => {
          if (sent) return;
          sent = true;
          child.stdin.end(STDIN);
        };
        child.once("spawn", send);
        if (child.pid) send();
        child.on("error", () => resolve({ code: 1, stdout, stderr }));
        child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
      }),
  );
}

function assertDeny(got, agent) {
  const expected = formatHookResponse(agent, { decision: "deny", reason: REASON });
  assert.equal(got.code, expected.exitCode);
  assert.equal(got.stdout, expected.stdout);
  assert.deepEqual(JSON.parse(got.stdout), JSON.parse(expected.stdout));
  assert.equal(got.stderr, expected.stderr ?? "");
  assert.equal(got.stdout.includes('"allow"'), false);
  assert.equal(got.stdout.includes(MARKER), false);
  assert.equal(got.stderr.includes(MARKER), false);
  assert.equal(got.stdout.includes(CANARY), false);
  assert.equal(got.stderr.includes(CANARY), false);
}

describe("hook bootstrap failure", () => {
  before(() => {
    scratchPromise = createRuntime();
    return scratchPromise;
  });

  after(async () => {
    if (!scratchPromise) return;
    const scratch = await scratchPromise;
    await rm(scratch.root, { recursive: true, force: true });
  });

  it("claude bootstrap failure returns protocol deny exit and stdout", async () => {
    const expected = formatHookResponse("claude", { decision: "deny", reason: REASON });
    const got = await run(["hook", "--agent", "claude"], true);
    assert.equal(got.code, expected.exitCode);
    assert.equal(got.stdout, expected.stdout);
    assert.deepEqual(JSON.parse(got.stdout), JSON.parse(expected.stdout));
    assert.equal(got.stderr, expected.stderr ?? "");
  });

  it("every hooked agent bootstrap failure matches formatHookResponse deny", async () => {
    for (const agent of HOOK_AGENTS) {
      const got = await run(["hook", "--agent", agent], true);
      assertDeny(got, agent);
    }
  });

  it("missing and unknown agents use the generic bootstrap deny", async () => {
    for (const args of [["hook"], ["hook", "--agent"], ["hook", "--agent", "not-a-host"]]) {
      assertDeny(await run(args, true), "unknown");
    }
  });

  it("respawn propagates the claude bootstrap deny unchanged", async () => {
    assertDeny(await run(["hook", "--agent", "claude"], false), "claude");
  });

  it("respawn propagates the codex bootstrap deny unchanged", async () => {
    assertDeny(await run(["hook", "--agent", "codex"], false), "codex");
  });

  it("version and status bootstrap failures exit nonzero without hook JSON", async () => {
    for (const command of ["version", "status"]) {
      for (const stripTypes of [true, false]) {
        const got = await run([command], stripTypes);
        assert.equal(got.stdout, "");
        assert.equal(got.code, 1);
        assert.equal(got.stdout.includes(REASON), false);
        assert.equal(got.stderr.includes(REASON), false);
        assert.equal(got.stdout.includes("permissionDecision"), false);
        assert.equal(got.stderr.includes("permissionDecision"), false);
        assert.equal(got.stdout.includes(CANARY), false);
        assert.equal(got.stderr.includes(CANARY), false);
      }
    }
  });

  it("bootstrap catch does not import the protocol graph", () => {
    const src = readFileSync(join(coreSrc, "nmzp.mjs"), "utf8");
    assert.equal(src.includes("hook-protocol"), false);
    assert.equal(src.includes('from "./cli.ts"'), false);
    assert.equal(src.includes('from "./hook.ts"'), false);
    assert.match(src, /await import\(\s*["']\.\/cli\.ts["']\s*\)/);
  });
});
