import assert from "node:assert/strict";
import cp from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { after, describe, it } from "node:test";
import { GROK_HOOK_FILE } from "./constants.ts";
import { codexHookConfiguredRaw } from "./codex-hooks.ts";
import { isNmzpOwnedHook } from "./install-hooks.ts";

const realSpawn = cp.spawnSync;
const aclHomes = new Set<string>();

cp.spawnSync = ((command: unknown, args?: unknown, options?: { env?: Record<string, string | undefined> }) => {
  const target = options?.env?.NMZP_ACL_PATH;
  assert.equal(command, "powershell.exe", "only permission boundary is mocked");
  assert.equal(typeof target, "string", "ACL target must be owned fixture");
  const resolved = resolve(String(target));
  assert.ok(
    [...aclHomes].some((home) => resolved.startsWith(home + sep)),
    "ACL target must be owned fixture",
  );
  const list = Array.isArray(args) ? args : [];
  assert.ok(
    list.includes("-Command") && list.some((arg) => typeof arg === "string" && arg.includes("SetAccessControl")),
    "only known ACL script intercepted",
  );
  return { status: 0, stdout: "", stderr: "", signal: null, pid: 0, output: [] };
}) as unknown as typeof cp.spawnSync;
syncBuiltinESMExports();

const { leaveDevice } = await import("./install.ts");

after(() => {
  cp.spawnSync = realSpawn;
  syncBuiltinESMExports();
});

function homePath(home: string, ...parts: string[]): string {
  const slash = home.includes("\\") && !home.includes("/") ? "\\" : "/";
  return [home.replace(/[\\/]$/, ""), ...parts].join(slash);
}

function makeHome(): { dir: string; home: string } {
  const dir = mkdtempSync(join(tmpdir(), "nmzp-leave-"));
  const home = join(dir, "home");
  mkdirSync(home);
  aclHomes.add(resolve(home));
  return { dir, home };
}

function writeBytes(path: string, body: Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body);
}

function writeText(path: string, body: string): void {
  writeBytes(path, Buffer.from(body, "utf8"));
}

function manifest(home: string, extra: Record<string, unknown> = {}): string {
  const path = homePath(home, ".nmzp", "manifest.json");
  writeText(
    path,
    JSON.stringify({
      version: "0.2.5",
      deviceId: "dev_fixture",
      grokPath: homePath(home, ".grok", "hooks", GROK_HOOK_FILE),
      claudePath: homePath(home, ".claude", "settings.json"),
      runtimeDir: homePath(home, ".nmzp", "runtime", "0.2.5"),
      task: "NMZPProbe",
      taskOwned: false,
      autostart: "skipped",
      files: [],
      grok: { created: false, originalSha256: null, writtenSha256: "" },
      claude: { originalSha256: null, writtenSha256: "" },
      ...extra,
    }),
  );
  return path;
}

function claudeDoc(): string {
  return JSON.stringify({
    extra: "keep-claude",
    hooks: {
      PreToolUse: [
        {
          matcher: "Read",
          hooks: [
            { type: "command", command: "echo keep-claude" },
            { type: "command", command: "other-tool --nmzp-not-ours" },
            { type: "command", command: "node nmzp.mjs hook --agent claude" },
          ],
        },
      ],
    },
  });
}

function grokDoc(): string {
  return JSON.stringify({
    userKey: "keep-grok",
    hooks: {
      SessionStart: [{ type: "command", command: "echo grok-session" }],
      PreToolUse: [
        {
          hooks: [
            { type: "command", command: "echo keep-grok" },
            { type: "command", command: "node nmzp.mjs hook --agent grok" },
          ],
        },
      ],
    },
  });
}

function codexDoc(): string {
  return JSON.stringify({
    hooks: {
      PreToolUse: [
        {
          hooks: [
            { type: "command", command: "echo keep-codex" },
            {
              type: "command",
              command: "node nmzp.mjs hook --agent codex",
              statusMessage: "NMZP PreToolUse v1",
            },
          ],
        },
      ],
    },
  });
}

function commands(raw: string): string[] {
  const doc = JSON.parse(raw) as {
    hooks?: { PreToolUse?: Array<{ hooks?: Array<{ command?: string }> }> };
  };
  return (doc.hooks?.PreToolUse ?? []).flatMap((row) => (row.hooks ?? []).map((hook) => String(hook.command ?? "")));
}

function assertUserKept(path: string, userCommand: string): void {
  const cmds = commands(readFileSync(path, "utf8"));
  assert.ok(cmds.includes(userCommand), userCommand);
  assert.equal(
    cmds.some((command) => isNmzpOwnedHook({ command })),
    false,
    userCommand,
  );
}

async function leave(home: string, launcherRunner?: Parameters<typeof leaveDevice>[0]["launcherRunner"]) {
  try {
    return await leaveDevice({
      home,
      skipRegister: true,
      probeController: {
        async start() {
          throw new Error("unexpected start");
        },
        async stopOwn() {
          return { ok: true, stopped: false };
        },
        async isOwnRunning() {
          throw new Error("unexpected isOwnRunning");
        },
      },
      launcherRunner,
    });
  } catch {
    assert.fail("leave must report host failures instead of throwing");
  }
}

describe("leaveDevice per-host uninstall report", { concurrency: false }, () => {
  it("leave reports corrupt claude settings as failed and keeps exact bytes", async () => {
    const { dir, home } = makeHome();
    const claudePath = homePath(home, ".claude", "settings.json");
    const corrupt = Buffer.from("{claude-corrupt", "utf8");
    writeBytes(claudePath, corrupt);
    try {
      const r = await leave(home);
      assert.equal(r.ok, false, "corrupt claude leave must fail");
      assert.deepEqual(r.failed, [{ target: "claude:settings.json", reason: "config_corrupt" }]);
      assert.equal(r.removed.includes("claude:nmzp-entry"), false);
      assert.deepEqual(readFileSync(claudePath), corrupt);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leave reports corrupt grok hook file as failed and keeps exact bytes", async () => {
    const { dir, home } = makeHome();
    const grokPath = homePath(home, ".grok", "hooks", GROK_HOOK_FILE);
    const corrupt = Buffer.from("{grok-corrupt", "utf8");
    writeBytes(grokPath, corrupt);
    try {
      const r = await leave(home);
      assert.equal(r.ok, false, "corrupt grok leave must fail");
      assert.deepEqual(r.failed, [{ target: `grok:${GROK_HOOK_FILE}`, reason: "config_corrupt" }]);
      assert.equal(r.removed.includes("grok:nmzp-entry"), false);
      assert.deepEqual(readFileSync(grokPath), corrupt);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leave with corrupt codex hooks reports failure and still cleans the other hosts", async () => {
    const { dir, home } = makeHome();
    const codexPath = homePath(home, ".codex", "hooks.json");
    const claudePath = homePath(home, ".claude", "settings.json");
    const grokPath = homePath(home, ".grok", "hooks", GROK_HOOK_FILE);
    const cred = homePath(home, ".nmzp", "credentials.json");
    const corrupt = Buffer.from("{codex-corrupt", "utf8");
    manifest(home, { codexPath });
    writeBytes(codexPath, corrupt);
    writeText(claudePath, claudeDoc());
    writeText(grokPath, grokDoc());
    writeText(cred, "{\"token\":\"synthetic\"}\n");
    try {
      const r = await leave(home);
      assert.equal(r.ok, false);
      assert.deepEqual(r.failed, [{ target: "codex:hooks.json", reason: "config_corrupt" }]);
      assert.deepEqual(readFileSync(codexPath), corrupt);
      assertUserKept(claudePath, "echo keep-claude");
      assert.equal(JSON.parse(readFileSync(claudePath, "utf8")).extra, "keep-claude");
      assertUserKept(grokPath, "echo keep-grok");
      const grok = JSON.parse(readFileSync(grokPath, "utf8")) as {
        userKey: string;
        hooks: { SessionStart: Array<{ command: string }> };
      };
      assert.equal(grok.userKey, "keep-grok");
      assert.equal(grok.hooks.SessionStart[0]?.command, "echo grok-session");
      assert.equal(existsSyncSafe(cred), true);
      assert.equal(r.removed.includes(cred), false);
      assert.equal(r.removed.includes("claude:nmzp-entry"), true);
      assert.equal(r.removed.includes("grok:nmzp-entry"), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("partial failure keeps credentials policy cache and manifest", async () => {
    const { dir, home } = makeHome();
    const cred = homePath(home, ".nmzp", "credentials.json");
    const core = homePath(home, ".nmzp", "core.json");
    const policy = homePath(home, ".nmzp", "policy-cache.json");
    const runtime = homePath(home, ".nmzp", "runtime", "0.2.5", "placeholder.txt");
    const launcherPath = homePath(home, "launcher-placeholder.txt");
    const claudePath = homePath(home, ".claude", "settings.json");
    const grokPath = homePath(home, ".grok", "hooks", GROK_HOOK_FILE);
    const corrupt = Buffer.from("{claude-partial", "utf8");
    let launcherRemoved = false;
    const manifestPath = manifest(home, {
      launcher: { created: true, originalSha256: null, writtenSha256: "unused", path: launcherPath },
    });
    const credBytes = Buffer.from("{\"token\":\"synthetic\"}\n", "utf8");
    const coreBytes = Buffer.from("{\"fixture\":true}\n", "utf8");
    const policyBytes = Buffer.from("{\"version\":1}\n", "utf8");
    const runtimeBytes = Buffer.from("synthetic runtime placeholder\n", "utf8");
    const launcherBytes = Buffer.from("synthetic launcher placeholder\n", "utf8");
    const manifestBytes = readFileSync(manifestPath);
    writeBytes(cred, credBytes);
    writeBytes(core, coreBytes);
    writeBytes(policy, policyBytes);
    writeBytes(runtime, runtimeBytes);
    writeBytes(launcherPath, launcherBytes);
    writeBytes(claudePath, corrupt);
    writeText(grokPath, grokDoc());
    try {
      const r = await leave(home, {
        async install() {
          throw new Error("unexpected launcher install");
        },
        async removeIfUnmodified() {
          launcherRemoved = true;
          return { removed: true };
        },
      });
      assert.equal(existsSyncSafe(cred), true, "partial failure must keep credentials.json");
      assert.deepEqual(readFileSync(cred), credBytes);
      assert.equal(existsSyncSafe(policy), true);
      assert.deepEqual(readFileSync(policy), policyBytes);
      assert.equal(existsSyncSafe(manifestPath), true);
      assert.deepEqual(readFileSync(manifestPath), manifestBytes);
      assert.equal(existsSyncSafe(core), true);
      assert.deepEqual(readFileSync(core), coreBytes);
      assert.deepEqual(readFileSync(runtime), runtimeBytes);
      assert.equal(launcherRemoved, false);
      assert.deepEqual(readFileSync(launcherPath), launcherBytes);
      assert.deepEqual(readFileSync(claudePath), corrupt);
      assert.equal(r.ok, false);
      assert.deepEqual(r.failed, [{ target: "claude:settings.json", reason: "config_corrupt" }]);
      assertUserKept(grokPath, "echo keep-grok");
      assert.equal(r.removed.includes(cred), false);
      assert.equal(r.removed.includes("grok:nmzp-entry"), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("clean leave removes owned entries and preserves user entries", async () => {
    const { dir, home } = makeHome();
    const claudePath = homePath(home, ".claude", "settings.json");
    const grokPath = homePath(home, ".grok", "hooks", GROK_HOOK_FILE);
    const codexPath = homePath(home, ".codex", "hooks.json");
    const cred = homePath(home, ".nmzp", "credentials.json");
    const core = homePath(home, ".nmzp", "core.json");
    const policy = homePath(home, ".nmzp", "policy-cache.json");
    const runtime = homePath(home, ".nmzp", "runtime", "0.2.5", "placeholder.txt");
    const manifestPath = manifest(home, { codexPath });
    writeText(claudePath, claudeDoc());
    writeText(grokPath, grokDoc());
    writeText(codexPath, codexDoc());
    writeText(cred, "{\"token\":\"synthetic\"}\n");
    writeText(core, "{\"fixture\":true}\n");
    writeText(policy, "{\"version\":1}\n");
    writeText(runtime, "synthetic runtime placeholder\n");
    try {
      const r = await leave(home);
      assert.equal(r.ok, true);
      assertUserKept(claudePath, "echo keep-claude");
      assert.ok(commands(readFileSync(claudePath, "utf8")).includes("other-tool --nmzp-not-ours"));
      assert.equal(JSON.parse(readFileSync(claudePath, "utf8")).extra, "keep-claude");
      assertUserKept(grokPath, "echo keep-grok");
      const grok = JSON.parse(readFileSync(grokPath, "utf8")) as {
        userKey: string;
        hooks: { SessionStart: Array<{ command: string }> };
      };
      assert.equal(grok.userKey, "keep-grok");
      assert.equal(grok.hooks.SessionStart[0]?.command, "echo grok-session");
      assertUserKept(codexPath, "echo keep-codex");
      assert.equal(codexHookConfiguredRaw(readFileSync(codexPath, "utf8")), false);
      assert.equal(r.removed.includes("claude:nmzp-entry"), true);
      assert.equal(r.removed.includes("grok:nmzp-entry"), true);
      assert.equal(r.removed.includes("codex:nmzp-entry"), true);
      assert.equal(existsSyncSafe(cred), false);
      assert.equal(existsSyncSafe(core), false);
      assert.equal(existsSyncSafe(policy), false);
      assert.equal(existsSyncSafe(manifestPath), false);
      assert.equal(readFileSync(runtime, "utf8"), "synthetic runtime placeholder\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function existsSyncSafe(path: string): boolean {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}
