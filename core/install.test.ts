import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { GROK_HOOK_FILE, NMZP_VERSION, TASK_NAME } from "./constants.ts";
import { isNmzpOwnedHook } from "./install-hooks.ts";
import {
  STARTUP_LAUNCHER_NAME,
  copyRuntime,
  defaultHome,
  grokHookDoc,
  grokPreToolUseMatches,
  hiddenProbeTr,
  applySnapshotGuardStandalone,
  joinDevice,
  leaveDevice,
  mergeClaudeSettings,
  parseJoinBundle,
  schtasksCreateArgs,
  startupLauncherBody,
  stripClaudeSettings,
  type JoinTransport,
  type LauncherRunner,
  type ProbeController,
  type TaskRunner,
} from "./install.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

const CLAUDE_ENTRY = {
  matcher: "*",
  hooks: [{ type: "command", command: "node nmzp.mjs hook --agent claude" }],
};

async function tempHome(): Promise<{ dir: string; home: string }> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-home-"));
  const home = join(dir, "home");
  await mkdir(home, { recursive: true });
  return { dir, home };
}

function fakeTransport(): JoinTransport & { joinCalls: number; tickets: string[] } {
  const tickets: string[] = [];
  const t: JoinTransport & { joinCalls: number; tickets: string[] } = {
    joinCalls: 0,
    tickets,
    async join(req) {
      t.joinCalls += 1;
      tickets.push(req.ticket);
      return { status: 200, body: JSON.stringify({ deviceId: "dev_abc", deviceToken: "tok_abc" }) };
    },
    async policy() {
      return {
        status: 200,
        body: JSON.stringify({ version: 1, mode: "enforcing", customRules: [], stopped: false, updatedAt: 1 }),
      };
    },
  };
  return t;
}

function fakeTasks(opts?: { createOk?: boolean; queryOk?: boolean; queryOutput?: string; foreign?: boolean }): TaskRunner & {
  creates: string[];
  removes: number;
} {
  const creates: string[] = [];
  let created = false;
  let lastTr = "";
  const runner: TaskRunner & { creates: string[]; removes: number } = {
    creates,
    removes: 0,
    create: async (tr) => {
      creates.push(tr);
      lastTr = tr;
      if (opts?.foreign) return { ok: false, output: "ERROR: Access is denied." };
      if (opts?.createOk === false) return { ok: false, output: "ERROR: Access is denied." };
      created = true;
      return { ok: true, output: "SUCCESS: The scheduled task was successfully created." };
    },
    query: async () => {
      if (opts?.foreign) {
        return {
          ok: true,
          output: opts?.queryOutput ?? "TaskName: NMZPProbe\nTask To Run: C:\\Windows\\notepad.exe",
        };
      }
      if (created || opts?.queryOk) {
        return {
          ok: true,
          output: opts?.queryOutput ?? `TaskName: ${TASK_NAME}\nTask To Run: ${lastTr || "node nmzp.mjs probe"}`,
        };
      }
      return { ok: false, output: opts?.queryOutput ?? "ERROR: The system cannot find the file specified." };
    },
    remove: async () => {
      runner.removes += 1;
      return { ok: true, output: "ok" };
    },
  };
  return runner;
}

function fakeProbe(running = false): ProbeController & { starts: number; stops: number; hidden: boolean | undefined } {
  let live = running;
  const p: ProbeController & { starts: number; stops: number; hidden: boolean | undefined } = {
    starts: 0,
    stops: 0,
    hidden: undefined,
    start: async (opts) => {
      p.starts += 1;
      p.hidden = opts.hidden;
      live = true;
      return { ok: true, pid: 4242 };
    },
    stopOwn: async () => {
      p.stops += 1;
      const stopped = live;
      live = false;
      return { ok: true, stopped, pid: 4242 };
    },
    isOwnRunning: async () => live,
  };
  return p;
}

async function stubRuntime(_coreDir: string, dest: string): Promise<void> {
  mkdirSync(dest, { recursive: true });
  writeFileSync(join(dest, "nmzp.mjs"), "export {}\n");
}

function bundle(ticket = "ticket-aaaa") {
  return {
    url: "https://nmzp.example.test",
    caPem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    fingerprintSha256: "ab".repeat(32),
    ticket,
  };
}

async function runJoin(
  home: string,
  extra: Record<string, unknown> = {},
): Promise<{
  result: Awaited<ReturnType<typeof joinDevice>>;
  transport: ReturnType<typeof fakeTransport>;
  probe: ReturnType<typeof fakeProbe>;
  tasks: ReturnType<typeof fakeTasks>;
  startupDir: string;
}> {
  const transport = (extra.transport as ReturnType<typeof fakeTransport> | undefined) ?? fakeTransport();
  const probe = (extra.probeController as ReturnType<typeof fakeProbe> | undefined) ?? fakeProbe();
  const tasks = (extra.taskRunner as ReturnType<typeof fakeTasks> | undefined) ?? fakeTasks();
  const startupDir = (extra.startupDir as string | undefined) ?? join(home, "Startup");
  await mkdir(startupDir, { recursive: true });
  const result = await joinDevice({
    home,
    bundle: bundle(),
    nodePath: process.execPath,
    coreDir,
    os: "win32",
    hostname: "testhost",
    user: "tester",
    skipRegister: false,
    transport,
    probeController: probe,
    taskRunner: tasks,
    copyRuntime: stubRuntime,
    startupDir,
    ...extra,
  });
  return { result, transport, probe, tasks, startupDir };
}

describe("windows join/leave (temp HOME)", () => {
  it("merges Claude hooks without wiping user entries", () => {
    const existing = JSON.stringify({
      hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo user" }] }] },
      extra: true,
    });
    const merged = mergeClaudeSettings(existing, CLAUDE_ENTRY);
    const doc = JSON.parse(merged.body) as { extra: boolean; hooks: { PreToolUse: unknown[] } };
    assert.equal(doc.extra, true);
    assert.equal(doc.hooks.PreToolUse.length, 2);
    const stripped = JSON.parse(stripClaudeSettings(merged.body)) as {
      hooks: { PreToolUse: Array<{ hooks: Array<{ command: string }> }> };
    };
    assert.equal(stripped.hooks.PreToolUse.length, 1);
    assert.equal(stripped.hooks.PreToolUse[0]!.hooks[0]!.command, "echo user");
  });

  it("Grok PreToolUse uses official match-all so write_file/WebFetch/MCP load the hook", () => {
    const doc = grokHookDoc("C:\\rt\\nmzp.mjs", "C:\\node.exe", "linux") as {
      hooks: { PreToolUse: Array<{ matcher?: string; hooks: Array<{ command: string }> }> };
    };
    const row = doc.hooks.PreToolUse[0]!;
    assert.equal(row.matcher, undefined);
    for (const tool of ["write_file", "WebFetch", "mcp__http__post", "read_file", "run_terminal_command"]) {
      assert.equal(grokPreToolUseMatches(tool, row.matcher), true, tool);
    }
    const listed = "Bash|Read|Write|Edit|run_terminal_command|search_replace|read_file";
    assert.equal(grokPreToolUseMatches("write_file", listed), false);
    assert.equal(grokPreToolUseMatches("WebFetch", listed), false);
    assert.equal(grokPreToolUseMatches("mcp__http__post", listed), false);
    const raw = JSON.stringify(doc);
    assert.equal(raw.includes("permissionDecision"), false);
    assert.match(row.hooks[0]!.command, /hook --agent grok/);
    assert.doesNotMatch(row.hooks[0]!.command, /\ballow\b/);
  });

  it("rejects http join bundles", () => {
    assert.equal(
      parseJoinBundle(JSON.stringify({ url: "http://192.168.1.10:8787", caPem: "x", fingerprintSha256: "aa", ticket: "t" })),
      null,
    );
  });

  it("rejects corrupt Claude JSON instead of wiping it", () => {
    assert.throws(() => mergeClaudeSettings("{not-json", CLAUDE_ENTRY), /claude_settings_corrupt/);
    assert.equal(stripClaudeSettings("{not-json"), "{not-json");
  });

  it("only removes owned NMZP subhooks and keeps siblings plus unidentified entries", () => {
    const existing = JSON.stringify({
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash",
            hooks: [
              { type: "command", command: "echo user" },
              { type: "command", command: "node nmzp.mjs hook --agent claude" },
              { type: "command", command: "other-tool --nmzp-not-ours" },
              { type: "prompt", prompt: "leave-me" },
            ],
          },
        ],
      },
      extra: 1,
    });
    const merged = mergeClaudeSettings(existing, CLAUDE_ENTRY);
    const doc = JSON.parse(merged.body) as {
      extra: number;
      hooks: { PreToolUse: Array<{ hooks: Array<{ command?: string; prompt?: string; type?: string }> }> };
    };
    assert.equal(doc.extra, 1);
    const cmds = doc.hooks.PreToolUse.flatMap((row) => row.hooks.map((h) => h.command)).filter(Boolean) as string[];
    assert.ok(cmds.includes("echo user"));
    assert.ok(cmds.includes("other-tool --nmzp-not-ours"));
    assert.equal(cmds.filter((c) => /nmzp(?:\.mjs)?/.test(c) && /hook --agent/.test(c)).length, 1);
    assert.ok(doc.hooks.PreToolUse.some((row) => row.hooks.some((h) => h.prompt === "leave-me")));
    const stripped = JSON.parse(stripClaudeSettings(merged.body)) as {
      hooks: { PreToolUse: Array<{ hooks: Array<{ command?: string; prompt?: string }> }> };
    };
    const after = stripped.hooks.PreToolUse.flatMap((row) => row.hooks);
    assert.ok(after.some((h) => h.command === "echo user"));
    assert.ok(after.some((h) => h.command === "other-tool --nmzp-not-ours"));
    assert.ok(after.some((h) => h.prompt === "leave-me"));
    assert.ok(!after.some((h) => /nmzp(?:\.mjs)?/.test(String(h.command ?? "")) && /hook --agent/.test(String(h.command ?? ""))));
  });

  it("schtasks create is not force-overwrite and probe task is hidden", () => {
    const args = schtasksCreateArgs("TR", TASK_NAME);
    assert.ok(args.includes("/create"));
    assert.ok(!args.includes("/f"));
    const tr = hiddenProbeTr("C:\\Program Files\\nodejs\\node.exe", "C:\\rt dir\\nmzp.mjs", "C:\\home");
    assert.match(tr, /WindowStyle Hidden|wscript/i);
    assert.match(tr, /probe|wscript/i);
    assert.doesNotMatch(tr, /ExecutionPolicy|Bypass/i);
    assert.match(tr, /rt dir/);
  });

  it("defaultHome uses NMZP_HOME and never the real profile in these tests", () => {
    const prev = process.env.NMZP_HOME;
    const isolated = join(tmpdir(), "nmzp-env-home-test");
    process.env.NMZP_HOME = isolated;
    try {
      assert.equal(defaultHome(), isolated);
    } finally {
      if (prev === undefined) delete process.env.NMZP_HOME;
      else process.env.NMZP_HOME = prev;
    }
  });

  it("join copies versioned runtime, protects creds, starts hidden probe; leave keeps user edits", async () => {
    const { dir, home } = await tempHome();
    await mkdir(join(home, ".claude"), { recursive: true });
    await writeFile(
      join(home, ".claude", "settings.json"),
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Read", hooks: [{ type: "command", command: "my-hook" }] }] } }),
    );
    try {
      const { result, probe, tasks, startupDir } = await runJoin(home);
      assert.equal(result.deviceId, "dev_abc");
      assert.equal(result.autostart, "user_startup");
      assert.equal(result.taskOk, true);
      assert.ok(existsSync(join(startupDir, STARTUP_LAUNCHER_NAME)));
      assert.ok(result.runtimeDir.replace(/\\/g, "/").includes(`/.nmzp/runtime/${NMZP_VERSION}`) || result.runtimeDir.includes(join(".nmzp", "runtime", NMZP_VERSION)));
      assert.equal(probe.starts, 1);
      assert.equal(probe.hidden, true);
      assert.equal(tasks.creates.length, 1);
      assert.match(tasks.creates[0]!, /wscript|WindowStyle Hidden/i);
      assert.doesNotMatch(tasks.creates[0]!, /ExecutionPolicy|Bypass/i);
      const creds = JSON.parse(await readFile(join(home, ".nmzp", "credentials.json"), "utf8")) as { token: string };
      assert.equal(creds.token, "tok_abc");
      assert.ok(existsSync(join(home, ".grok", "hooks", GROK_HOOK_FILE)));
      const claude = JSON.parse(await readFile(join(home, ".claude", "settings.json"), "utf8")) as {
        hooks: { PreToolUse: Array<{ hooks?: Array<{ command?: string }> }> };
      };
      assert.ok(claude.hooks.PreToolUse.some((r) => r.hooks?.some((h) => isNmzpOwnedHook(h))));
      assert.ok(claude.hooks.PreToolUse.some((r) => r.hooks?.some((h) => h.command === "my-hook")));
      await writeFile(
        join(home, ".claude", "settings.json"),
        JSON.stringify({
          hooks: {
            PreToolUse: [
              ...claude.hooks.PreToolUse,
              { matcher: "Write", hooks: [{ type: "command", command: "later-user" }] },
            ],
          },
        }),
      );
      const left = await leaveDevice({ home, skipRegister: false, taskRunner: tasks, os: "win32", probeController: probe });
      assert.equal(left.ok, true);
      assert.equal(probe.stops, 1);
      assert.equal(existsSync(join(home, ".nmzp", "credentials.json")), false);
      const after = JSON.parse(await readFile(join(home, ".claude", "settings.json"), "utf8")) as {
        hooks: { PreToolUse: Array<{ hooks?: Array<{ command?: string }> }> };
      };
      assert.ok(after.hooks.PreToolUse.some((r) => r.hooks?.some((h) => h.command === "my-hook")));
      assert.ok(after.hooks.PreToolUse.some((r) => r.hooks?.some((h) => h.command === "later-user")));
      assert.ok(!after.hooks.PreToolUse.some((r) => r.hooks?.some((h) => isNmzpOwnedHook(h))));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses to join over corrupt Claude settings and leaves the original file", async () => {
    const { dir, home } = await tempHome();
    const claudePath = join(home, ".claude", "settings.json");
    await mkdir(join(home, ".claude"), { recursive: true });
    await writeFile(claudePath, "{bad");
    try {
      await assert.rejects(() => runJoin(home), /claude_settings_corrupt/);
      assert.equal(await readFile(claudePath, "utf8"), "{bad");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not overwrite an existing Grok hook file and keeps later user edits on leave", async () => {
    const { dir, home } = await tempHome();
    const grokPath = join(home, ".grok", "hooks", GROK_HOOK_FILE);
    await mkdir(join(home, ".grok", "hooks"), { recursive: true });
    await writeFile(grokPath, JSON.stringify({ userKey: "keep-me", hooks: { SessionStart: [{ type: "command", command: "echo grok-user" }] } }, null, 2));
    const probe = fakeProbe();
    const tasks = fakeTasks();
    try {
      await runJoin(home, { probeController: probe, taskRunner: tasks });
      const afterJoin = JSON.parse(await readFile(grokPath, "utf8")) as {
        userKey: string;
        hooks: { SessionStart: unknown[]; PreToolUse: Array<{ hooks: Array<{ command: string }> }> };
      };
      assert.equal(afterJoin.userKey, "keep-me");
      assert.equal(afterJoin.hooks.SessionStart.length, 1);
      assert.ok(afterJoin.hooks.PreToolUse.some((r) => r.hooks.some((h) => isNmzpOwnedHook(h))));
      await writeFile(grokPath, JSON.stringify({ ...afterJoin, later: true }, null, 2));
      await leaveDevice({ home, skipRegister: false, taskRunner: tasks, os: "win32", probeController: probe });
      assert.equal(existsSync(grokPath), true);
      const afterLeave = JSON.parse(await readFile(grokPath, "utf8")) as {
        userKey: string;
        later?: boolean;
        hooks?: { SessionStart?: unknown[]; PreToolUse?: Array<{ hooks: Array<{ command: string }> }> };
      };
      assert.equal(afterLeave.userKey, "keep-me");
      assert.equal(afterLeave.later, true);
      assert.ok(afterLeave.hooks?.SessionStart);
      assert.ok(!(afterLeave.hooks?.PreToolUse ?? []).some((r) => r.hooks.some((h) => isNmzpOwnedHook(h))));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("join is idempotent and does not consume a second ticket", async () => {
    const { dir, home } = await tempHome();
    const transport = fakeTransport();
    try {
      const first = await runJoin(home, { transport, bundle: bundle("ticket-aaaa") });
      const second = await runJoin(home, { transport, bundle: bundle("ticket-bbbb") });
      assert.equal(first.result.deviceId, "dev_abc");
      assert.equal(second.result.deviceId, "dev_abc");
      assert.equal(transport.joinCalls, 1);
      assert.deepEqual(transport.tickets, ["ticket-aaaa"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not force-overwrite a foreign scheduled task; falls back to user_startup", async () => {
    const { dir, home } = await tempHome();
    const tasks = fakeTasks({ foreign: true });
    try {
      const { result, startupDir } = await runJoin(home, { taskRunner: tasks });
      assert.equal(tasks.creates.length, 0);
      assert.notEqual(result.taskOk, true);
      assert.equal(result.autostart, "user_startup");
      assert.equal(existsSync(join(startupDir, STARTUP_LAUNCHER_NAME)), true);
      await leaveDevice({ home, skipRegister: false, taskRunner: tasks, os: "win32", probeController: fakeProbe() });
      assert.equal(tasks.removes, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("access-denied scheduled task falls back to user_startup and does not set taskOk", async () => {
    const { dir, home } = await tempHome();
    const tasks = fakeTasks({ createOk: false, queryOk: false });
    try {
      const { result, probe, startupDir } = await runJoin(home, { taskRunner: tasks });
      assert.equal(result.autostart, "user_startup");
      assert.notEqual(result.taskOk, true);
      assert.equal(result.taskOk, false);
      assert.equal(probe.starts, 1);
      assert.equal(probe.hidden, true);
      const launcher = join(startupDir, STARTUP_LAUNCHER_NAME);
      assert.equal(existsSync(launcher), true);
      const body = await readFile(launcher, "utf8");
      assert.match(body, /NMZP_PROBE_LAUNCHER/);
      assert.match(body, /\bprobe\b/);
      assert.doesNotMatch(body, /schtasks|HKLM/i);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("throws when both scheduled task and user startup fail", async () => {
    const { dir, home } = await tempHome();
    const tasks = fakeTasks({ createOk: false });
    const launcherRunner: LauncherRunner = {
      install: async () => ({ ok: false, error: "startup_failed" }),
      removeIfUnmodified: async () => ({ removed: false }),
    };
    try {
      await assert.rejects(() => runJoin(home, { taskRunner: tasks, launcherRunner }), /autostart_failed/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("leave only removes unmodified own startup launcher and does not touch other Startup items", async () => {
    const { dir, home } = await tempHome();
    const probe = fakeProbe();
    const tasks = fakeTasks({ createOk: false });
    try {
      const { startupDir } = await runJoin(home, { probeController: probe, taskRunner: tasks });
      const other = join(startupDir, "user-app.cmd");
      await writeFile(other, "@echo off\necho user\n");
      const launcher = join(startupDir, STARTUP_LAUNCHER_NAME);
      const original = await readFile(launcher, "utf8");
      await leaveDevice({ home, skipRegister: false, taskRunner: tasks, os: "win32", probeController: probe });
      assert.equal(existsSync(launcher), false);
      assert.equal(existsSync(other), true);
      assert.equal(await readFile(other, "utf8"), "@echo off\necho user\n");

      const { startupDir: startup2 } = await runJoin(home, { probeController: fakeProbe(), taskRunner: fakeTasks({ createOk: false }) });
      const path2 = join(startup2, STARTUP_LAUNCHER_NAME);
      await writeFile(path2, original + "\r\nREM user-later\r\n");
      const probe2 = fakeProbe();
      await leaveDevice({ home, skipRegister: false, taskRunner: fakeTasks({ createOk: false }), os: "win32", probeController: probe2 });
      assert.equal(existsSync(path2), true);
      assert.match(await readFile(path2, "utf8"), /user-later/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not overwrite a foreign same-name Startup launcher", async () => {
    const { dir, home } = await tempHome();
    const startupDir = join(home, "Startup");
    await mkdir(startupDir, { recursive: true });
    const foreign = join(startupDir, STARTUP_LAUNCHER_NAME);
    await writeFile(foreign, "@echo off\necho not-nmzp\n");
    const tasks = fakeTasks({ createOk: false });
    try {
      await assert.rejects(() => runJoin(home, { startupDir, taskRunner: tasks }), /startup_owned_by_other|autostart_failed/);
      assert.equal(await readFile(foreign, "utf8"), "@echo off\necho not-nmzp\n");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("hidden launcher body only starts NMZP probe", () => {
    const body = startupLauncherBody("C:\\node.exe", "C:\\rt\\nmzp.mjs", "C:\\tmp-home");
    assert.match(body, /NMZP_PROBE_LAUNCHER/);
    assert.match(body, /WScript\.Shell|WindowStyle Hidden/i);
    assert.match(body, /nmzp\.mjs/);
    assert.match(body, /\bprobe\b/);
    assert.doesNotMatch(body, /serve|hook --agent|HKLM|schtasks|ExecutionPolicy|Bypass/i);
  });

  it("does not overwrite a running same-version runtime", async () => {
    const { dir, home } = await tempHome();
    const probe = fakeProbe();
    try {
      const { result } = await runJoin(home, { probeController: probe });
      const marker = join(result.runtimeDir, "marker.txt");
      await writeFile(marker, "keep");
      const running = fakeProbe(true);
      await runJoin(home, { probeController: running, transport: fakeTransport() });
      assert.equal(await readFile(marker, "utf8"), "keep");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("restricts credentials and backups with current-user/SYSTEM ACL on Windows", async () => {
    const { dir, home } = await tempHome();
    try {
      await runJoin(home);
      const cred = join(home, ".nmzp", "credentials.json");
      assert.equal(existsSync(cred), true);
      if (process.platform === "win32") {
        const ic = spawnSync("icacls", [cred], { encoding: "utf8", windowsHide: true });
        assert.equal(ic.status, 0, ic.stderr || ic.stdout);
        const out = (ic.stdout || "").toLowerCase();
        assert.ok(out.includes("system"), ic.stdout);
        assert.ok(out.includes(userInfo().username.toLowerCase()), ic.stdout);
        assert.equal(out.includes("everyone"), false);
        const backupRoot = join(home, ".nmzp", "backups");
        assert.equal(existsSync(backupRoot), true);
        const bakIc = spawnSync("icacls", [backupRoot], { encoding: "utf8", windowsHide: true });
        const bak = (bakIc.stdout || "").toLowerCase();
        assert.ok(bak.includes("system"), bakIc.stdout);
        assert.equal(bak.includes("everyone"), false);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("copyRuntime places a complete ui tree on the runtime for board", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-ui-"));
    const core = join(dir, "pkg");
    await mkdir(join(core, "ui", "assets"), { recursive: true });
    await writeFile(join(core, "nmzp.mjs"), "export {}\n");
    await writeFile(join(core, "ui", "index.html"), "<html>board</html>\n");
    await writeFile(join(core, "ui", "assets", "app.js"), "console.log(1)\n");
    const dest = join(dir, "runtime");
    try {
      await copyRuntime(core, dest);
      assert.equal(await readFile(join(dest, "ui", "index.html"), "utf8"), "<html>board</html>\n");
      assert.equal(existsSync(join(dest, "ui", "assets", "app.js")), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("copyRuntime fails closed when no packed ui and no dist", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-noui-"));
    const core = join(dir, "pkg");
    await mkdir(core, { recursive: true });
    await writeFile(join(core, "nmzp.mjs"), "export {}\n");
    try {
      await assert.rejects(() => copyRuntime(core, join(dir, "runtime")), /install_missing_ui/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("snapshot guard install is read-only in join", () => {
  const publicOk = {
    supported: true,
    active: false,
    managed: false,
    targetPresent: true,
    writeBlocked: false,
    existingArchiveCoverage: "none",
    lastVerified: 1_700_000_000_000,
  };
  const external = {
    ...publicOk,
    writeBlocked: true,
    error: "external_restriction",
  };

  it("join default collector on temp home is read-only and not active", { timeout: 20_000 }, async () => {
    const { dir, home } = await tempHome();
    try {
      const t0 = Date.now();
      const { result } = await runJoin(home);
      const dt = Date.now() - t0;
      assert.ok(existsSync(join(home, ".grok", "hooks", GROK_HOOK_FILE)));
      assert.notEqual(result.snapshotGuard?.active, true);
      assert.ok(result.snapshotGuardApply === "degraded" || result.snapshotGuardApply === "cli");
      assert.ok(dt < 25_000, `join hung on snapshot status (${dt}ms)`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("join records status and never applies or restores", async () => {
    const { dir, home } = await tempHome();
    try {
      const { result } = await runJoin(home, {
        snapshotGuardStatus: async () => external,
      });
      assert.equal(result.snapshotGuardApply, "skipped_external");
      assert.equal(result.snapshotGuard?.error, "external_restriction");
      assert.equal(result.snapshotGuard?.writeBlocked, true);
      assert.equal(result.snapshotGuard?.managed, false);
      assert.ok(existsSync(join(home, ".grok", "hooks", GROK_HOOK_FILE)));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not claim protection just because .zcode exists without checkpoints", async () => {
    const { dir, home } = await tempHome();
    await mkdir(join(home, ".zcode"), { recursive: true });
    try {
      const { result } = await runJoin(home, {
        snapshotGuardStatus: async () => ({
          supported: true,
          active: false,
          managed: false,
          targetPresent: false,
          writeBlocked: false,
          existingArchiveCoverage: "none",
          error: "target_missing",
          lastVerified: 1,
        }),
      });
      assert.equal(result.snapshotGuardApply, "degraded");
      assert.equal(result.snapshotGuard?.active, false);
      assert.equal(result.snapshotGuard?.targetPresent, false);
      assert.equal(result.snapshotGuardError, "target_missing");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("standalone apply skips external, degrades missing target, never restores", async () => {
    let apply = 0;
    let restore = 0;
    const skipped = await applySnapshotGuardStandalone({
      home: join(tmpdir(), "nmzp-sg-apply-ext"),
      status: async () => external,
      apply: async () => {
        apply += 1;
        return publicOk;
      },
      restore: async () => {
        restore += 1;
        return publicOk;
      },
    });
    assert.equal(skipped.action, "skipped_external");
    assert.equal(apply, 0);
    assert.equal(restore, 0);

    const missing = await applySnapshotGuardStandalone({
      home: join(tmpdir(), "nmzp-sg-apply-miss"),
      status: async () => ({ ...publicOk, targetPresent: false, error: "target_missing" }),
      apply: async () => {
        apply += 1;
        return publicOk;
      },
      restore: async () => {
        restore += 1;
        return publicOk;
      },
    });
    assert.equal(missing.action, "degraded");
    assert.equal(missing.error, "target_missing");
    assert.equal(apply, 0);
    assert.equal(restore, 0);

    const applied = await applySnapshotGuardStandalone({
      home: join(tmpdir(), "nmzp-sg-apply-ok"),
      status: async () => publicOk,
      apply: async () => ({
        ...publicOk,
        active: true,
        managed: true,
        writeBlocked: true,
        existingArchiveCoverage: "none",
      }),
      restore: async () => {
        restore += 1;
        return publicOk;
      },
    });
    assert.equal(applied.action, "applied");
    assert.equal(applied.status?.active, true);
    assert.equal(restore, 0);

    const failedApply = await applySnapshotGuardStandalone({
      home: join(tmpdir(), "nmzp-sg-apply-fail"),
      status: async () => publicOk,
      apply: async () => ({
        ...publicOk,
        active: false,
        error: "apply_failed",
      }),
      restore: async () => {
        restore += 1;
        return publicOk;
      },
    });
    assert.equal(failedApply.action, "degraded");
    assert.equal(failedApply.error, "apply_failed");
    assert.notEqual(failedApply.action, "applied");
    assert.equal(restore, 0);

    const unknownCov = await applySnapshotGuardStandalone({
      home: join(tmpdir(), "nmzp-sg-apply-unk"),
      status: async () => publicOk,
      apply: async () => ({
        ...publicOk,
        active: false,
        writeBlocked: true,
        existingArchiveCoverage: "unknown",
        error: "coverage_unknown",
      }),
    });
    assert.equal(unknownCov.action, "degraded");
    assert.notEqual(unknownCov.action, "applied");
  });
});

