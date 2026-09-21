import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { GROK_HOOK_FILE } from "./constants.ts";
import { codexHookEntry, codexHookTrust, mergeCodexHooks } from "./codex-hooks.ts";
import { mergeZcodeConfig, zcodeConfigPath, zcodeHookGroup } from "./zcode-hooks.ts";
import { antigravityHookDoc, antigravityHooksPath, mergeAntigravityHooks } from "./antigravity-hooks.ts";
import { hookCommand } from "./install-hooks.ts";
import {
  HOOK_STATUS_CONTRACT,
  WINDOWS_CANDIDATE_IDENTITY_SCRIPT,
  WINDOWS_PROCESS_INDEX_SCRIPT,
  assembleProbeReport,
  classifyAgentProc,
  claudeHookConfigured,
  grokHookConfigured,
  readHookStatus,
  recordHookOutcome,
  snapshotGuardForHeartbeat,
  type ProcRow,
} from "./probe.ts";

function ownedPreToolUse(agent: "grok" | "claude", os: string, extraHooks: unknown[] = []): Record<string, unknown> {
  const command = hookCommand("/usr/bin/node", "/opt/nmzp/nmzp.mjs", agent, os);
  return {
    extraUser: true,
    hooks: {
      PreToolUse: [
        ...extraHooks,
        { matcher: agent === "claude" ? "*" : undefined, hooks: [{ type: "command", command, timeout: 8 }] },
      ],
    },
  };
}

function rows(list: ProcRow[]): ProcRow[] {
  return list;
}

describe("probe identity and evidence", () => {
  it("windows process index does not request CommandLine", () => {
    assert.match(WINDOWS_PROCESS_INDEX_SCRIPT, /ProcessId/);
    assert.match(WINDOWS_PROCESS_INDEX_SCRIPT, /ParentProcessId/);
    assert.match(WINDOWS_PROCESS_INDEX_SCRIPT, /Name/);
    assert.doesNotMatch(WINDOWS_PROCESS_INDEX_SCRIPT, /CommandLine/);
  });

  it("candidate identity query does not request CommandLine", () => {
    const script = WINDOWS_CANDIDATE_IDENTITY_SCRIPT([11, 22]);
    assert.match(script, /ExecutablePath/);
    assert.doesNotMatch(script, /CommandLine/);
    assert.match(script, /11/);
    assert.match(script, /22/);
  });

  it("does not treat shared node with grok/claude words in cmdline as grok", () => {
    const all = rows([
      { pid: 1, ppid: 0, name: "explorer.exe" },
      {
        pid: 10,
        ppid: 1,
        name: "node.exe",
        cmdline: "node C:\\Users\\u\\project\\grok-claude-server.js",
        exe: "C:\\Program Files\\nodejs\\node.exe",
      },
    ]);
    assert.equal(classifyAgentProc(all[1]!, all), "unknown");
  });

  it("does not inherit identity from an unverified named parent", () => {
    const all = rows([
      { pid: 5, ppid: 1, name: "grok.exe" },
      { pid: 10, ppid: 5, name: "node.exe", exe: "C:\\Program Files\\nodejs\\node.exe" },
    ]);
    assert.equal(classifyAgentProc(all[1]!, all), "unknown");
  });

  it("does not trust a shared runtime based on install path", () => {
    const all = rows([
      { pid: 1, ppid: 0, name: "services.exe" },
      {
        pid: 10,
        ppid: 1,
        name: "node.exe",
        exe: "C:\\Users\\u\\AppData\\Local\\Programs\\Grok\\runtime\\node.exe",
      },
    ]);
    assert.equal(classifyAgentProc(all[1]!, all), "unknown");
  });

  it("named grok.exe is only a candidate; chrome is not an agent", () => {
    assert.equal(classifyAgentProc({ pid: 3, ppid: 1, name: "grok.exe" }, []), "unknown");
    assert.equal(classifyAgentProc({ pid: 4, ppid: 1, name: "chrome.exe" }, []), null);
  });

  it("hook active requires hook-status success evidence, not process presence", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-probe-"));
    const home = join(dir, "home");
    await mkdir(join(home, ".grok", "hooks"), { recursive: true });
    await writeFile(
      join(home, ".grok", "hooks", GROK_HOOK_FILE),
      JSON.stringify(ownedPreToolUse("grok", "linux")),
    );
    const procs: ProcRow[] = [{ pid: 9, ppid: 1, name: "grok.exe" }];
    try {
      const without = assembleProbeReport({ home, procs, listOk: true, now: 1_700_000_000_000 });
      const grokCap = without.capabilities.find((c) => c.id === "hook_grok");
      assert.equal(grokCap?.supported, true);
      assert.equal(grokCap?.active, false);
      assert.equal(grokCap?.error, "offline");
      await mkdir(join(home, ".nmzp"), { recursive: true });
      await writeFile(
        join(home, ".nmzp", "hook-status.json"),
        JSON.stringify({
          version: 1,
          updatedAt: 1_700_000_000_000,
          hooks: { grok: { ok: true, lastSuccessAt: 1_700_000_000_000, eventId: "e1", tool: "run_terminal_command" } },
        }),
      );
      const status = readHookStatus(home);
      assert.equal(status?.hooks?.grok?.ok, true);
      const withEv = assembleProbeReport({ home, procs, listOk: true, now: 1_700_000_000_000 });
      assert.equal(withEv.capabilities.find((c) => c.id === "hook_grok")?.active, true);
      recordHookOutcome(home, "grok", { ok: false, error: "timeout", at: 1_700_000_000_100 });
      const ex = assembleProbeReport({ home, procs, listOk: true, now: 1_700_000_000_100 });
      assert.equal(ex.capabilities.find((c) => c.id === "hook_grok")?.active, false);
      assert.equal(ex.capabilities.find((c) => c.id === "hook_grok")?.error, "timeout");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("publishes the hook-status.json contract for the hook worker", () => {
    assert.equal(HOOK_STATUS_CONTRACT.version, 1);
    assert.equal(HOOK_STATUS_CONTRACT.relativePath, ".nmzp/hook-status.json");
    assert.match(HOOK_STATUS_CONTRACT.writeWhen, /stdout/);
    assert.equal(HOOK_STATUS_CONTRACT.heartbeat.success, "capability.active=true");
    assert.equal(HOOK_STATUS_CONTRACT.heartbeat.offline, "capability.error=offline (missing, stale, or no lastSuccessAt)");
    assert.equal(HOOK_STATUS_CONTRACT.heartbeat.exception, "capability.error=exception (ok=false or error code)");
  });

  it("collection failure reports unknown and does not mark snapshot active", () => {
    const r = assembleProbeReport({ home: join(tmpdir(), "nmzp-missing-home"), procs: [], listOk: false, now: 10 });
    const snap = r.capabilities.find((c) => c.id === "process_snapshot");
    assert.equal(snap?.supported, true);
    assert.equal(snap?.active, false);
    assert.equal(snap?.error, "unknown");
    assert.deepEqual(r.agents, ["unknown"]);
    assert.equal(JSON.stringify(r).includes("CommandLine"), false);
  });

  it("heartbeat payload never includes process cmdline or CommandLine", () => {
    const r = assembleProbeReport({
      home: join(tmpdir(), "nmzp-missing-home"),
      procs: [{ pid: 1, ppid: 0, name: "grok.exe", cmdline: "SECRET --token abc" }],
      listOk: true,
      now: 10,
    });
    const raw = JSON.stringify(r);
    assert.equal(raw.includes("SECRET"), false);
    assert.equal(raw.includes("--token abc"), false);
    assert.equal(raw.includes("CommandLine"), false);
    assert.ok(r.agents.includes("unknown"));
    assert.deepEqual(r.agentProcs, []);
    // No unverified process record is published.
  });
});

describe("hook configured requires owned PreToolUse command", () => {
  async function tmpHome(): Promise<{ dir: string; home: string }> {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-probe-cfg-"));
    return { dir, home: join(dir, "home") };
  }

  it("empty, corrupt, or user-only hooks are not configured; extra keys stay", async () => {
    const { dir, home } = await tmpHome();
    const grokPath = join(home, ".grok", "hooks", GROK_HOOK_FILE);
    const claudePath = join(home, ".claude", "settings.json");
    const userHook = { matcher: "Bash", hooks: [{ type: "command", command: "echo user-pre" }] };
    try {
      await mkdir(join(home, ".grok", "hooks"), { recursive: true });
      await mkdir(join(home, ".claude"), { recursive: true });
      await writeFile(grokPath, "{}");
      assert.equal(grokHookConfigured(home), false);
      assert.equal(
        assembleProbeReport({ home, procs: [], listOk: true, now: 10 }).capabilities.find((c) => c.id === "hook_grok")
          ?.error,
        "hook_not_installed",
      );

      await writeFile(grokPath, JSON.stringify({ hooks: { PreToolUse: [] }, keep: 1 }));
      assert.equal(grokHookConfigured(home), false);

      await writeFile(grokPath, "{not json");
      assert.equal(grokHookConfigured(home), false);

      await writeFile(claudePath, JSON.stringify({ keep: "claude-extra", hooks: { PreToolUse: [userHook] } }));
      assert.equal(claudeHookConfigured(home), false);
      const claudeRaw = await readFile(claudePath, "utf8");
      assert.equal(JSON.parse(claudeRaw).keep, "claude-extra");
      assert.equal(claudeRaw.includes("echo user-pre"), true);

      await mkdir(join(home, ".nmzp"), { recursive: true });
      await writeFile(
        join(home, ".nmzp", "hook-status.json"),
        JSON.stringify({
          version: 1,
          updatedAt: 10,
          hooks: { grok: { ok: true, lastSuccessAt: 10 }, claude: { ok: true, lastSuccessAt: 10 } },
        }),
      );
      const caps = assembleProbeReport({ home, procs: [], listOk: true, now: 10 }).capabilities;
      assert.equal(caps.find((c) => c.id === "hook_grok")?.active, false);
      assert.equal(caps.find((c) => c.id === "hook_grok")?.error, "hook_not_installed");
      assert.equal(caps.find((c) => c.id === "hook_claude")?.active, false);
      assert.equal(caps.find((c) => c.id === "hook_claude")?.error, "hook_not_installed");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("Grok and Claude EncodedCommand owned entries count as configured and keep siblings", async () => {
    const { dir, home } = await tmpHome();
    const grokPath = join(home, ".grok", "hooks", GROK_HOOK_FILE);
    const claudePath = join(home, ".claude", "settings.json");
    const userHook = { matcher: "Bash", hooks: [{ type: "command", command: "echo keep-me" }] };
    try {
      await mkdir(join(home, ".grok", "hooks"), { recursive: true });
      await mkdir(join(home, ".claude"), { recursive: true });
      const grokDoc = ownedPreToolUse("grok", "win32", [userHook]);
      const claudeDoc = ownedPreToolUse("claude", "win32", [userHook]);
      await writeFile(grokPath, JSON.stringify(grokDoc, null, 2));
      await writeFile(claudePath, JSON.stringify(claudeDoc, null, 2));

      const grokRaw = await readFile(grokPath, "utf8");
      const claudeRaw = await readFile(claudePath, "utf8");
      assert.equal(grokRaw.includes("hook --agent"), false);
      assert.equal(claudeRaw.includes("hook --agent"), false);
      assert.equal(grokHookConfigured(home), true);
      assert.equal(claudeHookConfigured(home), true);
      assert.equal(JSON.parse(grokRaw).extraUser, true);
      assert.equal(JSON.parse(claudeRaw).extraUser, true);
      assert.equal(grokRaw.includes("echo keep-me"), true);
      assert.equal(claudeRaw.includes("echo keep-me"), true);

      const r = assembleProbeReport({ home, procs: [], listOk: true, now: 10 });
      assert.equal(r.capabilities.find((c) => c.id === "hook_grok")?.error, "offline");
      assert.equal(r.capabilities.find((c) => c.id === "hook_claude")?.error, "offline");
      assert.equal(r.capabilities.find((c) => c.id === "hook_grok")?.active, false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("hook_codex is gated by Codex persisted trust", () => {
  it("configured but untrusted stays inactive even with a fresh receipt; trusted follows receipts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-probe-codex-"));
    const home = join(dir, "home");
    const hooksPath = join(home, ".codex", "hooks.json");
    const configPath = join(home, ".codex", "config.toml");
    const now = 1_700_000_000_000;
    try {
      await mkdir(join(home, ".codex"), { recursive: true });
      await mkdir(join(home, ".nmzp"), { recursive: true });
      await writeFile(hooksPath, mergeCodexHooks(null, codexHookEntry("/usr/bin/node", "/opt/nmzp/nmzp.mjs", "linux")));
      await writeFile(
        join(home, ".nmzp", "hook-status.json"),
        JSON.stringify({ version: 1, updatedAt: now, hooks: { codex: { ok: true, lastSuccessAt: now, tool: "Bash" } } }),
      );
      const cap = () => assembleProbeReport({ home, procs: [], listOk: true, now }).capabilities.find((c) => c.id === "hook_codex");

      assert.equal(cap()?.active, false);
      assert.equal(cap()?.error, "hook_untrusted");

      const trust = codexHookTrust(home);
      await writeFile(configPath, `[hooks.state.'${trust.key}']\ntrusted_hash = "sha256:old"\n`);
      assert.equal(cap()?.error, "hook_modified");

      await writeFile(configPath, `[hooks.state.'${trust.key}']\ntrusted_hash = "${trust.currentHash}"\n`);
      assert.equal(cap()?.active, true);
      assert.equal(cap()?.error, undefined);

      await writeFile(join(home, ".nmzp", "hook-status.json"), JSON.stringify({ version: 1, updatedAt: now, hooks: {} }));
      assert.equal(cap()?.active, false);
      assert.equal(cap()?.error, "offline");

      await writeFile(configPath, `[features]\nhooks = false\n[hooks.state.'${trust.key}']\ntrusted_hash = "${trust.currentHash}"\n`);
      assert.equal(cap()?.error, "hooks_feature_off");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("hook_zcode and hook_antigravity follow host enable flags plus receipts", () => {
  it("disabled host config never becomes active; enabled config follows receipts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-probe-za-"));
    const home = join(dir, "home");
    const now = 1_700_000_000_000;
    const caps = () => assembleProbeReport({ home, procs: [], listOk: true, now }).capabilities;
    const cap = (id: string) => caps().find((c) => c.id === id);
    try {
      await mkdir(join(home, ".nmzp"), { recursive: true });
      assert.equal(cap("hook_zcode")?.error, "hook_not_installed");
      assert.equal(cap("hook_antigravity")?.error, "hook_not_installed");

      await mkdir(join(home, ".zcode", "cli"), { recursive: true });
      await mkdir(join(home, ".gemini", "config"), { recursive: true });
      await writeFile(zcodeConfigPath(home), mergeZcodeConfig(null, zcodeHookGroup("/usr/bin/node", "/opt/nmzp/nmzp.mjs")));
      await writeFile(antigravityHooksPath(home), mergeAntigravityHooks(null, antigravityHookDoc("/usr/bin/node", "/opt/nmzp/nmzp.mjs", "linux")));
      assert.equal(cap("hook_zcode")?.error, "offline");
      assert.equal(cap("hook_antigravity")?.error, "offline");

      await writeFile(
        join(home, ".nmzp", "hook-status.json"),
        JSON.stringify({
          version: 1,
          updatedAt: now,
          hooks: { zcode: { ok: true, lastSuccessAt: now, tool: "Bash" }, antigravity: { ok: true, lastSuccessAt: now, tool: "run_command" } },
        }),
      );
      assert.equal(cap("hook_zcode")?.active, true);
      assert.equal(cap("hook_antigravity")?.active, true);

      const z = JSON.parse(await readFile(zcodeConfigPath(home), "utf8"));
      z.hooks.enabled = false;
      await writeFile(zcodeConfigPath(home), JSON.stringify(z));
      assert.equal(cap("hook_zcode")?.active, false);
      assert.equal(cap("hook_zcode")?.error, "hooks_disabled");

      const a = JSON.parse(await readFile(antigravityHooksPath(home), "utf8"));
      a.nmzp.enabled = false;
      await writeFile(antigravityHooksPath(home), JSON.stringify(a));
      assert.equal(cap("hook_antigravity")?.active, false);
      assert.equal(cap("hook_antigravity")?.error, "hook_disabled");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("snapshot guard heartbeat collection", () => {
  it("stopped ticks skip collection; failures are inactive unknown, never old active", async () => {
    const home = join(tmpdir(), "nmzp-sg-probe-home");
    let calls = 0;
    const collect = async () => {
      calls += 1;
      return {
        supported: true,
        active: true,
        managed: true,
        targetPresent: true,
        writeBlocked: true,
        existingArchiveCoverage: "protected",
        lastVerified: 1_700_000_000_000,
        sddl: "O:BAG:SYD:(A;;FA;;;WD)",
        paths: ["C:\\\\Users\\\\u\\\\.zcode\\\\v2\\\\checkpoints"],
      };
    };
    const skipped = await snapshotGuardForHeartbeat({ home, stopped: true, collect });
    assert.equal(skipped, undefined);
    assert.equal(calls, 0);

    const ok = await snapshotGuardForHeartbeat({ home, stopped: false, collect });
    assert.ok(ok);
    assert.equal(ok!.active, true);
    assert.equal("sddl" in ok!, false);
    assert.equal("paths" in ok!, false);
    assert.equal(JSON.stringify(ok).includes(".zcode"), false);

    const failed = await snapshotGuardForHeartbeat({
      home,
      stopped: false,
      collect: async () => {
        throw new Error("helper_down");
      },
    });
    assert.ok(failed);
    assert.equal(failed!.active, false);
    assert.equal(failed!.existingArchiveCoverage, "unknown");
    assert.equal(failed!.error, "status_failed");
    assert.equal(failed!.lastVerified, 0);
    assert.notEqual(failed!.active, true);
  });

  it("times out a hung helper without using a previous success", async () => {
    const hung = snapshotGuardForHeartbeat({
      home: join(tmpdir(), "nmzp-sg-probe-hang"),
      stopped: false,
      timeoutMs: 30,
      collect: () => new Promise(() => undefined),
    });
    const r = await hung;
    assert.equal(r?.active, false);
    assert.equal(r?.error, "timeout");
    assert.equal(r?.existingArchiveCoverage, "unknown");
    assert.equal(r?.lastVerified, 0);
  });
});

