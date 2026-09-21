import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { runHook, settleHookAfterStdout } from "./hook.ts";
import { assembleProbeReport } from "./probe.ts";
import { hookCommand } from "./install-hooks.ts";
import { GROK_HOOK_FILE } from "./constants.ts";
import {
  ALIAS_CONFLICT,
  parseHookEvent,
  pickDefinedSame,
  toolInputToEvalFields,
} from "./hook-protocol.ts";
import { writePolicyCache } from "./policy-cache.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

/** Shape from maintenance-20260920-real-lan/hook-shape.jsonl (no body). */
const REAL_CWD = "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor";
const REAL_ROOT = "C:/Users/dev/Desktop/NMZP/nmzp-monitor/";

function grokReadFileShape(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const toolInput = { target_file: "core/hook-protocol.ts", limit: 80 };
  return {
    hookEventName: "pre_tool_use",
    sessionId: "sess-shape",
    cwd: REAL_CWD,
    workspaceRoot: REAL_ROOT,
    timestamp: 1_746_000_000_000,
    transcriptPath: "C:/Users/dev/.grok/sessions/shape/transcript.jsonl",
    permissionMode: "auto",
    toolName: "read_file",
    toolUseId: "tu_shape",
    toolInput,
    toolInputTruncated: false,
    hook_event_name: "PreToolUse",
    session_id: "sess-shape",
    transcript_path: "C:/Users/dev/.grok/sessions/shape/transcript.jsonl",
    permission_mode: "auto",
    tool_name: "read_file",
    tool_input: { ...toolInput },
    tool_use_id: "tu_shape",
    ...overrides,
  };
}

describe("real Grok PreToolUse shape (Windows cwd vs workspaceRoot)", () => {
  it("old cwd/workspaceRoot alias compare is the conflict; parse keeps cwd", () => {
    assert.equal(pickDefinedSame([REAL_CWD, REAL_ROOT]), ALIAS_CONFLICT);
    const p = parseHookEvent(JSON.stringify(grokReadFileShape()));
    assert.ok(p);
    assert.equal(p!.cwd, REAL_CWD);
    assert.equal(p!.toolName, "read_file");
    assert.equal(p!.sessionId, "sess-shape");
    assert.equal(p!.eventId, "tu_shape");
    assert.equal(p!.agentHint, "grok");
    assert.equal("timestamp" in p!, false);
    assert.equal("agent" in p!, false);
    const fields = toolInputToEvalFields(p!.toolName, p!.toolInput);
    assert.equal(fields.filePath, "core/hook-protocol.ts");
    assert.equal(fields.contents, undefined);
  });

  it("runHook does not deny this legal JSON as bad_hook_json", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-hook-shape-"));
    try {
      const r = await runHook({
        argv: ["--agent", "grok"],
        stdin: JSON.stringify(grokReadFileShape()),
        home,
        coreDir,
      });
      assert.equal(r.exitCode, 0, r.stdout);
      assert.equal(r.stdout.trim(), "");
      assert.equal(r.stdout.includes("bad_hook_json"), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("stopped cache still empty-passes this shape instead of bad_hook_json", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-hook-shape-stop-"));
    try {
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
        version: 1,
        mode: "off",
        customRules: [],
        stopped: true,
        updatedAt: Date.now(),
      });
      const r = await runHook({
        argv: ["--agent", "grok"],
        stdin: JSON.stringify(grokReadFileShape()),
        home,
        coreDir,
      });
      assert.equal(r.exitCode, 0, r.stdout);
      assert.equal(r.stdout.trim(), "");
      assert.equal(r.stdout.includes("bad_hook_json"), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("illegal JSON is still rejected (pause cannot swallow it)", async () => {
    assert.equal(parseHookEvent("{not json"), null);
    const home = await mkdtemp(join(tmpdir(), "nmzp-hook-shape-bad-"));
    try {
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
        version: 1,
        mode: "off",
        customRules: [],
        stopped: true,
        updatedAt: Date.now(),
      });
      const r = await runHook({
        argv: ["--agent", "grok"],
        stdin: "{not json",
        home,
        coreDir,
      });
      assert.equal(r.exitCode, 2);
      const j = JSON.parse(r.stdout) as { decision: string; reason: string };
      assert.equal(j.decision, "deny");
      assert.equal(j.reason, "bad_hook_json");
      assert.equal(r.statusRecord?.agent, "grok");
      assert.equal(r.statusRecord?.ok, false);
      assert.equal(r.statusRecord?.error, "bad_hook_json");
      assert.equal(JSON.stringify(r.statusRecord).includes("{not json"), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("bad_hook_json records a short failure so stale lastSuccess is not healthy", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-hook-shape-health-"));
    const grokPath = join(home, ".grok", "hooks", GROK_HOOK_FILE);
    try {
      await mkdir(join(home, ".grok", "hooks"), { recursive: true });
      await mkdir(join(home, ".nmzp"), { recursive: true });
      await writeFile(
        grokPath,
        JSON.stringify({
          hooks: {
            PreToolUse: [
              {
                hooks: [
                  {
                    type: "command",
                    command: hookCommand("/usr/bin/node", "/opt/nmzp/nmzp.mjs", "grok", "linux"),
                  },
                ],
              },
            ],
          },
        }),
      );
      await writeFile(
        join(home, ".nmzp", "hook-status.json"),
        JSON.stringify({
          version: 1,
          updatedAt: 1_700_000_000_000,
          hooks: { grok: { ok: true, lastSuccessAt: 1_700_000_000_000, eventId: "old", tool: "read_file" } },
        }),
      );
      const before = assembleProbeReport({ home, procs: [], listOk: true, now: 1_700_000_000_000 });
      assert.equal(before.capabilities.find((c) => c.id === "hook_grok")?.active, true);

      const r = await runHook({
        argv: ["--agent", "grok"],
        stdin: "{not json",
        home,
        coreDir,
      });
      assert.equal(r.exitCode, 2);
      assert.equal(r.statusRecord?.ok, false);
      assert.equal(r.statusRecord?.error, "bad_hook_json");
      await settleHookAfterStdout({ home, result: r });
      const after = assembleProbeReport({ home, procs: [], listOk: true, now: 1_700_000_000_000 });
      const cap = after.capabilities.find((c) => c.id === "hook_grok");
      assert.equal(cap?.active, false);
      assert.equal(cap?.error, "bad_hook_json");
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("Grok-hosted Claude skip still has no statusRecord", async () => {
    const r = await runHook({
      argv: ["--agent", "claude"],
      stdin: "{not json",
      home: join(tmpdir(), "nmzp-hook-shape-skip"),
      coreDir,
      env: { GROK_HOOK_EVENT: "pre_tool_use", GROK_SESSION_ID: "sess-host" },
    });
    assert.equal(r.exitCode, 0);
    assert.equal(r.stdout, "");
    assert.equal(r.statusRecord, undefined);
  });
});

