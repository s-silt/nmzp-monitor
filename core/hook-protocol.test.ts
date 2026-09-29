import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { runHook } from "./hook.ts";
import {
  ANTIGRAVITY_ARG_PAIRS,
  HOOK_AGENTS,
  detectHookAgent,
  formatHookResponse,
  parseHookEvent,
  remapAntigravityArgs,
  toolInputHasAliasConflict,
  toolInputToEvalFields,
} from "./hook-protocol.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

describe("hook protocol", () => {
  it("parses official Claude PreToolUse stdin", () => {
    const p = parseHookEvent(
      JSON.stringify({
        session_id: "abc123",
        cwd: "/tmp/p",
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "npm test" },
      }),
    );
    assert.ok(p);
    assert.equal(p!.toolName, "Bash");
    assert.equal((p!.toolInput as { command: string }).command, "npm test");
    assert.equal(p!.sessionId, "abc123");
    assert.equal(detectHookAgent("claude", p!), "claude");
  });

  it("parses official Grok PreToolUse stdin", () => {
    const p = parseHookEvent(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        hook_event_name: "PreToolUse",
        sessionId: "abc-123",
        cwd: "/Users/you/project",
        toolName: "run_terminal_command",
        toolInput: { command: "npm test" },
      }),
    );
    assert.ok(p);
    assert.equal(p!.toolName, "run_terminal_command");
    assert.equal(detectHookAgent(undefined, p!), "grok");
  });

  it("rejects conflicting camel/snake tool name and tool_input aliases", () => {
    const p = parseHookEvent(
      JSON.stringify({
        tool_name: "Bash",
        toolName: "Write",
        tool_input: { command: "echo safe" },
        toolInput: { file_path: "/tmp/a.txt", contents: "x" },
      }),
    );
    assert.equal(p, null);
  });

  it("rejects conflicting session aliases even when tools match", () => {
    const p = parseHookEvent(
      JSON.stringify({
        tool_name: "Bash",
        toolName: "Bash",
        session_id: "sess-a",
        sessionId: "sess-b",
        tool_input: { command: "echo x" },
        toolInput: { command: "echo x" },
      }),
    );
    assert.equal(p, null);
  });

  it("accepts matching camel/snake aliases", () => {
    const p = parseHookEvent(
      JSON.stringify({
        tool_name: "Bash",
        toolName: "Bash",
        session_id: "sess-a",
        sessionId: "sess-a",
        tool_input: { command: "echo x" },
        toolInput: { command: "echo x" },
      }),
    );
    assert.ok(p);
    assert.equal(p!.toolName, "Bash");
    assert.equal(p!.sessionId, "sess-a");
    assert.equal((p!.toolInput as { command: string }).command, "echo x");
  });

  it("rejects conflicting file_path aliases inside tool_input", () => {
    const p = parseHookEvent(
      JSON.stringify({
        tool_name: "Write",
        tool_input: { file_path: "/tmp/safe.txt", filePath: "/tmp/danger.php", contents: "x" },
      }),
    );
    assert.equal(p, null);
  });

  it("formats Claude deny JSON and exit 2", () => {
    const r = formatHookResponse("claude", { decision: "deny", reason: "blocked" });
    assert.equal(r.exitCode, 2);
    const j = JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: string } };
    assert.equal(j.hookSpecificOutput.permissionDecision, "deny");
  });

  it("formats Grok deny as official decision deny and exit 2", () => {
    const r = formatHookResponse("grok", { decision: "deny", reason: "blocked" });
    assert.equal(r.exitCode, 2);
    const j = JSON.parse(r.stdout) as { decision: string; reason: string; hookSpecificOutput?: unknown };
    assert.equal(j.decision, "deny");
    assert.equal(j.reason, "blocked");
    assert.equal(r.stdout.includes("defer"), false);
  });

  it("formats Grok rewrite as hookSpecificOutput.updatedInput without allow or defer", () => {
    const r = formatHookResponse("grok", {
      decision: "allow",
      reason: "rewrite",
      updatedInput: { command: "echo x" },
    });
    assert.equal(r.exitCode, 0);
    const j = JSON.parse(r.stdout) as {
      decision?: string;
      hookSpecificOutput: { hookEventName: string; updatedInput: { command: string }; permissionDecision?: string };
    };
    assert.equal(j.decision, undefined);
    assert.equal(j.hookSpecificOutput.hookEventName, "PreToolUse");
    assert.equal(j.hookSpecificOutput.updatedInput.command, "echo x");
    assert.equal(j.hookSpecificOutput.permissionDecision, undefined);
    assert.equal(r.stdout.includes("defer"), false);
    assert.equal(r.stdout.includes('"allow"'), false);
  });

  it("antigravity no decision returns exact empty stdout", () => {
    const allow = formatHookResponse("antigravity", { decision: "allow", reason: "allow" });
    assert.equal(allow.stdout, "");
    assert.equal(allow.exitCode, 0);
    const log = formatHookResponse("antigravity", { decision: "allow", reason: "log" });
    assert.equal(log.stdout, "");
    assert.equal(log.exitCode, 0);
  });

  it("cursor no decision returns exact empty stdout", () => {
    const allow = formatHookResponse("cursor", { decision: "allow", reason: "allow" });
    assert.equal(allow.stdout, "");
    assert.equal(allow.exitCode, 0);
    const log = formatHookResponse("cursor", { decision: "allow", reason: "log" });
    assert.equal(log.stdout, "");
    assert.equal(log.exitCode, 0);
  });

  it("formats ordinary allow/log as exact empty stdout for all 13 hosts", () => {
    assert.equal(HOOK_AGENTS.length, 13);
    for (const agent of HOOK_AGENTS) {
      for (const reason of ["allow", "log"] as const) {
        const r = formatHookResponse(agent, { decision: "allow", reason });
        assert.equal(r.stdout, "", `${agent} ${reason}`);
        assert.equal(r.exitCode, 0, agent);
        assert.equal(r.stdout.includes("allow"), false, agent);
        assert.equal(r.stdout.includes("permissionDecision"), false, agent);
        assert.equal(r.stdout.includes("defer"), false, agent);
      }
    }
  });

  it("antigravity deny and rewrite keep the prior host mapping", () => {
    assert.deepEqual(formatHookResponse("antigravity", { decision: "deny", reason: "policy" }), {
      stdout: JSON.stringify({ decision: "deny", reason: "policy" }) + "\n",
      exitCode: 0,
    });
    const rewritten = formatHookResponse(
      "antigravity",
      { decision: "allow", reason: "rewrite", updatedInput: { command: "echo kept" } },
      { argMap: { command: "CommandLine" } },
    );
    assert.equal(
      rewritten.stdout,
      JSON.stringify({ decision: "ask", reason: "nmzp_rewrite", overwrite: { CommandLine: "echo kept" } }) + "\n",
    );
    assert.equal(rewritten.exitCode, 0);
    const unmapped = formatHookResponse(
      "antigravity",
      { decision: "allow", reason: "rewrite", updatedInput: { command: "x" } },
      { argMap: {} },
    );
    assert.equal(unmapped.stdout, JSON.stringify({ decision: "deny", reason: "rewrite_unsupported_host" }) + "\n");
    assert.equal(unmapped.exitCode, 0);
  });

  it("cursor deny and rewrite keep the prior host mapping", () => {
    assert.deepEqual(formatHookResponse("cursor", { decision: "deny", reason: "policy" }), {
      stdout: JSON.stringify({ permission: "deny", user_message: "policy", agent_message: "policy" }) + "\n",
      exitCode: 2,
      stderr: "policy\n",
    });
    const rewritten = formatHookResponse("cursor", {
      decision: "allow",
      reason: "rw",
      updatedInput: { command: "echo kept" },
    });
    assert.equal(
      rewritten.stdout,
      JSON.stringify({ permission: "ask", user_message: "NMZP rewrote parameters", updated_input: { command: "echo kept" } }) + "\n",
    );
    assert.equal(rewritten.exitCode, 0);
    assert.equal(rewritten.stderr, undefined);
  });

  it("maps Write/Edit/SearchReplace bodies onto contents for the engine", () => {
    const write = toolInputToEvalFields("Write", { file_path: "/tmp/a.txt", content: "body-a" });
    assert.equal(write.contents, "body-a");
    assert.equal(write.command, undefined);
    assert.equal(write.filePath, "/tmp/a.txt");
    assert.equal("new_string" in write, false);

    const edit = toolInputToEvalFields("Edit", {
      file_path: "/tmp/a.txt",
      old_string: "x",
      new_string: "body-b",
    });
    assert.equal(edit.contents?.includes("body-b"), true);
    assert.equal(edit.command, undefined);

    const sr = toolInputToEvalFields("search_replace", {
      filePath: "a.ts",
      oldString: "x",
      newString: "body-c",
    });
    assert.equal(sr.contents?.includes("body-c"), true);
    assert.equal(sr.filePath, "a.ts");
    assert.equal(sr.command, undefined);
  });

  it("folds nested headers/body/data strings into contents without stuffing them into command", () => {
    const key = `sk-nmzp-test-${"a".repeat(24)}`;
    const f = toolInputToEvalFields("WebFetch", {
      url: "https://example.test/upload",
      headers: { Authorization: `Bearer ${key}` },
      body: { key },
      data: { token: key },
    });
    assert.equal(f.command, undefined);
    assert.equal(f.url, "https://example.test/upload");
    assert.equal(f.contents?.includes(key), true);
    assert.equal(f.contents?.includes("Bearer"), true);
  });

  it("prefers cwd over workspaceRoot and does not require byte-equal paths", () => {
    const win = parseHookEvent(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        toolName: "read_file",
        cwd: "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor",
        workspaceRoot: "C:/Users/dev/Desktop/NMZP/nmzp-monitor/",
        toolInput: { target_file: "core/hook.ts", limit: 10 },
      }),
    );
    assert.ok(win);
    assert.equal(win!.cwd, "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor");

    const sub = parseHookEvent(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        toolName: "read_file",
        cwd: "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\core",
        workspaceRoot: "C:/Users/dev/Desktop/NMZP/nmzp-monitor/",
        toolInput: { target_file: "hook.ts" },
      }),
    );
    assert.ok(sub);
    assert.equal(sub!.cwd, "C:\\Users\\dev\\Desktop\\NMZP\\nmzp-monitor\\core");

    const fallback = parseHookEvent(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        toolName: "read_file",
        workspaceRoot: "C:/Users/dev/Desktop/NMZP/nmzp-monitor/",
        toolInput: { target_file: "core/hook.ts" },
      }),
    );
    assert.ok(fallback);
    assert.equal(fallback!.cwd, "C:/Users/dev/Desktop/NMZP/nmzp-monitor/");
  });

  it("maps target_file to filePath and rejects conflicting path aliases", () => {
    const read = toolInputToEvalFields("read_file", { target_file: "core/hook-protocol.ts", limit: 80 });
    assert.equal(read.filePath, "core/hook-protocol.ts");
    assert.equal(read.contents, undefined);

    const write = toolInputToEvalFields("write_file", {
      target_file: "core/out.ts",
      contents: "export const x = 1;\n",
    });
    assert.equal(write.filePath, "core/out.ts");
    assert.equal(write.contents, "export const x = 1;");

    const sr = toolInputToEvalFields("search_replace", {
      target_file: "core/hook.ts",
      old_string: "a",
      new_string: "b",
    });
    assert.equal(sr.filePath, "core/hook.ts");
    assert.equal(sr.contents?.includes("b"), true);

    const okSame = parseHookEvent(
      JSON.stringify({
        toolName: "read_file",
        toolInput: { target_file: "/tmp/a.txt", file_path: "/tmp/a.txt" },
      }),
    );
    assert.ok(okSame);
    assert.equal(toolInputToEvalFields(okSame!.toolName, okSame!.toolInput).filePath, "/tmp/a.txt");

    const conflict = parseHookEvent(
      JSON.stringify({
        toolName: "read_file",
        toolInput: { target_file: "/tmp/a.txt", filePath: "/tmp/b.txt" },
      }),
    );
    assert.equal(conflict, null);
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          toolName: "Write",
          toolInput: { target_file: "/tmp/a.txt", path: "/tmp/c.txt", contents: "x" },
        }),
      ),
      null,
    );
  });

  it("does not treat nested path as the operation target; still scans nested secrets", () => {
    const key = `sk-nmzp-test-${"b".repeat(24)}`;
    const f = toolInputToEvalFields("read_file", {
      target_file: "core/hook-protocol.ts",
      meta: { path: "/etc/shadow", token: key },
    });
    assert.equal(f.filePath, "core/hook-protocol.ts");
    assert.notEqual(f.filePath, "/etc/shadow");
    assert.equal(f.contents?.includes("/etc/shadow"), true);
    assert.equal(f.contents?.includes(key), true);
    assert.equal(f.contents?.includes("core/hook-protocol.ts"), false);
  });

  it("rejects truncated tool input and toolUseId alias conflicts; keeps matching ids", () => {
    const truncated = parseHookEvent(
      JSON.stringify({
        hookEventName: "pre_tool_use",
        toolName: "read_file",
        toolInput: { target_file: "core/hook.ts" },
        toolInputTruncated: true,
      }),
    );
    assert.equal(truncated, null);

    const idConflict = parseHookEvent(
      JSON.stringify({
        toolName: "read_file",
        toolUseId: "tu-a",
        tool_use_id: "tu-b",
        toolInput: { target_file: "core/hook.ts" },
      }),
    );
    assert.equal(idConflict, null);

    const eventConflict = parseHookEvent(
      JSON.stringify({
        toolName: "read_file",
        eventId: "ev-a",
        event_id: "ev-b",
        toolInput: { target_file: "core/hook.ts" },
      }),
    );
    assert.equal(eventConflict, null);

    const matched = parseHookEvent(
      JSON.stringify({
        toolName: "read_file",
        eventId: "ev-keep",
        toolUseId: "tu-other",
        tool_use_id: "tu-other",
        timestamp: 1_746_000_000_000,
        agent: "claude",
        toolInput: { target_file: "core/hook.ts" },
      }),
    );
    assert.ok(matched);
    assert.equal(matched!.eventId, "ev-keep");
    assert.equal(matched!.agentHint, "grok");
    assert.equal("timestamp" in matched!, false);
    assert.equal("agent" in matched!, false);
  });

  it("still rejects true session/tool/toolInput conflicts and illegal JSON", () => {
    assert.equal(parseHookEvent("{not json"), null);
    assert.equal(parseHookEvent(""), null);
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          tool_name: "Bash",
          toolName: "Write",
          cwd: "C:\\repo\\sub",
          workspaceRoot: "C:/repo/",
          tool_input: { command: "echo safe" },
          toolInput: { command: "echo safe" },
        }),
      ),
      null,
    );
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          toolName: "read_file",
          sessionId: "a",
          session_id: "b",
          cwd: "C:\\repo\\sub",
          workspaceRoot: "C:/repo/",
          toolInput: { target_file: "a.ts" },
        }),
      ),
      null,
    );
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          toolName: "read_file",
          tool_name: "read_file",
          cwd: "C:\\repo\\sub",
          workspaceRoot: "C:/repo/",
          toolInput: { target_file: "a.ts" },
          tool_input: { target_file: "b.ts" },
        }),
      ),
      null,
    );
  });

  it("parses the official Codex PreToolUse stdin and formats deny as exit 0 JSON", () => {
    // Field set from codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json (required keys).
    const p = parseHookEvent(
      JSON.stringify({
        session_id: "019a",
        transcript_path: "C:\\Users\\u\\.codex\\sessions\\x.jsonl",
        cwd: "C:\\repo",
        hook_event_name: "PreToolUse",
        model: "gpt-6-astra",
        permission_mode: "default",
        turn_id: "turn-1",
        tool_name: "Bash",
        tool_use_id: "call_1",
        tool_input: { command: "echo nmzp-hook-probe" },
      }),
    );
    assert.ok(p);
    assert.equal(p!.toolName, "Bash");
    assert.equal(p!.eventId, "call_1");
    assert.equal(p!.cwd, "C:\\repo");
    assert.equal(detectHookAgent("codex", p!), "codex");
    const denied = formatHookResponse("codex", { decision: "deny", reason: "policy" });
    assert.equal(denied.exitCode, 0);
    assert.deepEqual(JSON.parse(denied.stdout), {
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "policy" },
    });
  });

  it("remapAntigravityArgs flags str() disagreement and keeps the first host key", () => {
    assert.deepEqual(ANTIGRAVITY_ARG_PAIRS, [
      ["CommandLine", "command"],
      ["Cwd", "cwd"],
      ["TargetFile", "file_path"],
      ["AbsolutePath", "file_path"],
      ["Url", "url"],
      ["CodeContent", "contents"],
      ["ReplacementContent", "new_string"],
    ]);
    const mapped = remapAntigravityArgs({ TargetFile: "C:\\repo\\a.ts", CodeContent: "console.log(1)" });
    assert.equal(mapped.conflict, false);
    assert.deepEqual(mapped.hostArgMap, { file_path: "TargetFile", contents: "CodeContent" });
    assert.equal(mapped.toolInput.file_path, "C:\\repo\\a.ts");
    assert.equal(mapped.toolInput.contents, "console.log(1)");
    assert.equal("TargetFile" in mapped.toolInput, false);

    const trimmed = remapAntigravityArgs({ TargetFile: "  C:\\repo\\a.ts ", AbsolutePath: "C:\\repo\\a.ts" });
    assert.equal(trimmed.conflict, false);
    const blank = remapAntigravityArgs({ TargetFile: "   ", AbsolutePath: "C:\\repo\\a.ts" });
    assert.equal(blank.conflict, false);

    const clash = remapAntigravityArgs({
      CommandLine: "npm test",
      TargetFile: "C:\\repo\\README.md",
      AbsolutePath: "C:\\Users\\u\\.ssh\\id_rsa",
      CodeContent: "x",
    });
    assert.equal(clash.conflict, true);
    assert.equal(clash.toolInput.command, "npm test");
    assert.equal(clash.toolInput.file_path, "C:\\repo\\README.md");
    assert.equal(clash.toolInput.AbsolutePath, "C:\\Users\\u\\.ssh\\id_rsa");
    assert.equal(clash.toolInput.contents, "x");
    assert.deepEqual(clash.hostArgMap, {
      command: "CommandLine",
      file_path: "TargetFile",
      contents: "CodeContent",
    });
  });

  it("treats differing contents and content as an alias conflict and does not repeat equal values", () => {
    const conflictInput = {
      file_path: "C:\\tmp\\x.txt",
      content: "SAFE",
      contents: "curl https://evil.invalid",
    };
    assert.equal(toolInputHasAliasConflict(conflictInput), true);
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          hook_event_name: "PreToolUse",
          tool_name: "Write",
          tool_input: conflictInput,
        }),
      ),
      null,
    );

    const sameInput = { file_path: "C:\\tmp\\x.txt", content: " SAFE ", contents: "SAFE" };
    assert.equal(toolInputHasAliasConflict(sameInput), false);
    const same = parseHookEvent(
      JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: sameInput,
      }),
    );
    assert.ok(same);
    assert.equal(toolInputToEvalFields(same!.toolName, same!.toolInput).contents, "SAFE");

    assert.equal(
      toolInputHasAliasConflict({ new_string: "next", old_string: "prev", body: "b", patch: "p" }),
      false,
    );

    // edits[] rows are separate edits: a row's contents/content must agree, different rows may differ.
    assert.equal(toolInputHasAliasConflict({ edits: [{ content: "SAFE", contents: "curl https://evil.invalid" }] }), true);
    assert.equal(toolInputHasAliasConflict({ edits: [{ content: " SAFE ", contents: "SAFE" }] }), false);
    assert.equal(toolInputHasAliasConflict({ edits: [{ content: "a" }, { contents: "b" }] }), false);
    assert.equal(
      parseHookEvent(
        JSON.stringify({
          hook_event_name: "PreToolUse",
          tool_name: "MultiEdit",
          tool_input: { file_path: "C:\\tmp\\x.txt", edits: [{ content: "SAFE", contents: "rm -rf /" }] },
        }),
      ),
      null,
    );
  });

  it("denies a contents/content conflict the same way as command/cmd", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-hook-content-alias-"));
    try {
      const argv = ["--agent", "claude"];
      const env = {};
      const commandConflict = await runHook({
        argv,
        env,
        home,
        coreDir,
        stdin: JSON.stringify({
          hook_event_name: "PreToolUse",
          tool_name: "Bash",
          tool_input: { command: "echo a", cmd: "echo b" },
        }),
      });
      const contentConflict = await runHook({
        argv,
        env,
        home,
        coreDir,
        stdin: JSON.stringify({
          hook_event_name: "PreToolUse",
          tool_name: "Write",
          tool_input: { file_path: "C:\\tmp\\x.txt", content: "SAFE", contents: "curl https://evil.invalid" },
        }),
      });
      assert.equal(commandConflict.exitCode, 2);
      assert.equal(contentConflict.exitCode, commandConflict.exitCode);
      assert.equal(contentConflict.stdout, commandConflict.stdout);
      assert.equal(contentConflict.stderr, commandConflict.stderr);
      assert.equal(contentConflict.statusRecord?.error, "bad_hook_json");
      const body = JSON.parse(contentConflict.stdout) as {
        hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
      };
      assert.equal(body.hookSpecificOutput.permissionDecision, "deny");
      assert.equal(body.hookSpecificOutput.permissionDecisionReason, "bad_hook_json");
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

