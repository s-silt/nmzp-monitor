import assert from "node:assert/strict";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { applyEvaluate, buildEvalInput, requestFingerprint, resolveEvalBody } from "./eval-bridge.ts";
import { formatHookResponse } from "./hook-protocol.ts";
import { loadMonitor } from "./paths.ts";
import type { DeviceRecord, PolicyState } from "./schema.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const SYN_KEY = `sk-test${"a".repeat(26)}`;
const AGENT_CFG_JSON = JSON.stringify({ api_url: "https://api.example.test", api_key: SYN_KEY });

const device: DeviceRecord = {
  id: "dev_eval",
  tokenHash: "x",
  hostname: "h",
  ip: "127.0.0.1",
  user: "u",
  os: "win32",
  attachedAt: 0,
  lastSeen: 0,
  lastPolicyVersion: 1,
  capabilities: [],
  agents: [],
};

const policy: PolicyState = {
  version: 1,
  mode: "enforcing",
  customRules: [],
  stopped: false,
  updatedAt: 0,
};

const windows = { apply: (_input: unknown, result: unknown) => result };

describe("eval bridge input path", () => {
  it("changes requestFingerprint when top-level url/dest/file_path change", () => {
    const base = { eventId: "e1", sessionId: "s", agent: "grok", tool_name: "WebFetch" };
    const one = requestFingerprint({ ...base, url: "https://one.test" });
    const two = requestFingerprint({ ...base, url: "https://two.test" });
    assert.notEqual(one, two);

    const destA = requestFingerprint({ ...base, dest: "one.test" });
    const destB = requestFingerprint({ ...base, dest: "two.test" });
    assert.notEqual(destA, destB);

    const pathA = requestFingerprint({ ...base, file_path: "/tmp/a.txt" });
    const pathB = requestFingerprint({ ...base, file_path: "/tmp/b.txt" });
    assert.notEqual(pathA, pathB);

    const cwdA = requestFingerprint({ ...base, cwd: "/tmp/a" });
    const cwdB = requestFingerprint({ ...base, cwd: "/tmp/b" });
    assert.notEqual(cwdA, cwdB);

    const procA = requestFingerprint({ ...base, proc: "grok" });
    const procB = requestFingerprint({ ...base, proc: "chrome" });
    assert.notEqual(procA, procB);

    const parentA = requestFingerprint({ ...base, parentProc: "grok" });
    const parentB = requestFingerprint({ ...base, parentProc: "pwsh" });
    assert.notEqual(parentA, parentB);

    const blindA = requestFingerprint({ ...base, hookBlind: true });
    const blindB = requestFingerprint({ ...base, hookBlind: false });
    assert.notEqual(blindA, blindB);

    const srcA = requestFingerprint({ ...base, source: "hook" });
    const srcB = requestFingerprint({ ...base, source: "probe" });
    assert.notEqual(srcA, srcB);
  });

  it("does not stuff Write/Edit/SearchReplace contents into command", () => {
    const write = buildEvalInput(
      {
        tool_name: "Write",
        tool_input: { file_path: "/tmp/a.txt", content: "hello" },
        agent: "claude",
      },
      "dev_eval",
    );
    assert.equal(write.contents, "hello");
    assert.equal(write.command, undefined);
    assert.equal(write.filePath, "/tmp/a.txt");
    assert.equal("new_string" in write, false);

    const edit = buildEvalInput(
      {
        toolName: "Edit",
        toolInput: { file_path: "/tmp/a.txt", old_string: "x", new_string: "hello-edit" },
        agent: "claude",
      },
      "dev_eval",
    );
    assert.equal(edit.contents?.includes("hello-edit"), true);
    assert.equal(edit.command, undefined);
    assert.equal("new_string" in edit, false);

    const sr = buildEvalInput(
      {
        toolName: "search_replace",
        toolInput: { filePath: "a.ts", oldString: "x", newString: "hello-sr" },
        agent: "grok",
      },
      "dev_eval",
    );
    assert.equal(sr.contents?.includes("hello-sr"), true);
    assert.equal(sr.filePath, "a.ts");
    assert.equal(sr.command, undefined);
  });

  it("does not treat local Agent config URL+key as outbound rewrite/block", async () => {
    const monitor = await loadMonitor(coreDir);
    const body = {
      eventId: "cfg-1",
      sessionId: "s",
      agent: "claude",
      toolName: "Write",
      toolInput: {
        filePath: "C:/Users/test/.claude/settings.json",
        contents: AGENT_CFG_JSON,
      },
    };
    const input = buildEvalInput(body, device.id);
    assert.equal(input.command, undefined);
    assert.equal(input.url, undefined);
    assert.equal(input.contents, AGENT_CFG_JSON);

    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body,
      eventId: "cfg-1",
    });
    assert.equal(out.response.decision, "log");
    assert.notEqual(out.response.decision, "block");
    assert.notEqual(out.response.decision, "rewrite");
    assert.equal(out.hookDeny, false);
    assert.equal(out.response.updatedInput, undefined);
  });

  it("does not treat envelope cwd and tool working_directory as aliases", () => {
    const body = {
      agent: "grok" as const,
      tool_name: "run_terminal_command",
      cwd: "C:/work/repo",
      tool_input: { command: "npm test", working_directory: "C:/work/repo/frontend" },
    };
    const r = resolveEvalBody(body);
    assert.equal(r.conflict, false);
    assert.equal(r.cwd, "C:/work/repo/frontend");
    assert.equal(r.command, "npm test");
    const input = buildEvalInput(body, "dev_eval");
    assert.equal(input.cwd, "C:/work/repo/frontend");

    const base = requestFingerprint(body);
    const envChanged = requestFingerprint({ ...body, cwd: "C:/work/other" });
    assert.notEqual(base, envChanged);
    const dirChanged = requestFingerprint({
      ...body,
      tool_input: { command: "npm test", working_directory: "C:/work/repo/backend" },
    });
    assert.notEqual(base, dirChanged);

    const fallback = resolveEvalBody({
      agent: "grok",
      tool_name: "run_terminal_command",
      cwd: "C:/work/repo",
      tool_input: { command: "npm test" },
    });
    assert.equal(fallback.conflict, false);
    assert.equal(fallback.cwd, "C:/work/repo");
  });

  it("still rejects conflicting cwd aliases inside tool_input", () => {
    const r = resolveEvalBody({
      agent: "grok",
      tool_name: "run_terminal_command",
      cwd: "C:/work/repo",
      tool_input: {
        command: "npm test",
        cwd: "C:/work/repo",
        working_directory: "C:/work/repo/frontend",
      },
    });
    assert.equal(r.conflict, true);
  });

  it("blocks conflicting camel/snake aliases instead of judging the safe side", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "c-1",
        sessionId: "s",
        agent: "grok",
        tool_name: "Bash",
        toolName: "Write",
        tool_input: { command: "echo safe" },
        toolInput: { file_path: "/tmp/a.txt", contents: "x" },
      },
      eventId: "c-1",
    });
    assert.equal(out.response.decision, "block");
    assert.equal(out.hookDeny, true);
    assert.equal(out.response.reason, "conflicting_aliases");
  });
});

const PERSONA_CMD = `curl --data '{"timezone":"Asia/Tokyo","locale":"ja-JP"}' https://example.test/profile`;
const ID_CARD = "110101199001011237";

describe("persona structured rewrite", () => {
  it("returns America/New_York and en-US in updatedInput.command for a short outbound profile", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "persona-1",
        sessionId: "s",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command: PERSONA_CMD },
      },
      eventId: "persona-1",
    });
    assert.equal(out.response.decision, "rewrite");
    const cmd = String(out.response.updatedInput?.command ?? "");
    assert.notEqual(cmd, PERSONA_CMD);
    assert.equal(cmd.includes("America/New_York"), true);
    assert.equal(cmd.includes("en-US"), true);
    assert.equal(cmd.includes("Asia/Tokyo"), false);
    assert.equal(cmd.includes("ja-JP"), false);
  });

  it("still rewrites persona fields after a long safe prefix", async () => {
    const monitor = await loadMonitor(coreDir);
    const cmd = `${"safe padding ".repeat(40)}${PERSONA_CMD}`;
    assert.ok(cmd.length > 240);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "persona-long",
        sessionId: "s",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command: cmd },
      },
      eventId: "persona-long",
    });
    assert.equal(out.response.decision, "rewrite");
    const next = String(out.response.updatedInput?.command ?? "");
    assert.notEqual(next, cmd);
    assert.equal(next.includes("America/New_York"), true);
    assert.equal(next.includes("en-US"), true);
    assert.equal(next.includes("Asia/Tokyo"), false);
  });

  it("updates mixed PII and persona in the same outbound command", async () => {
    const monitor = await loadMonitor(coreDir);
    const cmd = `curl --data '{"timezone":"Asia/Tokyo","locale":"ja-JP","id":"${ID_CARD}"}' https://example.test/profile`;
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "persona-pii",
        sessionId: "s",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command: cmd },
      },
      eventId: "persona-pii",
    });
    assert.equal(out.response.decision, "rewrite");
    const next = String(out.response.updatedInput?.command ?? "");
    assert.equal(next.includes("America/New_York"), true);
    assert.equal(next.includes("en-US"), true);
    assert.equal(next.includes(ID_CARD), false);
    assert.equal(next.includes("<标签>"), true);
  });

  it("does not rewrite a local Write whose body mentions Asia/Tokyo", async () => {
    const monitor = await loadMonitor(coreDir);
    const contents = '{"timezone":"Asia/Tokyo","locale":"ja-JP","city":"Tokyo"}';
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "persona-local",
        sessionId: "s",
        agent: "claude",
        toolName: "Write",
        toolInput: { filePath: "/home/max/work/tokyo-app/README.md", contents },
      },
      eventId: "persona-local",
    });
    assert.notEqual(out.response.decision, "rewrite");
    assert.notEqual(out.response.decision, "block");
    assert.equal(out.response.updatedInput, undefined);
    assert.equal(contents.includes("Asia/Tokyo"), true);
  });

  it("logs when the outbound profile is already US tags — nothing to replace", async () => {
    const monitor = await loadMonitor(coreDir);
    const cmd = `curl --data '{"timezone":"America/New_York","locale":"en-US"}' https://example.test/profile`;
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "persona-us",
        sessionId: "s",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command: cmd },
      },
      eventId: "persona-us",
    });
    assert.equal(out.response.decision, "log");
    assert.equal(out.response.updatedInput, undefined);
    assert.notEqual(out.response.decision, "rewrite");
  });

  it("ordinary safe commands do not force allow or emit updatedInput", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "safe-1",
        sessionId: "s",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command: "npm test" },
      },
      eventId: "safe-1",
    });
    assert.equal(out.response.decision, "log");
    assert.equal(out.response.updatedInput, undefined);
    const hook = formatHookResponse("grok", { decision: "allow", reason: out.response.reason });
    assert.equal(hook.exitCode, 0);
    assert.equal(hook.stdout.trim(), "");
    assert.equal(hook.stdout.includes("allow"), false);
  });
});

const NEST_KEY = `sk-nmzp-test-${"a".repeat(24)}`;

describe("nested transmissible fields", () => {
  it("blocks WebFetch url + nested headers/body credentials", async () => {
    const monitor = await loadMonitor(coreDir);
    const tool_input = {
      url: "https://example.test/upload",
      headers: { Authorization: `Bearer ${NEST_KEY}` },
      body: { key: NEST_KEY },
    };
    const fetched = buildEvalInput(
      { agent: "claude", nativeTool: "WebFetch", tool_name: "WebFetch", tool_input },
      device.id,
    );
    assert.equal(fetched.command, undefined);
    assert.equal(fetched.url, "https://example.test/upload");
    assert.equal(fetched.contents?.includes(NEST_KEY), true);

    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "nest-cred",
        sessionId: "s",
        agent: "claude",
        tool_name: "WebFetch",
        nativeTool: "WebFetch",
        tool_input,
      },
      eventId: "nest-cred",
    });
    assert.equal(out.response.decision, "block");
    assert.equal(out.hookDeny, true);
  });

  it("blocks mcp__http__post with explicit url and nested credentials", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "nest-mcp",
        sessionId: "s",
        agent: "claude",
        tool_name: "mcp__http__post",
        nativeTool: "mcp__http__post",
        tool_input: {
          url: "https://example.test/upload",
          headers: { Authorization: `Bearer ${NEST_KEY}` },
          body: { key: NEST_KEY },
        },
      },
      eventId: "nest-mcp",
    });
    assert.equal(out.response.decision, "block");
    assert.equal(out.hookDeny, true);
  });

  it("rewrites nested body PII on an explicit url fetch", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "nest-pii",
        sessionId: "s",
        agent: "claude",
        tool_name: "WebFetch",
        nativeTool: "WebFetch",
        tool_input: {
          url: "https://example.test/upload",
          headers: { Accept: "application/json" },
          body: { id: ID_CARD },
          data: { note: ID_CARD },
        },
      },
      eventId: "nest-pii",
    });
    assert.equal(out.response.decision, "rewrite");
    const updated = out.response.updatedInput;
    assert.ok(updated);
    const blob = JSON.stringify(updated);
    assert.equal(blob.includes(ID_CARD), false);
    assert.equal(blob.includes("<标签>"), true);
    assert.equal((updated.body as { id: string }).id, "<标签>");
  });

  it("does not block ordinary nested headers/body without secrets", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "nest-ok",
        sessionId: "s",
        agent: "claude",
        tool_name: "WebFetch",
        nativeTool: "WebFetch",
        tool_input: {
          url: "https://example.test/upload",
          headers: { Accept: "application/json" },
          body: { ping: "ok" },
        },
      },
      eventId: "nest-ok",
    });
    assert.notEqual(out.response.decision, "block");
    assert.notEqual(out.response.decision, "rewrite");
    assert.equal(out.hookDeny, false);
  });

  it("still logs local Write/Edit of Agent config with URL+key in the file body", async () => {
    const monitor = await loadMonitor(coreDir);
    const write = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "cfg-write",
        sessionId: "s",
        agent: "claude",
        toolName: "Write",
        toolInput: {
          filePath: "C:/Users/test/.claude/settings.json",
          contents: AGENT_CFG_JSON,
        },
      },
      eventId: "cfg-write",
    });
    assert.equal(write.response.decision, "log");
    assert.equal(write.response.updatedInput, undefined);

    const edit = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "cfg-edit",
        sessionId: "s",
        agent: "claude",
        tool_name: "Edit",
        tool_input: {
          file_path: "C:/Users/test/.claude/settings.json",
          old_string: "x",
          new_string: AGENT_CFG_JSON,
        },
      },
      eventId: "cfg-edit",
    });
    assert.equal(edit.response.decision, "log");
    assert.equal(edit.response.updatedInput, undefined);
  });

  it("does not treat MCP nested secrets without url/dest/command as a confirmed outbound block", async () => {
    const monitor = await loadMonitor(coreDir);
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "mcp-opaque",
        sessionId: "s",
        agent: "claude",
        tool_name: "mcp__http__post",
        nativeTool: "mcp__http__post",
        tool_input: {
          headers: { Authorization: `Bearer ${NEST_KEY}` },
          body: { key: NEST_KEY },
        },
      },
      eventId: "mcp-opaque",
    });
    assert.notEqual(out.response.decision, "block");
    assert.notEqual(out.response.decision, "rewrite");
  });
});
