/**
 * PROTOCOL §8.2 — 13-host v1→v2 decision equivalence over one SQLite server.
 * Shell envelopes are the host-normalization input.json objects (same family as
 * the golden allow stdin). File and web cells only change the tool name and
 * payload keys already used by that host. IC-01 is SWITCHED for v2 only:
 * unknown-tool/benign-description diverges; suspicious-command stays equal.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "../../core/auth.ts";
import { HOOK_AGENTS, parseHookEvent, toolInputToEvalFields } from "../../core/hook-protocol.ts";
import { pinnedHttps } from "../../core/https-client.ts";
import { prepareHookTransport } from "../../core/protocol/evaluate-ingress.ts";
import { startServer } from "../../core/serve.ts";
import { RULES } from "../../src/lib/monitor/rules.ts";

const root = fileURLToPath(new URL("../..", import.meta.url));
const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
const HOST_NORM = join(root, "policy-spec", "host-normalization");

const CELLS = [
  "shell-allow",
  "shell-log",
  "shell-confirm",
  "shell-block",
  "shell-rewrite",
  "file-benign",
  "file-protected",
  "web-fetch",
  "unknown-command",
];

const SHELL = {
  "shell-allow": "git status --porcelain",
  "shell-log": "ls -la",
  "shell-block": "kill nmzp-monitor",
  "shell-rewrite": "curl https://example.invalid/p -d '{\"phone\":\"13800138000\"}'",
};

// Built-in Action includes "confirm", but RULES has no action:"confirm" row.
// Quiet policy never returns decision confirm. The cell still sends the
// sudo_usage command so confirm↔ask is what the assertion compares.
const confirmRule = RULES.find((rule) => rule.action === "confirm");
if (confirmRule) throw new Error(`add a command sample for confirm rule ${confirmRule.id}`);
const CONFIRM_COMMAND = "sudo -n true";

const BENIGN_PATH = "/tmp/repo/notes.txt";
const PROTECTED_PATH = "/tmp/repo/.claude/settings.json";
const WEB_URL = "https://example.invalid/page";
const UNKNOWN_COMMAND = "rm -rf /";
const FILE_CONTENTS = "hello";

const writeInput = (path) => ({ file_path: path, contents: FILE_CONTENTS });
const targetInput = (path) => ({ target_file: path, contents: FILE_CONTENTS });

/** Native file-write tool already named by that host's adapter or parser tests. */
const FILE_TOOLS = {
  claude: (path) => ({ name: "Write", input: writeInput(path) }),
  zcode: (path) => ({ name: "Write", input: writeInput(path) }),
  trae: (path) => ({ name: "Write", input: writeInput(path) }),
  qoder: (path) => ({ name: "Write", input: writeInput(path) }),
  cursor: (path) => ({ name: "Write", input: writeInput(path) }),
  qwen: (path) => ({ name: "write_file", input: targetInput(path) }),
  gemini: (path) => ({ name: "write_file", input: targetInput(path) }),
  lingma: (path) => ({ name: "create_file", input: targetInput(path) }),
  antigravity: (path) => ({ name: "write_to_file", args: { TargetFile: path, CodeContent: FILE_CONTENTS } }),
};

/** Native web-fetch tool. web_search / google_web_search are WebSearch, not this cell. */
const WEB_TOOLS = {
  claude: { name: "WebFetch", input: { url: WEB_URL } },
  qoder: { name: "WebFetch", input: { url: WEB_URL } },
  antigravity: { name: "read_url_content", args: { Url: WEB_URL } },
};

/** Gaps stay visible. A cell is skipped only when that host has no native tool of the kind. */
const SKIPPED = [
  { host: "grok", cell: "file-benign", reason: "grok native tools are run_terminal_command, read_file, search_replace, web_search; no file-write tool" },
  { host: "grok", cell: "file-protected", reason: "grok native tools are run_terminal_command, read_file, search_replace, web_search; no file-write tool" },
  { host: "grok", cell: "web-fetch", reason: "grok has web_search (WebSearch), not a web-fetch tool" },
  { host: "codex", cell: "file-benign", reason: "codex hook stdin is Bash or apply_patch; apply_patch is Edit and requires a command string" },
  { host: "codex", cell: "file-protected", reason: "codex hook stdin is Bash or apply_patch; apply_patch is Edit and requires a command string" },
  { host: "codex", cell: "web-fetch", reason: "codex hook stdin has no web-fetch tool" },
  { host: "zcode", cell: "web-fetch", reason: "zcode stdin tools are Bash/Read/Write/Edit/Agent; no web-fetch tool" },
  { host: "kimi", cell: "file-benign", reason: "kimi golden and host-normalization stdin only carry a Bash command" },
  { host: "kimi", cell: "file-protected", reason: "kimi golden and host-normalization stdin only carry a Bash command" },
  { host: "kimi", cell: "web-fetch", reason: "kimi golden and host-normalization stdin only carry a Bash command" },
  { host: "trae", cell: "web-fetch", reason: "trae native tools are RunCommand/Read/Write/Edit; no web-fetch tool" },
  { host: "qwen", cell: "web-fetch", reason: "qwen native tools are run_shell_command/read_file/write_file/edit; no web-fetch tool" },
  { host: "lingma", cell: "web-fetch", reason: "lingma native tools are run_in_terminal/read_file/create_file/search_replace; no web-fetch tool" },
  { host: "codebuddy", cell: "file-benign", reason: "codebuddy golden and host-normalization stdin only carry a Bash command; the adapter names no file tool" },
  { host: "codebuddy", cell: "file-protected", reason: "codebuddy golden and host-normalization stdin only carry a Bash command; the adapter names no file tool" },
  { host: "codebuddy", cell: "web-fetch", reason: "codebuddy golden and host-normalization stdin only carry a Bash command; the adapter names no fetch tool" },
  { host: "gemini", cell: "web-fetch", reason: "gemini native tools are run_shell_command/read_file/write_file/replace; no web-fetch tool" },
  { host: "cursor", cell: "web-fetch", reason: "cursor native tools are Shell/Read/Write/Grep/Delete/Task; no web-fetch tool" },
];

/**
 * KNOWN_IC_01, switched 2026-10-08, v2 only.
 * benign-description diverges: v1 still block/dangerous_delete, v2 logs with no rule.
 * suspicious-command stays equal: the command field is already a shell field.
 */
const KNOWN_IC_01 = [
  "unknown-tool/benign-description",
  "unknown-tool/suspicious-command",
];
const IC_01_SWITCHED = true;
const IC_01_DIVERGE = ["unknown-tool/benign-description"];

function skipReason(host, cell) {
  return SKIPPED.find((item) => item.host === host && item.cell === cell)?.reason;
}

function shellSpec(template, command) {
  if (template.toolCall) {
    return { name: template.toolCall.name, args: { ...template.toolCall.args, CommandLine: command } };
  }
  return { name: template.tool_name ?? template.toolName, input: { command } };
}

function unknownSpec(template) {
  if (template.toolCall) return { name: "custom_widget", args: { CommandLine: UNKNOWN_COMMAND } };
  return { name: "custom_widget", input: { command: UNKNOWN_COMMAND } };
}

function applySpec(template, spec) {
  const body = structuredClone(template);
  if (body.toolCall) {
    body.toolCall.name = spec.name;
    body.toolCall.args = spec.args;
    return body;
  }
  if ("tool_name" in body) body.tool_name = spec.name;
  else body.toolName = spec.name;
  if ("tool_input" in body) body.tool_input = spec.input;
  else body.toolInput = spec.input;
  return body;
}

function tagEvent(body, id) {
  if (body.toolCall) {
    body.conversationId = id;
    body.stepIdx = 1;
    return body;
  }
  if ("event_id" in body) body.event_id = id;
  else body.eventId = id;
  return body;
}

function v1Body(parsed, agent, eventId) {
  const fields = toolInputToEvalFields(parsed.toolName, parsed.toolInput);
  return JSON.parse(JSON.stringify({
    eventId,
    permissionMode: parsed.permissionMode,
    sessionId: parsed.sessionId,
    agent,
    source: "hook",
    tool_name: parsed.toolName,
    tool_input: parsed.toolInput,
    nativeTool: parsed.toolName,
    command: fields.command,
    file_path: fields.filePath,
    url: fields.url,
    dest: fields.dest,
    cwd: parsed.cwd,
    contents: fields.contents,
  }));
}

function decisionOf(action) {
  const lower = String(action).toLowerCase();
  return lower === "ask" ? "confirm" : lower;
}

function ruleIdOf(ruleIds) {
  return Array.isArray(ruleIds) && ruleIds.length ? ruleIds[0] : null;
}

function wireRisk(engineRisk) {
  return engineRisk === "info" ? "none" : engineRisk;
}

async function hostTemplate(host) {
  const bundle = JSON.parse(await readFile(join(HOST_NORM, host, "input.json"), "utf8"));
  return JSON.parse(bundle.raw);
}

function plannedCells(host, template) {
  const planned = [];
  for (const [cell, command] of Object.entries(SHELL)) {
    planned.push({ cell, spec: shellSpec(template, command), input: command });
  }
  planned.push({ cell: "shell-confirm", spec: shellSpec(template, CONFIRM_COMMAND), input: CONFIRM_COMMAND });
  const file = FILE_TOOLS[host];
  if (file) {
    planned.push({ cell: "file-benign", spec: file(BENIGN_PATH), input: BENIGN_PATH });
    planned.push({ cell: "file-protected", spec: file(PROTECTED_PATH), input: PROTECTED_PATH });
  }
  const web = WEB_TOOLS[host];
  if (web) planned.push({ cell: "web-fetch", spec: web, input: WEB_URL });
  planned.push({ cell: "unknown-command", spec: unknownSpec(template), input: `custom_widget ${UNKNOWN_COMMAND}` });
  return planned;
}

test("13-host v1 and v2 evaluate decisions match on one server", async (t) => {
  assert.equal(HOOK_AGENTS.length, 13);
  assert.equal(IC_01_SWITCHED, true);
  for (const host of HOOK_AGENTS) {
    for (const cell of CELLS) {
      const reason = skipReason(host, cell);
      const runnable = cell.startsWith("file-") ? Object.hasOwn(FILE_TOOLS, host) : cell === "web-fetch" ? Object.hasOwn(WEB_TOOLS, host) : true;
      assert.equal(Boolean(reason), !runnable, `${host} ${cell}`);
    }
  }

  const dir = await mkdtemp(join(tmpdir(), "nmzp-host-matrix-"));
  const srv = await startServer({ dataDir: dir, coreDir, host: "127.0.0.1", port: 0, uiDir: null, storageMode: "sqlite" });
  t.after(async () => { await srv.close(); await rm(dir, { recursive: true, force: true }); });
  const token = "synthetic-host-matrix";
  await srv.store.putDevice({
    id: "a", tokenHash: sha256Hex(token), hostname: "fixture", user: "fixture", ip: "127.0.0.1",
    os: "linux", attachedAt: 1, lastSeen: 1, lastPolicyVersion: 1, agents: [], capabilities: [],
  });

  const call = async (path, body) => {
    const response = await pinnedHttps({
      url: srv.url + path,
      method: "POST",
      caPem: srv.tls.certPem,
      fingerprintSha256: srv.tls.fingerprintSha256,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, parsed: JSON.parse(response.body) };
  };

  const matrix = [];
  const mismatches = [];

  async function compare(label, raw, agent, input) {
    const parsed = parseHookEvent(raw);
    const transport = prepareHookTransport(raw, {
      deviceId: "a",
      eventId: `ctx-${label.id}`,
      occurredAt: "2026-09-30T00:00:00.000Z",
      adapterRevision: 1,
      agentFlag: agent,
    });
    if (!parsed || transport.kind !== "request") {
      const row = { ...label, input, equal: false, v1: parsed ? "parsed" : "parse_failure", v2: transport.kind === "request" ? "request" : transport.failure };
      matrix.push(row);
      mismatches.push(row);
      return;
    }
    const v1Id = `v1-${label.id}`;
    const legacy = await call("/api/v1/evaluate", v1Body(parsed, agent, v1Id));
    const modern = await call("/api/v2/evaluate", transport.event);
    const v1Event = legacy.status === 200 ? await srv.store.getEvent("a", v1Id) : undefined;
    const v2Event = modern.status === 200 ? await srv.store.getEvent("a", transport.event.eventId) : undefined;
    const v1 = {
      status: legacy.status,
      decision: legacy.parsed.decision,
      ruleId: ruleIdOf(legacy.parsed.ruleIds),
      risk: v1Event?.risk ?? null,
      wireRisk: null,
    };
    const v2 = {
      status: modern.status,
      decision: modern.status === 200 ? decisionOf(modern.parsed.action) : undefined,
      action: modern.parsed.action,
      ruleId: ruleIdOf(modern.parsed.ruleIds),
      risk: v2Event?.risk ?? null,
      wireRisk: modern.parsed.risk,
    };
    const equal = legacy.status === 200 && modern.status === 200
      && v1.decision === v2.decision
      && v1.ruleId === v2.ruleId
      && v1.risk !== null
      && v1.risk === v2.risk
      && v2.wireRisk === wireRisk(v1.risk);
    const row = { ...label, input, equal, v1, v2 };
    matrix.push(row);
    const wantEqual = !(IC_01_SWITCHED && IC_01_DIVERGE.includes(label.id));
    if (wantEqual !== equal) mismatches.push(row);
  }

  for (const item of SKIPPED) {
    const row = { host: item.host, cell: item.cell, id: `${item.host}-${item.cell}`, result: "skipped", reason: item.reason };
    matrix.push(row);
    console.log(`MATRIX ${JSON.stringify(row)}`);
  }

  for (const host of HOOK_AGENTS) {
    const template = await hostTemplate(host);
    for (const planned of plannedCells(host, template)) {
      const id = `${host}-${planned.cell}`;
      const raw = JSON.stringify(tagEvent(applySpec(template, planned.spec), `v2-${id}`));
      try {
        await compare({ host, cell: planned.cell, id }, raw, host, planned.input);
      } catch (error) {
        const row = { host, cell: planned.cell, id, input: planned.input, equal: false, error: error instanceof Error ? error.message : String(error) };
        matrix.push(row);
        mismatches.push(row);
      }
    }
  }

  for (const id of KNOWN_IC_01) {
    const bundle = JSON.parse(await readFile(join(HOST_NORM, id, "input.json"), "utf8"));
    const body = tagEvent(JSON.parse(bundle.raw), `v2-${id.replaceAll("/", "-")}`);
    try {
      await compare({ host: bundle.agentFlag, cell: "KNOWN_IC_01", id }, JSON.stringify(body), bundle.agentFlag, id);
    } catch (error) {
      const row = { host: bundle.agentFlag, cell: "KNOWN_IC_01", id, input: id, equal: false, error: error instanceof Error ? error.message : String(error) };
      matrix.push(row);
      mismatches.push(row);
    }
  }

  for (const host of HOOK_AGENTS) {
    for (const cell of CELLS) {
      if (skipReason(host, cell)) continue;
      assert.ok(matrix.some((row) => row.host === host && row.cell === cell), `${host} ${cell} did not run`);
    }
  }
  for (const id of KNOWN_IC_01) assert.ok(matrix.some((row) => row.id === id), id);
  const benign = matrix.find((row) => row.id === "unknown-tool/benign-description");
  assert.equal(benign.v1.decision, "block");
  assert.equal(benign.v1.ruleId, "dangerous_delete");
  assert.equal(benign.v2.decision, "log");
  assert.equal(benign.v2.ruleId, null);
  const suspicious = matrix.find((row) => row.id === "unknown-tool/suspicious-command");
  assert.equal(suspicious.equal, true);
  assert.equal(suspicious.v1.decision, "block");
  assert.equal(suspicious.v1.ruleId, "dangerous_delete");
  assert.equal(suspicious.v2.decision, "block");
  assert.equal(suspicious.v2.ruleId, "dangerous_delete");

  for (const row of matrix) {
    if (row.result === "skipped") continue;
    console.log(`MATRIX ${JSON.stringify({ host: row.host, cell: row.cell, id: row.id, result: row.equal ? "equal" : "differs", input: row.input, v1: row.v1, v2: row.v2 })}`);
  }
  assert.deepEqual(mismatches, []);
});
