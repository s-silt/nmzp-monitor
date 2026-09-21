import {permissionMode} from "./egress-schema.ts";
import { newEventId } from "./auth.ts";

export const HOOK_AGENTS = [
  "grok",
  "claude",
  "codex",
  "zcode",
  "antigravity",
  "kimi",
  "trae",
  "qwen",
  "qoder",
  "lingma",
  "codebuddy",
  "gemini",
  "cursor",
] as const;
export type HookAgent = (typeof HOOK_AGENTS)[number];

export interface ParsedHook {
  permissionMode?:string;
  agentHint: HookAgent | undefined;
  eventName: string;
  toolName: string;
  toolInput: Record<string, unknown>;
  sessionId?: string;
  cwd?: string;
  eventId: string;
  rawKeys: string[];
  hostArgMap?: Record<string, string>;
}

export const ALIAS_CONFLICT = Symbol("alias_conflict");

const CONTENT_KEYS = [
  "contents",
  "content",
  "new_string",
  "old_string",
  "newString",
  "oldString",
  "body",
  "patch",
  "new_source",
  "replacement",
  "file_text",
  "prompt",
] as const;

/** Top-level operational path aliases, including Grok `target_file`. Nested `path` is not an op target. */
const FILE_PATH_KEYS = ["file_path", "filePath", "path", "target_file"] as const;

/** Top-level operational fields. Nested payload keys with the same names are still scanned. */
const OP_KEYS = new Set([
  "command",
  "cmd",
  ...FILE_PATH_KEYS,
  "cwd",
  "working_directory",
  "workingDirectory",
  "directory",
  "url",
  "dest",
  "host",
  "hostname",
  "tool",
  "tool_name",
  "toolName",
]);

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function isTrueFlag(v: unknown): boolean {
  return v === true || v === "true";
}

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(",")}}`;
}

export function pickDefinedSame(values: Array<string | undefined>): string | undefined | typeof ALIAS_CONFLICT {
  const defined = values.filter((v): v is string => typeof v === "string" && v.length > 0);
  if (!defined.length) return undefined;
  const first = defined[0]!;
  for (let i = 1; i < defined.length; i += 1) {
    if (defined[i] !== first) return ALIAS_CONFLICT;
  }
  return first;
}

export function objectsConflict(values: Array<unknown>): boolean {
  const defined = values.filter(isPlain);
  if (defined.length <= 1) return false;
  const first = stableJson(defined[0]);
  return defined.some((v) => stableJson(v) !== first);
}

export function toolInputHasAliasConflict(obj: Record<string, unknown>): boolean {
  const command = pickDefinedSame([str(obj.command), str(obj.cmd)]);
  const filePath = pickDefinedSame(FILE_PATH_KEYS.map((k) => str(obj[k])));
  const dest = pickDefinedSame([str(obj.dest), str(obj.host), str(obj.hostname)]);
  const cwd = pickDefinedSame([str(obj.cwd), str(obj.working_directory), str(obj.workingDirectory)]);
  return command === ALIAS_CONFLICT || filePath === ALIAS_CONFLICT || dest === ALIAS_CONFLICT || cwd === ALIAS_CONFLICT;
}

function collectContentParts(obj: Record<string, unknown>): string[] {
  const parts: string[] = [];
  const push = (v: string | undefined) => {
    if (v && !parts.includes(v)) parts.push(v);
  };
  for (const key of CONTENT_KEYS) push(str(obj[key]));
  const edits = obj.edits;
  if (Array.isArray(edits)) {
    for (const row of edits) {
      if (!isPlain(row)) continue;
      for (const key of CONTENT_KEYS) push(str(row[key]));
    }
  }
  const seen = new WeakSet<object>();
  for (const [k, v] of Object.entries(obj)) {
    if (OP_KEYS.has(k)) continue;
    if (k === "edits") continue;
    if ((CONTENT_KEYS as readonly string[]).includes(k) && typeof v === "string") continue;
    walkScanLeaves(v, push, seen);
  }
  return parts;
}

function walkScanLeaves(val: unknown, push: (v: string | undefined) => void, seen: WeakSet<object>): void {
  if (typeof val === "string") {
    push(str(val));
    return;
  }
  if (!val || typeof val !== "object") return;
  if (seen.has(val)) return;
  seen.add(val);
  if (Array.isArray(val)) {
    for (const item of val) walkScanLeaves(item, push, seen);
    return;
  }
  if (!isPlain(val)) return;
  for (const v of Object.values(val)) walkScanLeaves(v, push, seen);
}

/**
 * Official Grok + Claude PreToolUse envelopes only.
 * Grok: hookEventName/toolName/toolInput (Claude aliases also present).
 * Claude: hook_event_name/tool_name/tool_input.
 * Conflicting camel/snake session/tool/toolInput/toolUseId values are rejected.
 * cwd is the execution dir; workspaceRoot is repo-root fallback only (not aliases).
 * toolInputTruncated=true is rejected so a truncated body is not audited as complete.
 * Does not copy timestamp or agent from the envelope.
 */
export function parseHookEvent(raw: string): ParsedHook | null {
  if (typeof raw !== "string") return null;
  const t = raw.replace(/^\uFEFF+/, "").trim();
  if (!t || t[0] !== "{") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(t);
  } catch {
    return null;
  }
  if (!isPlain(parsed)) return null;

  if (isTrueFlag(parsed.toolInputTruncated) || isTrueFlag(parsed.tool_input_truncated)) return null;

  if (isPlain(parsed.toolCall)) {
    const toolCall = parsed.toolCall;
    const toolName = str(toolCall.name);
    if (!toolName) return null;
    const args = isPlain(toolCall.args) ? toolCall.args : {};
    const toolInput: Record<string, unknown> = { ...args };
    const hostArgMap: Record<string, string> = {};
    const pairs: Array<[string, string]> = [
      ["CommandLine", "command"],
      ["Cwd", "cwd"],
      ["TargetFile", "file_path"],
      ["AbsolutePath", "file_path"],
      ["Url", "url"],
      ["CodeContent", "contents"],
      ["ReplacementContent", "new_string"],
    ];
    for (const [from, to] of pairs) {
      if (!Object.prototype.hasOwnProperty.call(args, from)) continue;
      if (hostArgMap[to]) continue;
      hostArgMap[to] = from;
      toolInput[to] = args[from];
      if (from !== to) delete toolInput[from];
    }
    if (toolInputHasAliasConflict(toolInput)) return null;
    const conversationId = str(parsed.conversationId);
    const workspacePaths = Array.isArray(parsed.workspacePaths) ? parsed.workspacePaths : [];
    const ws0 = workspacePaths[0];
    const cwd = str(args.Cwd) ?? (typeof ws0 === "string" ? ws0 : undefined);
    const eventId =
      conversationId && typeof parsed.stepIdx === "number" ? `${conversationId}:${parsed.stepIdx}` : newEventId();
    return {
      agentHint: "antigravity",
      eventName: str(parsed.hookEventName) ?? "PreToolUse",
      toolName,
      toolInput,
      sessionId: conversationId,
      cwd,
      eventId,
      rawKeys: Object.keys(parsed),
      permissionMode: permissionMode(parsed.permission_mode),
      hostArgMap,
    };
  }

  const toolName = pickDefinedSame([str(parsed.tool_name), str(parsed.toolName), str(parsed.tool)]);
  if (toolName === ALIAS_CONFLICT || !toolName) return null;

  const sessionId = pickDefinedSame([str(parsed.session_id), str(parsed.sessionId), str(parsed.conversation_id)]);
  if (sessionId === ALIAS_CONFLICT) return null;

  const roots = parsed.workspace_roots;
  const ws0 = Array.isArray(roots) && typeof roots[0] === "string" ? roots[0] : undefined;
  const cwd = str(parsed.cwd) ?? str(parsed.workspaceRoot) ?? str(ws0);

  const bags = [parsed.tool_input, parsed.toolInput, parsed.input];
  if (objectsConflict(bags)) return null;
  const toolInputRaw = bags.find(isPlain);
  const toolInput = toolInputRaw ?? {};
  if (toolInputHasAliasConflict(toolInput)) return null;

  const nestedTool = str(toolInput.tool);
  if (nestedTool && nestedTool !== toolName) return null;

  const eventIdAlias = pickDefinedSame([str(parsed.eventId), str(parsed.event_id)]);
  if (eventIdAlias === ALIAS_CONFLICT) return null;
  const toolUseId = pickDefinedSame([str(parsed.toolUseId), str(parsed.tool_use_id), str(parsed.tool_call_id)]);
  if (toolUseId === ALIAS_CONFLICT) return null;

  const eventName = str(parsed.hook_event_name) ?? str(parsed.hookEventName) ?? str(parsed.event) ?? "PreToolUse";
  let agentHint: ParsedHook["agentHint"];
  if (str(parsed.toolName) || str(parsed.hookEventName)) agentHint = "grok";
  else if (str(parsed.tool_name) || str(parsed.hook_event_name)) agentHint = "claude";
  return {
    agentHint,
    eventName,
    toolName,
    toolInput,
    sessionId,
    cwd,
    eventId: eventIdAlias ?? toolUseId ?? newEventId(),
    rawKeys: Object.keys(parsed),
    permissionMode:permissionMode(parsed.permission_mode),
  };
}

export function detectHookAgent(flag: string | undefined, parsed: ParsedHook): HookAgent | "unknown" {
  const f = (flag ?? "").toLowerCase();
  if ((HOOK_AGENTS as readonly string[]).includes(f)) return f as HookAgent;
  if (parsed.toolName === "RunCommand") return "trae";
  if (parsed.toolName === "Shell" || parsed.toolName === "Delete") return "cursor";
  if (parsed.agentHint === "grok" || parsed.agentHint === "claude" || parsed.agentHint === "antigravity") {
    return parsed.agentHint;
  }
  if (/^run_terminal_command$|^search_replace$|^read_file$|^web_search$/.test(parsed.toolName)) return "grok";
  if (/^(Bash|Read|Write|Edit|MultiEdit|Glob|Grep|WebFetch|WebSearch|Task)$/.test(parsed.toolName)) return "claude";
  if (
    /^(run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|list_dir|find_by_name|grep_search|read_url_content)$/.test(
      parsed.toolName,
    )
  ) {
    return "antigravity";
  }
  return "unknown";
}

export interface HookDecision {
  decision: "allow" | "deny";
  reason: string;
  updatedInput?: Record<string, unknown>;
}

/** Map NMZP decision onto official stdout JSON + exit code. Command is never executed. */
export function formatHookResponse(
  agent: HookAgent | "unknown",
  d: HookDecision,
  host?: { argMap?: Record<string, string> },
): { stdout: string; exitCode: number; stderr?: string } {
  const deny = d.decision === "deny";
  const reason = d.reason;
  const hookEventName = "PreToolUse";
  if (agent === "zcode") {
    if (deny) {
      return {
        stdout:
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName,
              permissionDecision: "deny",
              permissionDecisionReason: d.reason,
            },
          }) + "\n",
        exitCode: 0,
      };
    }
    if (d.updatedInput) {
      return {
        stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, updatedInput: d.updatedInput } }) + "\n",
        exitCode: 0,
      };
    }
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "antigravity") {
    if (deny) return { stdout: JSON.stringify({ decision: "deny", reason: d.reason }) + "\n", exitCode: 0 };
    if (d.updatedInput) {
      const argMap = host?.argMap ?? {};
      const overwrite: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(d.updatedInput)) {
        const hostKey = argMap[k];
        if (!hostKey) {
          return { stdout: JSON.stringify({ decision: "deny", reason: "rewrite_unsupported_host" }) + "\n", exitCode: 0 };
        }
        overwrite[hostKey] = v;
      }
      return { stdout: JSON.stringify({ decision: "ask", reason: "nmzp_rewrite", overwrite }) + "\n", exitCode: 0 };
    }
    return { stdout: "{}\n", exitCode: 0 };
  }
  if (agent === "codex") {
    if (deny) return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "deny", permissionDecisionReason: d.reason } }) + "\n", exitCode: 0 };
    if (d.updatedInput) return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "allow", updatedInput: d.updatedInput } }) + "\n", exitCode: 0 };
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "qwen" || agent === "qoder" || agent === "lingma" || agent === "trae") {
    if (deny) {
      return {
        stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "deny", permissionDecisionReason: reason } }) + "\n",
        exitCode: 2,
        stderr: reason + "\n",
      };
    }
    if (d.updatedInput) {
      return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, updatedInput: d.updatedInput } }) + "\n", exitCode: 0 };
    }
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "codebuddy") {
    if (deny) {
      return {
        stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "deny", permissionDecisionReason: reason } }) + "\n",
        exitCode: 2,
        stderr: reason + "\n",
      };
    }
    if (d.updatedInput) {
      return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, modifiedInput: d.updatedInput } }) + "\n", exitCode: 0 };
    }
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "kimi") {
    if (deny || d.updatedInput) {
      const r = d.updatedInput ? "rewrite_unsupported_host" : reason;
      return {
        stdout: JSON.stringify({ hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: r } }) + "\n",
        exitCode: 2,
        stderr: r + "\n",
      };
    }
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "gemini") {
    if (deny) return { stdout: JSON.stringify({ decision: "deny", reason }) + "\n", exitCode: 2, stderr: reason + "\n" };
    if (d.updatedInput) {
      return { stdout: JSON.stringify({ hookSpecificOutput: { tool_input: d.updatedInput } }) + "\n", exitCode: 0 };
    }
    return { stdout: "", exitCode: 0 };
  }
  if (agent === "cursor") {
    if (deny) {
      return {
        stdout: JSON.stringify({ permission: "deny", user_message: reason, agent_message: reason }) + "\n",
        exitCode: 2,
        stderr: reason + "\n",
      };
    }
    if (d.updatedInput) {
      return {
        stdout: JSON.stringify({ permission: "ask", user_message: "NMZP rewrote parameters", updated_input: d.updatedInput }) + "\n",
        exitCode: 0,
      };
    }
    return { stdout: JSON.stringify({ permission: "allow" }) + "\n", exitCode: 0 };
  }
  if (deny) {
    if (agent === "claude") {
      return {
        stdout:
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName,
              permissionDecision: "deny",
              permissionDecisionReason: reason,
            },
          }) + "\n",
        exitCode: 2,
        stderr: reason + "\n",
      };
    }
    return {
      stdout: JSON.stringify({ decision: "deny", reason }) + "\n",
      exitCode: 2,
      stderr: reason + "\n",
    };
  }
  if (d.updatedInput) {
    return {
      stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, updatedInput: d.updatedInput } }) + "\n",
      exitCode: 0,
    };
  }
  return { stdout: "", exitCode: 0 };
}

export function toolInputToEvalFields(toolName: string, toolInput: Record<string, unknown>) {
  const s = (k: string) => (typeof toolInput[k] === "string" ? (toolInput[k] as string) : undefined);
  const parts = collectContentParts(toolInput);
  return {
    nativeTool: toolName,
    command: str(s("command")) ?? str(s("cmd")),
    filePath: str(s("file_path")) ?? str(s("filePath")) ?? str(s("path")) ?? str(s("target_file")),
    url: str(s("url")),
    contents: parts.length ? parts.join("\n") : undefined,
    dest: str(s("dest")) ?? str(s("host")) ?? str(s("hostname")),
    cwd: str(s("working_directory")) ?? str(s("workingDirectory")) ?? str(s("cwd")),
  };
}
