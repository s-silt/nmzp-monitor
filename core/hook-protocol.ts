import {permissionMode} from "./egress-schema.ts";
import { newEventId } from "./auth.ts";
import {
  ALIAS_CONFLICT,
  EVENT_ID_KEYS,
  SESSION_ID_KEYS,
  TOOL_INPUT_BAG_KEYS,
  TOOL_NAME_KEYS,
  TOOL_USE_ID_KEYS,
  aliasStr,
  isPlainObject,
  objectsConflict,
  pickDefinedSame,
  toolInputHasAliasConflict,
} from "./hook-alias-keys.ts";

export {
  ALIAS_CONFLICT,
  COMMAND_KEYS,
  CONTENT_ALIAS_KEYS,
  CONTENT_KEYS,
  collectContentLeaves,
  contentLeavesToV1,
  CWD_KEYS,
  DEST_KEYS,
  EVAL_BRIDGE_FILE_PATH_KEYS,
  EVAL_BRIDGE_SESSION_ID_KEYS,
  EVAL_BRIDGE_TOOL_NAME_KEYS,
  EVENT_ID_KEYS,
  FILE_PATH_KEYS,
  SESSION_ID_KEYS,
  TOOL_INPUT_BAG_KEYS,
  TOOL_NAME_KEYS,
  TOOL_USE_ID_KEYS,
  URL_KEYS,
  objectsConflict,
  pickDefinedSame,
  stableJson,
  toolInputHasAliasConflict,
  toolInputToEvalFields,
} from "./hook-alias-keys.ts";

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

export const ANTIGRAVITY_ARG_PAIRS: Array<[string, string]> = [
  ["CommandLine", "command"],
  ["Cwd", "cwd"],
  ["TargetFile", "file_path"],
  ["AbsolutePath", "file_path"],
  ["Url", "url"],
  ["CodeContent", "contents"],
  ["ReplacementContent", "new_string"],
];

function isPlain(v: unknown): v is Record<string, unknown> {
  return isPlainObject(v);
}

function str(v: unknown): string | undefined {
  return aliasStr(v);
}

function isTrueFlag(v: unknown): boolean {
  return v === true || v === "true";
}

/**
 * Antigravity `toolCall.args` → v1 toolInput.
 * `conflict` is the KIRO-Q2 rule: two host keys for one canonical differ after `str()`.
 * The canonical slot goes to the first host key whose value survives `str()`; an empty,
 * blank, null or non-string key claims it only when no other key does.
 * Non-claiming host keys are left in place; on conflict callers reject the event.
 */
export function remapAntigravityArgs(args: Record<string, unknown>): {
  toolInput: Record<string, unknown>;
  hostArgMap: Record<string, string>;
  conflict: boolean;
} {
  const toolInput: Record<string, unknown> = { ...args };
  const hostArgMap: Record<string, string> = {};
  const claim: Record<string, string> = {};
  for (const [from, to] of ANTIGRAVITY_ARG_PAIRS) {
    if (!Object.prototype.hasOwnProperty.call(args, from)) continue;
    const current = claim[to];
    if (current === undefined || (str(args[current]) === undefined && str(args[from]) !== undefined)) claim[to] = from;
  }
  let conflict = false;
  for (const [from, to] of ANTIGRAVITY_ARG_PAIRS) {
    if (!Object.prototype.hasOwnProperty.call(args, from)) continue;
    if (claim[to] !== from) {
      if (pickDefinedSame([str(args[claim[to]!]), str(args[from])]) === ALIAS_CONFLICT) conflict = true;
      continue;
    }
    hostArgMap[to] = from;
    toolInput[to] = args[from];
    if (from !== to) delete toolInput[from];
  }
  return { toolInput, hostArgMap, conflict };
}

export interface HookEnvelopeCwd {
  /** Exact legacy parser return value; Antigravity workspacePaths may be blank/untrimmed. */
  value: string;
  exact: string;
  provenance: string;
}

/** Actual envelope-format selection shared by the parser and canonical projection. */
export function selectHookEnvelopeCwd(raw: Record<string, unknown>): HookEnvelopeCwd | undefined {
  if (isPlain(raw.toolCall)) {
    const args = isPlain(raw.toolCall.args) ? raw.toolCall.args : {};
    const direct = str(args.Cwd);
    if (direct !== undefined) return { value: direct, exact: args.Cwd as string, provenance: "/toolCall/args/Cwd" };
    const first = Array.isArray(raw.workspacePaths) ? raw.workspacePaths[0] : undefined;
    if (typeof first === "string") return { value: first, exact: first, provenance: "/workspacePaths/0" };
    return;
  }
  const first = Array.isArray(raw.workspace_roots) ? raw.workspace_roots[0] : undefined;
  for (const candidate of [
    { exact: raw.cwd, provenance: "/cwd" },
    { exact: raw.workspaceRoot, provenance: "/workspaceRoot" },
    { exact: first, provenance: "/workspace_roots/0" },
  ]) {
    const value = str(candidate.exact);
    if (value !== undefined) return { value, exact: candidate.exact as string, provenance: candidate.provenance };
  }
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
    const remapped = remapAntigravityArgs(args);
    if (remapped.conflict || toolInputHasAliasConflict(remapped.toolInput)) return null;
    const { toolInput, hostArgMap } = remapped;
    const conversationId = str(parsed.conversationId);
    const cwd = selectHookEnvelopeCwd(parsed)?.value;
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

  const toolName = pickDefinedSame(TOOL_NAME_KEYS.map((key) => str(parsed[key])));
  if (toolName === ALIAS_CONFLICT || !toolName) return null;

  const sessionId = pickDefinedSame(SESSION_ID_KEYS.map((key) => str(parsed[key])));
  if (sessionId === ALIAS_CONFLICT) return null;

  const cwd = selectHookEnvelopeCwd(parsed)?.value;

  const bags = TOOL_INPUT_BAG_KEYS.map((key) => parsed[key]);
  if (objectsConflict(bags)) return null;
  const toolInputRaw = bags.find(isPlain);
  const toolInput = toolInputRaw ?? {};
  if (toolInputHasAliasConflict(toolInput)) return null;

  const nestedTool = str(toolInput.tool);
  if (nestedTool && nestedTool !== toolName) return null;

  const eventIdAlias = pickDefinedSame(EVENT_ID_KEYS.map((key) => str(parsed[key])));
  if (eventIdAlias === ALIAS_CONFLICT) return null;
  const toolUseId = pickDefinedSame(TOOL_USE_ID_KEYS.map((key) => str(parsed[key])));
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
    return { stdout: "", exitCode: 0 };
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
    return { stdout: "", exitCode: 0 };
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
