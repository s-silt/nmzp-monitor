import { AGENTS, isAgentId } from "./agents.ts";
import { agentFromBin } from "./watch.ts";
import type { AgentId } from "./types";

export interface ModelGuess {
  model: string;
  agent: AgentId;
  source: "session" | "host" | "tool" | "payload";
}

const HOST_MODEL: Array<{ re: RegExp; agent: AgentId; model: string }> = [
  { re: /(api\.z\.ai|open\.bigmodel\.cn)/i, agent: "zcode", model: "glm-4.6" },
  { re: /(api\.openai\.com|chatgpt\.com|oaiusercontent)/i, agent: "codex", model: "gpt-5-codex" },
  { re: /(api\.x\.ai|assets\.grok\.com)/i, agent: "grok", model: "grok-code" },
  { re: /(api\.anthropic\.com)/i, agent: "claude", model: "claude-sonnet-4" },
  { re: /(api2\.cursor\.sh|\.cursor\.sh)/i, agent: "cursor", model: "cursor-small" },
  { re: /(api\.githubcopilot\.com|copilot-proxy)/i, agent: "copilot", model: "gpt-4.1" },
  { re: /(windsurf\.com|codeium\.com)/i, agent: "windsurf", model: "cascade" },
  { re: /(generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com)/i, agent: "gemini", model: "gemini-2.5-pro" },
  { re: /(dashscope\.aliyuncs\.com)/i, agent: "qwen", model: "qwen3-coder" },
  { re: /(api\.trae\.ai)/i, agent: "trae", model: "doubao-seed" },
];

const PAYLOAD_MODEL: Array<{ re: RegExp; model: string; agent?: AgentId }> = [
  { re: /\bglm-4\.6\b/i, model: "glm-4.6", agent: "zcode" },
  { re: /\bglm-4\.5-air\b/i, model: "glm-4.5-air", agent: "zcode" },
  { re: /\bglm-4/i, model: "glm-4.5", agent: "zcode" },
  { re: /\bgpt-5-codex\b/i, model: "gpt-5-codex", agent: "codex" },
  { re: /\bgpt-5\b/i, model: "gpt-5" },
  { re: /\bgpt-4\.1\b/i, model: "gpt-4.1" },
  { re: /\bgpt-4o\b/i, model: "gpt-4o" },
  { re: /\bo4-mini\b/i, model: "o4-mini", agent: "codex" },
  { re: /\bo3\b/, model: "o3", agent: "codex" },
  { re: /\bgrok-code\b/i, model: "grok-code", agent: "grok" },
  { re: /\bgrok-4\.6\b/i, model: "grok-4.6", agent: "grok" },
  { re: /\bgrok-build\b/i, model: "grok-build", agent: "grok" },
  { re: /\bclaude-opus-4\b/i, model: "claude-opus-4", agent: "claude" },
  { re: /\bclaude-sonnet-4\b/i, model: "claude-sonnet-4", agent: "claude" },
  { re: /\bclaude-haiku\b/i, model: "claude-haiku", agent: "claude" },
  { re: /\bclaude-3\.7\b/i, model: "claude-3.7-sonnet", agent: "claude" },
  { re: /\bgemini-2\.5-pro\b/i, model: "gemini-2.5-pro", agent: "gemini" },
  { re: /\bgemini-2\.5-flash\b/i, model: "gemini-2.5-flash", agent: "gemini" },
  { re: /\bgemini-2\.0\b/i, model: "gemini-2.0-pro", agent: "gemini" },
  { re: /\bqwen3-coder\b/i, model: "qwen3-coder", agent: "qwen" },
  { re: /\bqwen-max\b/i, model: "qwen-max", agent: "qwen" },
  { re: /\bdeepseek-v3\b/i, model: "deepseek-v3" },
  { re: /\bdeepseek-r1\b/i, model: "deepseek-r1" },
  { re: /\bdeepseek-chat\b/i, model: "deepseek-chat" },
  { re: /\b(kimi-k2|moonshot-v1)\b/i, model: "kimi-k2" },
  { re: /\bdoubao\b/i, model: "doubao-seed", agent: "trae" },
  { re: /\bcascade\b/i, model: "cascade", agent: "windsurf" },
  { re: /\bcodestral\b/i, model: "codestral" },
  { re: /\bmistral-large\b/i, model: "mistral-large" },
  { re: /\bllama-4\b/i, model: "llama-4" },
];

const TOOL_AGENT: Array<{ re: RegExp; agent: AgentId }> = [
  { re: /^(apply_patch|shell|shell_command|exec_command)$/i, agent: "codex" },
  { re: /^(read_file|write_file|edit_file|search_web|search_x)$/i, agent: "grok" },
  { re: /^(Agent|MultiEdit)$/i, agent: "zcode" },
  { re: /^(str_replace|strreplace)$/i, agent: "claude" },
  {
    re: /^(run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|list_dir|find_by_name|grep_search|read_url_content|invoke_subagent)$/i,
    agent: "antigravity",
  },
];

export function guessModel(input: {
  agent: AgentId;
  nativeTool: string;
  command?: string;
  dest?: string;
  sessionModel?: string;
  proc?: string;
  parentProc?: string;
}): ModelGuess {
  const blob = `${input.command ?? ""} ${input.dest ?? ""}`;
  const fromProc = agentFromBin(input.proc) ?? agentFromBin(input.parentProc);

  for (const row of PAYLOAD_MODEL) {
    if (row.re.test(blob)) {
      return {
        model: row.model,
        agent: fromProc ?? input.agent,
        source: "payload",
      };
    }
  }

  if (fromProc) {
    return {
      model: input.sessionModel || AGENTS[fromProc].models[0]!,
      agent: fromProc,
      source: "session",
    };
  }

  if (input.dest) {
    for (const row of HOST_MODEL) {
      if (row.re.test(input.dest)) {
        return { model: row.model, agent: fromProc ?? row.agent, source: "host" };
      }
    }
  }

  for (const row of TOOL_AGENT) {
    if (row.re.test(input.nativeTool)) {
      return { model: AGENTS[row.agent].models[0]!, agent: row.agent, source: "tool" };
    }
  }

  const sessionAgent = isAgentId(input.agent) ? input.agent : "zcode";
  return {
    model: input.sessionModel || AGENTS[sessionAgent].models[0]!,
    agent: sessionAgent,
    source: "session",
  };
}
