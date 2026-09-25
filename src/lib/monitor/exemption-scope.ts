import { isNodeDataCommand } from "./command-intent.ts";
import { analyzeDangerousDelete } from "./dangerous-delete.ts";
import { CANONICAL_TOOL_NAMES } from "./policy-schema.ts";
import { RULE_BY_ID } from "./rules.ts";
import type { RuleDef } from "./types.ts";

/**
 * Operands of the segments that trigger a rule.
 * null means the compound is ambiguous: the caller must not exempt.
 * An empty list means no triggering operand was found: do not fall back to the full inspect string.
 * Comments, redirect targets, and trailing tool labels are not operands.
 * A backslash, expansion, substitution, or heredoc makes the whole string ambiguous.
 */

const MAX_CHARS = 65_536;
const MAX_STATEMENTS = 64;

const DOWNLOAD_CURL_OUT = /\b(?:curl|wget2?)\b[^\n]{0,800}(?:-o\b|-O\b|--output\b)/i;
const DOWNLOAD_SCRIPT_EXT = /\.(?:sh|py|pl|rb)\b/i;
const DOWNLOAD_THEN_RUN = /\b(?:bash|sh|zsh|python3?|chmod\s+\+x)\b|\.\//i;

/** Raw native tool names that buildInspect appends. They are not shell segments. */
const TOOL_LABELS = new Set<string>([
  ...CANONICAL_TOOL_NAMES,
  "bash",
  "shell",
  "shell_command",
  "exec_command",
  "run_terminal_command",
  "run_command",
  "read",
  "view_file",
  "list_dir",
  "find_by_name",
  "read_file",
  "write",
  "write_file",
  "write_to_file",
  "edit",
  "edit_file",
  "replace_file_content",
  "multi_replace_file_content",
  "apply_patch",
  "strreplace",
  "str_replace",
  "search_replace",
  "multiedit",
  "glob",
  "grep",
  "grep_search",
  "webfetch",
  "read_url_content",
  "websearch",
  "search_web",
  "search_x",
  "web_search",
  "task",
  "agent",
  "delegate",
  "spawn_subagent",
  "invoke_subagent",
  "skill",
  "runcommand",
  "run_shell_command",
  "run_in_terminal",
  "create_file",
  "replace",
  "delete",
  "fetchurl",
  "web_fetch",
  "google_web_search",
  "list_directory",
  "read_many_files",
  "invoke_agent",
]);

interface ShellStatement {
  trigger: string;
  operand: string;
}

const patternCache = new Map<string, RegExp>();

function ruleRegex(rule: RuleDef): RegExp {
  let re = patternCache.get(rule.id);
  if (!re) {
    re = new RegExp(rule.pattern, "i");
    patternCache.set(rule.id, re);
  }
  re.lastIndex = 0;
  return re;
}

function startsComment(trigger: string): boolean {
  if (!trigger) return true;
  const prev = trigger[trigger.length - 1];
  return prev === " " || prev === "\t" || prev === "\n" || prev === "\r" || prev === "|" || prev === "<" || prev === ">";
}

/** Keep aligned with engine.ts fieldMatches. Ambiguous delete segments never qualify. */
function statementTriggers(rule: RuleDef, trigger: string): boolean | "ambiguous" {
  if (rule.id === "dangerous_delete") {
    const analysis = analyzeDangerousDelete(trigger);
    if (analysis.status === "ambiguous") return "ambiguous";
    return analysis.status === "match";
  }
  if (rule.id === "curl_download_then_exec") {
    return DOWNLOAD_CURL_OUT.test(trigger) && DOWNLOAD_SCRIPT_EXT.test(trigger) && DOWNLOAD_THEN_RUN.test(trigger);
  }
  const re = ruleRegex(rule);
  const matched = re.test(trigger);
  re.lastIndex = 0;
  if (rule.id === "wget_post_file" && matched && isNodeDataCommand(trigger)) return false;
  return matched;
}

function parseStatements(text: string): ShellStatement[] | null {
  if (text.length > MAX_CHARS) return null;
  const statements: ShellStatement[] = [];
  let trigger = "";
  let operand = "";
  let quote = "";
  let redirect: "none" | "operator" | "target" = "none";
  let sawTarget = false;

  const finish = (): boolean => {
    const triggerText = trigger.trim();
    const operandText = operand.trim();
    trigger = "";
    operand = "";
    redirect = "none";
    sawTarget = false;
    if (!triggerText && !operandText) return true;
    statements.push({ trigger: triggerText, operand: operandText });
    return statements.length <= MAX_STATEMENTS;
  };

  for (let i = 0; i < text.length; i += 1) {
    const c = text[i] ?? "";
    if (quote) {
      if (quote === '"' && (c === "$" || c === "`" || c === "\\")) return null;
      trigger += c;
      if (redirect !== "target") operand += c;
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"') {
      if (redirect === "operator") redirect = "target";
      quote = c;
      trigger += c;
      if (redirect === "target") sawTarget = true;
      else operand += c;
      continue;
    }
    if (c === "#" && startsComment(trigger)) {
      while (i + 1 < text.length && text[i + 1] !== "\n" && text[i + 1] !== "\r") i += 1;
      continue;
    }
    if (c === "\n" || c === "\r" || c === ";") {
      if (!finish()) return null;
      if (c === "\r" && text[i + 1] === "\n") i += 1;
      continue;
    }
    if (c === "|") {
      if (text[i + 1] === "|") {
        if (!finish()) return null;
        i += 1;
        continue;
      }
      if (redirect !== "none") return null;
      trigger += c;
      operand += c;
      continue;
    }
    if (c === "&") {
      if (text[i + 1] === "&") {
        if (!finish()) return null;
        i += 1;
        continue;
      }
      if (redirect === "operator") {
        trigger += c;
        continue;
      }
      return null;
    }
    if (c === "<") {
      if (text[i + 1] === "<") return null;
      trigger += c;
      redirect = "operator";
      sawTarget = false;
      continue;
    }
    if (c === ">") {
      trigger += c;
      redirect = "operator";
      sawTarget = false;
      continue;
    }
    if (c === "$" || c === "`" || c === "(" || c === ")" || c === "{" || c === "}" || c === "\\") return null;
    if (c === " " || c === "\t" || c === "\f" || c === "\v") {
      trigger += c;
      if (redirect === "operator") {
        redirect = "target";
        continue;
      }
      if (redirect === "target") {
        if (sawTarget) {
          redirect = "none";
          sawTarget = false;
        }
        continue;
      }
      operand += c;
      continue;
    }
    trigger += c;
    if (redirect === "operator" || redirect === "target") {
      redirect = "target";
      sawTarget = true;
      continue;
    }
    operand += c;
  }
  if (quote) return null;
  if (!finish()) return null;
  return statements;
}

export function exemptionSubjects(inspect: string, ruleId: string): string[] | null {
  const statements = parseStatements(inspect);
  if (!statements) return null;
  const rule = RULE_BY_ID[ruleId];
  if (!rule) {
    const parts: string[] = [];
    for (const statement of statements) {
      const operand = statement.operand.trim();
      if (!operand || TOOL_LABELS.has(operand)) continue;
      parts.push(operand);
    }
    return parts;
  }
  const subjects: string[] = [];
  for (const statement of statements) {
    if (!statement.trigger) continue;
    const hit = statementTriggers(rule, statement.trigger);
    if (hit === "ambiguous") return null;
    if (!hit) continue;
    const operand = statement.operand.trim();
    if (!operand) return null;
    subjects.push(operand);
  }
  return subjects;
}
