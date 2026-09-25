/**
 * Bounded literal argv check for dangerous_delete.
 * Never runs a shell and never expands variables.
 * After assignments and reserved words, an unquoted rm in the same simple
 * command is still an invocation, unless the command word is echo/printf/grep.
 * An unresolved operand is not a protected target by itself.
 * "$X"/* stays unresolved: an empty variable is not treated as root.
 */

export type DeleteKind = "root" | "home" | "parent" | "ordinary" | "ambiguous";

export type DangerousDeleteReason =
  | "budget"
  | "depth"
  | "unclosed-quote"
  | "bad-substitution"
  | "nesting"
  | "heredoc"
  | "unknown-option"
  | "unresolved-target"
  | "unknown-executable"
  | "prefix-depth";

export type DangerousDeleteAnalysis =
  | { status: "match" }
  | { status: "none" }
  | { status: "ambiguous"; reason: DangerousDeleteReason };

const MAX_CHARS = 16_384;
const MAX_WORDS = 192;
const MAX_SEGMENTS = 32;
const MAX_NESTED = 8;
const MAX_DEPTH = 8;
const MAX_STEPS = 20_000;

const DATA_ONLY = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg"]);
const RESERVED = new Set([
  "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "in",
  "case", "esac", "select", "time", "!", "{", "}", "coproc", "function",
]);
const PREFIXES = new Set(["sudo", "env", "command", "exec"]);

interface Word {
  text: string;
  literal: boolean;
  homeTilde: boolean;
  homeVar: boolean;
  quoted: boolean;
  sawQuote: boolean;
  sawRaw: boolean;
}

interface TokenOk {
  ok: true;
  segments: Word[][];
  nested: string[];
}

interface TokenBad {
  ok: false;
  reason: DangerousDeleteReason;
}

interface Budget {
  steps: number;
}

function limited(budget: Budget): boolean {
  budget.steps += 1;
  return budget.steps > MAX_STEPS;
}

function mentionsRm(command: string): boolean {
  const end = Math.min(command.length, MAX_CHARS);
  for (let i = 0; i + 1 < end; i++) {
    const a = command.charCodeAt(i);
    const b = command.charCodeAt(i + 1);
    if ((a === 114 || a === 82) && (b === 109 || b === 77)) return true;
  }
  return false;
}

function basename(text: string): string {
  let cut = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "/" || c === "\\") cut = i;
  }
  let name = text.slice(cut + 1).toLowerCase();
  if (name.endsWith(".exe")) name = name.slice(0, -4);
  return name;
}

function indexOfGlob(token: string): number {
  for (let i = 0; i < token.length; i++) {
    const c = token[i];
    if (c === "*" || c === "?" || c === "[" || c === "]") return i;
  }
  return -1;
}

function splitSlash(token: string): string[] | "ambiguous" {
  if (token.length > 4096) return "ambiguous";
  const parts: string[] = [];
  let cur = "";
  for (let i = 0; i < token.length; i++) {
    const c = token[i];
    if (c === "/") {
      parts.push(cur);
      cur = "";
      if (parts.length > 64) return "ambiguous";
    } else {
      cur += c;
      if (cur.length > 1024) return "ambiguous";
    }
  }
  parts.push(cur);
  return parts.length > 64 ? "ambiguous" : parts;
}

function classifyAbsolute(token: string): DeleteKind {
  const parts = splitSlash(token);
  if (parts === "ambiguous") return "ambiguous";
  const stack: string[] = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length) stack.pop();
      continue;
    }
    stack.push(part);
  }
  return stack.length === 0 ? "root" : "ordinary";
}

function classifyRelative(token: string): DeleteKind {
  const parts = splitSlash(token);
  if (parts === "ambiguous") return "ambiguous";
  const stack: string[] = [];
  let escape = 0;
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length) stack.pop();
      else escape += 1;
      continue;
    }
    stack.push(part);
  }
  if (escape > 0 && stack.length === 0) return "parent";
  return "ordinary";
}

function classifyHomeRest(rest: string): DeleteKind {
  if (rest === "" || rest === "." || rest === "./") return "home";
  const parts = splitSlash(rest.startsWith("/") ? rest.slice(1) : rest);
  if (parts === "ambiguous") return "ambiguous";
  const stack: string[] = [];
  let escape = 0;
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length) stack.pop();
      else escape += 1;
      continue;
    }
    stack.push(part);
  }
  if (stack.length === 0 && escape === 0) return "home";
  if (stack.length === 0 && escape > 0) return "parent";
  return "ordinary";
}

function classifyTildeUser(token: string): DeleteKind {
  const body = token.slice(1);
  const slash = body.indexOf("/");
  if (slash < 0) return body.length > 0 ? "home" : "ordinary";
  return classifyHomeRest(body.slice(slash + 1));
}

function stripTrailingSlashes(token: string): string {
  let end = token.length;
  while (end > 1 && token[end - 1] === "/") end -= 1;
  return token.slice(0, end);
}

function classifyLiteralTarget(token: string): DeleteKind {
  if (token.length === 0) return "ordinary";
  if (token.length > 4096) return "ambiguous";
  if (token === "~" || token === "~/") return "home";
  if (token.startsWith("~/")) return classifyHomeRest(token.slice(2));
  if (token.startsWith("~")) return classifyTildeUser(token);
  if (token === "$HOME" || token === "${HOME}" || token === "$HOME/" || token === "${HOME}/") return "home";
  if (token.startsWith("$HOME/")) return classifyHomeRest(token.slice("$HOME/".length));
  if (token.startsWith("${HOME}/")) return classifyHomeRest(token.slice("${HOME}/".length));
  if (token.startsWith("/")) return classifyAbsolute(token);
  return classifyRelative(token);
}

function classifyGlob(token: string, globAt: number): DeleteKind {
  const prefix = token.slice(0, globAt);
  if (prefix === "" || prefix === "." || prefix === "./") return "ordinary";
  const base = classifyLiteralTarget(stripTrailingSlashes(prefix));
  if (base === "root" || base === "home" || base === "parent") return base;
  return base === "ambiguous" ? "ambiguous" : "ordinary";
}

/** Root, home, and parent targets, including dot-segments and the `/*` form. */
export function normalizeDeleteTarget(token: string): DeleteKind {
  if (token.length > 4096) return "ambiguous";
  const globAt = indexOfGlob(token);
  if (globAt >= 0) return classifyGlob(token, globAt);
  return classifyLiteralTarget(token);
}

function looksLikeHomeText(token: string): boolean {
  return token.startsWith("~") || token.startsWith("$HOME") || token.startsWith("${HOME}");
}

interface OneFlag {
  recursive: boolean;
  force: boolean;
}

const LONG_NEUTRAL = new Set([
  "--no-preserve-root",
  "--one-file-system",
  "--verbose",
  "--dir",
  "--help",
  "--version",
]);

function readRmFlag(token: string): OneFlag | "ambiguous" {
  if (token.startsWith("--")) {
    const eq = token.indexOf("=");
    const name = eq === -1 ? token : token.slice(0, eq);
    const value = eq === -1 ? undefined : token.slice(eq + 1);
    if (name === "--recursive") return value === undefined ? { recursive: true, force: false } : "ambiguous";
    if (name === "--force") return value === undefined ? { recursive: false, force: true } : "ambiguous";
    if (name === "--preserve-root" && (value === undefined || value === "all")) return { recursive: false, force: false };
    if (name === "--interactive" && (value === undefined || value === "never" || value === "once" || value === "always")) {
      return { recursive: false, force: false };
    }
    if (LONG_NEUTRAL.has(name) || value !== undefined) return { recursive: false, force: false };
    return { recursive: false, force: false };
  }
  if (!token.startsWith("-") || token.length < 2) return "ambiguous";
  let recursive = false;
  let force = false;
  for (let i = 1; i < token.length; i++) {
    const c = token[i];
    if (c === "r" || c === "R") recursive = true;
    else if (c === "f" || c === "F") force = true;
  }
  return { recursive, force };
}

/**
 * Each flag token is applied on its own.
 * `-rf` sets both modes; `-r` and `-f` only do so together.
 */
export function absorbRmFlags(tokens: readonly string[]): { recursive: boolean; force: boolean } | "ambiguous" {
  let recursive = false;
  let force = false;
  for (const token of tokens) {
    const one = readRmFlag(token);
    if (one === "ambiguous") return "ambiguous";
    recursive = recursive || one.recursive;
    force = force || one.force;
  }
  return { recursive, force };
}

function isRmFlagToken(token: string): boolean {
  return token.startsWith("-") && token !== "-" && !token.startsWith("---");
}

function isAssignment(word: Word): boolean {
  if (!word.literal || word.quoted) return false;
  const eq = word.text.indexOf("=");
  if (eq <= 0) return false;
  for (let i = 0; i < eq; i++) {
    const c = word.text[i];
    const ok =
      (c >= "A" && c <= "Z") ||
      (c >= "a" && c <= "z") ||
      c === "_" ||
      (i > 0 && c >= "0" && c <= "9");
    if (!ok) return false;
  }
  return true;
}

function isReserved(word: Word): boolean {
  if (!word.literal || word.quoted) return false;
  return RESERVED.has(word.text) || RESERVED.has(word.text.toLowerCase());
}

function isDataOnly(bin: string): boolean {
  return DATA_ONLY.has(bin);
}

/** Later unquoted words may still be the rm invocation. */
export function rmIndex(words: readonly Word[], from: number): number {
  for (let i = from; i < words.length; i++) {
    const word = words[i];
    if (!word.literal || basename(word.text) !== "rm") continue;
    if (i === from || !word.quoted) return i;
  }
  return -1;
}

function operandKind(word: Word): DeleteKind {
  if (!word.literal) return "ordinary";
  if (!word.homeTilde && !word.homeVar && looksLikeHomeText(word.text)) return "ordinary";
  return normalizeDeleteTarget(word.text);
}

function classifyRm(args: readonly Word[]): DangerousDeleteAnalysis {
  const flags: string[] = [];
  const operands: Word[] = [];
  let ended = false;
  for (const word of args) {
    if (!ended && word.literal && word.text === "--" && !word.quoted) {
      ended = true;
      continue;
    }
    if (!ended && word.literal && !word.quoted && isRmFlagToken(word.text)) {
      flags.push(word.text);
      continue;
    }
    operands.push(word);
  }
  const modes = absorbRmFlags(flags);
  if (modes === "ambiguous") return { status: "ambiguous", reason: "unknown-option" };
  if (!modes.recursive || !modes.force) return { status: "none" };
  if (operands.length === 0) return { status: "none" };
  for (const operand of operands) {
    const kind = operandKind(operand);
    if (kind === "root" || kind === "home" || kind === "parent") return { status: "match" };
  }
  return { status: "none" };
}

function hasWordRm(word: Word): boolean {
  let buf = "";
  const hit = () => basename(buf) === "rm";
  for (let i = 0; i < word.text.length; i++) {
    const c = word.text[i];
    if (c === " " || c === "\t" || c === "\n") {
      if (buf && hit()) return true;
      buf = "";
    } else buf += c;
  }
  return buf !== "" && hit();
}

function tailHasRm(words: readonly Word[]): boolean {
  return words.some(hasWordRm);
}

function takesArg(bin: string, flag: string): boolean {
  if (bin === "sudo") {
    return (
      flag === "-u" || flag === "-g" || flag === "-p" || flag === "-C" || flag === "-D" ||
      flag === "-R" || flag === "-T" || flag === "-U" || flag === "-r" || flag === "-t" ||
      flag === "--user" || flag === "--group" || flag === "--prompt" || flag === "--close-from" ||
      flag === "--chdir" || flag === "--chroot" || flag === "--command-timeout" ||
      flag === "--other-user" || flag === "--role" || flag === "--type" || flag === "--host"
    );
  }
  if (bin === "env") return flag === "-u" || flag === "-C" || flag === "--unset" || flag === "--chdir";
  if (bin === "exec") return flag === "-a";
  return false;
}

function noArg(bin: string, flag: string): boolean {
  if (bin === "sudo") {
    return (
      flag === "-A" || flag === "-b" || flag === "-E" || flag === "-H" || flag === "-K" ||
      flag === "-k" || flag === "-n" || flag === "-P" || flag === "-S" || flag === "--askpass" ||
      flag === "--background" || flag === "--preserve-env" || flag === "--set-home" ||
      flag === "--remove-timestamp" || flag === "--reset-timestamp" || flag === "--non-interactive" ||
      flag === "--preserve-groups" || flag === "--stdin"
    );
  }
  if (bin === "env") {
    return flag === "-i" || flag === "-0" || flag === "-v" || flag === "--ignore-environment" || flag === "--null" || flag === "--debug";
  }
  if (bin === "command") return flag === "-p";
  if (bin === "exec") return flag === "-l" || flag === "-c";
  return false;
}

function nonExec(bin: string, flag: string): boolean {
  if (bin === "command") return flag === "-v" || flag === "-V" || flag === "--help";
  if (bin === "sudo") {
    return (
      flag === "-l" || flag === "-L" || flag === "-V" || flag === "-v" || flag === "-h" ||
      flag === "--list" || flag === "--version" || flag === "--validate" || flag === "--help"
    );
  }
  if (bin === "env") return flag === "--help" || flag === "--version";
  return false;
}

function unwrapPrefix(bin: string, words: Word[]): Word[] | "ambiguous" | "none" {
  let i = 0;
  while (i < words.length) {
    const current = words[i];
    if (!current.literal || current.quoted) break;
    const token = current.text;
    if (token === "--") return words.slice(i + 1);
    if (!token.startsWith("-") || token === "-") break;
    const eq = token.startsWith("--") ? token.indexOf("=") : -1;
    const name = eq > 0 ? token.slice(0, eq) : token;
    if (bin === "env" && (name === "-S" || name === "--split-string")) {
      const value = eq > 0 ? token.slice(eq + 1) : (words[i + 1]?.text ?? "");
      return hasWordRm({ ...current, text: value }) ? "ambiguous" : "none";
    }
    if (nonExec(bin, name)) return "none";
    if (takesArg(bin, name)) {
      if (eq > 0) {
        i += 1;
        continue;
      }
      if (i + 1 >= words.length) return tailHasRm(words.slice(i)) ? "ambiguous" : "none";
      i += 2;
      continue;
    }
    if (noArg(bin, name)) {
      i += 1;
      continue;
    }
    return tailHasRm(words.slice(i)) ? "ambiguous" : "none";
  }
  return words.slice(i);
}

function classifyWords(words: readonly Word[], depth: number): DangerousDeleteAnalysis {
  if (depth > MAX_DEPTH) return { status: "ambiguous", reason: "prefix-depth" };
  let index = 0;
  while (index < words.length && isAssignment(words[index])) index += 1;
  while (index < words.length && isReserved(words[index])) index += 1;
  if (index >= words.length) return { status: "none" };
  const head = words[index];
  if (!head.literal) return { status: "none" };
  const bin = basename(head.text);
  if (PREFIXES.has(bin)) {
    const unwrapped = unwrapPrefix(bin, words.slice(index + 1));
    if (unwrapped === "ambiguous") return { status: "ambiguous", reason: "unknown-option" };
    if (unwrapped === "none") return { status: "none" };
    return classifyWords(unwrapped, depth + 1);
  }
  if (isDataOnly(bin)) return { status: "none" };
  const at = rmIndex(words, index);
  if (at >= 0) {
    const hit = classifyRm(words.slice(at + 1));
    if (hit.status !== "none") return hit;
  }
  for (let i = index + 1; i < words.length; i++) {
    const word = words[i];
    if (!word.quoted || !mentionsRm(word.text)) continue;
    const inner = analyzeDangerousDelete(word.text, depth + 1);
    if (inner.status !== "none") return inner;
  }
  return { status: "none" };
}

function blankWord(): Word {
  return { text: "", literal: true, homeTilde: false, homeVar: false, quoted: false, sawQuote: false, sawRaw: false };
}

function isSpace(c: string): boolean {
  return c === " " || c === "\t" || c === "\f" || c === "\v" || c === "\r";
}

function extractSubstitution(input: string, open: number, budget: Budget): { body: string; next: number } | TokenBad {
  let depth = 1;
  let quote = "";
  let i = open;
  while (i < input.length) {
    if (limited(budget)) return { ok: false, reason: "budget" };
    const c = input[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < input.length) {
        i += 2;
        continue;
      }
      if (c === quote) quote = "";
      i += 1;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      i += 1;
      continue;
    }
    if (c === "(") depth += 1;
    else if (c === ")") {
      depth -= 1;
      if (depth === 0) return { body: input.slice(open, i), next: i + 1 };
    }
    i += 1;
  }
  return { ok: false, reason: "bad-substitution" };
}

function extractBacktick(input: string, open: number, budget: Budget): { body: string; next: number } | TokenBad {
  let i = open;
  while (i < input.length) {
    if (limited(budget)) return { ok: false, reason: "budget" };
    if (input[i] === "\\" && i + 1 < input.length) {
      i += 2;
      continue;
    }
    if (input[i] === "`") return { body: input.slice(open, i), next: i + 1 };
    i += 1;
  }
  return { ok: false, reason: "bad-substitution" };
}

function tokenize(input: string): TokenOk | TokenBad {
  const budget: Budget = { steps: 0 };
  const segments: Word[][] = [];
  const nested: string[] = [];
  let words: Word[] = [];
  let word = blankWord();
  let active = false;
  let quote = "";
  const flushWord = (): TokenBad | null => {
    if (!active) return null;
    if (words.length >= MAX_WORDS) return { ok: false, reason: "budget" };
    word.quoted = word.sawQuote && !word.sawRaw;
    words.push(word);
    word = blankWord();
    active = false;
    return null;
  };
  const flushSegment = (): TokenBad | null => {
    const bad = flushWord();
    if (bad) return bad;
    if (words.length) {
      if (segments.length >= MAX_SEGMENTS) return { ok: false, reason: "budget" };
      segments.push(words);
      words = [];
    }
    return null;
  };
  const remember = (body: string): TokenBad | null => {
    if (nested.length >= MAX_NESTED) return { ok: false, reason: "budget" };
    nested.push(body);
    return null;
  };

  for (let i = 0; i < input.length; ) {
    if (limited(budget)) return { ok: false, reason: "budget" };
    const c = input[i];
    if (quote === "'") {
      if (c === "'") quote = "";
      else {
        word.text += c;
        word.sawQuote = true;
        active = true;
      }
      i += 1;
      continue;
    }
    if (quote === '"') {
      if (c === '"') {
        quote = "";
        i += 1;
        continue;
      }
      word.sawQuote = true;
      active = true;
      if (c === "\\" && i + 1 < input.length) {
        word.text += input[i + 1];
        i += 2;
        continue;
      }
      if (c === "`") {
        const body = extractBacktick(input, i + 1, budget);
        if ("ok" in body) return body;
        const bad = remember(body.body);
        if (bad) return bad;
        word.literal = false;
        i = body.next;
        continue;
      }
      if (c === "$" && input[i + 1] === "(") {
        const body = extractSubstitution(input, i + 2, budget);
        if ("ok" in body) return body;
        const bad = remember(body.body);
        if (bad) return bad;
        word.literal = false;
        i = body.next;
        continue;
      }
      if (c === "$") {
        const home = readHome(input, i);
        if (home) {
          word.text += home.text;
          word.homeVar = home.pure;
          if (!home.pure) word.literal = false;
          i = home.next;
          continue;
        }
        word.literal = false;
        word.text += c;
        i += 1;
        continue;
      }
      word.text += c;
      i += 1;
      continue;
    }

    if (isSpace(c)) {
      const bad = flushWord();
      if (bad) return bad;
      i += 1;
      continue;
    }
    if (c === "\n") {
      const bad = flushSegment();
      if (bad) return bad;
      i += 1;
      continue;
    }
    if (c === "\\" && input[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (c === "\\" && i + 1 < input.length) {
      word.text += input[i + 1];
      word.sawRaw = true;
      active = true;
      i += 2;
      continue;
    }
    if (!active && c === "#") {
      while (i < input.length && input[i] !== "\n") i += 1;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      word.sawQuote = true;
      active = true;
      i += 1;
      continue;
    }
    if (c === "(" || c === ")") {
      const bad = flushSegment();
      if (bad) return bad;
      i += 1;
      continue;
    }
    if (c === "&" || c === "|" || c === ";") {
      const bad = flushSegment();
      if (bad) return bad;
      if ((c === "&" || c === "|") && input[i + 1] === c) i += 2;
      else if (c === "|" && input[i + 1] === "&") i += 2;
      else i += 1;
      continue;
    }
    if (c === ">" || c === "<") {
      if (active && isDigits(word.text) && c === ">") {
        word = blankWord();
        active = false;
      } else {
        const bad = flushWord();
        if (bad) return bad;
      }
      if (input[i] === "<" && input[i + 1] === "(") return { ok: false, reason: "nesting" };
      if (input[i] === "<" && input[i + 1] === "<") return { ok: false, reason: "heredoc" };
      i += 1;
      if (input[i] === ">" || input[i] === "&" || input[i] === "|") i += 1;
      while (isSpace(input[i] ?? "")) i += 1;
      if (i >= input.length || input[i] === "\n" || input[i] === ";" || input[i] === "|" || input[i] === "&") {
        return { ok: false, reason: "heredoc" };
      }
      const target = readRedirectWord(input, i, budget);
      if ("ok" in target) return target;
      i = target.next;
      continue;
    }
    if (c === "$" && input[i + 1] === "(") {
      const body = extractSubstitution(input, i + 2, budget);
      if ("ok" in body) return body;
      const bad = remember(body.body);
      if (bad) return bad;
      word.literal = false;
      word.sawRaw = true;
      active = true;
      i = body.next;
      continue;
    }
    if (c === "`") {
      const body = extractBacktick(input, i + 1, budget);
      if ("ok" in body) return body;
      const bad = remember(body.body);
      if (bad) return bad;
      word.literal = false;
      word.sawRaw = true;
      active = true;
      i = body.next;
      continue;
    }
    if (c === "$") {
      const home = readHome(input, i);
      if (home) {
        if (!active && home.pure) word.homeVar = true;
        word.text += home.text;
        if (!home.pure) word.literal = false;
        else word.homeVar = true;
        word.sawRaw = true;
        active = true;
        i = home.next;
        continue;
      }
      word.literal = false;
      word.text += c;
      word.sawRaw = true;
      active = true;
      i += 1;
      continue;
    }
    if (!active && c === "~") word.homeTilde = true;
    word.text += c;
    word.sawRaw = true;
    active = true;
    i += 1;
  }
  if (quote) return { ok: false, reason: "unclosed-quote" };
  const bad = flushSegment();
  if (bad) return bad;
  return { ok: true, segments, nested };
}

function isDigits(text: string): boolean {
  if (!text) return false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c < "0" || c > "9") return false;
  }
  return true;
}

function isNameStart(c: string | undefined): boolean {
  return c !== undefined && ((c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "_");
}

function isNameChar(c: string | undefined): boolean {
  return isNameStart(c) || (c !== undefined && c >= "0" && c <= "9");
}

function readHome(input: string, start: number): { text: string; next: number; pure: boolean } | null {
  if (input[start] !== "$") return null;
  let i = start + 1;
  if (input[i] === "{") {
    i += 1;
    const nameAt = i;
    while (i < input.length && input[i] !== "}") {
      if (!isNameChar(input[i])) return null;
      i += 1;
    }
    if (input[i] !== "}") return null;
    const name = input.slice(nameAt, i);
    const raw = input.slice(start, i + 1);
    const next = i + 1;
    if (name !== "HOME") return { text: raw, next, pure: false };
    return continueHomePath(input, raw, next);
  }
  if (!isNameStart(input[i])) return null;
  const nameAt = i;
  i += 1;
  while (isNameChar(input[i])) i += 1;
  const name = input.slice(nameAt, i);
  const raw = input.slice(start, i);
  if (name !== "HOME") return { text: raw, next: i, pure: false };
  return continueHomePath(input, raw, i);
}

function continueHomePath(input: string, raw: string, next: number): { text: string; next: number; pure: boolean } {
  if (input[next] !== "/") return { text: raw, next, pure: true };
  let i = next;
  let text = raw;
  while (i < input.length) {
    const c = input[i];
    if (isSpace(c) || c === "\n" || c === ";" || c === "|" || c === "&" || c === ">" || c === "<" || c === "'" || c === '"') {
      break;
    }
    if (c === "$" || c === "`" || c === "\\" || c === "(" || c === ")") return { text, next: i, pure: false };
    text += c;
    i += 1;
  }
  return { text, next: i, pure: true };
}

function readRedirectWord(input: string, start: number, budget: Budget): { next: number } | TokenBad {
  let i = start;
  let quote = "";
  if (i >= input.length) return { ok: false, reason: "heredoc" };
  while (i < input.length) {
    if (limited(budget)) return { ok: false, reason: "budget" };
    const c = input[i];
    if (quote) {
      if (c === quote) quote = "";
      i += 1;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      i += 1;
      continue;
    }
    if (isSpace(c) || c === "\n" || c === ";" || c === "|" || c === "&" || c === ">" || c === "<") break;
    i += 1;
  }
  if (quote) return { ok: false, reason: "unclosed-quote" };
  return i === start ? { ok: false, reason: "heredoc" } : { next: i };
}

function hasUnquotedRm(command: string): boolean {
  let quote = "";
  let word = "";
  let escaped = false;
  const end = Math.min(command.length, MAX_CHARS);
  const flush = () => {
    const hit = basename(word) === "rm";
    word = "";
    return hit;
  };
  for (let i = 0; i < end; i++) {
    const c = command[i];
    if (escaped) {
      if (!quote) word += c;
      escaped = false;
      continue;
    }
    if (quote) {
      if (c === "\\" && quote === '"') escaped = true;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === "\\" && i + 1 < end) {
      escaped = true;
      continue;
    }
    if (c === "'" || c === '"') {
      if (flush()) return true;
      quote = c;
      continue;
    }
    if (isSpace(c) || c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "<" || c === ">") {
      if (flush()) return true;
      continue;
    }
    word += c;
  }
  return flush();
}

export function analyzeDangerousDelete(command: string, depth = 0): DangerousDeleteAnalysis {
  if (depth > MAX_DEPTH) return mentionsRm(command) ? { status: "ambiguous", reason: "depth" } : { status: "none" };
  if (command.length > MAX_CHARS) {
    return mentionsRm(command) ? { status: "ambiguous", reason: "budget" } : { status: "none" };
  }
  if (!mentionsRm(command)) return { status: "none" };
  const tok = tokenize(command);
  if (!tok.ok) return hasUnquotedRm(command) ? { status: "ambiguous", reason: tok.reason } : { status: "none" };
  let ambiguous: DangerousDeleteAnalysis | null = null;
  for (const body of tok.nested) {
    const inner = analyzeDangerousDelete(body, depth + 1);
    if (inner.status === "match") return inner;
    if (inner.status === "ambiguous") ambiguous = inner;
  }
  for (const segment of tok.segments) {
    const hit = classifyWords(segment, depth);
    if (hit.status === "match") return hit;
    if (hit.status === "ambiguous") ambiguous = hit;
  }
  return ambiguous ?? { status: "none" };
}
