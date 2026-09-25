/**
 * disk_overwrite matches dd, mkfs, fdisk, and parted only as the executable word.
 * Does not run a shell. Ambiguous input fail-closes only when an unquoted disk basename is present.
 * dangerous-delete.ts does not export its tokenizer; flag lists for sudo/env/command/exec follow that walker.
 */

const MAX_CHARS = 16_384;
const MAX_WORDS = 192;
const MAX_SEGMENTS = 32;
const MAX_NESTED = 8;
const MAX_DEPTH = 8;
const MAX_STEPS = 20_000;

const READERS = new Set([
  "cat", "head", "tail", "less", "more", "wc", "stat", "file", "ls", "od", "strings",
  "nl", "cmp", "diff", "tac", "rev", "hexdump", "xxd", "cut", "sort", "uniq", "tr",
  "echo", "printf", "grep", "egrep", "fgrep", "rg",
]);

const RESERVED = new Set([
  "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "in",
  "case", "esac", "select", "!", "{", "}",
]);

const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ash", "ksh"]);

const SUDO_ARG = new Set([
  "-u", "-g", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
  "--user", "--group", "--prompt", "--close-from", "--chdir", "--chroot",
  "--command-timeout", "--other-user", "--role", "--type", "--host",
]);
const SUDO_NOARG = new Set([
  "-A", "-b", "-E", "-H", "-K", "-k", "-n", "-P", "-S", "--askpass", "--background",
  "--preserve-env", "--set-home", "--remove-timestamp", "--reset-timestamp",
  "--non-interactive", "--preserve-groups", "--stdin",
]);
const SUDO_NONE = new Set(["-l", "-L", "-V", "-v", "-h", "--list", "--version", "--validate", "--help"]);

const ENV_ARG = new Set(["-u", "-C", "--unset", "--chdir", "-S", "--split-string"]);
const ENV_NOARG = new Set(["-i", "-0", "-v", "--ignore-environment", "--null", "--debug"]);
const ENV_NONE = new Set(["--help", "--version"]);

export type DiskVerdict = "match" | "none" | "ambiguous";

interface StepBudget {
  steps: number;
}

function limited(budget: StepBudget): boolean {
  budget.steps += 1;
  return budget.steps > MAX_STEPS;
}

function basename(text: string): string {
  let cut = -1;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === "/" || c === "\\") cut = i;
  }
  let name = text.slice(cut + 1).toLowerCase();
  if (name.endsWith(".exe")) name = name.slice(0, -4);
  return name;
}

function isDisk(name: string): boolean {
  return name === "dd" || name === "fdisk" || name === "parted" || name === "mkfs" || name.startsWith("mkfs.");
}

function isSpace(c: string | undefined): boolean {
  return c === " " || c === "\t" || c === "\f" || c === "\v" || c === "\r";
}

function isAssignment(word: string): boolean {
  const eq = word.indexOf("=");
  if (eq <= 0) return false;
  for (let i = 0; i < eq; i += 1) {
    const c = word[i]!;
    const ok = (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "_" || (i > 0 && c >= "0" && c <= "9");
    if (!ok) return false;
  }
  return true;
}

function isReserved(word: string): boolean {
  return RESERVED.has(word) || RESERVED.has(word.toLowerCase());
}

function tailDisk(words: readonly string[], from: number): boolean {
  for (let i = from; i < words.length; i += 1) {
    if (isDisk(basename(words[i]!))) return true;
  }
  return false;
}

function hasUnquotedDisk(command: string): boolean {
  let quote = "";
  let word = "";
  let escaped = false;
  const end = Math.min(command.length, MAX_CHARS);
  const hit = () => isDisk(basename(word));
  for (let i = 0; i < end; i += 1) {
    const c = command[i]!;
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
      if (hit()) return true;
      word = "";
      quote = c;
      continue;
    }
    if (isSpace(c) || c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "<" || c === ">") {
      if (hit()) return true;
      word = "";
      continue;
    }
    word += c;
  }
  return hit();
}

interface TokOk {
  ok: true;
  segments: string[][];
  nested: string[];
}

function tokenize(input: string, budget: StepBudget): TokOk | DiskVerdict {
  const giveUp = (): DiskVerdict => (hasUnquotedDisk(input) ? "ambiguous" : "none");
  const segments: string[][] = [];
  const nested: string[] = [];
  let words: string[] = [];
  let word = "";
  let active = false;
  let quote = "";

  const flushWord = (): DiskVerdict | null => {
    if (!active || !word) {
      active = false;
      word = "";
      return null;
    }
    if (words.length >= MAX_WORDS) return giveUp();
    words.push(word);
    word = "";
    active = false;
    return null;
  };
  const flushSegment = (): DiskVerdict | null => {
    const bad = flushWord();
    if (bad) return bad;
    if (words.length) {
      if (segments.length >= MAX_SEGMENTS) return giveUp();
      segments.push(words);
      words = [];
    }
    return null;
  };
  const remember = (body: string): DiskVerdict | null => {
    if (nested.length >= MAX_NESTED) return giveUp();
    nested.push(body);
    return null;
  };
  const substitution = (open: number): { body: string; next: number } | DiskVerdict => {
    let depth = 1;
    let q = "";
    let i = open;
    while (i < input.length) {
      if (limited(budget)) return giveUp();
      const c = input[i]!;
      if (q) {
        if (c === "\\" && q === '"' && i + 1 < input.length) {
          i += 2;
          continue;
        }
        if (c === q) q = "";
        i += 1;
        continue;
      }
      if (c === "'" || c === '"') {
        q = c;
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
    return giveUp();
  };
  const backtick = (open: number): { body: string; next: number } | DiskVerdict => {
    let i = open;
    while (i < input.length) {
      if (limited(budget)) return giveUp();
      if (input[i] === "\\" && i + 1 < input.length) {
        i += 2;
        continue;
      }
      if (input[i] === "`") return { body: input.slice(open, i), next: i + 1 };
      i += 1;
    }
    return giveUp();
  };

  for (let i = 0; i < input.length; ) {
    if (limited(budget)) return giveUp();
    const c = input[i]!;
    if (quote === "'") {
      if (c === "'") quote = "";
      else {
        word += c;
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
      active = true;
      if (c === "\\" && i + 1 < input.length) {
        word += input[i + 1];
        i += 2;
        continue;
      }
      if (c === "`") {
        const body = backtick(i + 1);
        if (typeof body === "string") return body;
        const bad = remember(body.body);
        if (bad) return bad;
        i = body.next;
        continue;
      }
      if (c === "$" && input[i + 1] === "(") {
        const body = substitution(i + 2);
        if (typeof body === "string") return body;
        const bad = remember(body.body);
        if (bad) return bad;
        i = body.next;
        continue;
      }
      word += c;
      i += 1;
      continue;
    }
    if (isSpace(c)) {
      const bad = flushWord();
      if (bad) return bad;
      i += 1;
      continue;
    }
    if (c === "\n" || c === ";" || c === "&" || c === "|") {
      const bad = flushSegment();
      if (bad) return bad;
      if ((c === "&" || c === "|") && input[i + 1] === c) i += 2;
      else i += 1;
      continue;
    }
    if (c === "\\" && input[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (c === "\\" && i + 1 < input.length) {
      word += input[i + 1];
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
    if (c === ">" || c === "<") {
      const bad = flushWord();
      if (bad) return bad;
      if (input[i] === "<" && input[i + 1] === "(") return hasUnquotedDisk(input) ? "ambiguous" : "none";
      if (input[i] === "<" && input[i + 1] === "<") return hasUnquotedDisk(input) ? "ambiguous" : "none";
      i += 1;
      if (input[i] === ">" || input[i] === "&" || input[i] === "|") i += 1;
      while (isSpace(input[i])) i += 1;
      while (i < input.length && !isSpace(input[i]) && input[i] !== "\n" && input[i] !== ";" && input[i] !== "|" && input[i] !== "&") {
        if (input[i] === "'" || input[i] === '"') {
          const q = input[i]!;
          i += 1;
          while (i < input.length && input[i] !== q) i += 1;
          if (i >= input.length) return hasUnquotedDisk(input) ? "ambiguous" : "none";
        }
        i += 1;
      }
      continue;
    }
    if (c === "`") {
      const body = backtick(i + 1);
      if (typeof body === "string") return body;
      const bad = remember(body.body);
      if (bad) return bad;
      i = body.next;
      continue;
    }
    if (c === "$" && input[i + 1] === "(") {
      const body = substitution(i + 2);
      if (typeof body === "string") return body;
      const bad = remember(body.body);
      if (bad) return bad;
      i = body.next;
      continue;
    }
    word += c;
    active = true;
    i += 1;
  }
  if (quote) return hasUnquotedDisk(input) ? "ambiguous" : "none";
  const bad = flushSegment();
  if (bad) return bad;
  return { ok: true, segments, nested };
}

type Unwrap = { next: number } | { script: string } | "none" | "ambiguous" | "match";

function flagName(token: string): { name: string; attached: boolean } {
  const eq = token.startsWith("--") ? token.indexOf("=") : -1;
  if (eq > 0) return { name: token.slice(0, eq), attached: true };
  return { name: token, attached: false };
}

function skipFlags(
  words: readonly string[],
  start: number,
  arg: Set<string>,
  noarg: Set<string>,
  none: Set<string>,
): Unwrap {
  let j = start;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if (none.has(name)) return "none";
    if (arg.has(name)) {
      if (name === "-S" || name === "--split-string") {
        const script = attached ? token.slice(token.indexOf("=") + 1) : words[j + 1];
        if (script === undefined) return tailDisk(words, j) ? "ambiguous" : "none";
        return { script };
      }
      if (attached) {
        j += 1;
        continue;
      }
      if (j + 1 >= words.length) return tailDisk(words, j) ? "ambiguous" : "none";
      j += 2;
      continue;
    }
    if (noarg.has(name)) {
      j += 1;
      continue;
    }
    return tailDisk(words, j) ? "ambiguous" : "none";
  }
  return { next: j };
}

function shellScript(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  let dashC = false;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") {
      j += 1;
      break;
    }
    if (!token.startsWith("-") || token === "-") break;
    if (token.includes("c")) dashC = true;
    j += 1;
  }
  if (!dashC) return "none";
  const script = words[j];
  if (script === undefined) return "none";
  return { script };
}

function skipTimeout(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") {
      j += 1;
      break;
    }
    if (!token.startsWith("-") || token === "-") break;
    const { name, attached } = flagName(token);
    if (name === "-k" || name === "-s" || name === "--kill-after" || name === "--signal") {
      if (!attached) j += 1;
      j += 1;
      continue;
    }
    if (token.startsWith("-")) {
      j += 1;
      continue;
    }
    break;
  }
  if (j >= words.length) return "none";
  if (/^[0-9]+(\.[0-9]+)?[smhd]?$/.test(words[j]!)) j += 1;
  return { next: j };
}

function skipNice(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (/^--?\d+$/.test(token)) {
      j += 1;
      continue;
    }
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if (name === "-n" || name === "--adjustment") {
      if (!attached) j += 1;
      j += 1;
      continue;
    }
    j += 1;
  }
  return { next: j };
}

function skipStdbuf(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if ((name === "-o" || name === "-e" || name === "-i" || name === "--output" || name === "--error" || name === "--input") && !attached && !/^-[oei].+/.test(token)) {
      j += 2;
      continue;
    }
    j += 1;
  }
  return { next: j };
}

function skipXargs(words: readonly string[], index: number): Unwrap {
  const arg = new Set(["-n", "-I", "-P", "-L", "-s", "-a", "-d", "-E", "-J", "-R"]);
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if (arg.has(name) && !attached) {
      j += 2;
      continue;
    }
    j += 1;
  }
  return { next: j };
}

function skipWatch(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if ((name === "-n" || name === "--interval" || name === "-d" || name === "--differences") && name === "-n" && !attached) {
      j += 2;
      continue;
    }
    if ((name === "-n" || name === "--interval") && !attached && !token.startsWith("--interval=")) {
      j += 2;
      continue;
    }
    j += 1;
  }
  return { next: j };
}

function skipDoas(words: readonly string[], index: number): Unwrap {
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") return { next: j + 1 };
    if (!token.startsWith("-") || token === "-") return { next: j };
    const { name, attached } = flagName(token);
    if ((name === "-u" || name === "-a" || name === "-C") && !attached) {
      if (j + 1 >= words.length) return tailDisk(words, j) ? "ambiguous" : "none";
      j += 2;
      continue;
    }
    if (token.startsWith("-")) {
      j += 1;
      continue;
    }
    break;
  }
  return { next: j };
}

function skipSsh(words: readonly string[], index: number): Unwrap {
  const arg = new Set(["-p", "-l", "-i", "-o", "-F", "-J", "-b", "-c", "-D", "-E", "-e", "-L", "-R", "-S", "-W", "-w", "-m"]);
  let j = index + 1;
  while (j < words.length) {
    const token = words[j]!;
    if (token === "--") {
      j += 1;
      break;
    }
    if (!token.startsWith("-") || token === "-") break;
    const { name, attached } = flagName(token);
    if (arg.has(name) && !attached) {
      if (j + 1 >= words.length) return "none";
      j += 2;
      continue;
    }
    j += 1;
  }
  if (j >= words.length) return "none";
  j += 1;
  if (j >= words.length) return "none";
  return { script: words.slice(j).join(" ") };
}

function unwrap(bin: string, words: readonly string[], index: number): Unwrap {
  if (bin === "sudo") return skipFlags(words, index + 1, SUDO_ARG, SUDO_NOARG, SUDO_NONE);
  if (bin === "env") return skipFlags(words, index + 1, ENV_ARG, ENV_NOARG, ENV_NONE);
  if (bin === "command") return skipFlags(words, index + 1, new Set(), new Set(["-p"]), new Set(["-v", "-V", "--help"]));
  if (bin === "exec") return skipFlags(words, index + 1, new Set(["-a"]), new Set(["-l", "-c"]), new Set());
  if (SHELLS.has(bin)) return shellScript(words, index);
  if (bin === "timeout") return skipTimeout(words, index);
  if (bin === "nice" || bin === "time") return skipNice(words, index);
  if (bin === "stdbuf") return skipStdbuf(words, index);
  if (bin === "xargs") return skipXargs(words, index);
  if (bin === "watch") return skipWatch(words, index);
  if (bin === "doas") return skipDoas(words, index);
  if (bin === "ssh") return skipSsh(words, index);
  if (bin === "nohup" || bin === "busybox") {
    const next = words[index + 1] === "--" ? index + 2 : index + 1;
    return { next };
  }
  if (bin === "eval") {
    const rest = words.slice(index + 1);
    if (!rest.length) return "none";
    return { script: rest.length === 1 ? rest[0]! : rest.join(" ") };
  }
  return "none";
}

function worse(a: DiskVerdict, b: DiskVerdict): DiskVerdict {
  if (a === "match" || b === "match") return "match";
  if (a === "ambiguous" || b === "ambiguous") return "ambiguous";
  return "none";
}

function classifyWords(words: readonly string[], depth: number, budget: StepBudget): DiskVerdict {
  if (depth > MAX_DEPTH) return tailDisk(words, 0) ? "ambiguous" : "none";
  let i = 0;
  let hops = 0;
  while (i < words.length && hops < 24) {
    if (limited(budget)) return tailDisk(words, 0) ? "ambiguous" : "none";
    hops += 1;
    while (i < words.length && isAssignment(words[i]!)) i += 1;
    while (i < words.length && isReserved(words[i]!)) i += 1;
    if (i >= words.length) return "none";
    const bin = basename(words[i]!);
    if (isDisk(bin)) return "match";
    if (READERS.has(bin)) return "none";
    const step = unwrap(bin, words, i);
    if (step === "none") return "none";
    if (step === "ambiguous") return "ambiguous";
    if (step === "match") return "match";
    if ("script" in step) return classifyCommand(step.script, depth + 1, budget);
    i = step.next;
  }
  return i < words.length && tailDisk(words, i) ? "ambiguous" : "none";
}

function classifyCommand(command: string, depth: number, budget: StepBudget): DiskVerdict {
  if (depth > MAX_DEPTH) return hasUnquotedDisk(command) ? "ambiguous" : "none";
  if (command.length > MAX_CHARS) return hasUnquotedDisk(command) ? "ambiguous" : "none";
  const tok = tokenize(command, budget);
  if (tok === "none" || tok === "ambiguous" || tok === "match") return tok;
  let verdict: DiskVerdict = "none";
  for (const body of tok.nested) verdict = worse(verdict, classifyCommand(body, depth + 1, budget));
  if (verdict === "match") return verdict;
  for (const segment of tok.segments) verdict = worse(verdict, classifyWords(segment, depth, budget));
  return verdict;
}

const DISK_MENTION = /(?:^|[^A-Za-z0-9_-])(?:dd|mkfs(?:\.[A-Za-z0-9]+)?|fdisk|parted)(?![A-Za-z0-9_-])/i;

export function analyzeDiskOverwrite(command: string): DiskVerdict {
  if (!command || !DISK_MENTION.test(command)) return "none";
  return classifyCommand(command, 0, { steps: 0 });
}
