/** Bounded literal command analysis. Never expands variables or reads referenced files. */
import { literalScriptExecutions } from "./node-data.ts";
const TOKENS = /"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s"';&|]+)|([;&|\r\n]+)|(\s+)/g;
const basename = (s: string) =>
  s
    .replace(/\\/g, "/")
    .split("/")
    .pop()!
    .toLowerCase()
    .replace(/\.exe$/, "");
const CURL_FILE_FLAGS = new Set(["-T", "--upload-file"]);
const CURL_DATA_FLAGS = new Set([
  "-d",
  "--data",
  "--data-binary",
  "--data-ascii",
  "--data-urlencode",
]);

/**
 * Conservative script fallback, not a JavaScript execution model. Known executor
 * syntax plus possible file operands remains guarded even when AST extraction
 * is incomplete. Operand semantics stay in the same curl/wget parser below.
 */
export function hasPotentialScriptFileUpload(command: string): boolean {
  if (
    !/\b(?:execSync|spawnSync|spawn|execFile|execFileSync|eval|Function)\s*\(/.test(command) &&
    !command.includes("child_process")
  )
    return false;
  const commands = /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/gi;
  const extracted = literalScriptExecutions(command);
  if (extracted.calls.some((call) => guardedUpload(call.command, call.args))) return true;
  if (extracted.incomplete && commands.test(command)) return true;
  commands.lastIndex = 0;
  let budget = 1_048_576;
  for (const match of command.matchAll(commands)) {
    const tail = command.slice(match.index);
    // An exceeded scan budget is unknown, never proof that the script is harmless.
    if (tail.length > 262_144 || (budget -= tail.length) < 0) return true;
    if (guardedUpload(tail)) return true;
  }
  return false;
}

function fileOperands(argv: string[]): string[] {
  const bin = basename(argv[0] ?? "");
  const out: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    let flag = argv[i];
    let value: string | undefined;
    const eq = flag.startsWith("--") ? flag.indexOf("=") : -1;
    if (eq > 0) {
      value = flag.slice(eq + 1);
      flag = flag.slice(0, eq);
    } else if (bin === "curl" && /^-[TFd].+/.test(flag)) {
      value = flag.slice(2);
      flag = flag.slice(0, 2);
    }
    if (bin === "curl") {
      if (
        !CURL_FILE_FLAGS.has(flag) &&
        !CURL_DATA_FLAGS.has(flag) &&
        flag !== "-F" &&
        flag !== "--form"
      )
        continue;
      value ??= argv[++i];
      if (!value) continue;
      if (CURL_FILE_FLAGS.has(flag)) out.push(value);
      // --data-raw and --form-string deliberately excluded: @ is literal there.
      else if (flag === "-F" || flag === "--form") {
        const match = /^[^=]+=[@<](.+)$/.exec(value);
        if (match) out.push(match[1].split(";")[0]);
      } else if (value.startsWith("@")) out.push(value.slice(1));
      else if (flag === "--data-urlencode" && value.includes("@"))
        out.push(value.slice(value.indexOf("@") + 1));
    } else if (bin === "wget" && flag === "--post-file") {
      value ??= argv[++i];
      if (value) out.push(value);
    } else if (
      ["invoke-webrequest", "invoke-restmethod", "iwr", "irm"].includes(bin) &&
      flag.toLowerCase() === "-infile"
    ) {
      value ??= argv[++i];
      if (value) out.push(value);
    }
  }
  return out.filter(Boolean);
}

const MAX_SHELLS = 8;
const MAX_CHARS = 262_144;
const MAX_STEPS = 48_000;
const MAX_PATHS = 64;
const MAX_STATEMENTS = 512;
const MAX_JOBS = 4_096;
const SHELLS = new Set(["sh", "bash", "zsh", "pwsh", "powershell", "cmd"]);
const LEAD = new Set(["sudo", "exec", "command", "call", "env"]);
const SHELL_FLAG = /^(?:-c|-lc|-command|--command|\/c)$/i;
const SOURCE_OPERAND =
  /(?:^|[/\\])(?:\.git(?:[/\\]|$)|\.env(?:\.|$)|id_rsa$|id_ed25519$)|\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|kts|c|cc|cpp|h|hpp|cs|php|rb|swift|vue|svelte|sql|ipynb)$/i;
const DIAGNOSTIC_ARCHIVE = /(?:^|[/\\])zcode-diagnostic-logs\.zip$/i;

interface Budget {
  steps: number;
}

interface Found {
  paths: string[];
  suspicious: boolean;
}

interface Job {
  command: string;
  args?: string[];
  shells: number;
  past: boolean;
}

type Unwrapped =
  | { kind: "run"; bin: string; args: string[] }
  | { kind: "script"; text: string }
  | { kind: "none" };

function isAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function isLocalOperand(path: string): boolean {
  return path !== "-" && path !== "/dev/stdin" && path !== "/dev/fd/0";
}

function isSourceOperand(path: string): boolean {
  return SOURCE_OPERAND.test(path) || DIAGNOSTIC_ARCHIVE.test(path);
}

function takesArg(bin: string, flag: string): boolean {
  if (bin === "sudo") {
    return (
      flag === "-u" || flag === "-g" || flag === "-p" || flag === "-C" || flag === "-D" ||
      flag === "-h" || flag === "-R" || flag === "-T" || flag === "-U" || flag === "-r" ||
      flag === "-t" || flag === "--user" || flag === "--group" || flag === "--prompt" ||
      flag === "--chdir" || flag === "--role" || flag === "--type" || flag === "--host" ||
      flag === "--command-timeout" || flag === "--close-from" || flag === "--other-user" ||
      flag === "--chroot"
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

/** Known prefixes only. The next word is not executed when the prefix is a query. */
function advance(bin: string, words: string[], index: number): number | Unwrapped {
  let i = index;
  while (i < words.length) {
    const token = words[i];
    if (bin === "env" && isAssignment(token)) {
      i += 1;
      continue;
    }
    if (token === "--") return i + 1;
    if (!token.startsWith("-") || token === "-") return i;
    const eq = token.startsWith("--") ? token.indexOf("=") : -1;
    const name = eq > 0 ? token.slice(0, eq) : token;
    if (nonExec(bin, name)) return { kind: "none" };
    if (bin === "env" && (name === "-S" || name === "--split-string")) {
      const script = eq > 0 ? token.slice(eq + 1) : words[i + 1];
      if (!script) return { kind: "none" };
      return { kind: "script", text: script };
    }
    if (takesArg(bin, name)) {
      if (eq > 0) {
        i += 1;
        continue;
      }
      if (i + 1 >= words.length) return { kind: "none" };
      i += 2;
      continue;
    }
    if (noArg(bin, name)) {
      i += 1;
      continue;
    }
    let j = i + 1;
    while (j < words.length && (words[j].startsWith("-") || isAssignment(words[j]))) j += 1;
    return j;
  }
  return i;
}

function unwrapWords(words: string[]): Unwrapped {
  let i = 0;
  for (let guard = 0; guard < 32; guard += 1) {
    while (i < words.length && isAssignment(words[i])) i += 1;
    if (i >= words.length) return { kind: "none" };
    const bin = basename(words[i]);
    if (!LEAD.has(bin)) return { kind: "run", bin: words[i], args: words.slice(i + 1) };
    const next = advance(bin, words, i + 1);
    if (typeof next !== "number") return next;
    i = next;
  }
  return { kind: "script", text: words.slice(i).join(" ") };
}

function quoteOpen(text: string): boolean {
  let quote = "";
  const end = Math.min(text.length, MAX_CHARS * 2);
  for (let i = 0; i < end; i += 1) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"') quote = c;
  }
  return quote !== "";
}

function splitStatements(command: string, budget: Budget): { statements: string[][]; rest: string } {
  const statements: string[][] = [];
  let statement: string[] = [];
  let word = "";
  let hasWord = false;
  const pushWord = () => {
    if (!hasWord) return;
    statement.push(word);
    word = "";
    hasWord = false;
  };
  TOKENS.lastIndex = 0;
  for (const match of command.matchAll(TOKENS)) {
    if (budget.steps > MAX_STEPS || statements.length >= MAX_STATEMENTS) {
      pushWord();
      if (statement.length) statements.push(statement);
      return { statements, rest: command.slice(match.index ?? 0) };
    }
    budget.steps += 1;
    if (match[4] || match[5]) {
      pushWord();
      if (match[4] && statement.length) {
        statements.push(statement);
        statement = [];
      }
    } else {
      word += match[1] ?? match[2] ?? match[3] ?? "";
      hasWord = true;
    }
  }
  pushWord();
  if (statement.length) statements.push(statement);
  return { statements, rest: "" };
}

function pushSplit(queue: string[][], text: string): void {
  let rest = text;
  for (let hop = 0; hop < 8 && rest; hop += 1) {
    const split = splitStatements(rest, { steps: 0 });
    queue.push(...split.statements);
    if (!split.rest || split.rest === rest) return;
    rest = split.rest;
  }
}

/** Bounded residue check. Echo and literal @ forms are not local file uploads. */
function uploadHint(text: string): boolean {
  if (!text) return false;
  const samples = [text.slice(0, MAX_CHARS)];
  if (text.length > MAX_CHARS) {
    const tailStart = text.length - MAX_CHARS;
    if (!quoteOpen(text.slice(0, tailStart))) samples.push(text.slice(tailStart));
  }
  for (const sample of samples) {
    const queue: string[][] = [];
    pushSplit(queue, sample);
    let guard = 0;
    while (queue.length && guard < 4_096) {
      guard += 1;
      const statement = queue.shift();
      if (!statement?.length) continue;
      const unwrapped = unwrapWords(statement);
      if (unwrapped.kind === "none") continue;
      if (unwrapped.kind === "script") {
        pushSplit(queue, unwrapped.text);
        continue;
      }
      const name = basename(unwrapped.bin);
      if (SHELLS.has(name)) {
        const at = unwrapped.args.findIndex((value) => SHELL_FLAG.test(value));
        if (at >= 0) pushSplit(queue, unwrapped.args.slice(at + 1).join(" "));
        continue;
      }
      if (fileOperands([unwrapped.bin, ...unwrapped.args]).some(isLocalOperand)) return true;
    }
  }
  return false;
}

function addPaths(found: Found, paths: string[], past: boolean): void {
  const local = paths.filter(isLocalOperand);
  if (past && local.length > 0) found.suspicious = true;
  for (const path of paths) {
    if (!path || found.paths.includes(path)) continue;
    if (found.paths.length >= MAX_PATHS) {
      found.suspicious = true;
      return;
    }
    found.paths.push(path);
  }
}

function enqueueShell(job: Job, inner: string, queue: Job[]): void {
  if (!job.past && job.shells >= MAX_SHELLS) {
    queue.push({ command: inner, shells: job.shells, past: true });
    return;
  }
  queue.push({
    command: inner,
    shells: job.past ? job.shells : job.shells + 1,
    past: job.past,
  });
}

function handleArgv(job: Job, queue: Job[], found: Found, budget: Budget): void {
  if (budget.steps > MAX_STEPS) {
    if (uploadHint([job.command, ...(job.args ?? [])].join(" "))) found.suspicious = true;
    return;
  }
  budget.steps += 1;
  const unwrapped = unwrapWords([job.command, ...(job.args ?? [])]);
  if (unwrapped.kind === "none") return;
  if (unwrapped.kind === "script") {
    queue.push({ command: unwrapped.text, shells: job.shells, past: job.past });
    return;
  }
  const name = basename(unwrapped.bin);
  if (SHELLS.has(name)) {
    const at = unwrapped.args.findIndex((value) => SHELL_FLAG.test(value));
    if (at >= 0) {
      enqueueShell(job, unwrapped.args.slice(at + 1).join(" "), queue);
      return;
    }
  }
  if (unwrapped.args.length > 4_096) {
    if (uploadHint(`${unwrapped.bin} ${unwrapped.args.slice(0, 64).join(" ")}`)) found.suspicious = true;
    return;
  }
  addPaths(found, fileOperands([unwrapped.bin, ...unwrapped.args]), job.past);
}

function handleText(job: Job, queue: Job[], found: Found, budget: Budget): void {
  if (job.command.length > MAX_CHARS) {
    const tailStart = job.command.length - MAX_CHARS;
    queue.push({ command: job.command.slice(0, MAX_CHARS), shells: job.shells, past: true });
    if (tailStart > 0 && !quoteOpen(job.command.slice(0, tailStart))) {
      queue.push({ command: job.command.slice(tailStart), shells: job.shells, past: true });
    }
    return;
  }
  const split = splitStatements(job.command, budget);
  for (const statement of split.statements) {
    if (!statement.length) continue;
    // Shell depth counts only a real shell -c/-Command wrapper.
    queue.push({ command: statement[0], args: statement.slice(1), shells: job.shells, past: job.past });
  }
  if (split.rest && uploadHint(split.rest)) found.suspicious = true;
}

/**
 * Literal argv walk. Never executes a shell.
 * `shells` counts entered sh/bash/zsh/pwsh/cmd -c wrappers, not statement
 * flushes or env/sudo prefixes. Eight wrappers are still parsed. The next
 * wrapper keeps real operands and marks the scan suspicious. Paths are only
 * names taken from the command text.
 */
function collectUploads(command: string, args: string[] | undefined, shells: number): Found {
  const budget: Budget = { steps: 0 };
  const found: Found = { paths: [], suspicious: false };
  const queue: Job[] = [{ command, args, shells, past: shells > MAX_SHELLS }];
  let cursor = 0;
  while (cursor < queue.length) {
    if (budget.steps > MAX_STEPS || cursor >= MAX_JOBS) {
      if (queue.slice(cursor).some((job) => uploadHint(job.args ? [job.command, ...job.args].join(" ") : job.command))) {
        found.suspicious = true;
      }
      break;
    }
    const job = queue[cursor];
    cursor += 1;
    if (job.args !== undefined) handleArgv(job, queue, found, budget);
    else handleText(job, queue, found, budget);
  }
  return found;
}

function guardedUpload(command: string, args?: string[]): boolean {
  const found = collectUploads(command, args, 0);
  // Any parsed operand, including stdin "-", keeps the previous script-guard signal.
  return found.suspicious || found.paths.length > 0;
}

export function explicitUploadPaths(command: string, args?: string[], depth = 0): string[] {
  return collectUploads(command, args, depth).paths;
}

export function hasSourceUpload(command: string): boolean {
  const found = collectUploads(command, undefined, 0);
  return found.suspicious || found.paths.some(isSourceOperand);
}
