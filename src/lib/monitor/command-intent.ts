import { isDataProgram, literalNodeExecutions } from "./node-data.ts";

interface Segment {
  argv: string[];
  source: string;
  separator: string;
}

/** A bounded, literal shell subset. Unknown expansion/escaping never earns an exemption. */
function literalSegments(command: string): Segment[] | null {
  if (!command || command.length > 16_384 || command.includes("%")) return null;
  const segments: Segment[] = [];
  let argv: string[] = [],
    word = "",
    active = false,
    quote = "",
    start = 0;
  const finishWord = () => {
    if (active) argv.push(word);
    word = "";
    active = false;
  };
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) quote = "";
      else {
        // Backslash/backtick/expansion differ across POSIX, cmd and PowerShell.
        if (quote === '"' && /[$`%\\]/.test(c)) return null;
        word += c;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      active = true;
      continue;
    }
    if (c === "\r" || c === "\n") return null;
    if (/\s/.test(c)) {
      finishWord();
      continue;
    }
    if (c === ";" || c === "|" || c === "&") {
      finishWord();
      if (!argv.length) return null;
      let separator = c;
      if (command[i + 1] === c && c !== ";") separator += command[++i];
      if (separator === "&") return null;
      segments.push({ argv, source: command.slice(start, i + 1 - separator.length), separator });
      argv = [];
      start = i + 1;
      continue;
    }
    if (/[$`%\\\r\n<>#(){}]/.test(c)) return null;
    active = true;
    word += c;
  }
  if (quote) return null;
  finishWord();
  if (!argv.length) return null;
  segments.push({ argv, source: command.slice(start), separator: "" });
  return segments.length <= 32 ? segments : null;
}

function tarRead(argv: string[]): boolean {
  if (argv[0] !== "tar" && argv[0] !== "tar.exe") return false;
  let mode = "";
  const setMode = (value: string) => {
    if (mode) return false;
    mode = value;
    return true;
  };
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--list" || arg === "--extract" || arg === "--get") {
      if (!setMode(arg === "--list" ? "t" : "x")) return false;
    } else if (/^--(?:file|directory)=.+$/.test(arg)) continue;
    else if (arg === "--file" || arg === "--directory" || arg === "-C") {
      if (!argv[++i] || argv[i].startsWith("-")) return false;
    } else if (["--gzip", "--gunzip", "--bzip2", "--xz", "--verbose"].includes(arg)) continue;
    else if (arg.startsWith("--")) return false;
    else if (arg.startsWith("-") || (i === 1 && /^[txvzjJOf]+$/.test(arg))) {
      const flags = arg.replace(/^-/, "");
      if (!flags || !/^[txvzjJOf]+$/.test(flags)) return false;
      for (const f of flags) if ((f === "t" || f === "x") && !setMode(f)) return false;
      if (flags.includes("f")) {
        if (!flags.endsWith("f") || !argv[++i] || argv[i].startsWith("-")) return false;
      }
    } else if (!mode || /[*?[\]]/.test(arg)) return false;
  }
  return mode === "t" || mode === "x";
}

const ARCHIVE = /\b(tar|zip|7z|cpio|git\s+archive|git\s+bundle)\b/i;

/** Keep legacy conservative detection except for explicitly understood tar reads. */
export function hasArchiveCreation(command: string): boolean {
  if (!ARCHIVE.test(command)) return false;
  const segments = literalSegments(command);
  if (!segments) return true;
  // Output piped to an interpreter/unknown consumer can itself be executable.
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i].separator === "|" && !/^(?:head|Select-Object)$/.test(segments[i + 1].argv[0]))
      return true;
  }
  return segments.some((segment) => !tarRead(segment.argv) && ARCHIVE.test(segment.source));
}

/** Only one literal Node eval invocation with an AST-proven data program qualifies. */
function inlineNodeSource(command: string): string | undefined {
  if (!/\bnode(?:\.exe)?\b/.test(command)) return undefined;
  const segments = literalSegments(command);
  if (!segments || segments.length !== 1) return undefined;
  const argv = segments[0].argv;
  if (argv[0] !== "node" && argv[0] !== "node.exe") return undefined;
  let index = 1;
  if (argv[index] === "--input-type=module" || argv[index] === "--input-type=commonjs") index++;
  if (argv[index] !== "-e" && argv[index] !== "--eval") return undefined;
  return argv.length === index + 2 ? argv[index + 1] : undefined;
}

export function isNodeDataCommand(command: string): boolean {
  const source = inlineNodeSource(command);
  return source !== undefined && isDataProgram(source);
}

export function nodeShellCommands(command: string): Array<{ command: string; args?: string[] }> {
  const source = inlineNodeSource(command);
  return source === undefined ? [] : literalNodeExecutions(source);
}

/** Double-quoted literal echo is data on the supported shells; unknown forms stay checked. */
export function isDataOnlyCommand(command: string): boolean {
  if (isNodeDataCommand(command)) return true;
  return /^echo\s+"[^"\r\n]*"\s*$/.test(command) && literalSegments(command)?.length === 1;
}
