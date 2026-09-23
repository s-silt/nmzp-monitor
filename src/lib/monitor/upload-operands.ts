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
  if (extracted.calls.some((call) => explicitUploadPaths(call.command, call.args).length > 0))
    return true;
  if (extracted.incomplete && commands.test(command)) return true;
  commands.lastIndex = 0;
  let budget = 1_048_576;
  for (const match of command.matchAll(commands)) {
    const tail = command.slice(match.index);
    // An exceeded scan budget is unknown, never proof that the script is harmless.
    if (tail.length > 262_144 || (budget -= tail.length) < 0) return true;
    if (explicitUploadPaths(tail).length > 0) return true;
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

export function explicitUploadPaths(command: string, args?: string[], depth = 0): string[] {
  if (depth > 3 || command.length > 262144) return [];
  if (args) {
    const bin = basename(command);
    const at = args.findIndex((v) => /^(?:-c|-lc|-command|\/c)$/i.test(v));
    if (["sh", "bash", "zsh", "pwsh", "powershell", "cmd"].includes(bin) && at >= 0)
      return explicitUploadPaths(args.slice(at + 1).join(" "), undefined, depth + 1);
    return fileOperands([command, ...args]);
  }
  const out: string[] = [];
  let statement: string[] = [];
  let word = "";
  let hasWord = false;
  const pushWord = () => {
    if (hasWord) statement.push(word);
    word = "";
    hasWord = false;
  };
  const flush = () => {
    while (["sudo", "exec", "command", "call"].includes(statement[0])) statement.shift();
    if (statement.length)
      out.push(...explicitUploadPaths(statement[0], statement.slice(1), depth + 1));
    statement = [];
  };
  // Quoted separators remain one argument; echo/documentation is not an upload command.
  for (const match of command.matchAll(TOKENS)) {
    if (match[4] || match[5]) {
      pushWord();
      if (match[4]) flush();
    } else {
      word += match[1] ?? match[2] ?? match[3];
      hasWord = true;
    }
  }
  pushWord();
  flush();
  return out;
}

export function hasSourceUpload(command: string): boolean {
  return explicitUploadPaths(command).some(
    (path) =>
      /(?:^|[/\\])(?:\.git(?:[/\\]|$)|\.env(?:\.|$)|id_rsa$|id_ed25519$)|\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|kts|c|cc|cpp|h|hpp|cs|php|rb|swift|vue|svelte|sql|ipynb)$/i.test(
        path,
      ) || /(?:^|[/\\])zcode-diagnostic-logs\.zip$/i.test(path),
  );
}
