import type { CanonicalTool, ThreatKind } from "./types";

/** Matched by parsed action + install object. Engine skips these regexes. */
export const SELF_PROTECTION_RULE_IDS = new Set([
  "monitor_self_tamper",
  "monitor_self_tamper_cmd",
  "isolate_delete_binary",
  "isolate_stop_container",
  "isolate_kill_monitor",
  "kill_monitor_process",
]);

export interface SelfProtectionInput {
  tool: CanonicalTool;
  nativeTool?: string;
  command?: string;
  filePath?: string;
  cwd?: string;
}

export type SelfProtectionRuleId =
  | "monitor_self_tamper"
  | "monitor_self_tamper_cmd"
  | "isolate_delete_binary"
  | "isolate_stop_container"
  | "isolate_kill_monitor";

export interface SelfProtectionHit {
  ruleId: SelfProtectionRuleId;
  family: Extract<ThreatKind, "tamper" | "isolate">;
}

const READ_TOOLS = new Set<CanonicalTool>(["Read", "Glob", "Grep"]);
const WRITE_TOOLS = new Set<CanonicalTool>(["Write", "Edit", "MultiEdit"]);
const READ_NATIVE = /^(read_file|read|glob|grep|list_dir|list)$/i;

const PREFIX_VERBS = new Set(["sudo", "command", "exec", "nohup", "builtin", "time", "nice", "then"]);

const DELETE_VERBS = new Set(["rm", "rmdir", "unlink", "erase", "del", "remove-item", "clear-content"]);
const MOVE_VERBS = new Set(["mv", "move", "ren", "rename", "move-item", "rename-item"]);
const WRITE_VERBS = new Set(["set-content", "add-content", "out-file", "new-item", "tee"]);
const COPY_VERBS = new Set(["cp", "copy", "copy-item"]);

const STOP_UNITS = new Set(["nmzp", "nmzp.service"]);
const KILL_PROCS = new Set(["nmzp-monitor", "nmzp-probe", "nmzp-monitor.exe", "nmzp-probe.exe"]);
const STOP_TASKS = new Set(["nmzpprobe"]);

const VALUE_FLAGS = new Set([
  "-path",
  "-literalpath",
  "-destination",
  "-target",
  "-value",
  "-values",
  "-encoding",
  "-erroraction",
  "-warningaction",
  "-itemtype",
  "-name",
  "-filter",
  "-include",
  "-exclude",
  "-filepath",
  "-inputobject",
  "-id",
  "-taskname",
  "-displayname",
  "--time",
  "-t",
  "--signal",
  "-s",
  "--pid",
  "--ppid",
  "--user",
  "-u",
  "-p",
  "--name",
  "--filter",
  "--type",
]);

type MutKind = "delete" | "move" | "write" | "copy";

/**
 * Unconfirmed targets (variables, nested -c/-e/-Command strings, interpolated paths)
 * are not treated as protected. No live manifest; well-known install locations only.
 */
export function detectSelfProtection(input: SelfProtectionInput): SelfProtectionHit | undefined {
  if (READ_TOOLS.has(input.tool) || READ_NATIVE.test(input.nativeTool ?? "")) return undefined;

  if (WRITE_TOOLS.has(input.tool)) {
    const target = resolveToolPath(input.filePath ?? "", input.cwd);
    if (target && isProtectedInstallPath(target)) {
      return { ruleId: "monitor_self_tamper", family: "tamper" };
    }
    return undefined;
  }

  const command = input.command?.trim() ?? "";
  if (!command) return undefined;

  for (const stmt of splitStatements(command)) {
    const hit = inspectStatement(stmt, input.cwd);
    if (hit) return hit;
  }
  return undefined;
}

/** 复用动作解析，供信任库等保护对象检查写入目标；不把命令中提到的任意路径都当作写入。 */
export function mutatedPaths(input: SelfProtectionInput): string[] {
  if (READ_TOOLS.has(input.tool) || READ_NATIVE.test(input.nativeTool ?? "")) return [];
  if (WRITE_TOOLS.has(input.tool)) {
    return input.filePath ? [resolveToolPath(input.filePath, input.cwd)] : [];
  }
  if (input.tool !== "Bash") return [];
  return splitStatements(input.command ?? "").flatMap((stmt) => {
    const redirs = redirectionDests(stmt);
    const parsed = verbAndArgs(tokenize(stripRedirections(stmt)));
    const kind = parsed ? mutKind(normalizeVerb(parsed.verb)) : undefined;
    const targets = kind && parsed ? mutationTargets(kind, parseArgs(parsed.args), redirs) : redirs;
    return targets.map((p) => resolveToolPath(p, input.cwd)).filter(Boolean);
  });
}

export function normalizeFsPath(input: string): string {
  let raw = input.trim();
  if (raw.length >= 2) {
    const a = raw[0];
    const b = raw[raw.length - 1];
    if ((a === '"' && b === '"') || (a === "'" && b === "'")) raw = raw.slice(1, -1);
  }
  const slash = raw.replace(/\\/g, "/").replace(/\/+/g, "/");
  const driveMatch = /^[A-Za-z]:/.exec(slash);
  const drive = driveMatch ? driveMatch[0] : "";
  const rest = drive ? slash.slice(2) : slash;
  const tilde = rest === "~" || rest.startsWith("~/");
  const abs = rest.startsWith("/") || Boolean(drive);
  const bits = rest.split("/").filter((b) => b !== "" && b !== ".");
  const stack: string[] = [];
  for (const b of bits) {
    if (b === "..") {
      if (stack.length === 0) {
        if (!abs && !tilde) stack.push("..");
        continue;
      }
      const top = stack[stack.length - 1];
      if (top === ".." || top === "~") continue;
      stack.pop();
      continue;
    }
    stack.push(b);
  }
  const body = stack.join("/");
  if (drive) return body ? `${drive}/${body}` : `${drive}/`;
  if (tilde) return body || "~";
  if (abs) return `/${body}`;
  return body;
}

export function resolveToolPath(path: string, cwd?: string): string {
  const n = normalizeFsPath(path);
  if (!n) return "";
  if (n.startsWith("/") || n.startsWith("~") || /^[A-Za-z]:/.test(n)) return n;
  if (!cwd) return n;
  const base = normalizeFsPath(cwd);
  if (!base) return n;
  return normalizeFsPath(`${base.replace(/\/$/, "")}/${n}`);
}

/** Home-relative .nmzp / dedicated hook, or exact /opt/nmzp and /var/lib/nmzp. */
export function isProtectedInstallPath(path: string): boolean {
  const n = normalizeFsPath(path);
  if (!n) return false;
  const parts = segments(n);
  const lower = parts.map((s) => s.toLowerCase());
  if (isExactDeployPrefix(lower, ["opt", "nmzp"])) return true;
  if (isExactDeployPrefix(lower, ["var", "lib", "nmzp"])) return true;
  if (isHomeGrokHook(lower)) return true;
  return isHomeNmzp(lower);
}

function segments(normalized: string): string[] {
  return normalized.replace(/^[A-Za-z]:/, "").split("/").filter(Boolean);
}

function isExactDeployPrefix(lower: string[], prefix: string[]): boolean {
  if (lower.length < prefix.length) return false;
  return prefix.every((p, i) => lower[i] === p);
}

function isHomeNmzp(lower: string[]): boolean {
  if (lower[0] === "~" && lower[1] === ".nmzp") return true;
  if (lower[0] === "root" && lower[1] === ".nmzp") return true;
  if (lower[0] === "home" && lower.length >= 3 && lower[2] === ".nmzp") return true;
  if (lower[0] === "users" && lower.length >= 3 && lower[2] === ".nmzp") return true;
  return false;
}

function isHomeGrokHook(lower: string[]): boolean {
  let i = -1;
  if (lower[0] === "~" && lower[1] === ".grok") i = 1;
  else if (lower[0] === "root" && lower[1] === ".grok") i = 1;
  else if (lower[0] === "home" && lower[2] === ".grok") i = 2;
  else if (lower[0] === "users" && lower[2] === ".grok") i = 2;
  if (i < 0) return false;
  return lower[i] === ".grok" && lower[i + 1] === "hooks" && lower[i + 2] === "nmzp.json" && i + 3 === lower.length;
}

function inspectStatement(stmt: string, cwd?: string): SelfProtectionHit | undefined {
  const redirs = redirectionDests(stmt);
  const tokens = tokenize(stripRedirections(stmt));
  const parsed = verbAndArgs(tokens);
  if (!parsed) {
    if (redirs.some((p) => isProtectedInstallPath(resolveToolPath(p, cwd)))) {
      return { ruleId: "monitor_self_tamper_cmd", family: "tamper" };
    }
    return undefined;
  }
  const verb = normalizeVerb(parsed.verb);
  const args = parseArgs(parsed.args);

  const stop = inspectStopKill(verb, args);
  if (stop) return stop;

  const kind = mutKind(verb);
  if (kind) {
    const targets = mutationTargets(kind, args, redirs).map((p) => resolveToolPath(p, cwd));
    if (targets.some((p) => p && isProtectedInstallPath(p))) {
      if (kind === "delete") return { ruleId: "isolate_delete_binary", family: "isolate" };
      return { ruleId: "monitor_self_tamper_cmd", family: "tamper" };
    }
  }

  if (redirs.some((p) => isProtectedInstallPath(resolveToolPath(p, cwd)))) {
    return { ruleId: "monitor_self_tamper_cmd", family: "tamper" };
  }
  return undefined;
}

function inspectStopKill(verb: string, args: ParsedArgs): SelfProtectionHit | undefined {
  const pos = args.positionals;
  if (verb === "systemctl") {
    const action = pos[0];
    const unit = pos[1];
    if (action && /^(stop|disable|kill|mask)$/i.test(action) && unit && STOP_UNITS.has(unit.toLowerCase())) {
      return { ruleId: "isolate_stop_container", family: "isolate" };
    }
    return undefined;
  }
  if (verb === "service") {
    const a = pos[0]?.toLowerCase();
    const b = pos[1]?.toLowerCase();
    if (a && STOP_UNITS.has(a) && b === "stop") return { ruleId: "isolate_stop_container", family: "isolate" };
    if (a === "stop" && b && STOP_UNITS.has(b)) return { ruleId: "isolate_stop_container", family: "isolate" };
    return undefined;
  }
  if (verb === "docker") {
    const sub = pos[0]?.toLowerCase();
    if (sub === "network" && pos[1]?.toLowerCase() === "disconnect") {
      if (pos.slice(2).some((n) => STOP_UNITS.has(n.toLowerCase()))) {
        return { ruleId: "isolate_stop_container", family: "isolate" };
      }
      return undefined;
    }
    if (sub === "stop" || sub === "kill" || sub === "rm") {
      if (pos.slice(1).some((n) => STOP_UNITS.has(n.toLowerCase()))) {
        return { ruleId: "isolate_stop_container", family: "isolate" };
      }
    }
    return undefined;
  }
  if (verb === "sc") {
    if (pos[0]?.toLowerCase() === "stop" && pos[1] && STOP_UNITS.has(pos[1].toLowerCase())) {
      return { ruleId: "isolate_stop_container", family: "isolate" };
    }
    return undefined;
  }
  if (verb === "stop-service" || verb === "disable-service") {
    const names = [...(args.named["-name"] ?? []), ...pos];
    if (names.some((n) => STOP_UNITS.has(n.toLowerCase()))) {
      return { ruleId: "isolate_stop_container", family: "isolate" };
    }
    return undefined;
  }
  if (verb === "stop-scheduledtask" || verb === "disable-scheduledtask") {
    const names = [...(args.named["-taskname"] ?? []), ...pos];
    if (names.some((n) => STOP_TASKS.has(n.toLowerCase()))) {
      return { ruleId: "isolate_stop_container", family: "isolate" };
    }
    return undefined;
  }
  if (verb === "kill" || verb === "pkill" || verb === "killall" || verb === "stop-process") {
    const names = [...(args.named["-name"] ?? []), ...pos];
    if (names.some((n) => KILL_PROCS.has(n.toLowerCase()))) {
      return { ruleId: "isolate_kill_monitor", family: "isolate" };
    }
    return undefined;
  }
  return undefined;
}

function mutKind(verb: string): MutKind | undefined {
  if (DELETE_VERBS.has(verb)) return "delete";
  if (MOVE_VERBS.has(verb)) return "move";
  if (WRITE_VERBS.has(verb)) return "write";
  if (COPY_VERBS.has(verb)) return "copy";
  return undefined;
}

function mutationTargets(kind: MutKind, args: ParsedArgs, redirs: string[]): string[] {
  if (kind === "copy") {
    const dest = [...(args.named["-destination"] ?? []), ...(args.named["-target"] ?? [])];
    if (dest.length) return dest;
    if (redirs.length) return redirs;
    return args.positionals.length ? [args.positionals[args.positionals.length - 1]!] : [];
  }
  if (kind === "write") {
    const flagged = [
      ...(args.named["-path"] ?? []),
      ...(args.named["-literalpath"] ?? []),
      ...(args.named["-filepath"] ?? []),
      ...(args.named["-destination"] ?? []),
      ...(args.named["-target"] ?? []),
    ];
    if (flagged.length) return [...flagged, ...redirs];
    const pos = args.positionals[0] ? [args.positionals[0]] : [];
    return [...pos, ...redirs];
  }
  return [
    ...(args.named["-path"] ?? []),
    ...(args.named["-literalpath"] ?? []),
    ...(args.named["-destination"] ?? []),
    ...(args.named["-target"] ?? []),
    ...args.positionals.filter(looksLikePath),
    ...redirs,
  ];
}

interface ParsedArgs {
  named: Record<string, string[]>;
  positionals: string[];
}

function parseArgs(args: string[]): ParsedArgs {
  const named: Record<string, string[]> = {};
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const tok = args[i]!;
    if (tok === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (!isFlag(tok)) {
      positionals.push(tok);
      continue;
    }
    const eq = tok.indexOf("=");
    if (eq > 0) {
      const key = tok.slice(0, eq).toLowerCase();
      (named[key] ??= []).push(tok.slice(eq + 1));
      continue;
    }
    const key = tok.toLowerCase();
    if (isValueFlag(tok) && i + 1 < args.length && !isFlag(args[i + 1]!)) {
      (named[key] ??= []).push(args[++i]!);
    }
  }
  return { named, positionals };
}

function isValueFlag(tok: string): boolean {
  return VALUE_FLAGS.has(tok.toLowerCase());
}

function isFlag(tok: string): boolean {
  if (tok === "-" || tok === "--") return false;
  return tok.startsWith("-") && !/^[A-Za-z]:/.test(tok);
}

function verbAndArgs(tokens: string[]): { verb: string; args: string[] } | undefined {
  let i = 0;
  while (i < tokens.length && (/^[A-Za-z_][\w]*\+?=/.test(tokens[i]!) || tokens[i] === "&")) i += 1;
  while (i < tokens.length && PREFIX_VERBS.has(normalizeVerb(tokens[i]!))) {
    i += 1;
    while (i < tokens.length && isFlag(tokens[i]!)) {
      if (isValueFlag(tokens[i]!) && i + 1 < tokens.length && !isFlag(tokens[i + 1]!)) i += 2;
      else i += 1;
    }
  }
  if (i >= tokens.length) return undefined;
  return { verb: tokens[i]!, args: tokens.slice(i + 1) };
}

function normalizeVerb(verb: string): string {
  return verb.replace(/\.exe$/i, "").toLowerCase();
}

function splitStatements(command: string): string[] {
  const out: string[] = [];
  let buf = "";
  let quote: string | undefined;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (quote) {
      buf += c;
      if (c === "\\" && quote === '"') {
        if (i + 1 < command.length) buf += command[++i]!;
        continue;
      }
      if (c === quote) quote = undefined;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      buf += c;
      continue;
    }
    if (c === "\n" || c === ";") {
      if (buf.trim()) out.push(buf.trim());
      buf = "";
      continue;
    }
    if (c === "&" && command[i + 1] === "&") {
      if (buf.trim()) out.push(buf.trim());
      buf = "";
      i += 1;
      continue;
    }
    if (c === "|" && command[i + 1] === "|") {
      if (buf.trim()) out.push(buf.trim());
      buf = "";
      i += 1;
      continue;
    }
    buf += c;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function tokenize(command: string): string[] {
  const out: string[] = [];
  const re = /(["'])((?:\\.|[^\\])*?)\1|[^\s;|&]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(command))) {
    out.push(m[2] ?? m[0]!);
  }
  return out;
}

function redirectionDests(stmt: string): string[] {
  const dests: string[] = [];
  let quote: string | undefined;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i]!;
    if (quote) {
      if (c === "\\" && quote === '"') {
        i += 1;
        continue;
      }
      if (c === quote) quote = undefined;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    if (c === ">" && stmt[i - 1] !== ">") {
      let j = i + 1;
      if (stmt[j] === ">") j += 1;
      while (j < stmt.length && /\s/.test(stmt[j]!)) j += 1;
      const next = readToken(stmt, j);
      if (next.token) dests.push(next.token);
      i = next.end - 1;
    }
  }
  return dests;
}

function stripRedirections(stmt: string): string {
  let out = "";
  let quote: string | undefined;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i]!;
    if (quote) {
      out += c;
      if (c === "\\" && quote === '"') {
        if (i + 1 < stmt.length) out += stmt[++i]!;
        continue;
      }
      if (c === quote) quote = undefined;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      out += c;
      continue;
    }
    if (c === ">" || (c >= "0" && c <= "9" && stmt[i + 1] === ">")) {
      if (c >= "0" && c <= "9") i += 1;
      if (stmt[i + 1] === ">") i += 1;
      i += 1;
      while (i < stmt.length && /\s/.test(stmt[i]!)) i += 1;
      const next = readToken(stmt, i);
      i = next.end - 1;
      continue;
    }
    out += c;
  }
  return out;
}

function readToken(s: string, start: number): { token: string; end: number } {
  if (start >= s.length) return { token: "", end: start };
  const q = s[start];
  if (q === "'" || q === '"') {
    let i = start + 1;
    let tok = "";
    while (i < s.length && s[i] !== q) {
      if (s[i] === "\\" && q === '"') {
        i += 1;
        if (i < s.length) tok += s[i]!;
        i += 1;
        continue;
      }
      tok += s[i]!;
      i += 1;
    }
    return { token: tok, end: Math.min(i + 1, s.length) };
  }
  let i = start;
  while (i < s.length && !/\s|;|&/.test(s[i]!)) i += 1;
  return { token: s.slice(start, i), end: i };
}

function looksLikePath(s: string): boolean {
  if (!s) return false;
  if (s.startsWith("-") && !/^[A-Za-z]:/.test(s)) return false;
  if (s.startsWith("~") || s.startsWith("/") || s.startsWith(".") || /^[A-Za-z]:[\\/]/.test(s)) return true;
  return s.includes("/") || s.includes("\\");
}
