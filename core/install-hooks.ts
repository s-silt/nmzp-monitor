import { EMERGENCY_DENY } from "./hook-emergency-deny.mjs";
import { HOOK_AGENTS, type HookAgent } from "./hook-protocol.ts";

/** POSIX/cmd-style quoting for Unix hook commands. Windows uses EncodedCommand instead. */
export function posixQuote(s: string): string {
  if (!/[\s"]/.test(s)) return s;
  return `"${s.replace(/"/g, '\\"')}"`;
}

export function psSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

const WINDOWS_CODE_MARKER = "; $nmzpCode = $LASTEXITCODE";

/** Raw EMERGENCY_DENY bytes. Progress noise would change stderr, so it is silenced first. */
function windowsDenyFunction(agent: HookAgent): string {
  const denial = EMERGENCY_DENY[agent];
  if (!denial || (denial.exitCode !== 0 && denial.exitCode !== 2)) throw new Error("nmzp_emergency_deny_missing");
  const stdout = Buffer.from(denial.stdout, "utf8").toString("base64");
  const stderr = denial.stderr ? Buffer.from(denial.stderr, "utf8").toString("base64") : "";
  const errWrite = stderr
    ? `
  $err = [Convert]::FromBase64String('${stderr}')
  if ($err.Length -gt 0) {
    $stderr = [Console]::OpenStandardError()
    $stderr.Write($err, 0, $err.Length)
    $stderr.Flush()
  }`
    : "";
  return `function Exit-NmzpDeny {
  $out = [Convert]::FromBase64String('${stdout}')
  $stdout = [Console]::OpenStandardOutput()
  $stdout.Write($out, 0, $out.Length)
  $stdout.Flush()${errWrite}
  exit ${denial.exitCode}
}`;
}

export function windowsHookInnerScript(nodePath: string, runtimeEntry: string, agent: HookAgent): string {
  const node = psSingleQuote(nodePath);
  const entry = psSingleQuote(runtimeEntry);
  return [
    "$ProgressPreference = 'SilentlyContinue'",
    windowsDenyFunction(agent),
    `if (-not (Test-Path -LiteralPath ${node})) { Exit-NmzpDeny }`,
    `if (-not (Test-Path -LiteralPath ${entry})) { Exit-NmzpDeny }`,
    `& ${node} --experimental-strip-types ${entry} hook --agent ${agent}${WINDOWS_CODE_MARKER}`,
    "if ($null -eq $nmzpCode -or ($nmzpCode -ne 0 -and $nmzpCode -ne 2)) { Exit-NmzpDeny }",
    "exit $nmzpCode",
  ].join("\n");
}

export function encodeWindowsHookCommand(nodePath: string, runtimeEntry: string, agent: HookAgent): string {
  const encoded = Buffer.from(windowsHookInnerScript(nodePath, runtimeEntry, agent), "utf16le").toString("base64");
  return `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encoded}`;
}

export function hookCommand(
  nodePath: string,
  runtimeEntry: string,
  agent: HookAgent,
  os: string = process.platform,
): string {
  if (os === "win32") return encodeWindowsHookCommand(nodePath, runtimeEntry, agent);
  return `${posixQuote(nodePath)} --experimental-strip-types ${posixQuote(runtimeEntry)} hook --agent ${agent}`;
}

const ENCODED_COMMAND_RE = /(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)/i;

export function decodeWindowsEncodedCommand(command: string): string | null {
  const m = ENCODED_COMMAND_RE.exec(command);
  if (!m?.[1]) return null;
  try {
    const decoded = Buffer.from(m[1], "base64").toString("utf16le");
    return decoded.length ? decoded : null;
  } catch {
    return null;
  }
}

function hookTokenBase(token: string): string {
  const normalized = token.replace(/\\/g, "/");
  const cut = normalized.lastIndexOf("/");
  return cut >= 0 ? normalized.slice(cut + 1) : normalized;
}

/**
 * Reporting heuristic only. A token that names `nmzp` is unresolved, not owned.
 * Deletion uses `isNmzpOwnedHook` and does not call this.
 */
function looksLikeNmzpHookCommand(text: string): boolean {
  const windows = parseWindowsInner(text);
  const tokens = windows ? [windows.exe, windows.entry, windows.agent] : tokenizePosixHook(text);
  if (!tokens) return text.includes("nmzp");
  return tokens.some((token) => token.includes("nmzp"));
}

function readHookCommand(h: unknown): string | null {
  if (!h || typeof h !== "object") return null;
  const command = (h as { command?: unknown }).command;
  return typeof command === "string" ? command : null;
}

/** Substring heuristic for leftovers. Not proof that NMZP generated the command. */
export function isNmzpLikeHook(h: unknown): boolean {
  const command = readHookCommand(h);
  if (command === null) return false;
  const decoded = decodeWindowsEncodedCommand(command);
  if (decoded) return looksLikeNmzpHookCommand(decoded);
  return looksLikeNmzpHookCommand(command);
}

const POWERSHELL_HOOK_RE = /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)$/;
const WINDOWS_EXIT_SUFFIX = "; exit $LASTEXITCODE";

function isKnownHookAgent(agent: string): agent is HookAgent {
  return (HOOK_AGENTS as readonly string[]).includes(agent);
}

function isNodeExecutable(exe: string, windows: boolean): boolean {
  const cut = Math.max(exe.lastIndexOf("/"), exe.lastIndexOf("\\"));
  const base = cut >= 0 ? exe.slice(cut + 1) : exe;
  if (!base) return false;
  const name = windows ? base.toLowerCase() : base;
  return name === "node" || name === "node.exe";
}

/** `.nmzp/runtime/<one segment>/nmzp.mjs`, either separator. No filesystem access. */
function isManagedRuntimeEntry(entry: string): boolean {
  if (!entry || entry.endsWith("/") || entry.endsWith("\\")) return false;
  const parts = entry.split(/[/\\]/);
  if (parts.length < 4) return false;
  const file = parts[parts.length - 1];
  const segment = parts[parts.length - 2];
  const runtime = parts[parts.length - 3];
  const home = parts[parts.length - 4];
  if (file !== "nmzp.mjs" || runtime !== "runtime" || home !== ".nmzp") return false;
  return segment.length > 0;
}

function ownedIdentity(exe: string, entry: string, agent: string, windows: boolean): boolean {
  return isNodeExecutable(exe, windows) && isManagedRuntimeEntry(entry) && isKnownHookAgent(agent);
}

/** Exact script name. A managed runtime directory is not required. */
function isExactNmzpScript(entry: string): boolean {
  return hookTokenBase(entry) === "nmzp.mjs";
}

/** Configuration recognition. Not deletion authority and not a receipt. */
function recognizedIdentity(exe: string, entry: string, agent: string, windows: boolean): boolean {
  return isNodeExecutable(exe, windows) && isExactNmzpScript(entry) && isKnownHookAgent(agent);
}

function readPsSingleQuoted(script: string, index: number): { value: string; next: number } | null {
  if (script[index] !== "'") return null;
  let i = index + 1;
  let value = "";
  while (i < script.length) {
    if (script[i] === "'") {
      if (script[i + 1] === "'") {
        value += "'";
        i += 2;
        continue;
      }
      return { value, next: i + 1 };
    }
    value += script[i];
    i += 1;
  }
  return null;
}

/** Call-operator body, without a trailing exit. Unparseable quoting is not owned. */
function parseWindowsCall(body: string): { exe: string; entry: string; agent: string } | null {
  if (!body.startsWith("& ")) return null;
  const exe = readPsSingleQuoted(body, 2);
  if (!exe || body[exe.next] !== " ") return null;
  let i = exe.next + 1;
  if (body.startsWith("--experimental-strip-types ", i)) i += "--experimental-strip-types ".length;
  const entry = readPsSingleQuoted(body, i);
  if (!entry) return null;
  i = entry.next;
  if (!body.startsWith(" hook --agent ", i)) return null;
  const agent = body.slice(i + " hook --agent ".length);
  if (!agent || /\s/.test(agent)) return null;
  return { exe: exe.value, entry: entry.value, agent };
}

/** Installed 0.2.x one-liner: `& 'node' ... hook --agent X; exit $LASTEXITCODE`. */
function parseLegacyWindowsInner(script: string): { exe: string; entry: string; agent: string } | null {
  if (!script.endsWith(WINDOWS_EXIT_SUFFIX)) return null;
  return parseWindowsCall(script.slice(0, -WINDOWS_EXIT_SUFFIX.length));
}

/** Fail-closed wrapper. The legacy one-liner stays recognized by `parseLegacyWindowsInner`. */
function parseFailClosedWindowsInner(script: string): { exe: string; entry: string; agent: string } | null {
  if (!script.includes("function Exit-NmzpDeny")) return null;
  for (const rawLine of script.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line.startsWith("& ") || !line.endsWith(WINDOWS_CODE_MARKER)) continue;
    return parseWindowsCall(line.slice(0, -WINDOWS_CODE_MARKER.length));
  }
  return null;
}

/** Inverse of the legacy one-liner and of `windowsHookInnerScript`. */
function parseWindowsInner(script: string): { exe: string; entry: string; agent: string } | null {
  return parseLegacyWindowsInner(script) ?? parseFailClosedWindowsInner(script);
}

function windowsHookOwned(command: string): boolean {
  const parts = parsedWindowsHookCommand(command);
  if (!parts) return false;
  return ownedIdentity(parts.exe, parts.entry, parts.agent, true);
}

/** Generated Codex command shape, including paths outside `.nmzp/runtime`. Does not execute the command. */
export function isCodexHookCommandShape(command: string): boolean {
  const windows = parsedWindowsHookCommand(command);
  if (windows) return windows.agent === "codex";
  const tokens = tokenizePosixHook(command);
  if (!tokens) return false;
  const base = hookTokenBase(tokens[0] ?? "");
  if (base !== "node" && base !== "node.exe") return false;
  let index = 1;
  if (tokens[index] === "--experimental-strip-types") index += 1;
  if (tokens.length - index !== 4) return false;
  return tokens[index + 1] === "hook" && tokens[index + 2] === "--agent" && tokens[index + 3] === "codex";
}

/** Generated PowerShell hook shape. Not proof of a managed runtime path. */
export function parsedWindowsHookCommand(command: string): { exe: string; entry: string; agent: string } | null {
  const matched = POWERSHELL_HOOK_RE.exec(command);
  if (!matched?.[1]) return null;
  const decoded = Buffer.from(matched[1], "base64").toString("utf16le");
  if (!decoded) return null;
  return parseWindowsInner(decoded);
}

/** Inverse of `posixQuote`: whitespace separates tokens; only `\"` is special inside double quotes. */
function tokenizePosixHook(command: string): string[] | null {
  const tokens: string[] = [];
  let i = 0;
  while (i < command.length) {
    const ch = command[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    if (ch === '"') {
      let value = "";
      i += 1;
      let closed = false;
      while (i < command.length) {
        if (command[i] === "\\" && command[i + 1] === '"') {
          value += '"';
          i += 2;
          continue;
        }
        if (command[i] === '"') {
          i += 1;
          closed = true;
          break;
        }
        value += command[i];
        i += 1;
      }
      if (!closed) return null;
      const next = command[i];
      if (next !== undefined && next !== " " && next !== "\t" && next !== "\n" && next !== "\r") return null;
      tokens.push(value);
      continue;
    }
    let value = "";
    while (i < command.length) {
      const cur = command[i];
      if (cur === " " || cur === "\t" || cur === "\n" || cur === "\r") break;
      if (cur === '"') return null;
      value += cur;
      i += 1;
    }
    tokens.push(value);
  }
  return tokens;
}

function pathLooksWindows(token: string): boolean {
  return token.includes("\\") || /^[A-Za-z]:/.test(token);
}

function posixHookParts(tokens: string[]): { exe: string; entry: string; agent: string; windows: boolean } | null {
  let index = 0;
  const exe = tokens[index++];
  if (tokens[index] === "--experimental-strip-types") index += 1;
  if (tokens.length - index !== 4) return null;
  const entry = tokens[index];
  if (tokens[index + 1] !== "hook" || tokens[index + 2] !== "--agent") return null;
  const agent = tokens[index + 3];
  if (!exe || entry === undefined || agent === undefined) return null;
  return { exe, entry, agent, windows: tokens.some(pathLooksWindows) };
}

function posixTokensOwned(tokens: string[]): boolean {
  const parts = posixHookParts(tokens);
  if (!parts) return false;
  return ownedIdentity(parts.exe, parts.entry, parts.agent, parts.windows);
}

function commandOwned(command: string): boolean {
  if (POWERSHELL_HOOK_RE.test(command)) return windowsHookOwned(command);
  const tokens = tokenizePosixHook(command);
  if (!tokens) return false;
  return posixTokensOwned(tokens);
}

function commandRecognized(command: string): boolean {
  const windows = parsedWindowsHookCommand(command);
  if (windows) return recognizedIdentity(windows.exe, windows.entry, windows.agent, true);
  const tokens = tokenizePosixHook(command);
  if (!tokens) return false;
  const parts = posixHookParts(tokens);
  if (!parts) return false;
  return recognizedIdentity(parts.exe, parts.entry, parts.agent, parts.windows);
}

/** Node plus exact `nmzp.mjs` plus `hook --agent` known id. Does not authorize removal. */
export function isNmzpConfiguredHook(h: unknown): boolean {
  const command = readHookCommand(h);
  if (command === null) return false;
  return commandRecognized(command);
}

export function isNmzpOwnedHook(h: unknown): boolean {
  const command = readHookCommand(h);
  if (command === null) return false;
  return commandOwned(command);
}

export function stripNmzpFromPre(pre: unknown[]): unknown[] {
  const out: unknown[] = [];
  for (const row of pre) {
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      out.push(row);
      continue;
    }
    const rec = row as Record<string, unknown>;
    if (!Array.isArray(rec.hooks)) {
      out.push(row);
      continue;
    }
    const kept = rec.hooks.filter((h) => !isNmzpOwnedHook(h));
    if (kept.length === 0) continue;
    if (kept.length === rec.hooks.length) {
      out.push(row);
      continue;
    }
    out.push({ ...rec, hooks: kept });
  }
  return out;
}

export function mergeClaudeSettings(
  existingRaw: string | null,
  entry: Record<string, unknown>,
): { body: string; created: boolean } {
  let doc: Record<string, unknown> = {};
  if (existingRaw && existingRaw.trim()) {
    try {
      const parsed = JSON.parse(existingRaw) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("not object");
      }
      doc = parsed as Record<string, unknown>;
    } catch {
      throw new Error("claude_settings_corrupt");
    }
  }
  const hooks = (doc.hooks && typeof doc.hooks === "object" && !Array.isArray(doc.hooks) ? doc.hooks : {}) as Record<
    string,
    unknown
  >;
  const pre = Array.isArray(hooks.PreToolUse) ? [...(hooks.PreToolUse as unknown[])] : [];
  const next = stripNmzpFromPre(pre);
  next.push(entry);
  hooks.PreToolUse = next;
  doc.hooks = hooks;
  return { body: JSON.stringify(doc, null, 2) + "\n", created: !existingRaw };
}

export function stripClaudeSettings(existingRaw: string): string {
  let doc: Record<string, unknown>;
  try {
    const parsed = JSON.parse(existingRaw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return existingRaw;
    doc = parsed as Record<string, unknown>;
  } catch {
    return existingRaw;
  }
  const hooks = doc.hooks as Record<string, unknown> | undefined;
  if (!hooks || !Array.isArray(hooks.PreToolUse)) return existingRaw;
  hooks.PreToolUse = stripNmzpFromPre(hooks.PreToolUse as unknown[]);
  doc.hooks = hooks;
  return JSON.stringify(doc, null, 2) + "\n";
}

export function mergeGrokHookFile(
  existingRaw: string | null,
  ours: Record<string, unknown>,
): { body: string; created: boolean } {
  if (!existingRaw || !existingRaw.trim()) {
    return { body: JSON.stringify(ours, null, 2) + "\n", created: true };
  }
  let doc: unknown;
  try {
    doc = JSON.parse(existingRaw);
  } catch {
    throw new Error("grok_hook_corrupt");
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("grok_hook_corrupt");
  const rec = doc as Record<string, unknown>;
  const existingHooks =
    rec.hooks && typeof rec.hooks === "object" && !Array.isArray(rec.hooks)
      ? (rec.hooks as Record<string, unknown>)
      : {};
  const ourHooks =
    ours.hooks && typeof ours.hooks === "object" && !Array.isArray(ours.hooks)
      ? (ours.hooks as Record<string, unknown>)
      : {};
  const pre = Array.isArray(existingHooks.PreToolUse) ? [...(existingHooks.PreToolUse as unknown[])] : [];
  const stripped = stripNmzpFromPre(pre);
  const ourPre = Array.isArray(ourHooks.PreToolUse) ? (ourHooks.PreToolUse as unknown[]) : [];
  existingHooks.PreToolUse = [...stripped, ...ourPre];
  rec.hooks = existingHooks;
  return { body: JSON.stringify(rec, null, 2) + "\n", created: false };
}

export function stripGrokHookFile(existingRaw: string): string {
  try {
    const parsed = JSON.parse(existingRaw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return existingRaw;
    const rec = parsed as Record<string, unknown>;
    const hooks = rec.hooks as Record<string, unknown> | undefined;
    if (!hooks || !Array.isArray(hooks.PreToolUse)) return JSON.stringify(rec, null, 2) + "\n";
    hooks.PreToolUse = stripNmzpFromPre(hooks.PreToolUse as unknown[]);
    rec.hooks = hooks;
    return JSON.stringify(rec, null, 2) + "\n";
  } catch {
    return existingRaw;
  }
}

export type HostFileInspect =
  | { ok: false }
  | { ok: true; next: string; hadOwned: boolean };

/** null when the text is not a JSON object. False when no owned PreToolUse hook is present. */
function ownedPreToolUse(raw: string): boolean | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const hooks = (parsed as Record<string, unknown>).hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return false;
  const pre = (hooks as Record<string, unknown>).PreToolUse;
  if (!Array.isArray(pre)) return false;
  for (const row of pre) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const list = (row as Record<string, unknown>).hooks;
    if (Array.isArray(list) && list.some((hook) => isNmzpOwnedHook(hook))) return true;
  }
  return false;
}

function inspectPreToolUse(raw: string, strip: (raw: string) => string): HostFileInspect {
  const hadOwned = ownedPreToolUse(raw);
  if (hadOwned === null) return { ok: false };
  const next = strip(raw);
  if (hadOwned && ownedPreToolUse(next) !== false) return { ok: false };
  return { ok: true, next, hadOwned };
}

export function inspectClaudeSettings(raw: string): HostFileInspect {
  return inspectPreToolUse(raw, stripClaudeSettings);
}

export function inspectGrokHookFile(raw: string): HostFileInspect {
  return inspectPreToolUse(raw, stripGrokHookFile);
}

export function parseJsonObjectOrThrow(raw: string, code: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(code);
    return parsed as Record<string, unknown>;
  } catch (e) {
    if (e instanceof Error && e.message === code) throw e;
    throw new Error(code);
  }
}
