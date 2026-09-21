import type { HookAgent } from "./hook-protocol.ts";

/** POSIX/cmd-style quoting for Unix hook commands. Windows uses EncodedCommand instead. */
export function posixQuote(s: string): string {
  if (!/[\s"]/.test(s)) return s;
  return `"${s.replace(/"/g, '\\"')}"`;
}

export function psSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

export function windowsHookInnerScript(nodePath: string, runtimeEntry: string, agent: HookAgent): string {
  return `& ${psSingleQuote(nodePath)} --experimental-strip-types ${psSingleQuote(runtimeEntry)} hook --agent ${agent}; exit $LASTEXITCODE`;
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

function looksLikeNmzpHookCommand(text: string): boolean {
  return /nmzp(?:\.mjs)?/.test(text) && /hook --agent/.test(text);
}

export function isNmzpOwnedHook(h: unknown): boolean {
  if (!h || typeof h !== "object") return false;
  const c = (h as { command?: unknown }).command;
  if (typeof c !== "string") return false;
  const decoded = decodeWindowsEncodedCommand(c);
  if (decoded) return looksLikeNmzpHookCommand(decoded);
  return looksLikeNmzpHookCommand(c);
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
