import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { decodeWindowsEncodedCommand, hookCommand, isNmzpOwnedHook, stripNmzpFromPre } from "./install-hooks.ts";

export const EXTRA_HOOK_AGENTS = ["kimi", "trae", "qwen", "qoder", "lingma", "codebuddy", "gemini", "cursor"] as const;
export type ExtraHookAgent = (typeof EXTRA_HOOK_AGENTS)[number];

function object(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function eventKey(agent: ExtraHookAgent): string {
  if (agent === "gemini") return "BeforeTool";
  if (agent === "cursor") return "preToolUse";
  return "PreToolUse";
}

function ownEntry(agent: ExtraHookAgent, command: string): Record<string, unknown> {
  if (agent === "cursor") return { command, timeout: 8, matcher: ".*" };
  if (agent === "gemini") {
    return { matcher: "", hooks: [{ name: "nmzp", type: "command", command, timeout: 8000 }] };
  }
  if (agent === "trae") {
    return { matcher: "", hooks: [{ type: "command", command, timeout: 8 }] };
  }
  return { matcher: "*", hooks: [{ type: "command", command, timeout: 8 }] };
}

function stripEventArray(agent: ExtraHookAgent, arr: unknown[]): unknown[] {
  if (agent === "cursor") return arr.filter((row) => !isNmzpOwnedHook(row));
  return stripNmzpFromPre(arr);
}

function arrayConfigured(agent: ExtraHookAgent, arr: unknown[]): boolean {
  if (agent === "cursor") return arr.some((row) => isNmzpOwnedHook(row));
  return arr.some(
    (row) => object(row) && Array.isArray(row.hooks) && row.hooks.some((h) => isNmzpOwnedHook(h)),
  );
}

function corrupt(agent: ExtraHookAgent): never {
  throw Error(`${agent}_hooks_corrupt`);
}

function parseHostJson(agent: ExtraHookAgent, raw: string | null): Record<string, unknown> {
  if (raw === null) return {};
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    corrupt(agent);
  }
  if (!object(value)) corrupt(agent);
  if (value.hooks !== undefined && !object(value.hooks)) corrupt(agent);
  return value;
}

function needsVersion(agent: ExtraHookAgent): boolean {
  return agent === "trae" || agent === "cursor";
}

function applyVersion(agent: ExtraHookAgent, doc: Record<string, unknown>): void {
  if (needsVersion(agent) && doc.version === undefined) doc.version = 1;
}

function tomlQuote(s: string): string {
  if (!s.includes("'")) return `'${s}'`;
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function parseTomlString(raw: string): string | undefined {
  const t = raw.trim();
  if (t.startsWith("'")) {
    const end = t.indexOf("'", 1);
    if (end < 0) return undefined;
    return t.slice(1, end);
  }
  if (t.startsWith('"')) {
    let out = "";
    for (let i = 1; i < t.length; i++) {
      const c = t[i]!;
      if (c === "\\") {
        const n = t[++i];
        if (n === undefined) return undefined;
        out += n;
        continue;
      }
      if (c === '"') return out;
      out += c;
    }
    return undefined;
  }
  return undefined;
}

function headerStarts(raw: string): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < raw.length) {
    const nl = raw.indexOf("\n", i);
    const end = nl === -1 ? raw.length : nl;
    const line = raw.slice(i, end).replace(/\r$/, "");
    if (line.startsWith("[")) out.push(i);
    if (nl === -1) break;
    i = nl + 1;
  }
  return out;
}

function lineAt(raw: string, start: number): string {
  const nl = raw.indexOf("\n", start);
  const end = nl === -1 ? raw.length : nl;
  return raw.slice(start, end).replace(/\r$/, "");
}

function kimiCommandValue(block: string): string | undefined {
  for (const rawLine of block.split(/\r?\n/)) {
    const m = /^\s*command\s*=\s*(.*)$/.exec(rawLine);
    if (!m) continue;
    return parseTomlString(m[1]!);
  }
  return undefined;
}

function kimiOwned(block: string): boolean {
  const cmd = kimiCommandValue(block);
  if (cmd === undefined) return false;
  const text = decodeWindowsEncodedCommand(cmd) ?? cmd;
  return /hook --agent kimi(?:;|\s|$)/.test(text);
}

function kimiWithoutOwned(raw: string): string {
  const headers = headerStarts(raw);
  let out = "";
  let pos = 0;
  for (let i = 0; i < headers.length; i++) {
    const start = headers[i]!;
    if (!lineAt(raw, start).startsWith("[[hooks]]")) continue;
    out += raw.slice(pos, start);
    const end = i + 1 < headers.length ? headers[i + 1]! : raw.length;
    const block = raw.slice(start, end);
    if (!kimiOwned(block)) out += block;
    pos = end;
  }
  out += raw.slice(pos);
  return out;
}

function kimiConfigured(raw: string): boolean {
  const headers = headerStarts(raw);
  for (let i = 0; i < headers.length; i++) {
    const start = headers[i]!;
    if (!lineAt(raw, start).startsWith("[[hooks]]")) continue;
    const end = i + 1 < headers.length ? headers[i + 1]! : raw.length;
    if (kimiOwned(raw.slice(start, end))) return true;
  }
  return false;
}

function ensureBlankThen(kept: string, block: string): string {
  if (!kept) return block;
  if (/\r?\n\r?\n$/.test(kept)) return kept + block;
  if (/(?:\r?\n)$/.test(kept)) return kept + "\n" + block;
  return kept + "\n\n" + block;
}

function kimiWrite(raw: string | null, command?: string): string {
  const kept = raw === null ? "" : kimiWithoutOwned(raw);
  if (command === undefined) return kept;
  const block = `[[hooks]]\nevent = "PreToolUse"\ncommand = ${tomlQuote(command)}\ntimeout = 8\n`;
  return ensureBlankThen(kept, block);
}

function pretty(doc: Record<string, unknown>): string {
  return JSON.stringify(doc, null, 2) + "\n";
}

/** 只返回门槛存在的目标文件绝对路径（顺序固定如下）。 */
export function hostHookTargets(agent: ExtraHookAgent, home: string): string[] {
  const out: string[] = [];
  const pushIfDir = (gate: string, file: string) => {
    const dir = join(home, gate);
    if (existsSync(dir)) out.push(join(dir, file));
  };
  switch (agent) {
    case "kimi":
      pushIfDir(".kimi-code", "config.toml");
      break;
    case "trae":
      pushIfDir(".trae", "hooks.json");
      pushIfDir(".trae-cn", "hooks.json");
      break;
    case "qwen":
      pushIfDir(".qwen", "settings.json");
      break;
    case "qoder":
      pushIfDir(".qoder", "settings.json");
      break;
    case "lingma":
      pushIfDir(".lingma", "settings.json");
      pushIfDir(".qoder-cn", "settings.json");
      break;
    case "codebuddy":
      pushIfDir(".codebuddy", "settings.json");
      break;
    case "gemini": {
      const file = join(home, ".gemini", "settings.json");
      if (existsSync(file)) out.push(file);
      break;
    }
    case "cursor":
      pushIfDir(".cursor", "hooks.json");
      break;
  }
  return out;
}

export function hostHookWrite(
  agent: ExtraHookAgent,
  raw: string | null,
  nodePath: string,
  entry: string,
  os?: string,
): string {
  const command = hookCommand(nodePath, entry, agent, os);
  if (agent === "kimi") return kimiWrite(raw, command);
  const doc = parseHostJson(agent, raw);
  const hooks = object(doc.hooks) ? doc.hooks : {};
  const key = eventKey(agent);
  const cur = Array.isArray(hooks[key]) ? (hooks[key] as unknown[]) : [];
  hooks[key] = [...stripEventArray(agent, cur), ownEntry(agent, command)];
  doc.hooks = hooks;
  applyVersion(agent, doc);
  return pretty(doc);
}

export function hostHookStrip(agent: ExtraHookAgent, raw: string): string {
  if (agent === "kimi") return kimiWrite(raw);
  const doc = parseHostJson(agent, raw);
  if (object(doc.hooks)) {
    const key = eventKey(agent);
    if (Array.isArray(doc.hooks[key])) doc.hooks[key] = stripEventArray(agent, doc.hooks[key] as unknown[]);
  }
  applyVersion(agent, doc);
  return pretty(doc);
}

export function hostHookConfiguredRaw(agent: ExtraHookAgent, raw: string): boolean {
  try {
    if (agent === "kimi") return kimiConfigured(raw);
    const doc = JSON.parse(raw) as unknown;
    if (!object(doc) || !object(doc.hooks)) return false;
    const arr = doc.hooks[eventKey(agent)];
    return Array.isArray(arr) && arrayConfigured(agent, arr);
  } catch {
    return false;
  }
}

export function hostHookState(agent: ExtraHookAgent, home: string): { present: boolean; configured: boolean } {
  const paths = hostHookTargets(agent, home);
  let present = false;
  let configured = false;
  for (const path of paths) {
    if (!existsSync(path)) continue;
    present = true;
    try {
      if (hostHookConfiguredRaw(agent, readFileSync(path, "utf8"))) configured = true;
    } catch {
      /* unreadable target is present but not configured */
    }
  }
  return { present, configured };
}

export function isExtraHookAgent(v: string): v is ExtraHookAgent {
  return (EXTRA_HOOK_AGENTS as readonly string[]).includes(v);
}
