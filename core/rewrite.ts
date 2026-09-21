import type { CustomPrivacyRule } from "./schema.ts";

export interface PrivacyFns {
  REDACT_TAG: string;
  scanSecrets: (text: string) => Array<{ index: number; length: number }>;
  scanCustom: (text: string, rules: CustomPrivacyRule[]) => Array<{ index: number; length: number }>;
  cloakPersona?: (text: string) => { text: string; changed: boolean };
  shouldCloakPersona?: (input: {
    agent?: string;
    tool: string;
    command?: string;
    url?: string;
    dest?: string;
  }) => boolean;
}

const SHELL_FIELDS = new Set(["command", "cmd"]);
const PATH_FIELDS = new Set(["file_path", "filePath", "path", "target_file", "cwd", "working_directory", "workingDirectory", "directory"]);
const URL_FIELDS = new Set(["url", "uri", "href", "dest"]);

export type RewriteOutcome =
  | { ok: true; updatedInput: Record<string, unknown> }
  | { ok: false; reason: string };

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function mergeSpans(hits: Array<{ index: number; length: number }>): Array<{ index: number; length: number }> {
  const valid = hits.filter((h) => Number.isFinite(h.index) && h.index >= 0 && h.length > 0);
  valid.sort((a, b) => a.index - b.index || b.length - a.length);
  const out: Array<{ index: number; length: number }> = [];
  for (const h of valid) {
    const last = out[out.length - 1];
    const end = h.index + h.length;
    if (last && h.index <= last.index + last.length) {
      last.length = Math.max(last.index + last.length, end) - last.index;
    } else {
      out.push({ index: h.index, length: h.length });
    }
  }
  return out;
}

export function paintFull(
  text: string,
  secretHits: Array<{ index: number; length: number }>,
  customHits: Array<{ index: number; length: number }>,
  tag: string,
): string {
  const merged = mergeSpans([...secretHits, ...customHits]);
  let out = text;
  for (let i = merged.length - 1; i >= 0; i -= 1) {
    const h = merged[i]!;
    if (h.index + h.length > out.length) continue;
    out = `${out.slice(0, h.index)}${tag}${out.slice(h.index + h.length)}`;
  }
  return out;
}

export function redactField(text: string, customRules: CustomPrivacyRule[], p: PrivacyFns): string {
  const secrets = p.scanSecrets(text);
  const custom = p.scanCustom(text, customRules);
  if (!secrets.length && !custom.length) return text;
  return paintFull(text, secrets, custom, p.REDACT_TAG);
}

/** True when < or > appears outside quotes (shell redirect risk). */
export function hasUnquotedRedirect(cmd: string): boolean {
  let sq = false;
  let dq = false;
  let esc = false;
  for (const c of cmd) {
    if (esc) {
      esc = false;
      continue;
    }
    if (!sq && c === "\\") {
      esc = true;
      continue;
    }
    if (!dq && c === "'") {
      sq = !sq;
      continue;
    }
    if (!sq && c === '"') {
      dq = !dq;
      continue;
    }
    if (!sq && !dq && (c === "<" || c === ">")) return true;
  }
  return false;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function redactPathname(pathname: string, customRules: CustomPrivacyRule[], p: PrivacyFns): string {
  return pathname
    .split("/")
    .map((seg) => {
      if (!seg) return seg;
      const decoded = safeDecode(seg);
      const red = redactField(decoded, customRules, p);
      if (red === decoded) return seg;
      return encodeURIComponent(red);
    })
    .join("/");
}

export function redactUrlField(url: string, customRules: CustomPrivacyRule[], p: PrivacyFns): string {
  try {
    const u = new URL(url);
    if (u.username) u.username = redactField(u.username, customRules, p);
    if (u.password) u.password = redactField(u.password, customRules, p);
    if (u.pathname) u.pathname = redactPathname(u.pathname, customRules, p);
    const keys = [...u.searchParams.keys()];
    for (const k of keys) {
      const vals = u.searchParams.getAll(k);
      u.searchParams.delete(k);
      for (const v of vals) u.searchParams.append(k, redactField(v, customRules, p));
    }
    if (u.hash) {
      const raw = u.hash.slice(1);
      const decoded = safeDecode(raw);
      const red = redactField(decoded, customRules, p);
      u.hash = red === decoded ? u.hash : `#${encodeURIComponent(red)}`;
    }
    return u.toString();
  } catch {
    return redactField(url, customRules, p);
  }
}

function looksAbsoluteUrl(text: string): boolean {
  return /^https?:\/\/\S+$/i.test(text.trim());
}

type WalkResult = { ok: true; value: unknown; changed: boolean } | { ok: false; reason: string };

function payloadLooksOutbound(toolInput: Record<string, unknown>, p: PrivacyFns): boolean {
  if (!p.shouldCloakPersona) return false;
  const command = typeof toolInput.command === "string" ? toolInput.command : typeof toolInput.cmd === "string" ? toolInput.cmd : undefined;
  const url = typeof toolInput.url === "string" ? toolInput.url : undefined;
  const dest = typeof toolInput.dest === "string" ? toolInput.dest : undefined;
  return (
    p.shouldCloakPersona({ tool: "Bash", command, url, dest }) ||
    p.shouldCloakPersona({ tool: "WebFetch", command, url, dest }) ||
    p.shouldCloakPersona({ tool: "WebSearch", command, url, dest }) ||
    p.shouldCloakPersona({ tool: "MCP", command, url, dest })
  );
}

function applyCloakText(text: string, p: PrivacyFns, cloak: boolean): string {
  if (!cloak || !p.cloakPersona || !text) return text;
  return p.cloakPersona(text).text;
}

function rewriteValue(
  val: unknown,
  key: string,
  customRules: CustomPrivacyRule[],
  p: PrivacyFns,
  cloak: boolean,
): WalkResult {
  if (typeof val === "string") {
    if (!val) return { ok: true, value: val, changed: false };
    if (PATH_FIELDS.has(key)) return { ok: true, value: val, changed: false };
    let next =
      URL_FIELDS.has(key) || looksAbsoluteUrl(val) ? redactUrlField(val, customRules, p) : redactField(val, customRules, p);
    next = applyCloakText(next, p, cloak);
    if (SHELL_FIELDS.has(key) && next !== val && hasUnquotedRedirect(next)) {
      return { ok: false, reason: "rewrite_would_break_shell" };
    }
    return { ok: true, value: next, changed: next !== val };
  }
  if (Array.isArray(val)) {
    const out: unknown[] = [];
    let changed = false;
    for (const item of val) {
      const r = rewriteValue(item, key, customRules, p, cloak);
      if (!r.ok) return r;
      out.push(r.value);
      if (r.changed) changed = true;
    }
    return { ok: true, value: out, changed };
  }
  if (isPlain(val)) {
    const out: Record<string, unknown> = {};
    let changed = false;
    for (const [k, v] of Object.entries(val)) {
      const r = rewriteValue(v, k, customRules, p, cloak);
      if (!r.ok) return r;
      out[k] = r.value;
      if (r.changed) changed = true;
    }
    return { ok: true, value: out, changed };
  }
  return { ok: true, value: val, changed: false };
}

function scanText(text: string, customRules: CustomPrivacyRule[], p: PrivacyFns): boolean {
  return p.scanSecrets(text).length > 0 || p.scanCustom(text, customRules).length > 0;
}

function remainingSensitive(value: unknown, customRules: CustomPrivacyRule[], p: PrivacyFns): boolean {
  const blob = JSON.stringify(value);
  if (blob && scanText(blob, customRules, p)) return true;
  const stack: unknown[] = [value];
  while (stack.length) {
    const cur = stack.pop();
    if (typeof cur === "string") {
      if (scanText(cur, customRules, p)) return true;
      const decoded = safeDecode(cur);
      if (decoded !== cur && scanText(decoded, customRules, p)) return true;
      try {
        const u = new URL(cur);
        const pieces = [u.username, u.password, u.pathname, u.search, u.hash, ...u.searchParams.values()];
        for (const piece of pieces) {
          if (!piece) continue;
          const stripped = piece.replace(/^[?#]/, "");
          if (scanText(stripped, customRules, p) || scanText(safeDecode(stripped), customRules, p)) return true;
        }
      } catch {
        /* not a URL */
      }
    } else if (Array.isArray(cur)) {
      for (const item of cur) stack.push(item);
    } else if (isPlain(cur)) {
      for (const v of Object.values(cur)) stack.push(v);
    }
  }
  return false;
}

function remainingPersona(value: unknown, p: PrivacyFns): boolean {
  if (!p.cloakPersona) return false;
  const blob = JSON.stringify(value);
  return Boolean(blob && p.cloakPersona(blob).changed);
}

/**
 * Structured tool_input update. Never uses the 240-char display summary as the
 * replacement payload. Unquoted <标签> in a shell command → deny, not rewrite.
 * Any leftover transmissible secret after the walk → deny.
 */
export function structuredRewrite(
  toolInput: Record<string, unknown> | undefined,
  customRules: CustomPrivacyRule[],
  p: PrivacyFns,
): RewriteOutcome {
  if (!toolInput || !isPlain(toolInput)) {
    return { ok: false, reason: "tool_input is not a structured object; refusing unsafe rewrite" };
  }
  const cloak = payloadLooksOutbound(toolInput, p);
  const walked = rewriteValue(toolInput, "", customRules, p, cloak);
  if (!walked.ok) return walked;
  const updated = isPlain(walked.value) ? walked.value : { ...toolInput };
  if (remainingSensitive(updated, customRules, p)) {
    return { ok: false, reason: "sensitive_residue" };
  }
  if (cloak && remainingPersona(updated, p)) {
    return { ok: false, reason: "persona_residue" };
  }
  return { ok: true, updatedInput: updated };
}
