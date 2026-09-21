import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { hookCommand, decodeWindowsEncodedCommand } from "./install-hooks.ts";
const marker = "NMZP PreToolUse v1";
function object(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}
export function codexHookEntry(
  nodePath: string,
  entry: string,
  os = process.platform,
): Record<string, unknown> {
  return {
    hooks: [
      {
        type: "command",
        command: hookCommand(nodePath, entry, "codex", os),
        timeout: 8,
        statusMessage: marker,
      },
    ],
  };
}
function own(v: unknown): boolean {
  if (!object(v) || v.statusMessage !== marker || typeof v.command !== "string") return false;
  return /hook --agent codex(?:;|\s|$)/.test(decodeWindowsEncodedCommand(v.command) ?? v.command);
}
export function mergeCodexHooks(raw: string | null, entry?: Record<string, unknown>): string {
  let doc: Record<string, unknown> = {};
  if (raw !== null) {
    const parsed: unknown = JSON.parse(raw);
    if (!object(parsed)) throw Error("codex_hooks_corrupt");
    doc = parsed;
  }
  if (doc.hooks !== undefined && !object(doc.hooks)) throw Error("codex_hooks_corrupt");
  const hooks = object(doc.hooks) ? doc.hooks : {};
  if (hooks.PreToolUse !== undefined && !Array.isArray(hooks.PreToolUse))
    throw Error("codex_hooks_corrupt");
  const pre = (Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : []).flatMap((row) => {
    if (!object(row) || !Array.isArray(row.hooks)) return [row];
    const kept = row.hooks.filter((h) => !own(h));
    return kept.length ? [{ ...row, hooks: kept }] : [];
  });
  if (entry) pre.push(entry);
  return JSON.stringify({ ...doc, hooks: { ...hooks, PreToolUse: pre } }, null, 2) + "\n";
}
export function codexHookConfiguredRaw(raw: string): boolean {
  try {
    const doc = JSON.parse(raw);
    return (
      Array.isArray(doc?.hooks?.PreToolUse) &&
      doc.hooks.PreToolUse.some(
        (r: unknown) => object(r) && Array.isArray(r.hooks) && r.hooks.some(own),
      )
    );
  } catch {
    return false;
  }
}

/*
 * Codex persisted hook trust (codex-rs/hooks/src/engine/discovery.rs, codex-cli >= 0.154):
 * a non-managed hook runs only when `[hooks.state."<hooks.json path>:<event>:<group>:<handler>"]`
 * in ~/.codex/config.toml carries `trusted_hash` equal to the hook's current identity hash and
 * `enabled` is not false. hooks.json alone is discovered but skipped ("New hook - review required").
 * The identity hash is `version_for_toml` over the normalized handler:
 * sha256 of canonical (sorted-key, compact) JSON of {event_name, matcher?, hooks:[normalized command]}.
 */

export type CodexHookEventKey = "pre_tool_use" | "user_prompt_submit" | "post_tool_use" | "session_start" | "session_end" | "stop";

export interface CodexCommandHandler {
  type: "command";
  command: string;
  timeout?: number;
  async?: boolean;
  statusMessage?: string;
  additionalContextLimit?: number;
}

const CODEX_DEFAULT_TIMEOUT_SEC = 600;
const CODEX_DEFAULT_CONTEXT_LIMIT = 2500;

function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (object(v)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = canonical(v[k]);
    return out;
  }
  return v;
}

/** Same bytes Codex hashes for trust: normalized handler (timeout default 600, async default false). */
export function codexHookIdentityHash(
  event: CodexHookEventKey,
  handler: CodexCommandHandler,
  matcher: string | undefined,
): string {
  const normalized: Record<string, unknown> = {
    type: "command",
    command: handler.command,
    timeout: Math.max(1, Math.trunc(handler.timeout ?? CODEX_DEFAULT_TIMEOUT_SEC)),
    async: handler.async === true,
  };
  if (typeof handler.statusMessage === "string") normalized.statusMessage = handler.statusMessage;
  if (
    typeof handler.additionalContextLimit === "number" &&
    handler.additionalContextLimit !== CODEX_DEFAULT_CONTEXT_LIMIT
  ) {
    normalized.additionalContextLimit = handler.additionalContextLimit;
  }
  const identity: Record<string, unknown> = { event_name: event, hooks: [normalized] };
  if (typeof matcher === "string") identity.matcher = matcher;
  const bytes = JSON.stringify(canonical(identity));
  return `sha256:${createHash("sha256").update(bytes, "utf8").digest("hex")}`;
}

export function codexHookTrustKey(
  hooksJsonPath: string,
  event: CodexHookEventKey,
  groupIndex: number,
  handlerIndex: number,
): string {
  return `${hooksJsonPath}:${event}:${groupIndex}:${handlerIndex}`;
}

export interface CodexHookState {
  enabled?: boolean;
  trustedHash?: string;
}

export interface CodexHookStateFile {
  hooksFeatureEnabled: boolean;
  state: Map<string, CodexHookState>;
}

function unquoteTomlKey(raw: string): string | null {
  const t = raw.trim();
  if (t.length >= 2 && t.startsWith("'") && t.endsWith("'")) return t.slice(1, -1);
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1).replace(/\\(["\\])/g, "$1");
  }
  return null;
}

function tomlScalar(raw: string): string | boolean | null {
  let t = raw.trim();
  if (t.startsWith('"')) {
    const end = t.indexOf('"', 1);
    return end > 0 ? t.slice(1, end) : null;
  }
  if (t.startsWith("'")) {
    const end = t.indexOf("'", 1);
    return end > 0 ? t.slice(1, end) : null;
  }
  t = t.replace(/\s+#.*$/, "").trim();
  if (t === "true") return true;
  if (t === "false") return false;
  return null;
}

/** Minimal read-only TOML walk: only `[features] hooks` and `[hooks.state.<key>]` tables. */
export function parseCodexHookState(toml: string): CodexHookStateFile {
  const state = new Map<string, CodexHookState>();
  let hooksFeatureEnabled = true;
  let section: { kind: "features" } | { kind: "state"; key: string } | { kind: "other" } = { kind: "other" };
  for (const rawLine of toml.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      const header = line.replace(/\s+#.*$/, "");
      if (header === "[features]") {
        section = { kind: "features" };
        continue;
      }
      const m = /^\[hooks\.state\.(.+)\]$/.exec(header);
      const key = m?.[1] ? unquoteTomlKey(m[1]) : null;
      section = key ? { kind: "state", key } : { kind: "other" };
      if (key && !state.has(key)) state.set(key, {});
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const name = line.slice(0, eq).trim();
    const value = tomlScalar(line.slice(eq + 1));
    if (section.kind === "features" && name === "hooks" && typeof value === "boolean") hooksFeatureEnabled = value;
    if (section.kind === "state") {
      const cur = state.get(section.key) ?? {};
      if (name === "enabled" && typeof value === "boolean") cur.enabled = value;
      if (name === "trusted_hash" && typeof value === "string") cur.trustedHash = value;
      state.set(section.key, cur);
    }
  }
  return { hooksFeatureEnabled, state };
}

export type CodexHookTrustStatus =
  | "not_configured"
  | "trusted"
  | "untrusted"
  | "modified"
  | "disabled"
  | "feature_off"
  | "unknown";

export interface CodexHookTrust {
  configured: boolean;
  status: CodexHookTrustStatus;
  key?: string;
  currentHash?: string;
}

function samePath(a: string, b: string): boolean {
  const norm = (s: string) => s.replace(/\//g, "\\");
  const x = norm(a);
  const y = norm(b);
  if (x === y) return true;
  return /^[A-Za-z]:\\/.test(x) && x.toLowerCase() === y.toLowerCase();
}

/**
 * Trust status of the NMZP-owned PreToolUse handler as Codex will see it.
 * Reads ~/.codex/hooks.json and ~/.codex/config.toml only; never writes trust.
 */
export function codexHookTrust(home: string): CodexHookTrust {
  const hooksPath = join(home, ".codex", "hooks.json");
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(hooksPath, "utf8"));
  } catch {
    return { configured: false, status: "not_configured" };
  }
  const pre = object(doc) && object(doc.hooks) && Array.isArray(doc.hooks.PreToolUse) ? doc.hooks.PreToolUse : [];
  let found: { key: string; currentHash: string } | undefined;
  pre.forEach((row: unknown, groupIndex: number) => {
    if (found || !object(row) || !Array.isArray(row.hooks)) return;
    row.hooks.forEach((h: unknown, handlerIndex: number) => {
      if (found || !own(h)) return;
      const handler = h as Record<string, unknown>;
      const matcher = typeof row.matcher === "string" ? row.matcher : undefined;
      found = {
        key: codexHookTrustKey(hooksPath, "pre_tool_use", groupIndex, handlerIndex),
        currentHash: codexHookIdentityHash(
          "pre_tool_use",
          {
            type: "command",
            command: handler.command as string,
            timeout: typeof handler.timeout === "number" ? handler.timeout : undefined,
            async: handler.async === true,
            statusMessage: typeof handler.statusMessage === "string" ? handler.statusMessage : undefined,
            additionalContextLimit:
              typeof handler.additionalContextLimit === "number" ? handler.additionalContextLimit : undefined,
          },
          matcher,
        ),
      };
    });
  });
  if (!found) return { configured: false, status: "not_configured" };
  const base = { configured: true, key: found.key, currentHash: found.currentHash };
  const configPath = join(home, ".codex", "config.toml");
  if (!existsSync(configPath)) return { ...base, status: "untrusted" };
  let parsed: CodexHookStateFile;
  try {
    parsed = parseCodexHookState(readFileSync(configPath, "utf8"));
  } catch {
    return { ...base, status: "unknown" };
  }
  if (!parsed.hooksFeatureEnabled) return { ...base, status: "feature_off" };
  let state: CodexHookState | undefined;
  for (const [key, value] of parsed.state) {
    const sep = key.lastIndexOf(":pre_tool_use:");
    if (sep < 0) continue;
    if (samePath(key.slice(0, sep), hooksPath) && key.slice(sep) === found.key.slice(found.key.lastIndexOf(":pre_tool_use:"))) {
      state = value;
      break;
    }
  }
  if (!state || !state.trustedHash) return { ...base, status: "untrusted" };
  if (state.enabled === false) return { ...base, status: "disabled" };
  if (state.trustedHash !== found.currentHash) return { ...base, status: "modified" };
  return { ...base, status: "trusted" };
}

/** Capability error code for a non-runnable Codex hook; undefined when Codex would run it. */
export function codexHookGateError(trust: CodexHookTrust): string | undefined {
  if (!trust.configured) return undefined;
  switch (trust.status) {
    case "untrusted":
      return "hook_untrusted";
    case "modified":
      return "hook_modified";
    case "disabled":
      return "hook_disabled";
    case "feature_off":
      return "hooks_feature_off";
    default:
      return undefined;
  }
}
