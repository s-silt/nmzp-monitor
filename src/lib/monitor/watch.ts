/**
 * Allowlist of coding-agent binaries. Nothing else on the machine is in scope.
 * The human at the keyboard, their browser, their terminal, their mail — never.
 */

import type { AgentId, EventSource } from "./types";

const WATCHED: Array<{ bin: string; agent: AgentId }> = [
  { bin: "zcode", agent: "zcode" },
  { bin: "zcode-cli", agent: "zcode" },
  { bin: "codex", agent: "codex" },
  { bin: "codex-cli", agent: "codex" },
  { bin: "grok", agent: "grok" },
  { bin: "grok-cli", agent: "grok" },
  { bin: "grok-build", agent: "grok" },
  { bin: "claude", agent: "claude" },
  { bin: "claude-code", agent: "claude" },
  { bin: "cursor-agent", agent: "cursor" },
  { bin: "cursor-cli", agent: "cursor" },
  { bin: "copilot", agent: "copilot" },
  { bin: "copilot-cli", agent: "copilot" },
  { bin: "github-copilot", agent: "copilot" },
  { bin: "windsurf-agent", agent: "windsurf" },
  { bin: "cascade", agent: "windsurf" },
  { bin: "gemini", agent: "gemini" },
  { bin: "gemini-cli", agent: "gemini" },
  { bin: "aider", agent: "aider" },
  { bin: "qwen-code", agent: "qwen" },
  { bin: "lingma-cli", agent: "qwen" },
  { bin: "cline", agent: "cline" },
  { bin: "roo-cline", agent: "cline" },
  { bin: "trae-agent", agent: "trae" },
  { bin: "trae-cli", agent: "trae" },
];

/** Tools an agent is allowed to spawn. Still attributed to the parent agent. */
const TOOL_CHILD = new Set([
  "bash",
  "sh",
  "zsh",
  "dash",
  "cmd",
  "powershell",
  "pwsh",
  "python",
  "python3",
  "node",
  "curl",
  "wget",
  "tar",
  "zip",
  "git",
  "scp",
  "rsync",
  "rclone",
  "osascript",
  "screencapture",
  "pbcopy",
  "pbpaste",
  "xclip",
  "xsel",
  "wl-paste",
  "wl-copy",
  "grim",
  "gnome-screenshot",
]);

/** User environment. Even if a probe reports them, drop the event. */
const NEVER = new Set([
  "chrome",
  "chromium",
  "google chrome",
  "firefox",
  "safari",
  "msedge",
  "finder",
  "explorer",
  "dock",
  "windowserver",
  "terminal",
  "iterm2",
  "kitty",
  "alacritty",
  "wezterm",
  "warp",
  "gnome-terminal",
  "windowsterminal",
  "wt",
  "conhost",
  "cmd",
  "code",
  "code-insiders",
  "cursor",
  "windsurf",
  "trae",
  "slack",
  "discord",
  "telegram",
  "mail",
  "photos",
  "zsh",
  "bash",
  "fish",
  "pwsh",
  "powershell",
]);

const BIN_TO_AGENT = new Map(WATCHED.map((w) => [w.bin, w.agent]));

export const WATCHED_BINS = WATCHED.map((w) => w.bin);

export function basename(cmd: string | undefined): string {
  if (!cmd) return "";
  const trimmed = cmd.trim().split(/\s+/)[0] ?? "";
  const slash = trimmed.replace(/\\/g, "/");
  const base = slash.slice(slash.lastIndexOf("/") + 1).toLowerCase();
  // Windows process names often carry .exe / .cmd / .bat / .ps1 — strip so
  // WATCH / NEVER / TOOL_CHILD stay consistent across platforms.
  return base.replace(/\.(exe|cmd|bat|ps1)$/i, "");
}

export function agentFromBin(bin: string | undefined): AgentId | undefined {
  const b = basename(bin);
  return BIN_TO_AGENT.get(b);
}

export function isWatchedBin(bin: string | undefined): boolean {
  return BIN_TO_AGENT.has(basename(bin));
}

export function isNeverBin(bin: string | undefined): boolean {
  const b = basename(bin);
  if (!b) return false;
  if (BIN_TO_AGENT.has(b)) return false;
  return NEVER.has(b);
}

export function isToolChild(bin: string | undefined): boolean {
  return TOOL_CHILD.has(basename(bin));
}

/**
 * True only when the event is from a listed agent binary, or a tool child
 * whose parent is a listed agent. Hook payloads with no process field are
 * accepted (the hook only fires inside the agent). Probe events without a
 * matching binary are dropped — that is how we never watch the user.
 * Correlate windows must also drop skipped / unwatched events so a browser
 * or user shell cannot seed or consume another agent's session.
 */
export function isWatchedProcess(input: {
  proc?: string;
  parentProc?: string;
  source?: EventSource;
  agent?: AgentId;
}): boolean {
  const proc = basename(input.proc);
  const parent = basename(input.parentProc);

  if (isWatchedBin(proc)) return true;
  if (isWatchedBin(parent) && (isToolChild(proc) || !proc)) return true;

  if (!proc && !parent) {
    if (input.source === "probe") return Boolean(input.agent);
    return true;
  }
  return false;
}
