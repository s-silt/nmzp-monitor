export interface ProcRow {
  pid: number;
  ppid: number;
  name: string;
  exe?: string;
  cmdline?: string;
  /** CIM CreationDate as epoch ms. Network identity only; never from CommandLine. */
  startedAt?: number;
}

const AGENT_NAMES = new Set([
  "grok",
  "grok.exe",
  "grok-cli",
  "grok-build",
  "claude",
  "claude.exe",
  "claude-code",
  "zcode",
  "zcode.exe",
  "codex",
  "codex.exe",
  "codex-cli",
]);

export const WINDOWS_PROCESS_INDEX_SCRIPT =
  "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress";

export function WINDOWS_CANDIDATE_IDENTITY_SCRIPT(pids: number[]): string {
  const list = pids.filter((n) => Number.isInteger(n) && n > 0).join(",");
  return `$pids = @(${list}); Get-CimInstance Win32_Process | Where-Object { $pids -contains $_.ProcessId } | Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress`;
}

export function isCandidateProcessName(name: string): boolean {
  const n = (name || "").toLowerCase();
  const base = n.replace(/\.exe$/, "");
  return AGENT_NAMES.has(n) || AGENT_NAMES.has(base) || base === "node";
}

function basenameBin(s: string): string {
  return s.replace(/\\/g, "/").split("/").pop() || s;
}

export function binOf(row: ProcRow): string {
  if (row.name) return basenameBin(row.name);
  if (row.exe) return basenameBin(row.exe);
  return "unknown";
}

function agentFromName(name: string): string | null {
  const base = (name || "").toLowerCase().replace(/\.exe$/, "");
  if (base === "codex" || base === "codex-cli") return "codex";
  if (base === "claude" || base === "claude-code") return "claude";
  if (base === "grok" || base === "grok-cli" || base === "grok-build") return "grok";
  if (base === "zcode" || base === "zcode-cli") return "zcode";
  return null;
}

/** Name-based agent id. Network collection still requires a real ExecutablePath. */
export function agentFromProcessName(name: string): string | null {
  return agentFromName(name);
}

export function agentFromInstallPath(exe?: string): string | null {
  if (!exe) return null;
  const n = exe.replace(/\\/g, "/").toLowerCase();
  if (n.includes("/node_modules/")) return null;
  if (/(^|\/)\.grok(\/|$)/.test(n) || /\/programs\/grok\//.test(n) || /\/grok-cli\//.test(n) || /\/grok\/runtime\//.test(n)) {
    return "grok";
  }
  if (/(^|\/)\.claude(\/|$)/.test(n) || /anthropic/.test(n) || /\/programs\/claude/.test(n)) return "claude";
  if (/(^|\/)\.codex(\/|$)/.test(n) || /\/codex\//.test(n)) return "codex";
  if (/\/zcode\//.test(n)) return "zcode";
  return null;
}

function walkParents(row: ProcRow, byPid: Map<number, ProcRow>, max = 32): ProcRow[] {
  const out: ProcRow[] = [];
  let cur = row;
  const seen = new Set<number>();
  for (let i = 0; i < max; i++) {
    if (!cur.ppid || seen.has(cur.ppid)) break;
    seen.add(cur.ppid);
    const parent = byPid.get(cur.ppid);
    if (!parent) break;
    out.push(parent);
    cur = parent;
  }
  return out;
}

/** Legacy display classification cannot establish identity from names, paths or parents. */
export function classifyAgentProc(row: ProcRow, _all: ProcRow[] = []): string | null {
 return isCandidateProcessName(row.name) ? "unknown" : null;
}
