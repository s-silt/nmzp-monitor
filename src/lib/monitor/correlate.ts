import { extractHosts, isLegacySnapshotArtifact, isLocalCheckpointReference } from "./snapshot.ts";
import { hasArchiveCreation, isNodeDataCommand } from "./command-intent.ts";
import type { ThreatKind } from "./types";

export type Mark =
  | "git_push"
  | "archive"
  | "env_read"
  | "file_read"
  | "outbound"
  | "clipboard"
  | "screen"
  | "untrusted";

export interface WindowHit {
  ts: number;
  mark: Mark;
}

const WINDOW_MS = 120_000;
const MAX_HITS = 48;
const BULK_READS = 10;

const ALLOW_HOSTS = [
  "api.z.ai",
  "zcode.z.ai",
  "open.bigmodel.cn",
  "api.openai.com",
  "api.x.ai",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.deepseek.com",
  "dashscope.aliyuncs.com",
  "registry.npmjs.org",
  "pypi.org",
  "github.com",
  "githubusercontent.com",
  "proxy.golang.org",
  "crates.io",
  "cdn.jsdelivr.net",
];

/** Exact hostname or a subdomain, never a substring of another domain. */
export function hostnameAllowed(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "").split(":")[0] ?? "";
  if (!h) return false;
  for (const allowed of ALLOW_HOSTS) {
    if (h === allowed || h.endsWith(`.${allowed}`)) return true;
  }
  return false;
}

function hostSuffix(host: string, suffix: string): boolean {
  const h = host.trim().toLowerCase();
  return h === suffix || h.endsWith(`.${suffix}`);
}

function hostsOf(command: string, dest?: string): string[] {
  const out: string[] = [];
  for (const blob of [command, dest ?? ""]) {
    for (const h of extractHosts(blob)) {
      if (!out.includes(h)) out.push(h);
    }
  }
  return out;
}

function allHostsAllowed(command: string, dest?: string): boolean {
  const hosts = hostsOf(command, dest);
  return hosts.length > 0 && hosts.every(hostnameAllowed);
}

/** Paths that count as credential material for session correlate (not single-step block). */
const ENV_READ_RE =
  /(^|[\s/\\])\.env(\.|$|[\s/\\])|\.pem$|\.ssh([/\\]|$)|id_rsa|id_ed25519|[/\\]\.aws[/\\](credentials|config)$|[/\\]\.config[/\\]gcloud[/\\]|application_default_credentials\.json|[/\\]\.docker[/\\]config\.json$|[/\\]\.npmrc$|[/\\]\.netrc$|[/\\]\.kube[/\\]config$|credentials\.json$|service-account[^/\\]*\.json$/i;

const UPLOAD_FLAG_RE =
  /\s(-d|--data|--data-raw|--data-binary|-T|--upload-file|-F|--form)\b/i;

export function markFrom(input: {
  command: string;
  filePath: string;
  tool: string;
  dest?: string;
}): Mark | null {
  const text = `${input.command} ${input.filePath}`;
  // A proven data program can mention network commands without executing them.
  // Keep original text for credential-read evidence; do not hide file paths.
  if (isNodeDataCommand(input.command)) input = { ...input, command: "" };
  // 快照专项由当前事件的包/接口证据判定。不能用同窗内无关 POST 给本地 checkpoint 补成外传链。
  // 不写 archive 标记，也不将其文件名里的 tar 误识别为打包命令。
  if (isLegacySnapshotArtifact(text) || isLocalCheckpointReference(text)) return null;
  if (/\b(pbpaste|wl-paste|Get-Clipboard|xclip\s+-o)\b/i.test(text)) return "clipboard";
  if (/\b(screencapture|gnome-screenshot|grim|import\s+-window)\b/i.test(text)) return "screen";
  if (hasArchiveCreation(input.command)) return "archive";

  // Upload intent is not exempted by a hosting/model/registry domain allowlist.
  if(/\bgit\b[^\r\n]*\bpush\b/i.test(input.command))return "git_push";
  if((/\b(curl|wget)\b/i.test(input.command)&&UPLOAD_FLAG_RE.test(input.command))||/\b(?:gh\s+(?:release\s+upload|gist\s+create)|scp|rsync|rclone)\b/i.test(input.command))return "outbound";

  if (ENV_READ_RE.test(text) || ENV_READ_RE.test(input.filePath)) return "env_read";

  // Fetch of non-allowlisted hosts = low-trust inbound (untrusted), not yet exfil.
  // Prefer dest when present so a file suffix in the URL (README.md) is not a host.
  if (input.tool === "WebFetch") {
    const dest = (input.dest ?? "").trim();
    if (dest) {
      const host = dest.includes("://")
        ? (hostsOf("", dest)[0] ?? "")
        : dest.toLowerCase().replace(/\.$/, "").split(":")[0] ?? "";
      if (host && !hostnameAllowed(host)) return "untrusted";
    } else if (input.command && !allHostsAllowed(input.command)) {
      return "untrusted";
    }
  }
  if (/\b(curl|wget)\b/i.test(input.command) && !allHostsAllowed(input.command, input.dest)) {
    if (UPLOAD_FLAG_RE.test(input.command) || /\b(scp|rsync|rclone)\b/i.test(input.command)) {
      return "outbound";
    }
    return "untrusted";
  }

  if (input.tool === "Read" || input.tool === "Glob") return "file_read";
  if (input.dest) {
    const destHosts = hostsOf("", input.dest);
    // OSS 对端仍按出网记账；zcode.z.ai 登录/套餐/分享走 allowlist，凭证接口由规则拦截。
    if (destHosts.some((h) => hostSuffix(h, "aliyuncs.com"))) return "outbound";
    if (destHosts.length && !destHosts.every(hostnameAllowed)) return "outbound";
  }
  if (/\b(scp|rsync|rclone)\b/i.test(input.command) && !allHostsAllowed(input.command, input.dest)) return "outbound";
  return null;
}

export function pushHit(prev: WindowHit[] | undefined, hit: WindowHit): WindowHit[] {
  const cut = hit.ts - WINDOW_MS;
  const next = [...(prev ?? []).filter((h) => h.ts >= cut), hit];
  return next.length > MAX_HITS ? next.slice(-MAX_HITS) : next;
}

export function correlate(hits: WindowHit[], incoming: Mark, ts: number): ThreatKind | null {
  const cut = ts - WINDOW_MS;
  const recent = hits.filter((h) => h.ts >= cut);
  const has = (m: Mark) => recent.some((h) => h.mark === m);
  const reads = recent.filter((h) => h.mark === "file_read").length;
  if(incoming==="git_push"){
    if(has("env_read"))return "secret";
    if(has("clipboard")||has("screen")||has("untrusted"))return "exfil";
    return null; // A local archive is not necessarily part of the pushed commit.
  }
  if (incoming === "outbound" && has("archive")) return "exfil";
  if (incoming === "archive" && has("outbound")) return "exfil";
  if (incoming === "outbound" && has("clipboard")) return "exfil";
  if (incoming === "clipboard" && has("outbound")) return "exfil";
  if (incoming === "outbound" && has("screen")) return "exfil";
  if (incoming === "screen" && has("outbound")) return "exfil";
  if (incoming === "outbound" && has("env_read")) return "secret";
  if (incoming === "env_read" && has("outbound")) return "secret";
  // P0-2: low-trust fetch then secret read / upload
  if (incoming === "env_read" && has("untrusted")) return "secret";
  if (incoming === "untrusted" && has("env_read")) return "secret";
  if (incoming === "outbound" && has("untrusted")) return "exfil";
  if (incoming === "untrusted" && has("outbound")) return "exfil";
  if (incoming === "outbound" && reads >= BULK_READS) return "exfil";
  return null;
}

export const CORRELATE_WINDOW_MS = WINDOW_MS;
export const CORRELATE_BULK_READS = BULK_READS;
