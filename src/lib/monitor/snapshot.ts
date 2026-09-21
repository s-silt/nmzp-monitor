import type { AgentId, EventSource } from "./types";

/** Fingerprints the ZCode *app* silently snapshotting a workspace — not a model tool call. */

export const SNAPSHOT_RULE = {
  host: "zcode_snapshot_host",
  path: "zcode_checkpoint_path",
  capture: "zcode_capture_event",
} as const;

export type SnapshotRuleId = (typeof SNAPSHOT_RULE)[keyof typeof SNAPSHOT_RULE];

export const ZCODE_CONTEXT_RULE = {
  checkpoint: "zcode_local_checkpoint",
  feedback: "zcode_feedback_upload",
  form: "zcode_oss_form",
} as const;

const CHECKPOINT_RE = /(?:^|[\\/])\.zcode[\\/]v2[\\/]checkpoints(?:[\\/]|$)/i;
const ENCRYPTED_CHECKPOINT_RE =
  /\.zcode[\\/]v2[\\/]checkpoints[\\/][^\r\n"'<>]*?\.enc(?=$|[\s"';,)])/i;
const LEGACY_ARTIFACT_RE = /\brepo_snapshot_extra_manifest\b|\.tar\.gz\.enc\b/i;
const LOCAL_CHECKPOINT_RE =
  /\bgit-checkpoint-index\b|refs[\\/]zcode[\\/]checkpoints\b|checkpoint@zcode\.local\b/i;
const OSS_FORM_RE = /x-oss-signature|ossaccesskeyid|x-oss-signature-version/i;
const CAPTURE_RE = /\b(captureBeforePrompt|repo-wiki-update)\b/;
const ZCODE_APP_HOST_RE = /(?:^|\.)zcode\.z\.ai$/i;
const SNAPSHOT_CREDENTIAL_PATH =
  /^\/(?:api\/v1\/snapshot\/upload-credential|v2\/oss-credentials)\/?$/i;
const FEEDBACK_CREDENTIAL_PATH = /^\/(?:api\/v1\/)?feedback\/attachment\/upload-credential\/?$/i;
const MODEL_API_RE =
  /(?:^|\.)(api\.z\.ai|open\.bigmodel\.cn|api\.openai\.com|chatgpt\.com|api\.x\.ai|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.deepseek\.com|dashscope\.aliyuncs\.com|api\.moonshot\.(cn|ai)|api\.mistral\.ai)$/i;
const HOST_FIND = /(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;

export function extractHosts(text: string): string[] {
  if (!text) return [];
  const out: string[] = [];
  HOST_FIND.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HOST_FIND.exec(text))) {
    const h = m[1]!.toLowerCase();
    if (!out.includes(h)) out.push(h);
  }
  return out;
}

export function isModelApiHost(host: string) {
  return MODEL_API_RE.test(host.toLowerCase());
}

export function isCheckpointPath(path: string) {
  return CHECKPOINT_RE.test(path);
}

export function isLegacySnapshotArtifact(text: string): boolean {
  return LEGACY_ARTIFACT_RE.test(text) || ENCRYPTED_CHECKPOINT_RE.test(text);
}

export function isLocalCheckpointReference(text: string): boolean {
  return CHECKPOINT_RE.test(text) || LOCAL_CHECKPOINT_RE.test(text);
}

interface SnapshotInput {
  agent?: AgentId;
  nativeTool?: string;
  command?: string;
  filePath?: string;
  url?: string;
  dest?: string;
  source?: EventSource;
}

/** URL 的 host 和 pathname 必须来自同一个目标；查询参数、文档引用和旁边的域名不能拼成凭证请求。 */
function hasCredentialEndpoint(input: SnapshotInput, pathPattern: RegExp): boolean {
  const candidates = [input.url ?? "", ...(input.command?.match(/https?:\/\/[^\s"'<>`]+/gi) ?? [])];
  if (input.url?.startsWith("/") && input.dest) {
    try {
      const origin = new URL(input.dest.includes("://") ? input.dest : `https://${input.dest}`);
      candidates.push(new URL(input.url, origin).href);
    } catch {
      /* Invalid destination is not endpoint evidence. */
    }
  }
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate.replace(/[),;]+$/, ""));
      if (
        !/^https?:$/.test(url.protocol) ||
        !ZCODE_APP_HOST_RE.test(url.hostname.replace(/\.$/, ""))
      )
        continue;
      if (pathPattern.test(url.pathname)) return true;
    } catch {
      /* Not an absolute HTTP endpoint. */
    }
  }
  return false;
}

export function classifySnapshot(input: SnapshotInput): SnapshotRuleId | null {
  const blob = `${input.command ?? ""} ${input.filePath ?? ""}`;
  // 本地 JSON/ref/index 不是历史上传包。agent/source 标签也不是上传证据。
  if (isLegacySnapshotArtifact(blob)) return SNAPSHOT_RULE.path;
  if (CAPTURE_RE.test(blob)) return SNAPSHOT_RULE.capture;
  if (hasCredentialEndpoint(input, SNAPSHOT_CREDENTIAL_PATH)) return SNAPSHOT_RULE.host;
  return null;
}

export function classifyZcodeContext(input: SnapshotInput): string | null {
  if (hasCredentialEndpoint(input, FEEDBACK_CREDENTIAL_PATH))
    return ZCODE_CONTEXT_RULE.feedback;
  const blob = `${input.command ?? ""} ${input.filePath ?? ""}`;
  if (OSS_FORM_RE.test(blob)) return ZCODE_CONTEXT_RULE.form;
  if (isLocalCheckpointReference(blob)) return ZCODE_CONTEXT_RULE.checkpoint;
  return null;
}
