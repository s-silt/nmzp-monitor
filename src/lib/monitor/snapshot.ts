import {storageProvider} from "./storage-target.ts";
import type { AgentId, EventSource } from "./types";

/** Fingerprints the ZCode *app* silently snapshotting a workspace — not a model tool call. */

export const SNAPSHOT_RULE = {
  host: "zcode_snapshot_host",
  path: "zcode_checkpoint_path",
  form: "zcode_oss_form",
  capture: "zcode_capture_event",
} as const;

export type SnapshotRuleId = (typeof SNAPSHOT_RULE)[keyof typeof SNAPSHOT_RULE];

const CHECKPOINT_RE =
  /(?:^|[\\/])\.zcode[\\/]v2[\\/]checkpoints(?:[\\/]|$)|repo_snapshot_extra_manifest|\.tar\.gz\.enc\b/i;
const OSS_FORM_RE = /x-oss-signature|ossaccesskeyid|x-oss-signature-version/i;
const OSS_POLICY_RE = /\bpolicy\b/i;
const CAPTURE_RE = /\b(captureBeforePrompt|repo-wiki-update)\b/;
const ZCODE_APP_HOST_RE = /(?:^|\.)zcode\.z\.ai$/i;
const ZCODE_REF_RE = /(?:https?:\/\/)?(?:[\w-]+\.)*zcode\.z\.ai(?::\d+)?(\/[^\s"'<>]*)?/gi;
const ZCODE_DOCS_PATH_RE = /^\/(?:[a-z]{2}\/)?docs(?:[/?#]|$)/i;

/** True when every path-bearing zcode.z.ai reference in blob is a docs URL. */
function allZcodeRefsAreDocs(blob: string): boolean {
  ZCODE_REF_RE.lastIndex = 0;
  const paths: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = ZCODE_REF_RE.exec(blob))) {
    if (m[1]) paths.push(m[1]);
  }
  return paths.length > 0 && paths.every((p) => ZCODE_DOCS_PATH_RE.test(p));
}
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

export function classifySnapshot(input: {
  agent?: AgentId;
  nativeTool?: string;
  command?: string;
  filePath?: string;
  url?: string;
  dest?: string;
  source?: EventSource;
}): SnapshotRuleId | null {
  const command = input.command ?? "";
  const filePath = input.filePath ?? "";
  const blob = `${command} ${filePath} ${input.url ?? ""} ${input.dest ?? ""}`;

  if (CHECKPOINT_RE.test(blob)) return SNAPSHOT_RULE.path;
  if (CAPTURE_RE.test(blob)) return SNAPSHOT_RULE.capture;
  if (OSS_FORM_RE.test(blob)) return SNAPSHOT_RULE.form;

  const hosts = [
    ...(input.dest ? [input.dest.toLowerCase()] : []),
    ...extractHosts(input.url ?? ""),
    ...extractHosts(command),
  ];

  const fromZcode =
    input.agent === "zcode" || input.nativeTool === "snapshot" || input.source === "probe";
  const skipZcodeAppHost = allZcodeRefsAreDocs(blob);

  for (const host of hosts) {
    if (isModelApiHost(host)) continue;
    if (ZCODE_APP_HOST_RE.test(host) && !skipZcodeAppHost) return SNAPSHOT_RULE.host;
    if (storageProvider(host)==="oss" && (fromZcode || OSS_POLICY_RE.test(blob))) return SNAPSHOT_RULE.host;
  }
  return null;
}
