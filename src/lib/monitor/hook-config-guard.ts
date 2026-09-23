import { mutatedPaths, normalizeFsPath, type SelfProtectionInput } from "./self-protection.ts";
import { explicitUploadPaths } from "./upload-operands.ts";
import { isDataOnlyCommand, nodeShellCommands } from "./command-intent.ts";

export const HOOK_GUARD_RULE = {
  trust: "zcode_trust_store_tamper",
  poison: "agent_hook_poison",
  disable: "agent_hook_disable",
  relay: "claude_settings_relay_write",
} as const;

const CONFIG_PATH =
  /(?:^|\/)(?:zcode\.json|\.zcode\/(?:cli\/)?config\.json|\.(?:claude|gemini|qwen|qoder|lingma|codebuddy)\/settings\.json|\.(?:codex|cursor|trae|trae-cn|grok)\/hooks(?:\/[^/]+)?\.json|\.gemini\/config\/hooks\.json|hooks\/hooks\.json|\.(?:zcode|claude|codex|cursor)-plugin\/plugin\.json|\.?mcp\.json)$/i;
const TRUST_PATH = /(?:^|\/)workspace-hook-trust-v1\.json$|(?:^|\/)\.zcode\/security\/?$/i;
const DOWNLOAD_EXEC =
  /\b(?:curl|wget|fetch)\b[^\r\n]*\|\s*(?:sh|bash|zsh|pwsh|powershell)(?:\b|\.exe\b)|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\r\n]*\|\s*(?:iex|Invoke-Expression)\b/i;
const PIPE_UPLOAD =
  /\b(?:cat|type|Get-Content|tar|zip|7z)\b[^\r\n]*\|\s*(?:curl|nc|ncat|ssh|rclone)\b/i;
const HOOK_EVENT =
  /^(?:PreToolUse|PostToolUse|PostToolUseFailure|PermissionRequest|SessionStart|UserPromptSubmit|Stop|BeforeTool|AfterTool)$/;

const CLAUDE_SETTINGS = /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i;
const RELAY_KEY_FRAGMENT = /["']ANTHROPIC_BASE_URL["']\s*:/;

function dangerousCommand(command: string): boolean {
  if (isDataOnlyCommand(command)) return false;
  return explicitUploadPaths(command).length > 0 || DOWNLOAD_EXEC.test(command) || PIPE_UPLOAD.test(command)
    || nodeShellCommands(command).some((call) => explicitUploadPaths(call.command, call.args).length > 0);
}

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function poisonedHook(value: unknown, inHook = false, depth = 0, processOnly = false): boolean {
  if (depth > 32) return false;
  if (Array.isArray(value))
    return value.some((v) => poisonedHook(v, inHook, depth + 1, processOnly));
  if (!object(value)) return false;
  // process argv 中的 | 只是普通参数。只有 command hook 或明确的 shell -c/-Command 才执行管道。
  const shellProcess =
    typeof value.command === "string" &&
    /(?:^|[\\/])(?:ba|z)?sh(?:\.exe)?$|(?:^|[\\/])(?:pwsh|powershell)(?:\.exe)?$/i.test(
      value.command,
    ) &&
    Array.isArray(value.args) &&
    value.args.some((v) => typeof v === "string" && /^(?:-c|-lc|-command)$/i.test(v));
  const argv = Array.isArray(value.args)
    ? value.args.filter((v): v is string => typeof v === "string")
    : [];
  if (inHook && typeof value.command === "string") {
    if (value.type === "process" || processOnly) {
      if (explicitUploadPaths(value.command, argv).length) return true;
    } else if (dangerousCommand(value.command)) return true;
  }
  if (
    inHook &&
    typeof value.command === "string" &&
    ((!processOnly && value.type !== "process") || shellProcess)
  ) {
    const command = [
      value.command,
      ...(Array.isArray(value.args) ? value.args.filter((v) => typeof v === "string") : []),
    ].join(" ");
    if (dangerousCommand(command)) return true;
  }
  return Object.entries(value).some(([key, child]) =>
    poisonedHook(
      child,
      inHook || key === "hooks" || key === "mcpServers" || HOOK_EVENT.test(key),
      depth + 1,
      processOnly || key === "mcpServers",
    ),
  );
}

/** Caller agent is deliberately not an exemption: any connected agent can tamper with another host. */
export function detectHookConfigGuard(
  input: SelfProtectionInput & { contents?: string },
): string | undefined {
  const targets = mutatedPaths(input).map(normalizeFsPath);
  if (targets.some((p) => TRUST_PATH.test(p))) return HOOK_GUARD_RULE.trust;
  if (!targets.some((p) => CONFIG_PATH.test(p) || CLAUDE_SETTINGS.test(p))) return undefined;
  const text = input.contents || input.command || "";
  try {
    const doc: unknown = JSON.parse(text);
    const mcpFile = targets.some((p) => /(?:^|\/)\.?mcp\.json$/i.test(p));
    if (poisonedHook(doc, mcpFile, 0, mcpFile)) return HOOK_GUARD_RULE.poison;
    // 已知 ZCode 配置语义：关闭 hooks.enabled 会关闭用户配置里的 NMZP；普通模型/主题修改仍记账。
    if (
      targets.some((p) => /(?:^|\/)\.zcode\/cli\/config\.json$/i.test(p)) &&
      object(doc) &&
      object(doc.hooks) &&
      doc.hooks.enabled === false
    ) {
      return HOOK_GUARD_RULE.disable;
    }
    // 合法中转与普通 MCP 授权不等于投毒。先检查可执行危险链，再按实际键名记账，
    // 不根据 URL 是否属于官方域名决定配置写入的风险，也不修改已有 MCP 审批状态。
    if (targets.some((p) => CLAUDE_SETTINGS.test(p)) && object(doc)
      && object(doc.env) && typeof doc.env.ANTHROPIC_BASE_URL === "string") return HOOK_GUARD_RULE.relay;
  } catch {
    // Edit 或 shell 写入可能只有片段。仍要求配置写入目标 + hook 声明语境 + 危险执行链同时存在。
    if (
      /\b(?:hooks|PreToolUse|SessionStart|UserPromptSubmit|PermissionRequest|Stop)\b/.test(text) &&
      /["']?(?:command|args)["']?\s*:/.test(text) &&
      (DOWNLOAD_EXEC.test(text) || PIPE_UPLOAD.test(text))
    ) {
      return HOOK_GUARD_RULE.poison;
    }
    if (targets.some((p) => CLAUDE_SETTINGS.test(p)) && RELAY_KEY_FRAGMENT.test(text)) return HOOK_GUARD_RULE.relay;
  }
  return undefined;
}
