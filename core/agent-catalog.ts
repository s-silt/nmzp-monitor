/** Reviewed official identifiers. Search hints are NOT identity proofs. No detection from config folders. */
export interface AgentAdapter {
  id: string;
  product: string;
  form: "cli" | "desktop" | "extension";
  source: string;
  checkedOn: string;
  npm?: string;
  command?: string;
  extension?: string;
  names?: string[];
  appx?: string[];
  hints?: string[];
  unsupported?: string;
  hook?: "grok" | "claude" | "codex";
  lifecycle?: "retired";
}
const date = "2026-09-20";
const cli = (
  id: string,
  product: string,
  source: string,
  npm?: string,
  command?: string,
  hook?: AgentAdapter["hook"],
): AgentAdapter => ({
  id,
  product,
  form: "cli",
  source,
  checkedOn: date,
  npm,
  command,
  hook,
  names: [product],
});
const desktop = (id: string, product: string, source: string, names = [product]): AgentAdapter => ({
  id,
  product,
  form: "desktop",
  source,
  checkedOn: date,
  names,
});
const ext = (id: string, product: string, extension: string): AgentAdapter => ({
  id,
  product,
  form: "extension",
  extension,
  source: `https://marketplace.visualstudio.com/items?itemName=${extension}`,
  checkedOn: date,
});
export const AGENT_CATALOG: readonly AgentAdapter[] = [
  {
    ...cli(
      "claude-code-cli",
      "Claude Code",
      "https://code.claude.com/docs/en/setup",
      "@anthropic-ai/claude-code",
      "claude",
      "claude",
    ),
    hints: [".local/bin/claude.exe"],
  },
  desktop("claude-desktop", "Claude Desktop", "https://claude.com/download", ["Claude"]),
  ext("claude-code-extension", "Claude Code", "anthropic.claude-code"),
  cli(
    "codex-cli",
    "Codex CLI",
    "https://github.com/openai/codex",
    "@openai/codex",
    "codex",
    "codex",
  ),
  {
    ...desktop(
      "codex-desktop",
      "Codex desktop",
      "https://learn.chatgpt.com/docs/windows/windows-app",
      ["Codex"],
    ),
    appx: ["OpenAI.Codex"],
  },
  ext("codex-extension", "Codex", "openai.chatgpt"),
  {
    ...cli(
      "grok-cli",
      "Grok CLI",
      "https://docs.x.ai/build/cli/reference",
      undefined,
      "grok",
      "grok",
    ),
    hints: [".grok/bin/grok.exe"],
    names: ["Grok", "Grok Build"],
  },
  cli(
    "gemini-cli",
    "Gemini CLI",
    "https://github.com/google-gemini/gemini-cli",
    "@google/gemini-cli",
    "gemini",
  ),
  ext("gemini-extension", "Gemini Code Assist", "Google.geminicodeassist"),
  cli(
    "qwen-cli",
    "Qwen Code",
    "https://github.com/QwenLM/qwen-code",
    "@qwen-code/qwen-code",
    "qwen",
  ),
  cli(
    "opencode-cli",
    "OpenCode",
    "https://github.com/anomalyco/opencode",
    "opencode-ai",
    "opencode",
  ),
  desktop("opencode-desktop", "OpenCode", "https://opencode.ai/download"),
  cli("aider-cli", "Aider", "https://aider.chat/docs/install.html", undefined, "aider"),
  cli("goose-cli", "Goose CLI", "https://github.com/aaif-goose/goose", undefined, "goose"),
  desktop(
    "goose-desktop",
    "Goose",
    "https://goose-docs.ai/docs/getting-started/installation/",
  ),
  desktop("zcode-desktop", "ZCode", "https://zcode.z.ai/en"),
  {
    ...cli("zcode-cli", "ZCode CLI", "https://zcode.z.ai/en"),
    unsupported: "no_verified_windows_identifier",
  },
  desktop("cursor-desktop", "Cursor", "https://cursor.com/download"),
  {
    ...cli("cursor-cli", "Cursor CLI", "https://cursor.com/docs/cli/installation"),
    unsupported: "windows_native_identifier_not_verified",
  },
  desktop("windsurf-desktop", "Windsurf", "https://windsurf.com/download"),
  desktop("devin-desktop", "Devin Desktop", "https://devin.ai/download", [
    "Devin",
    "Devin Desktop",
  ]),
  desktop("trae-desktop", "TRAE", "https://www.trae.ai/download", ["TRAE", "Trae"]),
  desktop("antigravity-desktop", "Antigravity", "https://antigravity.google/download", [
    "Antigravity",
    "Google Antigravity",
  ]),
  {
    ...cli("antigravity-cli", "Antigravity CLI", "https://antigravity.google/download"),
    unsupported: "separate_cli_identifier_pending",
  },
  cli(
    "copilot-cli",
    "GitHub Copilot CLI",
    "https://github.com/github/copilot-cli",
    "@github/copilot",
    "copilot",
  ),
  ext("copilot-extension", "GitHub Copilot", "GitHub.copilot"),
  ext("copilot-chat-extension", "GitHub Copilot Chat", "GitHub.copilot-chat"),
  ext("cline-extension", "Cline", "saoudrizwan.claude-dev"),
  { ...ext("roo-extension", "Roo Code", "RooVeterinaryInc.roo-cline"), lifecycle: "retired" },
  ext("kilo-extension", "Kilo Code", "kilocode.Kilo-Code"),
  ext("continue-extension", "Continue", "Continue.continue"),
  ext("augment-extension", "Augment Code", "augment.vscode-augment"),
  {
    ...cli(
      "augment-cli",
      "Auggie CLI",
      "https://docs.augmentcode.com/cli/setup-auggie/install-auggie-cli",
    ),
    unsupported: "official_windows_support_is_wsl",
  },
  ext("amazon-q-extension", "Amazon Q Developer", "AmazonWebServices.amazon-q-vscode"),
  {
    ...desktop("jetbrains-ai", "JetBrains AI / Junie", "https://www.jetbrains.com/ai/"),
    unsupported: "jetbrains_plugin_adapter_not_implemented",
  },
  desktop("kiro-desktop", "Kiro", "https://kiro.dev/downloads/"),
];
export const adapterById = (id: string) => AGENT_CATALOG.find((a) => a.id === id);

const AGENT_HEADS = new Set([
  "zcode",
  "codex",
  "grok",
  "claude",
  "cursor",
  "copilot",
  "windsurf",
  "gemini",
  "aider",
  "qwen",
  "cline",
  "trae",
]);

/** Display/filter id from a discovery adapter. Not process ownership. */
export function agentIdFromAdapter(adapterId: string): string | undefined {
  const hooked = adapterById(adapterId)?.hook;
  if (hooked) return hooked;
  const head = adapterId.split("-")[0] ?? "";
  return AGENT_HEADS.has(head) ? head : undefined;
}

export function agentsFromDiscovery(
  items: ReadonlyArray<{ adapterId: string; installation?: string }>,
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const it of items) {
    if (it.installation === "not_found") continue;
    const id = agentIdFromAdapter(it.adapterId);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}
