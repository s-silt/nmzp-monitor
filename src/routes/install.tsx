import { Link, createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { AlertTriangle, ChevronDown } from "lucide-react";
import { AgentMark } from "@/components/agent-mark";
import { Button } from "@/components/ui/button";
import { AGENTS } from "@/lib/monitor/agents";
import {
  ANTIGRAVITY_HOOK,
  ATTACH_CMD,
  CLAUDE_HOOK,
  CODEBUDDY_HOOK,
  CODEX_HOOK,
  CODEX_TOML,
  CORE_INSTALL,
  CORE_PACK,
  CURSOR_HOOK,
  GEMINI_HOOK,
  GROK_HOOK,
  JOIN_COPY,
  KIMI_HOOK,
  LINGMA_HOOK,
  QODER_HOOK,
  QWEN_HOOK,
  TRAE_HOOK,
  ZCODE_HOOK,
} from "@/lib/monitor/hooks-config";
import { hookCapMsg, type Msg } from "@/lib/monitor/i18n";
import { formatRelative } from "@/lib/monitor/format";
import { SSH_CMD, SSH_HELP } from "@/lib/monitor/cli";
import { useMonitor, usePresentAgents, useScopedCapabilities, useT } from "@/lib/monitor/store";
import type { AgentId, DeviceCapability } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/install")({ component: InstallPage });

/** Agents with a real PreToolUse adapter. */
const SUPPORTED: AgentId[] = [
  "grok",
  "claude",
  "codex",
  "zcode",
  "antigravity",
  "kimi",
  "trae",
  "qwen",
  "qoder",
  "lingma",
  "codebuddy",
  "gemini",
  "cursor",
];

const SNIPPETS: Partial<Record<AgentId, { files: Array<{ path: string; body: string }> }>> = {
  grok: { files: [{ path: "~/.grok/hooks/nmzp.json", body: GROK_HOOK }] },
  claude: { files: [{ path: "~/.claude/settings.json", body: CLAUDE_HOOK }] },
  codex: {
    files: [
      { path: "~/.codex/hooks.json", body: CODEX_HOOK },
      { path: "~/.codex/config.toml", body: CODEX_TOML },
    ],
  },
  zcode: { files: [{ path: "~/.zcode/cli/config.json", body: ZCODE_HOOK }] },
  antigravity: { files: [{ path: "~/.gemini/config/hooks.json", body: ANTIGRAVITY_HOOK }] },
  kimi: { files: [{ path: "~/.kimi-code/config.toml", body: KIMI_HOOK }] },
  trae: {
    files: [
      { path: "~/.trae/hooks.json", body: TRAE_HOOK },
      { path: "~/.trae-cn/hooks.json", body: TRAE_HOOK },
    ],
  },
  qwen: { files: [{ path: "~/.qwen/settings.json", body: QWEN_HOOK }] },
  qoder: { files: [{ path: "~/.qoder/settings.json", body: QODER_HOOK }] },
  lingma: {
    files: [
      { path: "~/.lingma/settings.json", body: LINGMA_HOOK },
      { path: "~/.qoder-cn/settings.json", body: LINGMA_HOOK },
    ],
  },
  codebuddy: { files: [{ path: "~/.codebuddy/settings.json", body: CODEBUDDY_HOOK }] },
  gemini: { files: [{ path: "~/.gemini/settings.json", body: GEMINI_HOOK }] },
  cursor: { files: [{ path: "~/.cursor/hooks.json", body: CURSOR_HOOK }] },
};

const MUST_ENABLE: Partial<Record<AgentId, Msg>> = {
  codex: "codexMustEnable",
  zcode: "zcodeMustEnable",
  antigravity: "antigravityMustEnable",
  kimi: "kimiMustEnable",
  trae: "traeMustEnable",
  qwen: "qwenMustEnable",
  qoder: "qoderMustEnable",
  lingma: "lingmaMustEnable",
  codebuddy: "codebuddyMustEnable",
  gemini: "geminiMustEnable",
  cursor: "cursorMustEnable",
};

export function InstallPage() {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const synced = useMonitor((s) => s.synced);
  const capabilities = useScopedCapabilities();
  const present = usePresentAgents();
  const detected = present.filter((id) => SUPPORTED.includes(id));
  const [userToggled, setUserToggled] = useState<Record<string, boolean>>({});

  const isExpanded = (id: AgentId) => {
    if (userToggled[id] !== undefined) return userToggled[id];
    return detected.includes(id);
  };

  const toggleExpanded = (id: AgentId) => {
    setUserToggled((prev) => ({ ...prev, [id]: !isExpanded(id) }));
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-medium tracking-tight">{tx("attachTitle")}</h1>
        <p className="mt-2 max-w-prose text-sm text-muted">{tx("attachBody")}</p>
      </div>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)] lg:p-5">
        <h2 className="text-sm font-medium">{tx("installPack")}</h2>
        <p className="mt-2 text-sm text-muted">{tx("installPackNote")}</p>
        <div className="mt-4">
          <CopyBlock path="pack" body={CORE_PACK} />
        </div>
      </section>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)] lg:p-5">
        <h2 className="text-sm font-medium">{tx("installCore")}</h2>
        <p className="mt-2 text-sm text-muted">{tx("installCoreNote")}</p>
        <div className="mt-4">
          <CopyBlock path="ct" body={CORE_INSTALL} />
        </div>
      </section>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)] lg:p-5">
        <h2 className="text-sm font-medium">{tx("installJoin")}</h2>
        <p className="mt-2 text-sm text-muted">{tx("installJoinNote")}</p>
        <div className="mt-4 flex flex-col gap-4">
          <CopyBlock path="bundle" body={JOIN_COPY} />
          <CopyBlock path="join" body={ATTACH_CMD} />
        </div>
        <p className="mt-3 text-sm text-muted">{tx("attachNote")}</p>
        <p className="mt-2 text-sm text-muted">{tx("archiveHint")}</p>
      </section>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)] lg:p-5">
        <h2 className="text-sm font-medium">{tx("sshTitle")}</h2>
        <p className="mt-2 max-w-prose text-sm text-muted">{tx("sshBody")}</p>
        <div className="mt-4 flex flex-col gap-4">
          <CopyBlock path="board" body={SSH_CMD} />
          <CopyBlock path="nmzp" body={SSH_HELP} />
        </div>
      </section>

      <section className="grid gap-2 md:grid-cols-3">
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <p className="font-mono text-xs text-subtle">1</p>
          <h2 className="mt-1 text-sm font-medium">{tx("coreLayer")}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{tx("coreLayerBody")}</p>
        </article>
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <p className="font-mono text-xs text-subtle">2</p>
          <h2 className="mt-1 text-sm font-medium">{tx("probeLayer")}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{tx("probeLayerBody")}</p>
        </article>
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <p className="font-mono text-xs text-subtle">3</p>
          <h2 className="mt-1 text-sm font-medium">{tx("hookLayer")}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{tx("hookLayerBody")}</p>
        </article>
      </section>

      <section className="grid gap-2 md:grid-cols-2">
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-medium">{tx("interceptTitle")}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{tx("interceptBody")}</p>
        </article>
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-medium">{tx("personaTitle")}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{tx("personaBody")}</p>
        </article>
      </section>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
        <h2 className="text-sm font-medium">{tx("supportedAdapters")}</h2>
        <p className="mt-2 text-sm text-muted">{tx("supportedHint")}</p>
        <ul className="mt-3 flex flex-wrap gap-2">
          {SUPPORTED.map((id) => (
            <li key={id} className="rounded-md bg-elevated px-2 py-1">
              <AgentMark id={id} />
            </li>
          ))}
        </ul>
      </section>

      {detected.length > 0 ? (
        <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-medium">{tx("presentOnly")}</h2>
          <p className="mt-2 text-sm text-muted">{tx("presentHint")}</p>
          <ul className="mt-3 flex flex-wrap gap-2">
            {detected.map((id) => (
              <li key={id} className="rounded-md bg-elevated px-2 py-1">
                <AgentMark id={id} />
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {/* Prominent warning banner: Installation is not protection */}
      <div className="rounded-xl border border-warn/30 bg-warn/10 p-4 text-xs leading-relaxed text-fg flex items-start gap-3 shadow-[var(--shadow-border)]">
        <AlertTriangle className="size-4 text-warn shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-warn">{tx("installNotGuarded")}</div>
          <div className="text-muted leading-relaxed">{tx("whyQuiet")}</div>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        {SUPPORTED.map((id) => (
          <AgentInstallAccordion
            key={id}
            id={id}
            isOpen={isExpanded(id)}
            onToggle={() => toggleExpanded(id)}
            cap={capabilities[`hook_${id}`]}
            synced={synced}
            locale={locale}
          />
        ))}
      </div>

      <p className="text-xs text-subtle">
        <Link to="/rules" className="underline-offset-2 hover:underline">
          {tx("customRules")}
        </Link>
        {" · "}
        <Link to="/threats" className="underline-offset-2 hover:underline">
          {tx("navThreats")}
        </Link>
      </p>
    </div>
  );
}

function AgentInstallAccordion({
  id,
  isOpen,
  onToggle,
  cap,
  synced,
  locale,
}: {
  id: AgentId;
  isOpen: boolean;
  onToggle: () => void;
  cap?: DeviceCapability;
  synced: boolean;
  locale: "zh" | "en";
}) {
  const tx = useT();
  const def = AGENTS[id];
  const spec = SNIPPETS[id];
  const extraKey = MUST_ENABLE[id];
  const extra = extraKey ? tx(extraKey) : "";
  const hint = extra ? `${tx("hookLayerBody")} ${extra}` : tx("hookLayerBody");
  const msg = hookCapMsg(cap);

  return (
    <section className="rounded-xl border border-line bg-surface p-4 shadow-[var(--shadow-border)] transition-all">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full cursor-pointer flex-wrap items-center justify-between gap-3 text-left focus-visible:outline-none"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <AgentMark id={id} />
          <span className="font-mono text-xs text-subtle">
            {def.vendor} · {def.process}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!synced ? (
            <span className="h-5 w-24 rounded bg-elevated/70 animate-pulse border border-line/40" />
          ) : (
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[11px] border",
                msg === "hookCapActive"
                  ? "bg-ok/10 text-ok border-ok/20"
                  : msg === "hookCapUntrusted" ||
                      msg === "hookCapModified" ||
                      msg === "hookCapDisabled" ||
                      msg === "hookCapFeatureOff" ||
                      msg === "hookCapError"
                    ? "bg-warn/10 text-warn border-warn/25"
                    : "bg-elevated text-muted border-line",
              )}
            >
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  msg === "hookCapActive"
                    ? "bg-ok"
                    : msg === "hookCapUntrusted" || msg === "hookCapModified" || msg === "hookCapError"
                      ? "bg-warn"
                      : "bg-muted",
                )}
              />
              <span>{tx(msg)}</span>
              {cap?.lastSuccess ? (
                <span className="tabular-nums text-subtle">
                  ({formatRelative(cap.lastSuccess, locale)})
                </span>
              ) : null}
            </span>
          )}
          <ChevronDown
            className={cn(
              "size-4 text-muted transition-transform duration-200",
              isOpen && "rotate-180",
            )}
          />
        </div>
      </button>

      {isOpen && (
        <div className="mt-4 space-y-3 border-t border-line/50 pt-3 animate-in fade-in-50">
          {/* Prominent callout for configured without receipt */}
          {msg === "hookCapNoReceipt" && (
            <div className="rounded-lg border border-line bg-elevated/80 p-3 text-xs text-muted flex items-start gap-2.5">
              <AlertTriangle className="size-4 text-warn shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-fg">{tx("installNoReceiptCallout")}</span>
              </div>
            </div>
          )}

          {/* Prominent callout for untrusted / modified */}
          {(msg === "hookCapUntrusted" || msg === "hookCapModified") && (
            <div className="rounded-lg border border-warn/30 bg-warn/10 p-3 text-xs text-warn flex items-start gap-2.5">
              <AlertTriangle className="size-4 text-warn shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold">{tx(msg)}</span>
              </div>
            </div>
          )}

          <p className="text-xs leading-relaxed text-muted">{hint}</p>

          {spec ? (
            <div className="flex flex-col gap-3">
              {spec.files.map((file) => (
                <FoldableCopyBlock key={file.path} path={file.path} body={file.body} />
              ))}
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}

function FoldableCopyBlock({ path, body }: { path: string; body: string }) {
  const tx = useT();
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(false);
  const lineCount = body.trim().split("\n").length;

  return (
    <div className="rounded-lg border border-line/60 bg-elevated/40 p-3 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-xs text-fg break-all">{path}</p>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(body);
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1600);
              } catch {
                setCopied(false);
              }
            }}
          >
            {copied ? tx("copied") : tx("copy")}
          </Button>
          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:text-fg hover:bg-elevated transition-colors cursor-pointer"
          >
            <span>{open ? tx("hideConfigSnippet") : tx("showConfigSnippet")}</span>
            <span className="text-[10px] text-subtle tabular-nums">({lineCount})</span>
            <ChevronDown className={cn("size-3.5 transition-transform", open && "rotate-180")} />
          </button>
        </div>
      </div>
      {open ? (
        <pre className="max-h-96 overflow-x-auto rounded-md bg-elevated p-3 font-mono text-xs leading-relaxed text-fg border border-line/40">
          {body}
        </pre>
      ) : null}
    </div>
  );
}

function CopyBlock({ path, body }: { path: string; body: string }) {
  const tx = useT();
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="font-mono text-xs text-muted">{path}</p>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(body);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1600);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? tx("copied") : tx("copy")}
        </Button>
      </div>
      <pre className="overflow-x-auto rounded-md bg-elevated p-3 font-mono text-xs leading-relaxed text-fg">
        {body}
      </pre>
    </div>
  );
}
