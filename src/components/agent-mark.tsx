import { AGENTS } from "@/lib/monitor/agents";
import type { AgentId } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

const tone: Partial<Record<AgentId, string>> = {
  zcode: "text-zcode",
  codex: "text-codex",
  grok: "text-grok",
};

export function AgentMark({
  id,
  showName = true,
  className,
}: {
  id: AgentId;
  showName?: boolean;
  className?: string;
}) {
  const def = AGENTS[id];
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span
        className={cn(
          "inline-flex size-5 items-center justify-center rounded-xs font-mono text-xs font-medium leading-none shadow-[var(--shadow-border)]",
          tone[id] ?? "text-fg",
        )}
      >
        {def.letter}
      </span>
      {showName ? <span className="text-sm text-fg">{def.name}</span> : null}
    </span>
  );
}
