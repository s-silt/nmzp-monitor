import { useT } from "@/lib/monitor/store";
import type { Action, Decision, Risk } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

const riskStyles: Record<Risk, { text: string; bg: string; border: string; dot: string }> = {
  high: {
    text: "text-danger",
    bg: "bg-danger/10",
    border: "border-danger/25",
    dot: "bg-danger",
  },
  medium: {
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/25",
    dot: "bg-warn",
  },
  low: {
    text: "text-ok",
    bg: "bg-ok/10",
    border: "border-ok/25",
    dot: "bg-ok",
  },
  info: {
    text: "text-info",
    bg: "bg-info/10",
    border: "border-info/25",
    dot: "bg-info",
  },
};

const decisionStyles: Record<Decision | Action, { text: string; bg: string; border: string; dot: string }> = {
  block: {
    text: "text-danger",
    bg: "bg-danger/10",
    border: "border-danger/25",
    dot: "bg-danger",
  },
  confirm: {
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/25",
    dot: "bg-warn",
  },
  allow: {
    text: "text-ok",
    bg: "bg-ok/10",
    border: "border-ok/25",
    dot: "bg-ok",
  },
  log: {
    text: "text-muted",
    bg: "bg-muted/10",
    border: "border-muted/20",
    dot: "bg-muted",
  },
  rewrite: {
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/25",
    dot: "bg-warn",
  },
};

export function RiskBadge({ risk, className }: { risk: Risk; className?: string }) {
  const tx = useT();
  const s = riskStyles[risk] ?? riskStyles.info;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px] font-medium tracking-tight",
        s.bg,
        s.border,
        s.text,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", s.dot, risk === "high" && "animate-pulse")} />
      {tx(risk)}
    </span>
  );
}

export function DecisionBadge({ decision, className }: { decision: Decision | Action; className?: string }) {
  const tx = useT();
  const s = decisionStyles[decision] ?? decisionStyles.log;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px] font-medium tracking-tight",
        s.bg,
        s.border,
        s.text,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", s.dot)} />
      {tx(decision)}
    </span>
  );
}

