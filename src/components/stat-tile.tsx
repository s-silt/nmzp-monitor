import React from "react";
import { formatCompact } from "@/lib/monitor/format";
import { cn } from "@/lib/utils";

export function StatTile({
  label,
  value,
  hint,
  icon: Icon,
  tone = "default",
  onClick,
}: {
  label: string;
  value: number | string;
  hint?: string;
  icon?: React.ComponentType<{ className?: string }>;
  tone?: "default" | "danger" | "warn";
  onClick?: () => void;
}) {
  const className = cn(
    "group relative flex min-h-22 w-full flex-col justify-between rounded-xl bg-surface p-4 text-left shadow-[var(--shadow-border)] transition-all duration-200",
    onClick && "hover:shadow-[var(--shadow-border-hover)] hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.99]",
    tone === "danger" && "hover:border-danger/30",
    tone === "warn" && "hover:border-warn/30",
  );
  const inner = (
    <>
      <div className="flex w-full items-center justify-between gap-2">
        <span className="text-xs font-medium tracking-tight text-muted group-hover:text-fg/85 transition-colors">
          {label}
        </span>
        {Icon ? (
          <span
            className={cn(
              "flex size-7 items-center justify-center rounded-lg bg-elevated/70 p-1 text-muted transition-colors group-hover:text-fg",
              tone === "danger" && "text-danger bg-danger/10",
              tone === "warn" && "text-warn bg-warn/10",
            )}
          >
            <Icon className="size-3.5" />
          </span>
        ) : null}
      </div>
      <div className="mt-2">
        <span
          className={cn(
            "font-mono text-2xl font-semibold tabular-nums tracking-tight",
            tone === "danger" && "text-danger",
            tone === "warn" && "text-warn",
            tone === "default" && "text-fg",
          )}
        >
          {typeof value === "number" ? formatCompact(value) : value}
        </span>
        {hint ? <p className="mt-1 text-[11px] text-subtle">{hint}</p> : null}
      </div>
    </>
  );
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={className}>
        {inner}
      </button>
    );
  }
  return <div className={className}>{inner}</div>;
}

