import { cn } from "@/lib/utils";

export function Meter({
  label,
  value,
  max,
  tone = "info",
}: {
  label: string;
  value: number;
  max: number;
  tone?: "info" | "ok" | "warn" | "danger";
}) {
  const pct = max <= 0 ? 0 : Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-3">
      <span className="w-36 shrink-0 truncate text-xs text-muted">{label}</span>
      <div className="h-1.5 min-w-0 flex-1 rounded-full bg-elevated">
        <div
          className={cn(
            "h-full rounded-full",
            tone === "danger" && "bg-danger",
            tone === "warn" && "bg-warn",
            tone === "ok" && "bg-ok",
            tone === "info" && "bg-fg/55",
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-10 shrink-0 text-right font-mono text-xs tabular-nums text-subtle">{value}</span>
    </div>
  );
}

export function QuotaMeter({ label, pct, hint }: { label: string; pct: number; hint?: string }) {
  const tone = pct >= 85 ? "danger" : pct >= 60 ? "warn" : "ok";
  return (
    <div className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-xs font-medium text-muted">{label}</span>
        <span
          className={cn(
            "font-mono text-2xl font-medium tabular-nums",
            tone === "danger" && "text-danger",
            tone === "warn" && "text-warn",
            tone === "ok" && "text-ok",
          )}
        >
          {pct}%
        </span>
      </div>
      <div className="mt-4 h-1.5 rounded-full bg-elevated">
        <div
          className={cn(
            "h-full rounded-full",
            tone === "danger" && "bg-danger",
            tone === "warn" && "bg-warn",
            tone === "ok" && "bg-ok",
          )}
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      {hint ? <p className="mt-2 text-xs text-subtle">{hint}</p> : null}
    </div>
  );
}
