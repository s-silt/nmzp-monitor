import { Camera, Shield } from "lucide-react";
import { formatDateTime } from "@/lib/monitor/format";
import { buildSnapshotView, snapshotHosts, type SnapshotTone } from "@/lib/monitor/snapshot-guard";
import { useMonitor, useT } from "@/lib/monitor/store";
import type { Machine } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

function toneClass(tone: SnapshotTone): string {
  if (tone === "ok") return "text-ok";
  if (tone === "warn") return "text-warn";
  return "text-muted";
}

export function SnapshotGuardSection({
  machines,
  host,
  now,
}: {
  machines: Machine[];
  host: string;
  now: number;
}) {
  const tx = useT();
  const rows = snapshotHosts(machines, host);
  return (
    <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]">
      <div className="flex items-center gap-2 border-b border-line pb-3">
        <Camera className="size-4 text-muted" />
        <h2 className="text-sm font-semibold text-fg">{tx("sgTitle")}</h2>
      </div>
      <p className="mt-3 max-w-3xl text-xs leading-relaxed text-muted">{tx("sgScope")}</p>
      {rows.length === 0 ? (
        <p className="mt-4 text-sm text-muted">{tx("sgEmpty")}</p>
      ) : (
        <ul className="mt-4 grid gap-3 lg:grid-cols-2">
          {rows.map((m) => (
            <SnapshotGuardCard key={m.id} machine={m} now={now} />
          ))}
        </ul>
      )}
    </section>
  );
}

function SnapshotGuardCard({ machine, now }: { machine: Machine; now: number }) {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const view = buildSnapshotView(machine.snapshotGuard, machine.status, now);
  return (
    <li className="rounded-lg border border-line bg-elevated/50 p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="size-3.5 text-muted" />
          <p className="font-mono text-sm font-semibold text-fg">{machine.hostname}</p>
        </div>
        {view.stale ? <span className="font-mono text-[11px] text-muted">{tx("sgStale")}</span> : null}
      </div>
      {view.status === "missing" ? (
        <p className="mt-3 text-xs text-muted">{tx("notCollected")}</p>
      ) : view.status === "invalid" ? (
        <p className="mt-3 text-xs text-muted">{tx("sgInvalid")}</p>
      ) : (
        <dl className="mt-3 grid gap-2 text-xs">
          <div>
            <dt className="text-[11px] text-subtle">{tx("sgWrite")}</dt>
            <dd className={cn("mt-0.5 font-medium", toneClass(view.write.tone))}>{tx(view.write.key)}</dd>
          </div>
          <div>
            <dt className="text-[11px] text-subtle">{tx("sgCoverage")}</dt>
            <dd className={cn("mt-0.5 font-medium", toneClass(view.coverage.tone))}>{tx(view.coverage.key)}</dd>
          </div>
          <div>
            <dt className="text-[11px] text-subtle">{tx("sgProvenance")}</dt>
            <dd className={cn("mt-0.5 font-medium", toneClass(view.provenance.tone))}>{tx(view.provenance.key)}</dd>
          </div>
          <div>
            <dt className="text-[11px] text-subtle">{tx("sgLastVerified")}</dt>
            <dd className="mt-0.5 font-mono text-muted">
              {view.lastVerified > 0 ? formatDateTime(view.lastVerified, locale) : tx("sgNotVerified")}
            </dd>
          </div>
          {view.errorKey ? <p className="text-warn">{tx(view.errorKey)}</p> : null}
          {view.activeKnownDirOnly ? <p className="text-[11px] text-subtle">{tx("sgActiveDirOnly")}</p> : null}
        </dl>
      )}
    </li>
  );
}
