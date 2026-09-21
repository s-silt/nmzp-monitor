import { Link, createFileRoute } from "@tanstack/react-router";
import { Key, Lock, Server, ShieldAlert, Skull } from "lucide-react";
import { AgentMark } from "@/components/agent-mark";
import { DecisionBadge, RiskBadge } from "@/components/risk-badge";
import { formatDateTime, sanitizeDisplayUrl, truncate } from "@/lib/monitor/format";
import { shortEvidenceId } from "@/lib/monitor/network-view";
import { RULE_BY_ID } from "@/lib/monitor/rules";
import { statsFrom } from "@/lib/monitor/stats";
import { useFilteredEvents, useMonitor, useOverviewMachines, useT } from "@/lib/monitor/store";
import { threatMsg } from "@/lib/monitor/i18n";

export const Route = createFileRoute("/threats")({ component: ThreatsPage });

export function ThreatsPage() {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const fleet = useOverviewMachines();
  const events = useFilteredEvents();
  const stats = statsFrom(events);
  const hostBlocked = [...events]
    .reverse()
    .filter((e) => e.enforcement === "blocked" && (e.threat === "exfil" || e.threat === "secret" || e.threat === "tamper" || e.threat === "isolate" || e.threat === "poison"))
    .slice(0, 12);
  const returnedDeny = [...events]
    .reverse()
    .filter((e) => e.enforcement === "returned_deny")
    .slice(0, 8);
  const snapshots = [...events]
    .reverse()
    .filter((e) => e.hookBlind)
    .slice(0, 8);

  return (
    <div className="flex flex-col gap-6">
      <div className="rounded-2xl bg-surface p-5 shadow-[var(--shadow-border)] border border-line">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-5 text-danger" />
            <h1 className="text-2xl font-bold tracking-tight text-fg">{tx("guardTitle")}</h1>
          </div>
          <span className="font-mono text-xs text-muted bg-elevated px-2 py-0.5 rounded border border-line">
            {tx("utc8")}
          </span>
        </div>
        <p className="mt-1 max-w-prose text-xs sm:text-sm text-muted">{tx("guardLead")}</p>
      </div>

      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-danger/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("exfil")}</p>
            <Lock className="size-3.5 text-danger" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-danger">{stats.exfil}</p>
        </div>
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-warn/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("secrets")}</p>
            <Key className="size-3.5 text-warn" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-warn">{stats.secrets}</p>
        </div>
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-danger/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("blocked")}</p>
            <Lock className="size-3.5 text-danger" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-danger">{stats.blocked}</p>
        </div>
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-warn/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("returnedDeny")}</p>
            <ShieldAlert className="size-3.5 text-warn" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-warn">{stats.returnedDeny}</p>
        </div>
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-danger/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("isolate")}</p>
            <Server className="size-3.5 text-danger" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-danger">{stats.isolate}</p>
        </div>
        <div className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] border border-warn/20">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-muted">{tx("poison")}</p>
            <Skull className="size-3.5 text-warn" />
          </div>
          <p className="mt-2 font-mono text-2xl font-bold tabular-nums text-warn">{stats.poison}</p>
        </div>
      </div>

      <section className="grid gap-3 lg:grid-cols-3">
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("actorTitle")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("actorBody")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("scopeTitle")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("scopeBody")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("attachTitle")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("attachBody")}</p>
        </article>
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("step2")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("step2Body")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("step3")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("step3Body")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("privacyTitle")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("privacyBody")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-semibold">{tx("selfTitle")}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("selfBody")}</p>
        </article>
      </section>

      {snapshots.length > 0 ? (
        <section>
          <h2 className="mb-3 text-sm font-medium">{tx("snapshotTitle")}</h2>
          <ul className="rounded-lg bg-surface px-4 shadow-[var(--shadow-border)]">
            {snapshots.map((e) => {
              const rule = e.ruleId ? RULE_BY_ID[e.ruleId] : undefined;
              const hostName = fleet.find((m) => m.id === e.machineId)?.hostname ?? e.machineId;
              const cleanCmd = sanitizeDisplayUrl(e.redacted || e.input);
              return (
                <li key={e.id} className="border-b border-line py-3 last:border-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <AgentMark id={e.agent} showName={false} />
                      <span className="font-mono text-xs uppercase text-warn">{tx("probeCaught")}</span>
                      <RiskBadge risk={e.risk} />
                      <DecisionBadge decision={e.decision} />
                    </div>
                    <span className="font-mono text-xs text-subtle" suppressHydrationWarning>
                      {shortEvidenceId(e.id)} · {formatDateTime(e.ts, locale)}
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-sm break-all">{truncate(cleanCmd, 120)}</p>
                  <p className="mt-1 text-xs text-muted font-mono">
                    {rule ? (locale === "zh" ? rule.title : rule.titleEn) : e.tool === "unknown" ? tx("unknown") : e.tool}
                    {e.dest ? ` · ${e.dest}` : ""}
                    {hostName ? ` · ${hostName}` : ""}
                  </p>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      <section>
        <h2 className="mb-3 text-sm font-medium">{tx("whyBlocked")}</h2>
        {hostBlocked.length === 0 ? (
          <p className="rounded-lg bg-surface px-4 py-8 text-center text-sm text-muted shadow-[var(--shadow-border)]">
            {tx("emptyEvents")}
          </p>
        ) : (
          <ul className="rounded-lg bg-surface px-4 shadow-[var(--shadow-border)]">
            {hostBlocked.map((e) => {
              const rule = e.ruleId ? RULE_BY_ID[e.ruleId] : undefined;
              const hostName = fleet.find((m) => m.id === e.machineId)?.hostname ?? e.machineId;
              const cleanCmd = sanitizeDisplayUrl(e.redacted || e.input);
              return (
                <li key={e.id} className="border-b border-line py-3 last:border-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <AgentMark id={e.agent} showName={false} />
                      {e.threat ? <span className="font-mono text-xs uppercase text-danger">{tx(threatMsg(e.threat))}</span> : null}
                      <span className="font-mono text-xs text-danger">{tx("blocked")}</span>
                      <RiskBadge risk={e.risk} />
                    </div>
                    <span className="font-mono text-xs text-subtle" suppressHydrationWarning>
                      {shortEvidenceId(e.id)} · {formatDateTime(e.ts, locale)}
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-sm break-all">{truncate(cleanCmd, 120)}</p>
                  <p className="mt-1 text-xs text-muted font-mono">
                    {rule ? (locale === "zh" ? rule.title : rule.titleEn) : e.tool === "unknown" ? tx("unknown") : e.tool}
                    {e.detectedModel ? ` · ${e.detectedModel}` : ""}
                    {e.secretKinds?.length ? ` · ${e.secretKinds.join(", ")}` : ""}
                    {hostName ? ` · ${hostName}` : ""}
                  </p>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {returnedDeny.length > 0 ? (
        <section>
          <h2 className="mb-3 text-sm font-medium">{tx("returnedDeny")}</h2>
          <ul className="rounded-lg bg-surface px-4 shadow-[var(--shadow-border)]">
            {returnedDeny.map((e) => {
              const rule = e.ruleId ? RULE_BY_ID[e.ruleId] : undefined;
              const hostName = fleet.find((m) => m.id === e.machineId)?.hostname ?? e.machineId;
              const cleanCmd = sanitizeDisplayUrl(e.redacted || e.input);
              return (
                <li key={e.id} className="border-b border-line py-3 last:border-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <AgentMark id={e.agent} showName={false} />
                      <span className="font-mono text-xs text-warn">{tx("returnedDeny")}</span>
                      <RiskBadge risk={e.risk} />
                    </div>
                    <span className="font-mono text-xs text-subtle" suppressHydrationWarning>
                      {shortEvidenceId(e.id)} · {formatDateTime(e.ts, locale)}
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-sm break-all">{truncate(cleanCmd, 120)}</p>
                  <p className="mt-1 text-xs text-muted font-mono">
                    {rule ? (locale === "zh" ? rule.title : rule.titleEn) : e.tool === "unknown" ? tx("unknown") : e.tool}
                    {hostName ? ` · ${hostName}` : ""}
                  </p>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      <p className="text-xs text-subtle">
        <Link to="/" className="underline-offset-2 hover:underline">
          {tx("navHome")}
        </Link>
        {" · "}
        <Link to="/rules" className="underline-offset-2 hover:underline">
          {tx("navRules")}
        </Link>
      </p>
    </div>
  );
}
