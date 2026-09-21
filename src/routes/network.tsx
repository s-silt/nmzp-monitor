import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Download, Search, X } from "lucide-react";
import { toast } from "sonner";
import { AgentMark } from "@/components/agent-mark";
import { DecisionBadge } from "@/components/risk-badge";
import { EventRow } from "@/components/event-row";
import { Button } from "@/components/ui/button";
import { isAgentId } from "@/lib/monitor/agents";
import { formatDateTime, formatRelative, sanitizeDisplayUrl, truncate } from "@/lib/monitor/format";
import { sourceMsg } from "@/lib/monitor/i18n";
import {
  networkOwnerMessage,
  CLOCK_TICK_MS,
  collectTcpRows,
  decisionMsg,
  enforcementMsg,
  eventOssHosts,
  filterDeclaredEvents,
  formatDeclaredHost,
  formatSocket,
  isSynSent,
  networkExportPayload,
  sampleStatusKey,
  sampleView,
  scopedHistory,
  shortEvidenceId,
  tcpEmptyKind,
  visibleDestinations,
  type NetworkViewStatus,
  type TcpRow,
} from "@/lib/monitor/network-view";
import { useFilteredEvents, useMonitor, useOverviewMachines, useT } from "@/lib/monitor/store";
import { effectiveMachineFilter } from "@/lib/monitor/stats";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/network")({ component: NetworkPage });

const PAGE = 50;

function useWallClock(periodMs = CLOCK_TICK_MS): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), periodMs);
    return () => clearInterval(id);
  }, [periodMs]);
  return now;
}

function statusClass(status: NetworkViewStatus): string {
  if (status === "offline") return "text-danger";
  if (
    status === "timeout" ||
    status === "permission" ||
    status === "unsupported" ||
    status === "partial" ||
    status === "truncated" ||
    status === "stale" ||
    status === "not_sampled" ||
    status === "error"
  ) {
    return "text-warn";
  }
  return "text-muted";
}

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function NetworkPage() {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const fleet = useOverviewMachines();
  const machineFilter = useMonitor((s) => s.machineFilter);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const historyAll = useMonitor((s) => s.networkHistory);
  const events = useFilteredEvents();
  const host = effectiveMachineFilter(machineFilter, fleet);
  const now = useWallClock();
  const [q, setQ] = useState("");
  const [ossHigh, setOssHigh] = useState(false);
  const [tcpLimit, setTcpLimit] = useState(PAGE);
  const [histLimit, setHistLimit] = useState(PAGE);
  const [declLimit, setDeclLimit] = useState(PAGE);

  const machines = host === "all" ? fleet : fleet.filter((m) => m.id === host);
  const query = q.trim().toLowerCase();

  const samples = useMemo(
    () => machines.map((m) => ({ machine: m, view: sampleView(m, now) })),
    [machines, now],
  );

  const tcpRows = useMemo(
    () => collectTcpRows(samples, { agent: agentFilter, query }),
    [samples, agentFilter, query],
  );

  const history = useMemo(
    () => scopedHistory(historyAll, { machineId: host, agent: agentFilter, query }),
    [historyAll, host, agentFilter, query],
  );

  const declared = useMemo(
    () => filterDeclaredEvents(events, { query, ossHigh }),
    [events, query, ossHigh],
  );

  const riskTargets = useMemo(
    () => filterDeclaredEvents(events, { query, ossHigh: true }),
    [events, query],
  );

  const anyLive = samples.some((s) => s.view.live);
  const emptyTcp = tcpEmptyKind(samples, tcpRows.length, { query, agent: agentFilter });

  const handleExport = () => {
    const exportedAt = Date.now();
    const day = formatDateTime(exportedAt, locale).slice(0, 10);
    downloadJson(
      `nmzp-network-export-${day === "—" ? exportedAt : day}.json`,
      networkExportPayload({
        exportedAt,
        filters: { machineId: host, agent: agentFilter, query, ossHigh },
        samples: samples.map(({ machine, view }) => ({
          machineId: machine.id,
          hostname: machine.hostname,
          status: view.status,
          quality: view.quality,
          live: view.live,
          ageMs: view.ageMs,
          observedAt: view.observedAt,
          receivedAt: view.receivedAt,
          truncated: view.truncated,
        })),
        tcp: tcpRows,
        history,
        declared,
      }),
    );
    toast.success(`${tx("toastExportedJson")}: ${tcpRows.length + declared.length + history.length}`);
  };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navNetwork")}</h1>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-muted sm:text-sm">{tx("netCoverageNote")}</p>
          <p className="mt-1 font-mono text-[11px] text-subtle">{tx("utc8")}</p>
        </div>
        <Button size="sm" variant="outline" onClick={handleExport} className="gap-1.5 text-xs">
          <Download className="size-3.5" />
          <span>{tx("netExport")}</span>
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[12rem] flex-1">
          <Search className="pointer-events-none absolute left-3 top-3 size-4 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={tx("netSearchHint")}
            className="h-10 w-full rounded-lg bg-surface pl-9 pr-8 text-xs text-fg shadow-[var(--shadow-border)] outline-none sm:text-sm"
          />
          {q ? (
            <button type="button" onClick={() => setQ("")} className="absolute right-2.5 top-3 text-muted hover:text-fg">
              <X className="size-4" />
            </button>
          ) : null}
        </div>
        <button
          type="button"
          onClick={() => setOssHigh((v) => !v)}
          className={cn(
            "h-10 shrink-0 rounded-lg px-3 font-mono text-xs shadow-[var(--shadow-border)]",
            ossHigh ? "bg-elevated text-fg font-semibold" : "bg-surface text-muted",
          )}
        >
          {tx("netRiskOssTitle")}
        </button>
      </div>

      <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
        <h2 className="text-sm font-semibold text-fg">{tx("netSampleStatus")}</h2>
        {samples.length === 0 ? (
          <p className="mt-3 text-sm text-muted">{tx("emptyFleet")}</p>
        ) : (
          <ul className="mt-3 grid gap-3 sm:grid-cols-2">
            {samples.map(({ machine, view }) => (
              <li key={machine.id} className="rounded-lg border border-line bg-elevated/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-sm font-semibold text-fg">{machine.hostname}</p>
                  <span className={cn("font-mono text-[11px]", statusClass(view.status))}>{tx(sampleStatusKey(view.status))}</span>
                </div>
                <p className="mt-1 font-mono text-[11px] text-subtle" suppressHydrationWarning>
                  {tx("netAge")}: {view.ageMs === null ? "—" : formatRelative(now - view.ageMs, locale, now)}
                </p>
                <p className="font-mono text-[11px] text-subtle" suppressHydrationWarning>
                  {tx("netLastSeen")}: {view.observedAt ? formatDateTime(view.observedAt, locale) : tx("unknown")}
                </p>
                {networkOwnerMessage(machine.network?.error,locale) && <p className="mt-1 text-[11px] text-warn">{networkOwnerMessage(machine.network?.error,locale)}</p>}
                {view.truncated ? <p className="mt-1 text-[11px] text-warn">{tx("netTruncated")}</p> : null}
                {view.status === "stale" && view.quality === "partial" ? (
                  <p className="mt-1 text-[11px] text-warn">{tx("netPartial")}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line pb-2.5">
          <div>
            <h2 className="text-sm font-semibold text-fg">{tx("netRiskTargets")}</h2>
            <p className="mt-0.5 text-xs text-muted">
              {locale === "zh"
                ? "优先展示命中外连规则、数据外传威胁或按域名识别的对象存储目标。"
                : "Priority list for outbound rules, exfiltration threats, or hostname-matched object-storage targets."}
            </p>
          </div>
          <span className="font-mono text-xs text-muted">
            {riskTargets.length} {tx("events")}
          </span>
        </div>

        {riskTargets.length === 0 ? (
          <p className="mt-4 py-8 text-center text-sm text-muted">{tx("emptyEvents")}</p>
        ) : (
          <ul className="mt-3 flex flex-col gap-3">
            {riskTargets.slice(0, PAGE).map((e) => {
              const dest = visibleDestinations(e);
              const machineObj = fleet.find((m) => m.id === e.machineId);
              const hostLabel = machineObj?.hostname ?? (e.machineId || tx("unknown"));
              const ossHosts = eventOssHosts(e);
              const isOss = ossHosts.length > 0;
              const rawInput = e.redacted || e.input || "";
              const cleanInput = sanitizeDisplayUrl(rawInput);

              return (
                <li key={e.id} className="rounded-lg border border-line bg-elevated/50 p-3 sm:p-4">
                  {/* Direct display: Target host/IP, Port, Agent, Machine, Time, Action, Short Evidence ID */}
                  <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {dest.kind === "missing" ? (
                          <span className="font-mono text-xs text-warn font-medium">{tx("netTargetNotCollected")}</span>
                        ) : dest.kind === "empty" ? (
                          <span className="font-mono text-xs text-muted font-medium">{tx("netTargetNone")}</span>
                        ) : (
                          <span className="break-all font-mono text-sm font-semibold text-fg">
                            {dest.hosts.join(" · ")}
                          </span>
                        )}
                        {isOss ? (
                          <span className="rounded bg-warn/15 px-2 py-0.5 font-mono text-[11px] font-medium text-warn border border-warn/30">
                            {tx("netOssShape")}
                          </span>
                        ) : null}
                      </div>
                      {isOss ? (
                        <p className="mt-1 text-[11px] text-subtle">
                          {tx("netOssNotOwner")}
                        </p>
                      ) : null}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <span className="font-mono text-xs text-subtle">
                        {tx("shortEvidenceId")}: {shortEvidenceId(e.id)}
                      </span>
                      <DecisionBadge decision={e.decision} />
                      <span
                        className={cn(
                          "rounded-full px-2 py-0.5 font-mono text-[11px] font-medium border",
                          e.enforcement === "blocked"
                            ? "bg-danger/10 text-danger border-danger/25"
                            : e.enforcement === "returned_deny"
                              ? "bg-warn/10 text-warn border-warn/25"
                              : "bg-elevated text-muted border-line",
                        )}
                      >
                        {tx(enforcementMsg(e.enforcement))}
                      </span>
                    </div>
                  </div>

                  {/* Meta row: Agent, Machine, Time in UTC+8 */}
                  <div className="mt-2.5 flex flex-wrap items-center gap-2.5 text-xs text-muted border-t border-line/60 pt-2 font-mono">
                    <AgentMark id={e.agent} showName={true} />
                    <span className="text-subtle">·</span>
                    <span>
                      {tx("fleet")}: {hostLabel}
                    </span>
                    <span className="text-subtle">·</span>
                    <span suppressHydrationWarning>
                      {formatDateTime(e.ts, locale)}
                    </span>
                  </div>

                  {cleanInput ? (
                    <p className="mt-2.5 break-all font-mono text-xs text-fg bg-surface/70 rounded p-2.5 border border-line/60">
                      {truncate(cleanInput, 140)}
                    </p>
                  ) : null}

                  {/* Expandable details: Full event ID, process info, policy version, request hash, execution feedback */}
                  <details className="mt-2.5 group">
                    <summary className="cursor-pointer text-xs text-muted hover:text-fg font-medium flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-fg/30 rounded py-1">
                      <span>{tx("evidenceDetail")} ({tx("eventId")} {e.id})</span>
                    </summary>
                    <dl className="mt-2 grid gap-1.5 break-all font-mono text-[11px] text-muted bg-surface/80 rounded-lg p-3 border border-line">
                      <div>
                        <span className="text-subtle">{tx("eventId")}:</span> {e.id}
                      </div>
                      {cleanInput ? (
                        <div>
                          <span className="text-subtle">{tx("commandText")}:</span>{" "}
                          <span className="text-fg">{cleanInput}</span>
                        </div>
                      ) : null}
                      <div suppressHydrationWarning>
                        <span className="text-subtle">{tx("utc8")}:</span> {formatDateTime(e.ts, locale)}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("processLabel")}:</span> {e.proc ?? tx("notCollected")} ·{" "}
                        <span className="text-subtle">{tx("sessionLabel")}:</span> {e.sessionId || tx("notCollected")}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("policyVersion")}:</span>{" "}
                        {typeof e.policyVersion === "number" ? `v${e.policyVersion}` : tx("notCollected")}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("requestHash")}:</span> {e.requestHash ?? tx("notCollected")}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("ruleVerdict")}:</span> {tx(decisionMsg(e.decision))} ·{" "}
                        <span className="text-subtle">{tx("execFeedback")}:</span> {tx(enforcementMsg(e.enforcement))}
                      </div>
                      {e.endpoints && e.endpoints.length > 0 ? (
                        <div>
                          <span className="text-subtle">{tx("netSourceDeclared")}:</span>{" "}
                          {e.endpoints.map((ep) => `${tx(sourceMsg(ep.source))}: ${formatDeclaredHost(ep)}`).join(" · ")}
                        </div>
                      ) : null}
                    </dl>
                  </details>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line pb-2.5">
          <div>
            <h2 className="text-sm font-semibold text-fg">{tx("netDeclared")}</h2>
            <p className="mt-0.5 text-xs text-muted">{tx("netDeclaredDesc")}</p>
          </div>
          <span className="font-mono text-xs text-muted">
            {declared.length} {tx("events")}
          </span>
        </div>

        {declared.length === 0 ? (
          <p className="mt-4 py-8 text-center text-sm text-muted">{tx("emptyEvents")}</p>
        ) : (
          <div className="mt-3 flex flex-col">
            {declared.slice(0, declLimit).map((e) => (
              <EventRow key={e.id} event={e} />
            ))}
          </div>
        )}
        {declared.length > declLimit ? (
          <div className="mt-3 text-center">
            <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setDeclLimit((n) => n + PAGE)}>
              {tx("loadMore")} ({declLimit} / {declared.length})
            </Button>
          </div>
        ) : null}
      </section>

      <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line pb-2.5">
          <div>
            <h2 className="text-sm font-semibold text-fg">{anyLive ? tx("netLatestTcp") : tx("netLastSample")}</h2>
            <p className="mt-0.5 text-xs text-muted">{tx("netObservedDesc")}</p>
          </div>
          <span className="font-mono text-xs text-muted">
            {tcpRows.length} {tx("hops")}
          </span>
        </div>

        {tcpRows.length === 0 ? (
          <p className="mt-4 py-8 text-center text-sm text-muted">
            {emptyTcp === "sampled_zero" ? tx("netSampledZero") : tx("netEmptyTcp")}
          </p>
        ) : (
          <ul className="mt-3 flex flex-col gap-2.5">
            {tcpRows.slice(0, tcpLimit).map((row) => (
              <li
                key={connectionRowKey(row)}
                className="rounded-lg border border-line bg-elevated/50 p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="break-all font-mono text-xs text-fg font-medium">
                    <span className="text-subtle">{tx("netLocal")}</span> {formatSocket(row.localIp, row.localPort)}
                    {isSynSent(row.state) ? " · " : " ↔ "}
                    <span className="text-subtle">{tx("netPeer")}</span> {formatSocket(row.remoteIp, row.remotePort)}
                  </p>
                  <span className="font-mono text-[11px] text-muted">
                    {row.hostname}
                  </span>
                </div>
                <p className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-muted font-mono">
                  {isAgentId(row.agent) ? <AgentMark id={row.agent} showName={false} /> : <span>{row.agent}</span>}
                  <span>{row.bin}</span>
                  <span>
                    {tx("pid")} {row.pid}
                  </span>
                  <span suppressHydrationWarning>
                    {tx("netPidStart")} {formatDateTime(row.processStartedAt, locale)}
                  </span>
                </p>
                <div className="mt-1.5 flex flex-wrap items-center justify-between gap-2 border-t border-line/50 pt-1.5 font-mono text-[11px] text-subtle">
                  <span>
                    {isSynSent(row.state) ? tx("netSynSentAttempt") : tx("netEstablishedPeer")}
                    {row.live ? null : ` · ${tx("netLastSample")}`}
                  </span>
                  <span suppressHydrationWarning>
                    {tx("netLastSeen")}: {formatDateTime(row.observedAt, locale)}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
        {tcpRows.length > tcpLimit ? (
          <div className="mt-3 text-center">
            <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setTcpLimit((n) => n + PAGE)}>
              {tx("loadMore")} ({tcpLimit} / {tcpRows.length})
            </Button>
          </div>
        ) : null}
      </section>

      <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line pb-2.5">
          <div>
            <h2 className="text-sm font-semibold text-fg">{tx("netHistory")}</h2>
            <p className="mt-0.5 text-xs text-muted">{tx("netHistoryDesc")}</p>
          </div>
          <span className="font-mono text-xs text-muted">
            {history.length} {tx("history")}
          </span>
        </div>

        {history.length === 0 ? (
          <p className="mt-4 py-8 text-center text-sm text-muted">{tx("netEmptyHistory")}</p>
        ) : (
          <ul className="mt-3 flex flex-col gap-2.5">
            {history.slice(0, histLimit).map((row) => {
              const hostName = fleet.find((m) => m.id === row.machineId)?.hostname ?? row.machineId;
              return (
                <li key={row.id} className="rounded-lg border border-line bg-elevated/50 p-3">
                  <details className="group">
                    <summary className="cursor-pointer break-all font-mono text-xs text-fg flex flex-wrap items-center justify-between gap-2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-fg/30 rounded py-1">
                      <span className="font-semibold">
                        {tx("netEvidenceId")} {row.id} · {formatSocket(row.remoteIp, row.remotePort)}
                      </span>
                      <span className="font-normal text-muted text-[11px]" suppressHydrationWarning>
                        {formatDateTime(row.lastSeen, locale)}
                      </span>
                    </summary>
                    <dl className="mt-2 grid gap-1.5 break-all font-mono text-[11px] text-muted bg-surface/80 rounded-lg p-3 border border-line">
                      <div>
                        <span className="text-subtle">{tx("fleet")}:</span> {hostName} ({row.machineId})
                      </div>
                      <div>
                        <span className="text-subtle">{tx("pid")}:</span> {row.pid} ·{" "}
                        <span className="text-subtle">{tx("netPidStart")}:</span> {formatDateTime(row.processStartedAt, locale)}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("agent") || "Agent"}:</span> {row.bin} · {row.agent}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("netLocal")}:</span> {formatSocket(row.localIp, row.localPort)}
                        {isSynSent(row.state) ? " · " : " ↔ "}
                        <span className="text-subtle">{tx("netPeer")}:</span> {formatSocket(row.remoteIp, row.remotePort)}
                      </div>
                      <div>
                        <span className="text-subtle">{tx("state") || "状态"}:</span>{" "}
                        {isSynSent(row.state) ? tx("netSynSentAttempt") : tx("netEstablishedPeer")}
                      </div>
                      <div suppressHydrationWarning>
                        <span className="text-subtle">{tx("netFirstSeen")}:</span> {formatDateTime(row.firstSeen, locale)}
                      </div>
                      <div suppressHydrationWarning>
                        <span className="text-subtle">{tx("netLastSeen")}:</span> {formatDateTime(row.lastSeen, locale)}
                      </div>
                    </dl>
                  </details>
                </li>
              );
            })}
          </ul>
        )}
        {history.length > histLimit ? (
          <div className="mt-3 text-center">
            <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setHistLimit((n) => n + PAGE)}>
              {tx("loadMore")} ({histLimit} / {history.length})
            </Button>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function connectionRowKey(row: TcpRow): string {
  return `${row.machineId}:${row.pid}:${row.processStartedAt}:${row.localIp}:${row.localPort}:${row.remoteIp}:${row.remotePort}`;
}
