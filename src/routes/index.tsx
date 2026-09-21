import {GithubUploadSettings} from "@/components/github-upload-settings";
import {ArchiveUploadSettings} from "@/components/archive-upload-settings";
import {AgentDiscoverySection, ObservedAppProcessSection} from "@/components/agent-discovery";
import { legacyAuditIdentityTitle } from "@/lib/monitor/observed-app-summary";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Bot,
  Box,
  ChevronDown,
  FileCode,
  Globe,
  Key,
  Layers,
  Lock,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Workflow,
  X,
} from "lucide-react";
import { AgentMark } from "@/components/agent-mark";
import { RiskBadge } from "@/components/risk-badge";
import { EventRow } from "@/components/event-row";
import { Meter } from "@/components/meter";
import { StatTile } from "@/components/stat-tile";
import { Button } from "@/components/ui/button";
import { AGENTS } from "@/lib/monitor/agents";
import { RULE_BY_ID } from "@/lib/monitor/rules";
import { effectiveMachineFilter, hookCoverage, isPersistedHostFilter, presentModels, statsFrom } from "@/lib/monitor/stats";
import {
  useFilteredEvents,
  useMachineViews,
  useMonitor,
  useOverviewMachines,
  usePresentAgents,
  useScopedCapabilities,
  useT,
} from "@/lib/monitor/store";
import { displayHostUser } from "@/lib/monitor/map-event";
import { homeReadyValue, hookCapMsg, type Msg } from "@/lib/monitor/i18n";
import { formatDateTime, formatRelative } from "@/lib/monitor/format";
import type { AgentId, DeviceCapability } from "@/lib/monitor/types";

/** Only agents with a real PreToolUse adapter. Status comes from probe receipts, never from discovery. */
const HOOK_ADAPTERS: Array<[AgentId, string]> = [
  ["grok", "hook_grok"],
  ["claude", "hook_claude"],
  ["codex", "hook_codex"],
  ["zcode", "hook_zcode"],
  ["antigravity", "hook_antigravity"],
  ["kimi", "hook_kimi"],
  ["trae", "hook_trae"],
  ["qwen", "hook_qwen"],
  ["qoder", "hook_qoder"],
  ["lingma", "hook_lingma"],
  ["codebuddy", "hook_codebuddy"],
  ["gemini", "hook_gemini"],
  ["cursor", "hook_cursor"],
];

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

import { SnapshotGuardSection } from "@/components/snapshot-guard";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({ component: Home });

function HomeMeter({
  dataReady,
  pending,
  label,
  value,
  max,
  tone,
}: {
  dataReady: boolean;
  pending: string;
  label: string;
  value: number;
  max: number;
  tone?: "info" | "ok" | "warn" | "danger";
}) {
  if (!dataReady) {
    return (
      <div className="flex items-center gap-3">
        <span className="w-36 shrink-0 truncate text-xs text-muted">{label}</span>
        <div className="h-1.5 min-w-0 flex-1 rounded-full bg-elevated" />
        <span className="shrink-0 text-right font-mono text-xs tabular-nums text-subtle">{pending}</span>
      </div>
    );
  }
  return <Meter label={label} value={value} max={max} tone={tone} />;
}

function Home() {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const disconnected = useMonitor((s) => s.disconnected);
  const synced = useMonitor((s) => s.synced);
  const dataReady = synced;
  const intervention = useMonitor((s) => s.intervention);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const machineFilter = useMonitor((s) => s.machineFilter);
  const setMachineFilter = useMonitor((s) => s.setMachineFilter);
  const sessions = useMonitor((s) => s.sessions);
  const identities = useMonitor((s) => s.identities);
  const events = useFilteredEvents();
  const fleet = useOverviewMachines();
  const allHosts = useMachineViews();
  const hops = useMonitor((s) => s.hops);
  const present = usePresentAgents();
  const capabilities = useScopedCapabilities();
  const stats = useMemo(() => statsFrom(events), [events]);
  const host = effectiveMachineFilter(machineFilter, allHosts);
  const allowed = new Set(fleet.map((m) => m.id));
  const [selectedHook, setSelectedHook] = useState<AgentId | null>(() => {
    if (typeof window === "undefined") return null;
    return new URLSearchParams(window.location.search).get("hook") as AgentId | null;
  });
  useEffect(() => {
    if (typeof window === "undefined") return;
    const p = new URLSearchParams(window.location.search).get("host");
    if (p && isPersistedHostFilter(p)) {
      setMachineFilter(p);
    }
  }, [setMachineFilter]);
  const coverage = useMemo(
    () => hookCoverage(fleet, host, HOOK_ADAPTERS.map(([a]) => a)),
    [fleet, host],
  );

  type HookGroupItem = {
    agent: AgentId;
    capId: string;
    msg: Msg;
    cap?: DeviceCapability;
  };

  const hookGroups = useMemo(() => {
    const active: HookGroupItem[] = [];
    const noReceipt: HookGroupItem[] = [];
    const actionRequired: HookGroupItem[] = [];
    const notConfigured: HookGroupItem[] = [];
    const notReported: HookGroupItem[] = [];

    for (const [agent, capId] of HOOK_ADAPTERS) {
      const cap = capabilities[capId];
      const msg = hookCapMsg(cap);
      const item: HookGroupItem = { agent, capId, msg, cap };
      if (msg === "hookCapActive") {
        active.push(item);
      } else if (msg === "hookCapNoReceipt") {
        noReceipt.push(item);
      } else if (
        msg === "hookCapUntrusted" ||
        msg === "hookCapModified" ||
        msg === "hookCapDisabled" ||
        msg === "hookCapFeatureOff" ||
        msg === "hookCapError"
      ) {
        actionRequired.push(item);
      } else if (msg === "hookCapNotInstalled") {
        notConfigured.push(item);
      } else {
        notReported.push(item);
      }
    }

    return [
      { key: "receiptConfirmed" as const, titleKey: "hookGroupActive" as const, items: active },
      { key: "noReceipt" as const, titleKey: "hookGroupNoReceipt" as const, items: noReceipt },
      { key: "actionRequired" as const, titleKey: "hookGroupActionRequired" as const, items: actionRequired },
      { key: "notConfigured" as const, titleKey: "hookGroupNotConfigured" as const, items: notConfigured },
      { key: "notReported" as const, titleKey: "hookGroupNotReported" as const, items: notReported },
    ];
  }, [capabilities]);
  const ident = identities.filter(
    (i) =>
      allowed.has(i.machineId) &&
      (host === "all" || i.machineId === host) &&
      (agentFilter === "all" || i.agent === agentFilter),
  );
  const collected = ident.filter((i) => typeof i.pid === "number" && i.pid > 0);
  const mismatch = collected.some((i) => i.matchesUiUser === false);
  const models = presentModels(
    sessions.filter((s) => allowed.has(s.machineId)),
    agentFilter === "all" || present.includes(agentFilter) ? agentFilter : "all",
    host,
  );
  const destinations = new Set(
    hops
      .filter(
        (h) =>
          allowed.has(h.machineId) &&
          (host === "all" || h.machineId === host) &&
          (agentFilter === "all" || h.agent === agentFilter),
      )
      .map((h) => h.hostname),
  );
  const hopsCollected = hops.length > 0;
  const archived = allHosts.filter((m) => m.status === "archived");
  const [open, setOpen] = useState<"sessions" | "blocked" | null>(null);
  const [drillQuery, setDrillQuery] = useState("");
  const blocked = events.filter((e) => e.enforcement === "blocked");
  const returnedDeny = events.filter((e) => e.enforcement === "returned_deny");
  const feed = [...events].reverse().slice(0, 8);
  const unknown = tx("unknown");
  const notCollected = tx("notCollected");
  const pendingLabel = tx("loading");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(null);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const hint =
    intervention === "enforcing"
      ? (locale === "zh" ? "按规则表执行（含你的覆盖）" : "Enforcing rules with your overrides")
      : intervention === "permissive"
        ? (locale === "zh" ? "全部只记，覆盖与豁免均不生效" : "Log all, overrides and exemptions disabled")
        : (locale === "zh" ? "未启用拦截" : "Intervention off");

  const linkStatus = disconnected ? tx("disconnected") : synced ? tx("lanCtActive") : tx("loading");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2 rounded-2xl bg-surface border border-line p-5 shadow-[var(--shadow-border)] sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 font-mono text-xs font-semibold uppercase tracking-wider text-ok">
            <span className="size-2 rounded-full bg-ok animate-pulse" />
            {tx("liveMode")}
          </span>
          <span className="rounded-full bg-elevated px-2.5 py-0.5 font-mono text-[11px] text-muted border border-line">
            {linkStatus}
            {disconnected && synced ? ` · ${tx("staleData")}` : ""}
          </span>
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-fg sm:text-3xl">{tx("tagline")}</h1>
        <p className="max-w-3xl text-sm leading-relaxed text-muted">{tx("whyQuiet")}</p>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-md bg-elevated px-2 py-1 font-mono text-fg border border-line">
            {hint}
          </span>
          <span className="text-subtle">{tx("fleetHint")}</span>
        </div>
      </div>

      {fleet.some((m) => m.status === "dark") ? (
        <Link
          to="/threats"
          className="group flex flex-col gap-1 rounded-xl border border-danger/30 bg-danger/10 p-4 transition-all hover:bg-danger/15"
        >
          <div className="flex items-center gap-2">
            <AlertOctagon className="size-4 text-danger animate-pulse" />
            <span className="font-semibold text-danger">{tx("machineDark")}</span>
          </div>
          <span className="font-mono text-xs text-danger/90">
            {fleet
              .filter((m) => m.status === "dark")
              .map((m) => `${m.hostname} (${m.ip})`)
              .join(" · ")}
          </span>
          <span className="text-xs text-muted group-hover:text-fg transition-colors">
            {tx("isolateBanner")} →
          </span>
        </Link>
      ) : null}

      <div>
        <div className="mb-2.5 flex items-center justify-between">
          <h2 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
            <Server className="size-3.5" />
            <span>{tx("monitoredFleet")} ({fleet.length})</span>
          </h2>
          {host !== "all" ? (
            <button
              type="button"
              onClick={() => setMachineFilter("all")}
              className="text-xs text-muted hover:text-fg underline-offset-2 hover:underline"
            >
              {tx("showAllMachines")}
            </button>
          ) : null}
        </div>
        {fleet.length === 0 ? <p className="text-sm text-muted">{dataReady ? tx("emptyFleet") : pendingLabel}</p> : null}
        <section className="grid gap-3 sm:grid-cols-3">
          {fleet.map((m) => {
            const active = host === m.id;
            const user = displayHostUser(m.user);
            const netCount = (m as unknown as { networkOwnerCount?: number }).networkOwnerCount ?? 0;
            return (
              <div
                key={m.id}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") setMachineFilter(active ? "all" : m.id);
                }}
                onClick={() => setMachineFilter(active ? "all" : m.id)}
                className={cn(
                  "group relative rounded-xl bg-surface p-4 text-left shadow-[var(--shadow-border)] transition-all duration-200 hover:-translate-y-0.5 cursor-pointer",
                  active
                    ? "border-fg/40 shadow-[var(--shadow-border-hover)] ring-1 ring-fg/30"
                    : "hover:border-line-strong",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Server className={cn("size-4", m.status === "dark" ? "text-danger" : "text-muted")} />
                    <p className="font-mono text-sm font-semibold text-fg">{m.hostname}</p>
                  </div>
                  <span
                    className={cn(
                      "flex items-center gap-1 font-mono text-[11px] font-medium rounded-full px-2 py-0.5 border",
                      m.status === "dark"
                        ? "bg-danger/15 text-danger border-danger/30 animate-pulse"
                        : "bg-ok/10 text-ok border-ok/20",
                    )}
                  >
                    <span className={cn("size-1.5 rounded-full", m.status === "dark" ? "bg-danger" : "bg-ok")} />
                    {m.status === "dark" ? tx("machineDark") : tx("machineOnline")}
                  </span>
                </div>
                <p className="mt-2.5 font-mono text-xs text-subtle">
                  {m.ip} · {user === "unknown" ? unknown : user}@{m.os}
                </p>
                <div className="mt-3 flex items-center gap-2 border-t border-line/60 pt-2 font-mono text-xs">
                  <span className={m.high > 0 ? "text-danger font-medium" : "text-muted"}>
                    {tx("machineHigh")}: {m.high}
                  </span>
                  {m.isolate > 0 ? <span className="text-danger font-medium">· {tx("isolate")}: {m.isolate}</span> : null}
                  {m.poison > 0 ? <span className="text-warn font-medium">· {tx("poison")}: {m.poison}</span> : null}
                </div>

                {/* 本机控制项（只读）折叠区 */}
                <details
                  className="mt-2.5 rounded border border-line bg-elevated/40 p-2 text-xs group"
                  onClick={(e) => e.stopPropagation()}
                >
                  <summary className="cursor-pointer font-medium text-subtle hover:text-fg select-none text-[11px]">
                    {tx("localControls")}
                  </summary>
                  <dl className="mt-2 flex flex-col gap-1.5 text-[11px] text-muted border-t border-line/60 pt-1.5">
                    <div>
                      <span className="font-medium text-fg">{tx("localSnapshotGuard")}: </span>
                      <span>
                        {m.snapshotGuard?.status === "ok" ? tx("localStatusNormal") : tx("localStatusNotConfigured")} · {tx("localNeedsRunOnHost")} nmzp snapshot-guard apply
                      </span>
                    </div>
                    <div>
                      <span className="font-medium text-fg">{tx("localDiscoveryPaths")}: </span>
                      <span>
                        {m.discovery ? tx("localStatusReported") : tx("localStatusNotCollected")} · {tx("localNeedsRunOnHost")} nmzp discover paths
                      </span>
                    </div>
                    <div>
                      <span className="font-medium text-fg">{tx("localProbeBinding")}: </span>
                      <span>
                        {m.probeProtection ? tx("localStatusBound") : tx("localStatusUnbound")} · {tx("localNeedsRunOnHost")} nmzp join
                      </span>
                    </div>
                    <div>
                      <span className="font-medium text-fg">{tx("networkOwnerCount")}: </span>
                      <span>
                        {tx("localGrantItems").replace("{n}", String(netCount))} · {tx("localNeedsRunOnHost")} nmzp network-owner approve
                      </span>
                    </div>
                  </dl>
                </details>
              </div>
            );
          })}
        </section>
      </div>

      {archived.length > 0 ? (
        <p className="text-xs text-subtle">
          {tx("archivedLabel")}: {archived.map((m) => m.hostname).join(" · ")} · {tx("archiveHint")}
        </p>
      ) : null}

      <SnapshotGuardSection machines={fleet} host={host} now={Date.now()} />

      {(stats.exfil > 0 || stats.secrets > 0) && (
        <Link
          to="/threats"
          className="flex items-center justify-between rounded-xl border border-danger/25 bg-danger/5 p-4 text-sm shadow-[var(--shadow-border)] transition-colors hover:bg-danger/10"
        >
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="size-5 text-danger shrink-0" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-danger">{tx("exfil")}</span>
                <span className="font-mono font-bold text-danger tabular-nums">{stats.exfil}</span>
                <span className="text-subtle">|</span>
                <span className="font-semibold text-warn">{tx("secrets")}</span>
                <span className="font-mono font-bold text-warn tabular-nums">{stats.secrets}</span>
              </div>
              <span className="text-xs text-muted block mt-0.5">{tx("threatBanner")}</span>
            </div>
          </div>
          <ArrowRight className="size-4 text-muted group-hover:text-fg" />
        </Link>
      )}

      <ObservedAppProcessSection
        machines={fleet}
        host={host}
        now={Date.now()}
        disconnected={disconnected}
      />

      <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]">
        <details className="group">
          <summary className="flex cursor-pointer list-none flex-wrap items-start justify-between gap-3 border-b border-line pb-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-fg/30 rounded-lg p-1 [&::-webkit-details-marker]:hidden">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <ShieldCheck className={cn("size-4", mismatch ? "text-warn" : "text-ok")} />
                <h2 className="text-sm font-semibold text-fg">
                  {legacyAuditIdentityTitle({
                    collectedCount: collected.length,
                    identityLabel: `${tx("identity")}`,
                  })}
                </h2>
                {mismatch ? (
                  <span className="rounded-full bg-warn/15 px-2 py-0.5 font-mono text-[11px] font-medium text-warn border border-warn/30">
                    {tx("identityWarn")}
                  </span>
                ) : null}
                {collected.some((i) => i.matchesUiUser === undefined || displayHostUser(i.user) === "unknown") && !mismatch ? (
                  <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
                    {tx("identityUnknownUser")}
                  </span>
                ) : null}
              </div>
              <p className="mt-1 text-xs text-muted">
                {collected.length === 0
                  ? tx("auditIdentityEmptySubtitle")
                  : mismatch
                    ? tx("identityWarn")
                    : collected.some((i) => i.matchesUiUser === true)
                      ? (collected.some((i) => i.matchesUiUser === undefined)
                          ? `${tx("identityOk")} · ${tx("identityUnknownUser")}`
                          : tx("identityOk"))
                      : tx("identityUnknownUser")}
              </p>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted">
              <span className="font-mono text-[11px]">{tx("expandDetails")}</span>
              <ChevronDown className="mt-0.5 size-4 shrink-0 text-muted transition-transform group-open:rotate-180" />
            </div>
          </summary>
          <ul className="mt-4 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-5">
            {collected.length === 0 ? (
              <li className="rounded-lg bg-elevated/70 p-3 border border-line/60 text-xs text-muted">{notCollected}</li>
            ) : (
              collected.map((row) => (
                <li key={`${row.machineId}:${row.agent}:${row.pid}`} className="rounded-lg bg-elevated/70 p-3 border border-line/60">
                  <AgentMark id={row.agent} />
                  <p className="mt-2 font-mono text-xs text-subtle">
                    PID {row.pid} · {row.proc}
                  </p>
                  <p className="font-mono text-[11px] text-muted">
                    {displayHostUser(row.user) === "unknown" ? unknown : row.user}
                  </p>
                  <p className="mt-1 truncate font-mono text-[11px] text-subtle" title={row.cwd}>
                    {row.cwd ? row.cwd : notCollected}
                  </p>
                </li>
              ))
            )}
          </ul>
        </details>
      </section>

      <section className="grid gap-3 md:grid-cols-3">
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)] flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-ok">
              <Terminal className="size-4" />
              <h2 className="text-sm font-semibold">{tx("hookLayer")}</h2>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-muted">{tx("hookLayerBody")}</p>
            {!dataReady || Object.keys(capabilities).length === 0 ? (
              <div className="mt-3 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs text-muted">
                  <span className="size-2 rounded-full bg-info/70 animate-pulse" />
                  <span>{tx("capabilitiesLoading")}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {[1, 2, 3, 4, 5, 6].map((n) => (
                    <div key={n} className="h-7 rounded-md bg-elevated/70 animate-pulse border border-line/40" />
                  ))}
                </div>
              </div>
            ) : (
              <div className="mt-3 flex flex-col gap-3">
                {hookGroups
                  .filter((g) => g.items.length > 0)
                  .map((g) => (
                    <div key={g.key} className="flex flex-col gap-1.5 border-t border-line/40 pt-2 first:border-0 first:pt-0">
                      <div className="flex items-center justify-between text-xs text-muted">
                        <span className="flex items-center gap-1.5 font-medium">
                          {g.key === "receiptConfirmed" ? (
                            <span className="size-1.5 rounded-full bg-ok" />
                          ) : g.key === "actionRequired" ? (
                            <span className="size-1.5 rounded-full bg-warn" />
                          ) : (
                            <span className="size-1.5 rounded-full bg-muted/60" />
                          )}
                          {tx(g.titleKey)}
                        </span>
                        <span className="font-mono text-[11px] text-subtle">{g.items.length}</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {g.items.map(({ agent, msg, cap }) => {
                          const isSelected = selectedHook === agent;
                          const hasSuccess = cap?.lastSuccess != null;
                          return (
                            <button
                              key={agent}
                              type="button"
                              onClick={() => setSelectedHook(isSelected ? null : agent)}
                              className={cn(
                                "group inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs transition-all border cursor-pointer",
                                msg === "hookCapActive"
                                  ? "bg-ok/10 text-ok border-ok/20 hover:border-ok/40"
                                  : g.key === "actionRequired"
                                    ? "bg-warn/10 text-warn border-warn/25 hover:border-warn/40"
                                    : "bg-elevated text-muted border-line hover:border-line-strong hover:text-fg",
                                isSelected ? "ring-1 ring-fg/40 border-fg/30" : "",
                              )}
                              title={`${AGENTS[agent]?.name ?? agent}: ${tx(msg)}${hasSuccess ? ` · ${formatRelative(cap.lastSuccess!, locale)}` : ""}`}
                            >
                              <AgentMark id={agent} showName={false} />
                              <span className="font-medium text-fg">
                                {AGENTS[agent]?.name ?? agent}
                                {host === "all" && coverage[agent]?.reporting > 1 ? (
                                  <span className="ml-1 font-mono text-[10px] font-normal text-subtle">
                                    {coverage[agent].active}/{coverage[agent].reporting}
                                  </span>
                                ) : null}
                              </span>
                              {msg === "hookCapActive" && hasSuccess ? (
                                <span className="font-mono text-[10px] text-ok/80 tabular-nums">
                                  {formatRelative(cap.lastSuccess!, locale)}
                                </span>
                              ) : null}
                              {g.key === "actionRequired" ? (
                                <span className="font-mono text-[10px] text-warn">
                                  {msg === "hookCapUntrusted"
                                    ? locale === "zh"
                                      ? "未信任"
                                      : "Untrusted"
                                    : locale === "zh"
                                      ? "需动作"
                                      : "Action"}
                                </span>
                              ) : null}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ))}

                {selectedHook ? (
                  <div className="rounded-lg border border-line bg-elevated/80 p-3 text-xs space-y-2 animate-in fade-in-50">
                    <div className="flex items-center justify-between gap-2 border-b border-line/60 pb-1.5">
                      <div className="flex items-center gap-2">
                        <AgentMark id={selectedHook} />
                        <span className="font-mono text-[11px] text-subtle">
                          {AGENTS[selectedHook]?.vendor} · {AGENTS[selectedHook]?.process}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedHook(null)}
                        className="text-muted hover:text-fg p-0.5"
                        aria-label={tx("close")}
                      >
                        <X className="size-3.5" />
                      </button>
                    </div>
                    <div>
                      <div className="text-[11px] text-muted font-medium">{tx("statusExplanation")}:</div>
                      <p
                        className={cn(
                          "mt-0.5 font-mono text-[11px]",
                          hookCapMsg(capabilities[`hook_${selectedHook}`]) === "hookCapActive"
                            ? "text-ok"
                            : "text-fg",
                        )}
                      >
                        {tx(hookCapMsg(capabilities[`hook_${selectedHook}`]))}
                      </p>
                    </div>
                    {capabilities[`hook_${selectedHook}`]?.lastSuccess ? (
                      <div>
                        <span className="text-[11px] text-muted">{tx("lastReceipt")}: </span>
                        <span className="font-mono text-[11px] text-fg tabular-nums">
                          {formatDateTime(capabilities[`hook_${selectedHook}`]!.lastSuccess!, locale)} (
                          {formatRelative(capabilities[`hook_${selectedHook}`]!.lastSuccess!, locale)})
                        </span>
                      </div>
                    ) : null}
                    {coverage[selectedHook]?.perMachine.length ? (
                      <div className="border-t border-line/60 pt-2 space-y-1.5">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted font-medium">{tx("hookCoverageTitle")}:</span>
                          {host === "all" && coverage[selectedHook] ? (
                            <span className="font-mono text-[10px] text-subtle">
                              {tx("hookCoverageCount")
                                .replace("{active}", String(coverage[selectedHook].active))
                                .replace("{reporting}", String(coverage[selectedHook].reporting))}
                            </span>
                          ) : null}
                        </div>
                        <div className="space-y-1">
                          {coverage[selectedHook].perMachine.map((m) => {
                            const mMsg = hookCapMsg(m.cap);
                            return (
                              <div
                                key={m.machineId}
                                className="flex flex-wrap items-center justify-between gap-1.5 rounded bg-surface/70 px-2 py-1 border border-line/40 text-[11px]"
                              >
                                <span className="font-mono text-fg font-medium">{m.hostname || m.machineId}</span>
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span
                                    className={cn(
                                      "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono border",
                                      mMsg === "hookCapActive"
                                        ? "bg-ok/10 text-ok border-ok/20"
                                        : mMsg === "hookCapUntrusted" ||
                                            mMsg === "hookCapModified" ||
                                            mMsg === "hookCapDisabled" ||
                                            mMsg === "hookCapFeatureOff" ||
                                            mMsg === "hookCapError"
                                          ? "bg-warn/10 text-warn border-warn/25"
                                          : "bg-surface text-muted border-line",
                                    )}
                                  >
                                    {tx(mMsg)}
                                  </span>
                                  {m.cap?.lastSuccess ? (
                                    <span className="font-mono text-[10px] text-subtle tabular-nums">
                                      {formatDateTime(m.cap.lastSuccess, locale)} ({formatRelative(m.cap.lastSuccess, locale)})
                                    </span>
                                  ) : null}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : null}
                    {MUST_ENABLE[selectedHook] || selectedHook === "grok" ? (
                      <div>
                        <div className="text-[11px] text-muted font-medium">{tx("nextAction")}:</div>
                        <p className="mt-0.5 text-xs text-muted leading-relaxed">
                          {selectedHook === "grok" ? tx("grokHttp") : tx(MUST_ENABLE[selectedHook]!)}
                        </p>
                      </div>
                    ) : null}
                    <div className="pt-1 flex justify-end">
                      <Link
                        to="/install"
                        className="inline-flex items-center gap-1 text-[11px] text-ok hover:underline"
                      >
                        <span>{tx("viewInstallGuide")}</span>
                        <ArrowRight className="size-3" />
                      </Link>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <div className="flex items-center gap-2 text-info">
            <Activity className="size-4" />
            <h2 className="text-sm font-semibold">{tx("probeLayer")}</h2>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("probeLayerBody")}</p>
        </article>
        <article className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <div className="flex items-center gap-2 text-fg">
            <Shield className="size-4" />
            <h2 className="text-sm font-semibold">{tx("coreLayer")}</h2>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-muted">{tx("coreLayerBody")}</p>
        </article>
      </section>

      <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]">
        <details className="group">
          <summary className="flex cursor-pointer list-none flex-wrap items-start justify-between gap-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-fg/30 rounded-lg p-1 [&::-webkit-details-marker]:hidden">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Workflow className="size-4 text-info" />
                <h2 className="text-sm font-semibold text-fg">{tx("uploadPolicySectionTitle")}</h2>
                <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
                  {tx("uploadPolicySectionBadge")}
                </span>
              </div>
              <p className="mt-1 text-xs text-muted">
                {tx("uploadPolicySectionSummary")}
              </p>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted">
              <span className="font-mono text-[11px]">{tx("expandSettings")}</span>
              <ChevronDown className="mt-0.5 size-4 shrink-0 text-muted transition-transform group-open:rotate-180" />
            </div>
          </summary>
          <div className="mt-4 grid gap-4 border-t border-line pt-4 lg:grid-cols-2">
            <ArchiveUploadSettings />
            <GithubUploadSettings />
          </div>
        </details>
      </section>

      <AgentDiscoverySection machines={fleet} host={host} />

      {models.length > 0 ? (
        <p className="font-mono text-xs text-muted">
          {tx("activeModels")}: {models.join(" · ")}
        </p>
      ) : (
        <p className="font-mono text-xs text-muted">
          {tx("activeModels")}: {notCollected}
        </p>
      )}

      <div>
        <h2 className="mb-2.5 text-xs font-semibold uppercase tracking-wider text-muted">
          {tx("metricsOverview")}
        </h2>
        <section className="grid grid-cols-2 gap-2.5 md:grid-cols-4 xl:grid-cols-8">
          <StatTile icon={Layers} label={tx("sessions")} value={notCollected} />
          <StatTile icon={Activity} label={tx("events")} value={homeReadyValue(dataReady, stats.total, pendingLabel)} />
          <StatTile
            icon={ShieldAlert}
            label={tx("blocked")}
            value={homeReadyValue(dataReady, blocked.length, pendingLabel)}
            tone="danger"
            onClick={dataReady && blocked.length ? () => setOpen("blocked") : undefined}
          />
          <StatTile
            icon={Shield}
            label={tx("returnedDeny")}
            value={homeReadyValue(dataReady, returnedDeny.length, pendingLabel)}
            tone="warn"
          />
          <StatTile icon={AlertTriangle} label={tx("bypass")} value={homeReadyValue(dataReady, stats.bypass, pendingLabel)} tone={stats.bypass ? "warn" : "default"} />
          <StatTile icon={Lock} label={tx("exfil")} value={homeReadyValue(dataReady, stats.exfil, pendingLabel)} tone="danger" />
          <StatTile icon={Key} label={tx("secrets")} value={homeReadyValue(dataReady, stats.secrets, pendingLabel)} tone="warn" />
          <StatTile icon={AlertOctagon} label={tx("isolate")} value={homeReadyValue(dataReady, stats.isolate, pendingLabel)} tone={stats.isolate ? "danger" : "default"} />
          <StatTile icon={Workflow} label={tx("rewrite")} value={homeReadyValue(dataReady, stats.rewrite, pendingLabel)} tone={stats.rewrite ? "warn" : "default"} />
          <StatTile icon={Terminal} label={tx("toolCalls")} value={homeReadyValue(dataReady, stats.toolCalls, pendingLabel)} />
          <StatTile icon={Box} label={tx("mcpCalls")} value={homeReadyValue(dataReady, stats.mcp, pendingLabel)} />
          <StatTile icon={Bot} label={tx("subagents")} value={homeReadyValue(dataReady, stats.subagent, pendingLabel)} />
          <StatTile icon={Globe} label={tx("trajectory")} value={hopsCollected ? destinations.size : notCollected} />
        </section>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
            <FileCode className="size-3.5" />
            {tx("fileOps")}
          </h2>
          <div className="grid grid-cols-2 gap-2">
            <StatTile label={tx("reads")} value={homeReadyValue(dataReady, stats.reads, pendingLabel)} />
            <StatTile label={tx("writes")} value={homeReadyValue(dataReady, stats.writes, pendingLabel)} />
            <StatTile label={tx("edits")} value={homeReadyValue(dataReady, stats.edits, pendingLabel)} />
            <StatTile label={tx("deletes")} value={homeReadyValue(dataReady, stats.deletes, pendingLabel)} />
          </div>
        </section>

        <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
            <Box className="size-3.5" />
            {tx("installs")}
          </h2>
          <div className="grid grid-cols-2 gap-2">
            <StatTile label={tx("pip")} value={homeReadyValue(dataReady, stats.pip, pendingLabel)} />
            <StatTile label={tx("sysPkg")} value={homeReadyValue(dataReady, stats.sys, pendingLabel)} />
            <StatTile label={tx("npm")} value={homeReadyValue(dataReady, stats.npm, pendingLabel)} />
            <StatTile label={tx("otherInstall")} value={homeReadyValue(dataReady, stats.otherInstall, pendingLabel)} />
          </div>
        </section>

        <section className="rounded-xl bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
            <Terminal className="size-3.5" />
            {tx("commandStats")}
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <StatTile label={tx("git")} value={homeReadyValue(dataReady, stats.git, pendingLabel)} />
            <StatTile label={tx("ssh")} value={homeReadyValue(dataReady, stats.ssh, pendingLabel)} />
            <StatTile label={tx("downloads")} value={homeReadyValue(dataReady, stats.download, pendingLabel)} />
            <StatTile label={tx("docker")} value={homeReadyValue(dataReady, stats.docker, pendingLabel)} />
            <StatTile label={tx("archive")} value={homeReadyValue(dataReady, stats.archive, pendingLabel)} />
            <StatTile label={tx("process")} value={homeReadyValue(dataReady, stats.process, pendingLabel)} />
          </div>
        </section>
      </div>

      <section className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]">
          <h2 className="mb-4 text-sm font-semibold flex items-center gap-2">
            <Layers className="size-4 text-info" />
            {tx("eventBreakdown")}
          </h2>
          <div className="flex flex-col gap-3.5">
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("appPre")} value={stats.layers.app_pre} max={stats.total} />
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("appPost")} value={stats.layers.app_post} max={stats.total} />
            <p className="text-xs text-muted">{tx("kernelExec")}: {notCollected}</p>
            <p className="text-xs text-muted">{tx("kernelNet")}: {notCollected}</p>
          </div>
        </div>
        <div className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]">
          <h2 className="mb-4 text-sm font-semibold flex items-center gap-2">
            <ShieldAlert className="size-4 text-danger" />
            {tx("riskBreakdown")}
          </h2>
          <div className="flex flex-col gap-3.5">
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("high")} value={stats.risks.high} max={stats.total} tone="danger" />
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("medium")} value={stats.risks.medium} max={stats.total} tone="warn" />
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("low")} value={stats.risks.low} max={stats.total} tone="ok" />
            <HomeMeter dataReady={dataReady} pending={pendingLabel} label={tx("info")} value={stats.risks.info} max={stats.total} />
          </div>
        </div>
      </section>

      <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)] flex flex-col">
        <div className="mb-3 flex items-center justify-between border-b border-line pb-2.5">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <Activity className="size-4 text-ok animate-pulse" />
            {tx("liveFeed")}
          </h2>
          <Link to="/audit" className="flex items-center gap-1 text-xs text-muted hover:text-fg font-medium">
            <span>{tx("navAudit")}</span>
            <ArrowRight className="size-3" />
          </Link>
        </div>
        <div className="flex-1 overflow-y-auto">
          {feed.length === 0 ? (
            <p className="py-12 text-center text-xs text-muted">{dataReady ? tx("emptyEvents") : pendingLabel}</p>
          ) : (
            feed.map((e) => <EventRow key={e.id} event={e} dense />)
          )}
        </div>
      </section>

      {open ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-bg/80 p-4 backdrop-blur-sm"
          onClick={() => setOpen(null)}
          role="presentation"
        >
          <div
            className="max-h-[85dvh] w-full max-w-2xl overflow-hidden rounded-2xl bg-surface shadow-2xl border border-line flex flex-col"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            <div className="flex items-center justify-between border-b border-line p-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="size-4 text-danger" />
                <h2 className="text-base font-semibold">
                  {open === "sessions" ? tx("drillSessions") : tx("drillBlocked")}
                </h2>
              </div>
              <Button size="icon-sm" variant="ghost" onClick={() => setOpen(null)}>
                <X className="size-4" />
              </Button>
            </div>

            <div className="border-b border-line p-3">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 size-3.5 text-muted" />
                <input
                  value={drillQuery}
                  onChange={(e) => setDrillQuery(e.target.value)}
                  placeholder={tx("filterDrilldown")}
                  className="h-8 w-full rounded-lg bg-elevated pl-8 pr-3 font-mono text-xs text-fg outline-none focus:ring-1 focus:ring-fg/30"
                />
              </div>
            </div>

            <div className="overflow-y-auto p-4 flex-1">
              {open === "sessions" ? (
                <p className="py-8 text-center text-xs text-muted">{notCollected}</p>
              ) : blocked.length === 0 ? (
                <p className="py-8 text-center text-xs text-muted">{tx("emptyEvents")}</p>
              ) : (
                blocked
                  .filter((e) =>
                    drillQuery
                      ? `${e.input} ${e.tool} ${e.ruleId}`.toLowerCase().includes(drillQuery.toLowerCase())
                      : true,
                  )
                  .slice()
                  .reverse()
                  .slice(0, 30)
                  .map((e) => (
                    <div key={e.id} className="border-b border-line py-2.5 last:border-0">
                      <div className="flex items-center justify-between gap-2">
                        <AgentMark id={e.agent} showName={false} />
                        <RiskBadge risk={e.risk} />
                      </div>
                      <p className="mt-1 font-mono text-xs text-fg break-all">{e.input}</p>
                      <p className="mt-1 text-[11px] text-muted">
                        {e.ruleId && RULE_BY_ID[e.ruleId]
                          ? locale === "zh"
                            ? RULE_BY_ID[e.ruleId]!.title
                            : RULE_BY_ID[e.ruleId]!.titleEn
                          : e.tool === "unknown"
                            ? unknown
                            : e.tool}
                      </p>
                    </div>
                  ))
              )}
            </div>

            <div className="border-t border-line p-3 flex justify-end">
              <Button size="sm" variant="outline" onClick={() => setOpen(null)}>
                {tx("close")}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
