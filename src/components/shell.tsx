import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Bot,
  Database,
  FileSearch,
  Globe,
  LayoutDashboard,
  Menu,
  Moon,
  Scale,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Terminal,
  Unplug,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { AGENTS } from "@/lib/monitor/agents";
import { t } from "@/lib/monitor/i18n";
import { useAppChrome } from "@/lib/monitor/simulator";
import { useCanMutate, useMonitor, useOverviewMachines, usePresentAgents, useT } from "@/lib/monitor/store";
import { login } from "@/lib/monitor/api";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", key: "navHome" as const, icon: LayoutDashboard },
  { to: "/threats", key: "navThreats" as const, icon: Shield },
  { to: "/audit", key: "navAudit" as const, icon: FileSearch },
  { to: "/history", key: "navHistory" as const, icon: Database },
  { to: "/tap", key: "navTap" as const, icon: Terminal },
  { to: "/network", key: "navNetwork" as const, icon: Globe },
  { to: "/rules", key: "navRules" as const, icon: Activity },
  { to: "/rights", key: "navRights" as const, icon: Scale },
  { to: "/install", key: "navInstall" as const, icon: Unplug },
];

function LoginBar() {
  const tx = useT();
  const syncFromServer = useMonitor((s) => s.syncFromServer);
  const [token, setToken] = useState("");
  return (
    <form
      className="flex flex-wrap items-center justify-center gap-2 border-b border-line bg-surface px-3 py-2"
      onSubmit={(e) => {
        e.preventDefault();
        void login(token.trim()).then((ok) => {
          if (ok) {
            setToken("");
            void syncFromServer();
          }
        });
      }}
    >
      <span className="text-xs text-muted">{tx("loginNeeded")}</span>
      <input
        type="password"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        autoComplete="off"
        aria-label={tx("loginTitle")}
        className="h-8 rounded-md bg-elevated px-2 font-mono text-xs shadow-[var(--shadow-border)]"
      />
      <label className="cursor-pointer text-xs text-muted underline">
        {tx("loginFromFile")}
        <input
          type="file"
          accept=".token,.txt,text/plain"
          className="sr-only"
          onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (!f) return;
            void f.text().then((text) => {
              const value = text.trim();
              if (!value) return;
              return login(value).then((ok) => {
                if (ok) {
                  setToken("");
                  void syncFromServer();
                }
              });
            });
          }}
        />
      </label>
      <Button type="submit" size="sm">
        {tx("loginGo")}
      </Button>
    </form>
  );
}

function isActive(pathname: string, to: string) {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}

export function Shell({ children }: { children: React.ReactNode }) {
  useAppChrome();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const theme = useMonitor((s) => s.theme);
  const paused = useMonitor((s) => s.paused);
  const interventionRaw = useMonitor((s) => s.intervention);
  const intervention =
    interventionRaw === "permissive" || interventionRaw === "off" || interventionRaw === "enforcing"
      ? interventionRaw
      : "enforcing";
  const disconnected = useMonitor((s) => s.disconnected);
  const loginNeeded = useMonitor((s) => s.loginNeeded);
  const synced = useMonitor((s) => s.synced);
  const access = useMonitor((s) => s.access);
  const agentFilter = useMonitor((s) => s.agentFilter);
  const setLocale = useMonitor((s) => s.setLocale);
  const setTheme = useMonitor((s) => s.setTheme);
  const setIntervention = useMonitor((s) => s.setIntervention);
  const setAgentFilter = useMonitor((s) => s.setAgentFilter);
  const setMachineFilter = useMonitor((s) => s.setMachineFilter);
  const machineFilter = useMonitor((s) => s.machineFilter);
  const present = usePresentAgents();
  const fleet = useOverviewMachines();
  const canMutate = useCanMutate();
  const host = machineFilter === "all" || !fleet.some((m) => m.id === machineFilter) ? "all" : machineFilter;
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  const cycleMode = () => {
    if (!canMutate) return;
    const next = intervention === "enforcing" ? "off" : "enforcing";
    void setIntervention(next).then((ok) => {
      if (!ok) {
        toast.error(tx("mutationFailed"));
        return;
      }
      toast(next === "enforcing" ? tx("enforcing") : tx("off"), {
        description: next === "enforcing" ? tx("enforcingHint") : tx("offHint"),
        icon: next === "enforcing" ? <ShieldCheck className="size-4 text-ok" /> : <ShieldAlert className="size-4 text-warn" />,
      });
    });
  };

  const isGuardActive = synced && !disconnected && intervention !== "off" && !paused;
  const showLogin = loginNeeded && !(synced && access === "viewer");

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-fg"
      >
        {tx("skipToContent")}
      </a>
      {disconnected ? (
        <div className="border-b border-warn/40 bg-warn/10 px-3 py-2 text-center text-xs text-warn">
          {tx("disconnected")} · {synced ? tx("staleData") : tx("disconnectedHint")}
        </div>
      ) : null}
      {!synced && !disconnected ? (
        <div className="border-b border-line bg-elevated px-3 py-2 text-center text-xs text-muted">{tx("loading")}</div>
      ) : null}
      {access === "viewer" && synced ? (
        <div className="border-b border-line bg-elevated px-3 py-2 text-center text-xs text-muted">{tx("lanViewer")}</div>
      ) : null}
      {showLogin ? <LoginBar /> : null}
      <header className="sticky top-0 z-40 border-b border-line bg-bg/90 backdrop-blur-md transition-colors">
        <div className="mx-auto flex max-w-7xl items-center gap-2 px-3 py-2.5 sm:px-4 lg:px-6">
          <Link to="/" className="group flex shrink-0 items-center gap-2.5">
            <span className="relative inline-flex size-8 items-center justify-center rounded-lg bg-surface shadow-[var(--shadow-border)] transition-all group-hover:shadow-[var(--shadow-border-hover)]">
              <span className="font-mono text-sm font-semibold tracking-tight text-fg">NM</span>
              <span
                className={cn(
                  "absolute -right-0.5 -top-0.5 size-2 rounded-full ring-2 ring-bg",
                  isGuardActive ? "bg-ok" : "bg-warn",
                )}
              />
              {isGuardActive ? (
                <span className="pulse-ring absolute -right-0.5 -top-0.5 size-2 rounded-full bg-ok" />
              ) : null}
            </span>
            <div className="hidden flex-col md:flex">
              <span className="font-mono text-xs font-semibold tracking-wider text-fg">NMZP</span>
              <span className="text-[10px] text-muted leading-none">{tx("guardCore")}</span>
            </div>
          </Link>

          <nav
            className="hidden min-w-0 flex-1 items-center gap-1 overflow-x-auto px-2 lg:flex"
            aria-label="Primary"
          >
            {NAV.map((item) => {
              const active = isActive(pathname, item.to);
              const Icon = item.icon;
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "relative flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-all duration-150",
                    active
                      ? "bg-elevated text-fg shadow-[var(--shadow-border)] font-semibold"
                      : "text-muted hover:bg-surface/70 hover:text-fg",
                  )}
                >
                  <Icon className={cn("size-3.5", active ? "text-fg" : "text-muted")} />
                  <span>{tx(item.key)}</span>
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-1.5">
            {canMutate ? (
              <Button
                size="sm"
                variant="outline"
                onClick={cycleMode}
                className={cn(
                  "hidden items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium sm:inline-flex",
                  intervention === "enforcing"
                    ? "border-ok/30 bg-ok/10 text-ok hover:bg-ok/20"
                    : "border-warn/30 bg-warn/10 text-warn hover:bg-warn/20",
                )}
              >
                {intervention === "enforcing" ? (
                  <ShieldCheck className="size-3.5" />
                ) : (
                  <ShieldAlert className="size-3.5" />
                )}
                <span>{tx(intervention)}</span>
              </Button>
            ) : synced ? (
              <span className="hidden rounded-full bg-elevated px-3 py-1 font-mono text-xs text-muted sm:inline-flex">
                {tx(intervention)}
                {access === "viewer" ? ` · ${tx("lanViewer")}` : ""}
              </span>
            ) : null}

            <span className="rounded-md bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted">
              {tx("utc8")}
            </span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                const next = locale === "zh" ? "en" : "zh";
                setLocale(next);
                toast(t(next, "langSwitched"));
              }}
              aria-label="Language"
              className="rounded-lg px-2 font-mono text-xs text-muted hover:text-fg"
            >
              {locale === "zh" ? "EN" : "中"}
            </Button>
            <Button
              size="icon-sm"
              variant="ghost"
              aria-label={theme === "dark" ? tx("themeLight") : tx("themeDark")}
              onClick={() => {
                const next = theme === "dark" ? "light" : "dark";
                setTheme(next);
                toast(next === "dark" ? tx("themeDark") : tx("themeLight"));
              }}
              className="rounded-lg text-muted hover:text-fg"
            >
              {theme === "dark" ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
            </Button>
            <Button
              size="icon-sm"
              variant="ghost"
              className="rounded-lg text-muted hover:text-fg lg:hidden"
              aria-label="Menu"
              onClick={() => setOpen((v) => !v)}
            >
              {open ? <X className="size-4" /> : <Menu className="size-4" />}
            </Button>
          </div>
        </div>

        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 border-t border-line/60 px-3 py-2 sm:px-4 lg:px-6">
          <div className="flex min-w-0 max-w-full items-center gap-2 overflow-x-auto">
            <span className="flex shrink-0 items-center gap-1 font-mono text-[11px] text-subtle">
              <Server className="size-3" />
              {tx("fleet")}:
            </span>
            <div
              className="flex shrink-0 items-center rounded-lg bg-surface/80 p-0.5 shadow-[var(--shadow-border)]"
              role="group"
              aria-label={tx("allMachines")}
            >
              <button
                type="button"
                onClick={() => setMachineFilter("all")}
                className={cn(
                  "h-6.5 rounded-md px-2.5 font-mono text-xs transition-all",
                  machineFilter === "all" || host === "all"
                    ? "bg-elevated text-fg font-medium shadow-sm"
                    : "text-muted hover:text-fg",
                )}
              >
                {tx("allMachines")}
              </button>
              {fleet.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setMachineFilter(m.id)}
                  title={`${m.hostname} (${m.ip})`}
                  className={cn(
                    "flex h-6.5 items-center gap-1.5 rounded-md px-2 font-mono text-xs transition-all",
                    host === m.id
                      ? "bg-elevated text-fg font-medium shadow-sm"
                      : "text-muted hover:text-fg",
                    m.status === "dark" && "text-danger font-semibold",
                  )}
                >
                  <span
                    className={cn(
                      "size-1.5 rounded-full",
                      m.status === "dark" ? "bg-danger animate-pulse" : "bg-ok",
                    )}
                  />
                  <span>{m.hostname}</span>
                  {m.status === "dark" ? (
                    <span className="rounded bg-danger/15 px-1 py-0.2 text-[10px] text-danger">
                      {tx("machineDark")}
                    </span>
                  ) : null}
                </button>
              ))}
            </div>
          </div>

          <div className="flex min-w-0 max-w-full items-center gap-2 overflow-x-auto">
            <span className="flex shrink-0 items-center gap-1 font-mono text-[11px] text-subtle">
              <Bot className="size-3" />
              {tx("allAgents")}:
            </span>
            <div
              className="flex shrink-0 items-center rounded-lg bg-surface/80 p-0.5 shadow-[var(--shadow-border)]"
              role="group"
              aria-label={tx("allAgents")}
            >
              <button
                type="button"
                onClick={() => setAgentFilter("all")}
                className={cn(
                  "h-6.5 rounded-md px-2.5 font-mono text-xs transition-all",
                  agentFilter === "all"
                    ? "bg-elevated text-fg font-medium shadow-sm"
                    : "text-muted hover:text-fg",
                )}
              >
                {tx("all")}
              </button>
              {present.map((id) => {
                const def = AGENTS[id];
                const active = agentFilter === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setAgentFilter(id)}
                    title={def.name}
                    className={cn(
                      "flex h-6.5 min-w-7 items-center justify-center gap-1 rounded-md px-2 font-mono text-xs transition-all",
                      active
                        ? "bg-elevated text-fg font-semibold shadow-sm"
                        : "text-muted hover:text-fg",
                    )}
                  >
                    <span>{def.letter}</span>
                    {active ? <span className="hidden sm:inline text-[11px]">{def.name}</span> : null}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {open ? (
          <nav className="grid gap-1 border-t border-line bg-surface/95 p-4 backdrop-blur-lg lg:hidden" aria-label="Mobile">
            <div className="mb-2 flex items-center justify-between rounded-lg bg-elevated p-2">
              {canMutate ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={cycleMode}
                  className={cn(
                    "text-xs font-medium",
                    intervention === "enforcing" ? "text-ok" : "text-warn",
                  )}
                >
                  {tx(intervention)}
                </Button>
              ) : (
                <span className="font-mono text-xs text-muted">{tx(intervention)}</span>
              )}
              <span className="font-mono text-xs text-muted">
                {synced ? (paused ? tx("off") : tx("live")) : tx("loading")}
              </span>
            </div>
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex min-h-10 items-center gap-2.5 rounded-lg px-3 text-sm font-medium transition-colors",
                  isActive(pathname, item.to)
                    ? "bg-elevated text-fg shadow-[var(--shadow-border)]"
                    : "text-muted hover:bg-elevated/50 hover:text-fg",
                )}
              >
                <item.icon className="size-4" />
                {tx(item.key)}
              </Link>
            ))}
          </nav>
        ) : null}
      </header>
      <main id="main" className="mx-auto max-w-7xl px-3 py-5 sm:px-4 lg:px-6 lg:py-6">
        {children}
      </main>
    </div>
  );
}
