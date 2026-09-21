import { Link, createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { DATA_CATEGORIES } from "@/lib/monitor/rights";
import { useCanMutate, useMonitor, useT } from "@/lib/monitor/store";

export const Route = createFileRoute("/rights")({ component: RightsPage });

export function RightsPage() {
  const tx = useT();
  const events = useMonitor((s) => s.events);
  const machines = useMonitor((s) => s.machines);
  const rules = useMonitor((s) => s.customRules);
  const exportLocal = useMonitor((s) => s.exportLocal);
  const wipeLocal = useMonitor((s) => s.wipeLocal);
  const stopProcessing = useMonitor((s) => s.stopProcessing);
  const resumeProcessing = useMonitor((s) => s.resumeProcessing);
  const paused = useMonitor((s) => s.paused);
  const access = useMonitor((s) => s.access);
  const canMutate = useCanMutate();
  const [armed, setArmed] = useState(false);

  const download = async () => {
    const body = await exportLocal();
    if (!body) {
      toast.error(tx("mutationFailed"));
      return;
    }
    const blob = new Blob([body], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "nmzp-rights-export.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const counts: Record<(typeof DATA_CATEGORIES)[number], number | string> = {
    agent_events: events.length,
    network_hops: tx("notCollected"),
    machine_inventory: machines.length,
    custom_rules: rules.length,
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-medium tracking-tight">{tx("rightsTitle")}</h1>
        <p className="mt-2 max-w-prose text-sm text-muted">{tx("rightsLead")}</p>
        {access === "viewer" ? <p className="mt-2 text-sm text-muted">{tx("lanViewer")}</p> : null}
      </div>

      <section className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)] lg:p-5">
        <h2 className="text-sm font-medium">{tx("rightsAccess")}</h2>
        <p className="mt-2 text-sm text-muted">{tx("rightsAccessNote")}</p>
        <dl className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div className="rounded-md bg-bg px-3 py-2">
            <dt className="text-xs text-subtle">{tx("catEvents")}</dt>
            <dd className="font-mono text-lg">{counts.agent_events}</dd>
          </div>
          <div className="rounded-md bg-bg px-3 py-2">
            <dt className="text-xs text-subtle">{tx("catHops")}</dt>
            <dd className="font-mono text-sm text-muted">{counts.network_hops}</dd>
          </div>
          <div className="rounded-md bg-bg px-3 py-2">
            <dt className="text-xs text-subtle">{tx("catMachines")}</dt>
            <dd className="font-mono text-lg">{counts.machine_inventory}</dd>
          </div>
          <div className="rounded-md bg-bg px-3 py-2">
            <dt className="text-xs text-subtle">{tx("catRules")}</dt>
            <dd className="font-mono text-lg">{counts.custom_rules}</dd>
          </div>
        </dl>
        <p className="mt-3 text-sm text-muted">{tx("rightsStay")}</p>
      </section>

      <section className="grid gap-3 md:grid-cols-2">
        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-medium">{tx("rightsExport")}</h2>
          <p className="mt-2 text-sm text-muted">{tx("rightsExportNote")}</p>
          <Button className="mt-4" type="button" onClick={() => void download()}>
            {tx("rightsExport")}
          </Button>
        </article>

        {canMutate ? (
          <>
            <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
              <h2 className="text-sm font-medium">{tx("rightsErase")}</h2>
              <p className="mt-2 text-sm text-muted">{tx("rightsEraseNote")}</p>
              <Button
                className="mt-4"
                type="button"
                variant={armed ? "default" : "outline"}
                onClick={() => {
                  if (!armed) {
                    setArmed(true);
                    return;
                  }
                  void wipeLocal().then((ok) => {
                    setArmed(false);
                    if (ok) toast.success(tx("toastAuditCleared"));
                    else toast.error(tx("mutationFailed"));
                  });
                }}
              >
                {armed ? tx("rightsEraseArm") : tx("rightsErase")}
              </Button>
            </article>

            <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
              <h2 className="text-sm font-medium">{tx("rightsStop")}</h2>
              <p className="mt-2 text-sm text-muted">{tx("rightsStopNote")}</p>
              <Button
                className="mt-4"
                type="button"
                variant="outline"
                onClick={() => {
                  void (paused ? resumeProcessing() : stopProcessing()).then((ok) => {
                    if (!ok) toast.error(tx("mutationFailed"));
                  });
                }}
              >
                {paused ? tx("live") : tx("rightsStop")}
              </Button>
            </article>
          </>
        ) : null}

        <article className="rounded-lg bg-surface p-4 shadow-[var(--shadow-border)]">
          <h2 className="text-sm font-medium">{tx("rightsFix")}</h2>
          <p className="mt-2 text-sm text-muted">{tx("rightsFixNote")}</p>
          <Link to="/rules" className="mt-4 inline-block text-sm underline-offset-2 hover:underline">
            {tx("navRules")}
          </Link>
        </article>
      </section>
    </div>
  );
}
