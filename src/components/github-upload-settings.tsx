import { useEffect, useState } from "react";
import { Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useMonitor, useT } from "@/lib/monitor/store";
import { GITHUB_AGENT_IDS } from "@/lib/monitor/egress-evidence";
import { AGENTS } from "@/lib/monitor/agents";

export function GithubUploadSettings() {
  const tx = useT();
  const current = useMonitor((s) => s.githubUpload);
  const save = useMonitor((s) => s.setGithubUpload);
  const access = useMonitor((s) => s.access);
  const synced = useMonitor((s) => s.synced);
  const disconnected = useMonitor((s) => s.disconnected);

  const [mode, setMode] = useState(current.mode);
  const [agents, setAgents] = useState(current.agents);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const key = current.agents.join(",");
  useEffect(() => {
    setMode(current.mode);
    setAgents([...current.agents]);
  }, [current.mode, current.agents, key]);

  async function submit() {
    if (busy) return;
    setBusy(true);
    try {
      const ok = await save({ mode, agents });
      setMessage(ok ? tx("githubSaveSuccess") : tx("githubSaveFail"));
    } catch {
      setMessage(tx("githubSaveConnFail"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="rounded-xl border border-line bg-surface p-5 shadow-[var(--shadow-border)] flex flex-col gap-3"
      aria-label={tx("githubPolicyTitle")}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <Globe className="size-4 text-fg" />
          <h3 className="text-sm font-semibold text-fg">{tx("githubPolicyTitle")}</h3>
        </div>
        <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
          {tx("uploadPolicySectionBadge")}
        </span>
      </div>

      <p className="text-xs leading-relaxed text-muted">{tx("githubPolicyDesc")}</p>

      {!synced ? (
        <p className="text-xs text-muted">{tx("githubPolicyNotSynced")}</p>
      ) : access === "admin" ? (
        <div className="flex flex-col gap-3 pt-1">
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-xs font-medium text-fg">
              <span>{tx("githubModeLabel")}</span>
              <select
                aria-label={tx("githubModeLabel")}
                value={mode}
                onChange={(e) => {
                  setMode(e.target.value as "selected" | "unlimited");
                  setMessage("");
                }}
                className="rounded-lg border border-line bg-elevated px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              >
                <option value="selected">{tx("githubModeSelected")}</option>
                <option value="unlimited">{tx("githubModeUnlimited")}</option>
              </select>
            </label>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || disconnected}
              onClick={submit}
              className="h-8 text-xs"
            >
              {busy ? tx("githubSaving") : tx("githubSaveBtn")}
            </Button>
          </div>

          <fieldset
            disabled={mode === "unlimited"}
            className="flex flex-wrap gap-x-4 gap-y-2 rounded-lg bg-elevated/40 border border-line/60 p-3 text-xs disabled:opacity-50"
          >
            <legend className="px-1 text-xs text-muted font-medium">
              {tx("githubAgentsLegend")}
            </legend>
            {GITHUB_AGENT_IDS.map((id) => (
              <label key={id} className="flex items-center gap-1.5 cursor-pointer text-fg">
                <input
                  type="checkbox"
                  checked={agents.includes(id)}
                  onChange={(e) => {
                    setMessage("");
                    setAgents((prev) =>
                      e.target.checked ? [...prev, id] : prev.filter((a) => a !== id),
                    );
                  }}
                  className="rounded border-line bg-surface text-fg focus:ring-1 focus:ring-fg/30"
                />
                <span>{AGENTS[id].name}</span>
              </label>
            ))}
          </fieldset>
        </div>
      ) : (
        <div className="rounded-lg bg-elevated/60 border border-line/60 p-3 text-xs text-muted">
          <p className="font-mono text-fg">
            {current.mode === "unlimited"
              ? tx("githubViewerUnlimited")
              : tx("githubViewerSelected").replace(
                  "{agents}",
                  current.agents.map((id) => AGENTS[id as keyof typeof AGENTS]?.name ?? id).join("、") ||
                    tx("unknown"),
                )}
          </p>
        </div>
      )}

      <p className="text-[11px] leading-relaxed text-subtle">{tx("githubDisclaimer")}</p>

      {disconnected ? (
        <p className="text-xs text-warn">{tx("githubDisconnected")}</p>
      ) : null}
      {message ? (
        <p role="status" className="text-xs text-ok font-medium">
          {message}
        </p>
      ) : null}
    </section>
  );
}
