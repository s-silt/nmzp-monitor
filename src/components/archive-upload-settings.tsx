import { useEffect, useState } from "react";
import { Archive } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useMonitor, useT } from "@/lib/monitor/store";

export function ArchiveUploadSettings() {
  const tx = useT();
  const current = useMonitor((s) => s.archiveUpload);
  const save = useMonitor((s) => s.setArchiveUpload);
  const access = useMonitor((s) => s.access);
  const synced = useMonitor((s) => s.synced);
  const disconnected = useMonitor((s) => s.disconnected);
  const mode = useMonitor((s) => s.intervention);

  const [value, setValue] = useState(String(current.thresholdMiB));
  const [action, setAction] = useState<"warn" | "block">("warn");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    setValue(String(current.thresholdMiB));
    setAction("warn");
  }, [current.thresholdMiB, current.action]);

  const n = Number(value);
  const valid = Number.isSafeInteger(n) && n >= 1 && n <= 1048576;

  async function submit() {
    if (!valid || busy) return;
    setBusy(true);
    try {
      const ok = await save({ thresholdMiB: n, action });
      setMessage(ok ? tx("archiveSaveSuccess") : tx("archiveSaveFail"));
    } catch {
      setMessage(tx("archiveSaveConnFail"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="rounded-xl border border-line bg-surface p-5 shadow-[var(--shadow-border)] flex flex-col gap-3"
      aria-label={tx("archivePolicyTitle")}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <Archive className="size-4 text-fg" />
          <h3 className="text-sm font-semibold text-fg">{tx("archivePolicyTitle")}</h3>
        </div>
        <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
          {tx("uploadPolicySectionBadge")}
        </span>
      </div>

      <p className="text-xs leading-relaxed text-muted">{tx("archivePolicyDesc")}</p>

      {!synced ? (
        <p className="text-xs text-muted">{tx("archivePolicyNotSynced")}</p>
      ) : access === "admin" ? (
        <div className="flex flex-col gap-2.5 pt-1">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs font-medium text-fg">
              <span>{tx("archiveThresholdLabel")}</span>
              <input
                aria-label={tx("archiveThresholdLabel")}
                type="number"
                min="1"
                max="1048576"
                step="1"
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  setMessage("");
                }}
                className="w-32 rounded-lg border border-line bg-elevated px-2.5 py-1.5 font-mono text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs font-medium text-fg">
              <span>{tx("archiveActionLabel")}</span>
              <select
                aria-label={tx("archiveActionLabel")}
                value={action}
                onChange={(e) => setAction(e.target.value as "warn" | "block")}
                className="rounded-lg border border-line bg-elevated px-2.5 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              >
                <option value="warn">{tx("archiveActionWarn")}</option>
                <option value="block" disabled>
                  {tx("archiveActionBlockDisabled")}
                </option>
              </select>
            </label>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!valid || busy || disconnected}
              onClick={submit}
              className="h-8 text-xs"
            >
              {busy ? tx("archiveSaving") : tx("archiveSaveBtn")}
            </Button>
          </div>
          {!valid ? <p className="text-xs text-warn">{tx("archiveInvalidThreshold")}</p> : null}
        </div>
      ) : (
        <div className="rounded-lg bg-elevated/60 border border-line/60 p-3 text-xs text-muted">
          <p className="font-mono text-fg">
            {tx("archiveViewerSummary").replace("{threshold}", String(current.thresholdMiB))}
          </p>
        </div>
      )}

      {mode !== "enforcing" ? (
        <p className="text-xs text-warn">{tx("archiveNotEnforcing")}</p>
      ) : null}
      {disconnected ? (
        <p className="text-xs text-warn">{tx("archiveDisconnected")}</p>
      ) : null}
      {message ? (
        <p role="status" className="text-xs text-ok font-medium">
          {message}
        </p>
      ) : null}
    </section>
  );
}
