import {EvidenceWindowNotice} from "@/components/evidence-window";
import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Copy, Download, Filter, Search, Sparkles, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { EventRow } from "@/components/event-row";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/monitor/format";
import { evidenceExport, eventMatchesQuery, isHighRiskOss } from "@/lib/monitor/network-view";
import { useCanMutate, useFilteredEvents, useMonitor, useT } from "@/lib/monitor/store";
import type { AuditEvent, Decision, Layer, Risk } from "@/lib/monitor/types";
import { buildPolicyContext } from "@/lib/monitor/policy-proposal";
import { RULES } from "@/lib/monitor/rules";
import { ExemptionModal } from "@/components/policy/exemption-modal";
import { ProposalModal } from "@/components/policy/proposal-modal";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/audit")({ component: AuditPage });

type QuickPreset = "all" | "high_risk" | "blocked" | "threats" | "app_layer" | "kernel_layer" | "oss_high";

export function AuditPage() {
  const tx = useT();
  const events = useFilteredEvents();
  const evidenceWindow = useMonitor((s) => s.evidenceWindow);
  const sessions = useMonitor((s) => s.sessions);
  const clearEvents = useMonitor((s) => s.clearEvents);
  const policyVersion = useMonitor((s) => s.policyVersion);
  const intervention = useMonitor((s) => s.intervention);
  const overrides = useMonitor((s) => s.overrides);
  const exemptions = useMonitor((s) => s.exemptions);
  const customRules = useMonitor((s) => s.customRules);
  const access = useMonitor((s) => s.access);
  const canMutate = useCanMutate();
  const [q, setQ] = useState("");
  const [preset, setPreset] = useState<QuickPreset>("all");
  const [risk, setRisk] = useState<Risk | "all">("all");
  const [decision, setDecision] = useState<Decision | "all">("all");
  const [layer, setLayer] = useState<Layer | "all">("all");
  const [sessionId, setSessionId] = useState("all");
  const [limit, setLimit] = useState(50);
  const [selectedFalsePositive, setSelectedFalsePositive] = useState<AuditEvent | null>(null);
  const [showProposalModal, setShowProposalModal] = useState(false);

  const handleClear = () => {
    void clearEvents().then((ok) => {
      if (ok) toast.success(tx("toastAuditCleared"));
      else toast.error(tx("mutationFailed"));
    });
  };

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    return [...events]
      .reverse()
      .filter((e) => {
        if (preset === "high_risk") return e.risk === "high";
        if (preset === "blocked") return e.enforcement === "blocked";
        if (preset === "threats") return Boolean(e.threat || e.secretKinds?.length);
        if (preset === "app_layer") return e.layer === "app_pre" || e.layer === "app_post" || e.layer === "model_response";
        if (preset === "kernel_layer") return e.layer === "kernel_exec" || e.layer === "kernel_net";
        if (preset === "oss_high") return isHighRiskOss(e);
        return true;
      })
      .filter((e) => (risk === "all" ? true : e.risk === risk))
      .filter((e) => (decision === "all" ? true : e.decision === decision))
      .filter((e) => (layer === "all" ? true : e.layer === layer))
      .filter((e) => (sessionId === "all" ? true : e.sessionId === sessionId))
      .filter((e) => eventMatchesQuery(e, query));
  }, [events, preset, q, risk, decision, layer, sessionId]);

  const handleExport = () => {
    const exportedAt = Date.now();
    const policyContext = buildPolicyContext(
      {
        policyVersion,
        mode: intervention,
        overrides,
        exemptions,
        customRules,
        rules: RULES,
      },
      access,
    );
    const jsonStr = JSON.stringify(
      {
        ...evidenceExport(filtered, exportedAt),
        evidenceWindow,
        evidenceWindowScope: "server",
        policyContext,
      },
      null,
      2,
    );
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const day = formatDateTime(exportedAt, "zh").slice(0, 10);
    a.download = `nmzp-audit-export-${day === "—" ? exportedAt : day}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`${tx("toastExportedJson")}: ${filtered.length}`);
  };

  const handleCopyAiPrompt = () => {
    const promptText =
      "以下是 NMZP 审计导出与策略上下文。请只输出一个 nmzp-policy-proposal/1 JSON，不要修改受保护规则，不要包含 mode 字段，所有新自定义规则默认 dryRun。";
    void navigator.clipboard.writeText(promptText).then(() => {
      toast.success("已复制 AI 提示词");
    });
  };

  const highCount = events.filter((e) => e.risk === "high").length;
  const blockedCount = events.filter((e) => e.enforcement === "blocked").length;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navAudit")}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span className="font-mono">
              {filtered.length} / {events.length} {tx("events")}
            </span>
            <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-subtle border border-line">
              {tx("utc8")}
            </span>
            {blockedCount > 0 ? (
              <span className="rounded-full bg-danger/10 px-2 py-0.5 font-mono text-[11px] font-medium text-danger border border-danger/25">
                {blockedCount} {tx("blocked")}
              </span>
            ) : null}
            {highCount > 0 ? (
              <span className="rounded-full bg-warn/10 px-2 py-0.5 font-mono text-[11px] font-medium text-warn border border-warn/25">
                {highCount} {tx("high")}
              </span>
            ) : null}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={handleCopyAiPrompt} className="gap-1.5 text-xs">
            <Copy className="size-3.5" />
            <span>{tx("copyAiPrompt")}</span>
          </Button>
          <Button size="sm" variant="outline" onClick={() => setShowProposalModal(true)} className="gap-1.5 text-xs">
            <Sparkles className="size-3.5 text-info" />
            <span>{tx("proposalImport")}</span>
          </Button>
          <Button size="sm" variant="outline" onClick={handleExport} className="gap-1.5 text-xs">
            <Download className="size-3.5" />
            <span>{tx("exportJson")}</span>
          </Button>
          {canMutate ? (
          <Button size="sm" variant="outline" onClick={handleClear} className="gap-1.5 text-xs text-muted hover:text-danger">
            <Trash2 className="size-3.5" />
            <span>{tx("clearLog")}</span>
          </Button>
          ) : null}
        </div>
      </div>

      <EvidenceWindowNotice />
      {/* Quick preset filter chips */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
        <span className="flex items-center gap-1 font-mono text-xs text-subtle shrink-0 mr-1">
          <Filter className="size-3" />
          {tx("quickFilter")}:
        </span>
        {[
          { id: "all", label: tx("filterAll") },
          { id: "high_risk", label: tx("filterHighRisk"), count: highCount },
          { id: "blocked", label: tx("filterBlocked"), count: blockedCount },
          { id: "threats", label: tx("filterThreats") },
          { id: "oss_high", label: tx("netHighOss") },
          { id: "app_layer", label: tx("filterApp") },
          { id: "kernel_layer", label: tx("filterKernel") },
        ].map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setPreset(item.id as QuickPreset)}
            className={cn(
              "flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1 font-mono text-xs transition-all",
              preset === item.id
                ? "bg-elevated text-fg font-semibold shadow-[var(--shadow-border)] border border-line-strong"
                : "bg-surface text-muted hover:text-fg hover:bg-elevated/60 shadow-[var(--shadow-border)]",
            )}
          >
            <span>{item.label}</span>
          </button>
        ))}
      </div>

      {/* Advanced Filter Inputs */}
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        <div className="relative">
          <Search className="absolute left-3 top-3 size-4 text-muted pointer-events-none" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={tx("search")}
            className="h-10 w-full rounded-lg bg-surface pl-9 pr-8 text-xs sm:text-sm text-fg shadow-[var(--shadow-border)] outline-none focus:shadow-[var(--shadow-border-hover)]"
          />
          {q ? (
            <button
              type="button"
              onClick={() => setQ("")}
              className="absolute right-2.5 top-3 text-muted hover:text-fg"
            >
              <X className="size-4" />
            </button>
          ) : null}
        </div>

        <select
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          className="h-10 rounded-lg bg-surface px-3 text-xs sm:text-sm text-fg shadow-[var(--shadow-border)] outline-none"
        >
          <option value="all">{tx("allSessions")}</option>
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              {s.folder} · {s.model} · {s.shortId}
            </option>
          ))}
        </select>

        <select
          value={risk}
          onChange={(e) => setRisk(e.target.value as Risk | "all")}
          className="h-10 rounded-lg bg-surface px-3 text-xs sm:text-sm text-fg shadow-[var(--shadow-border)] outline-none"
        >
          <option value="all">{tx("allRisks")}</option>
          <option value="high">{tx("high")}</option>
          <option value="medium">{tx("medium")}</option>
          <option value="low">{tx("low")}</option>
          <option value="info">{tx("info")}</option>
        </select>

        <select
          value={decision}
          onChange={(e) => setDecision(e.target.value as Decision | "all")}
          className="h-10 rounded-lg bg-surface px-3 text-xs sm:text-sm text-fg shadow-[var(--shadow-border)] outline-none"
        >
          <option value="all">{tx("allDecisions")}</option>
          <option value="block">{tx("block")}</option>
          <option value="rewrite">{tx("rewrite")}</option>
          <option value="allow">{tx("allow")}</option>
          <option value="log">{tx("log")}</option>
        </select>

        <select
          value={layer}
          onChange={(e) => setLayer(e.target.value as Layer | "all")}
          className="h-10 rounded-lg bg-surface px-3 text-xs sm:text-sm text-fg shadow-[var(--shadow-border)] outline-none"
        >
          <option value="all">{tx("allLayers")}</option>
          <option value="app_pre">{tx("appPre")}</option>
          <option value="model_response">{tx("modelResponse")}</option>
          <option value="app_post">{tx("appPost")}</option>
          <option value="kernel_exec">{tx("kernelExec")}</option>
          <option value="kernel_net">{tx("kernelNet")}</option>
        </select>
      </div>

      {/* Events List */}
      <div className="rounded-xl bg-surface p-2 shadow-[var(--shadow-border)]">
        {filtered.length === 0 ? (
          <div className="py-16 text-center">
            <p className="text-sm font-medium text-fg">{tx("emptyEvents")}</p>
            <p className="mt-1 text-xs text-muted">{tx("noAuditMatch")}</p>
            {(q || preset !== "all" || risk !== "all" || decision !== "all" || layer !== "all" || sessionId !== "all") && (
              <Button
                size="sm"
                variant="outline"
                className="mt-4 text-xs"
                onClick={() => {
                  setQ("");
                  setPreset("all");
                  setRisk("all");
                  setDecision("all");
                  setLayer("all");
                  setSessionId("all");
                }}
              >
                {tx("resetFilters")}
              </Button>
            )}
          </div>
        ) : (
          <>
            <div className="flex flex-col">
              {filtered.slice(0, limit).map((e) => (
                <EventRow
                  key={e.id}
                  event={e}
                  onMarkFalsePositive={(evt) => setSelectedFalsePositive(evt)}
                />
              ))}
            </div>
            {filtered.length > limit ? (
              <div className="border-t border-line p-3 text-center">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setLimit((n) => n + 50)}
                  className="font-mono text-xs"
                >
                  {tx("loadMore")} ({limit} / {filtered.length})
                </Button>
              </div>
            ) : null}
          </>
        )}
      </div>

      {selectedFalsePositive ? (
        <ExemptionModal
          event={selectedFalsePositive}
          onClose={() => setSelectedFalsePositive(null)}
        />
      ) : null}

      {showProposalModal ? (
        <ProposalModal onClose={() => setShowProposalModal(false)} />
      ) : null}
    </div>
  );
}
