import { useMemo, useState } from "react";
import { AlertTriangle, Check, FileUp, Sparkles, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { DecisionBadge } from "@/components/risk-badge";
import { formatTime } from "@/lib/monitor/format";
import { RULES } from "@/lib/monitor/rules";
import { useFilteredEvents, useMonitor, useT } from "@/lib/monitor/store";
import {
  mergeProposal,
  parsePolicyProposal,
  type PolicyProposal,
} from "@/lib/monitor/policy-proposal";
import {
  replayPolicy,
  type PolicyView,
} from "@/lib/monitor/policy-replay";

export function ProposalModal({ onClose }: { onClose: () => void }) {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const isZh = locale === "zh";
  const policyVersion = useMonitor((s) => s.policyVersion);
  const intervention = useMonitor((s) => s.intervention);
  const overrides = useMonitor((s) => s.overrides);
  const customRules = useMonitor((s) => s.customRules);
  const exemptions = useMonitor((s) => s.exemptions);
  const applyProposal = useMonitor((s) => s.applyProposal);
  const events = useFilteredEvents();

  const [rawText, setRawText] = useState("");
  const [proposal, setProposal] = useState<PolicyProposal | null>(null);
  const [parseErrors, setParseErrors] = useState<string[]>([]);
  const [forceDryRun, setForceDryRun] = useState(true);
  const [busy, setBusy] = useState(false);

  const currentPolicy: PolicyView = useMemo(
    () => ({ mode: intervention, overrides, customRules, exemptions }),
    [intervention, overrides, customRules, exemptions],
  );

  const handleParse = (text: string) => {
    setRawText(text);
    if (!text.trim()) {
      setProposal(null);
      setParseErrors([]);
      return;
    }
    try {
      const parsed = JSON.parse(text);
      const res = parsePolicyProposal(parsed, { rules: RULES });
      if (res.ok) {
        setProposal(res.proposal);
        setParseErrors([]);
      } else {
        setProposal(null);
        setParseErrors(res.errors);
      }
    } catch {
      setProposal(null);
      setParseErrors(["JSON 解析失败：输入不是合法的 JSON 格式"]);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result as string;
      handleParse(content);
    };
    reader.readAsText(file);
  };

  const mergeResult = useMemo(() => {
    if (!proposal) return null;
    return mergeProposal(
      { overrides, customRules, exemptions },
      proposal,
      {
        now: Date.now(),
        forceDryRun,
      },
    );
  }, [proposal, overrides, customRules, exemptions, forceDryRun]);

  const nextPolicy = mergeResult?.ok ? mergeResult.next : null;
  const mergeErrors = mergeResult && !mergeResult.ok ? mergeResult.errors : [];

  const replay = useMemo(() => {
    if (!nextPolicy) return null;
    const nextPolicyView: PolicyView = { mode: intervention, ...nextPolicy };
    return replayPolicy(
      events,
      nextPolicyView,
      currentPolicy,
      RULES,
      Date.now(),
    );
  }, [events, nextPolicy, currentPolicy, intervention]);

  const handleApply = async () => {
    if (!nextPolicy || busy) return;
    setBusy(true);
    try {
      const ok = await applyProposal(nextPolicy);
      if (ok) {
        toast.success(isZh ? "策略建议已成功应用" : "Policy proposal applied successfully");
        onClose();
      } else {
        toast.error("策略版本冲突（409），已自动同步最新状态，请重新确认建议");
      }
    } catch {
      toast.error(tx("mutationFailed"));
    } finally {
      setBusy(false);
    }
  };

  const versionMismatch =
    proposal?.basePolicyVersion !== undefined && proposal.basePolicyVersion !== policyVersion;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col rounded-xl border border-line bg-surface shadow-2xl">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-2">
            <Sparkles className="size-4 text-info" />
            <h3 className="font-semibold text-fg">{tx("proposalImport")}</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-muted hover:bg-elevated hover:text-fg"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-4 text-xs">
          {!proposal ? (
            <div className="flex flex-col gap-3">
              <p className="text-muted leading-relaxed">
                请粘贴由大模型根据审计上下文生成的 <code className="font-mono text-fg">nmzp-policy-proposal/1</code> 格式 JSON，或上传导出的 JSON 策略建议文件。
              </p>
              <textarea
                value={rawText}
                onChange={(e) => handleParse(e.target.value)}
                placeholder='{"schema": "nmzp-policy-proposal/1", ...}'
                rows={8}
                spellCheck={false}
                className="w-full rounded border border-line bg-elevated px-3 py-2 font-mono text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              />
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-1.5 cursor-pointer rounded border border-line bg-elevated px-3 py-1.5 text-xs text-muted hover:text-fg">
                  <FileUp className="size-3.5" />
                  <span>选择文件导入</span>
                  <input
                    type="file"
                    accept=".json,application/json"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>

              {parseErrors.length > 0 ? (
                <div className="rounded-lg border border-danger/30 bg-danger/10 p-3 text-danger">
                  <p className="font-semibold">提案校验未通过：</p>
                  <ul className="mt-1 list-disc pl-4 space-y-0.5">
                    {parseErrors.map((err, i) => (
                      <li key={i} className="font-mono text-[11px]">{err}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              {versionMismatch ? (
                <div className="flex items-center gap-2 rounded-lg border border-warn/30 bg-warn/10 p-3 text-warn">
                  <AlertTriangle className="size-4 shrink-0" />
                  <span>
                    {tx("proposalVersionMismatch")
                      .replace("{base}", String(proposal.basePolicyVersion))
                      .replace("{current}", String(policyVersion))}
                  </span>
                </div>
              ) : null}

              {mergeErrors.length > 0 ? (
                <div className="rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
                  <p className="font-semibold">{isZh ? "策略合并未通过：" : "Policy merge failed:"}</p>
                  <ul className="mt-1 list-disc pl-4 space-y-0.5">
                    {mergeErrors.map((err, i) => (
                      <li key={i} className="font-mono text-[11px]">{err}</li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {proposal.rationale ? (
                <div className="rounded-lg bg-elevated p-3 border border-line">
                  <span className="font-medium text-subtle">{tx("proposalRationale")}</span>
                  <p className="mt-1 text-fg leading-relaxed">{proposal.rationale}</p>
                </div>
              ) : null}

              <div className="flex items-center justify-between border-y border-line py-2">
                <label className="flex items-center gap-2 cursor-pointer font-medium text-fg">
                  <input
                    type="checkbox"
                    checked={forceDryRun}
                    onChange={(e) => setForceDryRun(e.target.checked)}
                    className="size-3.5 rounded border-line"
                  />
                  <span>{tx("proposalForceDry")}</span>
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setProposal(null);
                    setRawText("");
                  }}
                  className="text-xs text-muted hover:text-fg underline underline-offset-2"
                >
                  重新选择文件 / 粘贴
                </button>
              </div>

              {replay ? (
                <div className="flex flex-col gap-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-fg">{tx("proposalPreview")}</span>
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className="rounded bg-elevated px-2 py-0.5 font-mono text-danger border border-line">
                        拦截: {replay.summary.block}
                      </span>
                      <span className="rounded bg-elevated px-2 py-0.5 font-mono text-muted border border-line">
                        记录: {replay.summary.log}
                      </span>
                      <span className="rounded bg-elevated px-2 py-0.5 font-mono text-ok border border-line">
                        豁免: {replay.summary.exempt}
                      </span>
                      <span className="rounded bg-elevated px-2 py-0.5 font-mono text-info border border-line">
                        试运行: {replay.summary.customHits}
                      </span>
                      <span className="rounded-full bg-warn/10 px-2 py-0.5 font-mono font-medium text-warn border border-warn/30">
                        {tx("proposalEstimated")}
                      </span>
                    </div>
                  </div>

                  {replay.rows.length === 0 ? (
                    <div className="rounded-lg bg-elevated/50 p-4 text-center text-muted">
                      回放历史事件中无决策变动（共 {events.length} 条审计事件保持一致）
                    </div>
                  ) : (
                    <div className="max-h-56 overflow-y-auto rounded-lg border border-line bg-elevated/30">
                      <table className="w-full text-left font-mono text-[11px]">
                        <thead className="border-b border-line bg-elevated/80 text-subtle">
                          <tr>
                            <th className="px-3 py-1.5 font-medium">时间</th>
                            <th className="px-3 py-1.5 font-medium">规则 / 工具</th>
                            <th className="px-3 py-1.5 font-medium">变更前</th>
                            <th className="px-3 py-1.5 font-medium">变更后</th>
                            <th className="px-3 py-1.5 font-medium">来源</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line">
                          {replay.rows.map((row) => {
                            const ev = events.find((e) => e.id === row.eventId);
                            return (
                              <tr key={row.eventId} className="hover:bg-elevated/50">
                                <td className="px-3 py-1 text-muted tabular-nums">
                                  {ev ? formatTime(ev.ts, locale) : "—"}
                                </td>
                                <td className="px-3 py-1 text-fg truncate max-w-[140px]">
                                  {row.ruleId || ev?.tool || "—"}
                                </td>
                                <td className="px-3 py-1">
                                  <DecisionBadge decision={row.before} />
                                </td>
                                <td className="px-3 py-1">
                                  <DecisionBadge decision={row.after} />
                                </td>
                                <td className="px-3 py-1 text-subtle">
                                  {row.source} {row.approximate ? `(${tx("proposalEstimated")})` : ""}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
          <Button size="sm" variant="outline" onClick={onClose} disabled={busy}>
            {isZh ? "取消" : "Cancel"}
          </Button>
          {proposal ? (
            <Button
              size="sm"
              onClick={handleApply}
              disabled={busy || !nextPolicy || mergeErrors.length > 0}
              className="gap-1.5"
            >
              <Check className="size-3.5" />
              <span>{tx("proposalApply")}</span>
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
