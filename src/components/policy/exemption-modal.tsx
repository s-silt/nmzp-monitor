import { useState } from "react";
import { AlertCircle, Check, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { useMonitor, useT } from "@/lib/monitor/store";
import type { AuditEvent } from "@/lib/monitor/types";
import { CANONICAL_TOOL_NAMES, type PolicyExemption } from "@/lib/monitor/policy-schema";
import { compileMatch, escapeRegExp, exemptionId } from "@/lib/monitor/privacy";

export function ExemptionModal({
  event,
  onClose,
}: {
  event: AuditEvent | null;
  onClose: () => void;
}) {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const isZh = locale === "zh";
  const addExemption = useMonitor((s) => s.addExemption);

  const initialMatch = event
    ? escapeRegExp((event.redacted || event.input || "").split("\n")[0].slice(0, 80))
    : "";
  const initialTools = event?.tool && event.tool !== "unknown" ? [event.tool] : [];

  const [match, setMatch] = useState(initialMatch);
  const [tools, setTools] = useState<string[]>(initialTools);
  const [note, setNote] = useState("");
  const [ttlDays, setTtlDays] = useState(30);
  const [busy, setBusy] = useState(false);

  if (!event || !event.ruleId) return null;

  const validMatch = match.trim().length >= 4 && match.trim().length <= 80 && compileMatch(match.trim()) !== null;

  const handleToolToggle = (toolName: string) => {
    setTools((prev) =>
      prev.includes(toolName) ? prev.filter((t) => t !== toolName) : [...prev, toolName],
    );
  };

  const handleSave = async () => {
    if (!validMatch || busy) return;
    setBusy(true);
    const now = Date.now();
    const id = exemptionId(event.ruleId!, match.trim());
    const ex: PolicyExemption = {
      id,
      ruleId: event.ruleId!,
      match: match.trim(),
      tools: tools.length > 0 ? tools : undefined,
      note: note.trim() ? note.trim().slice(0, 120) : undefined,
      createdAt: now,
      expiresAt: now + ttlDays * 24 * 60 * 60 * 1000,
      sourceEventId: event.id,
    };

    try {
      const ok = await addExemption(ex);
      if (ok) {
        toast.success(isZh ? "豁免已添加" : "Exemption added");
        onClose();
      } else {
        toast.error(tx("mutationFailed"));
      }
    } catch {
      toast.error(tx("mutationFailed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-line bg-surface shadow-2xl">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-2">
            <AlertCircle className="size-4 text-warn" />
            <h3 className="font-semibold text-fg">{tx("markFalsePositive")}</h3>
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
          <div>
            <label className="font-medium text-subtle">命中规则 ID</label>
            <div className="mt-1 font-mono text-sm text-fg rounded bg-elevated px-3 py-1.5 border border-line">
              {event.ruleId}
            </div>
          </div>

          <div>
            <label className="font-medium text-subtle">来源事件 ID</label>
            <div className="mt-1 font-mono text-xs text-muted rounded bg-elevated px-3 py-1.5 border border-line">
              {event.id}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <label className="font-medium text-fg">豁免匹配表达式 (match)</label>
              <span className="text-[10px] text-muted">4..80 字符</span>
            </div>
            <input
              type="text"
              value={match}
              onChange={(e) => setMatch(e.target.value.slice(0, 80))}
              placeholder="请输入稳定的字面量匹配模式"
              className="mt-1 w-full rounded border border-line bg-elevated px-3 py-2 font-mono text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
            />
            {!validMatch && match.length > 0 ? (
              <p className="mt-1 text-[11px] text-danger">匹配表达式长度须为 4-80 字符且符合合法正则/字面量语法</p>
            ) : null}
          </div>

          <div>
            <label className="font-medium text-fg">{tx("scopeTools")}</label>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {CANONICAL_TOOL_NAMES.map((name) => {
                const active = tools.includes(name);
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => handleToolToggle(name)}
                    className={`rounded px-2 py-1 font-mono text-[11px] border transition-colors ${
                      active
                        ? "bg-fg text-bg border-fg"
                        : "bg-elevated text-muted border-line hover:text-fg"
                    }`}
                  >
                    {name}
                  </button>
                );
              })}
            </div>
            <p className="mt-1 text-[11px] text-muted">未勾选任何工具时，在所有工具生效。</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="font-medium text-fg">有效期限 (天)</label>
              <input
                type="number"
                min="1"
                max="365"
                value={ttlDays}
                onChange={(e) => setTtlDays(Math.max(1, Math.min(365, Number(e.target.value) || 30)))}
                className="mt-1 w-full rounded border border-line bg-elevated px-3 py-1.5 font-mono text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              />
            </div>
            <div>
              <label className="font-medium text-fg">备注说明 (可选)</label>
              <input
                type="text"
                value={note}
                onChange={(e) => setNote(e.target.value.slice(0, 120))}
                placeholder="误报原因说明"
                className="mt-1 w-full rounded border border-line bg-elevated px-3 py-1.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
          <Button size="sm" variant="outline" onClick={onClose} disabled={busy}>
            {isZh ? "取消" : "Cancel"}
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!validMatch || busy}
            className="gap-1.5"
          >
            <Check className="size-3.5" />
            <span>{isZh ? "确认添加豁免" : "Add Exemption"}</span>
          </Button>
        </div>
      </div>
    </div>
  );
}
