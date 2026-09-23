import {archiveAlert} from "@/lib/monitor/egress-evidence";
import {EgressEvidenceDetails} from "./egress-evidence";
import {ResponseEvidenceDetails} from "./response-evidence";
import { AgentMark } from "@/components/agent-mark";
import { DecisionBadge, RiskBadge } from "@/components/risk-badge";
import { formatDateTime, formatTime, sanitizeDisplayUrl, truncate } from "@/lib/monitor/format";
import { actorMsg, sourceMsg, threatMsg } from "@/lib/monitor/i18n";
import { decisionMsg, enforcementMsg, formatDeclaredHost, ossShapeOf, visibleDestinations } from "@/lib/monitor/network-view";
import { RULE_BY_ID } from "@/lib/monitor/rules";
import { useCanMutate, useMonitor, useT } from "@/lib/monitor/store";
import type { AuditEvent } from "@/lib/monitor/types";
import { isProtectedRule } from "@/lib/monitor/overrides";
import { cn } from "@/lib/utils";

const layerKey = {
  model_response: "modelResponse",
  app_pre: "appPre",
  app_post: "appPost",
  kernel_exec: "kernelExec",
  kernel_net: "kernelNet",
} as const;

export function EventRow({
  event,
  dense,
  onMarkFalsePositive,
}: {
  event: AuditEvent;
  dense?: boolean;
  onMarkFalsePositive?: (event: AuditEvent) => void;
}) {
  const locale = useMonitor((s) => s.locale);
  const canMutate = useCanMutate();
  const tx = useT();
  const rule = event.ruleId ? RULE_BY_ID[event.ruleId] : undefined;
  const extEvent = event as AuditEvent & {
    overrideSource?: "rule" | "family";
    exemptionId?: string;
    dryRunKinds?: string[];
  };
  const dest = visibleDestinations(event);
  const rawCommand = event.redacted || event.input;
  const command = event.layer === "model_response" ? tx(event.response?.findings.length ? "responseRisk" : "responseGap") : sanitizeDisplayUrl(rawCommand);
  return (
    <div
      className={cn(
        "grid grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-1 border-b border-line py-3 last:border-0 md:grid-cols-[88px_72px_1fr_92px_72px]",
        event.decision === "block" && "bg-danger/5",
        dense && "py-2",
      )}
    >
      <span className="font-mono text-xs tabular-nums text-subtle" suppressHydrationWarning>{formatTime(event.ts, locale)}</span>
      <span title={event.rawAgent}><AgentMark id={event.agent} showName={false} className="hidden md:inline-flex" /></span>
      <div className="min-w-0">
        <div className="flex items-center gap-2 md:hidden">
          <AgentMark id={event.agent} showName={false} />
          <RiskBadge risk={event.risk} />
        </div>
        {event.rawAgent ? <span className="text-xs text-muted">{event.rawAgent}</span> : null}
        {dest.kind === "missing" ? (
          <p className="break-all text-xs text-muted">{tx("netTargetNotCollected")}</p>
        ) : dest.kind === "empty" ? (
          <p className="text-xs text-muted">{tx("netTargetNone")}</p>
        ) : (
          <p className="break-all font-mono text-xs text-fg">
            {dest.hosts.map((host, i) => {
              const raw = event.endpoints?.[i]?.host ?? (dest.kind === "dest" ? event.dest : undefined);
              return (
                <span key={`${host}:${i}`}>
                  {i > 0 ? " · " : null}
                  {host}
                  {raw && ossShapeOf(raw) ? (
                    <span className="ml-1 text-[10px] text-muted">({tx("netOssShape")})</span>
                  ) : null}
                </span>
              );
            })}
          </p>
        )}
        <p className={cn("font-mono text-sm text-fg", dense ? "truncate" : "break-all")}>
          {dense ? truncate(command, 72) : command}
        </p>
        <p className="mt-0.5 break-all text-xs text-muted flex flex-wrap items-center gap-1.5">
          <span>{event.tool === "unknown" ? tx("unknown") : event.tool}</span>
          {event.enforcement === "blocked" ? (
            <span className="text-danger font-medium"> · {tx("blocked")}</span>
          ) : event.decision === "block" || event.enforcement === "returned_deny" ? (
            <span className="text-warn font-medium"> · {tx("returnedDeny")}</span>
          ) : null}
          {extEvent.overrideSource === "rule" ? (
            <span className="rounded bg-info/10 px-1.5 py-0.2 font-mono text-[10px] text-info border border-info/20">
              {tx("overrideSourceRule")}
            </span>
          ) : extEvent.overrideSource === "family" ? (
            <span className="rounded bg-info/10 px-1.5 py-0.2 font-mono text-[10px] text-info border border-info/20">
              {tx("overrideSourceFamily")}
            </span>
          ) : null}
          {extEvent.exemptionId ? (
            <span className="rounded bg-ok/10 px-1.5 py-0.2 font-mono text-[10px] text-ok border border-ok/20">
              {tx("exempted")} {extEvent.exemptionId}
            </span>
          ) : null}
          {extEvent.dryRunKinds && extEvent.dryRunKinds.length > 0 ? (
            <span className="rounded bg-warn/10 px-1.5 py-0.2 font-mono text-[10px] text-warn border border-warn/20">
              {tx("dryRunHit")} {extEvent.dryRunKinds.join(", ")}
            </span>
          ) : null}
          {event.actor ? (
            <span className={event.actor === "relay" ? "text-warn" : "text-subtle"}>
              · {tx(actorMsg(event.actor))}
            </span>
          ) : null}
          {event.threat && event.layer !== "model_response" ? (
            <span className="text-danger">
              · {tx(threatMsg(event.threat))}
            </span>
          ) : null}
          {event.hookBlind ? (
            <span className="text-warn">
              · {tx("probeCaught")}
            </span>
          ) : null}
          {event.correlateHit ? (
            <span className="text-subtle">
              · {tx("sessionStitch")}
            </span>
          ) : null}
          <span className="text-subtle">· {tx(layerKey[event.layer])}</span>
          {rule ? (
            <span className="text-subtle">
              · {locale === "zh" ? rule.title : rule.titleEn}
            </span>
          ) : event.ruleId?.startsWith("privacy:") ? (
            <span className="text-subtle">· {event.ruleId.slice(8)}</span>
          ) : null}
        </p>
        {event.egress&&archiveAlert(event.egress)?<p role="status" className="text-xs text-warn">{archiveAlert(event.egress)}</p>:null}
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <details className="group">
            <summary className="cursor-pointer text-[11px] text-muted hover:text-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-fg/30 rounded py-0.5">
              {tx("evidenceDetail")} ({tx("eventId")} {event.id})
            </summary>
            <dl className="mt-2 grid gap-1.5 break-all font-mono text-[11px] text-muted bg-surface/80 rounded-lg p-3 border border-line">
              <div>
                <span className="text-subtle">{tx("eventId")}:</span> {event.id}
              </div>
              <div>
                <span className="text-subtle">{tx(event.layer === "model_response" ? "safeSummary" : "commandText")}:</span>{" "}
                <span className="text-fg">{command}</span>
              </div>
              {event.egress ? <EgressEvidenceDetails event={event} /> : null}
              {event.response ? <ResponseEvidenceDetails evidence={event.response} /> : null}
              <div suppressHydrationWarning>
                <span className="text-subtle">{tx("utc8")}:</span> {formatDateTime(event.ts, locale)}
              </div>
              <div>
                <span className="text-subtle">{tx("requestHash")}:</span> {event.requestHash ?? tx("notCollected")}
              </div>
              <div>
                <span className="text-subtle">{tx("policyVersion")}:</span>{" "}
                {typeof event.policyVersion === "number" ? `v${event.policyVersion}` : tx("notCollected")}
              </div>
              <div>
                <span className="text-subtle">{event.layer === "model_response" ? (locale === "zh" ? "模型上游（不代表数据已泄露）" : "Model upstream (not evidence of disclosure)") : tx("netSourceDeclared")}:</span>{" "}
                {event.layer === "model_response" ? event.dest || tx("notCollected") : event.endpoints
                  ? event.endpoints.length
                    ? event.endpoints.map((ep) => `${tx(sourceMsg(ep.source))}: ${formatDeclaredHost(ep)}`).join(" · ")
                    : tx("netTargetNone")
                  : tx("netTargetNotCollected")}
              </div>
              <div>
                <span className="text-subtle">{tx("processLabel")}:</span> {event.proc ?? tx("notCollected")} ·{" "}
                <span className="text-subtle">{tx("sessionLabel")}:</span> {event.sessionId || tx("notCollected")}
              </div>
              <div>
                <span className="text-subtle">{tx("scopeMachine")}:</span> {event.machineId || tx("notCollected")}
              </div>
              <div>
                <span className="text-subtle">{tx("ruleVerdict")}:</span> {tx(decisionMsg(event.decision))} ·{" "}
                <span className="text-subtle">{tx("execFeedback")}:</span> {event.layer === "model_response" ? (locale === "zh" ? (event.enforcement === "delivered" ? "本地连接写入完成" : event.enforcement === "timeout" ? "回复转发超时" : "回复转发未完成") : (event.enforcement === "delivered" ? "Local socket write finished" : event.enforcement === "timeout" ? "Response transfer timed out" : "Response transfer incomplete")) : tx(enforcementMsg(event.enforcement))}
              </div>
            </dl>
          </details>
          {canMutate && event.ruleId && (!rule || !isProtectedRule(rule)) && onMarkFalsePositive ? (
            <button
              type="button"
              onClick={() => onMarkFalsePositive(event)}
              className="text-[11px] text-muted hover:text-warn underline-offset-2 hover:underline"
            >
              {tx("markFalsePositive")}
            </button>
          ) : null}
        </div>
      </div>
      <span className="hidden md:inline">
        <RiskBadge risk={event.risk} />
      </span>
      <span className="text-right">
        {event.decision === "block" && event.enforcement !== "blocked" ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-warn/25 bg-warn/10 px-2 py-0.5 font-mono text-[11px] font-medium text-warn">
            <span className="size-1.5 rounded-full bg-warn" />
            {tx("returnedDeny")}
          </span>
        ) : (
          <DecisionBadge decision={event.decision} />
        )}
      </span>
    </div>
  );
}
