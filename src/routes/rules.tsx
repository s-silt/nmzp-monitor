import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Lock, Shield, Trash2 } from "lucide-react";
import { DecisionBadge, RiskBadge } from "@/components/risk-badge";
import { Button } from "@/components/ui/button";
import { SUGGESTED_PRIVACY } from "@/lib/monitor/privacy";
import { ADMIN_HIDDEN } from "@/lib/monitor/map-event";
import { RULES } from "@/lib/monitor/rules";
import { useCanMutate, useFilteredEvents, useMonitor, useT } from "@/lib/monitor/store";
import type { Action, Risk } from "@/lib/monitor/types";
import { formatDateTime } from "@/lib/monitor/format";
import {
  CANONICAL_TOOL_NAMES,
  CUSTOM_RULE_FIELDS,
  THREAT_KINDS,
  customRuleState,
  type CustomRuleScope,
} from "@/lib/monitor/policy-schema";
import {
  PROTECTED_FAMILIES,
  composeAction,
  isProtectedRule,
} from "@/lib/monitor/overrides";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/rules")({ component: RulesPage });

const ALL_FAMILIES = [...THREAT_KINDS, "other"] as const;

export function RulesPage() {
  const tx = useT();
  const locale = useMonitor((s) => s.locale);
  const intervention = useMonitor((s) => s.intervention);
  const policyVersion = useMonitor((s) => s.policyVersion);
  const overrides = useMonitor((s) => s.overrides);
  const exemptions = useMonitor((s) => s.exemptions);
  const customRules = useMonitor((s) => s.customRules);
  const machines = useMonitor((s) => s.machines);
  const access = useMonitor((s) => s.access);
  const events = useFilteredEvents();

  const setRuleOverride = useMonitor((s) => s.setRuleOverride);
  const setFamilyOverride = useMonitor((s) => s.setFamilyOverride);
  const setCustomRuleState = useMonitor((s) => s.setCustomRuleState);
  const setCustomRuleScope = useMonitor((s) => s.setCustomRuleScope);
  const removeExemption = useMonitor((s) => s.removeExemption);
  const addPrivacyDraft = useMonitor((s) => s.addPrivacyDraft);
  const removePrivacyRule = useMonitor((s) => s.removePrivacyRule);
  const canMutate = useCanMutate();
  const viewer = access === "viewer";

  const [q, setQ] = useState("");
  const [risk, setRisk] = useState<Risk | "all">("all");
  const [draft, setDraft] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [expandedScopeRuleId, setExpandedScopeRuleId] = useState<string | null>(null);

  const onlineMachines = machines.filter((m) => m.status === "online");
  const syncedCount = onlineMachines.filter(
    (m) => ((m as unknown as { lastPolicyVersion?: number }).lastPolicyVersion ?? 0) >= policyVersion,
  ).length;
  const totalCount = onlineMachines.length;

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return RULES.filter((r) => (risk === "all" ? true : r.risk === risk)).filter((r) =>
      query
        ? `${r.id} ${r.title} ${r.titleEn} ${r.desc} ${r.descEn}`.toLowerCase().includes(query)
        : true,
    );
  }, [q, risk]);

  // Group rules by family
  const groupedRules = useMemo(() => {
    const map = new Map<string, typeof RULES>();
    for (const f of ALL_FAMILIES) map.set(f, []);
    for (const r of rows) {
      const f = r.family && THREAT_KINDS.includes(r.family as (typeof THREAT_KINDS)[number]) ? r.family : "other";
      map.get(f)!.push(r);
    }
    return map;
  }, [rows]);

  const missingSuggestions = SUGGESTED_PRIVACY.filter(
    (s) => !customRules.some((r) => r.match.toLowerCase() === s.match.toLowerCase()),
  );

  const handleToggleScopeTool = (ruleId: string, currentScope: CustomRuleScope | undefined, toolName: string) => {
    if (!canMutate) return;
    const currentTools = currentScope?.tools ?? [];
    const nextTools = currentTools.includes(toolName)
      ? currentTools.filter((t) => t !== toolName)
      : [...currentTools, toolName];
    void setCustomRuleScope(ruleId, {
      ...currentScope,
      tools: nextTools.length > 0 ? nextTools : undefined,
    });
  };

  const handleToggleScopeField = (
    ruleId: string,
    currentScope: CustomRuleScope | undefined,
    field: "command" | "file_path" | "url" | "contents",
  ) => {
    if (!canMutate) return;
    const currentFields = currentScope?.fields ?? [];
    const nextFields = currentFields.includes(field)
      ? currentFields.filter((f) => f !== field)
      : [...currentFields, field];
    void setCustomRuleScope(ruleId, {
      ...currentScope,
      fields: nextFields.length > 0 ? nextFields : undefined,
    });
  };

  return (
    <div className="flex flex-col gap-5">
      {/* 顶部常驻状态条 */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-surface px-4 py-2.5 font-mono text-xs shadow-[var(--shadow-border)]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-semibold text-fg">{tx("overrideOnlyEnforcing")}</span>
          <span className="text-subtle">·</span>
          <span className="text-muted">当前 {tx(intervention)}</span>
          <span className="text-subtle">·</span>
          <span className="rounded bg-elevated px-2 py-0.5 font-medium text-fg border border-line">
            策略 v{policyVersion}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-muted">
          <span className="size-1.5 rounded-full bg-ok" />
          <span>
            {tx("syncedHosts").replace("{n}", String(syncedCount)).replace("{m}", String(totalCount))}
          </span>
        </div>
      </div>

      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navRules")}</h1>
        <p className="mt-1 text-sm text-muted">
          {tx("enabledRules")} {RULES.length} · {tx("customRules")} {customRules.length}/64 · {tx("firstMatch")}
        </p>
      </div>

      {/* 自定义规则区 */}
      <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)] border border-line">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
          <h2 className="text-sm font-semibold text-fg">
            {tx("customRules")} ({customRules.length}/64)
          </h2>
          <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
            最多 64 条
          </span>
        </div>
        <p className="mt-2 max-w-prose text-xs text-muted">{tx("customRulesHint")}</p>
        {viewer ? <p className="mt-1 text-xs text-warn">{tx("viewerRulesHint")}</p> : null}

        {canMutate ? (
          <form
            className="mt-4 flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void addPrivacyDraft(draft).then((n) => {
                setNote(n > 0 ? `${tx("addedRules")} ${n}` : tx("noNewRules"));
                if (n > 0) setDraft("");
              });
            }}
          >
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value.slice(0, 800))}
              placeholder={`${tx("draftPlaceholder")}\nBash,url: db.prod.internal | block`}
              rows={3}
              spellCheck={false}
              className="w-full rounded-lg border border-line bg-elevated px-3 py-2 font-mono text-xs text-fg focus:outline-none focus:ring-1 focus:ring-fg/30"
              aria-label={tx("customRules")}
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" size="sm">
                {tx("addRules")}
              </Button>
              {note ? <span className="text-xs text-muted">{note}</span> : null}
            </div>
          </form>
        ) : null}

        {canMutate && missingSuggestions.length > 0 ? (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="text-xs text-subtle">{tx("suggested")}</span>
            {missingSuggestions.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() =>
                  addPrivacyDraft(
                    s.mode === "replace" ? `${s.match} => ${s.kind}` : `${s.match} | block | ${s.kind}`,
                  )
                }
                className="rounded bg-elevated px-2 py-1 font-mono text-xs text-muted border border-line hover:text-fg"
              >
                {s.kind}
              </button>
            ))}
          </div>
        ) : null}

        {customRules.length === 0 ? (
          <p className="mt-4 text-xs text-muted">{tx("emptyCustom")}</p>
        ) : (
          <ul className="mt-4 flex flex-col gap-2.5">
            {customRules.map((rule) => {
              const state = customRuleState(rule);
              const dryHits =
                state === "dry_run"
                  ? events.filter(
                      (e) => e.dryRunKinds?.includes(rule.kind) || e.dryRunKinds?.includes(rule.id),
                    ).length
                  : 0;
              const hasScope = Boolean(rule.scope?.tools?.length || rule.scope?.fields?.length);
              const isScopeOpen = expandedScopeRuleId === rule.id;

              return (
                <li
                  key={rule.id}
                  className="flex flex-col gap-2 rounded-lg border border-line bg-elevated/40 p-3.5"
                >
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="truncate font-mono text-sm font-medium text-fg">
                          {viewer ? ADMIN_HIDDEN : rule.match}
                        </p>
                        {state === "dry_run" ? (
                          <span className="rounded bg-warn/10 px-1.5 py-0.5 font-mono text-[10px] text-warn border border-warn/25">
                            {tx("dryRunHit")} {dryHits}
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-xs text-muted flex flex-wrap items-center gap-2">
                        <span>{rule.kind}</span>
                        <span>·</span>
                        <span>{rule.mode === "block" ? tx("modeBlock") : tx("modeReplace")}</span>
                        {rule.mode === "replace" ? (
                          <span>· {viewer ? ADMIN_HIDDEN : rule.replaceWith}</span>
                        ) : null}
                        {hasScope ? (
                          <span className="rounded bg-elevated px-1.5 py-0.2 font-mono text-[10px] text-subtle border border-line">
                            限定作用域
                          </span>
                        ) : null}
                      </p>
                    </div>

                    {/* 三态开关控件 */}
                    <div className="flex shrink-0 items-center gap-2">
                      <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
                        <button
                          type="button"
                          disabled={!canMutate}
                          onClick={() => void setCustomRuleState(rule.id, "on")}
                          className={cn(
                            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                            state === "on"
                              ? "bg-ok/15 text-ok font-semibold"
                              : "text-muted hover:text-fg",
                          )}
                        >
                          {tx("ruleStateOn")}
                        </button>
                        <button
                          type="button"
                          disabled={!canMutate}
                          onClick={() => void setCustomRuleState(rule.id, "dry_run")}
                          className={cn(
                            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                            state === "dry_run"
                              ? "bg-warn/15 text-warn font-semibold"
                              : "text-muted hover:text-fg",
                          )}
                        >
                          {tx("ruleStateDry")}
                        </button>
                        <button
                          type="button"
                          disabled={!canMutate}
                          onClick={() => void setCustomRuleState(rule.id, "off")}
                          className={cn(
                            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                            state === "off"
                              ? "bg-elevated text-subtle font-semibold"
                              : "text-muted hover:text-fg",
                          )}
                        >
                          {tx("ruleStateOff")}
                        </button>
                      </div>

                      {canMutate ? (
                        <>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              setExpandedScopeRuleId(isScopeOpen ? null : rule.id)
                            }
                            className="text-xs text-muted"
                          >
                            {isScopeOpen ? "收起作用域" : "作用域"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void removePrivacyRule(rule.id)}
                            className="text-xs text-muted hover:text-danger"
                          >
                            <Trash2 className="size-3.5" />
                          </Button>
                        </>
                      ) : null}
                    </div>
                  </div>

                  {/* 作用域展开编辑区 */}
                  {isScopeOpen ? (
                    <div className="mt-2 border-t border-line/60 pt-2.5 flex flex-col gap-2 text-xs">
                      <div>
                        <span className="font-medium text-subtle">{tx("scopeTools")}:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {CANONICAL_TOOL_NAMES.map((tName) => {
                            const active = rule.scope?.tools?.includes(tName);
                            return (
                              <button
                                key={tName}
                                type="button"
                                disabled={!canMutate}
                                onClick={() => handleToggleScopeTool(rule.id, rule.scope, tName)}
                                className={cn(
                                  "rounded px-2 py-0.5 font-mono text-[10px] border transition-colors",
                                  active
                                    ? "bg-fg text-bg border-fg font-medium"
                                    : "bg-surface text-muted border-line hover:text-fg",
                                )}
                              >
                                {tName}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                      <div>
                        <span className="font-medium text-subtle">{tx("scopeFields")}:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {CUSTOM_RULE_FIELDS.map((fName) => {
                            const active = rule.scope?.fields?.includes(fName);
                            return (
                              <button
                                key={fName}
                                type="button"
                                disabled={!canMutate}
                                onClick={() => handleToggleScopeField(rule.id, rule.scope, fName)}
                                className={cn(
                                  "rounded px-2 py-0.5 font-mono text-[10px] border transition-colors",
                                  active
                                    ? "bg-fg text-bg border-fg font-medium"
                                    : "bg-surface text-muted border-line hover:text-fg",
                                )}
                              >
                                {fName}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {/* 豁免列表区 */}
      <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)] border border-line">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
          <h2 className="text-sm font-semibold text-fg">
            {tx("exemptions")} ({exemptions.length}/32)
          </h2>
          <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
            最多 32 条
          </span>
        </div>
        {exemptions.length === 0 ? (
          <p className="mt-4 text-xs text-muted">暂无豁免条目。可在审计日志中对误报事件点击「这条是误报」添加豁免。</p>
        ) : (
          <ul className="mt-4 flex flex-col gap-2">
            {exemptions.map((ex) => {
              const isExpired = Boolean(ex.expiresAt && ex.expiresAt <= Date.now());
              return (
                <li
                  key={ex.id}
                  className={cn(
                    "flex flex-col gap-2 rounded-lg border border-line bg-elevated/40 p-3 sm:flex-row sm:items-center sm:justify-between",
                    isExpired && "opacity-60 bg-elevated/20",
                  )}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-fg">{ex.ruleId}</span>
                      <span className="font-mono text-xs text-muted truncate max-w-[200px]">
                        {viewer ? ADMIN_HIDDEN : ex.match}
                      </span>
                      {isExpired ? (
                        <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-muted border border-line">
                          {tx("exemptionExpired")}
                        </span>
                      ) : null}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted">
                      {ex.tools && ex.tools.length > 0 ? (
                        <span>工具: {ex.tools.join(" / ")}</span>
                      ) : (
                        <span>所有工具</span>
                      )}
                      {ex.note ? <span>· 备注: {ex.note}</span> : null}
                      {ex.expiresAt ? (
                        <span>· 到期: {formatDateTime(ex.expiresAt, locale)}</span>
                      ) : null}
                      {ex.sourceEventId ? <span>· 来源: {ex.sourceEventId}</span> : null}
                    </div>
                  </div>
                  {canMutate ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => void removeExemption(ex.id)}
                      className="text-xs text-muted hover:text-danger shrink-0"
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {/* 内置规则列表区 */}
      <div>
        <h2 className="text-sm font-semibold text-fg">{tx("builtinRules")}</h2>
      </div>
      <div className="grid gap-2 sm:grid-cols-[1fr_180px]">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={tx("search")}
          className="h-10 rounded-lg border border-line bg-surface px-3 text-xs shadow-[var(--shadow-border)] outline-none focus:ring-1 focus:ring-fg/30"
        />
        <select
          value={risk}
          onChange={(e) => setRisk(e.target.value as Risk | "all")}
          className="h-10 rounded-lg border border-line bg-surface px-3 text-xs shadow-[var(--shadow-border)]"
        >
          <option value="all">{tx("risk")}</option>
          <option value="high">{tx("high")}</option>
          <option value="medium">{tx("medium")}</option>
          <option value="low">{tx("low")}</option>
          <option value="info">{tx("info")}</option>
        </select>
      </div>

      {/* 按族分组渲染规则列表 */}
      <div className="flex flex-col gap-6">
        {ALL_FAMILIES.map((familyKey) => {
          const familyRules = groupedRules.get(familyKey) ?? [];
          if (familyRules.length === 0) return null;

          const isProtectedFamily = familyKey !== "other" && PROTECTED_FAMILIES.has(familyKey);
          const currentFamilyOverride =
            familyKey !== "other"
              ? (overrides.families[familyKey as (typeof THREAT_KINDS)[number]] ?? null)
              : null;

          return (
            <div
              key={familyKey}
              className="rounded-xl border border-line bg-surface/60 p-4 shadow-[var(--shadow-border)]"
            >
              {/* 族分组标题行 */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
                <div className="flex items-center gap-2">
                  <Shield className="size-4 text-muted" />
                  <h3 className="font-mono text-sm font-bold uppercase tracking-wide text-fg">
                    {familyKey === "other" ? "通用 / 其他规则" : familyKey}
                  </h3>
                  <span className="font-mono text-xs text-muted">({familyRules.length})</span>
                </div>

                {/* 族级三段控件 / 强制拦截 */}
                {familyKey !== "other" ? (
                  isProtectedFamily ? (
                    <div className="flex items-center gap-1.5 rounded-full bg-danger/10 px-2.5 py-1 text-xs font-medium text-danger border border-danger/20">
                      <Lock className="size-3" />
                      <span>{tx("overrideLocked")}（{tx("forceBlock")}）</span>
                    </div>
                  ) : (
                    <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
                      <button
                        type="button"
                        disabled={!canMutate}
                        onClick={() => void setFamilyOverride(familyKey, null)}
                        className={cn(
                          "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                          currentFamilyOverride === null
                            ? "bg-elevated text-fg font-semibold"
                            : "text-muted hover:text-fg",
                        )}
                      >
                        {tx("overrideDefault")}
                      </button>
                      <button
                        type="button"
                        disabled={!canMutate}
                        onClick={() => void setFamilyOverride(familyKey, "block")}
                        className={cn(
                          "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                          currentFamilyOverride === "block"
                            ? "bg-danger/15 text-danger font-semibold"
                            : "text-muted hover:text-fg",
                        )}
                      >
                        {tx("overrideBlock")}
                      </button>
                      <button
                        type="button"
                        disabled={!canMutate}
                        onClick={() => void setFamilyOverride(familyKey, "log")}
                        className={cn(
                          "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                          currentFamilyOverride === "log"
                            ? "bg-muted/20 text-fg font-semibold"
                            : "text-muted hover:text-fg",
                        )}
                      >
                        {tx("overrideLog")}
                      </button>
                    </div>
                  )
                ) : null}
              </div>

              {/* 族内单条规则行 */}
              <ul className="mt-3 flex flex-col gap-2.5">
                {familyRules.map((rule) => {
                  const protectedRule = isProtectedRule(rule);
                  const composed = composeAction(
                    { ruleId: rule.id, family: rule.family, action: rule.action },
                    overrides,
                  );
                  const currentRuleOverride = overrides.rules[rule.id] ?? null;

                  return (
                    <li
                      key={rule.id}
                      className="rounded-lg border border-line bg-elevated/40 p-3.5"
                    >
                      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="font-semibold text-fg">
                              {locale === "zh" ? rule.title : rule.titleEn}
                            </p>
                            <RiskBadge risk={rule.risk} />
                            {/* 有效动作徽章 */}
                            <div className="flex items-center gap-1.5">
                              {composed.action === "off" ? (
                                <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
                                  {tx("overrideOff")}
                                </span>
                              ) : (
                                <DecisionBadge decision={composed.action as Action} />
                              )}
                              {composed.source === "rule" ? (
                                <span className="rounded bg-info/10 px-1.5 py-0.2 font-mono text-[10px] text-info border border-info/20">
                                  {tx("overrideSourceRule")}
                                </span>
                              ) : composed.source === "family" ? (
                                <span className="rounded bg-info/10 px-1.5 py-0.2 font-mono text-[10px] text-info border border-info/20">
                                  {tx("overrideSourceFamily")}
                                </span>
                              ) : null}
                            </div>
                          </div>
                          <p className="mt-1 max-w-prose text-xs text-muted">
                            {locale === "zh" ? rule.desc : rule.descEn}
                          </p>
                          <p className="mt-2 font-mono text-[11px] text-subtle">
                            {rule.id} · {rule.tools.join(" / ")} · {rule.field}
                          </p>
                          <pre className="mt-1.5 overflow-x-auto font-mono text-[11px] text-muted bg-surface/80 rounded p-2 border border-line/60">
                            {rule.pattern}
                          </pre>
                        </div>

                        {/* 单条覆盖四段 / 两段控件 */}
                        <div className="flex shrink-0 items-center gap-2">
                          {protectedRule ? (
                            <div className="flex items-center gap-2">
                              <span className="flex items-center gap-1 rounded bg-danger/10 px-2 py-1 font-mono text-[11px] text-danger border border-danger/20">
                                <Lock className="size-3" />
                                <span>{tx("overrideLocked")}</span>
                              </span>
                              <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
                                <button
                                  type="button"
                                  disabled={!canMutate}
                                  onClick={() => void setRuleOverride(rule.id, null)}
                                  className={cn(
                                    "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                                    currentRuleOverride === null
                                      ? "bg-elevated text-fg font-semibold"
                                      : "text-muted hover:text-fg",
                                  )}
                                >
                                  {tx("overrideDefault")}
                                </button>
                                <button
                                  type="button"
                                  disabled={!canMutate}
                                  onClick={() => void setRuleOverride(rule.id, "block")}
                                  className={cn(
                                    "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                                    currentRuleOverride === "block"
                                      ? "bg-danger/15 text-danger font-semibold"
                                      : "text-muted hover:text-fg",
                                  )}
                                >
                                  {tx("overrideBlock")}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
                              <button
                                type="button"
                                disabled={!canMutate}
                                onClick={() => void setRuleOverride(rule.id, null)}
                                className={cn(
                                  "rounded px-2 py-1 text-xs font-medium transition-colors",
                                  currentRuleOverride === null
                                    ? "bg-elevated text-fg font-semibold"
                                    : "text-muted hover:text-fg",
                                )}
                              >
                                {tx("overrideDefault")}
                              </button>
                              <button
                                type="button"
                                disabled={!canMutate}
                                onClick={() => void setRuleOverride(rule.id, "block")}
                                className={cn(
                                  "rounded px-2 py-1 text-xs font-medium transition-colors",
                                  currentRuleOverride === "block"
                                    ? "bg-danger/15 text-danger font-semibold"
                                    : "text-muted hover:text-fg",
                                )}
                              >
                                {tx("overrideBlock")}
                              </button>
                              <button
                                type="button"
                                disabled={!canMutate}
                                onClick={() => void setRuleOverride(rule.id, "log")}
                                className={cn(
                                  "rounded px-2 py-1 text-xs font-medium transition-colors",
                                  currentRuleOverride === "log"
                                    ? "bg-muted/20 text-fg font-semibold"
                                    : "text-muted hover:text-fg",
                                )}
                              >
                                {tx("overrideLog")}
                              </button>
                              <button
                                type="button"
                                disabled={!canMutate}
                                onClick={() => void setRuleOverride(rule.id, "off")}
                                className={cn(
                                  "rounded px-2 py-1 text-xs font-medium transition-colors",
                                  currentRuleOverride === "off"
                                    ? "bg-elevated text-subtle font-semibold"
                                    : "text-muted hover:text-fg",
                                )}
                              >
                                {tx("overrideOff")}
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
    </div>
  );
}
