import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Archive,
  ArrowDown,
  CheckCircle2,
  Clock,
  Database,
  Download,
  FileCode,
  HardDrive,
  History as HistoryIcon,
  Info,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { AgentMark } from "@/components/agent-mark";
import { DecisionBadge, RiskBadge } from "@/components/risk-badge";
import { formatBytes, formatDateTime, truncate } from "@/lib/monitor/format";
import { useMonitor, useT } from "@/lib/monitor/store";
import {
  type AuditEventsQuery,
  type AuditExportDownloadResult,
  type AuditStorageStatus,
  type HistoricalPolicyDetail,
  type PolicyRevision,
  downloadAuditExportStream,
  fetchAuditEvents,
  fetchAuditStorage,
  fetchPolicyHistory,
  fetchPolicyRevisionDetail,
  restorePolicyRevision,
} from "@/lib/monitor/api";
import type { AuditEvent, Decision, Risk } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/history")({ component: HistoryPage });

type TabId = "storage" | "events" | "export" | "policy";

export function HistoryPage() {
  const tx = useT();
  const access = useMonitor((s) => s.access);
  const locale = useMonitor((s) => s.locale);
  const currentPolicyVersion = useMonitor((s) => s.policyVersion);

  const [activeTab, setActiveTab] = useState<TabId>("storage");
  const [storageNotEnabled, setStorageNotEnabled] = useState(false);

  // Storage tab state
  const [storageStatus, setStorageStatus] = useState<AuditStorageStatus | null>(null);
  const [loadingStorage, setLoadingStorage] = useState(false);
  const [storageError, setStorageError] = useState<string | null>(null);

  // Events tab state
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [highWatermark, setHighWatermark] = useState<number | undefined>(undefined);
  const [nextBeforeSeq, setNextBeforeSeq] = useState<number | null>(null);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);

  // Filter states for Events & Export
  const [filterMachineId, setFilterMachineId] = useState("");
  const [filterAgent, setFilterAgent] = useState("");
  const [filterDecision, setFilterDecision] = useState<Decision | "all">("all");
  const [filterRisk, setFilterRisk] = useState<Risk | "all">("all");
  const [filterRuleId, setFilterRuleId] = useState("");
  const [filterFromTs, setFilterFromTs] = useState("");
  const [filterToTs, setFilterToTs] = useState("");

  const eventsAbortRef = useRef<AbortController | null>(null);

  // Export tab state
  const [exportFormat, setExportFormat] = useState<"json" | "jsonl">("json");
  const [exportGzip, setExportGzip] = useState(false);
  const [exportProgress, setExportProgress] = useState<{
    status: "idle" | "downloading" | "completed" | "error" | "cancelled";
    bytesRead: number;
    complete?: boolean;
    error?: string;
  }>({ status: "idle", bytesRead: 0 });
  const exportAbortRef = useRef<AbortController | null>(null);

  // Policy tab state
  const [policyRevisions, setPolicyRevisions] = useState<PolicyRevision[]>([]);
  const [nextBeforeVersion, setNextBeforeVersion] = useState<number | null>(null);
  const [loadingPolicy, setLoadingPolicy] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<HistoricalPolicyDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [restoreTarget, setRestoreTarget] = useState<(PolicyRevision & { expectedVersion: number }) | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [casConflictNotice, setCasConflictNotice] = useState<{ currentVersion: number } | null>(null);

  const storageAbortRef = useRef<AbortController | null>(null);
  const policyAbortRef = useRef<AbortController | null>(null);
  const detailAbortRef = useRef<AbortController | null>(null);
  const loadedTabs = useRef(new Set<TabId>());
  const eventFilters = useMemo<AuditEventsQuery>(() => ({
    limit: 20,
    machineId: filterMachineId.trim() || undefined,
    agent: filterAgent.trim() || undefined,
    decision: filterDecision !== "all" ? filterDecision : undefined,
    risk: filterRisk !== "all" ? filterRisk : undefined,
    ruleId: filterRuleId.trim() || undefined,
    fromTs: filterFromTs ? new Date(filterFromTs).getTime() : undefined,
    toTs: filterToTs ? new Date(filterToTs).getTime() : undefined,
  }), [filterMachineId, filterAgent, filterDecision, filterRisk, filterRuleId, filterFromTs, filterToTs]);

  useEffect(() => {
    eventsAbortRef.current?.abort();
    setEvents([]);
    setHighWatermark(undefined);
    setNextBeforeSeq(null);
    setLoadingEvents(false);
    loadedTabs.current.delete("events");
  }, [eventFilters]);

  useEffect(() => {
    loadedTabs.current.clear();
    setSelectedDetail(null);
    setRestoreTarget(null);
    return () => {
      for (const ref of [eventsAbortRef, storageAbortRef, policyAbortRef, detailAbortRef, exportAbortRef]) ref.current?.abort();
    };
  }, [access]);

  // Load storage status
  const loadStorage = useCallback(async () => {
    if (access !== "admin") return;
    storageAbortRef.current?.abort();
    const controller = new AbortController();
    storageAbortRef.current = controller;
    setLoadingStorage(true);
    setStorageError(null);
    try {
      const res = await fetchAuditStorage(controller.signal);
      if (controller.signal.aborted) return;
      if (!res.ok) {
        if (res.status === 404 && res.error === "storage_not_enabled") {
          setStorageNotEnabled(true);
        } else if (res.status === 401 || res.status === 403) {
          setStorageError(tx("historyViewerRestricted"));
        } else {
          setStorageError(res.error);
        }
      } else {
        setStorageStatus(res.data);
      }
    } catch {
      if (!controller.signal.aborted) setStorageError("网络请求失败");
    } finally {
      if (!controller.signal.aborted) setLoadingStorage(false);
    }
  }, [access, tx]);

  // Load first page of events (resets cursor)
  const loadEventsFirstPage = useCallback(async () => {
    if (access !== "admin") return;
    eventsAbortRef.current?.abort();
    const controller = new AbortController();
    eventsAbortRef.current = controller;

    setLoadingEvents(true);
    setEventsError(null);

    const query = eventFilters;

    try {
      const res = await fetchAuditEvents(query, controller.signal);
      if (controller.signal.aborted) return;
      if (!res.ok) {
        if (res.status === 404 && res.error === "storage_not_enabled") {
          setStorageNotEnabled(true);
        } else if (res.status === 401 || res.status === 403) {
          setEventsError(tx("historyViewerRestricted"));
        } else if (res.status === 400) {
          setEventsError("筛选参数错误 (400 audit_query_invalid)");
        } else if (res.status === 413) {
          setEventsError("页面数据过大 (413)，请缩小筛选范围");
        } else {
          setEventsError(res.error);
        }
      } else {
        setEvents(res.data.events);
        setHighWatermark(res.data.highWatermark);
        setNextBeforeSeq(res.data.nextBeforeSeq);
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      setEventsError("网络请求失败");
    } finally {
      if (!controller.signal.aborted) setLoadingEvents(false);
    }
  }, [access, eventFilters, tx]);

  // Load next page of events
  const loadEventsNextPage = useCallback(async () => {
    if (access !== "admin" || nextBeforeSeq === null || loadingEvents) return;
    eventsAbortRef.current?.abort();
    const controller = new AbortController();
    eventsAbortRef.current = controller;

    setLoadingEvents(true);
    const query = { ...eventFilters, highWatermark, beforeSeq: nextBeforeSeq };

    try {
      const res = await fetchAuditEvents(query, controller.signal);
      if (controller.signal.aborted) return;
      if (!res.ok) {
        setEventsError(res.error);
      } else {
        setEvents(res.data.events);
        setNextBeforeSeq(res.data.nextBeforeSeq);
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      setEventsError("网络请求失败");
    } finally {
      if (!controller.signal.aborted) setLoadingEvents(false);
    }
  }, [access, eventFilters, highWatermark, loadingEvents, nextBeforeSeq]);

  // Load policy history
  const loadPolicyRevisions = useCallback(async (before?: number) => {
    if (access !== "admin") return;
    policyAbortRef.current?.abort();
    const controller = new AbortController();
    policyAbortRef.current = controller;
    setLoadingPolicy(true);
    setPolicyError(null);
    try {
      const res = await fetchPolicyHistory({ limit: 50, beforeVersion: before }, controller.signal);
      if (controller.signal.aborted) return;
      if (!res.ok) {
        if (res.status === 404 && res.error === "storage_not_enabled") {
          setStorageNotEnabled(true);
        } else if (res.status === 401 || res.status === 403) {
          setPolicyError(tx("historyViewerRestricted"));
        } else {
          setPolicyError(res.error);
        }
      } else {
        setPolicyRevisions(res.data.revisions);
        setNextBeforeVersion(res.data.nextBeforeVersion);
      }
    } catch {
      if (!controller.signal.aborted) setPolicyError("网络请求失败");
    } finally {
      if (!controller.signal.aborted) setLoadingPolicy(false);
    }
  }, [access, tx]);

  // One initial attempt per tab/filter set. Empty/error responses never start a retry loop.
  useEffect(() => {
    if (access !== "admin" || storageNotEnabled || loadedTabs.current.has(activeTab)) return;
    loadedTabs.current.add(activeTab);
    if (activeTab === "storage") void loadStorage();
    else if (activeTab === "events") void loadEventsFirstPage();
    else if (activeTab === "policy") void loadPolicyRevisions();
  }, [access, activeTab, eventFilters, storageNotEnabled, loadStorage, loadEventsFirstPage, loadPolicyRevisions]);

  // Handle Export Stream
  const handleStartExport = async () => {
    if (access !== "admin") return;
    exportAbortRef.current?.abort();
    const controller = new AbortController();
    exportAbortRef.current = controller;

    setExportProgress({ status: "downloading", bytesRead: 0 });

    const result: AuditExportDownloadResult = await downloadAuditExportStream({
      format: exportFormat,
      gzip: exportGzip,
      machineId: filterMachineId.trim() || undefined,
      agent: filterAgent.trim() || undefined,
      decision: filterDecision !== "all" ? filterDecision : undefined,
      risk: filterRisk !== "all" ? filterRisk : undefined,
      ruleId: filterRuleId.trim() || undefined,
      fromTs: filterFromTs ? new Date(filterFromTs).getTime() : undefined,
      toTs: filterToTs ? new Date(filterToTs).getTime() : undefined,
      signal: controller.signal,
      onProgress: (p) => {
        if (exportAbortRef.current !== controller) return;
        setExportProgress((prev) => ({
          ...prev,
          status: p.status,
          bytesRead: p.bytesRead,
        }));
      },
    });

    if (exportAbortRef.current !== controller) return;
    if (result.ok) {
      if (result.complete === false) {
        toast.warning(tx("exportStreamIncomplete"), {
          description: `已导出 ${result.exportedCount ?? 0} 条事件，但导出期间发生了清理删除（${result.deletionsDuringExport ?? 0} 条）。`,
        });
        setExportProgress({
          status: "completed",
          bytesRead: result.totalBytes,
          complete: false,
        });
      } else {
        toast.success(tx("exportStreamComplete"), {
          description: `成功下载 ${result.exportedCount ?? 0} 条事件 (${formatBytes(result.totalBytes)})`,
        });
        setExportProgress({
          status: "completed",
          bytesRead: result.totalBytes,
          complete: true,
        });
      }
    } else {
      if (result.error === "cancelled") {
        toast.info("已取消下载");
        setExportProgress({ status: "cancelled", bytesRead: result.totalBytes });
      } else if (result.status === 404 && result.error === "storage_not_enabled") {
        setStorageNotEnabled(true);
      } else {
        toast.error(`导出失败: ${result.error ?? "未知错误"}`);
        setExportProgress({
          status: "error",
          bytesRead: result.totalBytes,
          error: result.error,
        });
      }
    }
  };

  const handleCancelExport = () => {
    exportAbortRef.current?.abort();
  };

  // Inspect revision detail in memory
  const handleInspectRevision = async (version: number) => {
    if (access !== "admin") return;
    detailAbortRef.current?.abort();
    const controller = new AbortController();
    detailAbortRef.current = controller;
    setLoadingDetail(true);
    try {
      const res = await fetchPolicyRevisionDetail(version, controller.signal);
      if (controller.signal.aborted) return;
      if (res.ok) {
        setSelectedDetail(res.data);
      } else {
        toast.error(`无法获取策略版本 ${version} 详情: ${res.error}`);
      }
    } catch {
      if (!controller.signal.aborted) toast.error("网络请求失败");
    } finally {
      if (!controller.signal.aborted) setLoadingDetail(false);
    }
  };

  // CAS Restore
  const handleConfirmRestore = async () => {
    if (!restoreTarget || restoring || access !== "admin") return;
    setRestoring(true);
    setCasConflictNotice(null);
    try {
      const res = await restorePolicyRevision({
        expectedVersion: restoreTarget.expectedVersion,
        sourceVersion: restoreTarget.version,
      });

      if (res.ok) {
        toast.success(`策略已成功恢复为新版本 ${res.version}！`, {
          description: tx("policyRestoreNewVersionNote"),
        });
        setRestoreTarget(null);
        await useMonitor.getState().syncFromServer();
        void loadPolicyRevisions();
      } else {
        if (res.status === 409 && res.error === "cas_conflict") {
          toast.error(tx("casConflictTitle"), {
            description: tx("casConflictDesc"),
          });
          setCasConflictNotice({ currentVersion: res.version ?? currentPolicyVersion });
          setRestoreTarget(null);
          await useMonitor.getState().syncFromServer();
          void loadPolicyRevisions();
        } else if (res.status === 503) {
          toast.error("核心拒绝恢复 (503 policy_recovery_required)", {
            description: "核心处于恢复保护状态，已停止自动重试。",
          });
        } else {
          toast.error(`恢复失败: ${res.error ?? "未知原因"}`);
        }
      }
    } catch {
      toast.error("网络请求失败");
    } finally {
      setRestoring(false);
    }
  };

  // 1. Viewer Role Guard
  if (access === "viewer") {
    return (
      <div className="flex flex-col gap-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navHistory")}</h1>
          <p className="mt-1 text-xs text-muted">SQLite 持久化历史审计、大导出与策略版本库</p>
        </div>
        <div className="rounded-xl border border-line bg-surface p-8 text-center shadow-[var(--shadow-border)]">
          <ShieldAlert className="mx-auto size-10 text-warn" />
          <h2 className="mt-4 text-base font-semibold text-fg">权限不足 (仅管理员可用)</h2>
          <p className="mx-auto mt-2 max-w-lg text-xs leading-relaxed text-muted">
            {tx("historyViewerRestricted")}
          </p>
        </div>
      </div>
    );
  }

  // 2. Storage Not Enabled Guard (404 storage_not_enabled)
  if (storageNotEnabled) {
    return (
      <div className="flex flex-col gap-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navHistory")}</h1>
          <p className="mt-1 text-xs text-muted">SQLite 持久化历史审计、大导出与策略版本库</p>
        </div>
        <div className="rounded-xl border border-line bg-surface p-8 text-center shadow-[var(--shadow-border)]">
          <Database className="mx-auto size-12 text-muted" />
          <h2 className="mt-4 text-lg font-semibold text-fg">{tx("storageNotEnabled")}</h2>
          <p className="mx-auto mt-2 max-w-xl text-xs leading-relaxed text-muted">
            {tx("storageNotEnabledDesc")}
          </p>
          <div className="mx-auto mt-6 max-w-md rounded-lg bg-elevated p-3 text-left font-mono text-xs text-muted border border-line">
            <div className="text-fg font-medium mb-1">启动命令参考:</div>
            <div>由管理员先备份并完成 storage preflight / migrate，再选择 sqlite 模式。</div>
          </div>
          <p className="mt-4 text-[11px] text-subtle">
            提示：当前系统仍保持原有的 2,000 条近期事件窗口运作，无需在浏览器端安装任何数据库。
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{tx("navHistory")}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-[11px] text-fg border border-line">
              SQLite 存储
            </span>
            <span className="text-subtle">历史完整性: unknown</span>
            <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-subtle border border-line">
              {tx("utc8")}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {activeTab === "storage" && (
            <Button size="sm" variant="outline" onClick={() => void loadStorage()} disabled={loadingStorage} className="gap-1.5 text-xs">
              <RefreshCw className={cn("size-3.5", loadingStorage && "animate-spin")} />
              <span>刷新状态</span>
            </Button>
          )}
          {activeTab === "events" && (
            <Button size="sm" variant="outline" onClick={() => void loadEventsFirstPage()} disabled={loadingEvents} className="gap-1.5 text-xs">
              <RefreshCw className={cn("size-3.5", loadingEvents && "animate-spin")} />
              <span>重新查询</span>
            </Button>
          )}
          {activeTab === "policy" && (
            <Button size="sm" variant="outline" onClick={() => void loadPolicyRevisions()} disabled={loadingPolicy} className="gap-1.5 text-xs">
              <RefreshCw className={cn("size-3.5", loadingPolicy && "animate-spin")} />
              <span>刷新版本</span>
            </Button>
          )}
        </div>
      </div>

      {/* Tabs Switcher */}
      <div className="flex items-center gap-2 border-b border-line pb-1 overflow-x-auto">
        {[
          { id: "storage", label: "存储与待传概览", icon: HardDrive },
          { id: "events", label: "历史审计检索", icon: Clock },
          { id: "export", label: "压缩大导出", icon: Download },
          { id: "policy", label: "策略版本与恢复", icon: HistoryIcon },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as TabId)}
              className={cn(
                "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all shrink-0",
                active
                  ? "bg-elevated text-fg font-semibold shadow-[var(--shadow-border)]"
                  : "text-muted hover:text-fg hover:bg-surface",
              )}
            >
              <Icon className="size-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: Storage & Device Outbox Status */}
      {activeTab === "storage" && (
        <div className="flex flex-col gap-4">
          {storageError && (
            <div className="rounded-lg bg-danger/10 border border-danger/30 p-3 text-xs text-danger flex items-center gap-2">
              <AlertCircle className="size-4 shrink-0" />
              <span>{storageError}</span>
            </div>
          )}

          {/* SQLite Retention Metrics */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
              <div className="text-xs font-medium text-muted">保留历史条数 (retained)</div>
              <div className="mt-2 text-2xl font-semibold font-mono text-fg">
                {storageStatus ? storageStatus.retained.toLocaleString() : "—"}
              </div>
              <div className="mt-1 text-[11px] text-subtle">
                墓碑记录: {storageStatus?.tombstones ?? "—"}
              </div>
            </div>

            <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
              <div className="text-xs font-medium text-muted">累计清理计数 (deleted)</div>
              <div className="mt-2 text-2xl font-semibold font-mono text-fg">
                {storageStatus ? storageStatus.deleted.toLocaleString() : "—"}
              </div>
              <div className="mt-1 text-[11px] text-subtle" title={tx("deletedCountHint")}>
                累计清理计数；迁移前缺失数据始终未知
              </div>
            </div>

            <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
              <div className="text-xs font-medium text-muted">数据库占用 (dbBytes)</div>
              <div className="mt-2 text-2xl font-semibold font-mono text-fg">
                {storageStatus ? formatBytes(storageStatus.dbBytes) : "—"}
              </div>
              <div className="mt-1 text-[11px] text-subtle" title={tx("reusableBytesHint")}>
                内部可复用: {storageStatus ? formatBytes(storageStatus.reusableBytes) : "—"} (非磁盘释放)
              </div>
            </div>

            <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
              <div className="text-xs font-medium text-muted">清理状态 (retentionPending)</div>
              <div className="mt-2 flex items-center gap-2">
                {storageStatus && storageStatus.retentionPending > 0 ? (
                  <span className="rounded-full bg-warn/15 px-2.5 py-0.5 font-mono text-xs font-semibold text-warn border border-warn/30">
                    清理中 ({storageStatus.retentionPending})
                  </span>
                ) : (
                  <span className="rounded-full bg-ok/15 px-2.5 py-0.5 font-mono text-xs font-semibold text-ok border border-ok/30">
                    {storageStatus ? "暂无待清理记录" : "尚未获取状态"}
                  </span>
                )}
              </div>
              <div className="mt-1 text-[11px] text-subtle">
                {storageStatus && storageStatus.retentionPending > 0
                  ? tx("retentionPendingNotice")
                  : storageStatus ? "当前没有待清理记录" : "等待存储状态"}
              </div>
            </div>
          </div>

          {/* Retention Limits & Physical Shrink Notice */}
          <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
            <h3 className="text-sm font-semibold text-fg flex items-center gap-2">
              <Info className="size-4 text-info" />
              <span>存储配额与自动清理约束</span>
            </h3>
            <p className="mt-1 text-xs text-muted leading-relaxed">
              {tx("storageLimitsNote")}
            </p>
            {storageStatus?.limits && (
              <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 font-mono text-xs">
                <div className="rounded bg-elevated p-2 border border-line">
                  <span className="text-muted block text-[10px]">条数上限 (maxRecords):</span>
                  <span className="font-semibold text-fg">{storageStatus.limits.maxRecords.toLocaleString()} 条</span>
                </div>
                <div className="rounded bg-elevated p-2 border border-line">
                  <span className="text-muted block text-[10px]">时间上限 (maxAgeMs):</span>
                  <span className="font-semibold text-fg">
                    {(storageStatus.limits.maxAgeMs / (24 * 3600 * 1000)).toFixed(0)} 天
                  </span>
                </div>
                <div className="rounded bg-elevated p-2 border border-line">
                  <span className="text-muted block text-[10px]">体积上限 (maxDbBytes):</span>
                  <span className="font-semibold text-fg">{formatBytes(storageStatus.limits.maxDbBytes)}</span>
                </div>
                <div className="rounded bg-elevated p-2 border border-line">
                  <span className="text-muted block text-[10px]">最低剩余空间 (minFreeBytes):</span>
                  <span className="font-semibold text-fg">{formatBytes(storageStatus.limits.minFreeBytes)}</span>
                </div>
              </div>
            )}
            <div className="mt-3 flex items-center gap-2 text-xs text-subtle font-mono">
              <span>物理收缩状态:</span>
              <span className={cn(
                "px-1.5 py-0.2 rounded font-medium",
                storageStatus?.physicalShrink === "manual_vacuum_required"
                  ? "bg-warn/10 text-warn border border-warn/25"
                  : "bg-elevated text-fg"
              )}>
                {storageStatus?.physicalShrink === "manual_vacuum_required" ? "需手动执行 VACUUM 收缩" : storageStatus ? "无需收缩" : "未知"}
              </span>
            </div>
          </div>

          {/* Device Outbox Status Card */}
          <div className="rounded-xl bg-surface p-4 border border-line shadow-[var(--shadow-border)]">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-fg flex items-center gap-2">
                <Archive className="size-4 text-muted" />
                <span>设备本地待传队列状态</span>
              </h3>
              <span className="rounded-full bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted border border-line">
                {tx("deviceOutboxNotCollected")}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted leading-relaxed">
              {tx("deviceOutboxHint")}
            </p>
            <div className="mt-3 rounded bg-elevated p-2.5 font-mono text-xs text-fg border border-line">
              nmzp audit outbox-status --home &lt;绝对路径&gt;
            </div>
            <p className="mt-2 text-[11px] text-subtle">
              前端界面严格不依据核心已有事件数猜测或虚构设备待传队列数。
            </p>
          </div>
        </div>
      )}

      {/* TAB 2: Historical Events Query */}
      {activeTab === "events" && (
        <div className="flex flex-col gap-4">
          {/* Filters Bar */}
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 rounded-xl bg-surface p-3 border border-line shadow-[var(--shadow-border)]">
            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">设备 (machineId)</label>
              <input
                value={filterMachineId}
                onChange={(e) => setFilterMachineId(e.target.value)}
                placeholder="全部设备 或 输入 ID"
                className="h-8 w-full rounded-md bg-elevated px-2.5 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">Agent</label>
              <input
                value={filterAgent}
                onChange={(e) => setFilterAgent(e.target.value)}
                placeholder="全部 Agent (如 grok, codex)"
                className="h-8 w-full rounded-md bg-elevated px-2.5 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">风险等级</label>
              <select
                value={filterRisk}
                onChange={(e) => setFilterRisk(e.target.value as Risk | "all")}
                className="h-8 w-full rounded-md bg-elevated px-2 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              >
                <option value="all">全部风险</option>
                <option value="high">高危 (high)</option>
                <option value="medium">中危 (medium)</option>
                <option value="low">低危 (low)</option>
                <option value="info">提示 (info)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">处置决策</label>
              <select
                value={filterDecision}
                onChange={(e) => setFilterDecision(e.target.value as Decision | "all")}
                className="h-8 w-full rounded-md bg-elevated px-2 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              >
                <option value="all">全部处置</option>
                <option value="block">拦截 (block)</option>
                <option value="rewrite">改写 (rewrite)</option>
                <option value="allow">允许 (allow)</option>
                <option value="log">记录 (log)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">规则 ID (ruleId)</label>
              <input
                value={filterRuleId}
                onChange={(e) => setFilterRuleId(e.target.value)}
                placeholder="如 rule-sample"
                className="h-8 w-full rounded-md bg-elevated px-2.5 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">起始时间</label>
              <input
                type="datetime-local"
                value={filterFromTs}
                onChange={(e) => setFilterFromTs(e.target.value)}
                className="h-8 w-full rounded-md bg-elevated px-2 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-muted mb-1">截止时间</label>
              <input
                type="datetime-local"
                value={filterToTs}
                onChange={(e) => setFilterToTs(e.target.value)}
                className="h-8 w-full rounded-md bg-elevated px-2 text-xs text-fg shadow-[var(--shadow-border)] outline-none"
              />
            </div>

            <div className="flex items-end gap-2">
              <Button size="sm" onClick={() => void loadEventsFirstPage()} className="w-full text-xs">
                <Search className="size-3.5 mr-1" />
                应用筛选
              </Button>
              {(filterMachineId || filterAgent || filterDecision !== "all" || filterRisk !== "all" || filterRuleId || filterFromTs || filterToTs) && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setFilterMachineId("");
                    setFilterAgent("");
                    setFilterDecision("all");
                    setFilterRisk("all");
                    setFilterRuleId("");
                    setFilterFromTs("");
                    setFilterToTs("");
                  }}
                  className="text-xs"
                >
                  <X className="size-3.5" />
                </Button>
              )}
            </div>
          </div>

          {eventsError && (
            <div className="rounded-lg bg-danger/10 border border-danger/30 p-3 text-xs text-danger flex items-center gap-2">
              <AlertCircle className="size-4 shrink-0" />
              <span>{eventsError}</span>
            </div>
          )}

          {/* Events List */}
          <div className="rounded-xl bg-surface p-3 border border-line shadow-[var(--shadow-border)]">
            <div className="mb-2 flex items-center justify-between text-xs text-muted border-b border-line pb-2 px-1">
              <span>
                本页显示: <span className="font-mono text-fg font-semibold">{events.length}</span> 条
                {highWatermark !== undefined ? ` · 本轮高水位 Seq: ${highWatermark}` : ""}
              </span>
              <span className="text-[11px] text-subtle">
                每页上限 25 条 · 序号非连续不推断完整性
              </span>
            </div>

            {events.length === 0 ? (
              <div className="py-12 text-center text-xs text-muted">
                {loadingEvents ? "正在加载历史审计…" : "未查询到符合条件的历史事件"}
              </div>
            ) : (
              <div className="flex flex-col divide-y divide-line">
                {events.map((evt) => {
                  const isUnknownAgent = evt.agent === "unknown";
                  return (
                    <div key={evt.id} className="py-2.5 px-1 flex flex-col gap-1.5 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-muted tabular-nums">
                            {formatDateTime(evt.ts, locale)}
                          </span>
                          {/* Agent rendering */}
                          {isUnknownAgent ? (
                            <span className="inline-flex items-center gap-1 font-medium text-warn bg-warn/10 px-1.5 py-0.5 rounded border border-warn/25">
                              <span>未知 Agent</span>
                              {evt.rawAgent && <span className="text-[10px] text-muted">({evt.rawAgent})</span>}
                            </span>
                          ) : (
                            <AgentMark id={evt.agent} showName={true} />
                          )}
                          <span className="font-mono text-[11px] text-muted">
                            [{evt.machineId || "unknown-pc"}]
                          </span>
                          {evt.policyVersion !== undefined && (
                            <span className="rounded bg-elevated px-1 py-0.2 font-mono text-[10px] text-subtle border border-line">
                              v{evt.policyVersion}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-1.5">
                          <RiskBadge risk={evt.risk} />
                          <DecisionBadge decision={evt.decision} />
                          {evt.enforcement === "offline" && (
                            <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-muted border border-line" title={tx("offlineBackfillNotice")}>
                              离线回传
                            </span>
                          )}
                          {evt.enforcement === "blocked" && (
                            <span className="rounded bg-danger/10 px-1.5 py-0.5 font-mono text-[10px] text-danger border border-danger/25">
                              宿主已阻断
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-baseline gap-2 font-mono text-xs text-fg break-all">
                        <span className="text-muted font-medium">[{evt.tool || evt.nativeTool || "Tool"}]:</span>
                        <span>{truncate(evt.redacted || evt.input || "—", 120)}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Pagination Controls */}
            <div className="mt-3 border-t border-line pt-3 flex items-center justify-between">
              <span className="text-xs text-muted font-mono">
                {nextBeforeSeq === null ? "已到最末页 (nextBeforeSeq: null)" : `游标 nextBeforeSeq: ${nextBeforeSeq}`}
              </span>
              {nextBeforeSeq !== null && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void loadEventsNextPage()}
                  disabled={loadingEvents}
                  className="text-xs gap-1"
                >
                  <ArrowDown className="size-3.5" />
                  <span>{loadingEvents ? "加载中…" : "加载下一页"}</span>
                </Button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Streamed Large Export */}
      {activeTab === "export" && (
        <div className="flex flex-col gap-4 max-w-3xl">
          <div className="rounded-xl bg-surface p-5 border border-line shadow-[var(--shadow-border)] flex flex-col gap-4">
            <div>
              <h3 className="text-base font-semibold text-fg flex items-center gap-2">
                <Download className="size-4 text-fg" />
                <span>管理员历史数据流式大导出</span>
              </h3>
              <p className="mt-1 text-xs text-muted leading-relaxed">
                服务端流式切片输出；浏览器通过 AbortController 响应流直接下载，不占用页面 React 状态内存。
                导出继承当前的设备、Agent、时间与风险筛选参数。
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-medium text-fg mb-1">导出格式</label>
                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-1.5 text-xs text-fg cursor-pointer">
                    <input
                      type="radio"
                      name="format"
                      checked={exportFormat === "json"}
                      onChange={() => setExportFormat("json")}
                    />
                    <span>普通 JSON (.json)</span>
                  </label>
                  <label className="flex items-center gap-1.5 text-xs text-fg cursor-pointer ml-4">
                    <input
                      type="radio"
                      name="format"
                      checked={exportFormat === "jsonl"}
                      onChange={() => setExportFormat("jsonl")}
                    />
                    <span>按行 JSONL (.jsonl)</span>
                  </label>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-fg mb-1">压缩设置</label>
                <label className="flex items-center gap-2 text-xs text-fg cursor-pointer mt-1">
                  <input
                    type="checkbox"
                    checked={exportGzip}
                    onChange={(e) => setExportGzip(e.target.checked)}
                    className="rounded"
                  />
                  <span>启用 Gzip 压缩 (gzip=1)</span>
                </label>
              </div>
            </div>

            <div className="rounded-lg bg-elevated p-3 border border-line text-xs text-muted flex flex-col gap-1">
              <div className="font-medium text-fg flex items-center gap-1.5">
                <Info className="size-3.5 text-info" />
                <span>完整性提示</span>
              </div>
              <p>
                中途断网或缺少末尾 summary/complete 将标记为不完整下载；若导出期间发生了清理删除，complete 将置为 false。
                即便 complete 为 true，由于迁移前历史未知，整体完整性仍记录为 unknown。
              </p>
            </div>

            <div className="flex items-center gap-3 pt-2">
              {exportProgress.status === "downloading" ? (
                <Button variant="outline" onClick={handleCancelExport} className="gap-1.5 text-danger border-danger/30">
                  <X className="size-4" />
                  <span>{tx("cancelExport")}</span>
                </Button>
              ) : (
                <Button onClick={() => void handleStartExport()} className="gap-1.5">
                  <Download className="size-4" />
                  <span>开始流式下载</span>
                </Button>
              )}

              {exportProgress.status === "downloading" && (
                <div className="flex items-center gap-2 text-xs font-mono text-fg">
                  <RefreshCw className="size-3.5 animate-spin text-info" />
                  <span>已接收: {formatBytes(exportProgress.bytesRead)}</span>
                </div>
              )}

              {exportProgress.status === "completed" && (
                <div className="flex items-center gap-1.5 text-xs font-medium text-ok">
                  <CheckCircle2 className="size-4" />
                  <span>下载已完成 ({formatBytes(exportProgress.bytesRead)})</span>
                </div>
              )}

              {exportProgress.status === "error" && (
                <div className="flex items-center gap-1.5 text-xs font-medium text-danger">
                  <AlertCircle className="size-4" />
                  <span>导出错误: {exportProgress.error}</span>
                </div>
              )}

              {exportProgress.status === "cancelled" && (
                <span className="text-xs text-muted">下载已取消</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Policy Revisions History & CAS Restore */}
      {activeTab === "policy" && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-fg">策略历史版本库</h3>
              <p className="text-xs text-muted">
                当前核心策略版本: <span className="font-mono font-semibold text-fg">v{currentPolicyVersion}</span>。恢复旧版本将发布递增的新版本，绝不回退版本数字。
              </p>
            </div>
          </div>

          {policyError && (
            <div className="rounded-lg bg-danger/10 border border-danger/30 p-3 text-xs text-danger flex items-center gap-2">
              <AlertCircle className="size-4 shrink-0" />
              <span>{policyError}</span>
            </div>
          )}

          {casConflictNotice && (
            <div className="rounded-lg bg-warn/10 border border-warn/30 p-3 text-xs text-warn flex flex-col gap-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertTriangle className="size-4" />
                <span>{tx("casConflictTitle")}</span>
              </div>
              <p>{tx("casConflictDesc")}</p>
            </div>
          )}

          {/* Revisions Table */}
          <div className="rounded-xl bg-surface border border-line shadow-[var(--shadow-border)] overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-elevated border-b border-line text-muted font-medium">
                <tr>
                  <th className="py-2.5 px-3">版本号</th>
                  <th className="py-2.5 px-3">发布时间 (UTC+8)</th>
                  <th className="py-2.5 px-3">策略 SHA-256</th>
                  <th className="py-2.5 px-3">引擎版本</th>
                  <th className="py-2.5 px-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {policyRevisions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-muted">
                      {loadingPolicy ? "正在加载策略历史…" : "暂无历史版本记录"}
                    </td>
                  </tr>
                ) : (
                  policyRevisions.map((rev) => (
                    <tr key={rev.version} className="hover:bg-elevated/50 transition-colors">
                      <td className="py-2.5 px-3 font-mono font-semibold text-fg">
                        v{rev.version}
                        {rev.version === currentPolicyVersion && (
                          <span className="ml-1.5 rounded bg-ok/10 px-1.5 py-0.2 text-[10px] text-ok border border-ok/25 font-normal">
                            CT 当前版本
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-muted font-mono">
                        {formatDateTime(rev.publishedAt, locale)}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-muted" title={rev.hash}>
                        {rev.hash ? `${rev.hash.slice(0, 12)}…` : "—"}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-muted">
                        {rev.engineVersion}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={loadingDetail}
                              onClick={() => void handleInspectRevision(rev.version)}
                            className="h-7 px-2 text-xs"
                          >
                            <FileCode className="size-3.5 mr-1" />
                            查看
                          </Button>
                          {rev.version !== currentPolicyVersion && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => { setCasConflictNotice(null); setRestoreTarget({ ...rev, expectedVersion: currentPolicyVersion }); }}
                              className="h-7 px-2 text-xs text-warn border-warn/30 hover:bg-warn/10"
                            >
                              <RotateCcw className="size-3.5 mr-1" />
                              恢复此版
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>

            {nextBeforeVersion !== null && (
              <div className="p-3 border-t border-line text-center">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void loadPolicyRevisions(nextBeforeVersion)}
                  disabled={loadingPolicy}
                  className="text-xs"
                >
                  加载更早版本 (before: {nextBeforeVersion})
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Revision Detail Modal (In-Memory Only, never in browser storage) */}
      {selectedDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs">
          <div className="max-h-[85vh] w-full max-w-2xl rounded-xl bg-surface p-5 border border-line shadow-xl flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-line pb-2">
              <h4 className="text-sm font-semibold text-fg">
                策略历史详情: v{selectedDetail.version}
              </h4>
              <button
                type="button"
                onClick={() => setSelectedDetail(null)}
                className="text-muted hover:text-fg"
              >
                <X className="size-4" />
              </button>
            </div>
            <div className="grid gap-2 text-xs font-mono text-muted sm:grid-cols-2">
              <div>发布时间: {formatDateTime(selectedDetail.publishedAt, locale)}</div>
              <div>引擎版本: {selectedDetail.engineVersion}</div>
              <div className="sm:col-span-2 break-all">Hash: {selectedDetail.hash}</div>
            </div>
            <div className="flex-1 overflow-auto rounded-lg bg-elevated p-3 border border-line">
              <pre className="text-xs font-mono text-fg whitespace-pre-wrap">
                {JSON.stringify(selectedDetail.policy, null, 2)}
              </pre>
            </div>
            <div className="flex justify-end pt-1">
              <Button size="sm" variant="outline" onClick={() => setSelectedDetail(null)} className="text-xs">
                关闭
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* CAS Restore Confirmation Modal */}
      {restoreTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-xl bg-surface p-5 border border-line shadow-xl flex flex-col gap-4">
            <div className="flex items-center justify-between border-b border-line pb-2">
              <h4 className="text-sm font-semibold text-fg flex items-center gap-2">
                <RotateCcw className="size-4 text-warn" />
                <span>确认恢复历史策略</span>
              </h4>
              <button
                type="button"
                onClick={() => setRestoreTarget(null)}
                className="text-muted hover:text-fg"
              >
                <X className="size-4" />
              </button>
            </div>

            <div className="flex flex-col gap-2 text-xs text-muted leading-relaxed">
              <p>
                即将从历史版本 <span className="font-mono font-bold text-fg">v{restoreTarget.version}</span> 恢复内容。
              </p>
              <div className="rounded-lg bg-elevated p-3 border border-line flex flex-col gap-1 font-mono">
                <div>当前预期版本 (expectedVersion): <span className="text-fg font-semibold">{restoreTarget.expectedVersion}</span></div>
                <div>来源策略版本 (sourceVersion): <span className="text-fg font-semibold">{restoreTarget.version}</span></div>
                <div className="text-ok font-semibold mt-1">预计发布新版本: v{restoreTarget.expectedVersion + 1}</div>
              </div>
              <div className="rounded bg-warn/10 p-2.5 border border-warn/25 text-warn text-[11px] flex flex-col gap-1">
                <div className="font-semibold flex items-center gap-1">
                  <AlertTriangle className="size-3.5" />
                  <span>并发保护与生效提醒</span>
                </div>
                <div>
                  • 若其他管理员已发布新版本，服务端将触发 409 cas_conflict，不可自动覆盖。
                </div>
                <div>
                  • 保存成功只代表核心端已提交，不代表所有设备已立即生效（设备实际状态依已有探针和心跳继续显示待同步/未知）。
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-line">
              <Button
                size="sm"
                variant="outline"
                onClick={() => setRestoreTarget(null)}
                disabled={restoring}
                className="text-xs"
              >
                取消
              </Button>
              <Button
                size="sm"
                onClick={() => void handleConfirmRestore()}
                disabled={restoring}
                className="text-xs bg-warn text-bg hover:bg-warn/90 font-medium"
              >
                {restoring ? "正在发布新版本…" : "确认发布递增恢复版本"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
