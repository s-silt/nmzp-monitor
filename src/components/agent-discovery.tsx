import {probeProtectionText} from "@/lib/monitor/probe-protection";
import { useEffect, useState } from "react";
import { Bot, ChevronDown, Search } from "lucide-react";
import {
  AGENT_CATALOG,
  adapterById,
  discoveryStale,
  parseDiscovery,
  type DiscoverySnapshot,
} from "@/lib/monitor/agent-discovery";
import type { Machine } from "@/lib/monitor/types";
import { useMonitor, useScopedCapabilities, useT } from "@/lib/monitor/store";
import { formatDateTime } from "@/lib/monitor/format";
import { cn } from "@/lib/utils";
import {
  observedRunningLabel,
  summarizeObservedAppProcesses,
} from "@/lib/monitor/observed-app-summary";

const HOOK_AGENTS = new Set([
  "grok",
  "claude",
  "codex",
  "zcode",
  "antigravity",
  "kimi",
  "trae",
  "qwen",
  "qoder",
  "lingma",
  "codebuddy",
  "gemini",
  "cursor",
]);

function hookAgentFromAdapter(adapterId: string): string | undefined {
  const a = adapterById(adapterId);
  if (a?.hook && HOOK_AGENTS.has(a.hook)) return a.hook;
  const head = adapterId.split("-")[0] ?? "";
  if (HOOK_AGENTS.has(head)) return head;
  return undefined;
}
const labels: Record<string, string> = {
  present: "发现安装",
  candidate: "候选，身份待确认",
  not_found: "本次范围未发现",
  unknown: "未知",
  observed: "观察到应用进程",
  not_observed: "未观察到候选进程",
  ok: "完成",
  partial: "部分结果",
  timeout: "扫描超时",
  permission: "权限不足",
  error: "扫描失败",
  unsupported: "平台暂不支持",
  corroborated: "元数据相符（非厂商认证）",
  cli: "CLI",
  desktop: "桌面 / IDE",
  extension: "IDE 扩展",
  registry: "卸载登记",
  appx: "系统应用包",
  path: "PATH / 安装入口",
  packages: "包安装记录",
  extensions: "扩展安装索引",
  processes: "候选进程",
  manual: "手动路径",
  uninstall_record: "卸载登记记录",
  appx_record: "系统应用包登记",
  file_metadata: "文件产品元数据",
  signature_valid: "系统签名校验有效",
  signature_unverified: "签名未验证",
  npm_manifest: "全局 npm 包及入口",
  python_metadata: "Python 安装元数据",
  extension_index: "实际扩展安装索引",
  extension_manifest: "扩展 ID 与版本相符",
  path_entry: "命令入口",
  manual_path: "本机登记路径",
  process_identity: "PID + 启动时间 + 路径复核",
  name_only: "仅候选名称，不能确认身份",
  publisher_not_pinned: "未绑定厂商发布者证明",
  unsigned_metadata: "元数据不构成签名证明",
  shared_host: "共享宿主，插件运行归属未知",
  runtime_unattributed: "无法安全归属运行实例",
  scan_incomplete: "本次检查不完整，保留历史观测",
  not_seen: "本次检查范围内未再发现",
  instance_not_bound: "尚未绑定到 NMZP 受控会话",
  metadata_conflict: "元数据冲突",
  entry_unresolved: "安装登记命中，入口待确认（可能为残留登记）",
};
const txt = (v: string) => labels[v] ?? v;
export function DiscoveryResults({
  snapshot,
  capabilities: explicitCapabilities,
  now = Date.now(),
}: {
  snapshot?: DiscoverySnapshot;
  capabilities?: Record<string, { supported: boolean; active: boolean; error?: string }>;
  now?: number;
}) {
  const tx = useT();
  const scopedCaps = useScopedCapabilities();
  const capabilities = explicitCapabilities ?? scopedCaps;
  if (!snapshot)
    return <p className="text-sm text-muted">尚无自动发现报告；旧探针或尚未检查，不代表未安装。</p>;
  const stale = discoveryStale(snapshot, now);
  return (
    <div className="space-y-3 min-w-0">
      <p className="text-sm text-muted">
        扫描：{txt(snapshot.status)}
        {stale ? " · 结果已过期" : ""} · 最后检查 {formatDateTime(snapshot.completedAt, "zh")} UTC+8
      </p>
      <p className="text-xs text-muted break-words">
        {snapshot.sources.map((s) => `${txt(s.id)}：${txt(s.status)}`).join(" · ")}
      </p>
      {!snapshot.items.length && (
        <p className="text-sm text-muted">
          {snapshot.status === "ok"
            ? "本次有限扫描未发现匹配实例；自定义位置可在本机补充。"
            : "尚无可用结果，不能据此判断未安装。"}
        </p>
      )}
      <div className="grid items-start gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {snapshot.items.map((item) => {
          const a = adapterById(item.adapterId)!;
          const agent = hookAgentFromAdapter(item.adapterId);
          const cap = agent && capabilities ? capabilities[`hook_${agent}`] : undefined;
          let tagKey: "tagReceiptConfirmed" | "tagHasAdapter" | "tagOnlyDiscovered" = "tagOnlyDiscovered";
          let tagStyle = "bg-elevated/60 text-subtle border-line/60";

          if (cap && cap.supported) {
            if (cap.active) {
              tagKey = "tagReceiptConfirmed";
              tagStyle = "bg-ok/10 text-ok border-ok/20";
            } else {
              tagKey = "tagHasAdapter";
              tagStyle = "bg-elevated text-muted border-line";
            }
          }
          const tagLabel = tx(tagKey);

          return (
            <article
              key={item.instanceId}
              className="min-w-0 rounded-xl border border-line bg-surface p-4 space-y-2"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="font-semibold break-words">
                  {a.product} <span className="text-xs text-muted">{txt(a.form)}</span>
                </div>
                <span className={cn("rounded-full px-2 py-0.5 font-mono text-[11px] border", tagStyle)}>
                  {tagLabel}
                </span>
              </div>
              <p className="text-xs">
                版本：{item.version ?? "未知"}
                {a.lifecycle === "retired" ? " · 官方已停止服务" : ""}
              </p>
              <dl className="text-sm space-y-1">
                <div>
                  安装：{stale ? "历史观测 · " : ""}
                  {txt(item.installation)}
                </div>
                <div>
                  运行：
                  {stale
                    ? "未知（缓存过期）"
                    : item.running === "observed"
                      ? observedRunningLabel(item)
                      : txt(item.running)}
                </div>
                <div>接入：{tagLabel}（未绑定此独立实例）</div>
                <div>保护：无本实例生效验证证据</div>
              </dl>
              <details className="text-xs text-muted min-w-0">
                <summary className="cursor-pointer">身份依据与保护详情</summary>
                <div className="space-y-2 mt-2 break-words">
                  <p>{txt(item.identity)}；不能据此扩大审计范围。</p>
                  <p>依据：{item.evidence.map(txt).join("、") || "不足"}</p>
                  <p>{item.reasons.map(txt).join("；")}</p>
                  <p>
                    最后发现 {formatDateTime(item.lastSeen, "zh")} UTC+8
                    <br />
                    本实例检查 {formatDateTime(item.lastChecked, "zh")} UTC+8
                  </p>
                  <p>实例 {item.instanceId.slice(3, 15)}</p>
                  {item.processes.map((p) => (
                    <p key={`${p.pid}:${p.startedAt}`}>
                      PID {p.pid} · 启动 {formatDateTime(p.startedAt, "zh")} UTC+8
                      {stale ? "（历史）" : ""}
                    </p>
                  ))}
                  <ul className="space-y-1">
                    {item.protections.map((p) => (
                      <li key={p.id}>
                        {
                          {
                            tool_pre: "工具前检查",
                            network: "出网限制",
                            clipboard: "剪贴板隔离",
                            screen: "截屏隔离",
                            privacy: "隐私替换",
                            response: "模型回复检测",
                          }[p.id]
                        }
                        ：
                        {
                          {
                            adapter_available: "适配器可用",
                            experimental: "实验实现",
                            unavailable: "无实例适配",
                          }[p.implementation]
                        }{" "}
                        · 本实例未验证
                      </li>
                    ))}
                    <li>最近保护验证：无</li>
                  </ul>
                  {a.hook && (
                    <a className="underline" href="/install">
                      查看现有接入流程（仍需实例绑定与宿主验收）
                    </a>
                  )}
                  <a
                    className="text-accent underline"
                    href={a.source}
                    target="_blank"
                    rel="noreferrer"
                  >
                    官方识别资料（{a.checkedOn} 核对）
                  </a>
                </div>
              </details>
            </article>
          );
        })}
      </div>
    </div>
  );
}
export function ObservedAppProcessSection({
  machines,
  host,
  now,
  disconnected,
}: {
  machines: Machine[];
  host: string;
  now: number;
  disconnected: boolean;
}) {
  const tx = useT();
  const summary = summarizeObservedAppProcesses(machines, { host, now, disconnected });
  return (
    <section className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)]" aria-label="已观察到应用进程">
      <details className="group">
        <summary className="flex cursor-pointer list-none flex-wrap items-start justify-between gap-3 border-b border-line pb-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-fg/30 rounded-lg p-1 [&::-webkit-details-marker]:hidden">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <Bot className="size-4 text-info" />
              <h2 className="text-sm font-semibold text-fg">{summary.headline}</h2>
              {summary.status === "observed" ? (
                <span className="rounded-full bg-info/10 text-info border border-info/25 px-2 py-0.5 font-mono text-[11px] font-medium">
                  {summary.count}
                </span>
              ) : summary.status === "unknown" ? (
                <span className="rounded-full bg-warn/10 text-warn border border-warn/25 px-2 py-0.5 font-mono text-[11px] font-medium">
                  {tx("unknown")}
                </span>
              ) : null}
            </div>
            <p className="mt-1 text-xs text-muted">{summary.note}</p>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-muted">
            <span className="font-mono text-[11px]">{tx("expandDetails")}</span>
            <ChevronDown className="mt-0.5 size-4 shrink-0 text-muted transition-transform group-open:rotate-180" />
          </div>
        </summary>
        {summary.status === "observed" ? (
          <ul className="mt-4 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {summary.apps.map((app) => (
              <li key={app.instanceId} className="rounded-lg bg-elevated/70 p-3 border border-line/60">
                <p className="font-semibold text-sm break-words">
                  {app.product}{" "}
                  <span className="text-xs text-muted">
                    {app.form === "cli" ? "CLI" : app.form === "desktop" ? "桌面 / IDE" : "IDE 扩展"}
                  </span>
                </p>
                <p className="mt-1 text-xs text-muted">{app.runningLabel}</p>
                {app.processes.map((p) => (
                  <p key={`${p.pid}:${p.startedAt}`} className="mt-1 font-mono text-xs text-subtle">
                    PID {p.pid} · 启动 {p.startedAtText}
                  </p>
                ))}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-4 text-xs text-muted">{summary.note}</p>
        )}
      </details>
    </section>
  );
}
export function AgentDiscoverySection({ machines, host }: { machines: Machine[]; host: string }) {
  const access = useMonitor((s) => s.access);
  const locale = useMonitor((s) => s.locale);
  const disconnected = useMonitor((s) => s.disconnected);
  const scopedCaps = useScopedCapabilities();
  const [local, setLocal] = useState<DiscoverySnapshot>();
  const [paths, setPaths] = useState<Array<{ kind: string; path: string }>>([]);
  const [available, setAvailable] = useState(false);
  const [path, setPath] = useState("");
  const [kind, setKind] = useState("executable");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(Date.now());
  async function loadLocal() {
    try {
      const r = await fetch("/api/v1/local/discovery", { credentials: "include" });
      if (!r.ok) return;
      const b = await r.json();
      setAvailable(true);
      setLocal(parseDiscovery(b.snapshot));
      if (Array.isArray(b.paths)) setPaths(b.paths);
    } catch {
      // Local management discovery endpoint is optional; ignore if unavailable
    }
  }
  useEffect(() => {
    if (access === "admin") void loadLocal();
    const t = setInterval(() => {
      setClock(Date.now());
      if (access === "admin") void loadLocal();
    }, 5000);
    return () => clearInterval(t);
  }, [access]);
  async function action(
    action: "refresh" | "paths",
    values?: Array<{ kind: string; path: string }>,
  ) {
    setBusy(true);
    try {
      const r = await fetch(`/api/v1/local/discovery/${action}`, {
        method: action === "paths" ? "PUT" : "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(values ?? {}),
      });
      setMessage(
        r.ok
          ? "已请求本机检查；等待实际结果，设备视图将在下一次心跳同步。"
          : "请求失败；路径须为本机绝对路径，最多 24 项。",
      );
      if (r.ok) {
        setPath("");
        await loadLocal();
      }
    } catch {
      setMessage("本机管理入口不可用。");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      className="rounded-xl border border-line bg-surface p-5 shadow-[var(--shadow-border)] space-y-4 min-w-0"
      aria-label="编码 Agent 自动发现"
    >
      <div className="border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <Search className="size-4 text-fg" />
          <h2 className="text-sm font-semibold text-fg">编码 Agent 自动发现</h2>
        </div>
        <p className="text-xs text-muted mt-1 leading-relaxed">
          安装、应用进程、接入与保护分别记录。桌面应用运行不等于正在执行 Agent
          任务；扩展安装不等于运行。
        </p>
        {disconnected && (
          <p className="text-warn text-xs mt-1">服务连接失败，以下设备数据为历史缓存。</p>
        )}
      </div>
      {machines
        .filter((m) => host === "all" || m.id === host)
        .map((m) => (
          <div key={m.id} className="rounded-lg bg-elevated/40 border border-line/60 p-3.5 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-fg">设备 {m.hostname}</h3>
              <span className="font-mono text-xs text-subtle">{m.ip}</span>
            </div>
            <p className="text-xs text-muted leading-relaxed" role="status">
              {probeProtectionText(m.probeProtection, locale, clock)}
              {m.probeProtection?.lastAuthenticatedAt
                ? ` · 核心最后验证 ${formatDateTime(m.probeProtection.lastAuthenticatedAt, locale)} UTC+8`
                : ""}
            </p>
            <DiscoveryResults snapshot={m.discovery} capabilities={m.capabilities} now={clock} />
          </div>
        ))}
      {!machines.length && (
        <p className="text-sm text-muted">尚无设备上报。不会用产品目录或演示数据填充发现结果。</p>
      )}
      {access === "admin" && available && (
        <details className="border border-line rounded-lg bg-surface/50 p-4">
          <summary className="cursor-pointer text-xs font-semibold text-muted hover:text-fg">
            本机刷新与路径补充（管理员）
          </summary>
          <div className="mt-3 space-y-3">
            <p className="text-xs text-muted">
              仅作用于当前管理代理所在机器。路径不上传到 CT / LAN；登记路径不会启动程序或授予信任。
            </p>
            <button
              className="rounded-lg border border-line bg-surface px-3 py-1.5 text-xs text-fg hover:bg-elevated disabled:opacity-50"
              disabled={busy}
              onClick={() => void action("refresh")}
            >
              刷新本机发现
            </button>
            <form
              className="flex flex-col gap-2 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                void action("paths", [...paths, { kind, path }]);
              }}
            >
              <select
                aria-label="路径类型"
                value={kind}
                onChange={(e) => setKind(e.target.value)}
                className="bg-elevated border border-line rounded-lg p-1.5 text-xs text-fg"
              >
                <option value="executable">可执行文件</option>
                <option value="npm-prefix">全局 npm 前缀</option>
                <option value="extensions">IDE 扩展目录</option>
                <option value="python-env">Python 工具环境</option>
              </select>
              <input
                aria-label="本机绝对路径"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className="min-w-0 flex-1 bg-elevated border border-line rounded-lg p-1.5 font-mono text-xs text-fg focus:ring-1 focus:ring-fg/30"
                placeholder="本机绝对路径"
                required
                maxLength={500}
              />
              <button
                disabled={busy}
                className="border border-line rounded-lg bg-surface px-3 py-1.5 text-xs text-fg hover:bg-elevated disabled:opacity-50"
              >
                登记路径
              </button>
            </form>
            {paths.map((p, i) => (
              <div key={`${p.kind}:${p.path}`} className="flex min-w-0 items-start gap-2 text-xs">
                <span className="break-all flex-1 font-mono text-[11px] text-muted">
                  {p.kind} · {p.path}
                </span>
                <button
                  disabled={busy}
                  className="shrink-0 text-xs text-muted hover:text-fg underline"
                  onClick={() =>
                    void action(
                      "paths",
                      paths.filter((_, n) => i !== n),
                    )
                  }
                >
                  移除登记
                </button>
              </div>
            ))}
            {message ? (
              <p role="status" className="text-xs text-muted">
                {message}
              </p>
            ) : null}
            <DiscoveryResults snapshot={local} capabilities={scopedCaps} now={clock} />
          </div>
        </details>
      )}
      <details className="text-xs text-muted">
        <summary className="cursor-pointer hover:text-fg">识别范围与限制</summary>
        <p className="mt-2 leading-relaxed">
          仅
          Windows；按明确元数据适配器识别，不承诺识别任意软件。未发现不代表全盘不存在；自定义扩展目录需本机登记。其他平台、远程容器、WSL
          与 JetBrains 扩展归属未验证。
        </p>
        <p className="mt-1 leading-relaxed">
          暂不支持的形态：
          {AGENT_CATALOG.filter((a) => a.unsupported)
            .map((a) => a.product)
            .join("、")}
          。安装目录和签名状态均不能直接证明保护生效。
        </p>
      </details>
    </section>
  );
}
