import {
  DISK_MIN_FREE_BYTES,
  FRICTION_HIGH_COUNT,
  NOT_AVAILABLE_SUMMARY,
  type CheckId,
  type DoctorCheck,
  type DoctorRole,
  checkResult,
  notAvailable,
} from "./report.ts";

export type SignatureState = "ok" | "bad" | "not_available";

export function classifyBinary(input: { exists: boolean; signature: SignatureState; path: string }): DoctorCheck {
  if (!input.exists) {
    return checkResult("binary", "ERROR", "程序不在预期路径", "把 nmzp 放回安装时记录的路径。doctor 不会复制或覆盖文件。", {
      path: input.path,
    });
  }
  if (input.signature === "bad") {
    return checkResult("binary", "ERROR", "程序签名校验失败", "不要继续使用这份程序。doctor 不会替换文件。", {
      path: input.path,
    });
  }
  if (input.signature === "not_available") return notAvailable("binary", { path: input.path });
  return checkResult("binary", "OK", "程序在预期路径且签名校验通过", null, { path: input.path });
}

export function classifyVersion(input: { local: number; required: number | null }): DoctorCheck {
  if (input.required === null) return notAvailable("version", { localEngineRevision: input.local });
  if (input.local < input.required) {
    return checkResult(
      "version",
      "ERROR",
      "本机 engineRevision 低于服务端要求的最低版本",
      "升级设备端程序。doctor 不会发起更新。",
      { localEngineRevision: input.local, requiredEngineRevision: input.required },
    );
  }
  return checkResult("version", "OK", "engineRevision 满足服务端最低版本", null, {
    localEngineRevision: input.local,
    requiredEngineRevision: input.required,
  });
}

export function classifyService(state: "running" | "stopped" | null): DoctorCheck {
  if (state === "running") return checkResult("service", "OK", "服务进程在运行", null, { state });
  if (state === "stopped") {
    return checkResult("service", "ERROR", "服务未运行", "启动 nmzp serve 或设备 agent 后再看。doctor 不会启动或停止服务。", {
      state,
    });
  }
  return checkResult("service", "UNKNOWN", "没有可读取的服务状态", null, {
    code: "platform_manager_unavailable",
  });
}

export interface StorageInput {
  mode: "window" | "sqlite" | "invalid";
  policy: "missing" | "ok" | "invalid" | "unreadable";
  schemaVersion: number | null;
  devices: "missing" | "ok" | "invalid" | "unreadable";
  devicesSnapshot: number | null;
  db: "missing" | "present";
  integrity: "ok" | "bad" | "unreadable" | "skipped";
  history: "ok" | "bad" | "missing" | "skipped";
  auditFormat: number | null;
}

export function classifyStorage(input: StorageInput): DoctorCheck {
  if (input.mode === "invalid") return unknown("storage", "invalid_storage_mode");
  if (input.policy === "unreadable") return unknown("storage", "policy_unreadable");
  if (input.devices === "unreadable") return unknown("storage", "devices_unreadable");
  if (input.integrity === "unreadable") return unknown("storage", "sqlite_unreadable");
  if (input.policy === "missing") return storageError("policy_missing", "数据目录里没有 policy.json");
  if (input.policy === "invalid") return storageError("policy_file_invalid", "policy.json 完整性检查失败");
  if (input.schemaVersion !== null && input.schemaVersion !== 1) {
    return storageError("schema_mismatch", "policy schemaVersion 与 0.x 不匹配");
  }
  if (input.devices === "invalid") return storageError("devices_invalid", "devices.json 完整性检查失败");
  if (input.devicesSnapshot !== null && input.devicesSnapshot !== 1) {
    return storageError("schema_mismatch", "devices snapshotVersion 与 0.x 不匹配");
  }
  if (input.mode === "window" && input.db === "present") {
    return storageError("storage_mode_mismatch", "window 模式数据目录里存在 nmzp.db");
  }
  if (input.mode === "sqlite" && input.db === "missing") {
    return storageError("policy_history_missing", "sqlite 模式缺少 nmzp.db");
  }
  if (input.integrity === "bad") return storageError("sqlite_integrity_failed", "数据库完整性检查失败");
  if (input.mode === "sqlite" && input.history !== "ok") {
    return storageError("policy_history_corrupt", "策略历史 schema 无法读取");
  }
  if (input.auditFormat !== null && input.auditFormat !== 1) {
    return storageError("schema_mismatch", "audit format_version 与 0.x 不匹配");
  }
  return checkResult("storage", "OK", "存储可读且 schemaVersion 匹配", null, { schemaVersion: 1, mode: input.mode });
}

export function classifyDisk(input: { freeBytes: number | null; code?: string }): DoctorCheck {
  if (input.freeBytes === null) return unknown("disk", input.code ?? "statfs_failed");
  if (input.freeBytes < DISK_MIN_FREE_BYTES) {
    return checkResult(
      "disk",
      "ERROR",
      `可用空间 ${input.freeBytes} 字节，低于 ${DISK_MIN_FREE_BYTES} 字节`,
      "清理所在卷，至少保留 200 MiB。doctor 不会删除数据。",
      { freeBytes: input.freeBytes, minFreeBytes: DISK_MIN_FREE_BYTES },
    );
  }
  return checkResult("disk", "OK", `可用空间 ${input.freeBytes} 字节`, null, {
    freeBytes: input.freeBytes,
    minFreeBytes: DISK_MIN_FREE_BYTES,
  });
}

export interface TlsInput {
  material: "absent" | "invalid" | "present";
  expired: boolean;
  san: "ok" | "mismatch" | "unchecked";
  fingerprint: "ok" | "mismatch" | "unchecked";
  publicHost?: string | null;
}

export function classifyTls(input: TlsInput): DoctorCheck {
  if (input.material === "absent") return unknown("tls", "tls_material_absent");
  if (input.material === "invalid") return unknown("tls", "tls_cert_invalid");
  const san = input.san;
  const fingerprint = input.fingerprint;
  if (input.expired) {
    return checkResult("tls", "ERROR", "证书已过期", "重新签发证书。doctor 不会写入 identity 或证书。", {
      expired: true,
    });
  }
  if (fingerprint === "mismatch") {
    return checkResult("tls", "ERROR", "证书指纹与已保存的 pin 不一致", "不要继续使用这份证书。doctor 不会轮换证书。", {
      fingerprint: "mismatch",
    });
  }
  if (san === "mismatch") {
    return checkResult("tls", "ERROR", "证书 SAN 不含 NMZP_PUBLIC_URL 的主机名", "证书需要覆盖公开地址。doctor 不会改证书。", {
      san: "mismatch",
      ...(input.publicHost ? { host: input.publicHost } : {}),
    });
  }
  if (fingerprint !== "ok" && san !== "ok") return unknown("tls", "tls_unpinned");
  return checkResult("tls", "OK", "证书未过期，指纹或 SAN 与本地记录一致", null, { san, fingerprint });
}

export interface IdentityInput {
  perm: "ok" | "wide" | "listable" | "unknown";
  revoked: boolean | null;
}

export function classifyIdentity(input: IdentityInput): DoctorCheck {
  if (input.revoked === true) {
    return checkResult("identity", "ERROR", "存在已吊销的设备", "在服务端确认吊销列表。doctor 不会修改吊销状态或权限。", {
      perm: input.perm,
      revoked: true,
    });
  }
  if (input.perm === "wide") {
    return checkResult(
      "identity",
      "ERROR",
      "身份或数据文件权限过宽，且本次不会自动收紧",
      "手动把目录收到 0700、文件收到 0600。doctor 不会 chmod。",
      { perm: "wide", revoked: input.revoked },
    );
  }
  if (input.perm === "unknown" || input.revoked === null) {
    return checkResult("identity", "UNKNOWN", "无法确认权限或吊销状态", null, {
      code: input.perm === "unknown" ? "posix_mode_not_authoritative" : "revocation_unreadable",
      perm: input.perm,
    });
  }
  if (input.perm === "listable") {
    return checkResult("identity", "WARN", "目录可被其他用户列出", "建议 chmod 700。doctor 不会 chmod。", {
      perm: "listable",
      revoked: input.revoked,
    });
  }
  return checkResult("identity", "OK", "权限不宽于 0700/0600，且没有已吊销设备", null, {
    perm: "ok",
    revoked: false,
  });
}

export interface PolicyInput {
  cache: "missing" | "valid" | "invalid";
  headRulesHash: string | null;
  engineRulesHash: string | null;
}

export function classifyPolicy(input: PolicyInput): DoctorCheck {
  if (input.headRulesHash !== null && input.engineRulesHash !== null) {
    if (input.headRulesHash !== input.engineRulesHash) {
      return checkResult("policy", "ERROR", "policy head 的 rulesHash 与当前引擎不一致", "不要假定新旧规则集相同。doctor 不会改策略。", {
        match: false,
      });
    }
    return checkResult("policy", "OK", "policy head 的 rulesHash 与当前引擎一致", null, { match: true });
  }
  if (input.cache === "invalid") {
    return checkResult("policy", "UNKNOWN", "策略缓存无法校验，按过期处理", null, { reason: "cache_expired" });
  }
  return notAvailable("policy");
}

export function classifyProtected(input: { downgrades: string[] | null; code?: string }): DoctorCheck {
  if (input.downgrades === null) return unknown("protected_rules", input.code ?? "policy_unreadable");
  if (input.downgrades.length > 0) {
    return checkResult(
      "protected_rules",
      "ERROR",
      "受保护规则被降级",
      "需要人工把这些规则恢复为 block。doctor 不会改策略，也不会放宽。",
      { downgrades: input.downgrades },
    );
  }
  return checkResult("protected_rules", "OK", "没有受保护规则被降级", null, { downgrades: [] });
}

export interface AuditInput {
  mode: "window" | "sqlite" | "invalid";
  corruptCount: number | null;
  worker: "not_applicable" | "ready" | "not_ready" | "unknown";
  code?: string;
}

export function classifyAudit(input: AuditInput): DoctorCheck {
  if (input.corruptCount !== null && input.corruptCount > 0) {
    return checkResult("audit", "ERROR", "审计里有损坏记录", "先导出并核对损坏行。doctor 不会删除或修复审计。", {
      corruptCount: input.corruptCount,
      worker: input.worker,
    });
  }
  if (input.worker === "not_ready") {
    return checkResult("audit", "ERROR", "审计 worker 未就绪", "doctor 不会启动 worker。", { worker: "not_ready" });
  }
  if (input.mode === "invalid" || input.corruptCount === null || input.worker === "unknown") {
    return checkResult("audit", "UNKNOWN", "不能在不启动 worker 的情况下确认审计状态", null, {
      code: input.code ?? "audit_worker_not_observable",
      mode: input.mode,
    });
  }
  return checkResult("audit", "OK", "审计可读且 corruptCount 为 0", null, {
    corruptCount: 0,
    worker: input.worker,
    mode: input.mode,
  });
}

export interface ConfigItemView {
  key: string;
  value: string | number | null;
  source: "DEFAULT" | "ENV" | "FILE";
  secret: boolean;
  securityRelevant: boolean;
  valid: boolean;
  isSet: boolean;
  problem?: string;
}

export interface ConfigInput {
  role: DoctorRole;
  /** Null when resolveEffectiveConfig could not run. */
  items: ConfigItemView[] | null;
  cacheInvalid: boolean;
}

function bindKind(items: ConfigItemView[]): "loopback" | "open" | "unset" {
  const bind = items.find((row) => row.key === "NMZP_BIND");
  if (!bind || bind.source === "DEFAULT" || bind.value === "" || bind.value === null) return "unset";
  const raw = String(bind.value);
  if (raw === "127.0.0.1" || raw === "localhost" || raw === "::1") return "loopback";
  return "open";
}

function wildcardBindWarn(role: DoctorRole, items: ConfigItemView[]): boolean {
  const bind = items.find((row) => row.key === "NMZP_BIND");
  if (!bind) return false;
  const raw = bind.value;
  const wildcard = raw === "0.0.0.0" || raw === "::";
  if (!wildcard) return false;
  if (role === "server") return true;
  return bind.source === "ENV";
}

export function classifyConfig(input: ConfigInput): DoctorCheck {
  if (input.items === null) {
    return checkResult("config", "UNKNOWN", "无法读取生效配置", null, { code: "config_unreadable" });
  }
  const illegal = input.items.filter((row) => row.securityRelevant && !row.valid).map((row) => row.key);
  if (illegal.length > 0) {
    return checkResult("config", "ERROR", "安全相关配置非法", "修正列出的 NMZP_* 后重启。doctor 不会改配置。", {
      illegal,
    });
  }
  const bind = bindKind(input.items);
  const nonSecurity = input.items.filter((row) => !row.securityRelevant && !row.valid).map((row) => row.key);
  const bindWarn = wildcardBindWarn(input.role, input.items);
  const cacheWarn = input.cacheInvalid && input.role !== "server";
  if (nonSecurity.length > 0 || bindWarn || cacheWarn) {
    const parts: string[] = [];
    if (bindWarn) parts.push("监听不是回环地址；1.0 将默认绑回环，非回环需配置 CIDR（WP-30）");
    if (nonSecurity.length > 0) parts.push(`非安全配置非法，已按默认值理解：${nonSecurity.join(",")}`);
    if (cacheWarn) parts.push("设备配置非法，正在使用默认值");
    return checkResult("config", "WARN", parts.join("；"), "doctor 只报告，不会改绑定，也不会改设备配置。", {
      bind,
      cacheInvalid: input.cacheInvalid,
      ...(nonSecurity.length > 0 ? { invalid: nonSecurity } : {}),
    });
  }
  return checkResult("config", "OK", "没有发现非法配置", null, { bind });
}

export function classifyFriction(
  rows: Array<{ ruleId: string; count: number; samples: string[] }> | null,
  code?: string,
): DoctorCheck {
  if (rows === null) return unknown("friction", code ?? "events_unreadable");
  const hot = rows.filter((row) => row.count >= FRICTION_HIGH_COUNT);
  if (hot.length === 0) {
    return checkResult("friction", "OK", "24 小时内没有规则的 BLOCK+ASK 达到阈值", null, {
      threshold: FRICTION_HIGH_COUNT,
      rules: rows.length,
    });
  }
  return checkResult(
    "friction",
    "WARN",
    "有规则在 24 小时内的 BLOCK+ASK 偏高，请复查",
    "只复查这些规则。doctor 不会放宽、不会改 overrides、也不会代发策略。",
    {
      threshold: FRICTION_HIGH_COUNT,
      rules: hot.map((row) => ({ ruleId: row.ruleId, count: row.count, samples: row.samples.slice(0, 3) })),
    },
  );
}

export function classifyQueues(input: { role: DoctorRole; outbox: "missing" | "ok" | "full" | "dropped" | "corrupt" }): DoctorCheck {
  if (input.outbox === "corrupt") return unknown("queues", "outbox_corrupt");
  if (input.outbox === "full" || input.outbox === "dropped") {
    return checkResult("queues", "ERROR", input.outbox === "full" ? "outbox 已满" : "outbox 出现过丢弃", "腾出 outbox 或核对丢弃原因。doctor 不会清空队列。", {
      outbox: input.outbox,
    });
  }
  if (input.role === "device") return checkResult("queues", "OK", "outbox 未满且没有丢弃", null, { outbox: input.outbox });
  return notAvailable("queues");
}

export function classifyAdapters(input: {
  hosts: number;
  unreadable: boolean;
  ranges: "unavailable" | "checked";
  mismatches: string[];
}): DoctorCheck {
  if (input.unreadable) return unknown("adapters", "discovery_unreadable");
  if (input.hosts <= 0) return checkResult("adapters", "UNKNOWN", "没有发现任何宿主", null, { reason: "no_hosts" });
  if (input.mismatches.length > 0) {
    return checkResult("adapters", "ERROR", "宿主版本不在 adapter 要求的范围内", "升级或停用该宿主。doctor 不会改宿主安装。", {
      mismatches: input.mismatches,
    });
  }
  if (input.ranges === "unavailable") return notAvailable("adapters", { hosts: input.hosts });
  return checkResult("adapters", "OK", "已发现的宿主版本在 adapter 范围内", null, { hosts: input.hosts });
}

export function classifyHookConfig(input: { records: "none" | "unreadable" | "mismatch" | "match"; code?: string }): DoctorCheck {
  if (input.records === "unreadable") return unknown("hook_config", input.code ?? "hook_config_unreadable");
  if (input.records === "none") return unknown("hook_config", "install_hash_missing");
  if (input.records === "mismatch") {
    return checkResult("hook_config", "ERROR", "hook 配置与安装时的哈希不一致", "对照 manifest 里的 writtenSha256。doctor 不会重写 hook 配置。", {
      records: "mismatch",
    });
  }
  return checkResult("hook_config", "OK", "hook 配置与安装时的哈希一致", null, { records: "match" });
}

export function classifyHookObserved(input: {
  looked: boolean;
  unreadable: boolean;
  configured: readonly string[];
  observed: readonly string[];
}): DoctorCheck {
  const observed = new Set(input.observed);
  const missing = input.configured.filter((host) => !observed.has(host));
  if (observed.size === 0 && (input.unreadable || !input.looked)) {
    return checkResult("hook_observed", "UNKNOWN", "24 小时内没有可确认的 hook 观察记录", null, {
      code: input.unreadable ? "observation_unreadable" : "observation_source_missing",
    });
  }
  if (observed.size === 0 || missing.length > 0) {
    return checkResult(
      "hook_observed",
      "WARN",
      "24 小时内没有观察到全部宿主的 hook 事件",
      "配置正确也不能当成已观察到。doctor 不会把未观察记为 OK。",
      { configured: [...input.configured], observed: [...observed], missing },
    );
  }
  return checkResult("hook_observed", "OK", "24 小时内观察到了已配置宿主的 hook 事件", null, {
    observed: [...observed],
  });
}

export type HostTrustStatus =
  | "not_configured"
  | "trusted"
  | "untrusted"
  | "modified"
  | "disabled"
  | "feature_off"
  | "unknown"
  | "unreadable";

export function classifyHostTrust(status: HostTrustStatus): DoctorCheck {
  if (status === "trusted") return checkResult("host_trust", "OK", "Codex trusted_hash 与当前 hook 命令一致", null, { trust: status });
  if (status === "modified" || status === "untrusted") {
    return checkResult("host_trust", "ERROR", "Codex trusted_hash 与当前 hook 命令不一致", "在 Codex 里重新确认 hook。doctor 不会写 trust。", {
      trust: status,
    });
  }
  return checkResult("host_trust", "UNKNOWN", "无法确认 Codex trusted_hash", null, { code: status });
}

export function classifyConstantUnknown(id: CheckId): DoctorCheck {
  return notAvailable(id);
}

function unknown(id: CheckId, code: string): DoctorCheck {
  return checkResult(id, "UNKNOWN", "检查未能完成", null, { code });
}

function storageError(code: string, summary: string): DoctorCheck {
  return checkResult("storage", "ERROR", summary, "先核对数据目录。doctor 不会迁移、修复或删除存储。", { code });
}

export { NOT_AVAILABLE_SUMMARY };
