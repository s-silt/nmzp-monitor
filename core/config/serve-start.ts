import type { AuditRetention } from "../audit/store.ts";
import { tightenExistingDataDir } from "./posix.ts";
import {
  isWildcardBind,
  itemByKey,
  resolveEffectiveConfig,
  serveAuditRetention,
  type ConfigItem,
  type ConfigShowReport,
} from "./resolve.ts";

export interface PreparedServe {
  ok: true;
  host: string;
  port: number;
  dataDir: string;
  tlsHosts: string[];
  storageMode: "window" | "sqlite";
  auditRetention: AuditRetention;
}

export interface RejectedServe {
  ok: false;
}

const WP30 =
  "0.0.0.0/:: without CIDR; 1.0 will default to loopback and require CIDR on non-loopback (WP-30)";

export function securityInvalid(report: ConfigShowReport): ConfigItem[] {
  return report.items.filter((row) => row.securityRelevant && !row.valid);
}

export function nonSecurityInvalid(report: ConfigShowReport): ConfigItem[] {
  return report.items.filter((row) => !row.securityRelevant && !row.valid);
}

export async function prepareServeProcess(
  env: NodeJS.ProcessEnv,
  writeStderr: (text: string) => void,
): Promise<PreparedServe | RejectedServe> {
  const report = resolveEffectiveConfig(env);
  const illegal = securityInvalid(report);
  if (illegal.length > 0) {
    for (const row of illegal) {
      writeStderr(`${row.key}: ${row.problem ?? "invalid"}\n`);
    }
    return { ok: false };
  }
  for (const row of nonSecurityInvalid(report)) {
    writeStderr(`WARN ${row.key}: ${row.problem ?? "invalid"}; using default\n`);
  }
  const bind = itemByKey(report, "NMZP_BIND");
  if (isWildcardBind(bind.value)) {
    writeStderr(`WARN ${bind.key}: ${WP30}\n`);
  }
  const dataDir = String(itemByKey(report, "NMZP_DATA").value);
  const tightened = await tightenExistingDataDir(dataDir);
  if (!tightened.ok) {
    writeStderr(`NMZP_DATA: ${tightened.reason}\n`);
    return { ok: false };
  }
  const tlsRaw = String(itemByKey(report, "NMZP_TLS_HOSTS").value);
  const tlsHosts = tlsRaw.split(",").map((s) => s.trim()).filter(Boolean);
  const storage = itemByKey(report, "NMZP_STORAGE_MODE").value;
  return {
    ok: true,
    host: String(bind.value),
    port: Number(itemByKey(report, "NMZP_PORT").value),
    dataDir,
    tlsHosts,
    storageMode: storage === "sqlite" ? "sqlite" : "window",
    auditRetention: serveAuditRetention(report),
  };
}
