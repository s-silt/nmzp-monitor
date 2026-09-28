/**
 * Spike-only replacement for core/audit/runtime.ts defaultSpawn.
 * Loads the bundled production worker (runtime-worker.ts + store.ts message
 * protocol) from the SEA asset. Does not accept the test-only spawn factory.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { Worker } from "node:worker_threads";
import { getAsset, isSea } from "node:sea";
import type { AuditWorkerPort } from "../../core/audit/worker-channel.ts";

const ASSET_ID = "audit-runtime-worker.cjs";
const MARKER = "audit_worker_operation_invalid";

export function spawnSeaAuditWorker(workerData: unknown): AuditWorkerPort {
  if (!isSea()) {
    throw new Error("sea_audit_worker_requires_injected_executable");
  }
  const raw = getAsset(ASSET_ID);
  const source = typeof raw === "string" ? raw : Buffer.from(raw as Uint8Array).toString("utf8");
  if (!source.includes(MARKER)) {
    throw new Error("sea_audit_worker_asset_missing");
  }
  const dataDir = process.env.NMZP_DATA;
  if (typeof dataDir === "string" && dataDir.length > 1) {
    mkdirSync(dataDir, { recursive: true });
    const file = join(dataDir, "sea-audit-runtime-worker.cjs");
    writeFileSync(file, source);
    return new Worker(file, { workerData, execArgv: [] });
  }
  const beside = join(dirname(process.execPath), "sea-audit-runtime-worker.cjs");
  writeFileSync(beside, source);
  return new Worker(beside, { workerData, execArgv: [] });
}
