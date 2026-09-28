import { NMZP_VERSION } from "../constants.ts";
import { codexHookTrust } from "../codex-hooks.ts";
import {
  classifyAdapters,
  classifyAudit,
  classifyBinary,
  classifyConfig,
  classifyConstantUnknown,
  classifyDisk,
  classifyFriction,
  classifyHookConfig,
  classifyHookObserved,
  classifyHostTrust,
  classifyIdentity,
  classifyPolicy,
  classifyProtected,
  classifyQueues,
  classifyService,
  classifyStorage,
  classifyTls,
  classifyVersion,
  type SignatureState,
} from "./classify.ts";
import {
  readAdapters,
  readAudit,
  readBinary,
  readConfig,
  readDisk,
  readFriction,
  readHookConfig,
  readHookObservation,
  readIdentity,
  readPolicy,
  readProtected,
  readQueues,
  readRole,
  readServiceState,
  readStorage,
  readTls,
  readVersion,
  resolveDataDir,
  resolveHome,
  type InspectContext,
  type StatfsLike,
} from "./inspect.ts";
import {
  CHECK_TIMEOUT_MS,
  DOCTOR_SCHEMA_VERSION,
  aggregateOverall,
  checksForRole,
  doctorExitCode,
  formatDoctorText,
  safeErrorCode,
  scrubReport,
  type CheckId,
  type DoctorCheck,
  type DoctorReport,
} from "./report.ts";

export interface DoctorOptions {
  home?: string;
  dataDir?: string;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  statfs?: (path: string) => StatfsLike;
  /** Production leaves this unset. 0.x has no server minimum to compare. */
  serverMinEngineRevision?: number | null;
  /** Production leaves this unset, which means signature verification is not available. */
  binarySignature?: SignatureState;
  /** Production leaves this unset. 0.x catalog has no adapter version range. */
  adapterMismatches?: readonly string[];
  timeoutMs?: number;
}

export async function runDoctor(options: DoctorOptions = {}): Promise<DoctorReport> {
  const env = options.env ?? process.env;
  const home = resolveHome(env, options.home);
  const dataDir = resolveDataDir(env, options.dataDir);
  const at = (options.now ?? (() => new Date()))();
  const role = await readRole(home, dataDir);
  const ctx: InspectContext = {
    home,
    dataDir,
    env,
    nowMs: at.getTime(),
    role,
    statfs: options.statfs,
    serverMinEngineRevision: options.serverMinEngineRevision,
    binarySignature: options.binarySignature,
    adapterMismatches: options.adapterMismatches,
  };
  const checks = await Promise.all(
    checksForRole(role).map((id) => isolateCheck(id, () => runOne(id, ctx), options.timeoutMs ?? CHECK_TIMEOUT_MS)),
  );
  return scrubReport({
    schemaVersion: DOCTOR_SCHEMA_VERSION,
    role,
    nmzpVersion: NMZP_VERSION,
    generatedAt: at.toISOString(),
    overall: aggregateOverall(checks.map((item) => item.status)),
    checks,
  });
}

export async function isolateCheck(
  id: CheckId,
  run: () => Promise<DoctorCheck>,
  timeoutMs = CHECK_TIMEOUT_MS,
): Promise<DoctorCheck> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("check_timeout");
      (error as { code?: string }).code = "check_timeout";
      reject(error);
    }, timeoutMs);
    timer.unref?.();
  });
  const work = Promise.resolve().then(run);
  try {
    return await Promise.race([work, timeout]);
  } catch (error) {
    return {
      id,
      status: "UNKNOWN",
      summary: "检查未能完成",
      remediation: null,
      details: { code: safeErrorCode(error) },
    };
  } finally {
    if (timer) clearTimeout(timer);
    work.catch(() => undefined);
  }
}

async function runOne(id: CheckId, ctx: InspectContext): Promise<DoctorCheck> {
  switch (id) {
    case "binary":
      return classifyBinary(await readBinary(ctx));
    case "version":
      return classifyVersion(readVersion(ctx));
    case "service":
      return classifyService(await readServiceState(ctx.home, ctx.dataDir));
    case "storage":
      return classifyStorage(await readStorage(ctx));
    case "disk":
      return classifyDisk(readDisk(ctx));
    case "tls":
      return classifyTls(await readTls(ctx));
    case "identity":
      return classifyIdentity(await readIdentity(ctx));
    case "ct_reachability":
    case "backup":
    case "evidence_freshness":
    case "update_status":
      return classifyConstantUnknown(id);
    case "policy":
      return classifyPolicy(await readPolicy(ctx));
    case "protected_rules":
      return classifyProtected(await readProtected(ctx));
    case "audit":
      return classifyAudit(await readAudit(ctx));
    case "config":
      return classifyConfig(await readConfig(ctx));
    case "friction":
      return classifyFriction(await readFriction(ctx));
    case "queues":
      return classifyQueues(await readQueues(ctx));
    case "adapters":
      return classifyAdapters(await readAdapters(ctx));
    case "hook_config":
      return classifyHookConfig(await readHookConfig(ctx));
    case "hook_observed":
      return classifyHookObserved(await readHookObservation(ctx));
    case "host_trust":
      try {
        return classifyHostTrust(codexHookTrust(ctx.home).status);
      } catch {
        return classifyHostTrust("unreadable");
      }
    default: {
      const neverId: never = id;
      return neverId;
    }
  }
}

export { doctorExitCode, formatDoctorText };
