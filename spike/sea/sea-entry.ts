/**
 * SEA injected main (bundled to CJS). User argv starts at process.argv[2]
 * because argv[0] and argv[1] are both execPath in an injected SEA.
 */
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { backup, DatabaseSync } from "node:sqlite";
import { isSea, getAsset } from "node:sea";
import { NMZP_VERSION } from "../../core/constants.ts";
import { main } from "../../core/cli.ts";
import { AuditRuntime } from "../../core/audit/runtime.ts";

const BOOTSTRAP_REASON = "nmzp_hook_bootstrap_failed";
const HOOK_EVENT = "PreToolUse";

function jsonLine(body: unknown): string {
  return `${JSON.stringify(body)}\n`;
}

const specificOutput = jsonLine({
  hookSpecificOutput: {
    hookEventName: HOOK_EVENT,
    permissionDecision: "deny",
    permissionDecisionReason: BOOTSTRAP_REASON,
  },
});
const decisionDeny = jsonLine({ decision: "deny", reason: BOOTSTRAP_REASON });
const reasonLine = `${BOOTSTRAP_REASON}\n`;

function deny(stdout: string, exitCode: number, stderr?: string) {
  return stderr === undefined ? { stdout, exitCode } : { stdout, exitCode, stderr };
}

const genericDeny = deny(decisionDeny, 2, reasonLine);

const EMERGENCY_DENY: Record<string, { stdout: string; exitCode: number; stderr?: string }> = {
  claude: deny(specificOutput, 2, reasonLine),
  codex: deny(specificOutput, 0),
  zcode: deny(specificOutput, 0),
  antigravity: deny(decisionDeny, 0),
  qwen: deny(specificOutput, 2, reasonLine),
  qoder: deny(specificOutput, 2, reasonLine),
  lingma: deny(specificOutput, 2, reasonLine),
  trae: deny(specificOutput, 2, reasonLine),
  codebuddy: deny(specificOutput, 2, reasonLine),
  kimi: deny(
    jsonLine({
      hookSpecificOutput: {
        permissionDecision: "deny",
        permissionDecisionReason: BOOTSTRAP_REASON,
      },
    }),
    2,
    reasonLine,
  ),
  gemini: deny(decisionDeny, 2, reasonLine),
  cursor: deny(
    jsonLine({
      permission: "deny",
      user_message: BOOTSTRAP_REASON,
      agent_message: BOOTSTRAP_REASON,
    }),
    2,
    reasonLine,
  ),
  grok: genericDeny,
};

function agentFromArgv(argv: string[]): string | undefined {
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--agent") return argv[i + 1];
  }
  return undefined;
}

function emergencyDeny(argv: string[]) {
  const agent = agentFromArgv(argv);
  if (typeof agent === "string" && Object.hasOwn(EMERGENCY_DENY, agent))
    return EMERGENCY_DENY[agent];
  return genericDeny;
}

async function emitEmergency(denial: {
  stdout: string;
  exitCode: number;
  stderr?: string;
}): Promise<never> {
  await new Promise<void>((resolve) => {
    process.stdout.write(denial.stdout, () => {
      if (!denial.stderr) return resolve();
      process.stderr.write(denial.stderr, () => resolve());
    });
  });
  process.exit(denial.exitCode);
}

function userArgv(): string[] {
  return process.argv.slice(2);
}

function identity() {
  let workerAsset = false;
  let workerBytes = 0;
  try {
    const raw = getAsset("audit-runtime-worker.cjs");
    workerBytes = typeof raw === "string" ? Buffer.byteLength(raw) : (raw as Uint8Array).byteLength;
    workerAsset = workerBytes > 32;
  } catch {
    workerAsset = false;
  }
  return {
    isSea: isSea(),
    execPath: process.execPath,
    argv0: process.argv0,
    argv: process.argv,
    cwd: process.cwd(),
    filename: __filename,
    dirname: __dirname,
    version: NMZP_VERSION,
    node: process.versions.node,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
    ppid: process.ppid,
    workerAsset,
    workerBytes,
    title: process.title,
  };
}

function event(id: string) {
  return {
    id,
    ts: Date.now(),
    machineId: "sea-device",
    agent: "grok",
    sessionId: "sea-session",
    layer: "app_pre",
    tool: "Read",
    nativeTool: "Read",
    input: "synthetic",
    redacted: "synthetic",
    risk: "info" as const,
    decision: "allow" as const,
    category: "other",
    workdirScope: "project",
    policyVersion: 1,
    evaluation: "allow" as const,
    enforcement: "offline" as const,
  };
}

async function selftestSqlite(dir: string): Promise<unknown> {
  mkdirSync(dir, { recursive: true });
  const stamp = `${Date.now()}-${process.pid}`;
  const src = join(dir, `pragma-${stamp}.db`);
  const vac = join(dir, `vacuum-${stamp}.db`);
  const bak = join(dir, `backup-${stamp}.db`);
  const db = new DatabaseSync(src);
  db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA busy_timeout=1000");
  db.exec(
    "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT NOT NULL); INSERT INTO t(v) VALUES ('sea-sqlite-probe')",
  );
  const journal = db.prepare("PRAGMA journal_mode").get();
  const page = db.prepare("PRAGMA page_size").get();
  const count = db.prepare("PRAGMA page_count").get();
  const vacPath = vac.replaceAll("\\", "/");
  db.exec(`VACUUM INTO '${vacPath}'`);
  const backupPages = await backup(db, bak);
  const row = db.prepare("SELECT id, v FROM t").get();
  db.close();
  const vacDb = new DatabaseSync(vac, { readOnly: true });
  const vacRow = vacDb.prepare("SELECT id, v FROM t").get();
  vacDb.close();
  const bakDb = new DatabaseSync(bak, { readOnly: true });
  const bakRow = bakDb.prepare("SELECT id, v FROM t").get();
  bakDb.close();
  const match =
    (row as { v: string }).v === "sea-sqlite-probe" &&
    (vacRow as { v: string }).v === "sea-sqlite-probe" &&
    (bakRow as { v: string }).v === "sea-sqlite-probe";
  return { journal, page, count, backupPages, row, vacRow, bakRow, match, src, vac, bak };
}

async function selftestAuditWorker(dir: string): Promise<unknown> {
  mkdirSync(dir, { recursive: true });
  const stamp = `${Date.now()}-${process.pid}`;
  const path = join(dir, `nmzp-${stamp}.db`);
  const first = await AuditRuntime.open(path, { create: true, retention: { minFreeBytes: 0 } });
  const id = `sea-audit-${stamp}`;
  const appended = await first.append(event(id));
  const stateOpen = first.state;
  await first.close();
  const second = await AuditRuntime.open(path, { create: false, retention: { minFreeBytes: 0 } });
  const got = await second.get("sea-device", id);
  const recent = await second.recent(5);
  const stateReopen = second.state;
  await second.close();
  return {
    path,
    inserted: appended.inserted,
    stateOpen,
    stateReopen,
    recoveredId: got?.id ?? null,
    recoveredDecision: got?.decision ?? null,
    recentIds: recent.map((row) => row.id),
    spawnFactoryUsed: false,
  };
}

async function selftestRespawn(): Promise<unknown> {
  const child = spawn(process.execPath, ["sea-selftest", "identity"], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, NMZP_SEA_RESPAWN_CHILD: "1" },
  });
  const pid = child.pid;
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => {
    stdout += c;
  });
  child.stderr.on("data", (c: string) => {
    stderr += c;
  });
  const code: number = await new Promise((resolve) => {
    child.on("close", (c) => resolve(c ?? 1));
    setTimeout(() => {
      try {
        if (pid && !child.killed) child.kill();
      } catch {
        /* owned child only */
      }
    }, 20_000).unref();
  });
  let parsed: { execPath?: string; isSea?: boolean; pid?: number } | null = null;
  try {
    parsed = JSON.parse(stdout) as { execPath?: string; isSea?: boolean; pid?: number };
  } catch {
    parsed = null;
  }
  return {
    parentExecPath: process.execPath,
    parentPid: process.pid,
    childPid: pid ?? null,
    childCode: code,
    childExecPath: parsed?.execPath ?? null,
    childIsSea: parsed?.isSea ?? null,
    childMatchesParent: parsed?.execPath === process.execPath,
    stderr: stderr.slice(0, 500),
  };
}

async function runSelftest(args: string[]): Promise<void> {
  const kind = args[0] ?? "identity";
  const outDir = process.env.NMZP_DATA || join(dirname(process.execPath), "sea-selftest");
  let result: unknown;
  if (kind === "identity") result = identity();
  else if (kind === "sqlite") result = await selftestSqlite(join(outDir, "sqlite-selftest"));
  else if (kind === "audit-worker")
    result = await selftestAuditWorker(join(outDir, "audit-selftest"));
  else if (kind === "respawn") result = await selftestRespawn();
  else {
    process.stderr.write(`unknown_selftest:${kind}\n`);
    process.exit(2);
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

async function run(): Promise<void> {
  const argv = userArgv();
  if (argv[0] === "sea-selftest") {
    await runSelftest(argv.slice(1));
    process.exit(0);
  }
  if (argv[0] === "--version" || argv[0] === "-v" || argv[0] === "version") {
    process.stdout.write(`nmzp ${NMZP_VERSION}\n`);
    return;
  }
  try {
    await main(argv);
  } catch (err) {
    if (argv[0] === "hook") await emitEmergency(emergencyDeny(argv));
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}

void run().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
  );
  process.exit(1);
});
