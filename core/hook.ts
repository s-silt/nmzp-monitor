import {archivePolicy,githubPolicy} from "./egress-schema.ts";
import {observeUploadSize} from "./upload-size.ts";
import { stdin as stdinStream } from "node:process";
import { homedir } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import {
  BODY_LIMIT,
  HOOK_BUDGET_MS,
  HOOK_CT_MS,
  HOOK_LOCK_MS,
  HOOK_RECEIPT_MS,
  NEED_CHECK_TOOLS,
} from "./constants.ts";
import {
  HOOK_AGENTS,
  detectHookAgent,
  formatHookResponse,
  parseHookEvent,
  toolInputToEvalFields,
  type HookAgent,
  type ParsedHook,
} from "./hook-protocol.ts";
import { pinnedHttps } from "./https-client.ts";
import { readPolicyCache, writePolicyCache } from "./policy-cache.ts";
import { policyExemptions, policyOverrides } from "./policy-schema.ts";
import { loadMonitor } from "./paths.ts";
import { applyEvaluate } from "./eval-bridge.ts";
import { newEventId } from "./auth.ts";
import type { DeviceRecord } from "./schema.ts";
import { FileSessionWindows } from "./window-cache.ts";
import type { Enforcement } from "./schema.ts";
import { withFileLock } from "./persist.ts";
import { recordHookOutcome } from "./probe-status.ts";

export interface HookRunOpts {
  argv: string[];
  stdin: string;
  home?: string;
  coreDir: string;
  now?: number;
  env?: NodeJS.ProcessEnv;
}

export interface DeviceCreds {
  deviceId: string;
  token: string;
  url: string;
  caPem: string;
  fingerprintSha256: string;
}

export interface PendingReceipt {
  creds: DeviceCreds;
  eventId: string;
  evaluation: string;
  enforcement: Enforcement;
}

export interface StatusRecord {
  agent: HookAgent;
  ok: boolean;
  eventId?: string;
  tool?: string;
  error?: string;
}

export interface HookResult {
  stdout: string;
  exitCode: number;
  stderr?: string;
  pendingReceipt?: PendingReceipt;
  statusRecord?: StatusRecord;
  startedAt: number;
}

async function readStdin(limit = BODY_LIMIT): Promise<{ ok: true; text: string } | { ok: false; tooLarge: true }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let n = 0;
    let settled = false;
    const finish = (tooLarge: boolean) => {
      if (settled) return;
      settled = true;
      stdinStream.off("data", onData);
      stdinStream.off("end", onEnd);
      stdinStream.off("error", onEnd);
      if (tooLarge) resolve({ ok: false, tooLarge: true });
      else resolve({ ok: true, text: Buffer.concat(chunks).toString("utf8") });
    };
    const onData = (c: Buffer | string) => {
      const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
      n += b.length;
      if (n > limit) {
        stdinStream.resume();
        finish(true);
        return;
      }
      chunks.push(b);
    };
    const onEnd = () => finish(false);
    stdinStream.on("data", onData);
    stdinStream.on("end", onEnd);
    stdinStream.on("error", onEnd);
    stdinStream.resume();
  });
}

export function parseArgv(argv: string[]): { agent?: string; event?: string } {
  const out: { agent?: string; event?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--agent") out.agent = argv[++i];
    else if (argv[i] === "--event") out.event = argv[++i];
  }
  return out;
}

/** Grok also loads Claude settings; skip our Claude copy so the Grok entry owns the event. */
export function isGrokHostedClaudeCompat(
  agent: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (agent !== "claude") return false;
  const event = env.GROK_HOOK_EVENT;
  const session = env.GROK_SESSION_ID;
  return typeof event === "string" && event.length > 0 && typeof session === "string" && session.length > 0;
}

export async function loadCreds(home: string): Promise<DeviceCreds | null> {
  try {
    const raw = await readFile(join(home, ".nmzp", "credentials.json"), "utf8");
    const j = JSON.parse(raw) as DeviceCreds;
    if (!j.token || !j.url || !j.caPem || !j.fingerprintSha256) return null;
    return j;
  } catch {
    return null;
  }
}

function deny(
  agent: HookAgent | "unknown",
  reason: string,
  argMap?: Record<string, string>,
) {
  return formatHookResponse(
    agent === "unknown" ? "grok" : agent,
    { decision: "deny", reason },
    argMap ? { argMap } : undefined,
  );
}

/** Pass / rewrite: protocol formats empty success or updatedInput-only (no forced allow). */
function pass(
  agent: HookAgent | "unknown",
  reason: string,
  updatedInput?: Record<string, unknown>,
  argMap?: Record<string, string>,
) {
  return formatHookResponse(
    agent === "unknown" ? "grok" : agent,
    {
      decision: "allow",
      reason,
      updatedInput,
    },
    argMap ? { argMap } : undefined,
  );
}

export type InterpretedEval =
  | { action: "deny"; reason: string; evaluation: "block" }
  | { action: "allow"; reason: string; updatedInput?: Record<string, unknown>; evaluation: "allow" | "log" | "rewrite" }
  | { action: "stopped"; reason: string; policyVersion?: number }
  | { action: "fallback" };

/** Unknown/corrupt 200 → deny. rewrite without updatedInput → deny. Never default-allow. Never guess evaluation from reason. */
export function interpretEvaluateResponse(status: number, bodyText: string): InterpretedEval {
  if (status === 413) return { action: "deny", reason: "payload_too_large", evaluation: "block" };
  if (status === 409) return { action: "deny", reason: "event_conflict", evaluation: "block" };
  if (status === 401 || status === 403) return { action: "deny", reason: "unauthorized", evaluation: "block" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText || "{}");
  } catch {
    if (status === 200) return { action: "deny", reason: "bad_eval_json", evaluation: "block" };
    return { action: "fallback" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return status === 200 ? { action: "deny", reason: "bad_eval_json", evaluation: "block" } : { action: "fallback" };
  }
  const j = parsed as {
    decision?: string;
    reason?: string;
    stopped?: boolean;
    policyVersion?: number;
    updatedInput?: Record<string, unknown>;
    error?: string;
  };
  if (j.stopped === true || j.reason === "processing_stopped" || j.error === "processing_stopped") {
    return { action: "stopped", reason: "processing_stopped", policyVersion: j.policyVersion };
  }
  if (status !== 200) return { action: "fallback" };
  const decision = j.decision;
  if (decision === "block") return { action: "deny", reason: j.reason ?? "block", evaluation: "block" };
  if (decision === "rewrite") {
    if (!j.updatedInput || typeof j.updatedInput !== "object") {
      return { action: "deny", reason: "rewrite_missing_updated_input", evaluation: "block" };
    }
    return { action: "allow", reason: j.reason ?? "rewrite", updatedInput: j.updatedInput, evaluation: "rewrite" };
  }
  if (decision === "allow") return { action: "allow", reason: j.reason ?? "allow", evaluation: "allow" };
  if (decision === "log") return { action: "allow", reason: j.reason ?? "log", evaluation: "log" };
  return { action: "deny", reason: "unknown_decision", evaluation: "block" };
}

async function sendReceipt(
  creds: DeviceCreds,
  eventId: string,
  evaluation: string,
  enforcement: Enforcement,
  timeoutMs: number,
): Promise<void> {
  try {
    await pinnedHttps({
      url: `${creds.url}/api/v1/receipt`,
      method: "POST",
      body: JSON.stringify({ eventId, evaluation, enforcement }),
      headers: { "content-type": "application/json", authorization: `Bearer ${creds.token}` },
      caPem: creds.caPem,
      fingerprintSha256: creds.fingerprintSha256,
      timeoutMs,
    });
  } catch {
    /* receipt is best-effort and bounded */
  }
}

async function persistLocalMark(opts: {
  home: string;
  coreDir: string;
  input: Record<string, unknown>;
  result: { skipped?: boolean; tool?: string; decision: string };
  timeoutMs: number;
}): Promise<void> {
  const monitor = await loadMonitor(opts.coreDir);
  const windows = new FileSessionWindows(join(opts.home, ".nmzp", "window-cache.json"), monitor);
  await windows.transact(() => {
    windows.apply(opts.input, opts.result, "enforcing");
  }, opts.timeoutMs);
}

function isHookAgent(v: string | undefined): v is HookAgent {
  return !!v && (HOOK_AGENTS as readonly string[]).includes(v);
}

/** Grok-style skip: Cursor/Trae import ~/.claude/settings.json; the Claude copy no-ops. */
export function isForeignHostPayload(flag: string | undefined, parsed: ParsedHook): "cursor" | "trae" | undefined {
  if (flag !== "claude") return undefined;
  if (parsed.rawKeys.includes("cursor_version")) return "cursor";
  if (parsed.rawKeys.includes("llm_tool_name")) return "trae";
  return undefined;
}

function statusFor(
  agent: HookAgent | "unknown",
  eventId: string,
  tool: string,
): StatusRecord | undefined {
  if (!isHookAgent(agent)) return undefined;
  return { agent, ok: true, eventId, tool };
}

function wrap(
  r: { stdout: string; exitCode: number; stderr?: string },
  extra: Omit<HookResult, "stdout" | "exitCode">,
): HookResult {
  return {
    stdout: r.stdout,
    exitCode: r.exitCode,
    ...(r.stderr !== undefined ? { stderr: r.stderr } : {}),
    ...extra,
  };
}

const STDOUT_CONFIRM_MS = 400;

export type StdoutWriteResult = { ok: true } | { ok: false; error: "stdout_error" | "stdout_timeout" };

type ConfirmStream = Pick<NodeJS.WritableStream, "write"> & {
  on?: (event: "error", listener: (err: Error) => void) => unknown;
  destroyed?: boolean;
};

/** Wait for write callback or stream error, bounded by remaining hook budget. Empty chunk still confirms. */
export function writeStdoutConfirmed(
  stream: ConfirmStream,
  data: string,
  timeoutMs: number,
): Promise<StdoutWriteResult> {
  if (timeoutMs <= 0) {
    try {
      stream.write(data);
    } catch {
      /* confirmation already failed */
    }
    return Promise.resolve({ ok: false, error: "stdout_timeout" });
  }
  if (stream.destroyed) return Promise.resolve({ ok: false, error: "stdout_error" });
  return new Promise((resolve) => {
    let settled = false;
    const onError = (_err: Error) => finish({ ok: false, error: "stdout_error" });
    const finish = (result: StdoutWriteResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => finish({ ok: false, error: "stdout_timeout" }), timeoutMs);
    if (stream.on) stream.on("error", onError);
    try {
      stream.write(data, (err?: Error | null) => {
        if (err) finish({ ok: false, error: "stdout_error" });
        else finish({ ok: true });
      });
    } catch {
      finish({ ok: false, error: "stdout_error" });
    }
  });
}

function failedStatus(result: HookResult, error: string): StatusRecord | undefined {
  const rec = result.statusRecord;
  if (!rec) return undefined;
  return { agent: rec.agent, ok: false, eventId: rec.eventId, tool: rec.tool, error };
}

/**
 * Confirm stdout, then settle. Write error/timeout: no success receipt, no ok status.
 * Does not rewrite stdout. Empty stdout is a successful write.
 */
export async function emitHookStdoutThenSettle(opts: {
  stream: ConfirmStream;
  home: string;
  result: HookResult;
  timeoutMs: number;
  settle?: (args: { home: string; result: HookResult }) => Promise<void>;
}): Promise<StdoutWriteResult> {
  const written = await writeStdoutConfirmed(opts.stream, opts.result.stdout, opts.timeoutMs);
  if (written.ok && opts.result.stderr) {
    try {
      process.stderr.write(opts.result.stderr);
    } catch {
      /* stderr is best-effort after official stdout */
    }
  }
  const settle = opts.settle ?? settleHookAfterStdout;
  if (written.ok) {
    await settle({ home: opts.home, result: opts.result });
  } else {
    await settle({
      home: opts.home,
      result: {
        ...opts.result,
        pendingReceipt: undefined,
        statusRecord: failedStatus(opts.result, written.error),
      },
    });
  }
  return written;
}

/**
 * After official stdout has been written: merge-lock hook-status for this agent, then bounded receipt.
 * Does not claim the host Agent executed deny — only that this adapter produced stdout.
 */
export async function settleHookAfterStdout(opts: {
  home: string;
  result: HookResult;
}): Promise<void> {
  const remaining = () => Math.max(0, HOOK_BUDGET_MS - (Date.now() - opts.result.startedAt));
  const rec = opts.result.statusRecord;
  if (rec) {
    const ms = Math.min(HOOK_LOCK_MS, remaining());
    if (ms >= 20) {
      try {
        await withFileLock(
          join(opts.home, ".nmzp"),
          async () => {
            recordHookOutcome(opts.home, rec.agent, {
              ok: rec.ok,
              eventId: rec.eventId,
              tool: rec.tool,
              error: rec.error,
            });
          },
          { timeoutMs: ms },
        );
      } catch {
        /* status must not rewrite stdout */
      }
    }
  }
  const pending = opts.result.pendingReceipt;
  if (pending) {
    const ms = Math.min(HOOK_RECEIPT_MS, remaining());
    if (ms >= 20) await sendReceipt(pending.creds, pending.eventId, pending.evaluation, pending.enforcement, ms);
  }
}

export async function runHook(opts: HookRunOpts): Promise<HookResult> {
  const t0 = Date.now();
  const remaining = () => Math.max(0, HOOK_BUDGET_MS - (Date.now() - t0));
  const flags = parseArgv(opts.argv);
  const home = opts.home ?? process.env.NMZP_HOME ?? homedir();
  const base = { startedAt: t0 };
  const env = opts.env ?? process.env;
  if (isGrokHostedClaudeCompat(flags.agent, env)) {
    return { stdout: "", exitCode: 0, startedAt: t0 };
  }
  const flaggedAgent = isHookAgent(flags.agent) ? flags.agent : "grok";
  const failStatus = (error: string): HookResult =>
    wrap(deny(flaggedAgent, error), { ...base, statusRecord: { agent: flaggedAgent, ok: false, error } });
  if (opts.stdin.length > BODY_LIMIT) return failStatus("payload_too_large");
  const parsed = parseHookEvent(opts.stdin);
  if (!parsed) return failStatus("bad_hook_json");
  if (isForeignHostPayload(flags.agent, parsed)) {
    return { stdout: "", exitCode: 0, startedAt: t0 };
  }
  const agent = detectHookAgent(flags.agent, parsed);
  const argMap = parsed.hostArgMap;
  const eventName = flags.event ?? parsed.eventName;
  if (/^(post|after)/i.test(eventName) || eventName.toLowerCase().includes("post")) {
    return { stdout: "", exitCode: 0, startedAt: t0 };
  }
  if (agent === "codex" && parsed.eventName !== "PreToolUse") return {stdout:"",exitCode:0,startedAt:t0};
  if (agent === "codex" && (parsed.toolName === "Bash" || parsed.toolName === "apply_patch") && typeof parsed.toolInput.command !== "string") return failStatus("missing_tool_command");
  const fields = toolInputToEvalFields(parsed.toolName, parsed.toolInput);
  const creds = await loadCreds(home);
  const cachePath = join(home, ".nmzp", "policy-cache.json");
  let cache = await readPolicyCache(cachePath);
  const eventId = parsed.eventId || newEventId();
  const evalBody = {
    eventId,
    permissionMode:parsed.permissionMode,
    uploadSize:await observeUploadSize(fields.command??"",parsed.cwd),
    sessionId: parsed.sessionId,
    agent: flags.agent ?? (agent === "unknown" ? undefined : agent),
    source: "hook" as const,
    tool_name: parsed.toolName,
    tool_input: parsed.toolInput,
    nativeTool: parsed.toolName,
    command: fields.command,
    file_path: fields.filePath,
    url: fields.url,
    dest: fields.dest,
    cwd: parsed.cwd,
    contents: fields.contents,
  };
  const markInput: Record<string, unknown> = {
    deviceId: creds?.deviceId,
    agent: evalBody.agent,
    sessionId: evalBody.sessionId,
    eventId,
    command: fields.command ?? "",
    filePath: fields.filePath ?? "",
    nativeTool: parsed.toolName,
    dest: fields.dest,
    url: fields.url,
    source: "hook",
  };
  const stamped = (r: { stdout: string; exitCode: number; stderr?: string }, extra?: Partial<HookResult>): HookResult =>
    wrap(r, {
      startedAt: t0,
      statusRecord: statusFor(agent, eventId, parsed.toolName),
      ...extra,
    });

  const rememberOnline = async (decision: string) => {
    const ms = Math.min(HOOK_LOCK_MS, remaining());
    if (ms < 30) return;
    try {
      await persistLocalMark({
        home,
        coreDir: opts.coreDir,
        input: markInput,
        result: { skipped: false, tool: parsed.toolName, decision },
        timeoutMs: ms,
      });
    } catch {
      /* online decision already from CT; mark persist must not rewrite stdout */
    }
  };

  /** Cached stop: never POST tool bodies. Only GET /policy to recover. */
  if (cache?.stopped) {
    if (creds) {
      const ctMs = Math.min(HOOK_CT_MS, remaining());
      if (ctMs > 50) {
        try {
          const res = await pinnedHttps({
            url: `${creds.url}/api/v1/policy`,
            method: "GET",
            headers: { authorization: `Bearer ${creds.token}` },
            caPem: creds.caPem,
            fingerprintSha256: creds.fingerprintSha256,
            timeoutMs: ctMs,
          });
          if (res.status === 200) {
            const pol = JSON.parse(res.body || "{}") as {
              version?: number;
              mode?: string;
              stopped?: boolean;
              customRules?: unknown;
              archiveUpload?: unknown;
              githubUpload?: unknown;
              overrides?: unknown;
              exemptions?: unknown;
            };
            if (pol.stopped !== true && typeof pol.version === "number") {
              const mode =
                pol.mode === "enforcing" || pol.mode === "permissive" || pol.mode === "off" ? pol.mode : "enforcing";
              cache = {
                version: pol.version,
                archiveUpload:archivePolicy(pol.archiveUpload),
                githubUpload:githubPolicy(pol.githubUpload),
                mode,
                customRules: Array.isArray(pol.customRules) ? (pol.customRules as typeof cache.customRules) : [],
                stopped: false,
                updatedAt: Date.now(),
                overrides: policyOverrides(pol.overrides),
                exemptions: policyExemptions(pol.exemptions),
              };
              await writePolicyCache(cachePath, cache);
            } else {
              return stamped(pass(agent, "processing_stopped", undefined, argMap));
            }
          } else {
            return stamped(pass(agent, "processing_stopped", undefined, argMap));
          }
        } catch {
          return stamped(pass(agent, "processing_stopped", undefined, argMap));
        }
      } else {
        return stamped(pass(agent, "processing_stopped", undefined, argMap));
      }
    } else {
      return stamped(pass(agent, "processing_stopped", undefined, argMap));
    }
  }

  if (creds && !cache?.stopped) {
    try {
      const ctMs = Math.min(HOOK_CT_MS, remaining());
      if (ctMs > 50) {
        const res = await pinnedHttps({
          url: `${creds.url}/api/v1/evaluate`,
          method: "POST",
          body: JSON.stringify(evalBody),
          headers: { "content-type": "application/json", authorization: `Bearer ${creds.token}` },
          caPem: creds.caPem,
          fingerprintSha256: creds.fingerprintSha256,
          timeoutMs: ctMs,
        });
        const interpreted = interpretEvaluateResponse(res.status, res.body);
        if (interpreted.action === "stopped") {
          await writePolicyCache(cachePath, {
            version: interpreted.policyVersion ?? cache?.version ?? 1,
            mode: "off",
            customRules: cache?.customRules ?? [],
            archiveUpload:archivePolicy(cache?.archiveUpload),
            githubUpload:githubPolicy(cache?.githubUpload),
            stopped: true,
            updatedAt: Date.now(),
            overrides: cache?.overrides,
            exemptions: cache?.exemptions,
          });
          return stamped(pass(agent, "processing_stopped", undefined, argMap));
        }
        if (interpreted.action === "deny") {
          await rememberOnline("block");
          return stamped(deny(agent, interpreted.reason, argMap), {
            pendingReceipt: creds
              ? { creds, eventId, evaluation: interpreted.evaluation, enforcement: "returned_deny" }
              : undefined,
          });
        }
        if (interpreted.action === "allow") {
          await rememberOnline(interpreted.evaluation);
          return stamped(pass(agent, interpreted.reason, interpreted.updatedInput, argMap), {
            pendingReceipt: {
              creds,
              eventId,
              evaluation: interpreted.evaluation,
              enforcement: "delivered",
            },
          });
        }
      }
    } catch {
      /* network: cache */
    }
  }

  if (cache?.stopped) {
    return stamped(pass(agent, "processing_stopped", undefined, argMap));
  }
  if (!cache) {
    const tool = parsed.toolName;
    if (NEED_CHECK_TOOLS.has(tool) || /command|write|edit|patch|fetch|bash|shell/i.test(tool)) {
      return stamped(deny(agent, "no_policy_cache", argMap));
    }
    return stamped(pass(agent, "no_cache_low_risk", undefined, argMap));
  }
  const lockMs = Math.min(HOOK_LOCK_MS, remaining());
  if (lockMs < 30) {
    if (NEED_CHECK_TOOLS.has(parsed.toolName)) return stamped(deny(agent, "budget", argMap));
    return stamped(pass(agent, "budget_low_risk", undefined, argMap));
  }
  const monitor = await loadMonitor(opts.coreDir);
  const windows = new FileSessionWindows(join(home, ".nmzp", "window-cache.json"), monitor);
  const device: DeviceRecord = {
    id: creds?.deviceId ?? "local",
    tokenHash: "",
    hostname: "local",
    ip: "",
    user: "",
    os: "win32",
    attachedAt: 0,
    lastSeen: Date.now(),
    lastPolicyVersion: cache.version,
    capabilities: [],
    agents: [],
  };
  let out: ReturnType<typeof applyEvaluate>;
  try {
    out = await windows.transact(
      () =>
        applyEvaluate({
          monitor,
          windows,
          policy: cache!,
          device,
          body: evalBody,
          eventId,
          degraded: true,
        }),
      lockMs,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "offline_eval_failed";
    return stamped(deny(agent, msg === "lock_timeout" ? "lock_timeout" : "offline_eval_failed", argMap));
  }
  if (out.hookDeny) return stamped(deny(agent, out.response.reason, argMap));
  if (out.response.decision === "rewrite" && !out.response.updatedInput) {
    return stamped(deny(agent, "rewrite_missing_updated_input", argMap));
  }
  return stamped(pass(agent, out.response.reason, out.response.updatedInput, argMap));
}

export async function hookMain(argv: string[], coreDir: string): Promise<void> {
  const t0 = Date.now();
  const remaining = () => Math.max(0, Math.min(STDOUT_CONFIRM_MS, HOOK_BUDGET_MS - (Date.now() - t0)));
  const flags = parseArgv(argv);
  const flaggedAgent = isHookAgent(flags.agent) ? flags.agent : "grok";
  const home = process.env.NMZP_HOME ?? homedir();
  const stdin = await readStdin();
  if (isGrokHostedClaudeCompat(flags.agent)) {
    await emitHookStdoutThenSettle({
      stream: process.stdout,
      home,
      timeoutMs: remaining(),
      result: { stdout: "", exitCode: 0, startedAt: t0 },
    });
    process.exitCode = 0;
    return;
  }
  if (!stdin.ok) {
    const r = deny(flaggedAgent, "payload_too_large");
    await emitHookStdoutThenSettle({
      stream: process.stdout,
      home,
      timeoutMs: remaining(),
      result: {
        stdout: r.stdout,
        exitCode: r.exitCode,
        startedAt: t0,
        statusRecord: { agent: flaggedAgent, ok: false, error: "payload_too_large" },
      },
    });
    process.exitCode = r.exitCode;
    return;
  }
  const r = await runHook({ argv, stdin: stdin.text, coreDir, home });
  await emitHookStdoutThenSettle({
    stream: process.stdout,
    home,
    result: r,
    timeoutMs: Math.max(0, Math.min(STDOUT_CONFIRM_MS, HOOK_BUDGET_MS - (Date.now() - r.startedAt))),
  });
  process.exitCode = r.exitCode;
}
