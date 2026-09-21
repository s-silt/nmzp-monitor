import {githubTarget} from "./github-upload.ts";
import {egressOperation,egressInteraction,permissionMode,parseUploadSize,archivePolicy,githubPolicy,type EgressEvidence} from "./egress-schema.ts";
import { sha256Hex } from "./auth.ts";
import { BODY_LIMIT, NEED_CHECK_TOOLS } from "./constants.ts";
import type { MonitorMods } from "./paths.ts";
import type { DeviceRecord, PolicyState, StoredEvent } from "./schema.ts";
import { structuredRewrite, type PrivacyFns } from "./rewrite.ts";
import {
  ALIAS_CONFLICT,
  objectsConflict,
  pickDefinedSame,
  stableJson,
  toolInputHasAliasConflict,
  toolInputToEvalFields,
} from "./hook-protocol.ts";
import { extractDeclaredEndpoints, sanitizeAuditText, sanitizeStoredEvent } from "./network-evidence.ts";
import { policyExemptions, policyOverrides } from "./policy-schema.ts";

export interface EvalRequestBody {
  permissionMode?: string;
  uploadSize?: unknown;
  eventId?: string;
  sessionId?: string;
  session_id?: string;
  agent?: string;
  source?: string;
  tool?: string;
  tool_name?: string;
  toolName?: string;
  tool_input?: Record<string, unknown>;
  toolInput?: Record<string, unknown>;
  nativeTool?: string;
  command?: string;
  file_path?: string;
  filePath?: string;
  url?: string;
  cwd?: string;
  dest?: string;
  proc?: string;
  parentProc?: string;
  hookBlind?: boolean;
  contents?: string;
}

export interface EvalResponse {
  egress?: EgressEvidence;
  eventId: string;
  decision: string;
  reason: string;
  ruleIds: string[];
  policyVersion: number;
  summary: string;
  updatedInput?: Record<string, unknown>;
  enforcement: StoredEvent["enforcement"];
  duplicate?: boolean;
  degraded?: boolean;
  overrideSource?: "rule" | "family";
  exemptionId?: string;
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** Host only. Never persist userinfo/query or the original string on parse failure. */
export function redactDest(dest: string | undefined): string | undefined {
  if (!dest) return undefined;
  const t = dest.trim();
  if (!t) return undefined;
  const tryParse = (s: string): string | undefined => {
    try {
      const u = new URL(s);
      return u.hostname || undefined;
    } catch {
      return undefined;
    }
  };
  return tryParse(t) ?? (/^[a-z0-9.-]+$/i.test(t) ? t.slice(0, 253) : undefined);
}

export interface ResolvedEvalBody {
  conflict: boolean;
  nativeTool: string;
  command?: string;
  contents?: string;
  filePath?: string;
  url?: string;
  dest?: string;
  cwd?: string;
  proc?: string;
  parentProc?: string;
  hookBlind?: boolean;
  source: "probe" | "hook";
  agent?: string;
  sessionId?: string;
  toolInput: Record<string, unknown>;
}

export function resolveEvalBody(body: EvalRequestBody): ResolvedEvalBody {
  const empty: ResolvedEvalBody = {
    conflict: true,
    nativeTool: "unknown",
    source: "hook",
    toolInput: {},
  };
  const nativeTool = pickDefinedSame([str(body.tool_name), str(body.toolName), str(body.tool), str(body.nativeTool)]);
  if (nativeTool === ALIAS_CONFLICT) return empty;

  const sessionId = pickDefinedSame([str(body.sessionId), str(body.session_id)]);
  if (sessionId === ALIAS_CONFLICT) return empty;

  if (objectsConflict([body.tool_input, body.toolInput])) return empty;
  const toolInput = isPlain(body.tool_input) ? body.tool_input : isPlain(body.toolInput) ? body.toolInput : {};
  if (toolInputHasAliasConflict(toolInput)) return empty;

  const fields = toolInputToEvalFields(nativeTool || "unknown", toolInput);
  const command = pickDefinedSame([fields.command, str(body.command)]);
  const filePath = pickDefinedSame([fields.filePath, str(body.file_path), str(body.filePath)]);
  const url = pickDefinedSame([fields.url, str(body.url)]);
  const dest = pickDefinedSame([fields.dest, str(body.dest)]);
  const contents = pickDefinedSame([fields.contents, str(body.contents)]);
  if (
    command === ALIAS_CONFLICT ||
    filePath === ALIAS_CONFLICT ||
    url === ALIAS_CONFLICT ||
    dest === ALIAS_CONFLICT ||
    contents === ALIAS_CONFLICT
  ) {
    return empty;
  }

  // Envelope cwd = agent session workspace. tool_input working_directory = this
  // command's target dir (subdir is normal). Not aliases; command dir wins.
  const cwd = fields.cwd ?? str(body.cwd);

  return {
    conflict: false,
    nativeTool: nativeTool || fields.nativeTool || "unknown",
    command,
    contents,
    filePath,
    url,
    dest,
    cwd,
    proc: str(body.proc),
    parentProc: str(body.parentProc),
    hookBlind: body.hookBlind,
    source: body.source === "probe" ? "probe" : "hook",
    agent: str(body.agent),
    sessionId,
    toolInput,
  };
}

function rewriteSource(resolved: ResolvedEvalBody): Record<string, unknown> | undefined {
  const base: Record<string, unknown> = isPlain(resolved.toolInput) ? { ...resolved.toolInput } : {};
  if (resolved.command && base.command === undefined && base.cmd === undefined) base.command = resolved.command;
  if (resolved.url && base.url === undefined) base.url = resolved.url;
  if (resolved.dest && base.dest === undefined) base.dest = resolved.dest;
  if (
    resolved.filePath &&
    base.file_path === undefined &&
    base.filePath === undefined &&
    base.path === undefined &&
    base.target_file === undefined
  ) {
    base.file_path = resolved.filePath;
  }
  return Object.keys(base).length ? base : undefined;
}

export function requestFingerprint(body: EvalRequestBody): string {
  const resolved = resolveEvalBody(body);
  return sha256Hex(
    stableJson({
      permissionMode:permissionMode(body.permissionMode)??"unknown",
      conflict: resolved.conflict,
      sessionId: resolved.sessionId ?? "",
      agent: resolved.agent ?? "",
      source: resolved.source,
      nativeTool: resolved.nativeTool,
      toolInput: resolved.toolInput,
      command: resolved.command ?? "",
      contents: resolved.contents ?? "",
      filePath: resolved.filePath ?? "",
      url: resolved.url ?? "",
      dest: resolved.dest ?? "",
      cwd: resolved.cwd ?? "",
      envelopeCwd: str(body.cwd) ?? "",
      proc: resolved.proc ?? "",
      parentProc: resolved.parentProc ?? "",
      hookBlind: resolved.hookBlind === true,
      raw: resolved.conflict
        ? {
            tool_name: body.tool_name ?? "",
            toolName: body.toolName ?? "",
            tool: body.tool ?? "",
            nativeTool: body.nativeTool ?? "",
            url: body.url ?? "",
            dest: body.dest ?? "",
            file_path: body.file_path ?? "",
            filePath: body.filePath ?? "",
            cwd: body.cwd ?? "",
            proc: body.proc ?? "",
            parentProc: body.parentProc ?? "",
            source: body.source ?? "",
            command: body.command ?? "",
            contents: body.contents ?? "",
            tool_input: isPlain(body.tool_input) ? body.tool_input : {},
            toolInput: isPlain(body.toolInput) ? body.toolInput : {},
          }
        : undefined,
    }),
  );
}

export function buildEvalInput(body: EvalRequestBody, deviceId: string) {
  const resolved = resolveEvalBody(body);
  return {
    nativeTool: resolved.nativeTool,
    command: resolved.command,
    filePath: resolved.filePath,
    url: resolved.url,
    cwd: resolved.cwd,
    dest: resolved.dest,
    agent: resolved.agent,
    sessionId: resolved.sessionId,
    source: resolved.source,
    proc: resolved.proc,
    parentProc: resolved.parentProc,
    hookBlind: resolved.hookBlind,
    deviceId,
    eventId: body.eventId,
    contents: resolved.contents,
  };
}

export function mapNmzpDecision(decision: string): { hook: "allow" | "deny"; enforcement: StoredEvent["enforcement"] } {
  if (decision === "block" || decision === "confirm") return { hook: "deny", enforcement: "returned_deny" };
  return { hook: "allow", enforcement: "pending_verify" };
}

export function privacyFrom(mod: MonitorMods): PrivacyFns {
  return {
    REDACT_TAG: mod.privacy.REDACT_TAG as string,
    scanSecrets: mod.privacy.scanSecrets,
    scanCustom: mod.privacy.scanCustom,
    cloakPersona: mod.privacy.cloakPersona,
    shouldCloakPersona: mod.privacy.shouldCloakPersona,
  };
}

function conflictResponse(
  eventId: string,
  policy: PolicyState,
  device: DeviceRecord,
): { response: EvalResponse; event: StoredEvent; hookDeny: true } {
  const event: StoredEvent = {
    id: eventId,
    ts: Date.now(),
    machineId: device.id,
    agent: "grok",
    sessionId: "",
    layer: "app_pre",
    tool: "Bash",
    nativeTool: "unknown",
    input: "conflicting_aliases",
    risk: "high",
    decision: "block",
    workdirScope: "project",
    redacted: "conflicting_aliases",
    category: "other",
    secretKinds: [],
    source: "hook",
    policyVersion: policy.version,
    evaluation: "block",
    enforcement: "returned_deny",
  };
  return {
    response: {
      eventId,
      decision: "block",
      reason: "conflicting_aliases",
      ruleIds: [],
      policyVersion: policy.version,
      summary: "",
      enforcement: "returned_deny",
    },
    event,
    hookDeny: true,
  };
}

export function applyEvaluate(opts: {
  monitor: MonitorMods;
  windows: { apply: (input: unknown, result: unknown, intervention: unknown, ts?: number) => unknown };
  policy: PolicyState;
  device: DeviceRecord;
  body: EvalRequestBody;
  eventId: string;
  degraded?: boolean;
}): { response: EvalResponse; event: StoredEvent | null; hookDeny: boolean } {
  const { monitor, windows, policy, device, body, eventId } = opts;
  const resolved = resolveEvalBody(body);
  if (resolved.conflict) return conflictResponse(eventId, policy, device);

  const input = buildEvalInput(body, device.id);
  const toolInput = rewriteSource(resolved);
  const evaluated = monitor.evaluate(input, policy.mode, policy.customRules, {
    overrides: policyOverrides(policy.overrides),
    exemptions: policyExemptions(policy.exemptions),
  });
  const result = windows.apply(input, evaluated, policy.mode) as typeof evaluated;
  const p = privacyFrom(monitor);
  const scan = {
    scanSecrets: p.scanSecrets,
    scanCustom: p.scanCustom,
    customRules: policy.customRules,
  };
  const endpoints = extractDeclaredEndpoints({
    url: resolved.url,
    dest: resolved.dest,
    command: resolved.command,
    ...scan,
  });
  const audit = sanitizeAuditText(typeof result.redacted === "string" ? result.redacted : "", scan);
  let decision = result.decision as StoredEvent["decision"];
  let reason = result.rule?.id ?? (result.skipped ? "skipped" : decision);
  let updatedInput: Record<string, unknown> | undefined;
  let enforcement: StoredEvent["enforcement"] = "pending_verify";

  if (result.skipped) {
    return {
      response: {
        eventId,
        decision: "allow",
        reason: "out_of_scope",
        ruleIds: [],
        policyVersion: policy.version,
        summary: sanitizeAuditText(result.redacted || "", scan),
        enforcement: "delivered",
      },
      event: null,
      hookDeny: false,
    };
  }

  if (decision === "rewrite") {
    const rw = structuredRewrite(toolInput, policy.customRules, p);
    if (!rw.ok) {
      decision = "block";
      reason = rw.reason;
    } else if (stableJson(rw.updatedInput) === stableJson(toolInput ?? {})) {
      decision = "log";
      reason = "rewrite_noop";
      updatedInput = undefined;
    } else {
      updatedInput = rw.updatedInput;
    }
  }

  if (opts.degraded && NEED_CHECK_TOOLS.has(result.tool) && decision === "allow") {
    /* cache path already applied mode; keep */
  }

  let egress:EgressEvidence|undefined;
  const operation=result.storageAccess?"storage_access":result.tool==="Bash"?egressOperation(resolved.command??""):undefined;
  if(operation){
    const size=parseUploadSize(body.uploadSize),ap=archivePolicy(policy.archiveUpload);
    const fresh=size&&Date.now()-size.checkedAt<30000?size:undefined;
    const gp=githubPolicy(policy.githubUpload),target=(operation==="git_push"||operation==="upload")?githubTarget(resolved.command??""):"other";
    const github=target==="github"?(gp.mode==="unlimited"?"unlimited":gp.agents.includes(resolved.agent??"")?"agent_allowed":"agent_denied"):target==="unknown"?"target_unknown":undefined;
    const ghDeny=gp.mode==="selected"&&!gp.agents.includes(resolved.agent??"")&&(target==="github"||operation==="git_push"&&target==="unknown");
    const large=github!=="unlimited"&&(operation==="upload"||operation==="storage_access")&&fresh?.status==="observed"&&fresh.bytes!>ap.thresholdMiB*1024*1024;
    egress={observationOnly:true,operation,interaction:egressInteraction(resolved.agent,body.permissionMode,resolved.source,resolved.hookBlind),
      authorization:policy.mode!=="enforcing"?"policy_inactive":decision==="block"?"risk_blocked":operation==="local_archive"?"not_required":"not_observed",
      uploadSize:fresh,archivePolicy:ap,github,
      basis:result.storageAccess?"storage_endpoint":ghDeny?"github_agent":large?"large_archive":result.correlateHit?"correlation":operation==="local_archive"?"local_only":"existing_policy"};
  }

  const event: StoredEvent = {
    id: eventId,
    ts: Date.now(),
    machineId: device.id,
    agent: typeof input.agent === "string" ? input.agent : "grok",
    sessionId: typeof input.sessionId === "string" ? input.sessionId : "",
    layer: input.source === "probe" ? "kernel_exec" : "app_pre",
    tool: result.tool,
    nativeTool: input.nativeTool,
    egress,
    input: audit,
    risk: result.risk,
    decision,
    ruleId: result.rule?.id,
    category: result.category,
    workdirScope: result.workdirScope,
    dest: endpoints[0]?.host,
    endpoints,
    redacted: audit,
    threat: result.threat,
    secretKinds: result.secretKinds,
    detectedModel: result.detectedModel,
    source: input.source,
    hookBlind: input.hookBlind,
    correlateHit: result.correlateHit,
    actor: result.actor,
    proc: typeof input.proc === "string" ? input.proc : undefined,
    rewritten: decision === "rewrite",
    policyVersion: policy.version,
    evaluation: decision,
    enforcement,
    overrideSource: result.overrideSource,
    exemptionId: result.exemptionId,
    dryRunKinds: result.dryRunKinds,
    degraded: opts.degraded,
  };
  const stored = sanitizeStoredEvent(event, scan);

  return {
    response: {
      eventId,
      decision,
      reason,
      ruleIds: result.rule?.id ? [result.rule.id] : [],
      policyVersion: policy.version,
      summary: stored.redacted,
      egress,
      updatedInput,
      enforcement,
      degraded: opts.degraded,
      overrideSource: result.overrideSource,
      exemptionId: result.exemptionId,
    },
    event: stored,
    hookDeny: decision === "block",
  };
}

export function reconstructRewrite(body: EvalRequestBody, customRules: PolicyState["customRules"], p: PrivacyFns) {
  const resolved = resolveEvalBody(body);
  if (resolved.conflict) return { ok: false as const, reason: "conflicting_aliases" };
  return structuredRewrite(rewriteSource(resolved), customRules, p);
}

export function oversizeReject(): { status: number; body: { ok: false; error: string } } {
  return { status: 413, body: { ok: false, error: "payload_too_large" } };
}

export { BODY_LIMIT };
