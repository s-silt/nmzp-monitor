import {parseResponseEvidence} from "./response-evidence.ts";
import type { ModelGatewayEvent } from "./model-gateway.ts";
import type { NmzpStore } from "./persist.ts";
/** Trusted in-process controller adapter, never a public agent self-attestation route. */
export async function storeResponseObservation(
  store: NmzpStore,
  binding: { machineId: string; sessionId: string; agent: string; proc?: string },
  event: ModelGatewayEvent,
): Promise<void> {
  const report = event.responseObservation;
  if (!report || !event.requestId || (!report.findings.length && report.coverage === "complete" && event.transport?.outcome === "complete"))
    return;
  const response = parseResponseEvidence({
    ruleVersion: report.ruleVersion,
    coverage: report.coverage,
    action: report.action,
    transport: event.transport ?? {upstreamComplete:false,clientWriteComplete:false,outcome:"unknown"},
    observationRecorded: true,
    findings: report.findings,
  });
  if (!response) throw new Error("invalid_response_evidence");
  const summary = JSON.stringify(response);
  await store.appendEvent({
    response,
    id: "response_" + event.requestId,
    ts: event.t,
    machineId: binding.machineId,
    sessionId: binding.sessionId,
    agent: binding.agent,
    proc: binding.proc,
    layer: "model_response",
    tool: "ModelResponse",
    nativeTool: "chat/completions",
    input: summary,
    redacted: summary,
    risk: report.findings.length ? "high" : "medium",
    decision: "log",
    evaluation: "log",
    ruleId: report.ruleVersion,
    category: "other",
    workdirScope: "controlled_session",
    dest: event.upstreamHost,
    source: "trusted_gateway_response",
    actor: "relay",
    threat: report.findings.length ? "poison" : undefined,
    enforcement: event.transport?.outcome === "complete" && event.transport.upstreamComplete && event.transport.clientWriteComplete ? "delivered" : event.transport?.outcome === "timeout" ? "timeout" : "failed",
    policyVersion: store.getPolicy().version,
  });
}
