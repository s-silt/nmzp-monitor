/** Fixed messages for device-route failures. Never reflect exception/request text. */
import { v2AccessError, v2Error } from "./v2-error.ts";

export function v2DeviceError(code: string, requestId: string) {
  switch (code) {
    case "unauthorized": return v2AccessError("unauthorized", requestId).body;
    case "forbidden": return v2AccessError("forbidden", requestId).body;
    case "not_found": return v2AccessError("not_found", requestId).body;
    case "payload_too_large": return v2Error("payload_too_large", { message: "The request body is too large.", requestId });
    case "bad_schema": return v2Error("bad_schema", { message: "The evaluation request is invalid.", requestId });
    case "bad_json": return v2Error("bad_json", { message: "The request body is not valid JSON.", requestId });
    case "bad_receipt": return v2Error("bad_receipt", { message: "The receipt is invalid.", requestId });
    case "bad_backfill": return v2Error("bad_backfill", { message: "The backfill is invalid.", requestId });
    case "bad_heartbeat": return v2Error("bad_heartbeat", { message: "The heartbeat is invalid.", requestId });
    case "probe_proof_required": return v2Error("probe_proof_required", { message: "A valid probe proof is required.", requestId });
    case "evaluation_immutable": return v2Error("evaluation_immutable", { message: "The recorded evaluation cannot be changed.", requestId });
    case "storage_not_enabled": return v2Error("storage_not_enabled", { message: "Audit storage is not enabled.", requestId });
    case "processing_stopped": return v2Error("processing_stopped", { message: "Processing is stopped.", requestId });
    case "conflict": return v2Error("conflict", { message: "The final receipt enforcement cannot be changed.", requestId });
    case "event_conflict": return v2Error("event_conflict", { message: "The event conflicts with its recorded request.", requestId });
    case "event_protocol_incompatible": return v2Error("event_protocol_incompatible", { message: "The event must use its original evaluation protocol.", requestId });
    case "evaluation_replay_unavailable": return v2Error("evaluation_replay_unavailable", { message: "The historical evaluation cannot be replayed.", requestId });
    case "evaluation_result_too_large": return v2Error("evaluation_result_too_large", { message: "The evaluation response exceeds the supported size.", requestId });
    case "event_expired": return v2Error("event_expired", { message: "The event has expired.", requestId });
    case "policy_recovery_required": return v2Error("policy_recovery_required", { message: "Policy recovery is required.", requestId });
    case "policy_not_committed": return v2Error("policy_not_committed", { message: "The policy was not committed.", requestId });
    case "policy_queue_full": return v2Error("policy_queue_full", { message: "The policy queue is full.", requestId });
    case "audit_storage_unavailable": return v2Error("audit_storage_unavailable", { message: "Audit storage is unavailable.", requestId });
    default: return v2Error("internal_error", { message: "The request could not be completed.", requestId });
  }
}
