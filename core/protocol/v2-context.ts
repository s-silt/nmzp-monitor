/** Candidate boundary helpers only. No HTTP route is wired by this module. */
import { parseUploadSize, permissionMode } from "../egress-schema.ts";
import type { AdapterContext, CanonicalToolEvent } from "./v2-adapter.ts";

/** Implementation revision of the existing core adapter, not a verified host version. */
export const SERVER_ADAPTER_REVISION = 1;

function observedTime(now: number): string {
  if (!Number.isSafeInteger(now) || now <= 0) throw new Error("invalid_observation_time");
  const value = new Date(now).toISOString();
  if (value.startsWith("1970-")) throw new Error("placeholder_observation_time");
  return value;
}

/** Only call with the device resolved from the bearer token, never with a body id. */
export function serverAdapterContext(deviceId: string, eventId: string, now = Date.now()): AdapterContext {
  if (!deviceId || deviceId === "UNOBSERVED_DEVICE") throw new Error("invalid_authenticated_device");
  return { deviceId, eventId, occurredAt: observedTime(now), adapterRevision: SERVER_ADAPTER_REVISION };
}

/** Match identity without overwriting or laundering device-declared time/revision. */
export function canonicalDeviceMatches(event: CanonicalToolEvent, authenticatedDeviceId: string): boolean {
  return authenticatedDeviceId.length > 0 && authenticatedDeviceId !== "UNOBSERVED_DEVICE"
    && event.device.id === authenticatedDeviceId;
}

/** The legacy input is already resolved at the application boundary; no host re-parsing here. */
export function legacyCanonicalContext(
  origin: CanonicalToolEvent["origin"],
  body: { proc?: unknown; parentProc?: unknown; hookBlind?: unknown; permissionMode?: unknown; uploadSize?: unknown },
  now = Date.now(),
): CanonicalToolEvent["context"] {
  const mode = permissionMode(body.permissionMode) as CanonicalToolEvent["context"]["permissionMode"];
  const uploadSize = parseUploadSize(body.uploadSize, now);
  return {
    proc: typeof body.proc === "string" && body.proc.trim() ? body.proc.trim() : null,
    parentProc: typeof body.parentProc === "string" && body.parentProc.trim() ? body.parentProc.trim() : null,
    hookBlind: origin === "BACKFILL" || (origin === "PROBE" && body.hookBlind === true),
    ...(mode === undefined ? {} : { permissionMode: mode }),
    ...(uploadSize === undefined ? {} : { uploadSize }),
  };
}
