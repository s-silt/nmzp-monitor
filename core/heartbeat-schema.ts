import type { Capability } from "./schema.ts";

/**
 * Ingress bounds measured against probe.ts heartbeats.
 * assembleProbeReport emits 18 capabilities; the longest id is "hook_antigravity" (17).
 * Discovery keeps at most 128 items, and agentsFromDiscovery dedupes them.
 * POSIX HOST_NAME_MAX is 255; join stores hostname/user/ip at 80/64/64.
 * hookCapability folds gateError into error, and safeErrorCode caps that string at 64.
 * Capability ids use the viewer's short-id grammar so one stored id cannot blank LAN state.
 * That grammar is not a catalog allowlist. Body size stays BODY_LIMIT.
 */
export const HEARTBEAT_LIMITS = {
  labelChars: 256,
  agentCount: 256,
  agentChars: 256,
  capabilityCount: 256,
  capabilityIdChars: 48,
  errorChars: 1024,
} as const;

export const HEARTBEAT_CAPABILITY_ID = new RegExp(
  `^[A-Za-z][A-Za-z0-9_-]{0,${HEARTBEAT_LIMITS.capabilityIdChars - 1}}$`,
);

export type HeartbeatFields = {
  hostname?: string;
  user?: string;
  ip?: string;
  agents?: string[];
  capabilities?: Capability[];
  policyVersion?: number;
  pollOnly?: boolean;
  stoppedAck?: boolean;
};

export type HeartbeatParse =
  | { ok: true; fields: HeartbeatFields }
  | { ok: false; error: "bad_heartbeat" };

const BAD_HEARTBEAT: HeartbeatParse = { ok: false, error: "bad_heartbeat" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function supplied(body: Record<string, unknown>, key: string): boolean {
  return Object.hasOwn(body, key) && body[key] !== undefined;
}

/** Known Capability keys only. Invalid evidence is omitted, never returned active. */
export function parseCapabilityEntry(value: unknown): Capability | undefined {
  if (!isRecord(value)) return undefined;
  const { id, supported, active } = value;
  if (typeof id !== "string" || !HEARTBEAT_CAPABILITY_ID.test(id)) return undefined;
  if (typeof supported !== "boolean" || typeof active !== "boolean") return undefined;
  const cap: Capability = { id, supported, active };
  if (supplied(value, "lastSuccess")) {
    if (typeof value.lastSuccess !== "number" || !Number.isFinite(value.lastSuccess)) return undefined;
    cap.lastSuccess = value.lastSuccess;
  }
  if (supplied(value, "error")) {
    if (typeof value.error !== "string" || value.error.length > HEARTBEAT_LIMITS.errorChars) return undefined;
    cap.error = value.error;
  }
  return cap;
}

function readString(
  body: Record<string, unknown>,
  key: string,
  max: number,
): { ok: true; value?: string } | { ok: false } {
  if (!supplied(body, key)) return { ok: true };
  const value = body[key];
  if (typeof value !== "string" || value.length > max) return { ok: false };
  return { ok: true, value };
}

function readBoolean(
  body: Record<string, unknown>,
  key: string,
): { ok: true; value?: boolean } | { ok: false } {
  if (!supplied(body, key)) return { ok: true };
  if (typeof body[key] !== "boolean") return { ok: false };
  return { ok: true, value: body[key] as boolean };
}

/** Unknown top-level keys are ignored. Present basic fields must already have the right shape. */
export function parseHeartbeatBody(raw: unknown): HeartbeatParse {
  if (!isRecord(raw)) return BAD_HEARTBEAT;
  const hostname = readString(raw, "hostname", HEARTBEAT_LIMITS.labelChars);
  const user = readString(raw, "user", HEARTBEAT_LIMITS.labelChars);
  const ip = readString(raw, "ip", HEARTBEAT_LIMITS.labelChars);
  const pollOnly = readBoolean(raw, "pollOnly");
  const stoppedAck = readBoolean(raw, "stoppedAck");
  if (!hostname.ok || !user.ok || !ip.ok || !pollOnly.ok || !stoppedAck.ok) return BAD_HEARTBEAT;

  let policyVersion: number | undefined;
  if (supplied(raw, "policyVersion")) {
    if (typeof raw.policyVersion !== "number" || !Number.isFinite(raw.policyVersion)) return BAD_HEARTBEAT;
    policyVersion = raw.policyVersion;
  }

  let agents: string[] | undefined;
  if (supplied(raw, "agents")) {
    if (!Array.isArray(raw.agents) || raw.agents.length > HEARTBEAT_LIMITS.agentCount) return BAD_HEARTBEAT;
    agents = [];
    for (const item of raw.agents) {
      if (typeof item !== "string" || item.length > HEARTBEAT_LIMITS.agentChars) return BAD_HEARTBEAT;
      agents.push(item);
    }
  }

  let capabilities: Capability[] | undefined;
  if (supplied(raw, "capabilities")) {
    if (!Array.isArray(raw.capabilities) || raw.capabilities.length > HEARTBEAT_LIMITS.capabilityCount) {
      return BAD_HEARTBEAT;
    }
    capabilities = [];
    for (const item of raw.capabilities) {
      const cap = parseCapabilityEntry(item);
      if (!cap) return BAD_HEARTBEAT;
      capabilities.push(cap);
    }
  }

  const fields: HeartbeatFields = {};
  if (hostname.value !== undefined) fields.hostname = hostname.value;
  if (user.value !== undefined) fields.user = user.value;
  if (ip.value !== undefined) fields.ip = ip.value;
  if (agents) fields.agents = agents;
  if (capabilities) fields.capabilities = capabilities;
  if (policyVersion !== undefined) fields.policyVersion = policyVersion;
  if (pollOnly.value !== undefined) fields.pollOnly = pollOnly.value;
  if (stoppedAck.value !== undefined) fields.stoppedAck = stoppedAck.value;
  return { ok: true, fields };
}

export function projectStoredLabel(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export function projectStoredAgents(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const agents: string[] = [];
  for (const item of value) {
    if (typeof item === "string") agents.push(item);
  }
  return agents;
}

export function projectStoredCapabilities(value: unknown): Capability[] {
  if (!Array.isArray(value)) return [];
  const capabilities: Capability[] = [];
  for (const item of value) {
    const cap = parseCapabilityEntry(item);
    if (cap) capabilities.push(cap);
  }
  return capabilities;
}
