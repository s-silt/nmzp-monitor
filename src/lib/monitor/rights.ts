/**
 * The user is the controller. Processing stays on their CT.
 * Implements the substance of GDPR Arts. 15–21 and PIPL Arts. 44–47:
 * access, copy/export, rectification via rules, erasure, restrict/object.
 * Not a certification.
 */
import type { AuditEvent, CustomPrivacyRule, Machine, NetworkHop } from "./types.ts";

export const CROSS_BORDER = false;

export const LEGAL_BASIS = {
  controller: "user",
  purpose: "prevent listed coding agents from sending local privacy off-box",
  gdpr: ["15", "16", "17", "18", "20", "21"],
  pipl: ["44", "45", "46", "47"],
} as const;

export const DATA_CATEGORIES = [
  "agent_events",
  "network_hops",
  "machine_inventory",
  "custom_rules",
] as const;

export interface PortableEvent {
  id: string;
  ts: number;
  machineId: string;
  agent: string;
  tool: string;
  redacted: string;
  risk: string;
  decision: string;
  ruleId?: string;
  dest?: string;
  actor?: string;
  threat?: string;
}

export interface RightsBundle {
  version: 1;
  exportedAt: number;
  crossBorder: false;
  basis: typeof LEGAL_BASIS;
  categories: typeof DATA_CATEGORIES;
  events: PortableEvent[];
  hops: Array<{ ts: number; dest: string; machineId?: string }>;
  machines: Array<{ id: string; hostname: string; ip: string; os: string }>;
  rules: CustomPrivacyRule[];
}

export function portableEvent(e: AuditEvent): PortableEvent {
  return {
    id: e.id,
    ts: e.ts,
    machineId: e.machineId,
    agent: e.agent,
    tool: e.tool,
    redacted: e.redacted,
    risk: e.risk,
    decision: e.decision,
    ruleId: e.ruleId,
    dest: e.dest,
    actor: e.actor,
    threat: e.threat,
  };
}

export function exportBundle(input: {
  events: AuditEvent[];
  hops: NetworkHop[];
  machines: Machine[];
  customRules: CustomPrivacyRule[];
}): RightsBundle {
  return {
    version: 1,
    exportedAt: Date.now(),
    crossBorder: false,
    basis: LEGAL_BASIS,
    categories: DATA_CATEGORIES,
    events: input.events.map(portableEvent),
    hops: input.hops.map((h) => ({
      ts: h.ts,
      dest: h.hostname,
      machineId: h.machineId,
    })),
    machines: input.machines.map((m) => ({ id: m.id, hostname: m.hostname, ip: m.ip, os: m.os })),
    rules: input.customRules,
  };
}

export function bundleOmitsRawInput(json: string) {
  const parsed = JSON.parse(json) as RightsBundle;
  return parsed.events.every((e) => !("input" in e) && typeof e.redacted === "string");
}
