import {publicProbeProtection} from "./probe-auth.ts";
import {parseDiscovery} from "./agent-discovery-schema.ts";
import type { NmzpStore } from "./persist.ts";
import { publicNetworkHistory, publicNetworkSample, sanitizeStoredEvent } from "./network-evidence.ts";

export function exportBundleShape(store: NmzpStore) {
  const events = store.listEvents().map((e) => {
    const c = sanitizeStoredEvent(e);
    return {
      id: c.id,
      egress:c.egress,layer:c.layer,source:c.source,category:c.category,workdirScope:c.workdirScope,response:c.response,
      ts: c.ts,
      machineId: c.machineId,
      agent: c.agent,
      sessionId: c.sessionId,
      tool: c.tool,
      nativeTool: c.nativeTool,
      redacted: c.redacted,
      risk: c.risk,
      decision: c.decision,
      ruleId: c.ruleId,
      dest: c.dest,
      endpoints: c.endpoints,
      actor: c.actor,
      threat: c.threat,
      enforcement: c.enforcement,
      requestHash: c.requestHash,
      policyVersion: c.policyVersion,
      proc: c.proc,
    };
  });
  const machines = store.listDevices().map((d) => ({
    id: d.id,
    hostname: d.hostname,
    ip: d.ip,
    os: d.os,
    status: d.status,
    ...(d.network ? { network: publicNetworkSample(d.network) } : {}),
    discovery:parseDiscovery(d.discovery),
    probeProtection:publicProbeProtection(d.probeBinding),
  }));
  const eventEndpoints: Record<string, NonNullable<(typeof events)[number] extends never ? never : import("./schema.ts").StoredEvent["endpoints"]>> = {};
  for (const e of store.listEvents()) {
    if (e.endpoints !== undefined) eventEndpoints[e.id] = e.endpoints;
  }
  const deviceNetwork: Record<string, NonNullable<ReturnType<typeof publicNetworkSample>>> = {};
  for (const d of store.listDevices()) {
    const network = publicNetworkSample(d.network);
    if (network) deviceNetwork[d.id] = network;
  }
  return {
    version: 1 as const,
    evidenceWindow: store.evidenceWindow(),
    exportedAt: Date.now(),
    timestampOffset: "+08:00" as const,
    timezone: "Asia/Shanghai" as const,
    crossBorder: false as const,
    categories: ["agent_events", "machine_inventory", "custom_rules", "network_connections", "policy_overrides"],
    events,
    hops: [] as Array<{ ts: number; dest: string }>,
    eventEndpoints,
    deviceNetwork,
    networkHistory: publicNetworkHistory(store.listNetworkHistory()),
    machines,
    rules: store.getPolicy().customRules,
    policy: {
      version: store.getPolicy().version,
      mode: store.getPolicy().mode,
      overrides: store.getPolicy().overrides,
      exemptions: store.getPolicy().exemptions,
    },
  };
}
