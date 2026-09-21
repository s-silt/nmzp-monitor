import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  NETWORK_STALE_MS,
  collectTcpRows,
  connectionKey,
  declaredTargets,
  dedupConnections,
  evidenceExport,
  eventOssHosts,
  eventSearchText,
  decisionMsg,
  enforcementMsg,
  filterDeclaredEvents,
  formatSocket,
  hostLike,
  isHighRiskOss,
  isNetworkRelevantEvent,
  tcpEmptyKind,
  isLiveSample,
  isSynSent,
  networkExportPayload,
  ossShapeOf,
  sampleStatusKey,
  sampleView,
  sameHostNotProvenDns,
  scopedHistory,
  tcpStateLabel,
  visibleDestinations,
} from "./network-view.ts";
import type { AuditEvent, Machine, NetworkConnection, NetworkHistoryRow } from "./types.ts";

const NOW = 1_700_000_090_000;

function machine(over: Partial<Machine> = {}): Machine {
  return {
    id: "m_a",
    hostname: "pc-a",
    ip: "10.0.0.2",
    user: "u",
    os: "win32",
    lastSeen: NOW,
    attachedAt: NOW - 60_000,
    status: "online",
    ...over,
  };
}

function conn(over: Partial<NetworkConnection> = {}): NetworkConnection {
  return {
    remoteIp: "198.51.100.9",
    remotePort: 443,
    localIp: "10.0.0.2",
    localPort: 51500,
    state: "Established",
    role: "egress",
    observedAt: NOW - 1_000,
    pid: 4400,
    ppid: 1,
    processStartedAt: NOW - 30_000,
    bin: "grok.exe",
    agent: "grok",
    ...over,
  };
}

function event(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: "e_1",
    ts: NOW - 2_000,
    machineId: "m_a",
    agent: "grok",
    sessionId: "s_1",
    layer: "app_pre",
    tool: "Bash",
    nativeTool: "bash",
    input: "curl https://example.com",
    risk: "info",
    decision: "log",
    category: "network",
    workdirScope: "project",
    redacted: "curl https://example.com",
    ...over,
  };
}

function hist(over: Partial<NetworkHistoryRow> = {}): NetworkHistoryRow {
  return {
    id: "net_aaaaaa",
    machineId: "m_a",
    agent: "grok",
    pid: 4400,
    ppid: 1,
    processStartedAt: NOW - 30_000,
    bin: "grok.exe",
    remoteIp: "198.51.100.9",
    remotePort: 443,
    localIp: "10.0.0.2",
    localPort: 51500,
    state: "Established",
    role: "egress",
    firstSeen: NOW - 20_000,
    lastSeen: NOW - 1_000,
    ...over,
  };
}

describe("sampleView status and age", () => {
  it("treats missing report as not collected, not sampled zero", () => {
    const v = sampleView(machine(), NOW);
    assert.equal(v.status, "missing");
    assert.equal(sampleStatusKey(v.status), "notCollected");
    assert.equal(v.connections.length, 0);
  });

  it("ok with empty connections is sampled zero only", () => {
    const v = sampleView(
      machine({
        network: { status: "ok", observedAt: NOW - 1_000, connections: [] },
      }),
      NOW,
    );
    assert.equal(v.status, "sampled_zero");
    assert.equal(v.ageMs, 1_000);
  });

  it("timeout/permission/unsupported empty is not sampled zero", () => {
    for (const status of ["timeout", "permission", "unsupported", "not_sampled"] as const) {
      const v = sampleView(
        machine({
          network: { status, observedAt: NOW - 1_000, connections: [] },
        }),
        NOW,
      );
      assert.equal(v.status, status, status);
      assert.notEqual(v.status, "sampled_zero");
      assert.equal(v.connections.length, 0);
    }
  });

  it("marks truncated and partial distinctly from ok", () => {
    const trunc = sampleView(
      machine({
        network: { status: "truncated", observedAt: NOW - 500, connections: [conn()], truncated: true },
      }),
      NOW,
    );
    assert.equal(trunc.status, "truncated");
    assert.equal(trunc.truncated, true);
    const part = sampleView(
      machine({
        network: { status: "partial", observedAt: NOW - 500, connections: [conn()] },
      }),
      NOW,
    );
    assert.equal(part.status, "partial");
  });

  it("stale ok sample is not live zero or ok", () => {
    const v = sampleView(
      machine({
        network: { status: "ok", observedAt: NOW - NETWORK_STALE_MS - 1, connections: [conn({ observedAt: NOW - NETWORK_STALE_MS - 1 })] },
      }),
      NOW,
    );
    assert.equal(v.status, "stale");
  });

  it("offline machine wins over an ok sample", () => {
    const v = sampleView(
      machine({
        status: "dark",
        network: { status: "ok", observedAt: NOW - 1_000, connections: [conn()] },
      }),
      NOW,
    );
    assert.equal(v.status, "offline");
    assert.equal(v.connections.length, 1);
  });

  it("rejects nonfinite/future observedAt for age", () => {
    const future = sampleView(
      machine({ network: { status: "ok", observedAt: NOW + 60_000, connections: [] } }),
      NOW,
    );
    assert.equal(future.ageMs, null);
    assert.equal(future.status, "stale");
    assert.equal(future.live, false);
    const bad = sampleView(machine({ network: { status: "ok", observedAt: 0, connections: [] } }), NOW);
    assert.equal(bad.ageMs, null);
    assert.equal(bad.live, false);
  });

  it("stale partial/truncated is not live even if the host still heartbeats", () => {
    const old = NOW - 3 * 24 * 60 * 60 * 1000;
    for (const status of ["partial", "truncated"] as const) {
      const v = sampleView(
        machine({
          status: "online",
          lastSeen: NOW,
          network: { status, observedAt: old, receivedAt: NOW, connections: [conn({ observedAt: old })], truncated: status === "truncated" },
        }),
        NOW,
      );
      assert.equal(v.status, "stale", status);
      assert.equal(v.quality, status);
      assert.equal(v.live, false);
      assert.equal(isLiveSample(v.status), false);
      assert.equal(v.connections.length, 1);
    }
  });

  it("receivedAt of a replayed heartbeat does not make ancient observedAt fresh", () => {
    const old = NOW - NETWORK_STALE_MS - 5_000;
    const v = sampleView(
      machine({
        status: "online",
        lastSeen: NOW,
        network: { status: "ok", observedAt: old, receivedAt: NOW, connections: [conn({ observedAt: old })] },
      }),
      NOW,
    );
    assert.equal(v.status, "stale");
    assert.equal(v.live, false);
    assert.equal(v.ageMs, NOW - old);
    assert.equal(v.receivedAt, NOW);
  });

  it("machine lastSeen aged is offline even when status says online", () => {
    const v = sampleView(
      machine({
        status: "online",
        lastSeen: NOW - NETWORK_STALE_MS - 1,
        network: { status: "ok", observedAt: NOW - 1_000, connections: [conn()] },
      }),
      NOW,
    );
    assert.equal(v.status, "offline");
    assert.equal(v.live, false);
    assert.equal(v.quality, "ok");
  });
});

describe("dedup and pid start identity", () => {
  it("keeps newer observedAt for the same socket+pid+start", () => {
    const older = conn({ observedAt: NOW - 5_000, localPort: 1 });
    const newer = conn({ observedAt: NOW - 100, localPort: 1 });
    const out = dedupConnections([older, newer, conn({ pid: 9, processStartedAt: NOW - 1, localPort: 1 })]);
    assert.equal(out.length, 2);
    assert.equal(out[0]!.observedAt, NOW - 100);
  });

  it("does not merge same pid with a new processStartedAt", () => {
    const a = conn({ pid: 7, processStartedAt: 100, remotePort: 443 });
    const b = conn({ pid: 7, processStartedAt: 200, remotePort: 443 });
    assert.notEqual(connectionKey(a), connectionKey(b));
    assert.equal(dedupConnections([a, b]).length, 2);
  });

  it("does not collapse the same socket+pid+start across machines and keeps machineId", () => {
    const shared = conn();
    const a = { ...shared, machineId: "m_a", hostname: "pc-a", live: true };
    const b = { ...shared, machineId: "m_b", hostname: "pc-b", live: true };
    const out = dedupConnections([a, b]);
    assert.equal(out.length, 2);
    assert.equal(out.find((r) => r.machineId === "m_a")?.hostname, "pc-a");
    assert.equal(out.find((r) => r.machineId === "m_b")?.hostname, "pc-b");
  });
});

describe("filter and source distinctions", () => {
  it("history filter is machine/agent/query and never claims DNS proof", () => {
    const rows = [
      hist(),
      hist({ id: "net_bbbbbb", machineId: "m_b", agent: "claude", remoteIp: "203.0.113.8" }),
      hist({ id: "net_cccccc", pid: 7, processStartedAt: 99 }),
    ];
    const scoped = scopedHistory(rows, { machineId: "m_a", agent: "grok", query: "198.51.100.9" });
    assert.equal(scoped.length, 2);
    assert.equal(
      scopedHistory(rows, { machineId: "m_b", agent: "all" }).map((r) => r.id).join(),
      "net_bbbbbb",
    );
    assert.equal(sameHostNotProvenDns("bucket.oss-cn-hangzhou.aliyuncs.com", "198.51.100.9"), false);
  });

  it("declared missing vs empty vs dest, without inferring hosts from paths", () => {
    assert.equal(visibleDestinations(event()).kind, "missing");
    assert.equal(declaredTargets(event()).collected, false);
    const empty = visibleDestinations(event({ endpoints: [] }));
    assert.equal(empty.kind, "empty");
    assert.equal(declaredTargets(event({ endpoints: [] })).collected, true);
    const dest = visibleDestinations(event({ dest: "api.example.com" }));
    assert.equal(dest.kind, "dest");
    assert.deepEqual(dest.hosts, ["api.example.com"]);
    assert.equal(hostLike("https://x.example/path?X-Amz-Signature=secret"), false);
    assert.equal(visibleDestinations(event({ dest: "https://x.example/path?sig=1" })).kind, "missing");
  });

  it("OSS label is suffix+service shape only; spoof suffix is not OSS", () => {
    assert.equal(ossShapeOf("bucket.oss-cn-hangzhou.aliyuncs.com"), true);
    assert.equal(ossShapeOf("bucket.oss-cn-hangzhou.aliyuncs.com.evil"), false);
    assert.equal(ossShapeOf("evil.aliyuncs.com.example"), false);
    const high = event({
      risk: "high",
      endpoints: [{ host: "bucket.oss-cn-hangzhou.aliyuncs.com", source: "tool_url", observation: "declared", scheme: "https" }],
    });
    assert.equal(isHighRiskOss(high), true);
    assert.deepEqual(eventOssHosts(high), ["bucket.oss-cn-hangzhou.aliyuncs.com"]);
    assert.equal(isHighRiskOss(event({ risk: "high", dest: "api.example.com" })), false);
  });

  it("search covers host/dest/id/hash/session/proc", () => {
    const e = event({
      id: "evt_deadbeef",
      risk: "high",
      dest: "objects.example.com",
      requestHash: "ab".repeat(32),
      sessionId: "sess_9",
      proc: "grok.exe",
      endpoints: [{ host: "bucket.oss-cn-hangzhou.aliyuncs.com", port: 443, source: "tool_command", observation: "declared" }],
    });
    const blob = eventSearchText(e);
    assert.match(blob, /evt_deadbeef/);
    assert.match(blob, /objects\.example\.com/);
    assert.match(blob, /abab/);
    assert.match(blob, /sess_9/);
    assert.match(blob, /grok\.exe/);
    assert.match(blob, /bucket\.oss-cn-hangzhou\.aliyuncs\.com/);
    const filtered = filterDeclaredEvents([e, event({ id: "e_other", risk: "high" })], {
      query: "bucket.oss",
      ossHigh: true,
    });
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0]!.id, "evt_deadbeef");
  });

  it("excludes unrelated Read/Edit/self-tamper and does not infer hosts from raw commands", () => {
    const read = event({
      id: "e_read",
      ts: NOW - 3_000,
      category: "file_read",
      tool: "Read",
      input: "read_file /tmp/a",
      redacted: "read_file /tmp/a",
    });
    const edit = event({
      id: "e_edit",
      ts: NOW - 2_000,
      category: "file_edit",
      tool: "Edit",
      input: "curl https://evil.example/path?sig=1",
      redacted: "curl https://evil.example/path",
    });
    const tamper = event({
      id: "e_tamper",
      ts: NOW - 1_000,
      category: "other",
      tool: "Bash",
      ruleId: "monitor_self_tamper",
      decision: "block",
      enforcement: "returned_deny",
      threat: "tamper",
    });
    const netNew = event({
      id: "e_new",
      ts: NOW - 100,
      endpoints: [{ host: "bucket.oss-cn-hangzhou.aliyuncs.com", source: "tool_url", observation: "declared" }],
    });
    const netOld = event({
      id: "e_old",
      ts: NOW - 9_000,
      dest: "objects.example.com",
      category: "network",
    });
    assert.equal(isNetworkRelevantEvent(read), false);
    assert.equal(isNetworkRelevantEvent(edit), false);
    assert.equal(isNetworkRelevantEvent(tamper), false);
    const rows = filterDeclaredEvents([read, edit, tamper, netOld, netNew], {});
    assert.deepEqual(rows.map((e) => e.id), ["e_new", "e_old"]);
  });

  it("tcp empty copy is sampled zero only when every machine sampled zero", () => {
    const zero = { view: sampleView(machine({ network: { status: "ok", observedAt: NOW - 1_000, connections: [] } }), NOW) };
    const missing = { view: sampleView(machine(), NOW) };
    assert.equal(tcpEmptyKind([zero], 0, {}), "sampled_zero");
    assert.equal(tcpEmptyKind([missing], 0, {}), "none_visible");
    assert.equal(tcpEmptyKind([zero], 0, { query: "198.51" }), "none_visible");
    assert.equal(decisionMsg("block"), "block");
    assert.equal(enforcementMsg("returned_deny"), "returnedDeny");
    assert.equal(enforcementMsg("delivered"), "netEnforcementDelivered");
  });
});

describe("labels and export", () => {
  it("labels Established vs SynSent without inventing bytes/blocked", () => {
    assert.equal(tcpStateLabel("Established"), "Established");
    assert.equal(tcpStateLabel("SynSent"), "SynSent");
    assert.equal(tcpStateLabel("syn_sent"), "SynSent");
    assert.equal(tcpStateLabel("Bound"), "Bound");
    assert.equal(formatSocket("2001:db8::1", 443), "[2001:db8::1]:443");
    assert.equal(formatSocket("198.51.100.9", 443), "198.51.100.9:443");
  });

  it("export keeps numeric epoch and Asia/Shanghai metadata, no fabricated fields", () => {
    const payload = evidenceExport([event({ ts: 1_700_000_000_123 })], NOW);
    assert.equal(payload.timezone, "Asia/Shanghai");
    assert.equal(payload.utcOffset, "+08:00");
    assert.equal(payload.exportedAt, NOW);
    assert.equal(payload.records[0]!.ts, 1_700_000_000_123);
    assert.equal("bytes" in payload.records[0]!, false);
    assert.equal("geo" in payload, false);
  });

  it("filtered TCP export honors agent and query and does not include other agents", () => {
    const grokM = machine({
      id: "m_a",
      network: {
        status: "ok",
        observedAt: NOW - 1_000,
        connections: [conn({ agent: "grok", remoteIp: "198.51.100.9" }), conn({ agent: "claude", pid: 8, remoteIp: "203.0.113.8" })],
      },
    });
    const samples = [{ machine: grokM, view: sampleView(grokM, NOW) }];
    const tcp = collectTcpRows(samples, { agent: "grok", query: "198.51.100.9" });
    assert.equal(tcp.length, 1);
    assert.equal(tcp[0]!.agent, "grok");
    assert.equal(tcp[0]!.machineId, "m_a");
    const payload = networkExportPayload({
      exportedAt: NOW,
      filters: { machineId: "all", agent: "grok", query: "198.51.100.9", ossHigh: false },
      samples: samples.map(({ machine, view }) => ({
        machineId: machine.id,
        hostname: machine.hostname,
        status: view.status,
        quality: view.quality,
        live: view.live,
        ageMs: view.ageMs,
        observedAt: view.observedAt,
        receivedAt: view.receivedAt,
        truncated: view.truncated,
      })),
      tcp,
      history: [],
      declared: [],
    });
    assert.equal(payload.filters.agent, "grok");
    assert.equal(payload.tcp.length, 1);
    assert.equal(payload.tcp[0]!.agent, "grok");
    assert.equal(payload.tcp.some((r) => r.agent === "claude"), false);
    assert.equal("connections" in payload.samples[0]!, false);
  });

  it("uses SynSent as attempt and does not treat Established as a direction arrow", () => {
    assert.equal(isSynSent("SynSent"), true);
    assert.equal(isSynSent("Established"), false);
    assert.equal(tcpStateLabel("Established"), "Established");
  });
});
