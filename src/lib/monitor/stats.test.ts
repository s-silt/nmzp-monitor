import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AuditEvent, Machine } from "./types.ts";
import {
  HEARTBEAT_MS,
  deriveMachineStatus,
  isPersistedHostFilter,
  machineRollup,
  scopedCapabilities,
  statsFrom,
} from "./stats.ts";

function host(over: Partial<Machine> = {}): Machine {
  return {
    id: "dev_pc",
    hostname: "pc.lan",
    ip: "192.168.1.24",
    user: "unknown",
    os: "win32",
    lastSeen: 1_700_000_000_000,
    attachedAt: 1_700_000_000_000,
    status: "online",
    ...over,
  };
}

function ev(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: "e1",
    ts: 1_700_000_000_000,
    machineId: "dev_pc",
    agent: "grok",
    sessionId: "",
    layer: "app_pre",
    tool: "Bash",
    nativeTool: "Bash",
    input: "x",
    risk: "high",
    decision: "block",
    category: "other",
    workdirScope: "other",
    redacted: "x",
    ...over,
  };
}

describe("heartbeat vs isolate for host status", () => {
  it("keeps a host online when heartbeat is fresh even if an isolate deny exists", () => {
    const now = 1_700_000_090_000;
    const machine = host({ lastSeen: now - 5_000 });
    const events = [ev({ threat: "isolate", enforcement: "returned_deny" })];
    assert.equal(deriveMachineStatus(machine, events, now), "online");
    assert.ok(now - machine.lastSeen < HEARTBEAT_MS);
  });

  it("marks dark from stale heartbeat, archived after 7 days", () => {
    const now = 1_700_000_090_000;
    assert.equal(deriveMachineStatus(host({ lastSeen: now - HEARTBEAT_MS - 1 }), [], now), "dark");
    assert.equal(
      deriveMachineStatus(host({ lastSeen: now - 8 * 24 * 60 * 60 * 1000 }), [], now),
      "archived",
    );
  });
});

describe("host-confirmed block vs returned_deny", () => {
  it("does not count returned_deny as host-confirmed blocked", () => {
    const rows = [
      ev({ id: "a", enforcement: "blocked" }),
      ev({ id: "b", enforcement: "returned_deny", decision: "block" }),
      ev({ id: "c", decision: "block" }),
    ];
    const stats = statsFrom(rows);
    assert.equal(stats.blocked, 1);
    assert.equal(stats.returnedDeny, 1);
    const views = machineRollup([host()], rows, 1_700_000_090_000);
    assert.equal(views[0]?.blocked, 1);
  });
});

describe("persisted host filter and per-device capabilities", () => {
  it("keeps real dev_ host ids", () => {
    assert.equal(isPersistedHostFilter("dev_ab12"), true);
    assert.equal(isPersistedHostFilter("m_studio"), true);
    assert.equal(isPersistedHostFilter("all"), true);
    assert.equal(isPersistedHostFilter("studio.lan"), false);
  });

  it("does not show another machine's hook active when one host is selected", () => {
    const a = {
      id: "dev_a",
      capabilities: { hook_grok: { supported: true, active: true } },
    };
    const b = {
      id: "dev_b",
      capabilities: { hook_claude: { supported: true, active: true } },
    };
    const onlyB = scopedCapabilities([a, b], "dev_b");
    assert.equal(onlyB.hook_grok, undefined);
    assert.equal(onlyB.hook_claude?.active, true);
    const fleet = scopedCapabilities([a, b], "all");
    assert.equal(fleet.hook_grok?.active, true);
    assert.equal(fleet.hook_claude?.active, true);
    assert.equal(onlyB.process_snapshot, undefined);
  });
});

