import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  HEARTBEAT_CAPABILITY_ID,
  HEARTBEAT_LIMITS,
  parseCapabilityEntry,
  parseHeartbeatBody,
  projectStoredAgents,
  projectStoredCapabilities,
  projectStoredLabel,
} from "./heartbeat-schema.ts";

const cap = (id: string, active = false, extra: Record<string, unknown> = {}) => ({
  id,
  supported: true,
  active,
  ...extra,
});

describe("heartbeat schema bounds", () => {
  it("pins finite bounds against real probe payload sizes", () => {
    assert.deepEqual(HEARTBEAT_LIMITS, {
      labelChars: 256,
      agentCount: 256,
      agentChars: 256,
      capabilityCount: 256,
      capabilityIdChars: 48,
      errorChars: 1024,
    });
    assert.equal(HEARTBEAT_LIMITS.labelChars, 256);
    assert.equal(HEARTBEAT_LIMITS.agentCount, 256);
    assert.equal(HEARTBEAT_LIMITS.agentChars, 256);
    assert.equal(HEARTBEAT_LIMITS.capabilityCount, 256);
    assert.equal(HEARTBEAT_LIMITS.capabilityIdChars, 48);
    assert.equal(HEARTBEAT_LIMITS.errorChars, 1024);
    assert.equal(HEARTBEAT_CAPABILITY_ID.source, "^[A-Za-z][A-Za-z0-9_-]{0,47}$");
    assert.equal(HEARTBEAT_CAPABILITY_ID.test("hook_antigravity"), true);
    assert.equal(HEARTBEAT_CAPABILITY_ID.test("a".repeat(48)), true);
    assert.equal(HEARTBEAT_CAPABILITY_ID.test("a".repeat(49)), false);
    assert.equal(HEARTBEAT_CAPABILITY_ID.test("future_sensor"), true);
    assert.equal(HEARTBEAT_CAPABILITY_ID.test("1hook"), false);
  });
});

describe("parseHeartbeatBody", () => {
  it("rejects non-objects and accepts an empty object without inventing fields", () => {
    for (const body of [null, [], 1, true, "heartbeat", { capabilities: [null] }]) {
      assert.deepEqual(parseHeartbeatBody(body), { ok: false, error: "bad_heartbeat" });
    }
    const empty = parseHeartbeatBody({});
    assert.deepEqual(empty, { ok: true, fields: {} });
    assert.deepEqual(parseHeartbeatBody({ agents: [], capabilities: [] }), {
      ok: true,
      fields: { agents: [], capabilities: [] },
    });
  });

  it("accepts stopped and normal probe shapes and ignores unknown keys", () => {
    const now = 1_700_000_000_000;
    const stopped = parseHeartbeatBody({
      pollOnly: true,
      stoppedAck: true,
      policyVersion: 4,
      hostname: "synthetic",
      os: "win32",
    });
    assert.deepEqual(stopped, {
      ok: true,
      fields: { pollOnly: true, stoppedAck: true, policyVersion: 4, hostname: "synthetic" },
    });
    const inputCap = {
      id: "future_sensor",
      supported: true,
      active: false,
      error: "offline",
      nested: { secret: true },
      note: "kept-out",
    };
    const normal = parseHeartbeatBody({
      hostname: "synthetic",
      user: "fixture",
      agents: ["grok", "claude"],
      agentProcs: [],
      discovery: { schemaVersion: "later" },
      capabilities: [
        { id: "heartbeat", supported: true, active: true, lastSuccess: now },
        { id: "process_snapshot", supported: true, active: false, error: "unknown" },
        { id: "hook_grok", supported: true, active: false, error: "hook_not_installed" },
        { id: "hook_codex", supported: true, active: false, lastSuccess: now, error: "offline" },
        { id: "quota", supported: false, active: false, error: "not_collected" },
        { id: "network_sample", supported: true, active: false, error: "not_sampled" },
        inputCap,
      ],
      os: "win32",
      policyVersion: 2,
      stoppedAck: false,
      snapshotGuard: { supported: true },
      network: { status: "ok" },
    });
    assert.equal(normal.ok, true);
    if (!normal.ok) return;
    assert.equal(normal.fields.hostname, "synthetic");
    assert.deepEqual(normal.fields.agents, ["grok", "claude"]);
    assert.equal(normal.fields.stoppedAck, false);
    assert.equal("os" in normal.fields, false);
    assert.equal("discovery" in normal.fields, false);
    assert.equal("network" in normal.fields, false);
    const future = normal.fields.capabilities?.find((item) => item.id === "future_sensor");
    assert.deepEqual(future, { id: "future_sensor", supported: true, active: false, error: "offline" });
    assert.equal(JSON.stringify(normal.fields).includes("secret"), false);
    assert.equal(normal.fields.capabilities?.some((item) => item.id === "heartbeat" && item.active), true);
  });

  it("does not coerce wrong types and rejects present nulls", () => {
    const bad = [
      { hostname: 1 },
      { hostname: { toString: () => "synthetic" } },
      { user: true },
      { ip: ["127.0.0.1"] },
      { hostname: null },
      { agents: "grok" },
      { agents: [1] },
      { agents: [{ toString: () => "grok" }] },
      { agents: [null] },
      { capabilities: { id: "hook_grok" } },
      { capabilities: ["hook_grok"] },
      { capabilities: [cap("hook_grok", true, { supported: "yes" })] },
      { capabilities: [{ id: "hook_grok", supported: true }] },
      { capabilities: [cap("", true)] },
      { capabilities: [cap("future_sensor", true, { lastSuccess: "1" })] },
      { capabilities: [cap("future_sensor", true, { error: ["offline"] })] },
      { capabilities: [cap("future_sensor", true, { error: { nested: true } })] },
      { policyVersion: "1" },
      { policyVersion: null },
      { policyVersion: Number.POSITIVE_INFINITY },
      { policyVersion: Number.NaN },
      { pollOnly: "true" },
      { pollOnly: null },
      { stoppedAck: 1 },
    ];
    for (const body of bad) assert.equal(parseHeartbeatBody(body).ok, false, JSON.stringify(body));
    const finite = parseHeartbeatBody({ policyVersion: 0, pollOnly: false, stoppedAck: false });
    assert.deepEqual(finite, { ok: true, fields: { policyVersion: 0, pollOnly: false, stoppedAck: false } });
  });

  it("accepts the documented maximum and rejects one past it", () => {
    const agents = Array.from({ length: HEARTBEAT_LIMITS.agentCount }, () => "grok");
    const caps = Array.from({ length: HEARTBEAT_LIMITS.capabilityCount }, () => cap("future_sensor"));
    assert.equal(parseHeartbeatBody({ agents }).ok, true);
    assert.equal(parseHeartbeatBody({ agents: [...agents, "grok"] }).ok, false);
    assert.equal(parseHeartbeatBody({ capabilities: caps }).ok, true);
    assert.equal(parseHeartbeatBody({ capabilities: [...caps, cap("future_sensor")] }).ok, false);
    assert.equal(parseHeartbeatBody({ hostname: "h".repeat(HEARTBEAT_LIMITS.labelChars) }).ok, true);
    assert.equal(parseHeartbeatBody({ user: "u".repeat(HEARTBEAT_LIMITS.labelChars + 1) }).ok, false);
    assert.equal(parseHeartbeatBody({ agents: ["a".repeat(HEARTBEAT_LIMITS.agentChars)] }).ok, true);
    assert.equal(parseHeartbeatBody({ agents: ["a".repeat(HEARTBEAT_LIMITS.agentChars + 1)] }).ok, false);
    assert.equal(parseHeartbeatBody({ capabilities: [cap("a".repeat(48))] }).ok, true);
    assert.equal(parseHeartbeatBody({ capabilities: [cap("a".repeat(49))] }).ok, false);
    assert.equal(
      parseHeartbeatBody({ capabilities: [cap("future_sensor", false, { error: "e".repeat(1024) })] }).ok,
      true,
    );
    assert.equal(
      parseHeartbeatBody({ capabilities: [cap("future_sensor", false, { error: "e".repeat(1025) })] }).ok,
      false,
    );
  });

  it("ignores a JSON __proto__ key instead of treating it as pollOnly", () => {
    const parsed = JSON.parse('{"__proto__":{"pollOnly":true},"hostname":"synthetic"}') as unknown;
    const result = parseHeartbeatBody(parsed);
    assert.deepEqual(result, { ok: true, fields: { hostname: "synthetic" } });
  });
});

describe("stored heartbeat projection", () => {
  it("drops invalid capability entries and never exposes them as active", () => {
    const projected = projectStoredCapabilities([
      null,
      "hook_grok",
      { id: "hook_claude", supported: "yes", active: true },
      { id: "hook_codex", active: true },
      { id: "hook_grok", supported: true, active: true, error: { nested: true } },
      { id: "not a valid id", supported: true, active: true },
      { id: "future_sensor", supported: true, active: false, error: "offline", nested: { a: 1 } },
      { id: "hook_zcode", supported: true, active: true, lastSuccess: 10 },
    ]);
    assert.deepEqual(projected, [
      { id: "future_sensor", supported: true, active: false, error: "offline" },
      { id: "hook_zcode", supported: true, active: true, lastSuccess: 10 },
    ]);
    assert.equal(projected.some((item) => item.active && item.id !== "hook_zcode"), false);
    assert.equal(parseCapabilityEntry({ id: "hook_grok", supported: true, active: true, error: 1 }), undefined);
    assert.deepEqual(projectStoredCapabilities("nope"), []);
  });

  it("replaces non-string labels and drops non-string agents without truncating real strings", () => {
    assert.equal(projectStoredLabel({ bad: true }), "");
    assert.equal(projectStoredLabel(12), "");
    assert.equal(projectStoredLabel(null), "");
    assert.equal(projectStoredLabel(undefined), "");
    const long = "h".repeat(500);
    assert.equal(projectStoredLabel(long), long);
    assert.deepEqual(projectStoredAgents(["grok", 7, { x: 1 }, "claude"]), ["grok", "claude"]);
    assert.deepEqual(projectStoredAgents("grok"), []);
    assert.deepEqual(projectStoredAgents(null), []);
  });
});
