import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mapEvent } from "./map-event.ts";
import { parseEndpointList, publicNetworkSample } from "./network-evidence.ts";

function row(over: Record<string, unknown> = {}) {
  return {
    id: "e1",
    ts: 1_700_000_000_000,
    machineId: "dev_a",
    agent: "grok",
    sessionId: "s1",
    layer: "app_pre",
    tool: "Bash",
    nativeTool: "Bash",
    risk: "high",
    decision: "block",
    redacted: "curl https://example.test",
    policyVersion: 3,
    requestHash: "ab".repeat(32),
    ...over,
  };
}

describe("mapEvent network evidence", () => {
  it("maps endpoints, requestHash, policyVersion; missing endpoints stay unknown", () => {
    const missing = mapEvent(row());
    assert.equal(missing?.endpoints, undefined);
    assert.equal(missing?.policyVersion, 3);
    assert.equal(missing?.requestHash, "ab".repeat(32));
    const empty = mapEvent(row({ endpoints: [] }));
    assert.deepEqual(empty?.endpoints, []);
    const have = mapEvent(
      row({
        endpoints: [{ host: "oss-cn-hangzhou.aliyuncs.com", scheme: "https", source: "tool_command", observation: "declared" }],
      }),
    );
    assert.equal(have?.endpoints?.[0]?.host, "oss-cn-hangzhou.aliyuncs.com");
    assert.equal(have?.endpoints?.[0]?.observation, "declared");
  });

  it("does not invent endpoints from dest", () => {
    assert.equal(parseEndpointList(undefined), undefined);
    const e = mapEvent(row({ dest: "legacy.example.test" }));
    assert.equal(e?.dest, "legacy.example.test");
    assert.equal(e?.endpoints, undefined);
  });

  it("parses device network and rejects ok+truncated contradiction", () => {
    const n = publicNetworkSample({
      status: "ok",
      observedAt: 1_700_000_000_000,
      connections: [],
    });
    assert.equal(n?.status, "ok");
    assert.equal(publicNetworkSample({ status: "ok", observedAt: 1_700_000_000_000, truncated: true, connections: [] }), undefined);
  });
});
