import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, test } from "node:test";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import { formatHookResponse, HOOK_AGENTS } from "../../core/hook-protocol.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import {
  canonicalToEvalInput,
  renderCanonicalDecision,
  renderHookFailure,
  sha256Prefixed,
  toCanonicalDecision,
  toCanonicalToolEvent,
  V2_STRICT_INGRESS_DEFAULT,
} from "../../core/protocol/v2-adapter.ts";
import { projectResult } from "../../scripts/spec-run.mjs";
import { createRealHookOracle, hookBytes } from "./real-hook-oracle.mjs";

const oracle = await createRealHookOracle();
after(() => oracle.close());
const context = {
  eventId: "failure-boundary",
  occurredAt: "2026-09-30T00:00:00Z",
  deviceId: "local",
  adapterRevision: 1,
};
const golden = JSON.parse(
  readFileSync(new URL("../compat/fixtures/hook-bytes-golden.json", import.meta.url), "utf8"),
);
const envelope = (bag, extra = {}) =>
  JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: bag,
    eventId: context.eventId,
    ...extra,
  });

function renderedSuccess(parsed, result) {
  return renderCanonicalDecision(
    parsed.host.agent,
    toCanonicalDecision({
      eventId: parsed.event.eventId,
      v1Result: result,
      policyVersion: 1,
      rulesHash: sha256Prefixed(""),
      engineRevision: ENGINE_REVISION,
      origin: "OFFLINE_CACHE",
    }),
    { argMap: parsed.host.argMap },
  );
}

test("incoming truncation: real hook failure classification and bytes for all 13 hosts", async () => {
  assert.equal(HOOK_AGENTS.length, 13);
  for (const agent of HOOK_AGENTS) {
    const fixture = golden.cases.find((item) => item.host === agent && item.kind === "truncated");
    assert.ok(fixture, agent);
    const real = await oracle.run(fixture.stdin, agent);
    assert.equal(real.evaluated, false, agent);
    const parsed = toCanonicalToolEvent(fixture.stdin, { ...context, agentFlag: agent });
    assert.equal(parsed.ok, false, agent);
    assert.equal(parsed.failure.failureClass, "incoming_truncation", agent);
    assert.deepEqual(
      hookBytes(renderHookFailure(agent, parsed.failure)),
      hookBytes(real.hook),
      agent,
    );
    assert.deepEqual(
      hookBytes(real.hook),
      { stdout: fixture.stdout, stderr: fixture.stderr, exitCode: fixture.exitCode },
      agent,
    );
  }
});

test("strict depth 64/65: real v1 default-off equivalence and explicit IC-10 rejection bytes", async () => {
  assert.equal(V2_STRICT_INGRESS_DEFAULT, false);
  for (const agent of HOOK_AGENTS) {
    for (const depth of [64, 65]) {
      const raw = envelope(
        { command: "echo safe" },
        { deep: JSON.parse("[".repeat(depth - 1) + "0" + "]".repeat(depth - 1)) },
      );
      const real = await oracle.run(raw, agent);
      assert.equal(real.evaluated, true, `${agent}/${depth}`);
      const off = toCanonicalToolEvent(raw, { ...context, agentFlag: agent });
      assert.equal(off.ok, true);
      const v2 = evaluate(canonicalToEvalInput(off.event), "enforcing", []);
      assert.deepEqual(
        projectResult(v2),
        projectResult(real.result),
        `${agent}/${depth} real decision`,
      );
      assert.deepEqual(
        hookBytes(renderedSuccess(off, v2)),
        hookBytes(real.hook),
        `${agent}/${depth} default bytes`,
      );
      const strict = toCanonicalToolEvent(
        raw,
        { ...context, agentFlag: agent },
        { strictIngress: true },
      );
      if (depth === 64) assert.equal(strict.ok, true, `${agent} depth64 accepted`);
      else {
        assert.equal(strict.ok, false, `${agent} depth65 rejected`);
        assert.equal(strict.failure.failureClass, "depth_exceeded");
        assert.equal(strict.failure.containerDepth, 65);
        assert.deepEqual(
          hookBytes(renderHookFailure(agent, strict.failure)),
          hookBytes(formatHookResponse(agent, { decision: "deny", reason: "depth_exceeded" })),
          `${agent} strict rejection bytes`,
        );
      }
    }
  }
});

test("Antigravity abe4413: real v1 failure is canonical conflicting_aliases and byte-equivalent", async () => {
  const raw = JSON.stringify({
    toolCall: { name: "view_file", args: { TargetFile: "/tmp/a", AbsolutePath: "/tmp/b" } },
  });
  const real = await oracle.run(raw, "antigravity");
  assert.equal(real.evaluated, false);
  const parsed = toCanonicalToolEvent(raw, { ...context, agentFlag: "antigravity" });
  assert.equal(parsed.ok, true, "must retain conflicting_aliases instead of json_syntax");
  assert.equal(parsed.aliasConflict, true);
  assert.deepEqual(
    hookBytes(renderHookFailure("antigravity", { aliasConflict: parsed.aliasConflict })),
    hookBytes(real.hook),
  );
});

test("edits contents/content: real hook conflict and failure bytes for all 13 hosts", async () => {
  const raw = envelope({ edits: [{ contents: "SAFE", content: "rm -rf /" }] });
  for (const agent of HOOK_AGENTS) {
    const real = await oracle.run(raw, agent);
    assert.equal(real.evaluated, false, agent);
    const parsed = toCanonicalToolEvent(raw, { ...context, agentFlag: agent });
    assert.equal(parsed.ok, true, `${agent}: alias conflict classification`);
    assert.equal(parsed.aliasConflict, true, agent);
    assert.deepEqual(
      hookBytes(renderHookFailure(agent, { aliasConflict: parsed.aliasConflict })),
      hookBytes(real.hook),
      agent,
    );
  }
});

test("real hook oracle preserves session, envelope cwd and source through the actual eval bridge", async () => {
  const raw = envelope(
    { command: "echo safe" },
    { session_id: "oracle-session", cwd: "/tmp/oracle-workspace" },
  );
  const real = await oracle.run(raw, "claude");
  assert.equal(real.evaluated, true);
  assert.equal(real.input.sessionId, "oracle-session");
  assert.equal(real.input.cwd, "/tmp/oracle-workspace");
  assert.equal(real.input.source, "hook");
  assert.equal(real.input.eventId, context.eventId);
  const parsed = toCanonicalToolEvent(raw, { ...context, agentFlag: "claude" });
  assert.equal(parsed.ok, true);
  const v2 = canonicalToEvalInput(parsed.event);
  for (const key of ["sessionId", "cwd", "source", "eventId", "deviceId"])
    assert.equal(v2[key], real.input[key], key);
});
