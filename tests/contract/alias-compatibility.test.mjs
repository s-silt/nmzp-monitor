import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildEvalInput, resolveEvalBody } from "../../core/eval-bridge.ts";
import { runHook } from "../../core/hook.ts";
import { HOOK_AGENTS, parseHookEvent, toolInputHasAliasConflict, toolInputToEvalFields } from "../../core/hook-protocol.ts";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import {
  canonicalToEvalInput, d8TrimAuditWarnings, d8TrimObservations, renderCanonicalDecision,
  sha256Prefixed, toCanonicalDecision, toCanonicalToolEvent,
} from "../../core/protocol/v2-adapter.ts";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import { classifyWorkdir } from "../../src/lib/monitor/path-scope.ts";

const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
const context = { eventId: "evt-alias-compat", occurredAt: "2026-09-30T00:00:00Z", deviceId: "local", adapterRevision: 1 };
const envelope = (toolInput, toolName = "Bash", extra = {}) => JSON.stringify({
  hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput,
  eventId: context.eventId, ...extra,
});
const bytes = (result) => ({ stdout: result.stdout, stderr: result.stderr ?? "", exitCode: result.exitCode });
const decision = (result) => ({ decision: result.decision, action: result.action, risk: result.risk, ruleId: result.rule?.id ?? null });

async function equivalent(raw, agent = "claude") {
  const parsed = parseHookEvent(raw);
  assert.ok(parsed);
  const body = { tool_name: parsed.toolName, tool_input: parsed.toolInput, cwd: parsed.cwd, agent, source: "hook" };
  assert.equal(resolveEvalBody(body).conflict, false);
  const v1Input = buildEvalInput(body, "local");
  const v1 = evaluate(v1Input, "enforcing", []);
  const canonical = toCanonicalToolEvent(raw, { ...context, agentFlag: agent });
  assert.equal(canonical.ok, true);
  assert.equal(canonical.aliasConflict, false);
  const v2Input = canonicalToEvalInput(canonical.event);
  const v2 = evaluate(v2Input, "enforcing", []);
  assert.deepEqual(decision(v2), decision(v1));
  const rendered = renderCanonicalDecision(agent, toCanonicalDecision({
    eventId: context.eventId, v1Result: v2, policyVersion: 1, rulesHash: sha256Prefixed(""),
    engineRevision: ENGINE_REVISION, origin: "OFFLINE_CACHE",
  }), { argMap: canonical.host.argMap });
  // Real hook.ts -> offline applyEvaluate -> resolveEvalBody, using only a new temporary home.
  // No credentials or network: fixtures are data, and runHook never executes the tool command.
  const home = await mkdtemp(join(tmpdir(), "nmzp-alias-compat-"));
  try {
    await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
      version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1,
    });
    const hooked = await runHook({ argv: ["--agent", agent], stdin: raw, home, coreDir, env: {} });
    assert.deepEqual(bytes(rendered), bytes(hooked), `${agent}: real v1/v2 hook bytes`);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
  return { canonical, v1Input, v2Input, v1, rendered };
}

test("B3 IC-11 NOT_SWITCHED: nested input and array patch concatenate rather than conflict", async () => {
  for (const toolInput of [
    { input: { contents: " a ", content: "b" } },
    { patch: [{ contents: " a ", content: "b" }, { contents: "a" }] },
  ]) {
    assert.equal(toolInputHasAliasConflict(toolInput), false);
    assert.equal(toolInputToEvalFields("Bash", toolInput).contents, "a\nb");
    const result = await equivalent(envelope(toolInput));
    assert.equal(result.v2Input.contents, "a\nb");
  }
  assert.equal(toolInputHasAliasConflict({ contents: "a", content: "b" }), true);
  assert.equal(toolInputHasAliasConflict({ edits: [{ contents: "a", content: "b" }] }), true);
});

test("B3 nested dangerous leaf is still scanned by the real hook and engine", async () => {
  for (const nested of [
    { input: { contents: "rm -rf /", content: "SAFE" } },
    { patch: [{ contents: "rm -rf /", content: "SAFE" }] },
  ]) {
    const result = await equivalent(envelope({ command: "echo safe", ...nested }));
    assert.equal(result.v1Input.contents, "rm -rf /\nSAFE");
    assert.equal(result.v1.decision, "block");
    assert.equal(result.v1.rule?.id, "dangerous_delete");
  }
});

test("N2: workdir stays a content leaf, not a cwd alias", async () => {
  const toolInput = { command: "echo safe", workdir: "/b" };
  const fields = toolInputToEvalFields("Bash", toolInput);
  assert.equal(fields.cwd, undefined);
  assert.equal(fields.contents, "/b");
  for (const extra of [{}, { cwd: "/home/u/project" }]) {
    const result = await equivalent(envelope(toolInput, "Bash", extra));
    assert.equal(result.v1Input.cwd, extra.cwd);
    assert.equal(result.v2Input.cwd, extra.cwd);
    assert.equal(result.v2Input.contents, "/b");
  }
});

test("B6 IC-02 NOT_SWITCHED: trim-equal command aliases do not conflict", async () => {
  for (const command of ["echo a", "  echo a  "]) {
    const toolInput = { command, cmd: command === "echo a" ? "  echo a  " : "echo a" };
    assert.equal(toolInputHasAliasConflict(toolInput), false);
    const result = await equivalent(envelope(toolInput));
    assert.equal(result.canonical.event.fields.command.value, command);
    assert.equal(result.v2Input.command, "echo a");
    assert.deepEqual(d8TrimAuditWarnings(result.canonical.event), []);
  }
  assert.equal(toolInputHasAliasConflict({ command: "echo a", cmd: "echo b" }), true);
});

const warning = (field) => ({ code: "path_whitespace_difference", severity: "warning", field, compatibility: "IC-12", status: "NOT_SWITCHED" });

test("B7 IC-12 NOT_SWITCHED: protected cwd / leading-space path remains v1 log, with warning", async () => {
  const cwd = "/home/u/.ssh";
  const filePath = " /tmp/a";
  // Lexical risk demonstration, not a claim of a real host/filesystem exploit.
  assert.equal(posix.resolve(cwd, filePath), "/home/u/.ssh/ /tmp/a");
  assert.equal(classifyWorkdir(filePath, cwd), "project");
  assert.equal(classifyWorkdir(filePath.trim(), cwd), "other");
  for (const agent of HOOK_AGENTS) {
    const result = await equivalent(envelope({ file_path: filePath, contents: "SAFE" }, "Write", { cwd }), agent);
    assert.equal(result.v1.decision, "log", `${agent}: known v1 path-whitespace risk`);
    assert.equal(result.v1Input.filePath, "/tmp/a");
    assert.equal(result.canonical.event.fields.filePath.value, filePath);
    assert.deepEqual(d8TrimAuditWarnings(result.canonical.event), [warning("filePath")]);
  }
});

test("B7 filePath/cwd trim warnings cover ASCII and Unicode whitespace without switching decisions", async () => {
  for (const whitespace of [" ", "\t", "\u00a0", "\u2028"]) {
    const result = await equivalent(envelope({
      file_path: `${whitespace}/tmp/a${whitespace}`, cwd: `${whitespace}/home/u/.ssh${whitespace}`, contents: "SAFE",
    }, "Write"));
    assert.deepEqual(d8TrimAuditWarnings(result.canonical.event), [warning("filePath"), warning("cwd")]);
    assert.equal(result.v1.decision, "log");
    assert.equal(result.v2Input.cwd, "/home/u/.ssh");
  }
  const clean = await equivalent(envelope({ file_path: "/tmp/a", cwd: "/home/u/.ssh", contents: "SAFE" }, "Write"));
  assert.deepEqual(d8TrimAuditWarnings(clean.canonical.event), []);
  const fallback = await equivalent(envelope({ file_path: "/tmp/a", contents: "SAFE" }, "Write", { cwd: " /home/u/.ssh " }));
  assert.deepEqual(d8TrimAuditWarnings(fallback.canonical.event), [warning("cwd")]);
});

test("B7 audit privacy: safe projection contains only fixed metadata, never exact/trimmed/provenance", () => {
  const result = toCanonicalToolEvent(envelope({ file_path: " /tmp/private-path-sentinel ", cwd: " /home/private-cwd-sentinel ", command: " echo private-command-sentinel " }, "Write"), context);
  assert.equal(result.ok, true);
  const observed = d8TrimObservations(result.event);
  assert.ok(observed.some((item) => item.exact.includes("private-path-sentinel")));
  assert.deepEqual(observed.filter((item) => item.warning).map((item) => item.warning), [warning("filePath"), warning("cwd")]);
  // Unknown/malicious member names and arbitrary provenance must not be copied to the audit sink.
  result.event.fields.filePath.provenance = "/private-provenance-sentinel";
  const safe = d8TrimAuditWarnings(result.event);
  assert.deepEqual(safe, [warning("filePath"), warning("cwd")]);
  const serialized = JSON.stringify(safe);
  for (const forbidden of ["sentinel", "exact", "trimmed", "provenance", "/tmp/", "/home/", "echo "]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  // A canonical whitespace-only path still differs from v1's missing value.
  result.event.fields.filePath.value = " \t";
  assert.equal(d8TrimObservations(result.event).find((item) => item.field === "filePath").trimmed, undefined);
  assert.deepEqual(d8TrimAuditWarnings(result.event), [warning("filePath"), warning("cwd")]);
});
