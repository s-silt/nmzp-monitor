import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseHookEvent, selectHookEnvelopeCwd, HOOK_AGENTS } from "../../core/hook-protocol.ts";
import { resolveEvalBody, rewriteSource } from "../../core/eval-bridge.ts";
import { buildRewriteLayout, materializeRewriteLayout } from "../../core/protocol/rewrite-layout.ts";
import { canonicalToEvalInput, toCanonicalToolEvent, renderCanonicalDecision, toCanonicalDecision, sha256Prefixed } from "../../core/protocol/v2-adapter.ts";
import { runHook } from "../../core/hook.ts";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import { evaluate } from "../../src/lib/monitor/engine.ts";

const ctx = { deviceId: "fixture", eventId: "cwd", occurredAt: "2026-09-30T00:00:00Z", adapterRevision: 1 };
const record = v => !!v && typeof v === "object" && !Array.isArray(v);
const str = v => typeof v === "string" && v.trim() ? v.trim() : undefined;
// Independent literal old parseHookEvent behavior at 23e35f5, including the untrimmed
// Antigravity array element. This catches wrong changes even when all consumers share a helper.
function oldCwd(raw) {
  if (record(raw.toolCall)) {
    const args = record(raw.toolCall.args) ? raw.toolCall.args : {};
    const workspacePaths = Array.isArray(raw.workspacePaths) ? raw.workspacePaths : [];
    const ws0 = workspacePaths[0];
    return str(args.Cwd) ?? (typeof ws0 === "string" ? ws0 : undefined);
  }
  const roots = raw.workspace_roots;
  const ws0 = Array.isArray(roots) && typeof roots[0] === "string" ? roots[0] : undefined;
  return str(raw.cwd) ?? str(raw.workspaceRoot) ?? str(ws0);
}
function parity(source, agentFlag) {
  const raw = JSON.stringify(source), host = parseHookEvent(raw), parsed = toCanonicalToolEvent(raw, { ...ctx, agentFlag });
  assert.ok(host); assert.equal(host.cwd, oldCwd(source));
  assert.equal(selectHookEnvelopeCwd(source)?.value, oldCwd(source));
  assert.equal(parsed.ok, true);
  const resolved = resolveEvalBody({ tool_name: host.toolName, tool_input: host.toolInput, cwd: host.cwd });
  assert.equal(canonicalToEvalInput(parsed.event).cwd, resolved.cwd);
  const layout = buildRewriteLayout(raw, parsed);
  assert.equal(layout.ok, true, `${JSON.stringify(source)}: ${JSON.stringify(layout)}`);
  assert.deepEqual(layout.view, rewriteSource(resolved));
  return { raw, parsed, layout };
}

const values = [undefined, null, false, 0, "", " \t\u00a0", "/selected", " /selected ", ["/not-string"], { "0": "/not-string" }];
test("cwd actual parser table preserves every legacy value and format precedence", () => {
  for (const cwd of values) for (const workspaceRoot of values) {
    parity({ tool_name: "Bash", tool_input: { command: "echo ok" }, cwd, workspaceRoot, workspace_roots: [" /third "], workspacePaths: ["/ignored"] });
  }
  for (const first of values) {
    for (const roots of [[first, "/must-not-use-second"], { "0": first }, null, []]) {
      parity({ tool_name: "Bash", tool_input: { command: "echo ok" }, workspace_roots: roots, workspacePaths: ["/ignored"] });
      for (const Cwd of values) parity({ toolCall: { name: "run_command", args: { CommandLine: "echo ok", Cwd } }, cwd: "/ignored", workspaceRoot: "/ignored", workspacePaths: roots }, "grok");
    }
  }
});

test("known mixed-format regressions resolve by parser format independent of agent flag", () => {
  const sources = [
    { toolCall: { name: "view_file", args: {} }, cwd: "/generic", workspacePaths: ["/actual"] },
    { tool_name: "Bash", tool_input: {}, workspacePaths: ["/ignored"] },
    { toolCall: { name: "view_file", args: { Cwd: "   " } }, cwd: "/generic", workspacePaths: [" \t "] },
  ];
  for (const source of sources) for (const flag of [undefined, "grok", "antigravity", "codex"]) parity(source, flag);
  for (const key of ["working_directory", "workingDirectory", "cwd"]) {
    parity({ tool_name: "Bash", tool_input: { command: "echo ok", [key]: " /tool " }, cwd: "/envelope" });
  }
});

test("materializer does not infer array shape from extras and still bounds declared cwd refs", () => {
  for (const source of [
    { tool_name: "Bash", tool_input: {}, workspace_roots: { "0": "/not-array" } },
    { toolCall: { name: "view_file", args: {} }, workspacePaths: { "0": "/not-array" } },
  ]) {
    const { parsed, layout } = parity(source);
    assert.equal(Object.hasOwn(layout.layout, "envelopeCwd"), false);
    assert.equal(materializeRewriteLayout(parsed.event, layout.layout).ok, true);
  }
  const { parsed, layout } = parity({ tool_name: "Bash", tool_input: { command: "echo ok" }, cwd: " /cwd " });
  assert.equal(materializeRewriteLayout(parsed.event, { ...layout.layout, envelopeCwd: { field: "command" } }).ok, false);
  const omitted = { ...layout.layout }; delete omitted.envelopeCwd;
  assert.equal(materializeRewriteLayout(parsed.event, omitted).reason, "projection");
  const fake = structuredClone(parsed); fake.event.fields.cwd.value = "/forged";
  assert.equal(buildRewriteLayout(JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo ok" }, cwd: " /cwd " }), fake).reason, "raw_binding");
});

test("cwd corrected projections preserve actual v1 bytes across thirteen hosts", async () => {
  const sources = [
    { toolCall: { name: "view_file", args: {} }, cwd: "/generic", workspacePaths: ["/actual"] },
    { tool_name: "Bash", tool_input: { command: "echo cwd" }, workspacePaths: ["/ignored"] },
  ];
  const coreDir = fileURLToPath(new URL("../../core/", import.meta.url));
  for (const source of sources) for (const agent of HOOK_AGENTS) {
    const { raw, parsed } = parity(source, agent);
    const result = evaluate(canonicalToEvalInput(parsed.event), "enforcing", []);
    const rendered = renderCanonicalDecision(agent, toCanonicalDecision({ eventId: ctx.eventId, v1Result: result, policyVersion: 1, rulesHash: sha256Prefixed(""), engineRevision: ENGINE_REVISION, origin: "OFFLINE_CACHE" }));
    const home = await mkdtemp(join(tmpdir(), "nmzp-cwd-host-"));
    try {
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
      const legacy = await runHook({ argv: ["--agent", agent], stdin: raw, home, coreDir, env: {} });
      const bytes = value => ({ stdout: value.stdout, stderr: value.stderr ?? "", exitCode: value.exitCode });
      assert.deepEqual(bytes(rendered), bytes(legacy), agent);
    } finally { await rm(home, { recursive: true, force: true }); }
  }
});
