import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, describe, test } from "node:test";
import { evaluate } from "../../src/lib/monitor/engine.ts";
import { cloakPersona, shouldCloakPersona } from "../../src/lib/monitor/cloak.ts";
import { REDACT_TAG, scanCustom, scanSecrets } from "../../src/lib/monitor/privacy.ts";
import { ENGINE_REVISION } from "../../core/policy/engine-revision.ts";
import { structuredRewrite } from "../../core/rewrite.ts";
import { stableJson } from "../../core/hook-protocol.ts";
import { resolveGoldenStdin } from "../compat/golden-stdin.mjs";
import {
  canonicalToEvalInput,
  renderCanonicalDecision,
  renderHookFailure,
  sha256Prefixed,
  toCanonicalDecision,
  toCanonicalToolEvent,
} from "../../core/protocol/v2-adapter.ts";

import { createRealHookOracle, hookBytes } from "./real-hook-oracle.mjs";

const oracle = await createRealHookOracle();
after(() => oracle.close());
const golden = JSON.parse(readFileSync(new URL("../compat/fixtures/hook-bytes-golden.json", import.meta.url), "utf8"));

const privacy = {
  REDACT_TAG,
  scanSecrets,
  scanCustom,
  cloakPersona,
  shouldCloakPersona,
};

const CTX = {
  occurredAt: "1970-01-01T00:00:00Z",
  deviceId: "local",
  adapterRevision: 0,
};

function updatedFieldsFrom(toolInput, updatedInput) {
  const fields = {};
  if (!updatedInput) return fields;
  if (typeof updatedInput.command === "string") fields.command = updatedInput.command;
  else if (typeof updatedInput.cmd === "string") fields.command = updatedInput.cmd;
  if (typeof updatedInput.file_path === "string") fields.filePath = updatedInput.file_path;
  if (typeof updatedInput.url === "string") fields.url = updatedInput.url;
  if (typeof updatedInput.dest === "string") fields.dest = updatedInput.dest;
  if (typeof updatedInput.cwd === "string") fields.cwd = updatedInput.cwd;
  if (typeof updatedInput.contents === "string") fields.contents = updatedInput.contents;
  return fields;
}

function renderCase(item) {
  if (item.kind === "bootstrap") {
    const decision = {
      v: 1,
      eventId: "bootstrap",
      action: "BLOCK",
      reasonCode: "nmzp_hook_bootstrap_failed",
      ruleIds: [],
      risk: "high",
      family: null,
      policy: { version: 1, rulesHash: sha256Prefixed("") },
      engineRevision: ENGINE_REVISION,
      origin: "FAIL_CLOSED",
      privacy: { findings: [], rewriteStatus: "NONE" },
      explain: [{ layer: "bootstrap", result: "fail_closed" }],
      userMessage: "NMZP blocked this call: nmzp_hook_bootstrap_failed. This action is not allowed by policy; do not retry it in another form.",
    };
    return renderCanonicalDecision(item.host, decision);
  }

  const parsedResult = toCanonicalToolEvent(resolveGoldenStdin(item), { ...CTX, agentFlag: item.host, eventId: `evt-${item.id}` });
  if (!parsedResult.ok) return renderHookFailure(item.host, parsedResult.failure);
  if (parsedResult.aliasConflict) return renderHookFailure(item.host, { aliasConflict: true });

  const evalInput = canonicalToEvalInput(parsedResult.event);
  const v1Result = evaluate(evalInput, "enforcing", []);
  let rewrite;
  let updatedInput;
  if (v1Result.decision === "rewrite") {
    const rw = structuredRewrite(parsedResult.host.toolInput, [], privacy);
    if (!rw.ok) rewrite = { status: "REFUSED", reason: rw.reason };
    else if (stableJson(rw.updatedInput) === stableJson(parsedResult.host.toolInput ?? {})) {
      rewrite = { status: "NOOP_NO_SPAN" };
    } else {
      updatedInput = rw.updatedInput;
      rewrite = { status: "APPLIED", updatedInput, updatedFields: updatedFieldsFrom(parsedResult.host.toolInput, updatedInput) };
    }
  }
  const decision = toCanonicalDecision({
    eventId: parsedResult.event.eventId,
    v1Result,
    rewrite,
    policyVersion: 1,
    rulesHash: sha256Prefixed(""),
    engineRevision: ENGINE_REVISION,
    origin: "OFFLINE_CACHE",
  });
  return renderCanonicalDecision(item.host, decision, { argMap: parsedResult.host.argMap, updatedInput });
}

describe("render golden bytes", () => {
  test("104/104 hook-bytes-golden cases match stdout/stderr/exitCode", async () => {
    assert.equal(golden.cases.length, 104);
    const mismatches = [];
    for (const item of golden.cases) {
      const got = renderCase(item);
      const stdin = resolveGoldenStdin(item);
      const real = item.kind === "bootstrap" || item.kind === "over-limit"
        ? await oracle.packed(item, stdin)
        : (await oracle.run(stdin, item.host)).hook;
      assert.deepEqual(hookBytes(real), { stdout: item.stdout, stderr: item.stderr, exitCode: item.exitCode }, `${item.id}: real v1 bytes vs immutable golden`);
      assert.deepEqual(hookBytes(got), hookBytes(real), `${item.id}: canonical rendering vs real v1 hook`);
      if (got.exitCode !== item.exitCode || got.stdout !== item.stdout || (got.stderr ?? "") !== item.stderr) {
        mismatches.push({
          id: item.id,
          expected: { exitCode: item.exitCode, stdout: item.stdout, stderr: item.stderr },
          got: { exitCode: got.exitCode, stdout: got.stdout, stderr: got.stderr ?? "" },
        });
      }
    }
    assert.deepEqual(mismatches, []);
  });
});
