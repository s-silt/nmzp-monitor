import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { deny as runtimeDeny, pass as runtimePass } from "./hook.ts";
import { deny, pass } from "./hook-renderer.ts";
import { formatHookResponse, HOOK_AGENTS } from "./hook-protocol.ts";
import { toCanonicalToolEvent } from "./protocol/v2-adapter.ts";

const context = {
  eventId: "render-test",
  occurredAt: "2026-09-30T00:00:00Z",
  deviceId: "test",
  adapterRevision: 1,
};

describe("pure hook rendering", () => {
  it("preserves the runtime exports and every host wrapper response", () => {
    assert.equal(runtimeDeny, deny);
    assert.equal(runtimePass, pass);
    const argMap = { command: "CommandLine", file_path: "AbsolutePath" };
    const updatedInput = { command: "echo replacement", file_path: "/tmp/example" };
    for (const agent of [...HOOK_AGENTS, "unknown"] as const) {
      const effectiveAgent = agent === "unknown" ? "grok" : agent;
      for (const map of [undefined, argMap]) {
        const options = map ? { argMap: map } : undefined;
        assert.deepEqual(
          deny(agent, "bad_hook_json", map),
          formatHookResponse(
            effectiveAgent,
            { decision: "deny", reason: "bad_hook_json" },
            options,
          ),
        );
        assert.deepEqual(
          pass(agent, "allow", undefined, map),
          formatHookResponse(
            effectiveAgent,
            { decision: "allow", reason: "allow", updatedInput: undefined },
            options,
          ),
        );
        assert.deepEqual(
          pass(agent, "rewrite", updatedInput, map),
          formatHookResponse(
            effectiveAgent,
            { decision: "allow", reason: "rewrite", updatedInput },
            options,
          ),
        );
      }
    }
  });

  it("keeps the existing parse-failure classification for a differing nested tool label", () => {
    const result = toCanonicalToolEvent(
      JSON.stringify({ tool_name: "Bash", tool_input: { tool: "Read", command: "echo ok" } }),
      context,
    );
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.failure.failureClass, "json_syntax");
    assert.equal(result.failure.errorCode, "bad_json");
  });

  it("loads the canonical adapter from a minimal core copy without hook runtime, src or contract", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-pure-render-"));
    try {
      const core = join(root, "core");
      await mkdir(join(core, "protocol"), { recursive: true });
      for (const name of [
        "hook-renderer.ts",
        "hook-protocol.ts",
        "hook-alias-keys.ts",
        "constants.ts",
        "egress-schema.ts",
        "auth.ts",
        "protocol/v2-adapter.ts",
      ]) {
        await cp(join(import.meta.dirname, name), join(core, name));
      }
      const adapter = await import(pathToFileURL(join(core, "protocol", "v2-adapter.ts")).href);
      const result = adapter.toCanonicalToolEvent(
        '{"tool_name":"Bash","tool_input":{"command":"echo ok"}}',
        context,
      );
      assert.equal(result.ok, true);
      assert.deepEqual(
        adapter.renderHookFailure("grok", { aliasConflict: true }),
        deny("grok", "bad_hook_json"),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
