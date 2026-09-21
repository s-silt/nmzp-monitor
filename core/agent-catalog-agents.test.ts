import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { agentIdFromAdapter, agentsFromDiscovery } from "./agent-catalog.ts";

describe("agentIdFromAdapter", () => {
  it("maps discovery adapters to board agent ids without treating antigravity as a product agent", () => {
    assert.equal(agentIdFromAdapter("zcode-desktop"), "zcode");
    assert.equal(agentIdFromAdapter("codex-desktop"), "codex");
    assert.equal(agentIdFromAdapter("codex-cli"), "codex");
    assert.equal(agentIdFromAdapter("grok-cli"), "grok");
    assert.equal(agentIdFromAdapter("claude-code-cli"), "claude");
    assert.equal(agentIdFromAdapter("claude-code-extension"), "claude");
    assert.equal(agentIdFromAdapter("copilot-chat-extension"), "copilot");
    assert.equal(agentIdFromAdapter("gemini-cli"), "gemini");
    assert.equal(agentIdFromAdapter("antigravity-desktop"), undefined);
  });
});

describe("agentsFromDiscovery", () => {
  it("lists found installs once and skips not_found", () => {
    assert.deepEqual(
      agentsFromDiscovery([
        { adapterId: "zcode-desktop", installation: "candidate" },
        { adapterId: "codex-desktop", installation: "present" },
        { adapterId: "codex-cli", installation: "candidate" },
        { adapterId: "grok-cli", installation: "present" },
        { adapterId: "kiro-desktop", installation: "not_found" },
        { adapterId: "antigravity-desktop", installation: "present" },
      ]),
      ["zcode", "codex", "grok"],
    );
  });
});
