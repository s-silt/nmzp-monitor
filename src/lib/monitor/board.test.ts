import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseApiState } from "./api.ts";
import { filterLiveEvents } from "./live-filter.ts";
import { t } from "./i18n.ts";
import type { AuditEvent } from "./types.ts";

describe("board state schema and live filters", () => {
  it("rejects HTML or incomplete 200 payloads so hydrate cannot set undefined mode", () => {
    assert.equal(parseApiState("<html>ok</html>"), null);
    assert.equal(parseApiState({ ok: true }), null);
    assert.equal(parseApiState({ policyVersion: 1, stopped: false, mode: "weird", devices: [], events: [] }), null);
    const ok = parseApiState({
      policyVersion: 3,
      stopped: false,
      mode: "enforcing",
      devices: [],
      events: [],
      customRules: [],
    });
    assert.ok(ok);
    assert.equal(ok!.mode, "enforcing");
    assert.equal(ok!.access, "admin");
    const viewer = parseApiState({
      policyVersion: 3,
      stopped: false,
      mode: "enforcing",
      devices: [],
      events: [],
      access: "viewer",
    });
    assert.equal(viewer?.access, "viewer");
    const unknownAccess = parseApiState({
      policyVersion: 3,
      stopped: false,
      mode: "enforcing",
      devices: [],
      events: [],
      access: "superuser",
    });
    assert.equal(unknownAccess?.access, "viewer");
    assert.notEqual(unknownAccess?.access, "admin");
    assert.equal(t("zh", "enforcing"), "静默");
    assert.equal(t("zh", undefined as unknown as "enforcing"), "");
    assert.match(t("zh", "identityUnknownUser"), /PID/);
    assert.equal(t("zh", "interceptBody").includes("把 nmzp 这一条路径放行"), false);
    assert.equal(t("zh", "installJoinNote").includes("192.168.1.10"), false);
  });

  it("keeps history for agents that are no longer present", () => {
    const events = [
      { id: "1", machineId: "dev_a", agent: "grok", redacted: "a" },
      { id: "2", machineId: "dev_a", agent: "claude", redacted: "b" },
    ] as AuditEvent[];
    const rows = filterLiveEvents(events, {
      agentFilter: "all",
      machineFilter: "all",
      deviceIds: new Set(["dev_a"]),
    });
    assert.equal(rows.length, 2);
    assert.ok(rows.some((e) => e.agent === "claude"));
  });
});
