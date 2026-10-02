import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { NmzpStore } from "./persist.ts";
import { readPolicyCache, writePolicyCache } from "./policy-cache.ts";
import { LOCKED_RULE_IDS } from "./policy/locked-rules.ts";
import { LOCKED_RULE_IDS as ENGINE_LOCKED_RULE_IDS } from "../src/lib/monitor/overrides.ts";
import type { PolicyState } from "./schema.ts";

const CLIENTS = [
  { deviceId: "a", mode: "log_only" as const },
  { deviceId: "a", agent: "grok", mode: "log_only" as const },
];
const base: PolicyState = { version: 1, mode: "enforcing", customRules: [], stopped: false, updatedAt: 0 };

describe("client mode persistence", () => {
  it("pins the twelve locked rule ids outside overrides.ts", () => {
    assert.deepEqual([...LOCKED_RULE_IDS], [
      "isolate_cut_board",
      "isolate_delete_binary",
      "isolate_kill_monitor",
      "isolate_stop_container",
      "agent_hook_disable",
      "kill_monitor_process",
      "monitor_self_tamper",
      "monitor_self_tamper_cmd",
      "zcode_trust_store_tamper",
      "agent_hook_poison",
      "credential_file_upload",
      "env_piped_outbound",
    ]);
  });

  it("matches the engine locked set in overrides.ts", () => {
    assert.deepEqual([...LOCKED_RULE_IDS], [...ENGINE_LOCKED_RULE_IDS]);
  });

  it("json store round-trips clients and rejects a corrupt file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-clients-json-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      const freshFile = JSON.parse(await readFile(s.policyPath(), "utf8")) as { clients?: unknown };
      assert.equal(freshFile.clients, undefined);
      assert.deepEqual(s.getPolicy().clients, []);
      const saved = await s.casPolicy(1, { clients: CLIENTS });
      assert.ok(!("conflict" in saved));
      assert.deepEqual(saved.clients, CLIENTS);
      assert.deepEqual(JSON.parse(await readFile(s.policyPath(), "utf8")).clients, CLIENTS);
      await s.close();
      const reloaded = new NmzpStore(dir);
      await reloaded.load();
      assert.deepEqual(reloaded.getPolicy().clients, CLIENTS);
      reloaded.getPolicy().clients![0]!.deviceId = "mutated";
      assert.equal(reloaded.getPolicy().clients![0]!.deviceId, "a");
      await reloaded.close();
      const disk = JSON.parse(await readFile(join(dir, "policy.json"), "utf8")) as Record<string, unknown>;
      await writeFile(join(dir, "policy.json"), JSON.stringify({ ...disk, clients: [{ deviceId: "a", mode: "follow" }] }));
      await assert.rejects(() => new NmzpStore(dir).load(), /invalid_policy_clients/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("sqlite store round-trips clients in policy.json and policy_revisions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-clients-sql-"));
    try {
      const s = new NmzpStore(dir);
      await s.load({ storageMode: "sqlite" });
      const saved = await s.casPolicy(s.getPolicy().version, { clients: CLIENTS });
      assert.ok(!("conflict" in saved));
      assert.deepEqual(saved.clients, CLIENTS);
      await s.close();
      assert.deepEqual(JSON.parse(await readFile(join(dir, "policy.json"), "utf8")).clients, CLIENTS);
      const db = new DatabaseSync(join(dir, "nmzp.db"), { readOnly: true });
      try {
        const row = db.prepare("SELECT policy_json FROM policy_revisions ORDER BY version DESC LIMIT 1").get() as { policy_json: string };
        assert.deepEqual(JSON.parse(row.policy_json).clients, CLIENTS);
      } finally {
        db.close();
      }
      const reloaded = new NmzpStore(dir);
      await reloaded.load({ storageMode: "sqlite" });
      assert.deepEqual(reloaded.getPolicy().clients, CLIENTS);
      await reloaded.close();
      const disk = JSON.parse(await readFile(join(dir, "policy.json"), "utf8")) as Record<string, unknown>;
      await writeFile(join(dir, "policy.json"), JSON.stringify({ ...disk, clients: [{ deviceId: "a", mode: "follow" }] }));
      await assert.rejects(() => new NmzpStore(dir).load({ storageMode: "sqlite" }), /invalid_policy_clients/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("cache keeps valid clients, tolerates absence, and drops a bad shape", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-clients-cache-"));
    try {
      const file = join(dir, "cache.json");
      await writePolicyCache(file, { ...base, clients: CLIENTS });
      assert.deepEqual((await readPolicyCache(file))?.clients, CLIENTS);
      await writePolicyCache(file, base);
      assert.equal((await readPolicyCache(file))?.clients, undefined);
      await writePolicyCache(file, { ...base, clients: [{ deviceId: "a", mode: "follow" }] } as unknown as PolicyState);
      assert.equal(await readPolicyCache(file), null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
