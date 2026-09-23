import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createPolicySnapshot } from "./snapshot.ts";
import { PolicyPublisher, PolicyPublishError } from "./publisher.ts";

const fixture = (extra = {}) => ({
  version: 7, updatedAt: 100, mode: "enforcing", stopped: false,
  customRules: [], protected: "block", ...extra,
});
const bodyOf = ({ version: _v, updatedAt: _t, ...body }) => body;
function gate() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
async function open(options = {}, initial = fixture()) {
  return PolicyPublisher.open(initial, {
    prepare: () => {}, persist: async () => ({ kind: "committed" }), now: () => 200,
    ...options,
  });
}
const codeIs = (code) => (error) => error instanceof PolicyPublishError && error.code === code;

// Injected persistence/validation below is synthetic, not real fsync or real NMZP rules.
describe("single-writer policy publication", () => {
  it("validates startup without writing, and requires explicit adapters", async () => {
    let prepared = 0; let written = 0;
    const publisher = await open({ prepare: () => { prepared++; }, persist: async () => { written++; return { kind: "committed" }; } });
    assert.equal(prepared, 1); assert.equal(written, 0);
    assert.equal(publisher.capture().policy.version, 7);
    await assert.rejects(PolicyPublisher.open(fixture(), {}), /required/);
    await assert.rejects(open({ prepare() { throw new Error("invalid initial"); } }), /invalid initial/);
    for (const maxPending of [0, -1, 1.5, 1025]) await assert.rejects(open({ maxPending }), RangeError);
  });

  it("prepares then persists before publishing; old readers remain stable", async () => {
    const entered = gate(); const release = gate(); const steps = [];
    const publisher = await open({
      prepare: (s) => { steps.push(`prepare:${s.policy.version}`); },
      persist: async (next, previous) => {
        assert.equal(previous.policy.version, 7);
        steps.push(`persist:${next.policy.version}`); entered.resolve();
        await release.promise; return { kind: "committed" };
      },
    });
    const pinned = publisher.capture();
    const pending = publisher.publish(7, bodyOf(fixture({ mode: "permissive" })));
    await entered.promise;
    assert.equal(publisher.capture(), pinned);
    release.resolve();
    const result = await pending;
    assert.equal(result.conflict, false);
    assert.equal(result.snapshot.policy.version, 8);
    assert.equal(publisher.capture().policy.mode, "permissive");
    assert.equal(pinned.policy.mode, "enforcing");
    assert.equal(pinned.policy.version, 7);
    assert.deepEqual(steps, ["prepare:7", "prepare:8", "persist:8"]);
  });

  it("captures the submitted body before any asynchronous wait", async () => {
    const entered = gate(); const release = gate();
    const publisher = await open({
      prepare: async (s) => { if (s.policy.version === 8) { entered.resolve(); await release.promise; } },
    });
    const body = bodyOf(fixture({ customRules: [{ id: "original" }] }));
    const pending = publisher.publish(7, body);
    body.customRules[0].id = "mutated";
    await entered.promise; release.resolve();
    assert.equal((await pending).snapshot.policy.customRules[0].id, "original");
  });

  it("same-version concurrent writes have one winner and no implicit retry", async () => {
    let writes = 0;
    const publisher = await open({ persist: async () => { writes++; return { kind: "committed" }; } });
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) =>
      publisher.publish(7, bodyOf(fixture({ label: `candidate-${index}` })))));
    assert.equal(results.filter((r) => !r.conflict).length, 1);
    assert.equal(results.filter((r) => r.conflict && r.version === 8).length, 7);
    assert.equal(writes, 1);
    assert.equal(publisher.capture().policy.label, "candidate-0");
    assert.equal(publisher.pendingCount, 0);
  });

  it("does not prepare or persist a stale-version candidate", async () => {
    let prepared = 0; let written = 0;
    const publisher = await open({ prepare: () => { prepared++; }, persist: async () => { written++; return { kind: "committed" }; } });
    assert.deepEqual(await publisher.publish(6, bodyOf(fixture())), { conflict: true, version: 7 });
    assert.equal(prepared, 1); assert.equal(written, 0);
  });

  it("serializes successive revisions and bounds the pending queue", async () => {
    const entered = gate(); const release = gate(); let activeWrites = 0; let maximum = 0;
    const publisher = await open({ maxPending: 2, persist: async (next) => {
      activeWrites++; maximum = Math.max(maximum, activeWrites);
      if (next.policy.version === 8) { entered.resolve(); await release.promise; }
      activeWrites--; return { kind: "committed" };
    } });
    const first = publisher.publish(7, bodyOf(fixture()));
    await entered.promise;
    const second = publisher.publish(8, bodyOf(fixture({ label: "second" })));
    await assert.rejects(publisher.publish(9, bodyOf(fixture())), codeIs("policy_queue_full"));
    release.resolve();
    assert.equal((await first).snapshot.policy.version, 8);
    assert.equal((await second).snapshot.policy.version, 9);
    assert.equal(maximum, 1); assert.equal(publisher.pendingCount, 0);
  });

  it("rejects managed metadata, invalid expected versions and invalid body shapes", async () => {
    const publisher = await open();
    for (const body of [fixture(), { updatedAt: undefined }, { version: 8 }]) {
      await assert.rejects(publisher.publish(7, body), codeIs("managed_revision_fields"));
    }
    for (const expected of [0, -1, 1.2, "7", NaN, Infinity]) {
      await assert.rejects(publisher.publish(expected, {}), codeIs("invalid_expected_version"));
    }
    for (const body of [null, [], false, "json"]) {
      await assert.rejects(publisher.publish(7, body), codeIs("invalid_policy_body"));
    }
    assert.equal(publisher.capture().policy.version, 7);
  });

  it("keeps the last confirmed snapshot on prepare failure and continues safely", async () => {
    const publisher = await open({ prepare: (s) => {
      if (s.policy.protected !== "block") throw new Error("synthetic protected constraint");
    } });
    const previous = publisher.capture();
    await assert.rejects(publisher.publish(7, bodyOf(fixture({ protected: "off" }))), /protected constraint/);
    assert.equal(publisher.capture(), previous); assert.equal(publisher.recoveryRequired, false);
    assert.equal((await publisher.publish(7, bodyOf(fixture()))).snapshot.policy.version, 8);
  });

  it("does not write before asynchronous prepare has finished", async () => {
    const entered = gate(); const release = gate(); let writes = 0;
    const publisher = await open({
      prepare: async (s) => { if (s.policy.version === 8) { entered.resolve(); await release.promise; } },
      persist: async () => { writes++; return { kind: "committed" }; },
    });
    const pending = publisher.publish(7, bodyOf(fixture()));
    await entered.promise;
    assert.equal(writes, 0); assert.equal(publisher.capture().policy.version, 7);
    release.resolve(); await pending; assert.equal(writes, 1);
  });

  it("known non-commit leaves old state and allows a later retry", async () => {
    let writes = 0;
    const publisher = await open({ persist: async () => ({ kind: ++writes === 1 ? "not_committed" : "committed" }) });
    const previous = publisher.capture();
    await assert.rejects(publisher.publish(7, bodyOf(fixture())), codeIs("policy_not_committed"));
    assert.equal(publisher.capture(), previous); assert.equal(publisher.recoveryRequired, false);
    assert.equal((await publisher.publish(7, bodyOf(fixture()))).snapshot.policy.version, 8);
  });

  it("ambiguous write errors fence publication and new captures without leaking details", async () => {
    const publisher = await open({ persist: async () => { throw new Error("sensitive-backend-path"); } });
    const pinned = publisher.capture();
    await assert.rejects(publisher.publish(7, bodyOf(fixture())), (error) => {
      assert.equal(error.code, "policy_recovery_required");
      assert.ok(!error.message.includes("sensitive-backend-path")); return true;
    });
    assert.equal(publisher.recoveryRequired, true);
    assert.throws(() => publisher.capture(), codeIs("policy_recovery_required"));
    await assert.rejects(publisher.publish(7, bodyOf(fixture())), codeIs("policy_recovery_required"));
    assert.equal(pinned.policy.version, 7, "already captured immutable data is not mutated");
  });

  it("a thrown not-committed error is ambiguous; only an explicit outcome is trusted", async () => {
    const publisher = await open({ persist: async () => { throw new PolicyPublishError("policy_not_committed"); } });
    await assert.rejects(publisher.publish(7, bodyOf(fixture())), codeIs("policy_recovery_required"));
    assert.equal(publisher.recoveryRequired, true);
  });

  it("invalid persistence outcomes require reload instead of guessing success", async () => {
    for (const outcome of [null, undefined, true, {}, { kind: "queued" }, { get kind() { throw new Error("bad"); } }]) {
      const publisher = await open({ persist: async () => outcome });
      await assert.rejects(publisher.publish(7, bodyOf(fixture())), codeIs("policy_recovery_required"));
    }
  });

  it("aborts already queued writes after an ambiguous commit", async () => {
    const entered = gate(); const release = gate(); let writes = 0;
    const publisher = await open({ persist: async () => {
      writes++; entered.resolve(); await release.promise; throw new Error("unknown write result");
    } });
    const first = publisher.publish(7, bodyOf(fixture()));
    await entered.promise;
    const second = publisher.publish(8, bodyOf(fixture()));
    const settled = Promise.allSettled([first, second]);
    release.resolve();
    const results = await settled;
    assert.equal(writes, 1);
    for (const result of results) {
      assert.equal(result.status, "rejected"); assert.equal(result.reason.code, "policy_recovery_required");
    }
    assert.equal(publisher.pendingCount, 0);
  });

  it("clock regression cannot decrease updatedAt; invalid clocks do not write", async () => {
    const publisher = await open({ now: () => 50 });
    assert.equal((await publisher.publish(7, bodyOf(fixture()))).snapshot.policy.updatedAt, 100);
    for (const now of [NaN, -1, 1.5, Infinity]) {
      let writes = 0;
      const p = await open({ now: () => now, persist: async () => { writes++; return { kind: "committed" }; } });
      await assert.rejects(p.publish(7, bodyOf(fixture())), codeIs("invalid_policy_clock"));
      assert.equal(writes, 0); assert.equal(p.capture().policy.version, 7);
    }
  });

  it("refuses version overflow before prepare/persist", async () => {
    let writes = 0;
    const publisher = await open({ persist: async () => { writes++; return { kind: "committed" }; } }, fixture({ version: Number.MAX_SAFE_INTEGER }));
    await assert.rejects(publisher.publish(Number.MAX_SAFE_INTEGER, bodyOf(fixture())), codeIs("policy_version_exhausted"));
    assert.equal(writes, 0);
  });

  it("restores old content as a new validated revision", async () => {
    const prepared = [];
    const publisher = await open({ prepare: (s) => { prepared.push(s.policy.version); } });
    const old = publisher.capture();
    const changed = await publisher.publish(7, bodyOf(fixture({ mode: "permissive" })));
    assert.equal(changed.conflict, false);
    assert.equal(changed.snapshot.policy.version, 8);
    const restored = await publisher.restore(8, old);
    assert.equal(restored.conflict, false);
    assert.equal(restored.snapshot.policy.mode, "enforcing");
    assert.equal(restored.snapshot.policy.version, 9);
    assert.equal(restored.snapshot.policy.updatedAt, 200);
    assert.equal(old.policy.version, 7);
    assert.notEqual(restored.snapshot.hash, old.hash);
    assert.deepEqual(prepared, [7, 8, 9]);
  });

  it("restores through current validation and rejects mismatched/future snapshots", async () => {
    const publisher = await open({ prepare: (s) => {
      if (s.policy.protected !== "block") throw new Error("current validation");
    } });
    const rejected = createPolicySnapshot(fixture({ version: 1, protected: "off" }));
    await assert.rejects(publisher.restore(7, rejected), /current validation/);
    await assert.rejects(publisher.restore(7, { ...publisher.capture(), hash: "wrong" }), codeIs("invalid_restore_snapshot"));
    await assert.rejects(publisher.restore(7, createPolicySnapshot(fixture({ version: 99 }))), codeIs("invalid_restore_snapshot"));
    assert.equal(publisher.capture().policy.version, 7);
  });

  it("owns its options so external mutation cannot replace persistence or limits", async () => {
    const options = { limits: { maxBytes: 512 }, persist: async () => ({ kind: "committed" }) };
    const publisher = await open(options);
    options.limits.maxBytes = 1; options.persist = async () => { throw new Error("mutated"); };
    assert.equal((await publisher.publish(7, bodyOf(fixture()))).snapshot.policy.version, 8);
  });
});
