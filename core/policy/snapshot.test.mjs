import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";
import { capturePolicyData, createPolicySnapshot } from "./snapshot.ts";

const fixture = (extra = {}) => ({
  version: 7, updatedAt: 100, mode: "enforcing", stopped: false,
  customRules: [{ id: "fixture", match: "synthetic", scope: { tools: ["Bash"] } }],
  ...extra,
});

// Pure JSON/identity tests. Not tests of NMZP's real rule validation or authorization.
describe("immutable policy snapshot", () => {
  it("owns all nested objects and arrays without freezing caller input", () => {
    const input = fixture();
    const snapshot = createPolicySnapshot(input);
    input.customRules[0].scope.tools.push("Read");
    input.mode = "off";
    assert.equal(snapshot.policy.mode, "enforcing");
    assert.deepEqual(snapshot.policy.customRules[0].scope.tools, ["Bash"]);
    assert.ok(!Object.isFrozen(input));
    assert.ok(Object.isFrozen(snapshot));
    assert.ok(Object.isFrozen(snapshot.policy));
    assert.ok(Object.isFrozen(snapshot.policy.customRules[0].scope.tools));
    assert.throws(() => { snapshot.policy.mode = "off"; }, TypeError);
    assert.throws(() => snapshot.policy.customRules.push({}), TypeError);
    assert.throws(() => { snapshot.hash = "changed"; }, TypeError);
  });

  it("produces equal identity for equivalent property order", () => {
    const left = fixture({ overrides: { rules: { b: "log", a: "block" }, families: {} } });
    const right = {
      overrides: { families: {}, rules: { a: "block", b: "log" } },
      customRules: left.customRules, stopped: false, mode: "enforcing", updatedAt: 100, version: 7,
    };
    assert.equal(createPolicySnapshot(left).hash, createPolicySnapshot(right).hash);
  });

  it("includes version, timestamp, array order and policy values in identity", () => {
    const initial = createPolicySnapshot(fixture());
    for (const patch of [
      { version: 8 }, { updatedAt: 101 }, { mode: "off" },
      { customRules: [{ id: "b" }, { id: "a" }] },
      { customRules: [{ id: "a" }, { id: "b" }] },
    ]) assert.notEqual(createPolicySnapshot(fixture(patch)).hash, initial.hash);
    const a = createPolicySnapshot(fixture({ customRules: [1, 2] }));
    const b = createPolicySnapshot(fixture({ customRules: [2, 1] }));
    assert.notEqual(a.hash, b.hash);
    assert.match(initial.hash, /^[a-f0-9]{64}$/);
    assert.equal(initial.hash, createHash("sha256").update(JSON.stringify(initial.policy)).digest("hex"));
  });

  it("omits undefined object fields without changing null or empty arrays", () => {
    const snap = createPolicySnapshot(fixture({ optional: undefined, empty: [], nil: null }));
    assert.ok(!Object.hasOwn(snap.policy, "optional"));
    assert.equal(snap.policy.nil, null);
    assert.deepEqual(snap.policy.empty, []);
  });

  it("normalizes negative zero to its JSON representation", () => {
    const data = capturePolicyData({ n: -0 });
    assert.ok(Object.is(data.n, 0));
  });

  it("preserves dangerous-looking JSON keys without prototype pollution", () => {
    const input = JSON.parse('{"__proto__":{"polluted":true},"constructor":"value"}');
    const data = capturePolicyData(input);
    assert.equal(Object.getPrototypeOf(data), Object.prototype);
    assert.ok(Object.hasOwn(data, "__proto__"));
    assert.equal(data.__proto__.polluted, true);
    assert.equal({}.polluted, undefined);
    assert.deepEqual(JSON.parse(JSON.stringify(data)), input);
  });

  it("accepts null-prototype dictionaries and shared acyclic subobjects", () => {
    const shared = { value: "same" };
    const data = capturePolicyData(Object.assign(Object.create(null), { a: shared, b: shared }));
    assert.deepEqual(data.a, data.b);
    assert.notEqual(data.a, shared);
    assert.notEqual(data.a, data.b);
  });

  it("rejects cycles, exotic objects and non-JSON values", () => {
    const cycle = {}; cycle.self = cycle;
    for (const value of [cycle, new Date(), new Map(), new Set(), /x/, Buffer.from("x"),
      () => {}, 1n, Symbol("x"), NaN, Infinity, undefined]) {
      assert.throws(() => capturePolicyData(value), /invalid_policy_snapshot/);
    }
  });

  it("rejects object accessors without invoking them", () => {
    let calls = 0;
    const input = fixture();
    Object.defineProperty(input, "secret", { enumerable: true, get() { calls++; return "sensitive"; } });
    assert.throws(() => createPolicySnapshot(input), /property/);
    assert.equal(calls, 0);
  });

  it("rejects executable toJSON, symbols and hidden own properties", () => {
    let calls = 0;
    assert.throws(() => createPolicySnapshot(fixture({ toJSON() { calls++; return {}; } })), /non_json_value/);
    assert.equal(calls, 0);
    assert.throws(() => capturePolicyData({ [Symbol("x")]: 1 }), /symbol_key/);
    assert.throws(() => capturePolicyData(Object.defineProperty({}, "hidden", { value: 1 })), /property/);
  });

  it("rejects sparse/undefined arrays, custom properties, and array accessors", () => {
    const extra = [1]; extra.label = "not JSON";
    const getter = [1]; let calls = 0;
    Object.defineProperty(getter, "0", { enumerable: true, get() { calls++; return 1; } });
    for (const value of [[undefined], new Array(2), extra, getter]) {
      assert.throws(() => capturePolicyData(value), /invalid_policy_snapshot/);
    }
    assert.equal(calls, 0);
  });

  it("validates revision metadata and object roots", () => {
    for (const version of [0, -1, 1.5, "7", NaN, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => createPolicySnapshot(fixture({ version })), /invalid_policy_snapshot/);
    }
    for (const updatedAt of [-1, 1.5, "100", NaN, Infinity]) {
      assert.throws(() => createPolicySnapshot(fixture({ updatedAt })), /invalid_policy_snapshot/);
    }
    for (const value of [null, [], false, 42, "value"]) {
      assert.throws(() => createPolicySnapshot(value), /invalid_policy_snapshot/);
    }
    assert.equal(createPolicySnapshot(fixture({ updatedAt: 0 })).policy.updatedAt, 0);
  });

  it("enforces exact encoded UTF-8 byte limits including escaped characters", () => {
    const input = { text: "中文\n\"" };
    const bytes = Buffer.byteLength(JSON.stringify(input));
    assert.deepEqual(capturePolicyData(input, { maxBytes: bytes }), input);
    assert.throws(() => capturePolicyData(input, { maxBytes: bytes - 1 }), /size/);
    assert.throws(() => capturePolicyData({ value: "x".repeat(100) }, { maxBytes: 10 }), /size/);
  });

  it("enforces depth/node limits and rejects invalid limits", () => {
    assert.throws(() => capturePolicyData({ a: { b: { c: 1 } } }, { maxDepth: 1 }), /depth/);
    assert.throws(() => capturePolicyData([1, 2, 3], { maxNodes: 2 }), /nodes/);
    assert.throws(() => capturePolicyData({ a: 1, b: 2 }, { maxNodes: 2 }), /nodes/);
    for (const key of ["maxBytes", "maxDepth", "maxNodes"]) {
      for (const value of [0, -1, 1.5, NaN]) {
        assert.throws(() => capturePolicyData({}, { [key]: value }), /limits/);
      }
    }
  });
});
