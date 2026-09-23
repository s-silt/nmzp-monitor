import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { RecentEvents } from "./recent-events.ts";

interface Event { machineId: string; id: string; value: number }
const event = (id: string, value = 0, machineId = "device"): Event => ({ machineId, id, value });
const ids = (rows: Event[]) => rows.map((row) => `${row.machineId}/${row.id}/${row.value}`);

describe("RecentEvents", () => {
  it("starts empty and rejects invalid capacity", () => {
    const cache = new RecentEvents<Event>(2);
    assert.equal(cache.size, 0);
    assert.deepEqual(cache.list(), []);
    assert.equal(cache.get("device", "a"), undefined);
    for (const n of [0, -1, 0.5, NaN, Infinity, 0x1_0000_0000]) {
      assert.throws(() => new RecentEvents<Event>(n), /event_capacity_invalid/);
    }
  });

  it("evicts the oldest event and its lookup entry after wraparound", () => {
    const cache = new RecentEvents<Event>(3);
    for (const id of ["a", "b", "c"]) cache.append(event(id));
    const added = cache.append(event("d"));
    assert.equal(added.inserted, true);
    if (added.inserted) assert.equal(added.evicted?.id, "a");
    assert.deepEqual(cache.list().map((row) => row.id), ["b", "c", "d"]);
    assert.equal(cache.get("device", "a"), undefined);
    assert.equal(cache.get("device", "d")?.id, "d");
    for (const id of ["e", "f", "g", "h"]) cache.append(event(id));
    assert.deepEqual(cache.list().map((row) => row.id), ["f", "g", "h"]);
    assert.equal(cache.size, 3);
  });

  it("does not overwrite or reorder duplicate event ids", () => {
    const cache = new RecentEvents<Event>(2);
    cache.append(event("a", 1));
    cache.append(event("b", 2));
    const duplicate = cache.append(event("a", 99));
    assert.deepEqual(duplicate, { inserted: false, event: event("a", 1) });
    assert.deepEqual(cache.list(), [event("a", 1), event("b", 2)]);
    cache.append(event("c", 3));
    assert.equal(cache.get("device", "a"), undefined);
  });

  it("updates a receipt projection in place without reordering", () => {
    const cache = new RecentEvents<Event>(2);
    cache.append(event("a", 1));
    cache.append(event("b", 2));
    assert.equal(cache.update(event("a", 3)), true);
    assert.equal(cache.update(event("missing")), false);
    assert.deepEqual(cache.list(), [event("a", 3), event("b", 2)]);
    assert.equal(cache.get("device", "a")?.value, 3);
  });

  it("keeps device identities separate, including embedded separators", () => {
    const cache = new RecentEvents<Event>(8);
    const rows = [event("b:c", 1, "a"), event("c", 2, "a:b"), event("id", 3, ""), event("id", 4, "设备")];
    for (const row of rows) cache.append(row);
    for (const row of rows) assert.deepEqual(cache.get(row.machineId, row.id), row);
    assert.equal(cache.size, rows.length);
  });

  it("lists only the requested tail and gives zero an explicit meaning", () => {
    const cache = new RecentEvents<Event>(3);
    for (const id of ["a", "b", "c", "d"]) cache.append(event(id));
    assert.deepEqual(cache.list(0), []);
    assert.deepEqual(cache.list(1), [event("d")]);
    assert.deepEqual(cache.list(2), [event("c"), event("d")]);
    assert.deepEqual(cache.list(999), [event("b"), event("c"), event("d")]);
    for (const n of [-1, 0.5, NaN, Infinity]) assert.throws(() => cache.list(n), /event_limit_invalid/);
    const snapshot = cache.list();
    snapshot.pop();
    assert.equal(cache.size, 3);
  });

  it("clears all entries and can be reused, including capacity one", () => {
    const cache = new RecentEvents<Event>(1);
    cache.append(event("a"));
    cache.append(event("b"));
    assert.deepEqual(cache.list(), [event("b")]);
    cache.clear();
    assert.equal(cache.get("device", "b"), undefined);
    assert.equal(cache.size, 0);
    cache.append(event("c"));
    assert.deepEqual(cache.list(), [event("c")]);
  });

  it("matches a simple reference model over 20000 seeded operations", () => {
    const capacity = 31;
    const cache = new RecentEvents<Event>(capacity);
    let reference: Event[] = [];
    let seed = 0x4e4d5a50;
    const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
    for (let step = 0; step < 20000; step += 1) {
      const operation = next() % 10;
      const row = event(String(next() % 50), step, String(next() % 4));
      const same = (r: Event) => r.machineId === row.machineId && r.id === row.id;
      if (operation < 6) {
        const previous = reference.find(same);
        const result = cache.append(row);
        assert.equal(result.inserted, !previous);
        if (!previous) reference = [...reference, row].slice(-capacity);
      } else if (operation < 9) {
        const position = reference.findIndex(same);
        assert.equal(cache.update(row), position !== -1);
        if (position !== -1) reference[position] = row;
      } else {
        cache.clear();
        reference = [];
      }
      assert.equal(cache.size, reference.length);
      assert.deepEqual(ids(cache.list()), ids(reference));
      assert.deepEqual(cache.get(row.machineId, row.id), reference.find(same));
    }
  });
});
