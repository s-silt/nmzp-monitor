/** Identity of an audit event. Different machines may use the same event id. */
export interface EventIdentity {
  readonly machineId: string;
  readonly id: string;
}

interface Entry<T> {
  readonly key: string;
  value: T;
}

export type AppendResult<T> =
  | { readonly inserted: false; readonly event: T }
  | { readonly inserted: true; readonly event: T; readonly evicted?: T };

/**
 * Bounded, insertion-ordered recent-event cache with O(1) lookup and update.
 *
 * This is NOT a durable store or a durable deduplication ledger. Commit to the
 * persistent store before publishing a change here. Treat cached values as
 * immutable; replace a value with update() instead of mutating its identity.
 */
export class RecentEvents<T extends EventIdentity> {
  readonly capacity: number;
  private readonly slots: Array<Entry<T> | undefined> = [];
  private readonly index = new Map<string, Entry<T>>();
  private head = 0;
  private count = 0;

  constructor(capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 0xffff_ffff) {
      throw new RangeError("event_capacity_invalid");
    }
    this.capacity = capacity;
  }

  get size(): number {
    return this.count;
  }

  get(machineId: string, eventId: string): T | undefined {
    return this.index.get(eventKey(machineId, eventId))?.value;
  }

  /** A duplicate keeps both the first value and its original position. */
  append(event: T): AppendResult<T> {
    const key = eventKey(event.machineId, event.id);
    const existing = this.index.get(key);
    if (existing) return { inserted: false, event: existing.value };

    const slot = (this.head + this.count) % this.capacity;
    let evicted: T | undefined;
    if (this.count === this.capacity) {
      const oldest = this.slots[this.head]!;
      evicted = oldest.value;
      this.index.delete(oldest.key);
      this.head = (this.head + 1) % this.capacity;
    } else {
      this.count += 1;
    }

    const entry: Entry<T> = { key, value: event };
    this.slots[slot] = entry;
    this.index.set(key, entry);
    return evicted === undefined
      ? { inserted: true, event }
      : { inserted: true, event, evicted };
  }

  /** Replace a retained event without changing its order or capacity. */
  update(event: T): boolean {
    const existing = this.index.get(eventKey(event.machineId, event.id));
    if (!existing) return false;
    existing.value = event;
    return true;
  }

  /** Return up to limit newest entries, in oldest-to-newest insertion order. */
  list(limit = this.count): T[] {
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new RangeError("event_limit_invalid");
    }
    const length = Math.min(limit, this.count);
    const result: T[] = [];
    const start = this.count - length;
    for (let offset = start; offset < this.count; offset += 1) {
      result.push(this.slots[(this.head + offset) % this.capacity]!.value);
    }
    return result;
  }

  clear(): void {
    this.slots.length = 0;
    this.index.clear();
    this.head = 0;
    this.count = 0;
  }
}

/** Length-prefix the machine id so embedded separators cannot alias a key. */
function eventKey(machineId: string, eventId: string): string {
  if (typeof machineId !== "string" || typeof eventId !== "string") {
    throw new TypeError("event_identity_invalid");
  }
  return `${machineId.length}:${machineId}${eventId}`;
}
