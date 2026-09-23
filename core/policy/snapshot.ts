import { createHash } from "node:crypto";

/** Structural constraint: the existing PolicyState satisfies this interface. */
export interface PolicyRevision {
  version: number;
  updatedAt: number;
}

export type DeepReadonly<T> = T extends readonly (infer Item)[]
  ? readonly DeepReadonly<Item>[]
  : T extends object
    ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
    : T;

export interface SnapshotLimits {
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

export interface PolicySnapshot<T extends PolicyRevision> {
  readonly policy: DeepReadonly<T>;
  /** Identity of normalized JSON, NOT a signature or proof of authority. */
  readonly hash: string;
}

export class InvalidPolicySnapshot extends Error {
  readonly code = "invalid_policy_snapshot";

  constructor(reason: string) {
    super(`invalid_policy_snapshot:${reason}`);
    this.name = "InvalidPolicySnapshot";
  }
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function positiveLimit(value: number | undefined, fallback: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1) throw new InvalidPolicySnapshot("limits");
  return result;
}

/**
 * Accept data, not executable objects. The caller must still validate the policy
 * schema, rule catalog and protected-rule invariants before publishing.
 * Object-valued undefined is omitted as in JSON; array holes/undefined are rejected.
 */
export function capturePolicyData<T>(input: T, limits: SnapshotLimits = {}): DeepReadonly<T> {
  const maxBytes = positiveLimit(limits.maxBytes, 262_144);
  const maxDepth = positiveLimit(limits.maxDepth, 32);
  const maxNodes = positiveLimit(limits.maxNodes, 16_384);
  const ancestors = new Set<object>();
  let nodes = 0;
  let estimatedBytes = 0;

  function account(text: string): void {
    estimatedBytes += Buffer.byteLength(text, "utf8");
    if (estimatedBytes > maxBytes) throw new InvalidPolicySnapshot("size");
  }

  function visit(value: unknown, depth: number): JsonValue {
    if (++nodes > maxNodes) throw new InvalidPolicySnapshot("nodes");
    if (depth > maxDepth) throw new InvalidPolicySnapshot("depth");
    if (value === null || typeof value === "boolean") {
      account(String(value));
      return value;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new InvalidPolicySnapshot("number");
      const normalized = Object.is(value, -0) ? 0 : value;
      account(String(normalized));
      return normalized;
    }
    if (typeof value === "string") {
      if (Buffer.byteLength(value, "utf8") > maxBytes) throw new InvalidPolicySnapshot("size");
      // Account for quoting and escapes too, not only the raw character count.
      account(JSON.stringify(value));
      return value;
    }
    if (typeof value !== "object") throw new InvalidPolicySnapshot("non_json_value");
    if (ancestors.has(value)) throw new InvalidPolicySnapshot("cycle");
    if (Object.getOwnPropertySymbols(value).length) throw new InvalidPolicySnapshot("symbol_key");
    const isArray = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (isArray ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
      throw new InvalidPolicySnapshot("prototype");
    }
    ancestors.add(value);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Object.keys(descriptors).length > maxNodes) throw new InvalidPolicySnapshot("nodes");
      if (isArray) {
        if (value.length > maxNodes) throw new InvalidPolicySnapshot("nodes");
        const keys = Object.keys(descriptors).filter((key) => key !== "length");
        if (keys.length !== value.length) throw new InvalidPolicySnapshot("array_shape");
        const result: JsonValue[] = [];
        account("[]");
        for (let index = 0; index < value.length; index++) {
          const descriptor = descriptors[String(index)];
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
            throw new InvalidPolicySnapshot("array_shape");
          }
          if (index) account(",");
          result.push(visit(descriptor.value, depth + 1));
        }
        return Object.freeze(result) as JsonValue[];
      }
      const result: { [key: string]: JsonValue } = {};
      account("{}");
      let count = 0;
      for (const key of Object.keys(descriptors).sort()) {
        const descriptor = descriptors[key]!;
        if (!("value" in descriptor) || !descriptor.enumerable) {
          throw new InvalidPolicySnapshot("property");
        }
        if (descriptor.value === undefined) continue;
        if (count++) account(",");
        account(`${JSON.stringify(key)}:`);
        // defineProperty preserves JSON keys such as __proto__ without invoking a setter.
        Object.defineProperty(result, key, {
          value: visit(descriptor.value, depth + 1),
          enumerable: true,
          writable: false,
          configurable: false,
        });
      }
      return Object.freeze(result);
    } finally {
      ancestors.delete(value);
    }
  }

  const data = visit(input, 0);
  if (Buffer.byteLength(JSON.stringify(data), "utf8") > maxBytes) {
    throw new InvalidPolicySnapshot("size");
  }
  return data as DeepReadonly<T>;
}

export function createPolicySnapshot<T extends PolicyRevision>(
  input: T,
  limits: SnapshotLimits = {},
): PolicySnapshot<T> {
  const policy = capturePolicyData(input, limits);
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new InvalidPolicySnapshot("root");
  }
  if (!Number.isSafeInteger(policy.version) || policy.version < 1) {
    throw new InvalidPolicySnapshot("version");
  }
  if (!Number.isSafeInteger(policy.updatedAt) || policy.updatedAt < 0) {
    throw new InvalidPolicySnapshot("updated_at");
  }
  const hash = createHash("sha256").update(JSON.stringify(policy), "utf8").digest("hex");
  return Object.freeze({ policy, hash });
}
