import type { Msg } from "./i18n.ts";

export type PolicyMutationOutcome =
  | { kind: "ok" }
  | { kind: "conflict" }
  | { kind: "rejected"; error?: string }
  | { kind: "unknown"; matchesRequest: boolean };

function deepEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (typeof left !== "object" || typeof right !== "object" || left === null || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    for (let i = 0; i < left.length; i += 1) {
      if (!deepEqual(left[i], right[i])) return false;
    }
    return true;
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord);
  if (leftKeys.length !== Object.keys(rightRecord).length) return false;
  for (const key of leftKeys) {
    if (!Object.hasOwn(rightRecord, key) || !deepEqual(leftRecord[key], rightRecord[key])) return false;
  }
  return true;
}

/** Content match only. `expectedVersion` is ignored. A version bump by itself is not a match. */
export function requestedFieldsMatch(requested: Record<string, unknown>, fresh: Record<string, unknown>): boolean {
  const keys = Object.keys(requested).filter((key) => key !== "expectedVersion");
  if (keys.length === 0) return false;
  for (const key of keys) {
    if (!Object.hasOwn(fresh, key) || !deepEqual(requested[key], fresh[key])) return false;
  }
  return true;
}

export function mutationMessageKey(outcome: PolicyMutationOutcome | null): Msg {
  if (!outcome || outcome.kind === "ok") return "mutationFailed";
  if (outcome.kind === "conflict") return "mutationConflict";
  if (outcome.kind === "rejected") return "mutationFailed";
  return outcome.matchesRequest ? "mutationUnknownMatches" : "mutationUnknown";
}
