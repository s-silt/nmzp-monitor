const RESTORE_CONTROL_FIELDS = ["mode", "stopped", "githubUpload", "archiveUpload"] as const;

export type RestoreControlField = (typeof RESTORE_CONTROL_FIELDS)[number];

export interface RestoreControlChange {
  field: RestoreControlField;
  current: unknown;
  restored: unknown;
}

export interface RestoreControlCurrent {
  mode: unknown;
  stopped: unknown;
  githubUpload: unknown;
  archiveUpload: unknown;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function definedKeys(value: Record<string, unknown>): string[] {
  return Object.keys(value).filter((key) => value[key] !== undefined);
}

/** Key order is irrelevant. Undefined properties match capturePolicyData, which drops them. */
function canonicalEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (typeof left !== "object" || typeof right !== "object" || left === null || right === null) {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) {
      if (!canonicalEqual(left[index], right[index])) return false;
    }
    return true;
  }
  if (!plainObject(left) || !plainObject(right)) return false;
  const leftKeys = definedKeys(left);
  const rightKeys = definedKeys(right);
  if (leftKeys.length !== rightKeys.length) return false;
  for (const key of leftKeys) {
    if (!Object.hasOwn(right, key) || right[key] === undefined || !canonicalEqual(left[key], right[key])) {
      return false;
    }
  }
  return true;
}

function restoredControl(policy: Record<string, unknown>, field: RestoreControlField): unknown {
  if (!Object.hasOwn(policy, field)) return undefined;
  const value = policy[field];
  return value === undefined ? undefined : value;
}

/**
 * publisher.restore republishes the historical body with version/updatedAt stripped.
 * It does not copy missing keys from the active policy. capturePolicyData also omits
 * undefined, so a missing control is absent on the next document and is listed only
 * when that absent value differs from current.
 */
export function restoreControlChanges(
  historicalPolicy: unknown,
  current: RestoreControlCurrent,
): RestoreControlChange[] | null {
  if (!plainObject(historicalPolicy)) return null;
  const changes: RestoreControlChange[] = [];
  for (const field of RESTORE_CONTROL_FIELDS) {
    const restored = restoredControl(historicalPolicy, field);
    if (!canonicalEqual(current[field], restored)) {
      changes.push({ field, current: current[field], restored });
    }
  }
  return changes;
}
