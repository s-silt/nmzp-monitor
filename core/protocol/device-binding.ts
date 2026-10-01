/** D12 body identity. v2 evaluate and the optional `device` member on other v2 routes share this comparison. */
const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

/** Declared id must be that exact token-device string. */
export function sameDeviceId(declared: unknown, deviceId: string): boolean {
  return typeof declared === "string" && declared === deviceId;
}

/**
 * Absent `device` is unchanged. A present `device` must be a plain `{ id }` for this token;
 * a match deletes it so the v1 parser sees the remaining members. Anything else is unauthorized.
 */
export function bindBodyDevice(body: unknown, deviceId: string): boolean {
  if (!isRecord(body) || !Object.hasOwn(body, "device")) return true;
  const device = body.device;
  if (!isRecord(device)) return false;
  const own = Object.keys(device);
  if (own.length !== 1 || own[0] !== "id" || !sameDeviceId(device.id, deviceId)) return false;
  delete body.device;
  return true;
}
