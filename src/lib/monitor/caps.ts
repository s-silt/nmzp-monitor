/** Hard caps so a long session cannot grow without bound. */

export const MAX_EVENTS = 360;
export const MAX_HOPS = 40;
export const MAX_APPROVALS = 24;
export const MAX_PENDING = 8;
export const MAX_TURNS = 32;
export const MAX_WINDOW = 8;
export const SETTINGS_KEY = "nmzp-monitor";
export const SETTINGS_MAX_BYTES = 8192;

export function capArray<T>(items: T[], max: number): T[] {
  return items.length > max ? items.slice(items.length - max) : items;
}
