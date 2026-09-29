/** Expand compact over-limit stdin. Absent pad fields return item.stdin unchanged. */
export function resolveGoldenStdin(item) {
  const base = typeof item.stdin === "string" ? item.stdin : "";
  if (item.stdinPadTo === undefined && item.stdinPadChar === undefined) return base;
  if (!Number.isInteger(item.stdinPadTo) || item.stdinPadTo < base.length) {
    throw new Error(`bad stdinPadTo for ${item.id ?? "?"}`);
  }
  const pad = item.stdinPadChar;
  if (typeof pad !== "string" || pad.length !== 1 || pad.charCodeAt(0) > 0x7f) {
    throw new Error(`stdinPadChar must be one ASCII character for ${item.id ?? "?"}`);
  }
  return base + pad.repeat(item.stdinPadTo - base.length);
}
