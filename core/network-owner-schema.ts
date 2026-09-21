/** Internal CT authority. Never accepted from heartbeat or projected to LAN. */
export interface NetworkOwnerGrant {
  id: string;
  agent: "grok" | "claude" | "codex";
  pid: number;
  startedAt: number;
  pathHash: string;
  sha256: string;
  approvedAt: number;
  expiresAt: number;
}
export const OWNER_MAX_MS = 60 * 60 * 1000;
export function parseOwnerGrant(raw: unknown): NetworkOwnerGrant | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
  const r = raw as Record<string, unknown>;
  if (typeof r.id !== "string" || !/^[a-f0-9-]{36}$/.test(r.id) ||
      !["grok", "claude", "codex"].includes(String(r.agent)) ||
      typeof r.pid !== "number" || !Number.isInteger(r.pid) || r.pid < 1 || r.pid > 4e9 ||
      ![r.startedAt, r.approvedAt, r.expiresAt].every(n => typeof n === "number" && Number.isSafeInteger(n) && n > 0) ||
      Number(r.startedAt) > Number(r.approvedAt) || Number(r.expiresAt) <= Number(r.approvedAt) ||
      Number(r.expiresAt) - Number(r.approvedAt) > OWNER_MAX_MS ||
      typeof r.pathHash !== "string" || !/^[a-f0-9]{64}$/.test(r.pathHash) ||
      typeof r.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(r.sha256)) return;
  return {id:r.id,agent:r.agent as NetworkOwnerGrant["agent"],pid:r.pid,startedAt:Number(r.startedAt),
    pathHash:r.pathHash,sha256:r.sha256,approvedAt:Number(r.approvedAt),expiresAt:Number(r.expiresAt)};
}
export function activeOwnerGrants(raw: unknown, now = Date.now()): NetworkOwnerGrant[] {
  if (!Array.isArray(raw) || raw.length > 8) return [];
  return raw.map(parseOwnerGrant).filter((r): r is NetworkOwnerGrant => !!r && r.approvedAt <= now && r.expiresAt > now);
}
