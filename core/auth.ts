import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function newSecret(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

export function safeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function newDeviceId(): string {
  return `dev_${randomBytes(12).toString("hex")}`;
}

export function newEventId(): string {
  return randomBytes(16).toString("hex");
}

export function parseBearer(header: string | undefined): string | null {
  if (!header || typeof header !== "string") return null;
  const m = /^Bearer\s+(\S+)/i.exec(header.trim());
  return m ? m[1]! : null;
}

export function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    if (k === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
