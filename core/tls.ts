/**
 * Dedicated CT certificate. Trusted only inside the NMZP process (ca + fingerprint).
 * Never install into the OS trust store. Never rejectUnauthorized:false.
 */
import { createHash, createSign, generateKeyPairSync, X509Certificate } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export interface TlsMaterial {
  keyPem: string;
  certPem: string;
  fingerprintSha256: string;
  hosts: string[];
}

function derLen(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  if (n < 65536) return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
  if (n < 16777216) return Buffer.from([0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  throw new Error("der too long");
}

function tlv(tag: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}

function seq(...parts: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(parts));
}

function oid(id: string): Buffer {
  const parts = id.split(".").map((x) => Number(x));
  const bytes: number[] = [40 * parts[0]! + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    const tmp: number[] = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      tmp.push((v & 0x7f) | 0x80);
      v >>= 7;
    }
    for (let j = tmp.length - 1; j >= 0; j--) bytes.push(tmp[j]!);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function intFromBuf(buf: Buffer): Buffer {
  let b = buf;
  while (b.length > 1 && b[0] === 0 && (b[1]! & 0x80) === 0) b = b.subarray(1);
  if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

function bitString(buf: Buffer): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
}

function utf8(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, "utf8"));
}

function utcTime(d: Date): Buffer {
  const yy = String(d.getUTCFullYear() % 100).padStart(2, "0");
  const mo = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  return tlv(0x17, Buffer.from(`${yy}${mo}${dd}${hh}${mm}${ss}Z`, "ascii"));
}

function bool(v: boolean): Buffer {
  return tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
}

function nameCn(cn: string): Buffer {
  return seq(tlv(0x31, seq(oid("2.5.4.3"), utf8(cn))));
}

function algSha256Rsa(): Buffer {
  return seq(oid("1.2.840.113549.1.1.11"), tlv(0x05, Buffer.alloc(0)));
}

function ext(id: string, value: Buffer, critical = false): Buffer {
  const parts = [oid(id)];
  if (critical) parts.push(bool(true));
  parts.push(tlv(0x04, value));
  return seq(...parts);
}

function parseHost(host: string): { dns?: string; ip?: Buffer } {
  const t = host.trim().toLowerCase();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (m) {
    const octets = m.slice(1).map(Number);
    if (octets.every((n) => n <= 255)) return { ip: Buffer.from(octets) };
  }
  return { dns: t };
}

export function fingerprintSha256Pem(certPem: string): string {
  const x = new X509Certificate(certPem);
  return createHash("sha256").update(x.raw).digest("hex");
}

export function generateNmzpCert(hosts: string[] = ["127.0.0.1", "localhost"]): TlsMaterial {
  const unique = [...new Set(["127.0.0.1", "localhost", ...hosts.map((h) => h.trim()).filter(Boolean)])];
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const serial = intFromBuf(Buffer.from(createHash("sha256").update(String(Date.now())).digest().subarray(0, 8)));
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + 5 * 365 * 24 * 60 * 60 * 1000);
  const subject = nameCn("nmzp-ct");
  const sanParts: Buffer[] = [];
  for (const h of unique) {
    const p = parseHost(h);
    if (p.ip) sanParts.push(tlv(0x87, p.ip));
    else if (p.dns) sanParts.push(tlv(0x82, Buffer.from(p.dns, "ascii")));
  }
  const san = ext("2.5.29.17", seq(...sanParts));
  const bc = ext("2.5.29.19", seq(bool(false)), true);
  const ku = ext("2.5.29.15", tlv(0x03, Buffer.from([0x05, 0xa0])), true);
  const extensions = tlv(0xa3, seq(bc, ku, san));
  const tbs = seq(
    tlv(0xa0, intFromBuf(Buffer.from([2]))),
    serial,
    algSha256Rsa(),
    subject,
    seq(utcTime(notBefore), utcTime(notAfter)),
    subject,
    spki,
    extensions,
  );
  const signer = createSign("SHA256");
  signer.update(tbs);
  signer.end();
  const sig = signer.sign(privateKey);
  const der = seq(tbs, algSha256Rsa(), bitString(sig));
  const certPem = pem("CERTIFICATE", der);
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  return {
    keyPem,
    certPem,
    fingerprintSha256: fingerprintSha256Pem(certPem),
    hosts: unique,
  };
}

function pem(type: string, der: Buffer): string {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----\n`;
}

export async function loadOrCreateTls(dataDir: string, hosts: string[]): Promise<TlsMaterial> {
  const dir = join(dataDir, "tls");
  const keyPath = join(dir, "server.key");
  const certPath = join(dir, "server.crt");
  const pinPath = join(dir, "pin.json");
  const haveKey = existsSync(keyPath);
  const haveCert = existsSync(certPath);
  const havePin = existsSync(pinPath);
  const any = haveKey || haveCert || havePin;
  const all = haveKey && haveCert && havePin;
  if (!any) {
    const material = generateNmzpCert(hosts);
    await mkdir(dir, { recursive: true });
    await writeFile(keyPath, material.keyPem, { mode: 0o600 });
    await writeFile(certPath, material.certPem, { mode: 0o600 });
    await writeFile(
      pinPath,
      JSON.stringify({ fingerprintSha256: material.fingerprintSha256, hosts: material.hosts }, null, 2),
      { mode: 0o600 },
    );
    return material;
  }
  if (!all) throw new Error("tls files incomplete");
  const [keyPem, certPem, pinRaw] = await Promise.all([
    readFile(keyPath, "utf8"),
    readFile(certPath, "utf8"),
    readFile(pinPath, "utf8"),
  ]);
  let pin: { fingerprintSha256?: string; hosts?: string[] };
  try {
    pin = JSON.parse(pinRaw) as { fingerprintSha256?: string; hosts?: string[] };
  } catch {
    throw new Error("tls pin corrupt");
  }
  const fp = fingerprintSha256Pem(certPem);
  if (!pin.fingerprintSha256 || pin.fingerprintSha256 !== fp) throw new Error("tls pin mismatch");
  if (!keyPem.includes("BEGIN") || !certPem.includes("BEGIN CERTIFICATE")) throw new Error("tls files corrupt");
  return { keyPem, certPem, fingerprintSha256: fp, hosts: pin.hosts ?? hosts };
}

/** Verify a peer cert fingerprint. Used by the device client. */
export function assertFingerprint(certPemOrDer: string | Buffer, expectedHex: string): void {
  const fp =
    typeof certPemOrDer === "string"
      ? fingerprintSha256Pem(certPemOrDer)
      : createHash("sha256").update(certPemOrDer).digest("hex");
  if (fp !== expectedHex.toLowerCase()) throw new Error("tls fingerprint mismatch");
}
