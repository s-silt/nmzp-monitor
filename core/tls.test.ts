import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { assertFingerprint, fingerprintSha256Pem, generateNmzpCert, loadOrCreateTls } from "./tls.ts";
import * as tlsApi from "./tls.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "nmzp.mjs");

function spawnCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ stdout, stderr, code: 1 });
    }, 45_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", () => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: 1 });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

function ticketEnv(data: string, publicUrl?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NMZP_DATA: data };
  delete env.NMZP_PUBLIC_URL;
  delete env.NMZP_PORT;
  delete env.NMZP_STORAGE_MODE;
  if (publicUrl !== undefined) env.NMZP_PUBLIC_URL = publicUrl;
  return env;
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function ticketCount(data: string): Promise<number> {
  let raw: string;
  try {
    raw = await readFile(join(data, "meta.json"), "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return 0;
    throw new Error("meta.json unreadable");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("meta.json unreadable");
  }
  if (!parsed || typeof parsed !== "object" || !("tickets" in parsed)) return 0;
  const tickets = (parsed as { tickets?: unknown }).tickets;
  return Array.isArray(tickets) ? tickets.length : 0;
}

function certificateCovers(certPem: string, host: string): boolean {
  assert.equal(typeof tlsApi.certificateCovers, "function", "certificateCovers missing");
  return tlsApi.certificateCovers(certPem, host);
}

describe("tls", () => {
  it("generates a self-signed cert with IP SAN that Node accepts", () => {
    const m = generateNmzpCert(["127.0.0.1", "localhost"]);
    assert.match(m.certPem, /BEGIN CERTIFICATE/);
    assert.match(m.keyPem, /BEGIN PRIVATE KEY/);
    assert.equal(m.fingerprintSha256.length, 64);
    const x = new X509Certificate(m.certPem);
    assert.ok(x.subject.includes("nmzp-ct"));
    assert.equal(fingerprintSha256Pem(m.certPem), m.fingerprintSha256);
  });

  it("persists and reloads the same fingerprint", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-tls-"));
    try {
      const a = await loadOrCreateTls(dir, ["127.0.0.1"]);
      const b = await loadOrCreateTls(dir, ["127.0.0.1"]);
      assert.equal(a.fingerprintSha256, b.fingerprintSha256);
      assert.equal(a.certPem, b.certPem);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it(
    "writes tls key, cert, and pin without group or other permissions",
    { skip: process.platform === "win32" && "Unix mode bits are not applied on Windows" },
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "nmzp-tls-mode-"));
      try {
        await loadOrCreateTls(dir, ["127.0.0.1"]);
        for (const name of ["server.key", "server.crt", "pin.json"]) {
          assert.equal(statSync(join(dir, "tls", name)).mode & 0o077, 0, name);
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  );

  it("certificate covers the loopback names it was created with", () => {
    const loopback = generateNmzpCert(["127.0.0.1", "localhost"]);
    assert.equal(certificateCovers(loopback.certPem, "127.0.0.1"), true);
    assert.equal(certificateCovers(loopback.certPem, "localhost"), true);
    assert.equal(certificateCovers(loopback.certPem, "[127.0.0.1]"), true);
    assert.equal(certificateCovers(loopback.certPem, "::1"), false);
    assert.equal(certificateCovers(loopback.certPem, "[::1]"), false);
    const createdWithV6 = generateNmzpCert(["::1"]);
    const san = new X509Certificate(createdWithV6.certPem).subjectAltName ?? "";
    const v6Included = san.split(", ").includes("IP Address:::1");
    assert.equal(certificateCovers(createdWithV6.certPem, "::1"), v6Included);
    assert.equal(certificateCovers(createdWithV6.certPem, "[::1]"), v6Included);
    assert.equal(certificateCovers(loopback.certPem, "\0"), false);
    assert.equal(certificateCovers("not-a-certificate", "localhost"), false);
  });

  it("certificate does not cover a new public address", () => {
    const material = generateNmzpCert(["127.0.0.1", "localhost"]);
    const certHash = createHash("sha256").update(material.certPem).digest("hex");
    const keyHash = createHash("sha256").update(material.keyPem).digest("hex");
    const fingerprint = material.fingerprintSha256;
    assert.equal(certificateCovers(material.certPem, "192.0.2.123"), false, "192.0.2.123 not covered");
    assert.equal(certificateCovers(material.certPem, "ct.example.test"), false, "ct.example.test not covered");
    assert.equal(createHash("sha256").update(material.certPem).digest("hex") === certHash, true, "cert bytes unchanged");
    assert.equal(createHash("sha256").update(material.keyPem).digest("hex") === keyHash, true, "key bytes unchanged");
    assert.equal(material.fingerprintSha256 === fingerprint, true, "fingerprint unchanged");
    assert.equal(fingerprintSha256Pem(material.certPem) === fingerprint, true, "fingerprint unchanged");
  });

  it("ticket refuses a public URL the certificate does not cover", async () => {
    const data = await mkdtemp(join(tmpdir(), "nmzp-m19-ticket-"));
    const out = join(data, "join-bundle.json");
    try {
      await loadOrCreateTls(data, ["127.0.0.1", "localhost"]);
      const beforeTickets = await ticketCount(data);
      const certBefore = await sha256File(join(data, "tls", "server.crt"));
      const keyBefore = await sha256File(join(data, "tls", "server.key"));
      const pinBefore = await sha256File(join(data, "tls", "pin.json"));
      const result = await spawnCli(["ticket", "--out", out], ticketEnv(data, "https://192.0.2.123:8787"));
      assert.equal(existsSync(out), false, "bundle file absent");
      assert.notEqual(result.code, 0);
      assert.equal(
        result.stderr,
        'certificate_address_mismatch: NMZP_PUBLIC_URL host 192.0.2.123 is not covered by the CT certificate (covers: 127.0.0.1, localhost); see docs/install.md "证书地址不匹配" / docs/install.en.md "Certificate address mismatch"\n',
      );
      assert.equal(result.stdout.length, 0);
      assert.equal(await ticketCount(data), beforeTickets, "ticket count unchanged");
      assert.equal((await sha256File(join(data, "tls", "server.crt"))) === certBefore, true, "cert bytes unchanged");
      assert.equal((await sha256File(join(data, "tls", "server.key"))) === keyBefore, true, "key bytes unchanged");
      assert.equal((await sha256File(join(data, "tls", "pin.json"))) === pinBefore, true, "fingerprint unchanged");
    } finally {
      await rm(data, { recursive: true, force: true });
    }
  });

  it("ticket without a public URL keeps the loopback bundle", async () => {
    const data = await mkdtemp(join(tmpdir(), "nmzp-m19-loop-"));
    const out = join(data, "join-bundle.json");
    try {
      const result = await spawnCli(["ticket", "--out", out], ticketEnv(data));
      assert.equal(result.code, 0);
      assert.equal(result.stdout, "bundle written (ticket not printed)\n");
      assert.equal(existsSync(out), true);
      const raw = await readFile(out, "utf8");
      let url = "";
      let hasTicket = false;
      let hasCert = false;
      let pinLength = 0;
      try {
        const bundle = JSON.parse(raw) as {
          url?: unknown;
          caPem?: unknown;
          fingerprintSha256?: unknown;
          ticket?: unknown;
        };
        url = typeof bundle.url === "string" ? bundle.url : "";
        hasTicket = typeof bundle.ticket === "string" && bundle.ticket.length > 0;
        hasCert = typeof bundle.caPem === "string" && bundle.caPem.includes("BEGIN CERTIFICATE");
        pinLength = typeof bundle.fingerprintSha256 === "string" ? bundle.fingerprintSha256.length : 0;
      } catch {
        assert.fail("bundle json");
      }
      assert.equal(url, "https://127.0.0.1:8787");
      assert.equal(hasTicket, true);
      assert.equal(hasCert, true);
      assert.equal(pinLength, 64);
      assert.equal(await ticketCount(data), 1);
    } finally {
      await rm(data, { recursive: true, force: true });
    }
  });

  it("pinned fingerprint mismatch is still rejected", () => {
    const first = generateNmzpCert(["127.0.0.1", "localhost"]);
    const second = generateNmzpCert(["127.0.0.1", "localhost"]);
    assert.throws(() => assertFingerprint(first.certPem, second.fingerprintSha256), { message: "tls fingerprint mismatch" });
    assert.doesNotThrow(() => assertFingerprint(first.certPem, first.fingerprintSha256));
  });
});
