import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { X509Certificate } from "node:crypto";
import { generateNmzpCert, loadOrCreateTls, fingerprintSha256Pem } from "./tls.ts";

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
});
