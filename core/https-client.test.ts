import assert from "node:assert/strict";
import { createServer } from "node:https";
import { describe, it } from "node:test";
import { pinnedHttps } from "./https-client.ts";
import { generateNmzpCert } from "./tls.ts";

describe("https-client pin and body cap", () => {
  it("verifies fingerprint on secureConnect before writing the body and caps the response", async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    let gotBody = false;
    const srv = createServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
      req.on("data", () => {
        gotBody = true;
      });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("x".repeat(80_000));
      });
    });
    await new Promise<void>((resolve, reject) => {
      srv.listen(0, "127.0.0.1", () => resolve());
      srv.on("error", reject);
    });
    const addr = srv.address();
    if (!addr || typeof addr === "string") throw new Error("listen failed");
    const url = `https://127.0.0.1:${addr.port}/x`;
    try {
      await assert.rejects(
        () =>
          pinnedHttps({
            url,
            method: "POST",
            body: "SECRET_SHOULD_NOT_ARRIVE",
            caPem: tls.certPem,
            fingerprintSha256: "0".repeat(64),
            timeoutMs: 2000,
          }),
        /tls fingerprint mismatch/,
      );
      assert.equal(gotBody, false);

      await assert.rejects(
        () =>
          pinnedHttps({
            url,
            method: "POST",
            body: "ok",
            caPem: tls.certPem,
            fingerprintSha256: tls.fingerprintSha256,
            timeoutMs: 2000,
            maxBodyBytes: 1024,
          }),
        /response_too_large/,
      );
    } finally {
      await new Promise<void>((resolve, reject) => srv.close((e) => (e ? reject(e) : resolve())));
    }
  });

  it("two sequential and concurrent requests on the same server succeed; missing pin fails", async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    let n = 0;
    const srv = createServer({ key: tls.keyPem, cert: tls.certPem }, (_req, res) => {
      n += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, n }));
    });
    await new Promise<void>((resolve, reject) => {
      srv.listen(0, "127.0.0.1", () => resolve());
      srv.on("error", reject);
    });
    const addr = srv.address();
    if (!addr || typeof addr === "string") throw new Error("listen failed");
    const url = `https://127.0.0.1:${addr.port}/health`;
    const pin = { caPem: tls.certPem, fingerprintSha256: tls.fingerprintSha256, timeoutMs: 2000 };
    try {
      assert.throws(
        () => {
          void pinnedHttps({ url, caPem: tls.certPem, fingerprintSha256: "", timeoutMs: 500 });
        },
        /tls pin required/,
      );
      const a = await pinnedHttps({ url, ...pin });
      const b = await pinnedHttps({ url, ...pin });
      assert.equal(a.status, 200);
      assert.equal(b.status, 200);
      const [c, d] = await Promise.all([pinnedHttps({ url, ...pin }), pinnedHttps({ url, ...pin })]);
      assert.equal(c.status, 200);
      assert.equal(d.status, 200);
      assert.ok(n >= 4);
    } finally {
      await new Promise<void>((resolve, reject) => srv.close((e) => (e ? reject(e) : resolve())));
    }
  });

  it("wall deadline covers a hung handshake", async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    const srv = createServer({ key: tls.keyPem, cert: tls.certPem }, () => {
      /* never respond */
    });
    await new Promise<void>((resolve, reject) => {
      srv.listen(0, "127.0.0.1", () => resolve());
      srv.on("error", reject);
    });
    const addr = srv.address();
    if (!addr || typeof addr === "string") throw new Error("listen failed");
    const url = `https://127.0.0.1:${addr.port}/x`;
    const t0 = Date.now();
    try {
      await assert.rejects(
        () =>
          pinnedHttps({
            url,
            caPem: tls.certPem,
            fingerprintSha256: tls.fingerprintSha256,
            timeoutMs: 250,
          }),
        /timeout/,
      );
      assert.ok(Date.now() - t0 < 1500);
    } finally {
      srv.close();
    }
  });
});
