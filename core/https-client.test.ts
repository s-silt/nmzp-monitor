import assert from "node:assert/strict";
import { createServer as createNetServer } from "node:net";
import { createServer } from "node:https";
import { describe, it } from "node:test";
import { phaseForTransportError, pinnedHttps, type PinnedHttpsPhase } from "./https-client.ts";
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
      assert.throws(() => {
        void pinnedHttps({ url, caPem: tls.certPem, fingerprintSha256: "", timeoutMs: 500 });
      }, /tls pin required/);
      const a = await pinnedHttps({ url, ...pin });
      const b = await pinnedHttps({ url, ...pin });
      assert.equal(a.status, 200);
      assert.equal(b.status, 200);
      const [c, d] = await Promise.all([
        pinnedHttps({ url, ...pin }),
        pinnedHttps({ url, ...pin }),
      ]);
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

function listen(
  server: ReturnType<typeof createNetServer> | ReturnType<typeof createServer>,
): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") reject(new Error("listen failed"));
      else resolve(addr.port);
    });
  });
}

describe("connect phase", () => {
  it("classifies dns, refusal, tls, and a finished handshake", () => {
    assert.equal(
      phaseForTransportError({
        code: "ENOTFOUND",
        message: "getaddrinfo ENOTFOUND",
        tcpUp: false,
        handshakeDone: false,
      }),
      "connect",
    );
    assert.equal(
      phaseForTransportError({
        code: "ECONNREFUSED",
        message: "connect ECONNREFUSED",
        tcpUp: false,
        handshakeDone: false,
      }),
      "connect",
    );
    assert.equal(
      phaseForTransportError({
        code: "ECONNRESET",
        message: "read ECONNRESET",
        tcpUp: true,
        handshakeDone: false,
      }),
      "tls",
    );
    assert.equal(
      phaseForTransportError({
        code: "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE",
        message: "ssl handshake",
        tcpUp: true,
        handshakeDone: false,
      }),
      "tls",
    );
    assert.equal(
      phaseForTransportError({
        code: "ECONNRESET",
        message: "socket hang up",
        tcpUp: true,
        handshakeDone: true,
      }),
      "response",
    );
  });

  it("without connectTimeoutMs a blackhole waits for the single deadline and has no phase", async () => {
    const sockets: import("node:net").Socket[] = [];
    const server = createNetServer((socket) => {
      sockets.push(socket);
      socket.on("error", () => {});
    });
    const port = await listen(server);
    const tls = generateNmzpCert(["127.0.0.1"]);
    const started = Date.now();
    try {
      await assert.rejects(
        () =>
          pinnedHttps({
            url: `https://127.0.0.1:${port}/x`,
            caPem: tls.certPem,
            fingerprintSha256: tls.fingerprintSha256,
            timeoutMs: 350,
          }),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /timeout/);
          assert.equal((error as { phase?: PinnedHttpsPhase }).phase, undefined);
          return true;
        },
      );
      const elapsed = Date.now() - started;
      assert.ok(elapsed >= 300, `default deadline returned early: ${elapsed}`);
      assert.ok(elapsed < 900, `default deadline overran: ${elapsed}`);
    } finally {
      for (const socket of sockets) socket.destroy();
      server.close();
    }
  });

  it("connectTimeoutMs fails a blackhole during the handshake and a hung body on the total deadline", async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    const sockets: import("node:net").Socket[] = [];
    const blackhole = createNetServer((socket) => {
      sockets.push(socket);
      socket.on("error", () => {});
    });
    const blackPort = await listen(blackhole);
    const hungSockets: { destroy(): void }[] = [];
    const hung = createServer({ key: tls.keyPem, cert: tls.certPem }, () => {});
    hung.on("connection", (socket) => {
      hungSockets.push(socket);
      socket.on("error", () => {});
    });
    const hungPort = await listen(hung);
    try {
      const started = Date.now();
      await assert.rejects(
        () =>
          pinnedHttps({
            url: `https://127.0.0.1:${blackPort}/x`,
            caPem: tls.certPem,
            fingerprintSha256: tls.fingerprintSha256,
            timeoutMs: 2000,
            connectTimeoutMs: 500,
          }),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /timeout/);
          const phase = (error as { phase?: PinnedHttpsPhase }).phase;
          assert.ok(phase === "tls" || phase === "connect", `phase ${phase}`);
          return true;
        },
      );
      const blackMs = Date.now() - started;
      assert.ok(blackMs >= 400 && blackMs < 900, `connect budget ${blackMs}`);

      const pinStarted = Date.now();
      await assert.rejects(
        () =>
          pinnedHttps({
            url: `https://127.0.0.1:${hungPort}/x`,
            method: "POST",
            body: "secret",
            caPem: tls.certPem,
            fingerprintSha256: "0".repeat(64),
            timeoutMs: 2000,
            connectTimeoutMs: 500,
          }),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /tls fingerprint mismatch/);
          assert.equal((error as { phase?: PinnedHttpsPhase }).phase, "pin");
          return true;
        },
      );
      assert.ok(Date.now() - pinStarted < 500);

      const bodyStarted = Date.now();
      await assert.rejects(
        () =>
          pinnedHttps({
            url: `https://127.0.0.1:${hungPort}/x`,
            caPem: tls.certPem,
            fingerprintSha256: tls.fingerprintSha256,
            timeoutMs: 800,
            connectTimeoutMs: 200,
          }),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /timeout/);
          assert.equal((error as { phase?: PinnedHttpsPhase }).phase, "response");
          assert.equal((error as { httpReceived?: boolean }).httpReceived, undefined);
          return true;
        },
      );
      const bodyMs = Date.now() - bodyStarted;
      assert.ok(bodyMs >= 600 && bodyMs < 1400, `response budget ${bodyMs}`);
    } finally {
      for (const socket of sockets) socket.destroy();
      for (const socket of hungSockets) socket.destroy();
      blackhole.close();
      hung.close();
    }
  });

  it("connection refused is a connect-phase error", async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    await assert.rejects(
      () =>
        pinnedHttps({
          url: "https://127.0.0.1:1/x",
          caPem: tls.certPem,
          fingerprintSha256: tls.fingerprintSha256,
          timeoutMs: 1000,
          connectTimeoutMs: 500,
        }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal((error as { code?: string }).code, "ECONNREFUSED");
        assert.equal((error as { phase?: PinnedHttpsPhase }).phase, "connect");
        return true;
      },
    );
  });
});
