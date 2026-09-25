import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage } from "node:http";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { isLoopback, serveStatic } from "./http-util.ts";

const SENTINEL = "NMZP_OUTSIDE_SENTINEL";

function textOf(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: "127.0.0.1", port, path, method: "GET" }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("serveStatic containment", () => {
  it("does not serve files outside the static root via dot-dot traversal", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-static-"));
    const ui = join(root, "ui");
    await mkdir(ui);
    await writeFile(join(ui, "app.js"), "INSIDE_APP");
    await writeFile(join(root, "sentinel-outside.txt"), SENTINEL);
    const server = createServer((req, res) => {
      if (!serveStatic(res, ui, req.url ?? "/")) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("missing");
      }
    });
    await new Promise<void>((resolve, reject) => {
      server.listen(0, "127.0.0.1", () => resolve());
      server.once("error", reject);
    });
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("listen");
    try {
      const inside = await textOf(addr.port, "/app.js");
      assert.equal(inside.status, 200);
      assert.equal(inside.body, "INSIDE_APP");
      for (const path of ["/../sentinel-outside.txt", "/..%2fsentinel-outside.txt", "/..%5csentinel-outside.txt"]) {
        const response = await textOf(addr.port, path);
        assert.equal(response.body.includes(SENTINEL), false, path);
        assert.equal(response.status, 404, path);
      }
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  });
});

function messageWith(remoteAddress: string | undefined): IncomingMessage {
  return { socket: { remoteAddress } } as unknown as IncomingMessage;
}

describe("isLoopback", () => {
  it("accepts 127.0.0.1", () => {
    assert.equal(isLoopback(messageWith("127.0.0.1")), true);
  });

  it("accepts ::1", () => {
    assert.equal(isLoopback(messageWith("::1")), true);
  });

  it("accepts IPv4-mapped loopback ::ffff:127.0.0.1", () => {
    assert.equal(isLoopback(messageWith("::ffff:127.0.0.1")), true);
  });

  it("rejects malformed mapped spelling :ffff:127.0.0.1", () => {
    assert.equal(isLoopback(messageWith(":ffff:127.0.0.1")), false);
  });

  it("rejects 192.0.2.1", () => {
    assert.equal(isLoopback(messageWith("192.0.2.1")), false);
  });

  it("rejects IPv4-mapped non-loopback ::ffff:192.0.2.1", () => {
    assert.equal(isLoopback(messageWith("::ffff:192.0.2.1")), false);
  });

  it("rejects undefined remoteAddress", () => {
    assert.equal(isLoopback(messageWith(undefined)), false);
  });
});
