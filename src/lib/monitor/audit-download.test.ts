import assert from "node:assert/strict";
import { it, type TestContext } from "node:test";
import { streamAuditDownload } from "./audit-download.ts";

function responseFrom(body: string): Response {
  const bytes = new TextEncoder().encode(body);
  return new Response(
    new ReadableStream({
      start(controller) {
        for (let offset = 0; offset < bytes.byteLength; offset += 1024) {
          controller.enqueue(bytes.subarray(offset, Math.min(offset + 1024, bytes.byteLength)));
        }
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "application/json; charset=utf-8" } },
  );
}

function memoryDestination(): WritableStream<Uint8Array> {
  const chunks: Uint8Array[] = [];
  return new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk.slice());
    },
  });
}

function installFetch(t: TestContext, body: string) {
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async () => responseFrom(body)) as typeof fetch;
}

it("json trailer with corrupt refs reports corruptCount and incomplete", async (t) => {
  const refs = Array.from({ length: 100 }, (_, index) => ({
    seq: index + 1,
    machineId: "m14-export-machine",
    id: `corrupt-${String(index).padStart(3, "0")}-${"x".repeat(64)}`,
  }));
  const counters = `,"exportedCount":7,"complete":false,"deletionsDuringExport":4,"corruptCount":100}\n`;
  const body = `{"metadata":{"formatVersion":1},"events":[],"corrupt":${JSON.stringify(refs)}${counters}`;
  const corruptAt = body.indexOf(`,"corrupt":`);
  const exportedAt = body.lastIndexOf(`,"exportedCount":`);
  assert.ok(exportedAt - corruptAt > 4096);
  assert.ok(body.length - exportedAt < 4096);
  assert.equal(JSON.parse(body).corrupt.length, 100);
  installFetch(t, body);
  const result = await streamAuditDownload({ format: "json", destination: memoryDestination() }, {});
  assert.equal(result.ok, true, "corrupt trailer must parse");
  assert.equal(result.complete, false);
  assert.equal(result.corruptCount, 100);
  assert.equal(result.exportedCount, 7);
  assert.equal(result.deletionsDuringExport, 4);
  assert.equal(result.totalBytes, new TextEncoder().encode(body).byteLength);
});

it("legacy json trailer without corruption fields still parses", async (t) => {
  const body =
    '{"metadata":{"formatVersion":1},"events":[],"exportedCount":10,"complete":true,"deletionsDuringExport":0}\n';
  installFetch(t, body);
  const result = await streamAuditDownload({ format: "json", destination: memoryDestination() }, {});
  assert.equal(result.ok, true);
  assert.equal(result.complete, true);
  assert.equal(result.exportedCount, 10);
  assert.equal(result.deletionsDuringExport, 0);
  assert.ok(result.corruptCount === 0 || result.corruptCount === undefined);
});

it("trailer claiming complete with corrupt rows is rejected", async (t) => {
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  const bodies = {
    json: '{"metadata":{"formatVersion":1},"events":[],"corrupt":[{"seq":1,"machineId":"m","id":"bad"}],"exportedCount":1,"complete":true,"deletionsDuringExport":0,"corruptCount":1}\n',
    jsonl: `${JSON.stringify({ kind: "metadata", formatVersion: 1 })}\n${JSON.stringify({ kind: "summary", exportedCount: 1, complete: true, deletionsDuringExport: 0, corruptCount: 1, corrupt: [{ seq: 1, machineId: "m", id: "bad" }] })}\n`,
  };
  for (const format of ["json", "jsonl"] as const) {
    globalThis.fetch = (async () => responseFrom(bodies[format])) as typeof fetch;
    const result = await streamAuditDownload({ format, destination: memoryDestination() }, {});
    assert.equal(result.ok, false, "complete with corrupt rows must be rejected");
    assert.equal(result.error, "invalid_export_summary", "complete with corrupt rows must be rejected");
  }
});

it("jsonl summary reports corruptCount", async (t) => {
  const body = [
    JSON.stringify({ kind: "metadata", formatVersion: 1 }),
    JSON.stringify({ kind: "corrupt", seq: 8, machineId: "m", id: "bad" }),
    JSON.stringify({ kind: "corrupt", seq: 9, machineId: "m", id: "bad-2" }),
    JSON.stringify({
      kind: "summary",
      exportedCount: 3,
      complete: false,
      deletionsDuringExport: 0,
      corruptCount: 2,
    }),
    "",
  ].join("\n");
  installFetch(t, body);
  const result = await streamAuditDownload({ format: "jsonl", destination: memoryDestination() }, {});
  assert.equal(result.ok, true);
  assert.equal(result.complete, false);
  assert.equal(result.corruptCount, 2);
  assert.equal(result.exportedCount, 3);
  assert.equal(result.deletionsDuringExport, 0);
});
