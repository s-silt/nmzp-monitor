import assert from "node:assert/strict";
import { test } from "node:test";
import { Worker } from "node:worker_threads";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { gzipSync } from "node:zlib";
import { encodeJson } from "./json-codec.ts";
import { AuditRuntime } from "./runtime.ts";

const codecUrl = new URL("./json-codec.ts", import.meta.url).href;
const script = `
const { parentPort, workerData } = require("node:worker_threads");
const zlib = require("node:zlib");
const { syncBuiltinESMExports } = require("node:module");
const actualAsync = zlib.gzip, actualSync = zlib.gzipSync;
let calls = [], failCompression = false;
zlib.gzip = (data, options, callback) => {
  calls.push(["async", data.length, options.level]);
  if (failCompression) return queueMicrotask(() => callback(new Error("synthetic private compression detail")));
  return actualAsync(data, options, callback);
};
zlib.gzipSync = (data, options) => {
  calls.push(["sync", data.length, options.level]);
  if (failCompression) throw new Error("synthetic private compression detail");
  return actualSync(data, options);
};
syncBuiltinESMExports();
(async () => {
  const { encodeJson } = await import(workerData.codecUrl);
  const results = [];
  for (const item of workerData.items) {
    const pair = [];
    let value = item.value;
    if (item.cyclic) { value = {}; value.self = value; }
    for (const enabled of workerData.hints) {
      calls = [];
      failCompression = item.failCompression === true;
      const options = { ...item.options, ...(enabled === undefined ? {} : { smallRecordSyncGzip: enabled }) };
      try {
        const r = await encodeJson(value, options);
        pair.push({ codec: r.codec, version: r.version, rawBytes: r.rawBytes, dataHex: r.data.toString("hex"), calls });
      } catch (error) {
        pair.push({ error: error.code, name: error.name, message: error.message, calls });
      }
    }
    results.push(pair);
  }
  parentPort.postMessage(results);
})().catch(error => { throw error; });
`;
async function inWorker(items, hints = [false, true]) {
  const worker = new Worker(script, {
    eval: true,
    workerData: { codecUrl, items, hints },
    execArgv: ["--experimental-strip-types"],
  });
  try {
    return await new Promise((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
      worker.once("exit", code => reject(new Error(`worker exited before result: ${code}`)));
    });
  } finally { await worker.terminate(); }
}
function noise(length) { let state = 0x13579bdf; return Array.from({ length }, () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return String.fromCharCode(33 + ((state >>> 0) % 90)); }).join(""); }

test("dedicated-worker small gzip is byte-identical to async codec at every scheduling/format boundary", async () => {
  const items = [1023,1024,1392,2385,16383,16384,16385,65536].flatMap(bytes => [
    { value: "x".repeat(bytes - 2) }, { value: noise(bytes - 2) },
  ]);
  items.push({ value: { unicode: "你好😀\u0000".repeat(1000), nested: [true, null, -0, 1e10] } }, { value: "x".repeat(2000), options: { minSavingsBytes: 100000 } },
    { value: true, options: { compressAtBytes: 0, minSavingsBytes: 0 } }, { value: "x".repeat(1200), options: { maxRawBytes: 1000 } },
    { value: "x".repeat(1200), options: { maxStoredBytes: 1 } }, { value: undefined }, { value: 1n });
  const results = await inWorker(items);
  for (const [index, [legacy, optimized]] of results.entries()) {
    const { calls: first, ...a } = legacy, { calls: second, ...b } = optimized;
    assert.deepEqual(b, a, `encoded bytes/options ${index}`);
    if (first.length) {
      assert.equal(first[0][0], "async"); assert.equal(second[0][1], first[0][1]);
      assert.equal(second[0][0], first[0][1] <= 16 * 1024 ? "sync" : "async");
      assert.equal(first[0][2], 6); assert.equal(second[0][2], 6);
    } else assert.deepEqual(second, []);
  }
});

test("worker sync gzip requires an explicit boolean opt-in; defaults remain async", async () => {
  const [results] = await inWorker([{ value: "x".repeat(2000) }], [undefined, false, true, 1, "true"]);
  const { calls: _calls, ...expected } = results[0];
  for (const [index, { calls, ...encoded }] of results.entries()) {
    assert.deepEqual(encoded, expected);
    assert.deepEqual(calls, [[index === 2 ? "sync" : "async", 2002, 6]]);
  }
});

test("worker scheduling uses exact serialized UTF-8 bytes at 1024 and 16384 boundaries", async () => {
  const sizes = [1023, 1024, 16383, 16384, 16385];
  const items = sizes.map(bytes => {
    const contentBytes = bytes - 2;
    const value = "汉".repeat(Math.floor(contentBytes / 3)) + "x".repeat(contentBytes % 3);
    assert.equal(Buffer.byteLength(JSON.stringify(value), "utf8"), bytes);
    return { value };
  });
  const results = await inWorker(items);
  for (const [index, [legacy, optimized]] of results.entries()) {
    const bytes = sizes[index];
    const { calls: asyncCalls, ...first } = legacy, { calls: optimizedCalls, ...second } = optimized;
    assert.deepEqual(second, first);
    assert.equal(second.rawBytes, bytes);
    assert.deepEqual(asyncCalls, bytes < 1024 ? [] : [["async", bytes, 6]]);
    assert.deepEqual(optimizedCalls, bytes < 1024 ? [] : [[bytes <= 16384 ? "sync" : "async", bytes, 6]]);
  }
});

test("worker gzip preserves the default 64-byte minimum saving exactly", async () => {
  const fixtures = new Map();
  for (let length = 64; length < 128; length++) {
    const value = "x".repeat(length), raw = Buffer.from(JSON.stringify(value));
    const compressed = gzipSync(raw, { level: 6 });
    const savings = raw.length - compressed.length;
    if (savings === 63 || savings === 64) fixtures.set(savings, { value, raw, compressed });
  }
  assert.equal(fixtures.size, 2, "both exact savings boundaries must be exercised");
  for (const [savings, { value, raw, compressed }] of fixtures) {
    const [[legacy, optimized]] = await inWorker([{ value, options: { compressAtBytes: 0 } }]);
    const { calls: asyncCalls, ...first } = legacy, { calls: syncCalls, ...second } = optimized;
    assert.deepEqual(second, first);
    assert.equal(second.codec, savings === 64 ? "gzip" : "json");
    assert.equal(second.dataHex, (savings === 64 ? compressed : raw).toString("hex"));
    assert.deepEqual(asyncCalls, [["async", raw.length, 6]]);
    assert.deepEqual(syncCalls, [["sync", raw.length, 6]]);
  }
});

test("worker options, size, serialization and compression errors preserve their safe codes", async () => {
  const value = "x".repeat(2000);
  const items = [
    ...[0, -1, NaN, Infinity, 0.5, 0x80000000].map(maxRawBytes => ({ value, options: { maxRawBytes }, expected: "invalid_options" })),
    { value, options: { maxStoredBytes: 0 }, expected: "invalid_options" },
    { value, options: { compressAtBytes: -1 }, expected: "invalid_options" },
    { value, options: { minSavingsBytes: -1 }, expected: "invalid_options" },
    { value, options: { maxRawBytes: 2001 }, expected: "payload_too_large" },
    { value, options: { maxStoredBytes: 1 }, expected: "payload_too_large" },
    { value, options: { minSavingsBytes: 100000, maxStoredBytes: 2001 }, expected: "payload_too_large" },
    { value: undefined, expected: "invalid_json" },
    { value: 1n, expected: "invalid_json" },
    { cyclic: true, expected: "invalid_json" },
    { value, failCompression: true, expected: "compression_failed" },
    { value: "x".repeat(16383), failCompression: true, expected: "compression_failed" },
  ];
  const results = await inWorker(items);
  for (const [index, pair] of results.entries()) {
    for (const { calls: _calls, ...error } of pair) {
      assert.deepEqual(error, { error: items[index].expected, name: "JsonCodecError", message: items[index].expected });
    }
  }
  assert.deepEqual(results.at(-2).map(result => result.calls), [[["async", 2002, 6]], [["sync", 2002, 6]]]);
  assert.deepEqual(results.at(-1).map(result => result.calls), [[["async", 16385, 6]], [["async", 16385, 6]]]);
});

test("main-thread codec remains asynchronous even when the dedicated-worker hint is provided", async () => {
  let settled = false;
  const pending = encodeJson("x".repeat(2000), { smallRecordSyncGzip: true }).then(r => { settled = true; return r; });
  await Promise.resolve();
  assert.equal(settled, false);
  assert.deepEqual(await pending, await encodeJson("x".repeat(2000)));
});

test("small-record worker scheduling keeps FIFO reads/receipts, compression and restart bytes", async t => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-small-gzip-")), path = join(dir, "nmzp.db");
  let runtime;
  t.after(async () => {
    await runtime?.close();
    await rm(dir, { recursive: true, force: true });
  });
  runtime = await AuditRuntime.open(path, { create: true, retention: { minFreeBytes: 0 } });
  const event = id => ({ id, ts: 1, machineId: "fixture", agent: "grok", layer: "app_pre", tool: "Read", nativeTool: "Read", input: "", redacted: "synthetic".repeat(Number(id.slice(1)) % 2 ? 3000 : 230), risk: "info", decision: "allow", category: "other", workdirScope: "project", policyVersion: 1, evaluation: "allow", enforcement: "pending_verify" });
  const jobs = [], observations = [];
  for (let i = 0; i < 8; i++) {
    jobs.push(runtime.append(event(`e${i}`)).then(r => { assert.equal(r.inserted, true); }));
    jobs.push(runtime.status().then(r => { observations.push(r.retained); }));
    jobs.push(runtime.get("fixture", `e${i}`).then(r => { assert.deepEqual(r, event(`e${i}`)); }));
  }
  await Promise.all(jobs); assert.deepEqual(observations, [1,2,3,4,5,6,7,8]);
  assert.equal((await runtime.updateReceipt("fixture", "e0", "delivered")).enforcement, "delivered");
  await runtime.close();
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const rows = db.prepare("SELECT id,codec,raw_bytes,body FROM audit_events ORDER BY id").all();
    for (const row of rows) {
      // Receipts update a separate column; immutable encoded event retains the initial value.
      const encoded = await encodeJson(event(row.id)); assert.equal(row.codec, "gzip"); assert.equal(row.raw_bytes, encoded.rawBytes); assert.deepEqual(Buffer.from(row.body), encoded.data);
    }
  } finally { db.close(); }
  runtime = await AuditRuntime.open(path, { retention: { minFreeBytes: 0 } });
  assert.equal((await runtime.status()).retained, 8); assert.equal((await runtime.get("fixture", "e0")).enforcement, "delivered");
});
