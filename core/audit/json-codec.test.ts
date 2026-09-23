import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { decodeJson, encodeJson, JsonCodecError, type EncodedJson } from "./json-codec.ts";

const errorCode = (code: string) => (error: unknown) => error instanceof JsonCodecError && error.code === code;
const raw = (text: string): EncodedJson => ({ version: 1, codec: "json", rawBytes: Buffer.byteLength(text), data: Buffer.from(text) });

describe("audit JSON codec", () => {
  it("preserves small JSON and Unicode without modifying event fields", async () => {
    const value = { id: "event-1", machineId: "电脑甲", redacted: "路径：项目/实验🧪", decision: "log", missing: null };
    const packed = await encodeJson(value);
    assert.equal(packed.codec, "json");
    assert.equal(packed.rawBytes, Buffer.byteLength(JSON.stringify(value)));
    assert.deepEqual(await decodeJson(packed), value);
    assert.equal(value.decision, "log");
  });

  it("compresses a large repetitive synthetic event losslessly", async () => {
    const value = { id: "synthetic-1", redacted: "synthetic audit event, no real data. ".repeat(3000) };
    const packed = await encodeJson(value);
    assert.equal(packed.codec, "gzip");
    assert.ok(packed.data.length < packed.rawBytes);
    assert.deepEqual(await decodeJson(packed), value);
  });

  it("retains plain JSON when compression does not meet savings threshold", async () => {
    const value = { noise: randomBytes(4096).toString("base64") };
    const packed = await encodeJson(value, { compressAtBytes: 0, minSavingsBytes: 100000 });
    assert.equal(packed.codec, "json");
    assert.deepEqual(await decodeJson(packed), value);
    assert.equal((await encodeJson(1, { compressAtBytes: 0, minSavingsBytes: 0 })).codec, "json");
  });

  it("handles JSON scalars and arrays using standard JSON serialization", async () => {
    for (const value of [null, true, false, 0, "", [1, "二", null]]) {
      assert.deepEqual(await decodeJson(await encodeJson(value)), value);
    }
    assert.deepEqual(await decodeJson(await encodeJson({ omitted: undefined, present: 1 })), { present: 1 });
  });

  it("rejects non-serializable top-level values and cycles", async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    for (const value of [undefined, 1n, () => 1, Symbol("test"), cyclic]) {
      await assert.rejects(encodeJson(value), errorCode("invalid_json"));
    }
  });

  it("uses UTF-8 bytes rather than JavaScript character counts for limits", async () => {
    await assert.rejects(encodeJson("汉字", { maxRawBytes: 7 }), errorCode("payload_too_large"));
    const packed = await encodeJson("汉字", { maxRawBytes: 8 });
    assert.equal(packed.rawBytes, 8);
    assert.equal(await decodeJson(packed, { maxRawBytes: 8 }), "汉字");
  });

  it("checks stored size and output size independently", async () => {
    await assert.rejects(encodeJson({ a: 1 }, { maxStoredBytes: 2 }), errorCode("payload_too_large"));
    const packed = await encodeJson("x".repeat(10000), { maxStoredBytes: 256 });
    assert.equal(packed.codec, "gzip");
    await assert.rejects(decodeJson(packed, { maxRawBytes: 100 }), errorCode("payload_too_large"));
    await assert.rejects(decodeJson(packed, { maxStoredBytes: 8 }), errorCode("payload_too_large"));
  });

  it("validates codec and metadata before interpreting stored data", async () => {
    const good = raw('{"ok":true}');
    await assert.rejects(decodeJson({ ...good, version: 2 } as unknown as EncodedJson), errorCode("invalid_payload"));
    await assert.rejects(decodeJson({ ...good, codec: "zstd" } as unknown as EncodedJson), errorCode("unsupported_codec"));
    await assert.rejects(decodeJson({ ...good, rawBytes: 0 }), errorCode("invalid_payload"));
    await assert.rejects(decodeJson({ ...good, rawBytes: NaN }), errorCode("invalid_payload"));
    await assert.rejects(decodeJson({ ...good, rawBytes: good.rawBytes + 1 }), errorCode("invalid_payload"));
    await assert.rejects(decodeJson({ ...good, data: "not bytes" } as unknown as EncodedJson), errorCode("invalid_payload"));
  });

  it("bounds actual decompression even if the declared size is dishonest", async () => {
    const data = gzipSync(JSON.stringify("x".repeat(100000)));
    await assert.rejects(
      decodeJson({ version: 1, codec: "gzip", rawBytes: 16, data }, { maxRawBytes: 1024 }),
      errorCode("payload_too_large"),
    );
  });

  it("rejects truncated and corrupt gzip data", async () => {
    const value = { redacted: "synthetic ".repeat(1000) };
    const packed = await encodeJson(value);
    assert.equal(packed.codec, "gzip");
    await assert.rejects(decodeJson({ ...packed, data: packed.data.subarray(0, packed.data.length - 4) }), errorCode("invalid_payload"));
    const corrupt = Buffer.from(packed.data);
    corrupt[corrupt.length - 8] ^= 0xff;
    await assert.rejects(decodeJson({ ...packed, data: corrupt }), errorCode("invalid_payload"));
  });

  it("rejects invalid JSON and invalid UTF-8 instead of replacement decoding", async () => {
    await assert.rejects(decodeJson(raw("{broken")), errorCode("invalid_json"));
    await assert.rejects(decodeJson({ version: 1, codec: "json", rawBytes: 3, data: Buffer.from([0x22, 0xff, 0x22]) }), errorCode("invalid_json"));
    await assert.rejects(decodeJson(raw('\ufeff{"a":1}')), errorCode("invalid_json"));
  });

  it("rejects invalid configuration without leaking payload content", async () => {
    for (const limit of [0, -1, Infinity, NaN, 0.5]) {
      await assert.rejects(encodeJson({ secret: "fixture" }, { maxRawBytes: limit }), errorCode("invalid_options"));
      await assert.rejects(decodeJson(raw("null"), { maxRawBytes: limit }), errorCode("invalid_options"));
    }
    await assert.rejects(encodeJson({}, { compressAtBytes: -1 }), errorCode("invalid_options"));
    await assert.rejects(encodeJson({}, { minSavingsBytes: -1 }), errorCode("invalid_options"));
  });
});
