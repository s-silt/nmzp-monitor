import { Buffer } from "node:buffer";
import { TextDecoder } from "node:util";
import { gzip, gunzip } from "node:zlib";

export type JsonCodec = "json" | "gzip";

/** Internal storage envelope. Never return this in place of public API JSON. */
export interface EncodedJson {
  readonly version: 1;
  readonly codec: JsonCodec;
  readonly rawBytes: number;
  readonly data: Buffer;
}

export interface JsonCodecLimits {
  /** Maximum serialized/decompressed bytes, not JavaScript string length. */
  readonly maxRawBytes?: number;
  /** Maximum accepted stored bytes, checked before decompression. */
  readonly maxStoredBytes?: number;
}

export interface JsonEncodeOptions extends JsonCodecLimits {
  readonly compressAtBytes?: number;
  readonly minSavingsBytes?: number;
}

export type JsonCodecErrorCode =
  | "invalid_options"
  | "invalid_json"
  | "invalid_payload"
  | "unsupported_codec"
  | "payload_too_large"
  | "compression_failed";

export class JsonCodecError extends Error {
  readonly code: JsonCodecErrorCode;

  constructor(code: JsonCodecErrorCode) {
    super(code);
    this.name = "JsonCodecError";
    this.code = code;
  }
}

const DEFAULT_MAX_BYTES = 1024 * 1024;
const MAX_BUFFER_BYTES = 0x7fff_ffff;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function byteLimit(value: number | undefined, fallback: number, allowZero = false): number {
  const n = value ?? fallback;
  if (!Number.isSafeInteger(n) || n < (allowZero ? 0 : 1) || n > MAX_BUFFER_BYTES) {
    throw new JsonCodecError("invalid_options");
  }
  return n;
}

/**
 * Encode using ordinary JSON.stringify semantics; undefined top-level values,
 * cycles, and BigInt are rejected. Callers validate their own event schema.
 * Only use this on bounded, already-normalized event objects, not whole exports.
 * Small or poorly compressible records remain plain UTF-8 JSON.
 * Callers must bound the number of concurrent compression jobs.
 */
export async function encodeJson(value: unknown, options: JsonEncodeOptions = {}): Promise<EncodedJson> {
  const maxRaw = byteLimit(options.maxRawBytes, DEFAULT_MAX_BYTES);
  const maxStored = byteLimit(options.maxStoredBytes, maxRaw);
  const threshold = byteLimit(options.compressAtBytes, 1024, true);
  const minSavings = byteLimit(options.minSavingsBytes, 64, true);

  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch {
    throw new JsonCodecError("invalid_json");
  }
  if (text === undefined) throw new JsonCodecError("invalid_json");
  const rawBytes = Buffer.byteLength(text, "utf8");
  if (rawBytes > maxRaw) throw new JsonCodecError("payload_too_large");
  const raw = Buffer.from(text, "utf8");

  if (rawBytes >= threshold) {
    const compressed = await new Promise<Buffer>((resolve, reject) => {
      gzip(raw, { level: 6 }, (error, data) => {
        if (error) reject(new JsonCodecError("compression_failed"));
        else resolve(data);
      });
    });
    if (compressed.length < rawBytes && rawBytes - compressed.length >= minSavings) {
      if (compressed.length > maxStored) throw new JsonCodecError("payload_too_large");
      return { version: 1, codec: "gzip", rawBytes, data: compressed };
    }
  }

  if (rawBytes > maxStored) throw new JsonCodecError("payload_too_large");
  return { version: 1, codec: "json", rawBytes, data: raw };
}

/**
 * Verify stored metadata, cap decompression output, check UTF-8, then parse.
 * Returns unknown deliberately: the event schema is a separate trust boundary.
 * Compression does not provide encryption, anonymity, or authenticity.
 */
export async function decodeJson(payload: EncodedJson, limits: JsonCodecLimits = {}): Promise<unknown> {
  const maxRaw = byteLimit(limits.maxRawBytes, DEFAULT_MAX_BYTES);
  const maxStored = byteLimit(limits.maxStoredBytes, maxRaw);
  if (
    !payload ||
    payload.version !== 1 ||
    !Buffer.isBuffer(payload.data) ||
    !Number.isSafeInteger(payload.rawBytes) ||
    payload.rawBytes < 1
  ) {
    throw new JsonCodecError("invalid_payload");
  }
  if (payload.codec !== "json" && payload.codec !== "gzip") {
    throw new JsonCodecError("unsupported_codec");
  }
  if (payload.rawBytes > maxRaw || payload.data.length > maxStored) {
    throw new JsonCodecError("payload_too_large");
  }

  const raw = payload.codec === "json"
    ? payload.data
    : await new Promise<Buffer>((resolve, reject) => {
        gunzip(payload.data, { maxOutputLength: Math.min(maxRaw, payload.rawBytes) }, (error, data) => {
          if (error) {
            const code = (error as NodeJS.ErrnoException).code;
            reject(new JsonCodecError(code === "ERR_BUFFER_TOO_LARGE" ? "payload_too_large" : "invalid_payload"));
          } else resolve(data);
        });
      });
  if (raw.length > maxRaw) throw new JsonCodecError("payload_too_large");
  if (raw.length !== payload.rawBytes) throw new JsonCodecError("invalid_payload");

  try {
    return JSON.parse(decoder.decode(raw)) as unknown;
  } catch {
    throw new JsonCodecError("invalid_json");
  }
}
