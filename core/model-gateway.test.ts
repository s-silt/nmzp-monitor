import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import net from "node:net";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import {
  inspectModelPayload,
  looksEncodedPayload,
  REDACT_TAG,
} from "./model-gateway-inspect.ts";
import {
  DEFAULT_TIMEOUT_MS,
  loopbackHttpFactory,
  startModelGateway,
  type ModelGatewayConfig,
  type ModelGatewayEvent,
  type ModelGatewayHandle,
} from "./model-gateway.ts";
import { generateNmzpCert } from "./tls.ts";

const ID = "110101199001011237";
const OPENAI_SK = "sk-abcdefghijklmnopqrstuvwxyz123456";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const BODY_MARK = "UNIQUE_BODY_MARKER_GW_TEST_918273";
const UP_MARK = "syn_up_token_should_never_log_";
const SESS_MARK = "gw_sess_token_should_never_log_";

const TEXT_BODY = {
  model: "synthetic-model",
  messages: [{ role: "user", content: "hello gateway" }],
};

const TOOL_BODY = {
  model: "synthetic-model",
  messages: [
    { role: "user", content: "weather?" },
    {
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: "call_1",
          type: "function",
          function: { name: "get_weather", arguments: '{"city":"Beijing"}' },
        },
      ],
    },
    { role: "tool", tool_call_id: "call_1", content: '{"temp":20}' },
  ],
  tools: [
    {
      type: "function",
      function: {
        name: "get_weather",
        description: "Get weather",
        parameters: {
          type: "object",
          properties: { city: { type: "string" } },
          required: ["city"],
        },
      },
    },
  ],
};

const FILE_SCHEMA_BODY = {
  model: "synthetic-model",
  messages: [{ role: "user", content: "read notes" }],
  tools: [
    {
      type: "function",
      function: {
        name: "read_meta",
        parameters: {
          type: "object",
          properties: {
            file: { type: "string", description: "name only" },
            api_key: { type: "string", description: "provider name field" },
          },
          required: ["file"],
        },
      },
    },
  ],
};

const INNER_FILE_ARGS_BODY = {
  model: "synthetic-model",
  messages: [
    {
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: "call_file",
          type: "function",
          function: { name: "read_meta", arguments: '{"file":"notes.txt"}' },
        },
      ],
    },
  ],
};

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function isConnReset(e: unknown): boolean {
  if (!e || typeof e !== "object") return false;
  const code = "code" in e ? String((e as { code?: string }).code) : "";
  const msg = e instanceof Error ? e.message : String(e);
  return code === "ECONNRESET" || code === "ECONNABORTED" || /socket hang up|ECONNRESET/i.test(msg);
}

async function listen(server: Server, host = "127.0.0.1"): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.listen(0, host, () => resolve());
    server.once("error", reject);
  });
  const a = server.address();
  if (!a || typeof a === "string") throw new Error("listen failed");
  return a.port;
}

async function closeServer(server: Server): Promise<void> {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((e) => (e ? reject(e) : resolve()));
  });
}

type Hit = {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage["headers"];
  body: Buffer;
};

function parseJson(text: string): { error?: string; [k: string]: unknown } {
  try {
    return JSON.parse(text) as { error?: string };
  } catch {
    return {};
  }
}

function call(opts: {
  port: number;
  token?: string | null;
  path?: string;
  method?: string;
  body?: string | Buffer;
  headers?: Record<string, string | undefined>;
  host?: string;
  chunked?: boolean;
  chunkDelayMs?: number;
  abortAfterMs?: number;
}): Promise<{
  status: number;
  text: string;
  json: { error?: string; [k: string]: unknown };
  headers: IncomingMessage["headers"];
  chunks: Buffer[];
}> {
  return new Promise((resolve, reject) => {
    const path = opts.path ?? "/v1/chat/completions";
    const body = opts.body === undefined ? JSON.stringify(TEXT_BODY) : opts.body;
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
    const headers: Record<string, string> = {
      host: opts.host ?? `127.0.0.1:${opts.port}`,
      "content-type": "application/json",
    };
    if (opts.token) headers.authorization = `Bearer ${opts.token}`;
    if (!opts.chunked) headers["content-length"] = String(payload.length);
    for (const [k, v] of Object.entries(opts.headers ?? {})) {
      if (v === undefined) delete headers[k];
      else headers[k] = v;
    }
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: opts.port,
        path,
        method: opts.method ?? "POST",
        headers,
        timeout: 8_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () => {
          const buf = Buffer.concat(chunks);
          const text = buf.toString("utf8");
          resolve({
            status: res.statusCode ?? 0,
            text,
            json: parseJson(text),
            headers: res.headers,
            chunks,
          });
        });
        res.on("error", reject);
      },
    );
    req.on("error", (e) => {
      reject(e);
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("client_timeout"));
    });
    if (opts.abortAfterMs !== undefined) {
      setTimeout(() => req.destroy(), opts.abortAfterMs);
    }
    if (opts.chunked) {
      const mid = Math.max(1, Math.floor(payload.length / 2));
      req.write(payload.subarray(0, mid));
      setTimeout(() => {
        req.write(payload.subarray(mid));
        req.end();
      }, opts.chunkDelayMs ?? 40);
    } else {
      if (payload.length) req.write(payload);
      req.end();
    }
  });
}

type PairCtx = {
  gw: ModelGatewayHandle;
  port: number;
  token: string;
  upToken: string;
  hits: Hit[];
  events: ModelGatewayEvent[];
  logs: string[];
  upstreamPort: number;
  connections: () => number;
};

async function withPair(
  fn: (ctx: PairCtx) => Promise<void>,
  opts?: {
    handle?: (req: IncomingMessage, res: ServerResponse, raw: Buffer, hits: Hit[]) => void;
    extra?: Partial<ModelGatewayConfig>;
  },
): Promise<void> {
  const hits: Hit[] = [];
  const events: ModelGatewayEvent[] = [];
  const logs: string[] = [];
  let connections = 0;
  const upstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      hits.push({ method: req.method, url: req.url, headers: req.headers, body: raw });
      if (opts?.handle) {
        opts.handle(req, res, raw, hits);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "syn", choices: [{ message: { role: "assistant", content: "ok" } }] }));
    });
  });
  upstream.on("connection", () => {
    connections += 1;
  });
  const upstreamPort = await listen(upstream);
  const upToken = `${UP_MARK}${randomBytes(18).toString("hex")}`;
  const token = `${SESS_MARK}${randomBytes(18).toString("hex")}`;
  const gw = await startModelGateway({
    bindHost: "127.0.0.1",
    upstreamOrigin: `http://127.0.0.1:${upstreamPort}`,
    upstreamToken: upToken,
    sessionToken: token,
    createUpstreamRequest: loopbackHttpFactory,
    timeoutMs: opts?.extra?.timeoutMs ?? 4_000,
    onEvent: (e) => events.push(e),
    log: (line) => logs.push(line),
    ...opts?.extra,
  });
  try {
    await fn({
      gw,
      port: gw.port,
      token: gw.sessionToken,
      upToken,
      hits,
      events,
      logs,
      upstreamPort,
      connections: () => connections,
    });
  } finally {
    await gw.close();
    await closeServer(upstream);
  }
}

function assertNoSecretsInTelemetry(logs: string[], events: ModelGatewayEvent[], extra: string[]): void {
  const blob = `${logs.join("\n")}\n${JSON.stringify(events)}`;
  for (const s of extra) {
    assert.equal(blob.includes(s), false, `telemetry leaked ${s.slice(0, 24)}`);
  }
  assert.equal(blob.includes(OPENAI_SK), false);
  assert.equal(blob.includes(AWS_KEY), false);
  assert.equal(blob.includes(ID), false);
  assert.equal(blob.includes(BODY_MARK), false);
}

describe("model-gateway inspect", () => {
  it("accepts plain text and tool messages", () => {
    const a = inspectModelPayload("/v1/chat/completions", JSON.stringify(TEXT_BODY));
    assert.equal(a.ok, true);
    const b = inspectModelPayload("/v1/chat/completions", JSON.stringify(TOOL_BODY));
    assert.equal(b.ok, true);
    if (b.ok) {
      assert.equal(b.stream, false);
      const msgs = b.payload.messages as unknown[];
      assert.equal(msgs.length, 3);
    }
  });

  it("rejects unimplemented routes without pretending compatibility", () => {
    const r = inspectModelPayload("/v1/messages", JSON.stringify(TEXT_BODY));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, "protocol_unsupported");
  });

  it("blocks secrets and redacts PII in place without truncating", () => {
    const secret = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ model: "m", messages: [{ role: "user", content: `leak ${OPENAI_SK}` }] }),
    );
    assert.equal(secret.ok, false);
    if (!secret.ok) assert.equal(secret.code, "secret_blocked");

    const long = `prefix-${"x".repeat(300)}-${ID}-suffix-${"y".repeat(300)}`;
    const pii = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ model: "m", messages: [{ role: "user", content: long }] }),
    );
    assert.equal(pii.ok, true);
    if (pii.ok) {
      assert.equal(pii.redacted, true);
      const content = (pii.payload.messages as Array<{ content: string }>)[0]!.content;
      assert.equal(content.includes(ID), false);
      assert.equal(content.includes(REDACT_TAG), true);
      assert.ok(content.length > 240);
      assert.equal(content.startsWith("prefix-"), true);
      assert.equal(content.endsWith("y".repeat(300)), true);
    }
  });

  it("rejects images, data URIs, unknown parts, and encoded blobs", () => {
    const img = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://x.test/a.png" } }] }],
      }),
    );
    assert.equal(img.ok, false);

    const dataUri = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: `data:image/png;base64,${Buffer.alloc(240, 155).toString("base64")}` }],
      }),
    );
    assert.equal(dataUri.ok, false);

    const placeholder = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: "docs example data:image/png;base64,AAAA" }],
      }),
    );
    assert.equal(placeholder.ok, true);

    const gz = gzipSync(Buffer.alloc(2048, 65)).toString("base64");
    assert.equal(looksEncodedPayload(gz), true);
    const enc = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ model: "m", messages: [{ role: "user", content: gz }] }),
    );
    assert.equal(enc.ok, false);
    if (!enc.ok) assert.equal(enc.code, "encoded_payload");
  });

  it("rejects unknown top-level keys used for URL/credential injection", () => {
    const r = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ ...TEXT_BODY, base_url: "https://evil.test", api_key: "x" }),
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, "protocol_unsupported");
  });

  it("allows tools JSON schema property names like file as text fields", () => {
    const r = inspectModelPayload("/v1/chat/completions", JSON.stringify(FILE_SCHEMA_BODY));
    assert.equal(r.ok, true);
  });

  it("denies PII property keys instead of forwarding them", () => {
    const r = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: "n" }],
        tools: [
          {
            type: "function",
            function: {
              name: "lookup",
              parameters: { type: "object", properties: { [ID]: { type: "string" } } },
            },
          },
        ],
      }),
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, "secret_blocked");
  });

  it("parses inner function.arguments JSON including unicode-escaped secrets", () => {
    const inner = `{"text":"\\u0073${OPENAI_SK.slice(1)}"}`;
    const r = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [
          {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "c1", type: "function", function: { name: "run", arguments: inner } }],
          },
        ],
      }),
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, "secret_blocked");

    const num = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [
          {
            role: "assistant",
            content: null,
            tool_calls: [
              { id: "c1", type: "function", function: { name: "run", arguments: '{"id":6222021234567890}' } },
            ],
          },
        ],
      }),
    );
    assert.equal(num.ok, false);

    const okInner = inspectModelPayload("/v1/chat/completions", JSON.stringify(INNER_FILE_ARGS_BODY));
    assert.equal(okInner.ok, true);
    if (okInner.ok) {
      const args = (okInner.payload.messages as Array<{ tool_calls: Array<{ function: { arguments: string } }> }>)[0]!
        .tool_calls[0]!.function.arguments;
      JSON.parse(args);
      assert.equal(args.includes("notes.txt"), true);
    }
  });

  it("shares walk node budget and redacted flag across siblings and function.arguments", () => {
    const nestedPii = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [
          {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "c1",
                type: "function",
                function: { name: "run", arguments: JSON.stringify({ nested: { value: ID } }) },
              },
            ],
          },
        ],
      }),
    );
    assert.equal(nestedPii.ok, true);
    if (nestedPii.ok) {
      assert.equal(nestedPii.redacted, true);
      const blob = JSON.stringify(nestedPii.payload);
      assert.equal(blob.includes(ID), false);
      const args = (nestedPii.payload.messages as Array<{ tool_calls: Array<{ function: { arguments: string } }> }>)[0]!
        .tool_calls[0]!.function.arguments;
      assert.equal(args.includes(ID), false);
      assert.equal(args.includes(REDACT_TAG), true);
    }

    const many = Array.from({ length: 2200 }, () => ({ a: true }));
    const over = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [
          {
            role: "assistant",
            content: null,
            tool_calls: [
              { id: "c1", type: "function", function: { name: "run", arguments: JSON.stringify({ items: many }) } },
            ],
          },
        ],
      }),
    );
    assert.equal(over.ok, false);
    if (!over.ok) {
      assert.equal(over.code, "nested_too_deep");
      assert.equal(over.field === undefined || over.field === "unknown_field" || typeof over.field === "string", true);
      if (over.field) assert.equal(over.field.includes(OPENAI_SK), false);
    }
  });

  it("accepts official stream_tool_calls and reasoning_effort", () => {
    const r = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        ...TEXT_BODY,
        stream: true,
        stream_tool_calls: false,
        reasoning_effort: "low",
        stream_options: { include_usage: true },
      }),
    );
    assert.equal(r.ok, true);
  });

  it("rejects prefixed large base64 and allows Bearer placeholder docs", () => {
    const prefixed = `payload: ${Buffer.alloc(240, 155).toString("base64")}`;
    assert.equal(looksEncodedPayload(prefixed), true);
    const enc = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ model: "m", messages: [{ role: "user", content: prefixed }] }),
    );
    assert.equal(enc.ok, false);
    if (!enc.ok) assert.equal(enc.code, "encoded_payload");

    const docs = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: "Use Authorization: Bearer token and api_key placeholder." }],
      }),
    );
    assert.equal(docs.ok, true);

    const realBearer = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: `Bearer ${"AbCdEfGhIjKlMnOpQrStUvWx"}` }],
      }),
    );
    assert.equal(realBearer.ok, false);
  });

  it("does not leak unknown secret keys into inspect.field", () => {
    const r = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ ...TEXT_BODY, [OPENAI_SK]: "x" }),
    );
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.code, "protocol_unsupported");
      assert.equal(r.field, "unknown_field");
      assert.equal(JSON.stringify(r).includes(OPENAI_SK), false);
    }
  });

  it("still rejects JSON-wrapped and prose-wrapped encoded payloads", () => {
    const gz = gzipSync(Buffer.alloc(2048, 65)).toString("base64");
    const wrapped = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({ model: "m", messages: [{ role: "user", content: JSON.stringify({ note: "see", blob: gz }) }] }),
    );
    assert.equal(wrapped.ok, false);
    if (!wrapped.ok) assert.equal(wrapped.code, "encoded_payload");

    const prose = inspectModelPayload(
      "/v1/chat/completions",
      JSON.stringify({
        model: "m",
        messages: [{ role: "user", content: `please review this archive for me:\n${gz}\nthanks` }],
      }),
    );
    assert.equal(prose.ok, false);
    if (!prose.ok) assert.equal(prose.code, "encoded_payload");
  });
});

describe("model-gateway http", () => {
  it("forwards normal text and tool messages with host-config auth only", async () => {
    await withPair(async (ctx) => {
      const st = ctx.gw.status();
      assert.equal(st.blocksDirectOutbound, false);
      assert.equal(st.poisonDetection, true);
      assert.equal(st.responseInspection, "chat_completions_json_sse_alert_only");
      assert.equal(st.covertChannelComplete, false);
      assert.equal(st.bindHost, "127.0.0.1");

      const a = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
      assert.equal(a.status, 200);
      assert.equal(a.json.id, "syn");
      assert.equal(ctx.hits.length, 1);
      const auth = String(ctx.hits[0]!.headers.authorization ?? "");
      assert.equal(auth, `Bearer ${ctx.upToken}`);
      assert.equal(auth.includes(ctx.token), false);
      assert.equal(ctx.hits[0]!.headers.cookie, undefined);
      assert.equal(ctx.hits[0]!.headers["accept-encoding"], "identity");
      assert.equal(ctx.hits[0]!.url, "/v1/chat/completions");

      const b = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TOOL_BODY) });
      assert.equal(b.status, 200);
      assert.equal(ctx.hits.length, 2);
      const sent = JSON.parse(ctx.hits[1]!.body.toString("utf8")) as typeof TOOL_BODY;
      assert.equal(sent.messages.length, 3);
      assert.equal((sent.messages[1] as { tool_calls: unknown[] }).tool_calls.length, 1);

      assertNoSecretsInTelemetry(ctx.logs, ctx.events, [ctx.token, ctx.upToken]);
    });
  });

  it("inspects chunked bodies fully before any upstream byte", async () => {
    await withPair(async (ctx) => {
      const payload = JSON.stringify({ model: "m", messages: [{ role: "user", content: BODY_MARK }] });
      const p = call({
        port: ctx.port,
        token: ctx.token,
        body: payload,
        chunked: true,
        chunkDelayMs: 60,
      });
      await delay(30);
      assert.equal(ctx.connections(), 0);
      assert.equal(ctx.hits.length, 0);
      const r = await p;
      assert.equal(r.status, 200);
      assert.equal(ctx.hits.length, 1);
      assert.equal(ctx.hits[0]!.body.toString("utf8").includes(BODY_MARK), true);
    });
  });

  it("replaces PII with tags on the wire and keeps legal upstream auth", async () => {
    await withPair(async (ctx) => {
      const r = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({
          model: "m",
          messages: [{ role: "user", content: `id=${ID} ${BODY_MARK}` }],
        }),
        headers: {
          cookie: "session=steal",
          "x-forwarded-for": "8.8.8.8",
          "x-api-key": OPENAI_SK,
          forwarded: "for=1.1.1.1",
        },
      });
      assert.equal(r.status, 200);
      assert.equal(ctx.hits.length, 1);
      const raw = ctx.hits[0]!.body.toString("utf8");
      assert.equal(raw.includes(ID), false);
      assert.equal(raw.includes(REDACT_TAG), true);
      assert.equal(raw.includes(BODY_MARK), true);
      assert.equal(ctx.hits[0]!.headers.cookie, undefined);
      assert.equal(ctx.hits[0]!.headers["x-forwarded-for"], undefined);
      assert.equal(ctx.hits[0]!.headers["x-api-key"], undefined);
      assert.equal(ctx.hits[0]!.headers.forwarded, undefined);
      assert.equal(ctx.hits[0]!.headers.authorization, `Bearer ${ctx.upToken}`);
      assertNoSecretsInTelemetry(ctx.logs, ctx.events, [ctx.token, ctx.upToken, ID, BODY_MARK]);
    });
  });

  it("does not connect upstream for secrets, binary, encoded, upload, redirect, URL injection, auth forgery, unknown types", async () => {
    await withPair(async (ctx) => {
      const deny = async (body: string | Buffer, extra?: Parameters<typeof call>[0]) => {
        const before = ctx.connections();
        const r = await call({
          port: ctx.port,
          token: ctx.token,
          body,
          ...extra,
        });
        assert.notEqual(r.status, 200);
        assert.ok(r.json.error);
        assert.equal(ctx.connections(), before);
        assert.equal(ctx.hits.length, 0);
        return r;
      };

      const secret = await deny(JSON.stringify({ model: "m", messages: [{ role: "user", content: OPENAI_SK }] }));
      assert.equal(secret.json.error, "secret_blocked");
      await deny(JSON.stringify({ model: "m", messages: [{ role: "user", content: AWS_KEY }] }));

      const gz = gzipSync(Buffer.alloc(4096, 7));
      const gzB64 = gz.toString("base64");
      const encoded = await deny(JSON.stringify({ model: "m", messages: [{ role: "user", content: gzB64 }] }));
      assert.equal(encoded.json.error, "encoded_payload");

      const key = randomBytes(32);
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const enc = Buffer.concat([cipher.update(Buffer.alloc(2048, 9)), cipher.final(), cipher.getAuthTag()]);
      const encB64 = Buffer.concat([iv, enc]).toString("base64");
      const encR = await deny(JSON.stringify({ model: "m", messages: [{ role: "user", content: encB64 }] }));
      assert.equal(encR.json.error, "encoded_payload");

      const bin = await call({
        port: ctx.port,
        token: ctx.token,
        body: Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff]),
        headers: { "content-type": "application/octet-stream" },
      });
      assert.equal(bin.json.error, "content_type");
      assert.equal(ctx.hits.length, 0);

      const gzipHdr = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify(TEXT_BODY),
        headers: { "content-encoding": "gzip" },
      });
      assert.equal(gzipHdr.json.error, "content_encoding");
      assert.equal(ctx.hits.length, 0);

      const multi = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify(TEXT_BODY),
        headers: { "content-type": "multipart/form-data; boundary=x" },
      });
      assert.equal(multi.json.error, "content_type");

      const upload = await call({ port: ctx.port, token: ctx.token, path: "/v1/files", body: JSON.stringify(TEXT_BODY) });
      assert.equal(upload.json.error, "route_denied");

      const audio = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/audio/transcriptions",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(audio.json.error, "route_denied");

      const abs = await call({
        port: ctx.port,
        token: ctx.token,
        path: "http://evil.example/v1/chat/completions",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(abs.json.error, "route_denied");

      const q = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/chat/completions?url=http://evil.example",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(q.json.error, "query_denied");

      const encPath = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/chat/%63ompletions",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(encPath.json.error, "route_denied");

      const trav = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/chat/completions/../files",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(trav.json.error, "route_denied");

      const host = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify(TEXT_BODY),
        host: "evil.example",
      });
      assert.equal(host.json.error, "host_denied");

      const forged = await call({
        port: ctx.port,
        token: "not-the-session-token-at-all-xxxxxxxx",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(forged.json.error, "auth_denied");

      const upAsClient = await call({
        port: ctx.port,
        token: ctx.upToken,
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(upAsClient.json.error, "auth_denied");

      const msg = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/messages",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(msg.json.error, "protocol_unsupported");

      const responses = await call({
        port: ctx.port,
        token: ctx.token,
        path: "/v1/responses",
        body: JSON.stringify(TEXT_BODY),
      });
      assert.equal(responses.json.error, "protocol_unsupported");

      const inject = await deny(
        JSON.stringify({ ...TEXT_BODY, base_url: "http://127.0.0.1:1", api_key: ctx.upToken }),
      );
      assert.equal(inject.json.error, "protocol_unsupported");

      const unknownType = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({
          model: "m",
          messages: [{ role: "user", content: [{ type: "input_audio", input_audio: { data: "AAAA", format: "wav" } }] }],
        }),
      });
      assert.equal(unknownType.json.error, "protocol_unsupported");
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);
    });
  });

  it("does not follow upstream redirects or leak Location", async () => {
    await withPair(
      async (ctx) => {
        const r = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(r.status, 502);
        assert.equal(r.json.error, "upstream_redirect");
        assert.equal(r.headers.location, undefined);
        assert.equal(r.text.includes("evil"), false);
        assert.equal(ctx.hits.length, 1);
      },
      {
        handle: (_req, res) => {
          res.writeHead(302, { location: "http://evil.example/steal", "content-type": "text/html" });
          res.end("redirect");
        },
      },
    );
  });

  it("streams SSE chunks faithfully", async () => {
    await withPair(
      async (ctx) => {
        const r = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ ...TEXT_BODY, stream: true }),
        });
        assert.equal(r.status, 200);
        assert.match(String(r.headers["content-type"]), /text\/event-stream/);
        const text = r.text;
        assert.equal(text.includes("data: {\"id\":\"c1\"}"), true);
        assert.equal(text.includes("data: {\"id\":\"c2\"}"), true);
        assert.equal(text.includes("data: [DONE]"), true);
        assert.ok(r.chunks.length >= 2);
        assert.equal(r.headers["cache-control"]?.includes("no-store"), true);
      },
      {
        handle: async (_req, res) => {
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.write("data: {\"id\":\"c1\"}\n\n");
          await delay(20);
          res.write("data: {\"id\":\"c2\"}\n\n");
          await delay(20);
          res.write("data: [DONE]\n\n");
          res.end();
        },
      },
    );
  });

  it("rejects oversize, malformed, timeout, cancel, and retries cannot skip inspect", async () => {
    await withPair(
      async (ctx) => {
        const mal = await call({ port: ctx.port, token: ctx.token, body: "{not json" });
        assert.equal(mal.json.error, "malformed");
        assert.equal(ctx.hits.length, 0);

        const big = "x".repeat(20_000);
        const over = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: big }] }),
        });
        assert.ok(over.json.error === "body_too_large" || over.json.error === "protocol_unsupported");
        assert.equal(ctx.hits.length, 0);

        const secret = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: OPENAI_SK }] }),
        });
        assert.equal(secret.json.error, "secret_blocked");
        const secret2 = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: OPENAI_SK }] }),
        });
        assert.equal(secret2.json.error, "secret_blocked");
        assert.equal(ctx.hits.length, 0);

        const ok = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok.status, 200);
        assert.equal(ctx.hits.length, 1);

        const timed = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hang-please" }] }),
        });
        assert.equal(timed.json.error, "timeout");

        await assert.rejects(
          () =>
            call({
              port: ctx.port,
              token: ctx.token,
              body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hang-please" }] }),
              abortAfterMs: 40,
            }),
        );

        const ok2 = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok2.status, 200);
        assert.ok(ctx.hits.length >= 2);

        const secret3 = await call({
          port: ctx.port,
          token: ctx.token,
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: `password=${OPENAI_SK}` }] }),
        });
        assert.equal(secret3.json.error, "secret_blocked");
        const after = ctx.hits.length;
        const ok3 = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok3.status, 200);
        assert.equal(ctx.hits.length, after + 1);
      },
      {
        extra: { timeoutMs: 250, bodyLimit: 16_384 },
        handle: (_req, res, raw) => {
          const text = raw.toString("utf8");
          if (text.includes("hang-please")) return;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ id: "syn" }));
        },
      },
    );
  });

  it("cancels upstream when the client disconnects mid-stream", async () => {
    let upstreamClosed = false;
    await withPair(
      async (ctx) => {
        await new Promise<void>((resolve, reject) => {
          const req = httpRequest(
            {
              hostname: "127.0.0.1",
              port: ctx.port,
              path: "/v1/chat/completions",
              method: "POST",
              headers: {
                host: `127.0.0.1:${ctx.port}`,
                authorization: `Bearer ${ctx.token}`,
                "content-type": "application/json",
                "content-length": Buffer.byteLength(JSON.stringify({ ...TEXT_BODY, stream: true })),
              },
            },
            (res) => {
              res.once("data", () => {
                req.destroy();
              });
            },
          );
          req.on("error", () => resolve());
          req.on("close", () => resolve());
          setTimeout(() => resolve(), 2_000);
          req.write(JSON.stringify({ ...TEXT_BODY, stream: true }));
          req.end();
          req.on("timeout", () => reject(new Error("timeout")));
        });
        await delay(80);
        assert.equal(upstreamClosed, true);
      },
      {
        handle: (_req, res) => {
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.write("data: {\"id\":\"c1\"}\n\n");
          res.on("close", () => {
            upstreamClosed = true;
          });
        },
      },
    );
  });

  it("close() destroys inflight upstreams", async () => {
    const hits: Hit[] = [];
    let connections = 0;
    const upstream = createServer((req, res) => {
      req.on("data", () => undefined);
      req.on("end", () => {
        hits.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.alloc(0) });
      });
      void res;
    });
    upstream.on("connection", () => {
      connections += 1;
    });
    const upstreamPort = await listen(upstream);
    const gw = await startModelGateway({
      upstreamOrigin: `http://127.0.0.1:${upstreamPort}`,
      upstreamToken: `${UP_MARK}close`,
      sessionToken: `${SESS_MARK}${"c".repeat(24)}`,
      createUpstreamRequest: loopbackHttpFactory,
      timeoutMs: 8_000,
    });
    try {
      const req = httpRequest({
        hostname: "127.0.0.1",
        port: gw.port,
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          host: `127.0.0.1:${gw.port}`,
          authorization: `Bearer ${gw.sessionToken}`,
          "content-type": "application/json",
        },
      });
      const finished = new Promise<void>((resolve) => {
        req.on("error", () => resolve());
        req.on("close", () => resolve());
      });
      req.write(JSON.stringify(TEXT_BODY));
      req.end();
      await delay(80);
      assert.ok(connections >= 1);
      await gw.close();
      await finished;
      assert.equal(gw.status().inflight, 0);
    } finally {
      await closeServer(upstream);
    }
  });

  it("CONNECT and upgrade never reach upstream", async () => {
    await withPair(async (ctx) => {
      const raw = await new Promise<string>((resolve) => {
        const s = net.connect(ctx.port, "127.0.0.1");
        let buf = "";
        s.on("data", (c) => {
          buf += c.toString("utf8");
        });
        s.on("close", () => resolve(buf));
        s.write(`CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n`);
        setTimeout(() => s.destroy(), 500);
      });
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);
      assert.equal(raw.includes("200"), false);

      const up = await new Promise<number>((resolve) => {
        const req = httpRequest({
          hostname: "127.0.0.1",
          port: ctx.port,
          path: "/v1/chat/completions",
          method: "GET",
          headers: {
            host: `127.0.0.1:${ctx.port}`,
            authorization: `Bearer ${ctx.token}`,
            connection: "Upgrade",
            upgrade: "websocket",
          },
        });
        req.on("upgrade", () => resolve(1));
        req.on("response", (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        req.on("error", () => resolve(0));
        req.end();
      });
      assert.notEqual(up, 101);
      assert.equal(ctx.hits.length, 0);
    });
  });

  it("http origin without factory is refused; production TLS is verified", async () => {
    await assert.rejects(
      () =>
        startModelGateway({
          upstreamOrigin: "http://127.0.0.1:9",
          sessionToken: `${SESS_MARK}${"t".repeat(24)}`,
        }),
      /origin_invalid/,
    );
    await assert.rejects(
      () =>
        startModelGateway({
          upstreamOrigin: "http://example.test",
          sessionToken: `${SESS_MARK}${"t".repeat(24)}`,
          createUpstreamRequest: loopbackHttpFactory,
        }),
      /origin_invalid/,
    );

    const tls = generateNmzpCert(["127.0.0.1"]);
    let gotBody = false;
    const srv = createHttpsServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
      req.on("data", () => {
        gotBody = true;
      });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{}");
      });
    });
    const port = await listen(srv);
    const gw = await startModelGateway({
      upstreamOrigin: `https://127.0.0.1:${port}`,
      sessionToken: `${SESS_MARK}${"t".repeat(24)}`,
      timeoutMs: 1_000,
    });
    try {
      const r = await call({
        port: gw.port,
        token: gw.sessionToken,
        body: JSON.stringify(TEXT_BODY),
      });
      assert.notEqual(r.status, 200);
      assert.equal(gotBody, false);
      assert.equal(r.json.error, "upstream_error");
    } finally {
      await gw.close();
      await closeServer(srv);
    }
  });

  it("errors are short codes and never include tokens or config", async () => {
    await withPair(async (ctx) => {
      const r = await call({
        port: ctx.port,
        token: "short-wrong-token-value-xxxxxxxx",
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: `${OPENAI_SK} ${ID} ${BODY_MARK}` }] }),
      });
      assert.equal(r.json.error, "auth_denied");
      assert.equal(Object.keys(r.json).join(","), "error");
      assert.equal(r.text.includes(ctx.token), false);
      assert.equal(r.text.includes(ctx.upToken), false);
      assert.equal(r.text.includes("127.0.0.1"), false);
      assert.equal(r.text.includes(OPENAI_SK), false);
      assert.equal(r.headers["cache-control"]?.includes("no-store"), true);
      assertNoSecretsInTelemetry(ctx.logs, ctx.events, [ctx.token, ctx.upToken]);
    });
  });

  it("default absolute budget is 10 minutes", async () => {
    const gw = await startModelGateway({
      upstreamOrigin: "https://api.example.test",
      sessionToken: `${SESS_MARK}${"d".repeat(24)}`,
    });
    try {
      assert.equal(gw.status().timeoutMs, DEFAULT_TIMEOUT_MS);
      assert.equal(DEFAULT_TIMEOUT_MS, 600_000);
    } finally {
      await gw.close();
    }
  });

  it("review leaks do not reach upstream; normal schema and inner JSON still do", async () => {
    await withPair(async (ctx) => {
      const keyPii = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({
          model: "m",
          messages: [{ role: "user", content: "n" }],
          tools: [
            {
              type: "function",
              function: {
                name: "lookup",
                parameters: { type: "object", properties: { [ID]: { type: "string" } } },
              },
            },
          ],
        }),
      });
      assert.equal(keyPii.json.error, "secret_blocked");
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);

      const inner = `{"text":"\\u0073${OPENAI_SK.slice(1)}"}`;
      const uni = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({
          model: "m",
          messages: [
            {
              role: "assistant",
              content: null,
              tool_calls: [{ id: "c1", type: "function", function: { name: "run", arguments: inner } }],
            },
          ],
        }),
      });
      assert.equal(uni.json.error, "secret_blocked");
      assert.equal(ctx.hits.length, 0);

      const prefixed = `payload: ${Buffer.alloc(240, 155).toString("base64")}`;
      const b64 = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: prefixed }] }),
      });
      assert.equal(b64.json.error, "encoded_payload");
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);

      const schema = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(FILE_SCHEMA_BODY) });
      assert.equal(schema.status, 200);
      assert.equal(ctx.hits.length, 1);

      const innerFile = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(INNER_FILE_ARGS_BODY) });
      assert.equal(innerFile.status, 200);
      assert.equal(ctx.hits.length, 2);
      const sentArgs = JSON.parse(ctx.hits[1]!.body.toString("utf8")) as typeof INNER_FILE_ARGS_BODY;
      const args = (sentArgs.messages[0] as { tool_calls: Array<{ function: { arguments: string } }> }).tool_calls[0]!
        .function.arguments;
      assert.equal(JSON.parse(args).file, "notes.txt");

      const stream = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({ ...TEXT_BODY, stream: true }),
      });
      assert.equal(stream.status, 200);
    });
  });

  it("far-oversize body is bounded with upstream 0 then a normal request still works", async () => {
    await withPair(
      async (ctx) => {
        const huge = JSON.stringify({ model: "m", messages: [{ role: "user", content: "x".repeat(300_000) }] });
        assert.ok(huge.length > 16_384 * 4);
        try {
          const over = await call({ port: ctx.port, token: ctx.token, body: huge });
          assert.ok(over.status === 413 || over.json.error === "body_too_large");
        } catch (e) {
          assert.equal(isConnReset(e), true);
        }
        assert.equal(ctx.hits.length, 0);
        assert.equal(ctx.connections(), 0);
        const ok = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok.status, 200);
        assert.equal(ctx.hits.length, 1);
      },
      { extra: { bodyLimit: 16_384, timeoutMs: 4_000 } },
    );
  });

  it("rejects gzip upstream responses and oversize streams then settles inflight", async () => {
    await withPair(
      async (ctx) => {
        const gz = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(gz.json.error, "upstream_encoding");
        assert.equal(ctx.gw.status().inflight, 0);
        assert.equal(ctx.hits[0]!.headers["accept-encoding"], "identity");
      },
      {
        handle: (_req, res) => {
          const payload = gzipSync(Buffer.from(JSON.stringify({ id: "gz" })));
          res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
          res.end(payload);
        },
      },
    );

    await withPair(
      async (ctx) => {
        await assert.rejects(() =>
          call({ port: ctx.port, token: ctx.token, body: JSON.stringify({ ...TEXT_BODY, stream: true }) }),
        );
        await delay(30);
        assert.equal(ctx.gw.status().inflight, 0);
        const ok = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok.status, 200);
      },
      {
        extra: { maxOutBytes: 64, timeoutMs: 2_000 },
        handle: (_req, res, raw) => {
          if (raw.includes('"stream":true')) {
            res.writeHead(200, { "content-type": "text/event-stream" });
            res.write("data: " + "y".repeat(200) + "\n\n");
            res.end();
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ id: "syn" }));
        },
      },
    );
  });

  it("stream idle timeout and concurrency 429 do not queue bodies onto upstream", async () => {
    await withPair(
      async (ctx) => {
        const t0 = Date.now();
        try {
          const r = await call({
            port: ctx.port,
            token: ctx.token,
            body: JSON.stringify({ ...TEXT_BODY, stream: true }),
          });
          assert.ok(r.json.error === "timeout" || r.status !== 200 || r.text.includes("c1"));
        } catch (e) {
          assert.ok(isConnReset(e) || e instanceof Error);
        }
        assert.ok(Date.now() - t0 < 1_500);
        await delay(20);
        assert.equal(ctx.gw.status().inflight, 0);
      },
      {
        extra: { streamIdleMs: 80, timeoutMs: 2_000 },
        handle: (_req, res) => {
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.write("data: {\"id\":\"c1\"}\n\n");
        },
      },
    );

    await withPair(
      async (ctx) => {
        const jobs = Array.from({ length: 6 }, () =>
          call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) }).then(
            (r) => r.status,
            () => 0,
          ),
        );
        const codes = await Promise.all(jobs);
        const busy = codes.filter((c) => c === 429).length;
        const ok = codes.filter((c) => c === 200).length;
        assert.ok(busy >= 1);
        assert.ok(ok >= 1 && ok <= 2);
        assert.ok(ctx.hits.length <= 2);
        assert.ok(ctx.connections() <= 2);
        await delay(250);
        const later = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(later.status, 200);
        assert.equal(
          ctx.events.every((e) => e.method === "POST" || e.method === "OTHER" || e.method === undefined),
          true,
        );
      },
      {
        extra: { maxInflight: 2, timeoutMs: 2_000 },
        handle: (_req, res) => {
          setTimeout(() => {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ id: "syn" }));
          }, 150);
        },
      },
    );
  });

  it("body idle timeout does not reach upstream", async () => {
    await withPair(
      async (ctx) => {
        try {
          await call({
            port: ctx.port,
            token: ctx.token,
            body: JSON.stringify(TEXT_BODY),
            chunked: true,
            chunkDelayMs: 120,
          });
        } catch {
          /* reset or timeout */
        }
        assert.equal(ctx.hits.length, 0);
        assert.equal(ctx.connections(), 0);
        const ok = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok.status, 200);
        assert.equal(ctx.hits.length, 1);
      },
      { extra: { bodyIdleMs: 40, timeoutMs: 2_000 } },
    );
  });

  it("unknown secret top-level keys stay out of events logs and error bodies", async () => {
    await withPair(async (ctx) => {
      const r = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({ ...TEXT_BODY, [OPENAI_SK]: "leak" }),
      });
      assert.equal(r.json.error, "protocol_unsupported");
      assert.equal(r.text.includes(OPENAI_SK), false);
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);
      const blob = `${ctx.logs.join("\n")}\n${JSON.stringify(ctx.events)}`;
      assert.equal(blob.includes(OPENAI_SK), false);
      assert.ok(ctx.events.some((e) => e.code === "protocol_unsupported" && e.field === "unknown_field"));
    });
  });

  it("JSON-wrapped encoded payload does not reach upstream", async () => {
    await withPair(async (ctx) => {
      const gz = gzipSync(Buffer.alloc(2048, 7)).toString("base64");
      const r = await call({
        port: ctx.port,
        token: ctx.token,
        body: JSON.stringify({
          model: "m",
          messages: [{ role: "user", content: JSON.stringify({ wrap: gz }) }],
        }),
      });
      assert.equal(r.json.error, "encoded_payload");
      assert.equal(ctx.hits.length, 0);
      assert.equal(ctx.connections(), 0);
    });
  });

  it("headerIdle short injection is not stuck on Node 30s checker", async () => {
    await withPair(
      async (ctx) => {
        assert.equal(ctx.gw.status().headerIdleMs, 80);
        const t0 = Date.now();
        await new Promise<void>((resolve) => {
          const s = net.connect(ctx.port, "127.0.0.1", () => {
            s.write(`POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:${ctx.port}\r\n`);
          });
          s.on("data", (c) => {
            s.ref();
            void c;
          });
          s.on("close", () => resolve());
          s.on("error", () => resolve());
          setTimeout(() => s.destroy(), 8_000);
        });
        const elapsed = Date.now() - t0;
        assert.ok(
          elapsed < 3_000,
          `header idle waited ${elapsed}ms events=${JSON.stringify(ctx.events)} headerIdleMs=${ctx.gw.status().headerIdleMs}`,
        );
        assert.equal(ctx.hits.length, 0);
        const ok = await call({ port: ctx.port, token: ctx.token, body: JSON.stringify(TEXT_BODY) });
        assert.equal(ok.status, 200);
      },
      { extra: { headerIdleMs: 80, timeoutMs: 20_000 } },
    );
  });

  it("method metadata is whitelisted", async () => {
    await withPair(async (ctx) => {
      const body = JSON.stringify(TEXT_BODY);
      await new Promise<void>((resolve) => {
        const s = net.connect(ctx.port, "127.0.0.1");
        s.on("close", () => resolve());
        s.on("error", () => resolve());
        s.write(
          `PURGE /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:${ctx.port}\r\nAuthorization: Bearer ${ctx.token}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
        setTimeout(() => s.destroy(), 500);
      });
      assert.equal(ctx.hits.length, 0);
      assert.equal(
        ctx.events.some((e) => e.method === "OTHER" && e.code === "method_denied"),
        true,
      );
      assert.equal(
        ctx.logs.some((l) => l.includes("PURGE")),
        false,
      );
    });
  });
});
