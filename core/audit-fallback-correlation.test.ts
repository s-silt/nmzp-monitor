import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "./auth.ts";
import { parseBackfill } from "./audit/backfill.ts";
import { drainOutbox, enqueueOutbox, outboxStatus } from "./audit/outbox.ts";
import { runHook } from "./hook.ts";
import { pinnedHttps } from "./https-client.ts";
import { writePolicyCache } from "./policy-cache.ts";
import { startServer, type RunningServer } from "./serve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

function derivedLocalId(eventId: string): string {
  return `local:${sha256Hex(eventId).slice(0, 32)}`;
}

type ApiResult = { status: number; body: Record<string, unknown> };

async function api(
  core: RunningServer,
  path: string,
  method = "GET",
  body?: unknown,
  token = core.adminToken,
): Promise<ApiResult> {
  const res = await pinnedHttps({
    url: core.url + path,
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    caPem: core.tls.certPem,
    fingerprintSha256: core.tls.fingerprintSha256,
    timeoutMs: 5000,
  });
  return { status: res.status, body: JSON.parse(res.body || "{}") as Record<string, unknown> };
}

async function withCore(fn: (core: RunningServer) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-m12-"));
  const core = await startServer({
    dataDir: join(root, "ct"),
    host: "127.0.0.1",
    port: 0,
    coreDir,
    uiDir: null,
    storageMode: "sqlite",
  });
  try {
    await fn(core);
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
}

async function enroll(core: RunningServer, hostname: string): Promise<{ deviceId: string; deviceToken: string }> {
  const ticket = await api(core, "/api/v1/ticket", "POST");
  assert.equal(ticket.status, 200);
  const joined = await api(core, "/api/v1/join", "POST", {
    ticket: ticket.body.ticket,
    hostname,
    os: "win32",
    user: "fixture",
  });
  assert.equal(joined.status, 200);
  assert.equal(typeof joined.body.deviceId, "string");
  assert.equal(typeof joined.body.deviceToken, "string");
  return { deviceId: joined.body.deviceId as string, deviceToken: joined.body.deviceToken as string };
}

function eventPayload(eventId: string, decision: "allow" | "block" | "log", relatedEventId?: string) {
  return {
    eventId,
    ts: 1_700_000_000_000,
    agent: "grok",
    tool: "Bash",
    decision,
    risk: "high" as const,
    policyVersion: 1,
    ...(relatedEventId ? { relatedEventId } : {}),
  };
}

it("timeout fallback keeps both online and local decisions linked", { timeout: 30_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "nmzp-m12-"));
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const sockets = new Set<{ destroy(): void }>();
  let core: RunningServer | undefined;
  let proxy: ReturnType<typeof createServer> | undefined;
  let online: ApiResult | undefined;
  try {
    core = await startServer({
      dataDir: join(root, "ct"),
      host: "127.0.0.1",
      port: 0,
      coreDir,
      uiDir: null,
      storageMode: "sqlite",
    });
    const device = await enroll(core, "synthetic");
    const server = core;
    proxy = createServer({ key: server.tls.keyPem, cert: server.tls.certPem }, (incoming, response) => {
      incoming.on("error", () => {
        if (!response.destroyed) response.destroy();
      });
      response.on("error", () => undefined);
      void (async () => {
        try {
          const chunks: Buffer[] = [];
          for await (const chunk of incoming) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          const forwarded = await api(server, "/api/v1/evaluate", "POST", JSON.parse(Buffer.concat(chunks).toString("utf8")), device.deviceToken);
          online = forwarded;
          const timer = setTimeout(() => {
            timers.delete(timer);
            if (response.destroyed || response.writableEnded) return;
            response.writeHead(forwarded.status, { "content-type": "application/json" });
            response.end(JSON.stringify(forwarded.body));
          }, 2100);
          timers.add(timer);
        } catch {
          if (!response.destroyed) response.destroy();
        }
      })();
    });
    proxy.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    await new Promise<void>((resolve) => proxy!.listen(0, "127.0.0.1", () => resolve()));
    const address = proxy.address();
    if (!address || typeof address === "string") throw new Error("proxy listen failed");
    const home = join(root, "device");
    await mkdir(join(home, ".nmzp"), { recursive: true });
    const creds = {
      deviceId: device.deviceId,
      token: device.deviceToken,
      url: `https://127.0.0.1:${address.port}`,
      caPem: server.tls.certPem,
      fingerprintSha256: server.tls.fingerprintSha256,
    };
    await writeFile(join(home, ".nmzp", "credentials.json"), JSON.stringify(creds));
    await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), { ...server.store.getPolicy(), mode: "permissive" });
    const eventId = "fallback-online";
    const result = await runHook({
      home,
      coreDir,
      env: {},
      argv: ["--agent", "grok"],
      stdin: JSON.stringify({ eventId, tool_name: "Bash", tool_input: { command: "mkfs" } }),
    });
    const deadline = Date.now() + 3000;
    while (!online && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(result.exitCode, 0, "host must follow the local cache decision");
    assert.equal(online?.body.decision, "block", "control tower must commit the online block");
    const before = await server.store.getEvent(device.deviceId, eventId);
    assert.equal(before?.decision, "block", "online decision must stay the committed block");
    assert.equal(before?.enforcement, "pending_verify", "online enforcement must stay pending_verify");
    assert.ok(result.pendingBackfill);
    const target = { ...creds, url: server.url };
    await enqueueOutbox(home, target, result.pendingBackfill.item);
    const drained = await drainOutbox(home, target, { timeoutMs: 5000, allowEvents: true });
    const status = await outboxStatus(home);
    assert.equal(status.quarantined, 0, "fallback backfill must not be quarantined");
    assert.equal(drained.acked, 1, "fallback backfill must be delivered");
    const localId = derivedLocalId(eventId);
    const local = await server.store.getEvent(device.deviceId, localId);
    assert.equal(local?.id, localId, "local fallback event must use the derived id");
    assert.equal(local?.relatedEventId, eventId, "stored local decision must keep relatedEventId");
    assert.equal(local?.source, "offline_backfill");
    assert.equal(local?.decision, "log", "local decision must be the permissive cache decision");
    assert.equal(local?.machineId, device.deviceId);
    const after = await server.store.getEvent(device.deviceId, eventId);
    assert.equal(after?.decision, before?.decision, "backfill must not rewrite the online decision");
    assert.equal(after?.enforcement, before?.enforcement, "backfill must not rewrite the online enforcement");
    assert.equal(after?.relatedEventId, undefined);
    const history = await api(server, "/api/v1/audit/events?limit=25");
    const projected = (history.body.events as Array<{ id?: string; relatedEventId?: string }> | undefined)?.find((row) => row.id === localId);
    assert.equal(projected?.relatedEventId, eventId, "audit history must project relatedEventId");
    const state = await api(server, "/api/v1/state");
    const stateRow = (state.body.events as Array<{ id?: string; relatedEventId?: string }> | undefined)?.find((row) => row.id === localId);
    assert.equal(stateRow?.relatedEventId, eventId, "state history must project relatedEventId");
  } finally {
    for (const timer of timers) clearTimeout(timer);
    for (const socket of sockets) socket.destroy();
    if (proxy?.listening) await new Promise<void>((resolve) => proxy!.close(() => resolve()));
    await core?.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("refused connection before the request is sent keeps the original event id", { timeout: 30_000 }, async () => {
  const home = await mkdtemp(join(tmpdir(), "nmzp-m12-refused-"));
  try {
    await withCore(async (core) => {
      const device = await enroll(core, "synthetic");
      await mkdir(join(home, ".nmzp"), { recursive: true });
      const creds = {
        deviceId: device.deviceId,
        token: device.deviceToken,
        url: "https://127.0.0.1:1",
        caPem: core.tls.certPem,
        fingerprintSha256: core.tls.fingerprintSha256,
      };
      await writeFile(join(home, ".nmzp", "credentials.json"), JSON.stringify(creds));
      await writePolicyCache(join(home, ".nmzp", "policy-cache.json"), {
        ...core.store.getPolicy(),
        mode: "permissive",
      });
      const eventId = "refused-before-send";
      const result = await runHook({
        home,
        coreDir,
        env: {},
        argv: ["--agent", "grok"],
        stdin: JSON.stringify({ eventId, tool_name: "Bash", tool_input: { command: "mkfs" } }),
      });
      const queued = result.pendingBackfill;
      assert.ok(queued, "refused connection must queue the local decision");
      assert.equal(
        queued.item.eventId,
        eventId,
        "refused connection must keep the original event id",
      );
      assert.equal(queued.item.kind, "event");
      if (queued.item.kind !== "event") throw new Error("expected event backfill");
      assert.equal(queued.item.payload.eventId, eventId);
      assert.equal(
        queued.item.payload.relatedEventId,
        undefined,
        "refused connection must not record relatedEventId",
      );
      const target = { ...creds, url: core.url };
      await enqueueOutbox(home, target, queued.item);
      const drained = await drainOutbox(home, target, { timeoutMs: 5000, allowEvents: true });
      assert.equal(drained.acked, 1, "original-id backfill must be delivered");
      const stored = await core.store.getEvent(device.deviceId, eventId);
      assert.equal(stored?.id, eventId, "backfilled event must keep the original event id");
      assert.equal(
        stored?.relatedEventId,
        undefined,
        "backfilled event must omit relatedEventId",
      );
      assert.equal(await core.store.getEvent(device.deviceId, derivedLocalId(eventId)), undefined);
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

it("duplicate fallback backfill is idempotent", async () => {
  await withCore(async (core) => {
    const device = await enroll(core, "synthetic");
    const eventId = derivedLocalId("online-anchor");
    const payload = eventPayload(eventId, "log", "online-anchor");
    const body = { kind: "event", eventId, payload };
    const first = await api(core, "/api/v1/audit/backfill", "POST", body, device.deviceToken);
    assert.equal(first.status, 200);
    assert.equal(first.body.duplicate, false);
    const second = await api(core, "/api/v1/audit/backfill", "POST", body, device.deviceToken);
    assert.equal(second.status, 200);
    assert.equal(second.body.duplicate, true, "duplicate fallback backfill must be acknowledged");
    const third = await api(core, "/api/v1/audit/backfill", "POST", {
      kind: "event",
      eventId,
      payload: { ...payload, relatedEventId: "other-anchor" },
    }, device.deviceToken);
    assert.equal(third.status, 409, "relatedEventId is part of the backfill identity");
    const stored = await core.store.getEvent(device.deviceId, eventId);
    assert.equal(stored?.relatedEventId, "online-anchor");
    assert.equal(stored?.decision, "log");
  });
});

it("another machine cannot attach to a foreign online event", async () => {
  await withCore(async (core) => {
    const machineA = await enroll(core, "machine-a");
    const machineB = await enroll(core, "machine-b");
    const onlineId = "device-a-online";
    const evaluated = await api(core, "/api/v1/evaluate", "POST", {
      eventId: onlineId,
      sessionId: "s",
      agent: "grok",
      tool_name: "Read",
      tool_input: { file_path: "synthetic.txt" },
    }, machineA.deviceToken);
    assert.equal(evaluated.status, 200);
    const before = await core.store.getEvent(machineA.deviceId, onlineId);
    assert.ok(before);
    const localId = derivedLocalId(onlineId);
    const posted = await api(core, "/api/v1/audit/backfill", "POST", {
      kind: "event",
      eventId: localId,
      payload: eventPayload(localId, "log", onlineId),
    }, machineB.deviceToken);
    assert.equal(posted.status, 200);
    const after = await core.store.getEvent(machineA.deviceId, onlineId);
    assert.equal(after?.decision, before.decision, "foreign backfill must not modify the online decision");
    assert.equal(after?.enforcement, before.enforcement, "foreign backfill must not modify the online enforcement");
    assert.equal(after?.source, before.source);
    assert.equal(after?.relatedEventId, before.relatedEventId);
    const rowB = await core.store.getEvent(machineB.deviceId, localId);
    assert.equal(rowB?.machineId, machineB.deviceId, "fallback record stays in the caller namespace");
    assert.equal(rowB?.relatedEventId, onlineId);
    assert.equal(await core.store.getEvent(machineA.deviceId, localId), undefined, "foreign backfill must not enter the other machine namespace");
    const pageA = await api(core, `/api/v1/audit/events?limit=25&machineId=${encodeURIComponent(machineA.deviceId)}`);
    const idsA = ((pageA.body.events as Array<{ id?: string }> | undefined) ?? []).map((row) => row.id);
    assert.equal(idsA.includes(localId), false);
    const pageB = await api(core, `/api/v1/audit/events?limit=25&machineId=${encodeURIComponent(machineB.deviceId)}`);
    const idsB = ((pageB.body.events as Array<{ id?: string }> | undefined) ?? []).map((row) => row.id);
    assert.equal(idsB.includes(localId), true);
    assert.equal(idsB.includes(onlineId), false);
  });
});

it("unrelated conflicting body under the same event id still conflicts", async () => {
  await withCore(async (core) => {
    const device = await enroll(core, "synthetic");
    const eventId = "same-event";
    const first = await api(core, "/api/v1/audit/backfill", "POST", {
      kind: "event",
      eventId,
      payload: eventPayload(eventId, "allow"),
    }, device.deviceToken);
    assert.equal(first.status, 200);
    const second = await api(core, "/api/v1/audit/backfill", "POST", {
      kind: "event",
      eventId,
      payload: eventPayload(eventId, "block"),
    }, device.deviceToken);
    assert.equal(second.status, 409, "unrelated body must still conflict");
    assert.equal(second.body.error, "event_conflict");
    assert.equal((await core.store.getEvent(device.deviceId, eventId))?.decision, "allow");
    const onlineId = "online-row";
    const evaluated = await api(core, "/api/v1/evaluate", "POST", {
      eventId: onlineId,
      sessionId: "s",
      agent: "grok",
      tool_name: "Read",
      tool_input: { file_path: "synthetic.txt" },
    }, device.deviceToken);
    assert.equal(evaluated.status, 200);
    const online = await core.store.getEvent(device.deviceId, onlineId);
    const clash = await api(core, "/api/v1/audit/backfill", "POST", {
      kind: "event",
      eventId: onlineId,
      payload: eventPayload(onlineId, "block"),
    }, device.deviceToken);
    assert.equal(clash.status, 409, "reusing an online event id with a different body must conflict");
    const after = await core.store.getEvent(device.deviceId, onlineId);
    assert.equal(after?.decision, online?.decision);
    assert.equal(after?.enforcement, online?.enforcement);
  });
});

it("backfill rejects relatedEventId equal to eventId or over 128 chars", () => {
  const eventId = "e";
  const base = eventPayload(eventId, "log");
  assert.ok(
    parseBackfill({ kind: "event", eventId, payload: { ...base, relatedEventId: "online-1" } }),
    "a distinct relatedEventId within 128 characters must be accepted",
  );
  assert.ok(
    parseBackfill({ kind: "event", eventId, payload: { ...base, relatedEventId: "r".repeat(128) } }),
    "relatedEventId of 128 characters must be accepted",
  );
  assert.equal(
    parseBackfill({ kind: "event", eventId, payload: { ...base, relatedEventId: eventId } }),
    null,
    "relatedEventId must not equal eventId",
  );
  assert.equal(
    parseBackfill({ kind: "event", eventId, payload: { ...base, relatedEventId: "x".repeat(129) } }),
    null,
    "relatedEventId over 128 characters must be rejected",
  );
  assert.equal(
    parseBackfill({ kind: "event", eventId, payload: { ...base, relatedEventId: "bad\nid" } }),
    null,
    "relatedEventId must not contain control characters",
  );
});
