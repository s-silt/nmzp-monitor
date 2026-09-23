import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { applyEvaluate } from "./eval-bridge.ts";
import { loadMonitor } from "./paths.ts";
import { NmzpStore } from "./persist.ts";
import { startServer } from "./serve.ts";
import { pinnedHttps } from "./https-client.ts";
import { mapEvent } from "../src/lib/monitor/map-event.ts";
import type { DeviceRecord, PolicyState } from "./schema.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

function tok(p: string): string {
  return `${p}_${randomBytes(8).toString("hex")}`;
}

const device: DeviceRecord = {
  id: "dev_eval",
  tokenHash: "x",
  hostname: "h",
  ip: "127.0.0.1",
  user: "u",
  os: "win32",
  attachedAt: 0,
  lastSeen: 0,
  lastPolicyVersion: 1,
  capabilities: [],
  agents: [],
};

const policy: PolicyState = {
  version: 7,
  mode: "enforcing",
  customRules: [],
  stopped: false,
  updatedAt: 0,
};

const windows = { apply: (_input: unknown, result: unknown) => result };

describe("evaluate audit projection", () => {
  it("keeps unique presigned secrets out of the whole stored event JSON", async () => {
    const monitor = await loadMonitor(coreDir);
    const sig = tok("synsig");
    const user = tok("synuser");
    const pathTok = tok("synpath");
    const oss = tok("syntok");
    const command =
      `curl "https://${user}:pw@bucket.oss-cn-hangzhou.aliyuncs.com/${pathTok}/o?X-Amz-Signature=${sig}&x-oss-security-token=${oss}" ` +
      `https://second.example.test/x`;
    const out = applyEvaluate({
      monitor,
      windows,
      policy,
      device,
      body: {
        eventId: "e-net-1",
        sessionId: "s-net",
        agent: "grok",
        tool_name: "run_terminal_command",
        tool_input: { command },
      },
      eventId: "e-net-1",
    });
    assert.ok(out.event);
    const raw = JSON.stringify(out.event);
    assert.equal(raw.includes(sig), false, raw.slice(0, 400));
    assert.equal(raw.includes(user), false);
    assert.equal(raw.includes(pathTok), false);
    assert.equal(raw.includes(oss), false);
    assert.equal(raw.includes("X-Amz-Signature"), false);
    assert.equal(out.event!.endpoints?.length, 2);
    assert.equal(out.event!.endpoints?.[0]?.host, "bucket.oss-cn-hangzhou.aliyuncs.com");
    assert.equal(out.event!.endpoints?.[0]?.source, "tool_command");
    assert.equal(out.event!.endpoints?.[0]?.observation, "declared");
    assert.equal(out.event!.endpoints?.[1]?.host, "second.example.test");
    assert.equal(out.event!.dest, "bucket.oss-cn-hangzhou.aliyuncs.com");
    assert.equal(out.event!.policyVersion, 7);
    assert.notEqual(out.event!.enforcement, "blocked");
    assert.equal(out.response.summary.includes(sig), false);
    const mapped = mapEvent({ ...out.event, requestHash: "a".repeat(64) });
    assert.equal(mapped?.endpoints?.length, 2);
    assert.equal(mapped?.policyVersion, 7);
    assert.equal(mapped?.requestHash, "a".repeat(64));
  });

  it("does not backfill historic rows missing endpoints", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-net-hist-"));
    try {
      const s = new NmzpStore(dir);
      await s.load();
      await writeFile(
        s.eventsPath(),
        `${JSON.stringify({
          id: "old-1",
          ts: 1_700_000_000_000,
          machineId: "dev_eval",
          agent: "grok",
          sessionId: "s",
          layer: "app_pre",
          tool: "Bash",
          nativeTool: "Bash",
          input: "curl https://legacy.example.test/x",
          redacted: "curl https://legacy.example.test/x",
          risk: "low",
          decision: "log",
          category: "shell",
          workdirScope: "project",
          dest: "legacy.example.test",
          policyVersion: 1,
          evaluation: "log",
          enforcement: "delivered",
        })}\n`,
      );
      const s2 = new NmzpStore(dir);
      await s2.load({ readOnly: true });
      const ev = await s2.getEvent("dev_eval", "old-1");
      assert.ok(ev);
      assert.equal("endpoints" in ev!, false);
      const mapped = mapEvent(ev);
      assert.ok(mapped);
      assert.equal(mapped!.endpoints, undefined);
      assert.equal(mapped!.dest, "legacy.example.test");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("evaluate+heartbeat public state", () => {
  it("stores endpoints and requestHash; maps timeout network without forging zero-ok", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-net-srv-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
    const admin = { authorization: `Bearer ${srv.adminToken}` };
    try {
      const ticketRes = await pinnedHttps({ url: `${srv.url}/api/v1/ticket`, method: "POST", headers: admin, ...pin });
      const ticket = (JSON.parse(ticketRes.body) as { ticket: string }).ticket;
      const join = await pinnedHttps({
        url: `${srv.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify({ ticket, hostname: "pc-net", os: "win32", user: "u" }),
        headers: { "content-type": "application/json" },
        ...pin,
      });
      const j = JSON.parse(join.body) as { deviceId: string; deviceToken: string };
      const deviceHdr = { authorization: `Bearer ${j.deviceToken}`, "content-type": "application/json" };
      const sig = tok("livesig");
      const ev = await pinnedHttps({
        url: `${srv.url}/api/v1/evaluate`,
        method: "POST",
        body: JSON.stringify({
          eventId: "evt-net",
          sessionId: "sess-net",
          agent: "grok",
          tool_name: "run_terminal_command",
          tool_input: { command: `curl https://files.example.test/p?X-Amz-Signature=${sig}` },
        }),
        headers: deviceHdr,
        ...pin,
      });
      assert.equal(ev.status, 200);
      assert.equal(ev.body.includes(sig), false);
      const hb = await pinnedHttps({
        url: `${srv.url}/api/v1/heartbeat`,
        method: "POST",
        body: JSON.stringify({
          hostname: "pc-net",
          agents: ["grok"],
          capabilities: [],
          network: { status: "timeout", observedAt: Date.now(), connections: [], error: "timeout" },
        }),
        headers: deviceHdr,
        ...pin,
      });
      assert.equal(hb.status, 200);
      const st = await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin });
      const state = JSON.parse(st.body) as {
        events: Array<Record<string, unknown>>;
        devices: Array<Record<string, unknown>>;
        networkHistory: unknown[];
      };
      const row = state.events.find((e) => e.id === "evt-net");
      assert.ok(row);
      assert.equal(JSON.stringify(row).includes(sig), false);
      assert.ok(Array.isArray(row!.endpoints));
      assert.equal((row!.endpoints as Array<{ host: string }>)[0]?.host, "files.example.test");
      assert.equal(typeof row!.requestHash, "string");
      assert.equal(typeof row!.policyVersion, "number");
      const mapped = mapEvent(row);
      assert.equal(mapped?.endpoints?.[0]?.observation, "declared");
      const net = state.devices[0]?.network as { status?: string; connections?: unknown[] };
      assert.equal(net.status, "timeout");
      assert.equal(net.connections?.length, 0);
      assert.ok(Array.isArray(state.networkHistory));
    } finally {
      await srv.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
