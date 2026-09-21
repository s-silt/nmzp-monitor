import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import http from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { pinnedHttps } from "./https-client.ts";
import {
  assertLanViewerBind,
  ipInAllowedCidrs,
  isPrivateOrLoopbackCidr,
  parseCidr,
  parseViewerFlags,
  projectViewerExport,
  projectViewerState,
  sourceIpv4,
  startLanViewer,
  viewerFetchSiteOk,
  VIEWER_HIDDEN_RULE,
} from "./lan-viewer.ts";
import { startServer } from "./serve.ts";
import { generateNmzpCert } from "./tls.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "nmzp.mjs");
const SECRET_MATCH = "LANVIEW_SECRET_MATCH_9f3a";
const SECRET_REPL = "LANVIEW_SECRET_REPL_9f3a";
const RAW_INPUT = "RAW_TOOL_INPUT_SHOULD_NOT_LEAK";
const TOKEN_HASH = "SHOULD_NOT_LEAK_TOKEN_HASH";

async function tmp() {
  return mkdtemp(join(tmpdir(), "nmzp-viewer-"));
}

async function linkOutsideUi(uiDir: string, outsideFile: string): Promise<string | null> {
  const leak = join(uiDir, "leak.txt");
  try {
    await symlink(outsideFile, leak, "file");
    return "/leak.txt";
  } catch {
    /* file symlink may need elevation */
  }
  const outsideDir = join(dirname(outsideFile), "outside-ui");
  await mkdir(outsideDir, { recursive: true });
  await writeFile(join(outsideDir, "secret.txt"), "LEAK_OUTSIDE_UI");
  const linkDir = join(uiDir, "out");
  try {
    await symlink(outsideDir, linkDir, "junction");
    return "/out/secret.txt";
  } catch {
    try {
      await symlink(outsideDir, linkDir, "dir");
      return "/out/secret.txt";
    } catch {
      return null;
    }
  }
}

function spawnCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ stdout, stderr, code: 1 });
    }, 20_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

function rawReq(opts: {
  port: number;
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: opts.port,
        path: opts.path,
        method: opts.method ?? "GET",
        headers: { connection: "close", ...opts.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function assertSec(headers: http.IncomingHttpHeaders | Headers) {
  const get = (k: string) =>
    headers instanceof Headers ? headers.get(k) : Array.isArray(headers[k]) ? headers[k]!.join(",") : (headers[k] ?? "");
  assert.match(String(get("cache-control")), /no-store/i);
  assert.match(String(get("x-content-type-options")), /nosniff/i);
  const xfo = String(get("x-frame-options"));
  const csp = String(get("content-security-policy"));
  assert.ok(/deny/i.test(xfo) || /frame-ancestors\s+'none'/i.test(csp));
  assert.equal(get("access-control-allow-origin") || "", "");
}

function sampleState(): Record<string, unknown> {
  return {
    access: "admin",
    serverTime: 1,
    policyVersion: 3,
    mode: "enforcing",
    stopped: false,
    customRules: [
      {
        id: "p_secret",
        enabled: true,
        mode: "replace",
        match: SECRET_MATCH,
        kind: "emp_id",
        replaceWith: SECRET_REPL,
        extra: "RULE_EXTRA",
      },
    ],
    devices: [
      {
        id: "dev_1",
        hostname: "pc",
        ip: "10.0.0.8",
        user: "u",
        os: "linux",
        lastSeen: 1,
        attachedAt: 1,
        status: "online",
        tokenHash: TOKEN_HASH,
        extraSecret: "DEVICE_EXTRA",
        capabilities: [
          { id: "hook_grok", supported: true, active: true, token: "CAP_TOKEN" },
          { id: "snapshot", supported: true, active: false },
        ],
        snapshotGuard: {
          supported: true,
          active: true,
          managed: true,
          targetPresent: true,
          writeBlocked: true,
          existingArchiveCoverage: "protected",
          lastVerified: 42,
          sddl: "O:BAG:SYD:(A;;GA;;;BA)",
          path: "C:\\\\Users\\\\x\\\\.zcode\\\\v2\\\\checkpoints",
        },
      },
    ],
    events: [
      {
        id: "evt-1",
        ts: 1,
        machineId: "dev_1",
        agent: "grok",
        sessionId: "s",
        layer: "app_pre",
        tool: "Bash",
        input: RAW_INPUT,
        requestHash: "abc",
        evaluation: "block",
        redacted: "redacted-line",
        risk: "high",
        decision: "block",
        category: "shell",
        ruleId: "r1",
        enforcement: "blocked",
        tokens: 99,
        hash: "EVT_HASH",
      },
    ],
    capabilities: {
      https: { supported: true, active: true },
      snapshot: { supported: true, active: false },
    },
    internalConfig: { hash: "NOPE", raw: RAW_INPUT },
  };
}

function sampleExport(): Record<string, unknown> {
  return {
    version: 1,
    exportedAt: 2,
    crossBorder: false,
    categories: ["agent_events", "machine_inventory", "custom_rules"],
    events: [{ id: "evt-1", ts: 1, machineId: "dev_1", agent: "grok", tool: "Bash", redacted: "r", input: RAW_INPUT }],
    hops: [{ ts: 1, dest: "x", raw: RAW_INPUT }],
    machines: [
      {
        id: "dev_1",
        hostname: "pc",
        ip: "10.0.0.8",
        os: "linux",
        status: "online",
        tokenHash: TOKEN_HASH,
        snapshotGuard: {
          supported: true,
          active: false,
          managed: false,
          targetPresent: true,
          writeBlocked: false,
          existingArchiveCoverage: "none",
          lastVerified: 7,
          sddl: "O:BAG:SYD:(A;;GA;;;BA)",
        },
      },
    ],
    rules: [{ id: "p_secret", enabled: true, mode: "replace", match: SECRET_MATCH, kind: "emp_id", replaceWith: SECRET_REPL }],
    dump: "ADMIN_ONLY_DUMP",
  };
}

async function mockCore(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; pin: { caPem: string; fingerprintSha256: string }; close: () => Promise<void> }> {
  const tls = generateNmzpCert(["127.0.0.1"]);
  const srv = createHttpsServer({ key: tls.keyPem, cert: tls.certPem }, handler);
  await new Promise<void>((resolve, reject) => {
    srv.listen(0, "127.0.0.1", () => resolve());
    srv.on("error", reject);
  });
  const addr = srv.address();
  if (!addr || typeof addr === "string") throw new Error("listen failed");
  return {
    url: `https://127.0.0.1:${addr.port}`,
    pin: { caPem: tls.certPem, fingerprintSha256: tls.fingerprintSha256 },
    close: () => new Promise((resolve, reject) => srv.close((e) => (e ? reject(e) : resolve()))),
  };
}

describe("lan viewer bind and projection", () => {
  it("accepts RFC1918/loopback host+CIDR and rejects public, 0.0.0.0, and 0/0", () => {
    assertLanViewerBind("127.0.0.1", ["127.0.0.0/8"]);
    assertLanViewerBind("10.1.2.3", ["10.0.0.0/8"]);
    assertLanViewerBind("192.168.1.10", ["192.168.0.0/16"]);
    assertLanViewerBind("172.16.0.1", ["172.16.0.0/12"]);
    assert.throws(() => assertLanViewerBind("0.0.0.0", ["127.0.0.0/8"]), /private IPv4/);
    assert.throws(() => assertLanViewerBind("8.8.8.8", ["127.0.0.0/8"]), /private IPv4/);
    assert.throws(() => assertLanViewerBind("1.1.1.1", ["10.0.0.0/8"]), /private IPv4/);
    assert.throws(() => assertLanViewerBind("127.0.0.1", ["0.0.0.0/0"]), /CIDR/);
    assert.throws(() => assertLanViewerBind("127.0.0.1", ["8.8.8.0/24"]), /CIDR/);
    assert.throws(() => assertLanViewerBind("127.0.0.1", ["10.0.0.0/7"]), /CIDR/);
    assert.throws(() => assertLanViewerBind("127.0.0.1", []), /allowedCidrs/);
    assert.ok(parseCidr("192.168.0.0/16"));
    assert.ok(parseCidr("172.16.0.0/12"));
    assert.ok(parseCidr("192.168.7.0/24"));
    assert.equal(isPrivateOrLoopbackCidr("192.168.7.0/24"), true);
    assertLanViewerBind("192.168.7.10", ["192.168.7.0/24"]);
    assert.equal(ipInAllowedCidrs("192.168.7.10", ["192.168.7.0/24"]), true);
    assert.equal(ipInAllowedCidrs("192.168.7.0", ["192.168.7.0/24"]), true);
    assert.equal(ipInAllowedCidrs("192.168.7.255", ["192.168.7.0/24"]), true);
    assert.equal(ipInAllowedCidrs("192.168.8.1", ["192.168.7.0/24"]), false);
    assert.equal(isPrivateOrLoopbackCidr("192.168.1.1/24"), false);
    assert.equal(isPrivateOrLoopbackCidr("192.168.1.0/24"), true);
    assert.equal(ipInAllowedCidrs("10.9.1.2", ["10.0.0.0/8"]), true);
    assert.equal(ipInAllowedCidrs("11.0.0.1", ["10.0.0.0/8"]), false);
    assert.equal(sourceIpv4("::ffff:192.168.1.5"), "192.168.1.5");
    assert.equal(ipInAllowedCidrs(sourceIpv4("::ffff:192.168.1.5") ?? "", ["192.168.0.0/16"]), true);
    assert.equal(sourceIpv4("::1"), null);
  });

  it("parseViewerFlags reads repeated CIDR flags and env fallback", () => {
    const a = parseViewerFlags(["--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8"]);
    assert.equal(a.host, "127.0.0.1");
    assert.equal(a.port, 0);
    assert.deepEqual(a.allowedCidrs, ["127.0.0.0/8"]);
    const b = parseViewerFlags(["--host", "10.0.0.1", "--allow-cidr", "10.0.0.0/8", "--allow-cidr", "192.168.0.0/16"]);
    assert.deepEqual(b.allowedCidrs, ["10.0.0.0/8", "192.168.0.0/16"]);
    const c = parseViewerFlags([], {
      NMZP_VIEWER_HOST: "127.0.0.1",
      NMZP_VIEWER_PORT: "8789",
      NMZP_VIEWER_ALLOW_CIDR: "127.0.0.0/8,10.0.0.0/8",
    });
    assert.equal(c.port, 8789);
    assert.deepEqual(c.allowedCidrs, ["127.0.0.0/8", "10.0.0.0/8"]);
    assert.throws(() => parseViewerFlags(["--host", "8.8.8.8", "--allow-cidr", "127.0.0.0/8"]), /private IPv4/);
  });

  it("projects known public fields and hides rule secrets / input / hashes", () => {
    const st = projectViewerState(sampleState());
    assert.equal(st.ok, true);
    if (!st.ok) return;
    assert.equal(st.state.access, "viewer");
    const json = JSON.stringify(st.state);
    assert.equal(json.includes(SECRET_MATCH), false);
    assert.equal(json.includes(SECRET_REPL), false);
    assert.equal(json.includes(RAW_INPUT), false);
    assert.equal(json.includes(TOKEN_HASH), false);
    assert.equal(json.includes("DEVICE_EXTRA"), false);
    assert.equal(json.includes("ADMIN_ONLY"), false);
    assert.equal(json.includes("internalConfig"), false);
    assert.equal(json.includes("evaluation"), false);
    assert.equal(json.includes("CAP_TOKEN"), false);
    const caps = st.state.capabilities as Record<string, { supported?: boolean; active?: boolean }>;
    assert.equal(caps.https?.supported, true);
    assert.equal(caps.snapshot?.supported, true);
    assert.equal(caps.snapshot?.active, false);
    const rules = st.state.customRules as Array<Record<string, unknown>>;
    assert.equal(rules[0]?.match, VIEWER_HIDDEN_RULE);
    assert.equal(rules[0]?.replaceWith, VIEWER_HIDDEN_RULE);
    assert.equal(rules[0]?.id, "p_secret");
    assert.equal(rules[0]?.enabled, true);
    const ev = (st.state.events as Array<Record<string, unknown>>)[0]!;
    assert.equal(ev.redacted, "redacted-line");
    assert.equal("input" in ev, false);
    assert.equal(ev.requestHash, "abc");
    assert.equal("evaluation" in ev, false);
    const dev = (st.state.devices as Array<Record<string, unknown>>)[0]!;
    assert.equal("tokenHash" in dev, false);
    const dCaps = dev.capabilities as Array<{ id: string }>;
    assert.ok(dCaps.some((c) => c.id === "snapshot"));
    assert.ok(dCaps.some((c) => c.id === "hook_grok"));
    const sg = dev.snapshotGuard as Record<string, unknown>;
    assert.equal(sg.existingArchiveCoverage, "protected");
    assert.equal(sg.lastVerified, 42);
    assert.equal("sddl" in sg, false);
    assert.equal("path" in sg, false);
    assert.equal(json.includes("O:BAG"), false);
    assert.equal(st.state.serverTime, 1);
    assert.equal(projectViewerState({ ok: true }).ok, false);
    assert.equal(projectViewerState({ ...sampleState(), serverTime: undefined }).ok, false);
    const nestedRedacted = sampleState();
    (nestedRedacted.events as Array<Record<string, unknown>>)[0]!.redacted = { raw: RAW_INPUT, token: TOKEN_HASH };
    assert.equal(projectViewerState(nestedRedacted).ok, false);
    const nestedCap = sampleState();
    (nestedCap.devices as Array<Record<string, unknown>>)[0]!.capabilities = [
      { id: "hook_grok", supported: true, active: true, error: { token: TOKEN_HASH, raw: RAW_INPUT } },
    ];
    assert.equal(projectViewerState(nestedCap).ok, false);
    assert.equal(viewerFetchSiteOk("cross-site"), false);
    assert.equal(viewerFetchSiteOk("Cross-Site"), false);
    assert.equal(viewerFetchSiteOk(undefined), true);
    assert.equal(viewerFetchSiteOk("same-origin"), true);
    assert.equal(viewerFetchSiteOk("none"), true);
    const ex = projectViewerExport(sampleExport());
    assert.equal(ex.ok, true);
    if (!ex.ok) return;
    const exj = JSON.stringify(ex.bundle);
    assert.equal(ex.bundle.access, "viewer");
    assert.equal(ex.bundle.exportedAt, 2);
    assert.equal(ex.bundle.crossBorder, false);
    assert.equal(exj.includes(SECRET_MATCH), false);
    assert.equal(exj.includes(RAW_INPUT), false);
    assert.equal(exj.includes("ADMIN_ONLY_DUMP"), false);
    assert.equal(exj.includes(TOKEN_HASH), false);
    const trueBorder = projectViewerExport({ ...sampleExport(), crossBorder: true, exportedAt: 99 });
    assert.equal(trueBorder.ok, true);
    if (trueBorder.ok) {
      assert.equal(trueBorder.bundle.crossBorder, true);
      assert.equal(trueBorder.bundle.exportedAt, 99);
    }
    assert.equal(projectViewerExport({ ...sampleExport(), exportedAt: undefined }).ok, false);
    assert.equal(projectViewerExport({ ...sampleExport(), crossBorder: undefined }).ok, false);
    const nestedHop = sampleExport();
    (nestedHop.hops as Array<Record<string, unknown>>)[0]!.dest = { raw: RAW_INPUT };
    assert.equal(projectViewerExport(nestedHop).ok, false);
    const exSg = (ex.bundle.machines as Array<Record<string, unknown>>)[0]!.snapshotGuard as Record<string, unknown>;
    assert.equal(exSg.lastVerified, 7);
    assert.equal("sddl" in exSg, false);
    const badLv = sampleState();
    (badLv.devices as Array<Record<string, unknown>>)[0]!.snapshotGuard = {
      supported: true,
      active: false,
      managed: false,
      targetPresent: true,
      writeBlocked: false,
      existingArchiveCoverage: "none",
      lastVerified: -1,
    };
    assert.equal(projectViewerState(badLv).ok, false);
  });

  it("keeps endpoints, requestHash, device.network, and networkHistory", () => {
    const now = 1_700_000_000_000;
    const raw = sampleState();
    (raw.events as Array<Record<string, unknown>>)[0]!.endpoints = [
      { host: "bucket.oss-cn-hangzhou.aliyuncs.com", scheme: "https", source: "tool_command", observation: "declared" },
    ];
    (raw.events as Array<Record<string, unknown>>)[0]!.requestHash = "ab".repeat(32);
    (raw.devices as Array<Record<string, unknown>>)[0]!.network = {
      status: "ok",
      observedAt: now,
      receivedAt: now + 50,
      connections: [],
    };
    raw.networkHistory = [
      {
        id: "net_abc123",
        machineId: "dev_1",
        agent: "grok",
        pid: 9,
        ppid: 1,
        processStartedAt: now,
        bin: "grok.exe",
        remoteIp: "203.0.113.7",
        remotePort: 443,
        localIp: "10.0.0.2",
        localPort: 40000,
        state: "Established",
        role: "egress",
        direction: "unknown",
        firstSeen: now,
        lastSeen: now,
      },
    ];
    raw.timestampOffset = "+08:00";
    raw.timezone = "Asia/Shanghai";
    const st = projectViewerState(raw);
    assert.equal(st.ok, true);
    if (!st.ok) return;
    const ev = (st.state.events as Array<Record<string, unknown>>)[0]!;
    assert.equal((ev.endpoints as Array<{ host: string }>)[0]?.host, "bucket.oss-cn-hangzhou.aliyuncs.com");
    assert.equal(ev.requestHash, "ab".repeat(32));
    const net = (st.state.devices as Array<Record<string, unknown>>)[0]!.network as { receivedAt?: number; status?: string };
    assert.equal(net.status, "ok");
    assert.equal(net.receivedAt, now + 50);
    const hist = st.state.networkHistory as Array<{ remoteIp: string }>;
    assert.equal(hist[0]?.remoteIp, "203.0.113.7");
    assert.equal(st.state.timestampOffset, "+08:00");
    const ex = projectViewerExport({
      version: 1,
      exportedAt: 2,
      crossBorder: false,
      events: raw.events,
      machines: (raw.devices as Array<Record<string, unknown>>).map(({ id, hostname, ip, os, status, network }) => ({ id, hostname, ip, os, status, network })), 
      hops: [],
      rules: [],
      networkHistory: raw.networkHistory,
      timestampOffset: "+08:00",
      timezone: "Asia/Shanghai",
    });
    assert.equal(ex.ok, true);
    if (!ex.ok) return;
    assert.equal((ex.bundle.networkHistory as Array<{ id: string }>)[0]?.id, "net_abc123");
    assert.equal(ex.bundle.timestampOffset, "+08:00");
  });
});

describe("lan viewer HTTP", () => {
  it("allows state/static/export, rejects writes and leaks, honors CIDR/Host/Origin", { timeout: 30_000 }, async () => {
    const dir = await tmp();
    const ui = join(dir, "ui");
    await mkdir(join(ui, "assets"), { recursive: true });
    await writeFile(join(ui, "index.html"), "<!doctype html><html><body>VIEWER_UI_MARK</body></html>");
    await writeFile(join(ui, "assets", "app.js"), "console.log('viewer-asset')");
    await writeFile(join(dir, "secret.txt"), "LEAK_OUTSIDE_UI");
    const srv = await startServer({ dataDir: join(dir, "data"), host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
    const admin = { authorization: `Bearer ${srv.adminToken}`, "content-type": "application/json" };
    const viewer = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: ui,
      ctUrl: srv.url,
      caPem: srv.tls.certPem,
      fingerprintSha256: srv.tls.fingerprintSha256,
      adminToken: srv.adminToken,
    });
    try {
      const ticketRes = await pinnedHttps({ url: `${srv.url}/api/v1/ticket`, method: "POST", headers: admin, ...pin });
      const ticket = (JSON.parse(ticketRes.body) as { ticket: string }).ticket;
      const join = await pinnedHttps({
        url: `${srv.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify({ ticket, hostname: "pc1", os: "win32", user: "u" }),
        headers: { "content-type": "application/json" },
        ...pin,
      });
      const j = JSON.parse(join.body) as { deviceId: string; deviceToken: string };
      const device = { authorization: `Bearer ${j.deviceToken}`, "content-type": "application/json" };
      await pinnedHttps({
        url: `${srv.url}/api/v1/evaluate`,
        method: "POST",
        body: JSON.stringify({
          eventId: "evt-lan",
          sessionId: "sess",
          agent: "grok",
          tool_name: "run_terminal_command",
          tool_input: { command: `echo ${RAW_INPUT}` },
        }),
        headers: device,
        ...pin,
      });
      const adminState = JSON.parse(
        (await pinnedHttps({ url: `${srv.url}/api/v1/state`, headers: admin, ...pin })).body,
      ) as { access: string; policyVersion: number; customRules: unknown[] };
      assert.equal(adminState.access, "admin");
      const put = await pinnedHttps({
        url: `${srv.url}/api/v1/policy`,
        method: "PUT",
        body: JSON.stringify({
          expectedVersion: adminState.policyVersion,
          customRules: [
            {
              id: "r_lan",
              enabled: true,
              mode: "replace",
              match: SECRET_MATCH,
              kind: "emp_id",
              replaceWith: SECRET_REPL,
            },
          ],
        }),
        headers: admin,
        ...pin,
      });
      assert.equal(put.status, 200);

      const health = await fetch(`${viewer.url}/health`);
      assert.equal(health.status, 200);
      assertSec(health.headers);
      const healthBody = (await health.json()) as { ok: boolean; name: string };
      assert.equal(healthBody.ok, true);
      assert.equal(healthBody.name, "nmzp-viewer");

      const headHealth = await rawReq({
        port: viewer.port,
        path: "/health",
        method: "HEAD",
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.equal(headHealth.status, 200);
      assert.equal(headHealth.body, "");
      assertSec(headHealth.headers);

      const stRes = await fetch(`${viewer.url}/api/v1/state`);
      assert.equal(stRes.status, 200);
      assertSec(stRes.headers);
      const stText = await stRes.text();
      const st = JSON.parse(stText) as {
        access: string;
        devices: Array<Record<string, unknown>>;
        events: Array<Record<string, unknown>>;
        customRules: Array<Record<string, unknown>>;
      };
      assert.equal(st.access, "viewer");
      assert.ok(st.devices.some((d) => d.id === j.deviceId));
      assert.ok(st.events.some((e) => e.id === "evt-lan"));
      assert.ok(st.customRules.some((r) => r.id === "r_lan" && r.match === VIEWER_HIDDEN_RULE));
      assert.equal(stText.includes(SECRET_MATCH), false);
      assert.equal(stText.includes(SECRET_REPL), false);
      assert.equal(stText.includes(srv.adminToken), false);
      assert.equal(stText.includes(j.deviceToken), false);
      assert.equal(stText.includes("tokenHash"), false);
      assert.ok(st.events.every((e) => !("input" in e) && !("evaluation" in e)));
      assert.ok(st.events.every((e) => typeof e.redacted === "string"));

      const exRes = await fetch(`${viewer.url}/api/v1/export`);
      assert.equal(exRes.status, 200);
      const exText = await exRes.text();
      const ex = JSON.parse(exText) as { access: string; rules: Array<Record<string, unknown>> };
      assert.equal(ex.access, "viewer");
      assert.ok(ex.rules.some((r) => r.match === VIEWER_HIDDEN_RULE));
      assert.equal(exText.includes(SECRET_MATCH), false);
      assert.equal(exText.includes(srv.adminToken), false);

      const page = await fetch(`${viewer.url}/`);
      assert.equal(page.status, 200);
      assert.match(page.headers.get("content-type") ?? "", /text\/html/);
      assert.match(await page.text(), /VIEWER_UI_MARK/);
      const spa = await fetch(`${viewer.url}/audit`);
      assert.equal(spa.status, 200);
      assert.match(await spa.text(), /VIEWER_UI_MARK/);
      const js = await fetch(`${viewer.url}/assets/app.js`);
      assert.equal(js.status, 200);
      assert.match(js.headers.get("content-type") ?? "", /javascript/);
      const headJs = await rawReq({
        port: viewer.port,
        path: "/assets/app.js",
        method: "HEAD",
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.equal(headJs.status, 200);
      assert.equal(headJs.body, "");

      const unknownApi = await fetch(`${viewer.url}/api/v1/nope`);
      assert.equal(unknownApi.status, 404);
      const unknownTxt = await unknownApi.text();
      assert.equal(unknownTxt.includes("VIEWER_UI_MARK"), false);
      assert.equal((JSON.parse(unknownTxt) as { error: string }).error, "not_found");

      const writes: Array<[string, string]> = [
        ["POST", "/api/v1/session"],
        ["PUT", "/api/v1/policy"],
        ["DELETE", "/api/v1/events"],
        ["POST", "/api/v1/evaluate"],
        ["POST", "/api/v1/join"],
        ["POST", "/api/v1/receipt"],
        ["POST", "/api/v1/ticket"],
        ["POST", "/api/v1/heartbeat"],
        ["POST", "/api/v1/state"],
        ["PUT", "/api/v1/export"],
        ["PATCH", "/api/v1/state"],
        ["OPTIONS", "/api/v1/state"],
      ];
      for (const [method, path] of writes) {
        const withBody = method === "POST" || method === "PUT" || method === "PATCH";
        const r = await rawReq({
          port: viewer.port,
          path,
          method,
          headers: {
            host: `127.0.0.1:${viewer.port}`,
            authorization: `Bearer ${srv.adminToken}`,
            ...(withBody ? { "content-type": "application/json", "x-http-method-override": "GET" } : {}),
            connection: "close",
          },
          body: withBody ? JSON.stringify({ token: srv.adminToken, expectedVersion: 1, stopped: true }) : undefined,
        });
        assert.ok(r.status === 405 || r.status === 403 || r.status === 404, `${method} ${path} -> ${r.status} ${r.body}`);
        assert.equal(r.body.includes(srv.adminToken), false);
        assert.equal(r.body.includes("VIEWER_UI_MARK"), false);
      }
      for (const path of ["/api/v1/session", "/api/v1/policy", "/api/v1/events", "/api/v1/evaluate", "/api/v1/join", "/api/v1/receipt"]) {
        const r = await fetch(`${viewer.url}${path}`, { headers: { authorization: `Bearer ${srv.adminToken}` } });
        assert.equal(r.status, 404, `GET ${path}`);
      }

      const overrideGet = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        method: "GET",
        headers: {
          host: `127.0.0.1:${viewer.port}`,
          "x-http-method-override": "DELETE",
          "x-method-override": "PUT",
          "x-http-method": "POST",
        },
      });
      assert.equal(overrideGet.status, 200);
      const overrideBody = JSON.parse(overrideGet.body) as { access?: string };
      assert.equal(overrideBody.access, "viewer");
      const overridePost = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        method: "POST",
        headers: {
          host: `127.0.0.1:${viewer.port}`,
          "x-http-method-override": "GET",
          "content-type": "application/json",
        },
        body: JSON.stringify({ token: srv.adminToken }),
      });
      assert.equal(overridePost.status, 405);

      const crossSite = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        headers: { host: `127.0.0.1:${viewer.port}`, "sec-fetch-site": "cross-site" },
      });
      assert.equal(crossSite.status, 403);
      const crossSiteCase = await rawReq({
        port: viewer.port,
        path: "/health",
        headers: { host: `127.0.0.1:${viewer.port}`, "sec-fetch-site": "Cross-Site" },
      });
      assert.equal(crossSiteCase.status, 403);

      const rebound = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        headers: { host: "evil.example" },
      });
      assert.equal(rebound.status, 403);
      const badOrigin = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        headers: { host: `127.0.0.1:${viewer.port}`, origin: "http://evil.example" },
      });
      assert.equal(badOrigin.status, 403);
      const xff = await rawReq({
        port: viewer.port,
        path: "/api/v1/state",
        headers: { host: `127.0.0.1:${viewer.port}`, "x-forwarded-for": "8.8.8.8" },
      });
      assert.equal(xff.status, 200);

      const trav = await rawReq({
        port: viewer.port,
        path: "/%2e%2e/secret.txt",
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.ok(trav.status === 400 || trav.status === 403 || trav.status === 404);
      assert.equal(trav.body.includes("LEAK_OUTSIDE_UI"), false);
      const trav2 = await rawReq({
        port: viewer.port,
        path: "/../secret.txt",
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.equal(trav2.body.includes("LEAK_OUTSIDE_UI"), false);
      const badEnc = await rawReq({
        port: viewer.port,
        path: "/%zz",
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.ok(badEnc.status === 400 || badEnc.status === 404);
      const serveJson = await fetch(`${viewer.url}/serve.json`);
      assert.equal(serveJson.status, 404);
      assert.equal((await serveJson.text()).includes("fingerprintSha256"), false);

      const lanCidr = await startLanViewer({
        host: "127.0.0.1",
        allowedCidrs: ["192.168.7.0/24"],
        port: 0,
        uiDir: null,
        ctUrl: srv.url,
        caPem: srv.tls.certPem,
        fingerprintSha256: srv.tls.fingerprintSha256,
        adminToken: srv.adminToken,
      });
      try {
        const offSeg = await fetch(`http://127.0.0.1:${lanCidr.port}/api/v1/state`);
        assert.equal(offSeg.status, 403);
      } finally {
        await lanCidr.close();
      }

      const denied = await startLanViewer({
        host: "127.0.0.1",
        allowedCidrs: ["10.0.0.0/8"],
        port: 0,
        uiDir: null,
        ctUrl: srv.url,
        caPem: srv.tls.certPem,
        fingerprintSha256: srv.tls.fingerprintSha256,
        adminToken: srv.adminToken,
      });
      try {
        const blocked = await fetch(`http://127.0.0.1:${denied.port}/api/v1/state`);
        assert.equal(blocked.status, 403);
        const spoof = await rawReq({
          port: denied.port,
          path: "/api/v1/state",
          headers: { host: `127.0.0.1:${denied.port}`, "x-forwarded-for": "10.0.0.1" },
        });
        assert.equal(spoof.status, 403);
      } finally {
        await denied.close();
      }
    } finally {
      await viewer.close().catch(() => undefined);
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not forward caller headers/cookies and does not empty-succeed on bad upstream", { timeout: 20_000 }, async () => {
    let lastUrl = "";
    let lastHeaders: http.IncomingHttpHeaders = {};
    let hits = 0;
    const core = await mockCore((req, res) => {
      hits += 1;
      lastUrl = req.url ?? "";
      lastHeaders = req.headers;
      const url = req.url ?? "";
      if (url.startsWith("/api/v1/state")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(sampleState()));
        return;
      }
      if (url.startsWith("/api/v1/export")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{not json");
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false }));
    });
    const viewer = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: core.url,
      ...core.pin,
      adminToken: "BACKEND_TOKEN_VALUE",
    });
    try {
      const st = await fetch(`${viewer.url}/api/v1/state?url=/api/v1/evaluate`, {
        headers: {
          authorization: "Bearer USER_TOKEN_VALUE",
          cookie: "nmzp_admin=USER_COOKIE",
          "x-forwarded-for": "8.8.8.8",
        },
      });
      assert.equal(st.status, 200);
      assert.equal(lastUrl, "/api/v1/state");
      assert.equal(lastHeaders.authorization, "Bearer BACKEND_TOKEN_VALUE");
      assert.equal(lastHeaders.cookie, undefined);
      assert.equal(String(lastHeaders["x-forwarded-for"] ?? ""), "");
      const body = await st.text();
      assert.equal(body.includes("USER_TOKEN_VALUE"), false);
      assert.equal(body.includes("BACKEND_TOKEN_VALUE"), false);
      assert.equal(body.includes(SECRET_MATCH), false);

      const badEx = await fetch(`${viewer.url}/api/v1/export`);
      assert.equal(badEx.status, 502);
      const badBody = JSON.parse(await badEx.text()) as { ok: boolean; error: string };
      assert.equal(badBody.ok, false);
      assert.ok(badBody.error);
      assert.equal("devices" in badBody, false);

      const before = hits;
      const post = await fetch(`${viewer.url}/api/v1/evaluate`, {
        method: "POST",
        headers: { authorization: "Bearer BACKEND_TOKEN_VALUE", "content-type": "application/json" },
        body: JSON.stringify({ tool_input: { command: RAW_INPUT } }),
      });
      assert.equal(post.status, 405);
      assert.equal(hits, before);
    } finally {
      await viewer.close().catch(() => undefined);
      await core.close().catch(() => undefined);
    }
  });

  it("pin mismatch does not send credentials or relax TLS; down/bad contract is 502/503", { timeout: 20_000 }, async () => {
    const tls = generateNmzpCert(["127.0.0.1"]);
    let sawReq = false;
    let sawAuth = false;
    const core = createHttpsServer({ key: tls.keyPem, cert: tls.certPem }, (req, res) => {
      sawReq = true;
      if (req.headers.authorization) sawAuth = true;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(sampleState()));
    });
    await new Promise<void>((resolve, reject) => {
      core.listen(0, "127.0.0.1", () => resolve());
      core.on("error", reject);
    });
    const addr = core.address();
    if (!addr || typeof addr === "string") throw new Error("listen failed");
    const url = `https://127.0.0.1:${addr.port}`;
    const viewer = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: url,
      caPem: tls.certPem,
      fingerprintSha256: "0".repeat(64),
      adminToken: "PINFAIL_TOKEN_SHOULD_NOT_BE_SENT",
    });
    try {
      const res = await fetch(`${viewer.url}/api/v1/state`);
      assert.ok(res.status === 502 || res.status === 503);
      const text = await res.text();
      assert.equal(text.includes("PINFAIL_TOKEN_SHOULD_NOT_BE_SENT"), false);
      const parsed = JSON.parse(text) as { ok: boolean; error?: string; devices?: unknown };
      assert.equal(parsed.ok, false);
      assert.ok(parsed.error);
      assert.equal(parsed.devices, undefined);
      assert.equal(sawReq, false);
      assert.equal(sawAuth, false);
      const src = readFileSync(join(coreDir, "lan-viewer.ts"), "utf8");
      assert.equal(/rejectUnauthorized\s*:\s*false/.test(src), false);
    } finally {
      await viewer.close().catch(() => undefined);
      await new Promise<void>((resolve, reject) => core.close((e) => (e ? reject(e) : resolve())));
    }

    const bad = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, devices: [], events: [] }));
    });
    const v2 = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: bad.url,
      ...bad.pin,
      adminToken: "t",
    });
    try {
      const res = await fetch(`${v2.url}/api/v1/state`);
      assert.equal(res.status, 502);
      const parsed = JSON.parse(await res.text()) as { ok: boolean; events?: unknown };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.events, undefined);
    } finally {
      await v2.close().catch(() => undefined);
      await bad.close().catch(() => undefined);
    }

    const v3 = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: "https://127.0.0.1:1",
      caPem: tls.certPem,
      fingerprintSha256: tls.fingerprintSha256,
      adminToken: "t",
      timeoutMs: 400,
    });
    try {
      const res = await fetch(`${v3.url}/api/v1/state`);
      assert.ok(res.status === 502 || res.status === 503);
      const parsed = JSON.parse(await res.text()) as { ok: boolean };
      assert.equal(parsed.ok, false);
    } finally {
      await v3.close().catch(() => undefined);
    }
  });

  it("rejects nested raw/token in known fields, missing timestamps, and preserves crossBorder", { timeout: 20_000 }, async () => {
    const nested = sampleState();
    (nested.events as Array<Record<string, unknown>>)[0]!.redacted = { raw: RAW_INPUT, token: TOKEN_HASH };
    const coreNested = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(nested));
    });
    const vNested = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: coreNested.url,
      ...coreNested.pin,
      adminToken: "t",
    });
    try {
      const res = await fetch(`${vNested.url}/api/v1/state`);
      assert.equal(res.status, 502);
      const body = await res.text();
      assert.equal(body.includes(RAW_INPUT), false);
      assert.equal(body.includes(TOKEN_HASH), false);
      const parsed = JSON.parse(body) as { ok: boolean; events?: unknown };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.events, undefined);
    } finally {
      await vNested.close().catch(() => undefined);
      await coreNested.close().catch(() => undefined);
    }

    const noTime = sampleState();
    delete noTime.serverTime;
    const coreTime = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(noTime));
    });
    const vTime = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: coreTime.url,
      ...coreTime.pin,
      adminToken: "t",
    });
    try {
      const res = await fetch(`${vTime.url}/api/v1/state`);
      assert.equal(res.status, 502);
    } finally {
      await vTime.close().catch(() => undefined);
      await coreTime.close().catch(() => undefined);
    }

    const capNested = sampleState();
    (capNested.devices as Array<Record<string, unknown>>)[0]!.capabilities = [
      { id: "snapshot", supported: true, active: true, error: { token: TOKEN_HASH } },
    ];
    const coreCap = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(capNested));
    });
    const vCap = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: coreCap.url,
      ...coreCap.pin,
      adminToken: "t",
    });
    try {
      const res = await fetch(`${vCap.url}/api/v1/state`);
      assert.equal(res.status, 502);
      assert.equal((await res.text()).includes(TOKEN_HASH), false);
    } finally {
      await vCap.close().catch(() => undefined);
      await coreCap.close().catch(() => undefined);
    }

    const coreEx = await mockCore((req, res) => {
      const url = req.url ?? "";
      res.writeHead(200, { "content-type": "application/json" });
      if (url.startsWith("/api/v1/export")) {
        res.end(JSON.stringify({ ...sampleExport(), crossBorder: true, exportedAt: 42 }));
        return;
      }
      res.end(JSON.stringify(sampleState()));
    });
    const vEx = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: coreEx.url,
      ...coreEx.pin,
      adminToken: "t",
    });
    try {
      const okState = await fetch(`${vEx.url}/api/v1/state`);
      assert.equal(okState.status, 200);
      const st = (await okState.json()) as { serverTime: number; capabilities: Record<string, unknown> };
      assert.equal(st.serverTime, 1);
      assert.ok(st.capabilities.snapshot);
      const ex = await fetch(`${vEx.url}/api/v1/export`);
      assert.equal(ex.status, 200);
      const bundle = (await ex.json()) as { crossBorder: boolean; exportedAt: number };
      assert.equal(bundle.crossBorder, true);
      assert.equal(bundle.exportedAt, 42);
    } finally {
      await vEx.close().catch(() => undefined);
      await coreEx.close().catch(() => undefined);
    }

    const coreMissingEx = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      const { exportedAt: _drop, ...rest } = sampleExport();
      res.end(JSON.stringify(rest));
    });
    const vMissingEx = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: null,
      ctUrl: coreMissingEx.url,
      ...coreMissingEx.pin,
      adminToken: "t",
    });
    try {
      const res = await fetch(`${vMissingEx.url}/api/v1/export`);
      assert.equal(res.status, 502);
      const parsed = JSON.parse(await res.text()) as { ok: boolean; exportedAt?: unknown };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.exportedAt, undefined);
    } finally {
      await vMissingEx.close().catch(() => undefined);
      await coreMissingEx.close().catch(() => undefined);
    }
  });

  it("refuses static symlinks that escape the UI directory", { timeout: 20_000 }, async () => {
    const dir = await tmp();
    const ui = join(dir, "ui");
    await mkdir(join(ui, "assets"), { recursive: true });
    await writeFile(join(ui, "index.html"), "<!doctype html><html><body>VIEWER_UI_MARK</body></html>");
    await writeFile(join(ui, "assets", "app.js"), "console.log(1)");
    await writeFile(join(dir, "secret.txt"), "LEAK_OUTSIDE_UI");
    const leakPath = await linkOutsideUi(ui, join(dir, "secret.txt"));
    assert.ok(leakPath, "need a file symlink or directory junction for this test");
    const core = await mockCore((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(sampleState()));
    });
    const viewer = await startLanViewer({
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      uiDir: ui,
      ctUrl: core.url,
      ...core.pin,
      adminToken: "t",
    });
    try {
      const leak = await rawReq({
        port: viewer.port,
        path: leakPath,
        headers: { host: `127.0.0.1:${viewer.port}` },
      });
      assert.ok(leak.status === 403 || leak.status === 404, `symlink status ${leak.status}`);
      assert.equal(leak.body.includes("LEAK_OUTSIDE_UI"), false);
      const page = await fetch(`${viewer.url}/`);
      assert.equal(page.status, 200);
      assert.match(await page.text(), /VIEWER_UI_MARK/);
    } finally {
      await viewer.close().catch(() => undefined);
      await core.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("lan viewer CLI and unit", () => {
  it("service unit is nmzp, after/requires core, read-only, no inventory IP", () => {
    const unit = readFileSync(join(coreDir, "nmzp-viewer.service"), "utf8");
    assert.match(unit, /^User=nmzp$/m);
    assert.match(unit, /^Group=nmzp$/m);
    assert.match(unit, /^After=nmzp\.service$/m);
    assert.match(unit, /^Requires=nmzp\.service$/m);
    assert.match(unit, /^Restart=/m);
    assert.match(unit, /ReadOnlyPaths=/);
    assert.match(unit, /ProtectSystem=strict/);
    assert.match(unit, /nmzp\.mjs viewer/);
    assert.match(unit, /NMZP_DATA=\/var\/lib\/nmzp/);
    assert.doesNotMatch(unit, /192\.168\.100\.206/);
    assert.doesNotMatch(unit, /0\.0\.0\.0/);
    const readme = readFileSync(join(coreDir, "..", "README.md"), "utf8");
    assert.match(readme, /nmzp viewer/);
    assert.match(readme, /nmzp-viewer\.service/);
    assert.doesNotMatch(readme, /192\.168\.100\.206/);
    assert.doesNotMatch(readme, /gemini\.google|generativelanguage/i);
  });

  it("CLI fails without core and does not write serve.json or print a token", { timeout: 20_000 }, async () => {
    const dir = await tmp();
    try {
      const r = await spawnCli(["viewer", "--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8"], {
        NMZP_DATA: dir,
      });
      assert.notEqual(r.code, 0);
      assert.match(`${r.stdout}\n${r.stderr}`, /not running|live pinned core/i);
      assert.equal(existsSync(join(dir, "serve.json")), false);
      const unique = "TOKEN_SHOULD_NEVER_BE_PRINTED_aabb";
      await writeFile(join(dir, "admin.token"), unique, { mode: 0o600 });
      const r2 = await spawnCli(["viewer", "--host", "127.0.0.1", "--allow-cidr", "127.0.0.0/8"], { NMZP_DATA: dir });
      assert.notEqual(r2.code, 0);
      assert.equal((r2.stdout + r2.stderr).includes(unique), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("CLI viewer starts against a live core and wrong token is not printed", { timeout: 30_000 }, async () => {
    const dir = await tmp();
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", entry, "viewer", "--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8"],
      { env: { ...process.env, NMZP_DATA: dir }, windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    try {
      const url = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`viewer start timeout out=${stdout} err=${stderr}`)), 15_000);
        const check = () => {
          const m = /nmzp viewer (http:\/\/127\.0\.0\.1:\d+)/.exec(stdout);
          if (m) {
            clearTimeout(timer);
            resolve(m[1]!);
          }
        };
        child.stdout.on("data", check);
        child.on("exit", (code) => {
          clearTimeout(timer);
          reject(new Error(`viewer exited ${code} out=${stdout} err=${stderr}`));
        });
        check();
      });
      const health = await fetch(`${url}/health`);
      assert.equal(health.status, 200);
      const st = await fetch(`${url}/api/v1/state`);
      assert.equal(st.status, 200);
      const body = await st.text();
      assert.equal(JSON.parse(body).access, "viewer");
      assert.equal(body.includes(srv.adminToken), false);
      assert.equal(stdout.includes(srv.adminToken), false);
      assert.equal(stderr.includes(srv.adminToken), false);

      child.kill();
      await new Promise((r) => child.once("close", r));

      await writeFile(join(dir, "admin.token"), "WRONG_TOKEN_PRINT_CHECK_ccdd\n", { mode: 0o600 });
      const bad = await spawnCli(["viewer", "--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8"], {
        NMZP_DATA: dir,
      });
      assert.notEqual(bad.code, 0);
      assert.equal((bad.stdout + bad.stderr).includes("WRONG_TOKEN_PRINT_CHECK_ccdd"), false);
    } finally {
      child.kill();
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
