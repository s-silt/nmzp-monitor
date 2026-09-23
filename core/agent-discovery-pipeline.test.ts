import assert from "node:assert/strict";
import { it } from "node:test";
import { mkdtemp, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startServer } from "./serve.ts";
import { startLanViewer } from "./lan-viewer.ts";
import { startAdminProxy } from "./admin-proxy.ts";
import { pinnedHttps } from "./https-client.ts";
import { sha256Hex } from "./auth.ts";
import { NmzpStore } from "./persist.ts";
import { scanMetadata } from "./agent-discovery-scan.ts";
import { parseDiscovery, discoveryStale } from "./agent-discovery-schema.ts";
import { parseApiState } from "../src/lib/monitor/api.ts";
it("detector → authenticated heartbeat → durable store → API / LAN / export / UI model; local management cannot traverse LAN", async () => {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-discovery-pipeline-"));
  const srv = await startServer({
    dataDir: join(dir, "data"),
    host: "127.0.0.1",
    port: 0,
    coreDir: import.meta.dirname,
    uiDir: null,
  });
  const pin = { caPem: srv.tls.certPem, fingerprintSha256: srv.tls.fingerprintSha256 };
  const headers = { authorization: `Bearer ${srv.adminToken}` };
  const viewer = await startLanViewer({
    host: "127.0.0.1",
    port: 0,
    allowedCidrs: ["127.0.0.0/8"],
    uiDir: dir,
    ctUrl: srv.url,
    ...pin,
    adminToken: srv.adminToken,
  });
  const proxy = await startAdminProxy({
    host: "127.0.0.1",
    port: 0,
    uiDir: null,
    ctUrl: srv.url,
    ...pin,
    adminToken: srv.adminToken,
    discoveryHome: join(dir, "home"),
  });
  const token = "synthetic-device-token";
  const now = Date.now();
  try {
    await srv.store.putDevice({
      id: "synthetic-device",
      tokenHash: sha256Hex(token),
      hostname: "PRIVATE_USERNAME-PC",
      ip: "127.0.0.1",
      user: "PRIVATE_USERNAME",
      os: "win32",
      attachedAt: now,
      lastSeen: now,
      lastPolicyVersion: 1,
      capabilities: [],
      agents: [],
    });
    const snapshot = scanMetadata({
      home: dir,
      key: "fixture",
      pathDirs: [],
      packageRoots: [],
      extensionRoots: [],
      pythonRoots: [],
      manual: [],
      now,
      os: {
        records: [],
        files: [
          {
            path: join(dir, "PRIVATE_PATH", "Antigravity.exe"),
            product: "Antigravity",
            signature: "Valid",
          },
        ],
        processes: [
          { pid: 123, startedAt: now - 1000, path: join(dir, "PRIVATE_PATH", "Antigravity.exe") },
        ],
        states: {},
      },
    });
    const body = JSON.stringify({
      discovery: { ...snapshot, privatePath: "PRIVATE_PATH" },
      agents: [],
    });
    const noAuth = await pinnedHttps({
      url: srv.url + "/api/v1/heartbeat",
      method: "POST",
      body,
      ...pin,
    });
    assert.equal(noAuth.status, 401);
    const uploaded = await pinnedHttps({
      url: srv.url + "/api/v1/heartbeat",
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      body,
      ...pin,
    });
    assert.equal(uploaded.status, 200);
    const reboot = new NmzpStore(join(dir, "data"));
    await reboot.load({ readOnly: true });
    assert.deepEqual(reboot.getDevice("synthetic-device")?.discovery?.items, snapshot.items);
    for (const target of ["state", "export"]) {
      const admin = await pinnedHttps({ url: `${srv.url}/api/v1/${target}`, headers, ...pin });
      assert.equal(admin.status, 200);
      const lan = await fetch(`${viewer.url}/api/v1/${target}`);
      assert.equal(lan.status, 200);
      const lanText = await lan.text();
      assert.ok(!lanText.includes("PRIVATE_USERNAME"));
      assert.ok(!lanText.includes("PRIVATE_PATH"));
      for (const text of [admin.body, lanText]) {
        const json = JSON.parse(text);
        const devices = target === "state" ? parseApiState(json)!.devices : json.machines;
        const d = parseDiscovery(devices[0].discovery)!;
        assert.equal(d.items[0].adapterId, "antigravity-desktop");
        assert.equal(d.items[0].running, "observed");
        assert.equal(d.items[0].protection, "not_verified");
        assert.equal(d.items[0].scopeEligible, false);
        assert.ok(!text.includes("PRIVATE_PATH"));
        assert.equal(discoveryStale(d, d.completedAt + 180001), true);
      }
    }
    for (const method of ["POST", "PUT"]) {
      const r = await fetch(viewer.url + "/api/v1/local/discovery/refresh", { method, body: "{}" });
      assert.equal(r.status, 405);
    }
    assert.equal((await fetch(viewer.url + "/api/v1/local/discovery")).status, 404);
    assert.equal((await fetch(proxy.url + "/api/v1/local/discovery")).status, 401);
    const login = await fetch(proxy.url + "/api/v1/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: srv.adminToken }),
    });
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    assert.equal(
      (await fetch(proxy.url + "/api/v1/local/discovery", { headers: { cookie } })).status,
      200,
    );
    const badOrigin = await fetch(proxy.url + "/api/v1/local/discovery/paths", {
      method: "PUT",
      headers: { cookie, origin: "http://evil.invalid" },
      body: "[]",
    });
    assert.equal(badOrigin.status, 403);
    const malformed = await fetch(proxy.url + "/api/v1/local/discovery/paths", {
      method: "PUT",
      headers: { cookie },
      body: JSON.stringify([{ kind: "executable", path: "\\\\server\\secret.exe" }]),
    });
    assert.equal(malformed.status, 400);
    // Hold a synthetic scan lease: exercise real local HTTP persistence without scanning this test runner's host.
    await mkdir(join(dir, "home", ".nmzp"), { recursive: true });
    await writeFile(join(dir, "home", ".nmzp", "discovery.lock"), "synthetic-scan-in-progress");
    const privatePaths = [
      { kind: "executable", path: join(dir, "PRIVATE_CUSTOM", "Antigravity.exe") },
    ];
    assert.equal(
      (
        await fetch(proxy.url + "/api/v1/local/discovery/paths", {
          method: "PUT",
          headers: { cookie },
          body: JSON.stringify(privatePaths),
        })
      ).status,
      202,
    );
    assert.equal(
      (
        await fetch(proxy.url + "/api/v1/local/discovery/refresh", {
          method: "POST",
          headers: { cookie },
          body: "{}",
        })
      ).status,
      202,
    );
    const local = await (
      await fetch(proxy.url + "/api/v1/local/discovery", { headers: { cookie } })
    ).json();
    assert.deepEqual(local.paths, privatePaths);
    assert.deepEqual(
      JSON.parse(await readFile(join(dir, "home", ".nmzp", "discovery-paths.json"), "utf8")),
      privatePaths,
    );
    assert.ok(
      !(await (await fetch(viewer.url + "/api/v1/state")).text()).includes("PRIVATE_CUSTOM"),
    );
    const ctManage = await pinnedHttps({
      url: srv.url + "/api/v1/local/discovery/paths",
      headers,
      method: "PUT",
      body: "[]",
      ...pin,
    });
    assert.equal(ctManage.status, 404);
    assert.ok(
      !JSON.stringify(srv.store.getDevice("synthetic-device")?.discovery).includes("PRIVATE_PATH"),
    );
  } finally {
    await proxy.close();
    await viewer.close();
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});
