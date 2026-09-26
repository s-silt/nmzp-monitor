import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { linkSync, promises as fsPromises, readFileSync, renameSync, symlinkSync } from "node:fs";
import { lstat, mkdtemp, readFile, readdir, rename, rm, unlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { newSecret, sha256Hex } from "./auth.ts";
import { setAtomicFileIoForTesting } from "./atomic-file.ts";
import { ADMIN_BODY_LIMIT } from "./constants.ts";
import { pinnedHttps, type PinResponse } from "./https-client.ts";
import { projectViewerExport, projectViewerState, startLanViewer } from "./lan-viewer.ts";
import { startServer, type RunningServer } from "./serve.ts";
import { createViewerCredential } from "./viewer-credential.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const entry = join(coreDir, "nmzp.mjs");
const SECRET_USER = "L29DroppedUser";
const SECRET_HOST = "L29DroppedHost";
const LEGACY_WARNING =
  'warning: viewer is using the core admin token; create a scoped credential with "nmzp viewer-credential" (see docs/install.md)';

function spawnCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env: { ...process.env, NMZP_VIEWER_CREDENTIAL: "", ...env },
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
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

/** serverTime and capability lastSuccess are Date.now() on each request. */
function stripVolatileState(value: Record<string, unknown>): Record<string, unknown> {
  const clone = structuredClone(value);
  delete clone.serverTime;
  const caps = clone.capabilities;
  if (caps && typeof caps === "object" && !Array.isArray(caps)) {
    for (const cap of Object.values(caps as Record<string, Record<string, unknown>>)) {
      if (cap && typeof cap === "object") delete cap.lastSuccess;
    }
  }
  return clone;
}

function stripVolatileExport(value: Record<string, unknown>): Record<string, unknown> {
  const clone = structuredClone(value);
  delete clone.exportedAt;
  return clone;
}

async function authed(
  srv: RunningServer,
  method: string,
  path: string,
  bearer: string,
  body?: string,
): Promise<PinResponse> {
  return pinnedHttps({
    url: `${srv.url}${path}`,
    method,
    body,
    headers: {
      authorization: `Bearer ${bearer}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    caPem: srv.tls.certPem,
    fingerprintSha256: srv.tls.fingerprintSha256,
    timeoutMs: 8000,
    maxBodyBytes: ADMIN_BODY_LIMIT,
  });
}

describe("viewer credential", () => {
  it("viewer credential reads projected state but is refused on admin routes", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-l29-state-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const viewerToken = newSecret(32);
    try {
      const ticketRes = await authed(srv, "POST", "/api/v1/ticket", srv.adminToken);
      assert.equal(ticketRes.status, 200);
      const ticket = (JSON.parse(ticketRes.body) as { ticket: string }).ticket;
      const joined = await pinnedHttps({
        url: `${srv.url}/api/v1/join`,
        method: "POST",
        body: JSON.stringify({ ticket, hostname: SECRET_HOST, os: "win32", user: SECRET_USER }),
        headers: { "content-type": "application/json" },
        caPem: srv.tls.certPem,
        fingerprintSha256: srv.tls.fingerprintSha256,
        timeoutMs: 8000,
      });
      assert.equal(joined.status, 200, "fixture device joins");
      const deviceId = (JSON.parse(joined.body) as { deviceId: string }).deviceId;
      await writeFile(join(dir, "viewer-token.sha256"), sha256Hex(viewerToken), { mode: 0o600 });

      const adminState = await authed(srv, "GET", "/api/v1/state", srv.adminToken);
      const viewerState = await authed(srv, "GET", "/api/v1/state", viewerToken);
      assert.equal(adminState.status, 200);
      assert.equal(viewerState.status, 200, "viewer credential reads state");
      const adminStateJson = JSON.parse(adminState.body) as Record<string, unknown>;
      const viewerStateJson = JSON.parse(viewerState.body) as Record<string, unknown>;
      const projectedState = projectViewerState(adminStateJson);
      assert.equal(projectedState.ok, true, "admin state is projectable");
      if (!projectedState.ok) return;
      assert.deepEqual(
        stripVolatileState(viewerStateJson),
        stripVolatileState(projectedState.state),
        "viewer state must equal the projection",
      );
      assert.equal(adminState.body.includes(SECRET_USER), true, "fixture keeps the account name");
      assert.equal(viewerState.body.includes(SECRET_USER), false, "viewer state must omit the dropped account field");
      assert.equal(viewerState.body.includes(SECRET_HOST), false, "viewer state must omit the dropped hostname");

      const adminExport = await authed(srv, "GET", "/api/v1/export", srv.adminToken);
      const viewerExport = await authed(srv, "GET", "/api/v1/export", viewerToken);
      assert.equal(adminExport.status, 200);
      assert.equal(viewerExport.status, 200, "viewer credential reads export");
      const adminExportJson = JSON.parse(adminExport.body) as Record<string, unknown>;
      const viewerExportJson = JSON.parse(viewerExport.body) as Record<string, unknown>;
      const projectedExport = projectViewerExport(adminExportJson);
      assert.equal(projectedExport.ok, true, "admin export is projectable");
      if (!projectedExport.ok) return;
      assert.deepEqual(
        stripVolatileExport(viewerExportJson),
        stripVolatileExport(projectedExport.bundle),
        "viewer export must equal the projection",
      );
      assert.equal(adminExport.body.includes(SECRET_HOST), true, "fixture export keeps the hostname");
      assert.equal(viewerExport.body.includes(SECRET_HOST), false, "viewer export must omit the dropped hostname");

      const unknown = "unknown-bearer-not-issued";
      const routes: Array<{ method: string; path: string; body?: string }> = [
        { method: "GET", path: "/api/v1/policy" },
        { method: "PUT", path: "/api/v1/policy", body: JSON.stringify({ expectedVersion: 1, stopped: true }) },
        { method: "GET", path: "/api/v1/audit/events" },
        { method: "POST", path: "/api/v1/devices/revoke", body: JSON.stringify({ deviceId }) },
      ];
      for (const route of routes) {
        const asViewer = await authed(srv, route.method, route.path, viewerToken, route.body);
        const asUnknown = await authed(srv, route.method, route.path, unknown, route.body);
        const label = `${route.method} ${route.path}`;
        assert.equal(asViewer.status, 401, `viewer bearer must match unknown bearer on ${label}`);
        assert.equal(asViewer.status, asUnknown.status, `viewer bearer must match unknown bearer on ${label}`);
        assert.equal(asViewer.body, asUnknown.body, `viewer bearer must match unknown bearer on ${label}`);
      }
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("viewer credential file never contains the admin token and refuses overwrite without replace", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-l29-file-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const out = join(dir, "viewer-credential.json");
    const hashPath = join(dir, "viewer-token.sha256");
    const adminToken = srv.adminToken;
    try {
      await rename(join(dir, "admin.token"), join(dir, "admin.token.aside"));
      const first = await spawnCli(["viewer-credential", "--out", out], { NMZP_DATA: dir });
      assert.equal(first.code, 0, "viewer-credential writes the bundle");
      const text = await readFile(out, "utf8");
      const bundle = JSON.parse(text) as { v?: unknown; token?: unknown; url?: unknown; fingerprintSha256?: unknown; caPem?: unknown };
      assert.equal(text.includes(adminToken), false, "viewer credential file never contains the admin token");
      assert.equal(`${first.stdout}\n${first.stderr}`.includes(adminToken), false, "viewer credential file never contains the admin token");
      assert.equal(bundle.v, 1);
      assert.equal(typeof bundle.token, "string");
      assert.notEqual(bundle.token, adminToken);
      assert.equal(bundle.url, srv.url);
      assert.equal(bundle.fingerprintSha256, srv.tls.fingerprintSha256);
      assert.equal(bundle.caPem, srv.tls.certPem);
      const hash = (await readFile(hashPath, "utf8")).trim();
      assert.equal(hash, sha256Hex(String(bundle.token)));
      assert.equal(hash.includes(adminToken), false);
      assert.equal(hash.includes(String(bundle.token)), false);
      const accepted = await authed(srv, "GET", "/api/v1/state", String(bundle.token));
      assert.equal(accepted.status, 200);

      const second = await spawnCli(["viewer-credential", "--out", out], { NMZP_DATA: dir });
      assert.notEqual(second.code, 0, "viewer credential refuses overwrite without replace");
      assert.match(second.stderr, /viewer_credential_exists/);
      assert.equal(await readFile(out, "utf8"), text);
      assert.equal(await readFile(hashPath, "utf8"), hash);

      const third = await spawnCli(["viewer-credential", "--out", out, "--replace"], { NMZP_DATA: dir });
      assert.equal(third.code, 0, "viewer-credential --replace rewrites the bundle");
      const replacedText = await readFile(out, "utf8");
      const replaced = JSON.parse(replacedText) as { token?: unknown };
      assert.notEqual(replaced.token, bundle.token);
      assert.equal(replacedText.includes(adminToken), false, "viewer credential file never contains the admin token");
      assert.equal((await readFile(hashPath, "utf8")).trim(), sha256Hex(String(replaced.token)));
      const stale = await authed(srv, "GET", "/api/v1/state", String(bundle.token));
      const fresh = await authed(srv, "GET", "/api/v1/state", String(replaced.token));
      assert.equal(stale.status, 401);
      assert.equal(fresh.status, 200);
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("removing viewer-token.sha256 revokes the viewer bearer without restart", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-l29-revoke-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const viewerToken = newSecret(32);
    const hashPath = join(dir, "viewer-token.sha256");
    try {
      await writeFile(hashPath, sha256Hex(viewerToken), { mode: 0o600 });
      const before = await authed(srv, "GET", "/api/v1/state", viewerToken);
      assert.equal(before.status, 200, "viewer bearer works before the hash file is removed");
      await unlink(hashPath);
      const after = await authed(srv, "GET", "/api/v1/state", viewerToken);
      const unknown = await authed(srv, "GET", "/api/v1/state", "unknown-bearer-not-issued");
      const admin = await authed(srv, "GET", "/api/v1/state", srv.adminToken);
      assert.equal(after.status, 401, "removing viewer-token.sha256 revokes the viewer bearer without restart");
      assert.equal(after.body, unknown.body, "removing viewer-token.sha256 revokes the viewer bearer without restart");
      assert.equal(admin.status, 200, "core stays up without a restart");
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("viewer unit runs as a separate user without access to the core data dir", () => {
    const unit = readFileSync(join(coreDir, "nmzp-viewer.service"), "utf8");
    assert.match(unit, /^User=nmzp-viewer$/m, "viewer unit user");
    assert.match(unit, /^Group=nmzp-viewer$/m, "viewer unit group");
    assert.match(unit, /^InaccessiblePaths=\/var\/lib\/nmzp$/m, "viewer unit blocks core data");
    assert.match(unit, /^Environment=NMZP_VIEWER_CREDENTIAL=\/etc\/nmzp\/viewer-credential\.json$/m);
    assert.match(unit, /^ReadOnlyPaths=\/opt\/nmzp$/m);
    assert.doesNotMatch(unit, /^ReadOnlyPaths=.*\/var\/lib\/nmzp/m);
    assert.doesNotMatch(unit, /^ReadWritePaths=\/var\/lib\/nmzp$/m);
    assert.match(unit, /^NoNewPrivileges=true$/m);
    assert.match(unit, /^ProtectSystem=strict$/m);
    assert.match(unit, /^ProtectKernelTunables=true$/m);
    assert.match(unit, /^ProtectControlGroups=true$/m);
    assert.match(unit, /^RestrictSUIDSGID=true$/m);
    assert.match(unit, /^LockPersonality=true$/m);
  });

  it("lan viewer requires exactly one core token", async () => {
    const base = {
      host: "127.0.0.1",
      allowedCidrs: ["127.0.0.0/8"],
      port: 0,
      ctUrl: "https://127.0.0.1:9",
      caPem: "",
      fingerprintSha256: "ab".repeat(32),
    };
    await assert.rejects(() => startLanViewer(base), { message: "viewer token required" });
    await assert.rejects(() => startLanViewer({ ...base, adminToken: "admin-token", viewerToken: "viewer-token" }), {
      message: "viewer token required",
    });
    await assert.rejects(() => startLanViewer({ ...base, adminToken: "admin-token" }), { message: "tls pin required" });
    await assert.rejects(() => startLanViewer({ ...base, viewerToken: "viewer-token" }), { message: "tls pin required" });
  });

  it("legacy viewer warns that it is still using the core admin token", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-l29-warn-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", entry, "viewer", "--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8"],
      { env: { ...process.env, NMZP_DATA: dir, NMZP_VIEWER_CREDENTIAL: "" }, windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`viewer start timeout out=${stdout} err=${stderr}`)), 20_000);
        const check = () => {
          if (/nmzp viewer http:\/\/127\.0\.0\.1:\d+/.test(stdout)) {
            clearTimeout(timer);
            resolve();
          }
        };
        child.stdout.on("data", check);
        child.on("exit", (code) => {
          clearTimeout(timer);
          reject(new Error(`viewer exited ${code} out=${stdout} err=${stderr}`));
        });
        check();
      });
      assert.equal(stderr.includes(LEGACY_WARNING), true, "legacy viewer warns about the core admin token");
      assert.equal(stdout.includes(srv.adminToken), false);
      assert.equal(stderr.includes(srv.adminToken), false);
    } finally {
      child.kill();
      await new Promise((resolve) => child.once("close", resolve));
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("viewer cli starts from the scoped credential and does not read admin.token", { timeout: 60_000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-l29-cli-"));
    const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
    const out = join(dir, "viewer-credential.json");
    const adminToken = srv.adminToken;
    try {
      await rename(join(dir, "admin.token"), join(dir, "admin.token.aside"));
      const written = await spawnCli(["viewer-credential", "--out", out], { NMZP_DATA: dir });
      assert.equal(written.code, 0, "viewer-credential writes the bundle");
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", entry, "viewer", "--host", "127.0.0.1", "--port", "0", "--allow-cidr", "127.0.0.0/8", "--credential", out],
        { env: { ...process.env, NMZP_DATA: dir, NMZP_VIEWER_CREDENTIAL: "" }, windowsHide: true },
      );
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      try {
        const url = await new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("scoped viewer did not start")), 20_000);
          const check = () => {
            const found = /nmzp viewer (http:\/\/127\.0\.0\.1:\d+)/.exec(stdout);
            if (found?.[1]) {
              clearTimeout(timer);
              resolve(found[1]);
            }
          };
          child.stdout.on("data", check);
          child.on("exit", (code) => {
            clearTimeout(timer);
            reject(new Error(`scoped viewer exited ${code}`));
          });
          check();
        });
        const state = await fetch(`${url}/api/v1/state`);
        assert.equal(state.status, 200);
        const body = await state.text();
        assert.equal(JSON.parse(body).access, "viewer");
        assert.equal(stderr.includes(LEGACY_WARNING), false);
        assert.equal(`${stdout}\n${stderr}\n${body}`.includes(adminToken), false);
      } finally {
        child.kill();
        await new Promise((resolve) => child.once("close", resolve));
      }
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("core unit keeps its own user and the systemd sandbox around the data dir", () => {
    const unit = readFileSync(join(coreDir, "nmzp.service"), "utf8");
    assert.match(unit, /^User=nmzp$/m);
    assert.match(unit, /^Group=nmzp$/m);
    assert.doesNotMatch(unit, /^User=nmzp-viewer$/m);
    assert.doesNotMatch(unit, /^User=root$/m);
    assert.match(unit, /^NoNewPrivileges=true$/m);
    assert.match(unit, /^PrivateTmp=true$/m);
    assert.match(unit, /^ProtectSystem=strict$/m);
    assert.match(unit, /^ProtectHome=true$/m);
    assert.match(unit, /^ReadWritePaths=\/var\/lib\/nmzp$/m);
    assert.match(unit, /^ReadOnlyPaths=\/opt\/nmzp$/m);
    assert.doesNotMatch(unit, /NMZP_VIEWER_CREDENTIAL/);
  });

  it("help lists every supported hook id and the ordinary pack boundary", async () => {
    const supported = [
      "grok",
      "claude",
      "codex",
      "zcode",
      "antigravity",
      "kimi",
      "trae",
      "qwen",
      "qoder",
      "lingma",
      "codebuddy",
      "gemini",
      "cursor",
    ];
    const { HOOK_AGENTS } = await import("./hook-protocol.ts");
    const result = await spawnCli(["help"], {});
    assert.equal(result.code, 0, result.stderr);
    const line = result.stdout.split("\n").find((item) => item.startsWith("nmzp hook --agent "));
    assert.ok(line, "help must contain the hook agent line");
    const ids = line.slice("nmzp hook --agent ".length).trim().split("|");
    assert.deepEqual(ids, supported);
    assert.deepEqual([...HOOK_AGENTS], supported);
    assert.match(result.stdout, /Ordinary pack excludes native-\*, model-gateway\*, protected-session\*, and model-response\*/);
    assert.match(result.stdout, /Other catalog entries are not hook ids/);
    assert.match(result.stdout, /Host enforcement is not proven/);
    assert.equal(result.stdout.includes("HOST_REAL"), false);
  });
});

function exposesSecret(haystack: string, secrets: readonly string[]): boolean {
  return secrets.some((secret) => secret.length > 8 && haystack.includes(secret));
}

function errnoOf(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

async function viewerFixture(): Promise<{ dir: string; srv: RunningServer; out: string; token: string; bundleText: string }> {
  const dir = await mkdtemp(join(tmpdir(), "nmzp-p2-viewer-"));
  const srv = await startServer({ dataDir: dir, host: "127.0.0.1", port: 0, coreDir, uiDir: null });
  const out = join(dir, "viewer-credential.json");
  const written = await spawnCli(["viewer-credential", "--out", out], { NMZP_DATA: dir });
  assert.equal(written.code, 0, "viewer-credential writes the bundle");
  const bundleText = await readFile(out, "utf8");
  const token = (JSON.parse(bundleText) as { token?: unknown }).token;
  assert.equal(typeof token, "string");
  return { dir, srv, out, token: String(token), bundleText };
}

describe("P2 viewer credential publication", () => {
  it("P2 failed output publication does not revoke the existing viewer credential", { timeout: 60_000 }, async () => {
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const hashBefore = await readFile(hashPath, "utf8");
    const missing = join(dir, "missing-parent", "viewer-credential.json");
    try {
      const failed = await spawnCli(["viewer-credential", "--out", missing], { NMZP_DATA: dir });
      const output = `${failed.stdout}\n${failed.stderr}`;
      assert.notEqual(failed.code, 0, "missing parent must fail");
      assert.equal(exposesSecret(output, [token, srv.adminToken]), false, "token exposed");
      assert.equal(await lstat(join(dir, "missing-parent")).then(() => true, () => false), false, "missing parent was created");
      assert.equal(sha256Hex(await readFile(out, "utf8")) === sha256Hex(bundleText), true, "prior bundle bytes changed");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      const still = await authed(srv, "GET", "/api/v1/state", token);
      assert.equal(still.status, 200, "old credential revoked");

      const rotated = await spawnCli(["viewer-credential", "--out", out, "--replace"], { NMZP_DATA: dir });
      assert.equal(rotated.code, 0, "normal rotation failed");
      assert.equal(exposesSecret(`${rotated.stdout}\n${rotated.stderr}`, [token, srv.adminToken]), false, "token exposed");
      const nextText = await readFile(out, "utf8");
      const nextToken = (JSON.parse(nextText) as { token?: unknown }).token;
      assert.equal(typeof nextToken, "string");
      assert.notEqual(nextToken, token);
      assert.equal(exposesSecret(nextText, [srv.adminToken]), false, "token exposed");
      assert.equal((await readFile(hashPath, "utf8")).trim(), sha256Hex(String(nextToken)));
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 401, "rotated credential still accepts the old token");
      assert.equal((await authed(srv, "GET", "/api/v1/state", String(nextToken))).status, 200, "rotated credential was not published");
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("P2 refuses an output path that aliases a server security file", { timeout: 60_000 }, async () => {
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const saved = new Map<string, Buffer>();
    for (const rel of ["admin.token", "viewer-token.sha256", join("tls", "server.key"), join("tls", "server.crt")]) {
      saved.set(join(dir, rel), await readFile(join(dir, rel)));
    }
    const outside = await mkdtemp(join(tmpdir(), "nmzp-p2-alias-"));
    const targets: Array<{ label: string; path: string }> = [
      { label: "admin.token", path: join(dir, "admin.token") },
      { label: "viewer-token.sha256", path: hashPath },
      { label: "tls/server.key", path: join(dir, "tls", "server.key") },
      { label: "tls/server.crt", path: join(dir, "tls", "server.crt") },
      { label: "tls/new-file", path: join(dir, "tls", "viewer-credential.json") },
    ];
    try {
      try {
        linkSync(join(dir, "admin.token"), join(outside, "admin-hard"));
        targets.push({ label: "admin-hardlink", path: join(outside, "admin-hard") });
      } catch (error) {
        const code = errnoOf(error);
        if (code !== "EPERM" && code !== "EACCES" && code !== "ENOTSUP" && code !== "ENOSYS") throw error;
      }
      try {
        symlinkSync(dir, join(outside, "data"), "junction");
        targets.push({ label: "junction-admin.token", path: join(outside, "data", "admin.token") });
      } catch (error) {
        const code = errnoOf(error);
        if (code !== "EPERM" && code !== "EACCES" && code !== "ENOTSUP" && code !== "ENOSYS") throw error;
      }
      const failures: string[] = [];
      for (const target of targets) {
        const hashBefore = await readFile(hashPath, "utf8");
        const before = await readFile(target.path)
          .then((buf) => sha256Hex(buf.toString("utf8")))
          .catch(() => "absent");
        let message = "";
        try {
          await createViewerCredential({ dataDir: dir, out: target.path, replace: true });
          message = "resolved";
        } catch (error) {
          message = error instanceof Error ? error.message : "unknown";
        }
        const after = await readFile(target.path)
          .then((buf) => sha256Hex(buf.toString("utf8")))
          .catch(() => "absent");
        const hashNow = await readFile(hashPath, "utf8").catch(() => "");
        const auth = await authed(srv, "GET", "/api/v1/state", token);
        if (!message.includes("viewer_credential_refused") || after !== before || auth.status !== 200 || hashNow !== hashBefore) {
          failures.push(target.label);
        }
        if (exposesSecret(message, [token, srv.adminToken])) failures.push(`${target.label}-secret`);
        for (const [path, bytes] of saved) {
          await writeFile(path, bytes);
        }
        await writeFile(out, bundleText);
      }
      assert.deepEqual(failures, []);
    } finally {
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("P2 hash publication failure preserves the prior bundle or reports a retained artifact", { timeout: 60_000 }, async () => {
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const hashBefore = await readFile(hashPath, "utf8");
    try {
      setAtomicFileIoForTesting({
        rename: (from, to) => {
          if (String(to).replace(/\\/g, "/").endsWith("/viewer-token.sha256")) {
            const error = new Error("hash_rename_failed") as NodeJS.ErrnoException;
            error.code = "EIO";
            throw error;
          }
          renameSync(from, to);
        },
      });
      let message = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      } finally {
        setAtomicFileIoForTesting();
      }
      assert.equal(exposesSecret(message, [token, srv.adminToken]), false, "token exposed");
      assert.equal(sha256Hex(await readFile(out, "utf8")) === sha256Hex(bundleText), true, "prior bundle bytes changed");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");
      const names = await readdir(dir);
      assert.equal(names.some((name) => name.includes("viewer.tmp")), false, "staged bundle left behind");

      setAtomicFileIoForTesting({
        platform: "linux",
        openDirectory: () => {
          const error = new Error("dir_sync_failed") as NodeJS.ErrnoException;
          error.code = "EIO";
          throw error;
        },
      });
      let uncertain = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        uncertain = error instanceof Error ? error.message : "unknown";
      } finally {
        setAtomicFileIoForTesting();
      }
      const hash = (await readFile(hashPath, "utf8")).trim();
      const fileText = await readFile(out, "utf8");
      const publishedToken = (JSON.parse(fileText) as { token?: unknown }).token;
      assert.equal(typeof publishedToken, "string");
      assert.match(uncertain, /viewer_credential_durability_unknown/);
      assert.equal(exposesSecret(uncertain, [token, srv.adminToken, String(publishedToken)]), false, "token exposed");
      assert.equal(publishedToken === token, false, "delivered bundle still has the previous token");
      assert.equal(hash === sha256Hex(String(publishedToken)), true, "delivered bundle does not match the hash");
      assert.equal((await authed(srv, "GET", "/api/v1/state", String(publishedToken))).status, 200, "delivered bundle was not authorized");
    } finally {
      setAtomicFileIoForTesting();
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("P2 does not overwrite an external bundle change or publish the hash for it", { timeout: 60_000 }, async () => {
    const mod = (await import("./viewer-credential.ts")) as {
      setViewerCredentialHooksForTesting?: (hooks?: {
        beforeHashPublish?: () => void | Promise<void>;
        beforeBundleInstall?: () => void | Promise<void>;
      }) => void;
    };
    assert.equal(typeof mod.setViewerCredentialHooksForTesting, "function", "bundle replace has no ownership check");
    const setHooks = mod.setViewerCredentialHooksForTesting;
    if (!setHooks) return;
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const hashBefore = await readFile(hashPath, "utf8");
    try {
      setHooks({
        beforeHashPublish: () => writeFile(out, "EXTERNAL-BEFORE-HASH"),
      });
      let conflict = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        conflict = error instanceof Error ? error.message : "unknown";
      } finally {
        setHooks();
      }
      assert.match(conflict, /viewer_credential_conflict/);
      assert.equal(exposesSecret(conflict, [token, srv.adminToken]), false, "token exposed");
      assert.equal(await readFile(out, "utf8"), "EXTERNAL-BEFORE-HASH", "external bundle change was overwritten");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");
      await writeFile(out, bundleText);

      setHooks({
        beforeBundleInstall: () => writeFile(out, "EXTERNAL-AFTER-HASH"),
      });
      let early = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        early = error instanceof Error ? error.message : "unknown";
      } finally {
        setHooks();
      }
      assert.match(early, /viewer_credential_conflict/);
      assert.equal(exposesSecret(early, [token, srv.adminToken]), false, "token exposed");
      assert.equal(await readFile(out, "utf8"), "EXTERNAL-AFTER-HASH", "external bundle change was overwritten");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");
    } finally {
      setHooks();
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("P2 final bundle rename failure leaves the previous viewer authorized", { timeout: 60_000 }, async () => {
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const hashBefore = await readFile(hashPath, "utf8");
    const originalRename = fsPromises.rename;
    const failDest = (dest: string) => {
      fsPromises.rename = (async (from: Parameters<typeof originalRename>[0], to: Parameters<typeof originalRename>[1]) => {
        if (String(to) === dest) {
          const error = new Error("rename_out_failed") as NodeJS.ErrnoException;
          error.code = "EIO";
          throw error;
        }
        return originalRename(from, to);
      }) as typeof fsPromises.rename;
      syncBuiltinESMExports();
    };
    const restoreRename = () => {
      fsPromises.rename = originalRename;
      syncBuiltinESMExports();
    };
    try {
      failDest(out);
      let replaceMessage = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        replaceMessage = error instanceof Error ? error.message : "unknown";
      } finally {
        restoreRename();
      }
      assert.notEqual(replaceMessage, "", "replace rename failure was ignored");
      assert.equal(exposesSecret(replaceMessage, [token, srv.adminToken]), false, "token exposed");
      assert.equal(sha256Hex(await readFile(out, "utf8")) === sha256Hex(bundleText), true, "prior bundle bytes changed");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");

      const created = join(dir, "fresh-viewer.json");
      failDest(created);
      let createMessage = "";
      try {
        await createViewerCredential({ dataDir: dir, out: created });
      } catch (error) {
        createMessage = error instanceof Error ? error.message : "unknown";
      } finally {
        restoreRename();
      }
      assert.notEqual(createMessage, "", "create rename failure was ignored");
      assert.equal(exposesSecret(createMessage, [token, srv.adminToken]), false, "token exposed");
      assert.equal(await lstat(created).then(() => true, () => false), false, "failed create left a bundle");
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal(sha256Hex(await readFile(out, "utf8")) === sha256Hex(bundleText), true, "prior bundle bytes changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");
    } finally {
      restoreRename();
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("P2 read failure after bundle publication restores the old bundle or reports it retained", { timeout: 60_000 }, async () => {
    const { dir, srv, out, token, bundleText } = await viewerFixture();
    const hashPath = join(dir, "viewer-token.sha256");
    const hashBefore = await readFile(hashPath, "utf8");
    const originalRead = fsPromises.readFile;
    let failMode: "off" | "once" | "always" = "off";
    const installRead = () => {
      fsPromises.readFile = (async (path: Parameters<typeof originalRead>[0], options?: Parameters<typeof originalRead>[1]) => {
        if (String(path) === out && failMode !== "off") {
          if (failMode === "once") failMode = "off";
          const error = new Error("read_out_failed") as NodeJS.ErrnoException;
          error.code = "EIO";
          throw error;
        }
        return originalRead(path, options);
      }) as typeof fsPromises.readFile;
      syncBuiltinESMExports();
    };
    const restoreRead = () => {
      failMode = "off";
      fsPromises.readFile = originalRead;
      syncBuiltinESMExports();
    };
    const assertKept = async (message: string) => {
      assert.equal(exposesSecret(message, [token, srv.adminToken]), false, "token exposed");
      assert.match(message, /viewer_credential_unpublished|viewer_credential_retained /);
      assert.equal((await readFile(hashPath, "utf8")) === hashBefore, true, "server hash changed");
      assert.equal((await authed(srv, "GET", "/api/v1/state", token)).status, 200, "old credential revoked");
      const text = await readFile(out, "utf8").catch(() => "");
      const prior = sha256Hex(text) === sha256Hex(bundleText);
      const retained = message.startsWith("viewer_credential_retained ");
      assert.equal(prior || retained, true, "invalid bundle left without an explicit retained report");
      if (!prior) await writeFile(out, bundleText);
    };
    try {
      installRead();
      const { setViewerCredentialHooksForTesting } = await import("./viewer-credential.ts");
      setViewerCredentialHooksForTesting({
        afterBundlePublish: () => {
          failMode = "once";
        },
      });
      let afterRename = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        afterRename = error instanceof Error ? error.message : "unknown";
      } finally {
        setViewerCredentialHooksForTesting();
      }
      await assertKept(afterRename);

      setViewerCredentialHooksForTesting({
        beforeHashPublish: () => {
          failMode = "once";
        },
      });
      let beforeHash = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        beforeHash = error instanceof Error ? error.message : "unknown";
      } finally {
        setViewerCredentialHooksForTesting();
      }
      await assertKept(beforeHash);

      setAtomicFileIoForTesting({
        rename: (from, to) => {
          if (String(to).replace(/\\/g, "/").endsWith("/viewer-token.sha256")) {
            failMode = "always";
            const error = new Error("hash_rename_failed") as NodeJS.ErrnoException;
            error.code = "EIO";
            throw error;
          }
          renameSync(from, to);
        },
      });
      let recovery = "";
      try {
        await createViewerCredential({ dataDir: dir, out, replace: true });
      } catch (error) {
        recovery = error instanceof Error ? error.message : "unknown";
      } finally {
        setAtomicFileIoForTesting();
        failMode = "off";
      }
      await assertKept(recovery);
    } finally {
      restoreRead();
      setAtomicFileIoForTesting();
      const { setViewerCredentialHooksForTesting } = await import("./viewer-credential.ts");
      setViewerCredentialHooksForTesting();
      await srv.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
