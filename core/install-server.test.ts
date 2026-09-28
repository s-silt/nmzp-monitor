import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdirSync, symlinkSync } from "node:fs";
import { lstat as lstatAsync, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "./auth.ts";
import {
  DEFAULT_DATA_DIR,
  DEFAULT_PREFIX,
  INSTALL_PORTS,
  INSTALL_STATE_PATH,
  LOGIN_DEFS_PATH,
  MIN_INSTALL_FREE_BYTES,
  NMZP_SYSTEM_SHELLS,
  RecordingInstallHost,
  SYSTEM_ID_LIMIT,
  SYSTEM_ID_MAX_FALLBACK,
  UNIT_PATH,
  assertSeedDir,
  assertSeedParent,
  createNodeInstallHost,
  isSystemAccountId,
  parseLoginDefsLimits,
  parseSystemdUnit,
  renderServiceUnit,
  runServerInstall,
  unitValues,
  type HostStat,
  type InstallArgs,
} from "./install-server.ts";
import { certificateCovers, generateNmzpCert } from "./tls.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const DATA = DEFAULT_DATA_DIR;
const GIB = 1024 * 1024 * 1024;

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    stdout: (text: string) => {
      out.push(text);
    },
    stderr: (text: string) => {
      err.push(text);
    },
    text: () => out.join(""),
    errText: () => err.join(""),
  };
}

async function withHost(
  opts: { platform?: NodeJS.Platform; arch?: string; rootUser?: boolean; free?: number },
  fn: (host: RecordingInstallHost) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-install-"));
  const host = new RecordingInstallHost({ root, platform: "linux", arch: "x64", ...opts });
  try {
    await fn(host);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function diskList(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string, prefix: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      out.push(entry.isDirectory() ? `${rel}/` : rel);
      if (entry.isDirectory()) await walk(join(dir, entry.name), rel);
    }
  }
  await walk(root, "");
  return out;
}

function snapshot(host: RecordingInstallHost): string {
  return JSON.stringify({
    commands: host.commands,
    mutations: host.mutations,
    entries: host.entries(),
  });
}

function assertAtomicRename(
  mutations: readonly string[],
  renameRe: RegExp,
  dir: string,
  uid: number,
  gid: number,
): void {
  let seen = 0;
  for (let i = 0; i < mutations.length; i += 1) {
    const line = mutations[i] ?? "";
    if (!renameRe.test(line)) continue;
    seen += 1;
    const tmp = /^rename (\S+) /.exec(line)?.[1];
    assert.ok(tmp);
    assert.equal(mutations[i - 3], `write ${tmp} ${0o600}`);
    assert.equal(mutations[i - 2], `fsync ${tmp}`);
    assert.equal(mutations[i - 1], `chown ${tmp} ${uid} ${gid}`);
    assert.equal(mutations[i + 1], `fsync ${dir}`);
  }
  assert.ok(seen > 0);
}

function args(extra: Partial<InstallArgs> = {}): InstallArgs {
  return { plan: false, dataDir: DATA, prefix: DEFAULT_PREFIX, ...extra };
}

function stateJson(over: Record<string, unknown> = {}): string {
  return `${JSON.stringify({
    v: 1,
    installer: "nmzp-server-install",
    dataDir: DATA,
    prefix: DEFAULT_PREFIX,
    publicUrl: null,
    uid: 960,
    gid: 960,
    tokenShown: true,
    serviceEnabled: true,
    ...over,
  })}\n`;
}

const JOIN_TICKET = {
  hash: "ab".repeat(32),
  expiresAt: 4_102_444_800_000,
  consumed: false,
};

function reentryCommands(): Array<{ cmd: string; args: string[] }> {
  return [
    { cmd: "/usr/bin/getent", args: ["group", "nmzp"] },
    { cmd: "/usr/bin/getent", args: ["passwd", "nmzp"] },
    { cmd: "/usr/bin/systemctl", args: ["stop", "nmzp"] },
    { cmd: "/usr/bin/systemctl", args: ["daemon-reload"] },
    { cmd: "/usr/bin/systemctl", args: ["enable", "--now", "nmzp"] },
  ];
}

async function install(
  host: RecordingInstallHost,
  extra: Partial<InstallArgs> = {},
  env: NodeJS.ProcessEnv = {},
) {
  const io = capture();
  const code = await runServerInstall(args(extra), { host, coreDir, env, ...io });
  return { code, stdout: io.text(), stderr: io.errText() };
}

describe("server install preflight", () => {
  it("rejects windows before any host write", async () => {
    await withHost({ platform: "win32" }, async (host) => {
      const before = snapshot(host);
      const result = await install(host);
      assert.notEqual(result.code, 0);
      assert.match(result.stderr, /Windows server install is WP-60/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a non-linux platform", async () => {
    await withHost({ platform: "darwin" }, async (host) => {
      const before = snapshot(host);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 1);
      assert.match(result.stderr, /linux x64\/arm64/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects an unsupported architecture", async () => {
    await withHost({ arch: "arm" }, async (host) => {
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /linux x64\/arm64/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a non-root execute without writing", async () => {
    await withHost({ rootUser: false }, async (host) => {
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /install requires root/);
      assert.match(result.stdout, /plan: preflight ok/);
      assert.equal(result.stdout.includes("admin token:"), false);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a busy 8787 without writing", async () => {
    await withHost({}, async (host) => {
      host.ports.set(8787, false);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /port 8787 is not free/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a busy 8788 without writing", async () => {
    await withHost({}, async (host) => {
      host.ports.set(8788, false);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /port 8788 is not free/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects one byte under 1 GiB and accepts exactly 1 GiB", async () => {
    assert.equal(MIN_INSTALL_FREE_BYTES, GIB);
    await withHost({ free: GIB - 1 }, async (host) => {
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /1 GiB/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
    await withHost({ free: GIB }, async (host) => {
      const before = snapshot(host);
      const disk = await diskList(host.root);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 0);
      assert.equal(snapshot(host), before);
      assert.deepEqual(await diskList(host.root), disk);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a symlink data directory without writing", async () => {
    await withHost({}, async (host) => {
      host.symlink(DATA, "/elsewhere");
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /refusing symlink/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a symlink parent of the data directory without writing", async () => {
    await withHost({}, async (host) => {
      host.symlink("/var/lib", "/elsewhere");
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /refusing symlink at \/var\/lib/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects an existing admin.token that this install did not write", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o755);
      await host.mkdir("/var/lib", 0o755);
      await host.mkdir(DATA, 0o700);
      await host.writeFile(`${DATA}/admin.token`, "legacy-secret\n", 0o600);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /nmzp migrate/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
      assert.equal(result.stdout.includes("legacy-secret"), false);
      assert.equal(result.stderr.includes("legacy-secret"), false);
    });
  });

  it("rejects an existing policy.json that this install did not write", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o755);
      await host.mkdir("/var/lib", 0o755);
      await host.mkdir(DATA, 0o700);
      await host.writeFile(`${DATA}/policy.json`, "{}\n", 0o600);
      const before = snapshot(host);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 1);
      assert.match(result.stderr, /nmzp migrate/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("accepts a tree marked by root-owned install-state.json", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o755);
      await host.mkdir("/var/lib", 0o755);
      await host.mkdir(DATA, 0o700);
      await host.chown(DATA, 960, 960);
      await host.writeFile(`${DATA}/policy.json`, "{}\n", 0o600);
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/nmzp", 0o700);
      await host.writeFile(INSTALL_STATE_PATH, stateJson(), 0o600);
      const before = snapshot(host);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 0, result.stderr);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects 0.x data when root install-state dataDir differs", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o755);
      await host.mkdir("/var/lib", 0o755);
      await host.mkdir(DATA, 0o700);
      await host.writeFile(`${DATA}/policy.json`, "{}\n", 0o600);
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/nmzp", 0o700);
      await host.writeFile(INSTALL_STATE_PATH, stateJson({ dataDir: "/var/lib/other" }), 0o600);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /nmzp migrate/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a root install-state whose dataDir does not match an empty tree", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/nmzp", 0o700);
      await host.writeFile(INSTALL_STATE_PATH, stateJson({ dataDir: "/var/lib/other" }), 0o600);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /install-state\.json dataDir does not match/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a group-writable ancestor before any write", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o777);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /refusing ancestor \/var: must be root-owned and not group\/world writable/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects an ancestor not owned by root before any write", async () => {
    await withHost({}, async (host) => {
      await host.mkdir("/var", 0o755);
      await host.chown("/var", 1000, 1000);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /refusing ancestor \/var: must be root-owned and not group\/world writable/);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a tls key that does not match the certificate without overwriting it", async () => {
    await withHost({}, async (host) => {
      await seedTlsParents(host);
      const cert = generateNmzpCert();
      const other = generateNmzpCert();
      await host.writeFile(`${DATA}/tls/server.crt`, cert.certPem, 0o600);
      await host.writeFile(`${DATA}/tls/server.key`, other.keyPem, 0o600);
      await host.writeFile(
        `${DATA}/tls/pin.json`,
        `${JSON.stringify({ fingerprintSha256: cert.fingerprintSha256 })}\n`,
        0o600,
      );
      const key = await host.readFile(`${DATA}/tls/server.key`);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /tls key does not match certificate; refusing to replace it/);
      assert.deepEqual(await host.readFile(`${DATA}/tls/server.key`), key);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });

  it("rejects a tls pin that does not match the certificate without overwriting it", async () => {
    await withHost({}, async (host) => {
      await seedTlsParents(host);
      const cert = generateNmzpCert();
      await host.writeFile(`${DATA}/tls/server.crt`, cert.certPem, 0o600);
      await host.writeFile(`${DATA}/tls/server.key`, cert.keyPem, 0o600);
      await host.writeFile(
        `${DATA}/tls/pin.json`,
        `${JSON.stringify({ fingerprintSha256: "ab".repeat(32) })}\n`,
        0o600,
      );
      const pin = await host.readFile(`${DATA}/tls/pin.json`);
      const before = snapshot(host);
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /tls pin mismatch; refusing to replace certificate files/);
      assert.deepEqual(await host.readFile(`${DATA}/tls/pin.json`), pin);
      assert.equal(snapshot(host), before);
      assert.equal(host.commands.length, 0);
    });
  });
});

describe("server install plan", () => {
  it("prints the plan and leaves the tree unchanged", async () => {
    await withHost({}, async (host) => {
      const before = snapshot(host);
      const disk = await diskList(host.root);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 0);
      assert.match(result.stdout, /plan: preflight ok/);
      assert.match(result.stdout, /plan: systemctl enable --now nmzp/);
      assert.equal(result.stdout.includes("admin token:"), false);
      assert.equal(snapshot(host), before);
      assert.deepEqual(await diskList(host.root), disk);
      assert.equal(host.commands.length, 0);
    });
  });

  it("plans as root without writing", async () => {
    await withHost({ rootUser: true }, async (host) => {
      const before = snapshot(host);
      const disk = await diskList(host.root);
      const result = await install(host, { plan: true });
      assert.equal(result.code, 0);
      assert.equal(snapshot(host), before);
      assert.deepEqual(await diskList(host.root), disk);
    });
  });
});

describe("server install execute", () => {
  it(
    "installs, skips a second run, tightens modes, and rewrites a changed unit",
    { timeout: 180_000 },
    async () => {
      await withHost({}, async (host) => {
        const result = await install(
          host,
          { publicUrl: "https://203.0.113.10:8787" },
          { NMZP_TLS_HOSTS: "ct.example" },
        );
        assert.equal(result.code, 0, result.stderr);
        assert.deepEqual(host.commands, [
          { cmd: "/usr/bin/getent", args: ["group", "nmzp"] },
          { cmd: "/usr/sbin/groupadd", args: ["--system", "nmzp"] },
          { cmd: "/usr/bin/getent", args: ["passwd", "nmzp"] },
          {
            cmd: "/usr/sbin/useradd",
            args: [
              "--system",
              "--gid",
              "nmzp",
              "--no-create-home",
              "--home-dir",
              "/nonexistent",
              "--shell",
              "/usr/sbin/nologin",
              "nmzp",
            ],
          },
          { cmd: "/usr/bin/getent", args: ["group", "nmzp"] },
          { cmd: "/usr/bin/getent", args: ["passwd", "nmzp"] },
          { cmd: "/usr/bin/systemctl", args: ["daemon-reload"] },
          { cmd: "/usr/bin/systemctl", args: ["enable", "--now", "nmzp"] },
        ]);
        assert.ok(
          host.mutations.some((line) => /^fsync \/etc\/nmzp\/install-state\.json\..+\.tmp$/.test(line)),
        );
        assert.ok(
          host.mutations.some((line) =>
            /^rename \/etc\/nmzp\/install-state\.json\..+\.tmp \/etc\/nmzp\/install-state\.json$/.test(line),
          ),
        );
        assertAtomicRename(
          host.mutations,
          /^rename \/etc\/nmzp\/install-state\.json\..+\.tmp \/etc\/nmzp\/install-state\.json$/,
          "/etc/nmzp",
          0,
          0,
        );
        const token = /^admin token: (\S+)$/m.exec(result.stdout)?.[1];
        assert.ok(token);
        assert.equal(result.stdout.split(token).length - 1, 1);
        const doctor = result.stdout.slice(result.stdout.indexOf("\ndoctor:\n"));
        assert.equal(doctor.includes(token), false);
        assert.equal(result.stderr.includes(token), false);
        assert.match(result.stdout, /admin 口令可以用 `nmzp admin reset-credential` 重置/);
        assert.match(result.stdout, /nmzp backup verify/);
        const stateRaw = (await host.readFile(INSTALL_STATE_PATH))?.toString("utf8") ?? "";
        assert.equal(await host.readFile(`${DATA}/install-state.json`), null);
        assert.equal(stateRaw.includes(token), false);
        const state = JSON.parse(stateRaw) as {
          tokenShown: boolean;
          serviceEnabled: boolean;
          uid: number;
        };
        assert.equal(state.tokenShown, true);
        assert.equal(state.serviceEnabled, true);
        assert.equal(state.uid, host.ids.uid);
        const tokenFile = await host.readFile(`${DATA}/admin.token`);
        assert.equal(tokenFile?.toString("utf8"), `${token}\n`);
        const meta = (await host.readFile(`${DATA}/meta.json`))?.toString("utf8") ?? "";
        assert.equal(meta.includes(token), false);
        assert.match(meta, new RegExp(sha256Hex(token)));
        const cert = (await host.readFile(`${DATA}/tls/server.crt`))?.toString("utf8") ?? "";
        assert.equal(certificateCovers(cert, "203.0.113.10"), true);
        assert.equal(certificateCovers(cert, "ct.example"), true);
        const pin = (await host.readFile(`${DATA}/tls/pin.json`))?.toString("utf8") ?? "";
        const fingerprint = /^identity: created fingerprint ([0-9a-f]+)$/m.exec(result.stdout)?.[1];
        assert.ok(fingerprint);
        assert.equal(pin.includes(fingerprint), true);
        const required = new Set([
          "/var",
          "/var/lib",
          DATA,
          `${DATA}/tls`,
          `${DATA}/policy.json`,
          `${DATA}/devices.json`,
          `${DATA}/meta.json`,
          `${DATA}/admin.token`,
          `${DATA}/tls/server.key`,
          `${DATA}/tls/server.crt`,
          `${DATA}/tls/pin.json`,
          "/etc",
          "/etc/nmzp",
          INSTALL_STATE_PATH,
          "/etc/systemd",
          "/etc/systemd/system",
          UNIT_PATH,
        ]);
        const optional = new Set([`${DATA}/events.jsonl`, `${DATA}/network.jsonl`]);
        for (const entry of host.entries()) {
          assert.ok(required.has(entry.path) || optional.has(entry.path), entry.path);
          if (entry.path === UNIT_PATH) {
            assert.equal(entry.type, "file");
            assert.equal(entry.mode, 0o644);
            assert.equal(entry.uid, 0);
            assert.equal(entry.gid, 0);
          } else if (entry.path === INSTALL_STATE_PATH) {
            assert.equal(entry.type, "file");
            assert.equal(entry.mode, 0o600);
            assert.equal(entry.uid, 0);
            assert.equal(entry.gid, 0);
          } else if (entry.path === "/etc/nmzp") {
            assert.equal(entry.type, "dir");
            assert.equal(entry.mode, 0o700);
            assert.equal(entry.uid, 0);
            assert.equal(entry.gid, 0);
          } else if (entry.type === "dir" && entry.path !== DATA && entry.path !== `${DATA}/tls`) {
            assert.equal(entry.mode, 0o755);
            assert.equal(entry.uid, 0);
          } else if (entry.type === "dir") {
            assert.equal(entry.mode, 0o700);
            assert.equal(entry.uid, host.ids.uid);
            assert.equal(entry.gid, host.ids.gid);
          } else {
            assert.equal(entry.mode, 0o600);
            assert.equal(entry.uid, host.ids.uid);
            assert.equal(entry.gid, host.ids.gid);
          }
        }
        for (const path of required)
          assert.ok(
            host.entries().some((entry) => entry.path === path),
            path,
          );
        const listed = new Set(
          (await diskList(host.root)).map((item) => `/${item.replace(/\/$/, "")}`),
        );
        for (const entry of host.entries()) assert.ok(listed.has(entry.path), entry.path);
        const unit = (await host.readFile(UNIT_PATH))?.toString("utf8") ?? "";
        const model = parseSystemdUnit(unit);
        assert.deepEqual(unitValues(model, "Service", "NoNewPrivileges"), ["true"]);
        assert.deepEqual(unitValues(model, "Service", "ProtectSystem"), ["strict"]);
        assert.deepEqual(unitValues(model, "Service", "User"), ["nmzp"]);
        assert.deepEqual(unitValues(model, "Service", "ReadWritePaths"), [DATA]);
        assert.deepEqual(unitValues(model, "Service", "PrivateTmp"), ["true"]);
        assert.deepEqual(unitValues(model, "Service", "ProtectHome"), ["true"]);
        assert.match(unit, /^Environment=NMZP_BIND=0\.0\.0\.0$/m);
        assert.match(unit, new RegExp(`^Environment=NMZP_DATA=${DATA}$`, "m"));
        assert.match(
          unit,
          /^ExecStart=\/usr\/local\/bin\/node --experimental-strip-types \/opt\/nmzp\/nmzp\.mjs serve$/m,
        );

        const key = await host.readFile(`${DATA}/tls/server.key`);
        const commandCount = host.commands.length;
        const mutationCount = host.mutations.length;
        const again = await install(
          host,
          { publicUrl: "https://203.0.113.10:8787" },
          { NMZP_TLS_HOSTS: "ct.example" },
        );
        assert.equal(again.code, 0, again.stderr);
        assert.deepEqual(host.commands.slice(commandCount), reentryCommands());
        assert.ok(host.mutations.slice(mutationCount).every((line) => line.startsWith("run ")));
        assert.match(again.stdout, /data dir: skip/);
        assert.match(again.stdout, /permissions: skip/);
        assert.match(again.stdout, /identity: skip/);
        assert.match(again.stdout, /store: skip/);
        assert.match(again.stdout, /admin: skip/);
        assert.match(again.stdout, /service: skip/);
        assert.match(again.stdout, /start: systemctl daemon-reload; systemctl enable --now nmzp/);
        assert.equal(again.stdout.includes("start: skip"), false);
        assert.equal(again.stdout.includes(token), false);
        assert.equal(again.stderr.includes(token), false);
        assert.deepEqual(await host.readFile(`${DATA}/tls/server.key`), key);
        assert.deepEqual(await host.readFile(`${DATA}/admin.token`), tokenFile);

        await host.chmod(DATA, 0o755);
        await host.chown(DATA, 0, 0);
        await host.chmod(`${DATA}/admin.token`, 0o644);
        const afterWiden = host.commands.length;
        const tightened = await install(
          host,
          { publicUrl: "https://203.0.113.10:8787" },
          { NMZP_TLS_HOSTS: "ct.example" },
        );
        assert.equal(tightened.code, 0, tightened.stderr);
        assert.deepEqual(host.commands.slice(afterWiden), reentryCommands());
        assert.match(tightened.stdout, /permissions: corrected/);
        assert.match(tightened.stdout, /identity: skip/);
        assert.equal(tightened.stdout.includes(token), false);
        const dirStat = await host.lstat(DATA);
        const tokenStat = await host.lstat(`${DATA}/admin.token`);
        assert.equal(dirStat?.mode, 0o700);
        assert.equal(dirStat?.uid, host.ids.uid);
        assert.equal(tokenStat?.mode, 0o600);
        assert.equal(tokenStat?.uid, host.ids.uid);
        assert.deepEqual(await host.readFile(`${DATA}/tls/server.key`), key);
        assert.deepEqual(await host.readFile(`${DATA}/admin.token`), tokenFile);

        await host.writeFile(UNIT_PATH, "changed\n", 0o644);
        const beforeRewrite = host.commands.length;
        const rewritten = await install(
          host,
          { publicUrl: "https://203.0.113.10:8787" },
          { NMZP_TLS_HOSTS: "ct.example" },
        );
        assert.equal(rewritten.code, 0, rewritten.stderr);
        assert.deepEqual(host.commands.slice(beforeRewrite), reentryCommands());
        const backup = await host.readFile(`${UNIT_PATH}.bak-${host.nowMs}`);
        assert.equal(backup?.toString("utf8"), "changed\n");
        const replaced = (await host.readFile(UNIT_PATH))?.toString("utf8") ?? "";
        assert.match(replaced, /^NoNewPrivileges=true$/m);
        assert.match(replaced, /^ProtectSystem=strict$/m);
        assert.match(replaced, new RegExp(`^ReadWritePaths=${DATA}$`, "m"));
        assert.match(rewritten.stdout, /service: backup/);
        assert.match(rewritten.stdout, /service: wrote/);
        assert.equal(rewritten.stdout.includes(token), false);
        assert.deepEqual(await host.readFile(`${DATA}/tls/server.key`), key);
        assert.deepEqual(await host.readFile(`${DATA}/admin.token`), tokenFile);
        const finalState = (await host.readFile(INSTALL_STATE_PATH))?.toString("utf8") ?? "";
        assert.equal(finalState.includes(token), false);
      });
    },
  );
});

describe("server install unit template", () => {
  it("keeps the packaged unit when data and prefix are the defaults", async () => {
    const template = (await readFile(join(coreDir, "nmzp.service"), "utf8")).replace(/\r\n/g, "\n");
    assert.equal(
      renderServiceUnit(template, { dataDir: DEFAULT_DATA_DIR, prefix: DEFAULT_PREFIX }),
      template,
    );
    const custom = renderServiceUnit(template, { dataDir: "/srv/nmzp", prefix: "/usr/local/nmzp" });
    const model = parseSystemdUnit(custom);
    assert.deepEqual(unitValues(model, "Service", "NoNewPrivileges"), ["true"]);
    assert.deepEqual(unitValues(model, "Service", "ProtectSystem"), ["strict"]);
    assert.deepEqual(unitValues(model, "Service", "User"), ["nmzp"]);
    assert.deepEqual(unitValues(model, "Service", "ReadWritePaths"), ["/srv/nmzp"]);
    assert.ok(unitValues(model, "Service", "Environment").includes("NMZP_BIND=0.0.0.0"));
    assert.match(
      custom,
      /^ExecStart=\/usr\/local\/bin\/node --experimental-strip-types \/usr\/local\/nmzp\/nmzp\.mjs serve$/m,
    );
    assert.deepEqual(INSTALL_PORTS, [8787, 8788]);
  });
});

describe("server install host", () => {
  it("node portFree binds only for the check", async () => {
    const host = createNodeInstallHost();
    const server = createServer();
    server.unref();
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "0.0.0.0", () => resolve());
    });
    const address = server.address();
    const port = address && typeof address === "object" ? address.port : 0;
    try {
      assert.equal(await host.portFree(port), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    assert.equal(await host.portFree(port), true);
  });

  it("rejects a real symlink data directory", { skip: process.platform === "win32" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-install-link-"));
    try {
      const target = join(root, "target");
      const link = join(root, "link");
      mkdirSync(target);
      symlinkSync(target, link);
      const host = createNodeInstallHost();
      const io = capture();
      const code = await runServerInstall(
        { plan: true, dataDir: link, prefix: DEFAULT_PREFIX },
        { host, coreDir, env: {}, ...io },
      );
      assert.equal(code, 1);
      assert.match(io.errText(), /refusing symlink/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("server install hardening", () => {
  it("aborts when a data-directory inode changes between lstat and open", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.ids.uid = 999;
      host.ids.gid = 999;
      host.shell = "/bin/false";
      host.swapOnOpen = "/var";
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /inode changed at \/var/);
      assert.doesNotMatch(result.stderr, /account_conflict/);
      assert.equal(
        host.commands.some((command) => command.cmd.endsWith("useradd")),
        false,
      );
      assert.equal(
        host.commands.some((command) => command.args[0] === "enable"),
        false,
      );
      const stat = await host.lstat("/var");
      assert.equal(stat?.mode, 0o777);
      assert.equal(stat?.uid, 99);
    });
  });

  it("aborts when a data file inode changes between lstat and open", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      await host.mkdir("/var", 0o755);
      await host.mkdir("/var/lib", 0o755);
      await host.mkdir(DATA, 0o700);
      await host.chown(DATA, 960, 960);
      await host.writeFile(`${DATA}/policy.json`, "{}\n", 0o600);
      await host.chown(`${DATA}/policy.json`, 960, 960);
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/nmzp", 0o700);
      await host.writeFile(INSTALL_STATE_PATH, stateJson(), 0o600);
      host.swapOnOpen = `${DATA}/policy.json`;
      const result = await install(host);
      assert.equal(result.code, 1, result.stderr);
      assert.match(result.stderr, /inode changed at \/var\/lib\/nmzp\/policy\.json/);
      host.swapOnOpen = null;
      const stat = await host.lstat(`${DATA}/policy.json`);
      assert.equal(stat?.mode, 0o777);
      assert.equal(stat?.uid, 99);
      assert.equal((await host.readFile(`${DATA}/policy.json`))?.toString("utf8"), "{}\n");
      assert.equal(
        host.commands.some((command) => command.args[0] === "enable"),
        false,
      );
    });
  });

  it("chmods the opened inode when the directory entry is replaced after open", async () => {
    await withHost({}, async (host) => {
      const path = `${DATA}/meta.json`;
      await host.writeFile(path, "old\n", 0o644);
      const handle = await host.openFile(path, {
        write: true,
        create: false,
        exclusive: false,
        mode: 0o644,
      });
      try {
        host.retarget(path);
        await handle.chmod(0o600);
        await handle.chown(960, 960);
        const bound = await handle.stat();
        assert.equal(bound.mode, 0o600);
        assert.equal(bound.uid, 960);
        const visible = await host.lstat(path);
        assert.equal(visible?.mode, 0o777);
        assert.equal(visible?.uid, 99);
        assert.notEqual(visible?.ino, bound.ino);
      } finally {
        await handle.close();
      }
    });
  });

  it("stops nmzp before data-dir writes when the unit already exists", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/systemd", 0o755);
      await host.mkdir("/etc/systemd/system", 0o755);
      await host.writeFile(UNIT_PATH, "unit\n", 0o644);
      host.swapOnOpen = "/var";
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /inode changed at \/var/);
      const stopAt = host.mutations.findIndex((line) => line.includes("systemctl stop nmzp"));
      const dataAt = host.mutations.findIndex((line) => line.startsWith("mkdir /var"));
      assert.ok(stopAt >= 0 && dataAt > stopAt);
      assert.equal(
        host.commands.some((command) => command.args[0] === "enable"),
        false,
      );
    });
  });

  it("stops before any file write when systemctl stop fails", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.failStop = true;
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/systemd", 0o755);
      await host.mkdir("/etc/systemd/system", 0o755);
      await host.writeFile(UNIT_PATH, "unit\n", 0o644);
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /systemctl stop nmzp failed/);
      assert.deepEqual(host.entries(), before);
      assert.equal(
        host.commands.some((command) => command.args[0] === "enable"),
        false,
      );
    });
  });

  it("rejects an existing nmzp account outside the system id range before any write", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.ids.uid = SYSTEM_ID_LIMIT;
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: system id range/);
      assert.deepEqual(host.entries(), before);
      assert.equal(
        host.commands.some((command) => command.cmd.endsWith("useradd")),
        false,
      );
    });
  });

  it("rejects an existing nmzp account whose shell can log in before any write", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.shell = "/bin/bash";
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: shell/);
      assert.deepEqual(host.entries(), before);
    });
  });

  it("rejects an existing nmzp account whose primary group is not nmzp before any write", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.passwdGid = 20;
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: primary group/);
      assert.deepEqual(host.entries(), before);
    });
  });

  it("rechecks the account after useradd and stops before any file write", async () => {
    await withHost({}, async (host) => {
      host.shellAfterCreate = "/bin/sh";
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: shell/);
      assert.deepEqual(host.entries(), before);
      assert.deepEqual(
        host.commands.find((command) => command.cmd.endsWith("useradd"))?.args,
        [
          "--system",
          "--gid",
          "nmzp",
          "--no-create-home",
          "--home-dir",
          "/nonexistent",
          "--shell",
          "/usr/sbin/nologin",
          "nmzp",
        ],
      );
    });
  });

  it("rejects install when state uid/gid does not match getent", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      await host.mkdir("/etc", 0o755);
      await host.mkdir("/etc/nmzp", 0o700);
      await host.writeFile(INSTALL_STATE_PATH, stateJson({ uid: 111, gid: 111 }), 0o600);
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /uid\/gid 111\/111 does not match the nmzp account 960\/960/);
      assert.deepEqual(host.entries(), before);
      assert.ok(host.commands.every((command) => command.cmd.endsWith("getent")));
    });
  });

  it("preserves join tickets when admin.token is missing", { timeout: 120_000 }, async () => {
    await withHost({}, async (host) => {
      await seedTrusted(host, { token: null, hash: "11".repeat(32), tickets: [JOIN_TICKET] });
      const result = await install(host);
      assert.equal(result.code, 0, result.stderr);
      const token = (await host.readFile(`${DATA}/admin.token`))?.toString("utf8").trim() ?? "";
      const meta = (await host.readFile(`${DATA}/meta.json`))?.toString("utf8") ?? "";
      const parsed = JSON.parse(meta) as { adminTokenHash: string; tickets: unknown };
      assert.ok(token);
      assert.equal(parsed.adminTokenHash, sha256Hex(token));
      assert.deepEqual(parsed.tickets, [JOIN_TICKET]);
      assert.equal(meta.includes(token), false);
      assert.equal(result.stderr.includes(token), false);
      const state = (await host.readFile(INSTALL_STATE_PATH))?.toString("utf8") ?? "";
      assert.equal(state.includes(token), false);
    });
  });

  it("preserves join tickets when backfilling a missing adminTokenHash", { timeout: 120_000 }, async () => {
    await withHost({}, async (host) => {
      const token = "kept-admin-token";
      await seedTrusted(host, { token, hash: "", tickets: [JOIN_TICKET] });
      const before = await host.readFile(`${DATA}/admin.token`);
      const result = await install(host);
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(await host.readFile(`${DATA}/admin.token`), before);
      const meta = (await host.readFile(`${DATA}/meta.json`))?.toString("utf8") ?? "";
      const parsed = JSON.parse(meta) as { adminTokenHash: string; tickets: unknown };
      assert.equal(parsed.adminTokenHash, sha256Hex(token));
      assert.deepEqual(parsed.tickets, [JOIN_TICKET]);
      assert.equal(meta.includes(token), false);
      assert.equal(result.stdout.includes(token), false);
      assert.equal(result.stderr.includes(token), false);
      assertAtomicRename(
        host.mutations,
        /^rename \/var\/lib\/nmzp\/meta\.json\..+\.tmp \/var\/lib\/nmzp\/meta\.json$/,
        DATA,
        host.ids.uid,
        host.ids.gid,
      );
      const metaStat = await host.lstat(`${DATA}/meta.json`);
      assert.equal(metaStat?.mode, 0o600);
      assert.equal(metaStat?.uid, host.ids.uid);
      assert.equal(metaStat?.gid, host.ids.gid);
    });
  });

  it(
    "reloads and enables nmzp even when serviceEnabled is already true",
    { timeout: 120_000 },
    async () => {
      await withHost({}, async (host) => {
        await seedTrusted(host, {
          token: "kept-admin-token",
          hash: sha256Hex("kept-admin-token"),
          tickets: [JOIN_TICKET],
          serviceEnabled: true,
        });
        const template = await readFile(join(coreDir, "nmzp.service"), "utf8");
        const unit = renderServiceUnit(template, { dataDir: DATA, prefix: DEFAULT_PREFIX });
        await host.mkdir("/etc/systemd", 0o755);
        await host.mkdir("/etc/systemd/system", 0o755);
        await host.writeFile(UNIT_PATH, unit, 0o644);
        const metaBefore = await host.readFile(`${DATA}/meta.json`);
        const result = await install(host);
        assert.equal(result.code, 0, result.stderr);
        assert.match(result.stdout, /service: skip/);
        assert.match(result.stdout, /start: systemctl daemon-reload; systemctl enable --now nmzp/);
        assert.equal(result.stdout.includes("start: skip"), false);
        assert.ok(host.commands.some((command) => command.args.join(" ") === "daemon-reload"));
        assert.ok(host.commands.some((command) => command.args.join(" ") === "enable --now nmzp"));
        assert.ok(host.commands.some((command) => command.args.join(" ") === "stop nmzp"));
        const metaRaw = await host.readFile(`${DATA}/meta.json`);
        assert.deepEqual(metaRaw, metaBefore);
        const meta = JSON.parse(metaRaw?.toString("utf8") ?? "{}") as {
          tickets: unknown;
        };
        assert.deepEqual(meta.tickets, [JOIN_TICKET]);
      });
    },
  );

  it("refuses a non-sticky seed parent and a seed dir that is not root mode 0700", async () => {
    assert.equal(SYSTEM_ID_LIMIT, 1000);
    assert.equal(isSystemAccountId(0), false);
    assert.equal(isSystemAccountId(1), true);
    assert.equal(isSystemAccountId(999), true);
    assert.equal(isSystemAccountId(1000), false);
    const sticky = {
      type: "dir" as const,
      mode: 0o777,
      uid: 0,
      gid: 0,
      dev: 1,
      ino: 1,
      special: 0o1000,
    };
    assert.doesNotThrow(() => assertSeedParent(sticky));
    assert.throws(() => assertSeedParent({ ...sticky, special: 0 }), /not sticky/);
    const rooted: HostStat = {
      type: "dir",
      mode: 0o700,
      uid: 0,
      gid: 0,
      dev: 1,
      ino: 1,
      special: 0,
    };
    assert.doesNotThrow(() => assertSeedDir(rooted));
    assert.throws(() => assertSeedDir({ ...rooted, mode: 0o755 }), /0700/);
    assert.throws(() => assertSeedDir({ ...rooted, uid: 4 }), /root-owned/);
    await withHost({}, async (host) => {
      host.seedParent = { ...host.seedParent, special: 0 };
      await assert.rejects(() => host.generatorDir(), /not sticky/);
      host.seedParent = { ...host.seedParent, special: 0o1000 };
      host.modelSeed = { ...rooted, mode: 0o755 };
      await assert.rejects(() => host.generatorDir(), /0700/);
      host.modelSeed = { ...rooted, uid: 4, gid: 4 };
      await assert.rejects(() => host.generatorDir(), /root-owned/);
    });
  });

  it("refuses to discard a seed directory whose inode changed", async () => {
    await withHost({}, async (host) => {
      const dir = await host.generatorDir();
      try {
        host.mismatchSeed(dir);
        await assert.rejects(() => host.discardGeneratorDir(dir), /seed dir changed/);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  it("does not follow a symlink when opening a file", { skip: process.platform !== "linux" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-install-nofollow-"));
    try {
      const target = join(root, "target");
      const link = join(root, "link");
      await writeFile(target, "safe");
      symlinkSync(target, link);
      const host = createNodeInstallHost();
      await assert.rejects(
        () => host.openFile(link, { write: true, create: false, exclusive: false, mode: 0o600 }),
        /refusing symlink/,
      );
      assert.equal(await readFile(target, "utf8"), "safe");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not follow a directory symlink", { skip: process.platform !== "linux" }, async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-install-nodir-"));
    try {
      const real = join(root, "real");
      const link = join(root, "link");
      mkdirSync(real);
      symlinkSync(real, link);
      const host = createNodeInstallHost();
      await assert.rejects(() => host.openDir(link), /refusing symlink/);
      const st = await lstatAsync(real);
      assert.equal(st.isDirectory(), true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it(
    "creates the seed directory under sticky /tmp as root",
    {
      skip:
        process.platform !== "linux" ||
        typeof process.getuid !== "function" ||
        process.getuid() !== 0,
    },
    async () => {
      const host = createNodeInstallHost();
      const dir = await host.generatorDir();
      try {
        assert.match(dir, /^\/tmp\/nmzp-install-seed-/);
        const st = await lstatAsync(dir);
        assert.equal(st.isSymbolicLink(), false);
        assert.equal(st.uid, 0);
        assert.equal(st.gid, 0);
        assert.equal(st.mode & 0o777, 0o700);
      } finally {
        await host.discardGeneratorDir(dir);
      }
    },
  );
});

describe("server install review round 2", () => {
  it("rejects a seed parent that is not root-owned or is a symlink", async () => {
    const sticky: HostStat = {
      type: "dir",
      mode: 0o777,
      uid: 0,
      gid: 0,
      dev: 1,
      ino: 1,
      special: 0o1000,
    };
    assert.throws(() => assertSeedParent({ ...sticky, uid: 1 }), /not root-owned/);
    assert.throws(() => assertSeedParent({ ...sticky, type: "symlink" }), /symlink/);
    assert.doesNotThrow(() => assertSeedParent({ ...sticky, gid: 7 }));
    await withHost({}, async (host) => {
      host.seedParent = { ...host.seedParent, uid: 1 };
      await assert.rejects(() => host.generatorDir(), /not root-owned/);
      host.seedParent = { ...host.seedParent, uid: 0, type: "symlink" };
      await assert.rejects(() => host.generatorDir(), /symlink/);
    });
  });

  it("parses login.defs limits and accepts nologin and false shells", async () => {
    assert.equal(SYSTEM_ID_MAX_FALLBACK, 999);
    assert.equal(SYSTEM_ID_LIMIT, SYSTEM_ID_MAX_FALLBACK + 1);
    assert.deepEqual(
      [...NMZP_SYSTEM_SHELLS],
      ["/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/bin/false", "/usr/bin/false"],
    );
    assert.deepEqual(parseLoginDefsLimits(""), { uidMax: 999, gidMax: 999 });
    assert.deepEqual(
      parseLoginDefsLimits("# SYS_UID_MAX 100\n\nUID_MIN 1000\nSYS_UID_MIN 100\n"),
      { uidMax: 999, gidMax: 999 },
    );
    assert.deepEqual(parseLoginDefsLimits("SYS_UID_MAX\t499\nSYS_GID_MAX 200\n"), {
      uidMax: 499,
      gidMax: 200,
    });
    assert.deepEqual(parseLoginDefsLimits("SYS_UID_MAX nope\nSYS_GID_MAX -1\nSYS_UID_MAX=\n"), {
      uidMax: 999,
      gidMax: 999,
    });
    assert.deepEqual(
      parseLoginDefsLimits("SYS_UID_MAX 100\nSYS_UID_MAX abc\nSYS_UID_MAX 1500\nSYS_GID_MAX 1200\n"),
      { uidMax: 1500, gidMax: 1200 },
    );
    assert.deepEqual(parseLoginDefsLimits(`SYS_UID_MAX ${Number.MAX_SAFE_INTEGER + 1}\n`), {
      uidMax: 999,
      gidMax: 999,
    });
    assert.equal(isSystemAccountId(1500, 1500), true);
    assert.equal(isSystemAccountId(1501, 1500), false);
    assert.equal(isSystemAccountId(0, 1500), false);
    for (const shell of NMZP_SYSTEM_SHELLS) {
      await withHost({}, async (host) => {
        host.groupPresent = true;
        host.userPresent = true;
        host.shell = shell;
        host.swapOnOpen = "/var";
        const result = await install(host);
        assert.equal(result.code, 1, shell);
        assert.doesNotMatch(result.stderr, /account_conflict: shell/);
        assert.match(result.stderr, /inode changed at \/var/);
      });
    }
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.shell = "/bin/nologin";
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: shell/);
      assert.deepEqual(host.entries(), before);
    });
  });

  it("reads SYS_UID_MAX and SYS_GID_MAX through the host and ignores a symlink", async () => {
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.ids.uid = 1500;
      host.ids.gid = 1500;
      await host.mkdir("/etc", 0o755);
      await host.writeFile(LOGIN_DEFS_PATH, "SYS_UID_MAX 1500\nSYS_GID_MAX 1500\n", 0o644);
      host.swapOnOpen = "/var";
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.doesNotMatch(result.stderr, /system id range/);
      assert.match(result.stderr, /inode changed at \/var/);
    });
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.ids.uid = 100;
      host.ids.gid = 50;
      await host.mkdir("/etc", 0o755);
      await host.writeFile(LOGIN_DEFS_PATH, "SYS_UID_MAX 999\nSYS_GID_MAX 40\n", 0o644);
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: system id range/);
      assert.deepEqual(host.entries(), before);
    });
    await withHost({}, async (host) => {
      host.groupPresent = true;
      host.userPresent = true;
      host.ids.uid = 1500;
      host.ids.gid = 1500;
      await host.mkdir("/etc", 0o755);
      await host.writeFile("/etc/evil-defs", "SYS_UID_MAX 2000\nSYS_GID_MAX 2000\n", 0o644);
      host.symlink(LOGIN_DEFS_PATH, "/etc/evil-defs");
      const before = host.entries();
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /account_conflict: system id range/);
      assert.deepEqual(host.entries(), before);
    });
  });

  it("leaves meta.json and tickets unchanged when the atomic patch write fails", { timeout: 120_000 }, async () => {
    await withHost({}, async (host) => {
      const token = "kept-admin-token";
      await seedTrusted(host, { token, hash: "", tickets: [JOIN_TICKET] });
      const beforeMeta = await host.readFile(`${DATA}/meta.json`);
      const beforeToken = await host.readFile(`${DATA}/admin.token`);
      const before = host.entries();
      host.failWrite = (path) => path.startsWith(`${DATA}/meta.json.`) && path.endsWith(".tmp");
      const result = await install(host);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /simulated write failure/);
      assert.deepEqual(await host.readFile(`${DATA}/meta.json`), beforeMeta);
      assert.deepEqual(await host.readFile(`${DATA}/admin.token`), beforeToken);
      const parsed = JSON.parse(beforeMeta?.toString("utf8") ?? "{}") as { tickets: unknown };
      assert.deepEqual(parsed.tickets, [JOIN_TICKET]);
      assert.deepEqual(
        JSON.parse((await host.readFile(`${DATA}/meta.json`))?.toString("utf8") ?? "{}"),
        JSON.parse(beforeMeta?.toString("utf8") ?? "{}"),
      );
      assert.deepEqual(host.entries(), before);
      assert.equal(
        host.entries().some((entry) => entry.path.includes(".tmp")),
        false,
      );
      assert.equal(
        host.mutations.some((line) => line.startsWith(`rename ${DATA}/meta.json.`)),
        false,
      );
      assert.equal(result.stdout.includes(token), false);
      assert.equal(result.stderr.includes(token), false);
    });
  });

  it("stops on admin_token_hash_mismatch without changing meta or the token", async () => {
    const token = "kept-admin-token";
    const digest = sha256Hex(token);
    for (const hash of [sha256Hex("other-token"), `${digest}zz`, digest.toUpperCase()]) {
      await withHost({}, async (host) => {
        await seedTrusted(host, { token, hash, tickets: [JOIN_TICKET] });
        const beforeMeta = await host.readFile(`${DATA}/meta.json`);
        const beforeToken = await host.readFile(`${DATA}/admin.token`);
        const before = host.entries();
        const result = await install(host);
        assert.equal(result.code, 1);
        assert.equal(result.stderr, "admin_token_hash_mismatch\n");
        assert.equal(result.stdout, "");
        assert.deepEqual(host.entries(), before);
        assert.deepEqual(await host.readFile(`${DATA}/meta.json`), beforeMeta);
        assert.deepEqual(await host.readFile(`${DATA}/admin.token`), beforeToken);
        assert.equal(host.commands.length, 0);
        const parsed = JSON.parse(beforeMeta?.toString("utf8") ?? "{}") as { tickets: unknown };
        assert.deepEqual(parsed.tickets, [JOIN_TICKET]);
      });
    }
  });
});

describe("server install cli", () => {
  it("help lists install", async () => {
    const result = await spawnCli(["help"]);
    assert.equal(result.code, 0, result.stderr);
    assert.match(
      result.stdout,
      /nmzp install \[--public-url URL\] \[--data DIR\] \[--prefix DIR\] \[--plan\]/,
    );
  });

  it(
    "windows cli exits with the WP-60 message",
    { skip: process.platform !== "win32" },
    async () => {
      const result = await spawnCli(["install", "--plan"]);
      assert.notEqual(result.code, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /Windows server install is WP-60/);
    },
  );
});

async function seedTlsParents(host: RecordingInstallHost): Promise<void> {
  await host.mkdir("/var", 0o755);
  await host.mkdir("/var/lib", 0o755);
  await host.mkdir(DATA, 0o755);
  await host.mkdir(`${DATA}/tls`, 0o755);
}

async function seedTrusted(
  host: RecordingInstallHost,
  opts: {
    token: string | null;
    hash: string;
    tickets: Array<{ hash: string; expiresAt: number; consumed: boolean }>;
    serviceEnabled?: boolean;
  },
): Promise<void> {
  host.groupPresent = true;
  host.userPresent = true;
  await host.mkdir("/var", 0o755);
  await host.mkdir("/var/lib", 0o755);
  await host.mkdir(DATA, 0o700);
  await host.chown(DATA, host.ids.uid, host.ids.gid);
  await host.mkdir(`${DATA}/tls`, 0o700);
  await host.chown(`${DATA}/tls`, host.ids.uid, host.ids.gid);
  const material = generateNmzpCert();
  await host.writeFile(`${DATA}/tls/server.key`, material.keyPem, 0o600);
  await host.writeFile(`${DATA}/tls/server.crt`, material.certPem, 0o600);
  await host.writeFile(
    `${DATA}/tls/pin.json`,
    `${JSON.stringify({ fingerprintSha256: material.fingerprintSha256, hosts: material.hosts }, null, 2)}\n`,
    0o600,
  );
  for (const name of ["server.key", "server.crt", "pin.json"]) {
    await host.chown(`${DATA}/tls/${name}`, host.ids.uid, host.ids.gid);
  }
  const policy = JSON.stringify(
    { version: 1, mode: "enforcing", customRules: [], stopped: false, updatedAt: 0 },
    null,
    2,
  );
  await host.writeFile(`${DATA}/policy.json`, `${policy}\n`, 0o600);
  await host.chown(`${DATA}/policy.json`, host.ids.uid, host.ids.gid);
  await host.writeFile(
    `${DATA}/meta.json`,
    `${JSON.stringify({ adminTokenHash: opts.hash, tickets: opts.tickets }, null, 2)}\n`,
    0o600,
  );
  await host.chown(`${DATA}/meta.json`, host.ids.uid, host.ids.gid);
  if (opts.token) {
    await host.writeFile(`${DATA}/admin.token`, `${opts.token}\n`, 0o600);
    await host.chown(`${DATA}/admin.token`, host.ids.uid, host.ids.gid);
  }
  await host.mkdir("/etc", 0o755);
  await host.mkdir("/etc/nmzp", 0o700);
  await host.writeFile(
    INSTALL_STATE_PATH,
    stateJson({ tokenShown: true, serviceEnabled: opts.serviceEnabled ?? true }),
    0o600,
  );
}

function spawnCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", join(coreDir, "nmzp.mjs"), ...args],
      {
        env: { ...process.env },
        windowsHide: true,
      },
    );
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ stdout, stderr, code: 1 });
    }, 30_000);
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
