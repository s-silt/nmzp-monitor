import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { lstatSync, mkdirSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { join } from "node:path";
import { describe, it } from "node:test";
import { codexHookEntry, codexHookTrust, mergeCodexHooks } from "../codex-hooks.ts";
import { NMZP_VERSION } from "../constants.ts";
import { sha256Text } from "../install-fs.ts";
import { ENGINE_REVISION } from "../policy/engine-revision.ts";
import { PolicyHistory } from "../policy/history.ts";
import { policyRulesHash } from "../policy/nmzp-service.ts";
import { createPolicySnapshot } from "../policy/snapshot.ts";
import { generateNmzpCert } from "../tls.ts";
import { isProtectedRule } from "../../src/lib/monitor/overrides.ts";
import { RULES } from "../../src/lib/monitor/rules.ts";
import {
  classifyAdapters,
  classifyAudit,
  classifyBinary,
  classifyConfig,
  classifyDisk,
  classifyFriction,
  classifyHookConfig,
  classifyHookObserved,
  classifyHostTrust,
  classifyIdentity,
  classifyPolicy,
  classifyProtected,
  classifyQueues,
  classifyService,
  classifyStorage,
  classifyTls,
  classifyVersion,
  type HostTrustStatus,
  type StorageInput,
} from "./classify.ts";
import { runDoctor, isolateCheck, type DoctorOptions } from "./run.ts";
import { readStatusExtras } from "./status.ts";
import { validateDoctorReport, loadDoctorSchema } from "./schema-validate.ts";
import {
  CHECK_IDS,
  DISK_MIN_FREE_BYTES,
  FRICTION_HIGH_COUNT,
  NOT_AVAILABLE_SUMMARY,
  OUTBOX_FULL_ITEMS,
  aggregateOverall,
  checksForRole,
  doctorExitCode,
  formatDoctorText,
  type CheckId,
  type DoctorCheck,
  type DoctorReport,
} from "./report.ts";

const doctorDir = import.meta.dirname;
const coreDir = join(doctorDir, "..");
const entry = join(coreDir, "nmzp.mjs");
const SECRET = "nmzp-doctor-secret-7f3c1a9e";
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----\n${SECRET}\n-----END PRIVATE KEY-----\n`;

function doctor(home: string, data: string, options: DoctorOptions = {}): Promise<DoctorReport> {
  return runDoctor({ ...options, home, dataDir: data, env: options.env ?? {} });
}

function byId(report: DoctorReport, id: CheckId): DoctorCheck {
  const found = report.checks.find((item) => item.id === id);
  assert.ok(found, id);
  return found;
}

async function tempTree(): Promise<{ root: string; home: string; data: string }> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-doctor-"));
  const home = join(root, "home");
  const data = join(root, "data");
  await mkdir(home);
  await mkdir(data);
  return { root, home, data };
}

function mkdir(path: string): Promise<void> {
  mkdirSync(path, { recursive: true });
  return Promise.resolve();
}

function policyBody(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1,
    updatedAt: 1,
    mode: "enforcing",
    stopped: false,
    customRules: [],
    ...extra,
  });
}

function servePointer(pid: number): string {
  return JSON.stringify({
    pid,
    host: "127.0.0.1",
    port: 8787,
    url: "https://127.0.0.1:8787",
    fingerprintSha256: "ab".repeat(32),
    startedAt: 1,
  });
}

function childEnv(home: string, data: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ["NMZP_BIND", "NMZP_PORT", "NMZP_PUBLIC_URL", "NMZP_STORAGE_MODE", "NMZP_HOME", "NMZP_DATA"]) {
    delete env[key];
  }
  return { ...env, ...extra, NMZP_HOME: home, NMZP_DATA: data, USERPROFILE: home, HOME: home };
}

function spawnCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...args], {
      env,
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

async function treeSnapshot(root: string): Promise<string> {
  const rows: string[] = [];
  async function walk(dir: string): Promise<void> {
    const names = (await readdir(dir)).sort();
    for (const name of names) {
      const path = join(dir, name);
      const st = lstatSync(path);
      const rel = path.slice(root.length);
      if (st.isDirectory()) {
        rows.push(`${rel}\tdir\t${st.size}\t${st.mtimeMs}\t${st.mode}`);
        await walk(path);
      } else {
        const body = await readFile(path);
        const sha = createHash("sha256").update(body).digest("hex");
        rows.push(`${rel}\t${st.size}\t${st.mtimeMs}\t${st.mode}\t${sha}`);
      }
    }
  }
  await walk(root);
  return rows.join("\n");
}

const storageBase = (): StorageInput => ({
  mode: "window",
  policy: "ok",
  schemaVersion: null,
  devices: "missing",
  devicesSnapshot: null,
  db: "missing",
  integrity: "skipped",
  history: "skipped",
  auditFormat: null,
});

describe("doctor report contract", () => {
  it("ranks ERROR above WARN above UNKNOWN above OK", () => {
    assert.equal(aggregateOverall([]), "OK");
    assert.equal(aggregateOverall(["OK", "OK"]), "OK");
    assert.equal(aggregateOverall(["OK", "UNKNOWN"]), "UNKNOWN");
    assert.equal(aggregateOverall(["UNKNOWN", "WARN"]), "WARN");
    assert.equal(aggregateOverall(["WARN", "ERROR", "UNKNOWN", "OK"]), "ERROR");
    assert.equal(doctorExitCode({ overall: "ERROR" }), 1);
    assert.equal(doctorExitCode({ overall: "WARN" }), 0);
    assert.equal(doctorExitCode({ overall: "UNKNOWN" }), 0);
    assert.equal(doctorExitCode({ overall: "OK" }), 0);
  });

  it("emits only the checks that apply to the role", () => {
    const server = checksForRole("server");
    const device = checksForRole("device");
    const unknown = checksForRole("unknown");
    assert.equal(server.length, 17);
    assert.equal(device.length, 17);
    assert.equal(unknown.length, 13);
    assert.equal(server.includes("storage"), true);
    assert.equal(server.includes("hook_config"), false);
    assert.equal(device.includes("hook_config"), true);
    assert.equal(device.includes("storage"), false);
    assert.deepEqual(unknown, CHECK_IDS.filter((id) => server.includes(id) && device.includes(id)));
    const schema = loadDoctorSchema();
    const props = schema.properties as { checks: { items: { properties: { id: { enum: string[] } } } } };
    const ref = (schema.$defs as { check: { properties: { id: { enum: string[] } } } }).check.properties.id.enum;
    assert.deepEqual(ref, [...CHECK_IDS]);
    assert.equal(props, props);
  });
});

describe("doctor check classifiers", () => {
  it("binary: missing or bad signature is ERROR, no signature source is never OK or WARN", () => {
    assert.equal(classifyBinary({ exists: false, signature: "not_available", path: "~/.nmzp/runtime/nmzp.mjs" }).status, "ERROR");
    assert.equal(classifyBinary({ exists: true, signature: "bad", path: "nmzp" }).status, "ERROR");
    assert.equal(classifyBinary({ exists: true, signature: "ok", path: "nmzp" }).status, "OK");
    const unavailable = classifyBinary({ exists: true, signature: "not_available", path: "nmzp" });
    assert.equal(unavailable.status, "UNKNOWN");
    assert.equal(unavailable.summary, NOT_AVAILABLE_SUMMARY);
    assert.equal(unavailable.details.reason, "not_available");
    for (const signature of ["ok", "bad", "not_available"] as const) {
      assert.notEqual(classifyBinary({ exists: true, signature, path: "nmzp" }).status, "WARN");
      assert.notEqual(classifyBinary({ exists: false, signature, path: "nmzp" }).status, "WARN");
    }
  });

  it("version: compares engine revisions and does not invent WARN", () => {
    assert.equal(classifyVersion({ local: 2, required: 2 }).status, "OK");
    assert.equal(classifyVersion({ local: 3, required: 2 }).status, "OK");
    assert.equal(classifyVersion({ local: 1, required: 2 }).status, "ERROR");
    const missing = classifyVersion({ local: ENGINE_REVISION, required: null });
    assert.equal(missing.status, "UNKNOWN");
    assert.equal(missing.summary, NOT_AVAILABLE_SUMMARY);
    assert.notEqual(missing.status, "OK");
    for (const required of [null, 1, 2, 9]) {
      assert.notEqual(classifyVersion({ local: 2, required }).status, "WARN");
    }
  });

  it("service: running, stopped, or no manager; never WARN", () => {
    assert.equal(classifyService("running").status, "OK");
    assert.equal(classifyService("stopped").status, "ERROR");
    assert.equal(classifyService(null).status, "UNKNOWN");
    assert.equal(classifyService(null).details.code, "platform_manager_unavailable");
    for (const state of ["running", "stopped", null] as const) assert.notEqual(classifyService(state).status, "WARN");
  });

  it("storage: schema and integrity errors, unreadable UNKNOWN, never WARN", () => {
    assert.equal(classifyStorage(storageBase()).status, "OK");
    assert.equal(classifyStorage({ ...storageBase(), schemaVersion: 2 }).status, "ERROR");
    assert.equal(classifyStorage({ ...storageBase(), policy: "invalid" }).status, "ERROR");
    assert.equal(classifyStorage({ ...storageBase(), mode: "window", db: "present" }).status, "ERROR");
    assert.equal(classifyStorage({ ...storageBase(), mode: "sqlite", db: "missing" }).status, "ERROR");
    assert.equal(
      classifyStorage({ ...storageBase(), mode: "sqlite", db: "present", integrity: "bad", history: "ok" }).status,
      "ERROR",
    );
    assert.equal(classifyStorage({ ...storageBase(), policy: "unreadable" }).status, "UNKNOWN");
    assert.equal(classifyStorage({ ...storageBase(), integrity: "unreadable" }).status, "UNKNOWN");
    assert.equal(classifyStorage({ ...storageBase(), mode: "invalid" }).status, "UNKNOWN");
    const samples: StorageInput[] = [
      storageBase(),
      { ...storageBase(), schemaVersion: 2 },
      { ...storageBase(), policy: "unreadable" },
      { ...storageBase(), mode: "invalid" },
    ];
    for (const sample of samples) assert.notEqual(classifyStorage(sample).status, "WARN");
  });

  it("disk: 200 MiB is OK and one byte under is ERROR", () => {
    assert.equal(classifyDisk({ freeBytes: DISK_MIN_FREE_BYTES }).status, "OK");
    assert.equal(classifyDisk({ freeBytes: DISK_MIN_FREE_BYTES - 1 }).status, "ERROR");
    assert.equal(classifyDisk({ freeBytes: DISK_MIN_FREE_BYTES + 1 }).status, "OK");
    assert.equal(classifyDisk({ freeBytes: null, code: "statfs_failed" }).status, "UNKNOWN");
    for (const freeBytes of [null, 0, DISK_MIN_FREE_BYTES - 1, DISK_MIN_FREE_BYTES]) {
      assert.notEqual(classifyDisk({ freeBytes }).status, "WARN");
    }
  });

  it("tls: expiry, pin, and SAN are ERROR; missing material is UNKNOWN; never WARN", () => {
    const present = {
      material: "present" as const,
      expired: false,
      san: "unchecked" as const,
      fingerprint: "ok" as const,
    };
    assert.equal(classifyTls(present).status, "OK");
    assert.equal(classifyTls({ ...present, fingerprint: "unchecked", san: "ok" }).status, "OK");
    assert.equal(classifyTls({ ...present, expired: true }).status, "ERROR");
    assert.equal(classifyTls({ ...present, fingerprint: "mismatch" }).status, "ERROR");
    assert.equal(classifyTls({ ...present, san: "mismatch" }).status, "ERROR");
    assert.equal(classifyTls({ ...present, material: "absent", fingerprint: "unchecked" }).status, "UNKNOWN");
    assert.equal(classifyTls({ ...present, material: "invalid", fingerprint: "unchecked" }).status, "UNKNOWN");
    assert.equal(classifyTls({ ...present, fingerprint: "unchecked" }).status, "UNKNOWN");
    assert.notEqual(classifyTls(present).status, "WARN");
    assert.notEqual(classifyTls({ ...present, expired: true }).status, "WARN");
  });

  it("identity: wide permissions or revocation are ERROR and are not auto-fixed", () => {
    assert.equal(classifyIdentity({ perm: "ok", revoked: false }).status, "OK");
    const wide = classifyIdentity({ perm: "wide", revoked: false });
    assert.equal(wide.status, "ERROR");
    assert.match(wide.remediation ?? "", /不会 chmod/);
    assert.equal(classifyIdentity({ perm: "ok", revoked: true }).status, "ERROR");
    assert.equal(classifyIdentity({ perm: "unknown", revoked: false }).status, "UNKNOWN");
    assert.equal(classifyIdentity({ perm: "ok", revoked: null }).status, "UNKNOWN");
    for (const perm of ["ok", "wide", "unknown"] as const) {
      for (const revoked of [true, false, null]) assert.notEqual(classifyIdentity({ perm, revoked }).status, "WARN");
    }
  });

  it("policy: hash mismatch is ERROR, invalid cache is UNKNOWN, missing hash is not OK", () => {
    assert.equal(classifyPolicy({ cache: "valid", headRulesHash: "aa", engineRulesHash: "aa" }).status, "OK");
    assert.equal(classifyPolicy({ cache: "valid", headRulesHash: "aa", engineRulesHash: "bb" }).status, "ERROR");
    const expired = classifyPolicy({ cache: "invalid", headRulesHash: null, engineRulesHash: null });
    assert.equal(expired.status, "UNKNOWN");
    assert.equal(expired.details.reason, "cache_expired");
    const missing = classifyPolicy({ cache: "missing", headRulesHash: null, engineRulesHash: null });
    assert.equal(missing.status, "UNKNOWN");
    assert.equal(missing.summary, NOT_AVAILABLE_SUMMARY);
    assert.notEqual(missing.status, "OK");
    assert.notEqual(expired.status, "WARN");
    assert.notEqual(classifyPolicy({ cache: "valid", headRulesHash: "aa", engineRulesHash: "aa" }).status, "WARN");
  });

  it("protected rules: downgrade is ERROR and the empty set is OK", () => {
    assert.equal(classifyProtected({ downgrades: [] }).status, "OK");
    const bad = classifyProtected({ downgrades: ["credential_file_upload"] });
    assert.equal(bad.status, "ERROR");
    assert.match(bad.remediation ?? "", /不会放宽/);
    assert.equal(classifyProtected({ downgrades: null, code: "policy_unreadable" }).status, "UNKNOWN");
    assert.notEqual(classifyProtected({ downgrades: [] }).status, "WARN");
    assert.notEqual(bad.status, "WARN");
  });

  it("audit: corrupt or a down worker is ERROR; an unobservable worker is not OK", () => {
    assert.equal(classifyAudit({ mode: "window", corruptCount: 0, worker: "not_applicable" }).status, "OK");
    assert.equal(classifyAudit({ mode: "sqlite", corruptCount: 0, worker: "ready" }).status, "OK");
    assert.equal(classifyAudit({ mode: "window", corruptCount: 2, worker: "not_applicable" }).status, "ERROR");
    assert.equal(classifyAudit({ mode: "window", corruptCount: 0, worker: "not_ready" }).status, "ERROR");
    const hidden = classifyAudit({ mode: "sqlite", corruptCount: null, worker: "unknown" });
    assert.equal(hidden.status, "UNKNOWN");
    assert.notEqual(hidden.status, "OK");
    assert.notEqual(classifyAudit({ mode: "window", corruptCount: 0, worker: "not_applicable" }).status, "WARN");
    assert.notEqual(hidden.status, "WARN");
  });

  it("backup, evidence, update, and ct reachability stay UNKNOWN without a 0.x source", async () => {
    const { home, data, root } = await tempTree();
    try {
      const report = await doctor(home, data);
      for (const id of ["backup", "evidence_freshness", "update_status", "ct_reachability"] as const) {
        if (!report.checks.some((item) => item.id === id)) continue;
        const item = byId(report, id);
        assert.equal(item.status, "UNKNOWN");
        assert.equal(item.summary, NOT_AVAILABLE_SUMMARY);
        assert.equal(item.details.reason, "not_available");
        assert.notEqual(item.status, "OK");
        assert.notEqual(item.status, "WARN");
        assert.notEqual(item.status, "ERROR");
      }
      assert.equal(report.checks.some((item) => item.id === "ct_reachability"), false);
      const device = await doctor(home, data, {});
      assert.equal(device.role, "unknown");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("config: illegal security settings are ERROR, non-loopback bind is WARN, never UNKNOWN", () => {
    assert.equal(
      classifyConfig({
        role: "server",
        storageModeInvalid: false,
        portInvalid: false,
        publicUrlInvalid: false,
        bind: "loopback",
        cacheInvalid: false,
      }).status,
      "OK",
    );
    const warn = classifyConfig({
      role: "server",
      storageModeInvalid: false,
      portInvalid: false,
      publicUrlInvalid: false,
      bind: "unset",
      cacheInvalid: false,
    });
    assert.equal(warn.status, "WARN");
    assert.match(warn.remediation ?? "", /不会改绑定/);
    const deviceWarn = classifyConfig({
      role: "device",
      storageModeInvalid: false,
      portInvalid: false,
      publicUrlInvalid: false,
      bind: "unset",
      cacheInvalid: true,
    });
    assert.equal(deviceWarn.status, "WARN");
    assert.equal(
      classifyConfig({
        role: "server",
        storageModeInvalid: true,
        portInvalid: false,
        publicUrlInvalid: false,
        bind: "loopback",
        cacheInvalid: false,
      }).status,
      "ERROR",
    );
    assert.notEqual(warn.status, "UNKNOWN");
    assert.notEqual(
      classifyConfig({
        role: "device",
        storageModeInvalid: false,
        portInvalid: true,
        publicUrlInvalid: false,
        bind: "unset",
        cacheInvalid: false,
      }).status,
      "UNKNOWN",
    );
  });

  it("friction only warns and does not offer a relax action", () => {
    assert.equal(classifyFriction([]).status, "OK");
    assert.equal(classifyFriction([{ ruleId: "a", count: FRICTION_HIGH_COUNT - 1, samples: [] }]).status, "OK");
    const hot = classifyFriction([{ ruleId: "a", count: FRICTION_HIGH_COUNT, samples: ["evt"] }]);
    assert.equal(hot.status, "WARN");
    assert.match(hot.remediation ?? "", /不会放宽/);
    assert.doesNotMatch(hot.remediation ?? "", /casPolicy|nmzp rules/);
    assert.equal(classifyFriction(null, "events_unreadable").status, "UNKNOWN");
    for (const count of [0, FRICTION_HIGH_COUNT - 1, FRICTION_HIGH_COUNT, 10_000]) {
      assert.notEqual(classifyFriction([{ ruleId: "a", count, samples: [] }]).status, "ERROR");
    }
  });

  it("queues: device outbox drops are ERROR, server lanes are not OK, never WARN", () => {
    assert.equal(classifyQueues({ role: "device", outbox: "ok" }).status, "OK");
    assert.equal(classifyQueues({ role: "device", outbox: "missing" }).status, "OK");
    assert.equal(classifyQueues({ role: "device", outbox: "dropped" }).status, "ERROR");
    assert.equal(classifyQueues({ role: "device", outbox: "full" }).status, "ERROR");
    assert.equal(classifyQueues({ role: "device", outbox: "corrupt" }).status, "UNKNOWN");
    const server = classifyQueues({ role: "server", outbox: "ok" });
    assert.equal(server.status, "UNKNOWN");
    assert.equal(server.summary, NOT_AVAILABLE_SUMMARY);
    assert.notEqual(server.status, "OK");
    assert.equal(OUTBOX_FULL_ITEMS, 256);
    for (const outbox of ["missing", "ok", "full", "dropped", "corrupt"] as const) {
      assert.notEqual(classifyQueues({ role: "device", outbox }).status, "WARN");
    }
  });

  it("adapters: no hosts is UNKNOWN, a range mismatch is ERROR, and 0.x has no range to OK", () => {
    assert.equal(classifyAdapters({ hosts: 0, unreadable: false, ranges: "unavailable", mismatches: [] }).details.reason, "no_hosts");
    assert.equal(classifyAdapters({ hosts: 1, unreadable: false, ranges: "checked", mismatches: [] }).status, "OK");
    assert.equal(classifyAdapters({ hosts: 1, unreadable: false, ranges: "checked", mismatches: ["codex-cli"] }).status, "ERROR");
    const missingRange = classifyAdapters({ hosts: 2, unreadable: false, ranges: "unavailable", mismatches: [] });
    assert.equal(missingRange.status, "UNKNOWN");
    assert.equal(missingRange.summary, NOT_AVAILABLE_SUMMARY);
    assert.notEqual(missingRange.status, "OK");
    assert.equal(classifyAdapters({ hosts: 0, unreadable: true, ranges: "unavailable", mismatches: [] }).status, "UNKNOWN");
    assert.notEqual(missingRange.status, "WARN");
    assert.notEqual(classifyAdapters({ hosts: 0, unreadable: false, ranges: "unavailable", mismatches: [] }).status, "WARN");
  });

  it("hook config: hash match, mismatch, and unreadable", () => {
    assert.equal(classifyHookConfig({ records: "match" }).status, "OK");
    assert.equal(classifyHookConfig({ records: "mismatch" }).status, "ERROR");
    assert.equal(classifyHookConfig({ records: "none" }).status, "UNKNOWN");
    assert.equal(classifyHookConfig({ records: "unreadable", code: "hook_config_unreadable" }).status, "UNKNOWN");
    for (const records of ["match", "mismatch", "none", "unreadable"] as const) {
      assert.notEqual(classifyHookConfig({ records }).status, "WARN");
    }
  });

  it("hook observed is OK only when the window actually contains the host", () => {
    const quiet = classifyHookObserved({ looked: true, unreadable: false, configured: ["grok"], observed: [] });
    assert.equal(quiet.status, "WARN");
    assert.notEqual(quiet.status, "OK");
    assert.match(quiet.summary, /没有观察到/);
    assert.equal(
      classifyHookObserved({ looked: true, unreadable: false, configured: ["grok"], observed: ["grok"] }).status,
      "OK",
    );
    assert.equal(
      classifyHookObserved({ looked: false, unreadable: false, configured: [], observed: [] }).status,
      "UNKNOWN",
    );
    assert.equal(
      classifyHookObserved({ looked: true, unreadable: false, configured: ["grok", "claude"], observed: ["grok"] }).status,
      "WARN",
    );
    assert.notEqual(quiet.status, "ERROR");
    assert.notEqual(
      classifyHookObserved({ looked: true, unreadable: false, configured: ["grok"], observed: ["grok"] }).status,
      "ERROR",
    );
  });

  it("host trust: trusted is OK, hash mismatch is ERROR, unread states are not WARN", () => {
    assert.equal(classifyHostTrust("trusted").status, "OK");
    assert.equal(classifyHostTrust("modified").status, "ERROR");
    assert.equal(classifyHostTrust("untrusted").status, "ERROR");
    assert.equal(classifyHostTrust("not_configured").status, "UNKNOWN");
    assert.equal(classifyHostTrust("unknown").status, "UNKNOWN");
    const statuses: HostTrustStatus[] = [
      "not_configured",
      "trusted",
      "untrusted",
      "modified",
      "disabled",
      "feature_off",
      "unknown",
      "unreadable",
    ];
    for (const status of statuses) assert.notEqual(classifyHostTrust(status).status, "WARN");
  });
});

describe("doctor read-only integration", () => {
  it("does not change a temp home or data directory", async () => {
    const { root, home, data } = await tempTree();
    try {
      await writeFile(join(data, "policy.json"), policyBody());
      await writeFile(join(data, "admin.token"), `${SECRET}\n`);
      await writeFile(join(data, "tls", "server.key"), PRIVATE_KEY).catch(async () => {
        mkdirSync(join(data, "tls"), { recursive: true });
        await writeFile(join(data, "tls", "server.key"), PRIVATE_KEY);
      });
      await writeFile(join(home, ".nmzp", "credentials.json"), credentialBody(SECRET)).catch(async () => {
        mkdirSync(join(home, ".nmzp"), { recursive: true });
        await writeFile(join(home, ".nmzp", "credentials.json"), credentialBody(SECRET));
      });
      await writeFile(
        join(data, "events.jsonl"),
        `${JSON.stringify({ id: "evt-secret", ts: 1, agent: "grok", source: "hook", decision: "allow", redacted: SECRET, password: SECRET })}\n`,
      );
      const snap = PolicyHistory.create(
        join(data, "nmzp.db"),
        createPolicySnapshot({ version: 1, updatedAt: 1, mode: "enforcing", stopped: false, customRules: [] }),
        "ab".repeat(32),
        NMZP_VERSION,
      );
      snap.close();
      const before = await treeSnapshot(root);
      const report = await doctor(home, data, { now: () => new Date("2026-09-28T00:00:00.000Z") });
      const text = `${JSON.stringify(report)}\n${formatDoctorText(report)}`;
      assert.equal(text.includes(SECRET), false);
      assert.equal(text.includes("BEGIN PRIVATE KEY"), false);
      const after = await treeSnapshot(root);
      assert.equal(after, before);
      const again = await treeSnapshot(root);
      await doctor(home, data);
      assert.equal(await treeSnapshot(root), again);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps configured-but-unobserved hooks off OK", async () => {
    const { root, home, data } = await tempTree();
    try {
      mkdirSync(join(home, ".nmzp"), { recursive: true });
      await writeFile(join(home, ".nmzp", "manifest.json"), JSON.stringify({ grokPath: join(home, "hook.json") }));
      await writeFile(join(data, "events.jsonl"), "");
      const empty = byId(await doctor(home, data), "hook_observed");
      assert.equal(empty.status, "WARN");
      assert.notEqual(empty.status, "OK");
      const oldTs = Date.now() - 25 * 60 * 60 * 1000;
      await writeFile(
        join(data, "events.jsonl"),
        `${JSON.stringify({ id: "old", ts: oldTs, agent: "grok", source: "hook", decision: "allow", redacted: "x" })}\n`,
      );
      assert.notEqual(byId(await doctor(home, data), "hook_observed").status, "OK");
      await writeFile(
        join(data, "events.jsonl"),
        `${JSON.stringify({ id: "probe", ts: Date.now(), agent: "grok", source: "probe", decision: "allow", redacted: "x" })}\n`,
      );
      assert.notEqual(byId(await doctor(home, data), "hook_observed").status, "OK");
      await writeFile(
        join(data, "events.jsonl"),
        `${JSON.stringify({ id: "seen", ts: Date.now(), agent: "grok", source: "hook", decision: "allow", redacted: SECRET })}\n`,
      );
      const seen = await doctor(home, data);
      assert.equal(byId(seen, "hook_observed").status, "OK");
      assert.equal(JSON.stringify(seen).includes(SECRET), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("uses on-disk sources for the implemented checks", async () => {
    const { root, home, data } = await tempTree();
    try {
      await writeFile(join(data, "serve.json"), servePointer(process.pid));
      await writeFile(join(data, "policy.json"), policyBody());
      const running = await doctor(home, data, { env: { NMZP_BIND: "127.0.0.1" } });
      assert.equal(running.role, "server");
      assert.equal(byId(running, "service").status, "OK");
      assert.equal(byId(running, "binary").status, "UNKNOWN");
      assert.notEqual(byId(running, "binary").status, "OK");
      assert.equal(byId(running, "version").summary, NOT_AVAILABLE_SUMMARY);
      assert.equal(byId(running, "storage").status, "OK");
      assert.equal(byId(running, "config").status, "OK");
      assert.equal(byId(running, "audit").status, "OK");
      assert.equal(byId(running, "backup").summary, NOT_AVAILABLE_SUMMARY);
      assert.equal(byId(running, "queues").summary, NOT_AVAILABLE_SUMMARY);

      await writeFile(join(data, "serve.json"), servePointer(2_147_483_646));
      assert.equal(byId(await doctor(home, data), "service").status, "ERROR");

      await writeFile(join(data, "policy.json"), "{");
      assert.equal(byId(await doctor(home, data), "storage").status, "ERROR");

      await writeFile(join(data, "policy.json"), policyBody({ schemaVersion: 2 }));
      assert.equal(byId(await doctor(home, data), "storage").details.code, "schema_mismatch");

      mkdirSync(join(data, "nmzp.db"));
      assert.equal(byId(await doctor(home, data, { env: { NMZP_STORAGE_MODE: "sqlite" } }), "storage").status, "UNKNOWN");
      await rm(join(data, "nmzp.db"), { recursive: true, force: true });

      const tls = generateNmzpCert(["127.0.0.1", "localhost"]);
      mkdirSync(join(data, "tls"), { recursive: true });
      await writeFile(join(data, "tls", "server.crt"), tls.certPem);
      await writeFile(join(data, "tls", "pin.json"), JSON.stringify({ fingerprintSha256: tls.fingerprintSha256 }));
      await writeFile(join(data, "serve.json"), servePointer(process.pid).replace("ab".repeat(32), tls.fingerprintSha256));
      await writeFile(join(data, "policy.json"), policyBody());
      const tlsOk = await doctor(home, data, { env: { NMZP_BIND: "127.0.0.1" } });
      assert.equal(byId(tlsOk, "tls").status, "OK");
      assert.equal(JSON.stringify(tlsOk).includes(tls.certPem), false);
      const expired = await doctor(home, data, {
        env: { NMZP_BIND: "127.0.0.1" },
        now: () => new Date(Date.now() + 6 * 365 * 24 * 60 * 60 * 1000),
      });
      assert.equal(byId(expired, "tls").status, "ERROR");
      await writeFile(join(data, "tls", "pin.json"), JSON.stringify({ fingerprintSha256: "ff".repeat(32) }));
      assert.equal(byId(await doctor(home, data), "tls").status, "ERROR");
      await writeFile(join(data, "tls", "pin.json"), JSON.stringify({ fingerprintSha256: tls.fingerprintSha256 }));
      const san = await doctor(home, data, { env: { NMZP_PUBLIC_URL: "https://uncovered.example" } });
      assert.equal(byId(san, "tls").status, "ERROR");
      assert.equal(JSON.stringify(san).includes("uncovered.example"), true);

      await writeFile(join(data, "devices.json"), JSON.stringify({ devices: [{ id: "dev_safe", revokedAt: 10 }] }));
      assert.equal(byId(await doctor(home, data), "identity").status, "ERROR");

      const protectedId = RULES.find((rule) => isProtectedRule(rule))?.id;
      assert.equal(typeof protectedId, "string");
      await writeFile(
        join(data, "policy.json"),
        policyBody({ overrides: { rules: { [protectedId!]: "log" }, families: {} } }),
      );
      const downgraded = byId(await doctor(home, data), "protected_rules");
      assert.equal(downgraded.status, "ERROR");
      assert.equal(JSON.stringify(downgraded.details).includes(protectedId!), true);

      await writeFile(join(data, "policy.json"), policyBody());
      const lines = Array.from({ length: FRICTION_HIGH_COUNT }, (_, index) =>
        JSON.stringify({
          id: `evt_${index}`,
          ts: Date.now(),
          agent: "grok",
          source: "hook",
          decision: index % 2 === 0 ? "block" : "confirm",
          ruleId: "credential_file_upload",
          redacted: "summary",
        }),
      );
      await writeFile(join(data, "events.jsonl"), `${lines.join("\n")}\n`);
      const hot = byId(await doctor(home, data), "friction");
      assert.equal(hot.status, "WARN");
      assert.equal(JSON.stringify(hot).includes("不会放宽") || (hot.remediation ?? "").includes("不会放宽"), true);
      await writeFile(join(data, "events.jsonl"), lines.slice(0, FRICTION_HIGH_COUNT - 1).join("\n"));
      assert.equal(byId(await doctor(home, data), "friction").status, "OK");
      mkdirSync(join(data, "events-dir"));
      await writeFile(join(data, "events.jsonl"), "");
      await rm(join(data, "events.jsonl"));
      mkdirSync(join(data, "events.jsonl"));
      assert.equal(byId(await doctor(home, data), "friction").status, "UNKNOWN");
      assert.equal(byId(await doctor(home, data), "audit").status, "UNKNOWN");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("compares sqlite policy head rulesHash without writing", async () => {
    const { root, home, data } = await tempTree();
    try {
      const body = { version: 1, updatedAt: 1, mode: "enforcing" as const, stopped: false, customRules: [] };
      await writeFile(join(data, "policy.json"), JSON.stringify(body));
      const engine = policyRulesHash({ RULES });
      const match = PolicyHistory.create(join(data, "nmzp.db"), createPolicySnapshot(body), engine, NMZP_VERSION);
      match.close();
      const before = await treeSnapshot(data);
      const ok = await doctor(home, data, { env: { NMZP_STORAGE_MODE: "sqlite", NMZP_BIND: "127.0.0.1" } });
      assert.equal(byId(ok, "policy").status, "OK");
      assert.equal(byId(ok, "storage").status, "OK");
      assert.equal(await treeSnapshot(data), before);
      await rm(join(data, "nmzp.db"));
      const mismatch = PolicyHistory.create(
        join(data, "nmzp.db"),
        createPolicySnapshot(body),
        "cd".repeat(32),
        NMZP_VERSION,
      );
      mismatch.close();
      assert.equal(byId(await doctor(home, data, { env: { NMZP_STORAGE_MODE: "sqlite" } }), "policy").status, "ERROR");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("reads device hook, outbox, discovery, and codex trust files", async () => {
    const { root, home, data } = await tempTree();
    try {
      mkdirSync(join(home, ".nmzp"), { recursive: true });
      await writeFile(join(home, ".nmzp", "credentials.json"), credentialBody("device-token-not-secret-marker"));
      const report = await doctor(home, data);
      assert.equal(report.role, "device");
      assert.equal(byId(report, "queues").status, "OK");
      assert.equal(byId(report, "adapters").details.reason, "no_hosts");
      assert.equal(byId(report, "hook_config").status, "UNKNOWN");
      assert.equal(byId(report, "ct_reachability").summary, NOT_AVAILABLE_SUMMARY);
      assert.equal(JSON.stringify(report).includes("device-token-not-secret-marker"), false);

      await writeFile(
        join(home, ".nmzp", "audit-outbox.json"),
        JSON.stringify({ formatVersion: 1, items: [], dropped: 1, expired: 0, quarantined: 0, conflicts: 0 }),
      );
      assert.equal(byId(await doctor(home, data), "queues").status, "ERROR");
      await writeFile(join(home, ".nmzp", "audit-outbox.json"), "{");
      assert.equal(byId(await doctor(home, data), "queues").status, "UNKNOWN");

      const hookBody = "hook-body\n";
      const hookPath = join(home, "owned-hook.json");
      await writeFile(hookPath, hookBody);
      await writeFile(
        join(home, ".nmzp", "manifest.json"),
        JSON.stringify({ grokPath: hookPath, grok: { writtenSha256: sha256Text(hookBody) } }),
      );
      assert.equal(byId(await doctor(home, data), "hook_config").status, "OK");
      await writeFile(hookPath, "changed\n");
      assert.equal(byId(await doctor(home, data), "hook_config").status, "ERROR");
      mkdirSync(join(home, "not-a-file"));
      await writeFile(
        join(home, ".nmzp", "manifest.json"),
        JSON.stringify({
          grokPath: join(home, "not-a-file"),
          grok: { writtenSha256: sha256Text("x") },
        }),
      );
      assert.equal(byId(await doctor(home, data), "hook_config").status, "UNKNOWN");

      const now = Date.now();
      await writeFile(
        join(home, ".nmzp", "discovery.json"),
        JSON.stringify({
          schemaVersion: 1,
          platform: "unsupported",
          checkedAt: now,
          completedAt: now,
          status: "partial",
          sources: [{ id: "manual", status: "ok" }],
          items: [
            {
              instanceId: `di_${"ab".repeat(16)}`,
              adapterId: "codex-cli",
              installation: "present",
              running: "not_observed",
              identity: "candidate",
              firstSeen: now,
              lastSeen: now,
              lastChecked: now,
              evidence: ["manual_path"],
              reasons: [],
              sources: ["manual"],
              processes: [],
            },
          ],
        }),
      );
      const adapters = byId(await doctor(home, data), "adapters");
      assert.equal(adapters.status, "UNKNOWN");
      assert.equal(adapters.summary, NOT_AVAILABLE_SUMMARY);
      assert.notEqual(adapters.status, "OK");

      mkdirSync(join(home, ".codex"), { recursive: true });
      const hooksPath = join(home, ".codex", "hooks.json");
      const entry = codexHookEntry("/usr/bin/node", "/opt/nmzp/nmzp.mjs", "linux");
      await writeFile(hooksPath, mergeCodexHooks(null, entry));
      const current = codexHookTrust(home);
      assert.equal(typeof current.key, "string");
      await writeFile(
        join(home, ".codex", "config.toml"),
        `[hooks.state.'${current.key}']\ntrusted_hash = "${current.currentHash}"\n`,
      );
      assert.equal(codexHookTrust(home).status, "trusted");
      assert.equal(byId(await doctor(home, data), "host_trust").status, "OK");
      await writeFile(
        join(home, ".codex", "config.toml"),
        `[hooks.state.'${current.key}']\ntrusted_hash = "sha256:${"ab".repeat(32)}"\n`,
      );
      assert.equal(byId(await doctor(home, data), "host_trust").status, "ERROR");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("bounds disk with an injected statfs and isolates a thrown or hung check", async () => {
    const { root, home, data } = await tempTree();
    try {
      const low = await doctor(home, data, { statfs: () => ({ bavail: DISK_MIN_FREE_BYTES - 1, bsize: 1 }) });
      assert.equal(byId(low, "disk").status, "ERROR");
      const exact = await doctor(home, data, { statfs: () => ({ bavail: DISK_MIN_FREE_BYTES, bsize: 1 }) });
      assert.equal(byId(exact, "disk").status, "OK");
      const broken = await doctor(home, data, {
        statfs: () => {
          throw Object.assign(new Error(`boom ${SECRET}\n    at secret-stack`), { stack: `STACK ${SECRET}` });
        },
      });
      const disk = byId(broken, "disk");
      assert.equal(disk.status, "UNKNOWN");
      assert.equal(disk.details.code, "statfs_failed");
      assert.equal(JSON.stringify(disk).includes(SECRET), false);
      assert.equal(JSON.stringify(disk).includes("STACK"), false);
      assert.equal(byId(broken, "version").status, "UNKNOWN");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
    const hung = isolateCheck(
      "disk",
      () => new Promise<DoctorCheck>(() => undefined),
      30,
    );
    const ok = isolateCheck("binary", async () => classifyBinary({ exists: true, signature: "ok", path: "nmzp" }), 200);
    const [timed, sibling] = await Promise.all([hung, ok]);
    assert.equal(timed.status, "UNKNOWN");
    assert.equal(timed.details.code, "check_timeout");
    assert.equal(sibling.status, "OK");
    const thrown = await isolateCheck("version", async () => {
      throw Object.assign(new Error(`boom ${SECRET}\n    at secret-stack`), { stack: `STACK ${SECRET}` });
    }, 200);
    assert.equal(thrown.status, "UNKNOWN");
    assert.equal(thrown.details.code, "check_failed");
    assert.equal(JSON.stringify(thrown).includes(SECRET), false);
    assert.equal(JSON.stringify(thrown).includes("STACK"), false);
    assert.equal(sibling.status, "OK");
  });

  it("finishes three runs with a median under 3000 ms", async () => {
    const { root, home, data } = await tempTree();
    try {
      const samples: number[] = [];
      for (let i = 0; i < 3; i += 1) {
        const started = performance.now();
        await doctor(home, data, { now: () => new Date("2026-09-28T00:00:00.000Z") });
        samples.push(performance.now() - started);
      }
      samples.sort((a, b) => a - b);
      assert.ok(samples[1]! <= 3_000, `median ${samples[1]} samples ${samples.join(",")}`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("doctor CLI", () => {
  it("prints help, human lines, json schema, and the ERROR exit code", async () => {
    const { root, home, data } = await tempTree();
    try {
      const help = await spawnCli(["help"], childEnv(home, data));
      assert.equal(help.code, 0);
      assert.match(help.stdout, /nmzp doctor \[--json\]/);
      assert.match(help.stdout, /exit 1 when overall is ERROR/);
      assert.match(help.stdout, /exit 0 for OK, WARN, and UNKNOWN/);

      const before = await treeSnapshot(root);
      const rejected = await spawnCli(["doctor", "--fix-safe"], childEnv(home, data));
      assert.equal(rejected.code, 1);
      assert.match(rejected.stderr, /nmzp doctor \[--json\]/);
      assert.equal(await treeSnapshot(root), before);

      const human = await spawnCli(["doctor"], childEnv(home, data));
      assert.equal(human.code, 0, human.stderr);
      assert.match(human.stdout, /^(OK|WARN|ERROR|UNKNOWN) {2}[a-z_]+ {2}.+/m);
      assert.equal(human.stdout.includes(SECRET), false);

      await writeFile(join(data, "policy.json"), policyBody({ schemaVersion: 2 }));
      await writeFile(join(data, "serve.json"), servePointer(process.pid));
      const failed = await spawnCli(["doctor", "--json"], childEnv(home, data));
      assert.equal(failed.code, 1, failed.stderr);
      const parsed = JSON.parse(failed.stdout) as DoctorReport;
      assert.equal(parsed.overall, "ERROR");
      assert.equal(validateDoctorReport(parsed).ok, true);
      assert.equal(parsed.generatedAt.includes("T"), true);
      const text = await spawnCli(["doctor"], childEnv(home, data));
      assert.match(text.stdout, /\n {2}\S/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("validates json from a temp home and omits planted secrets", async () => {
    const { root, home, data } = await tempTree();
    try {
      mkdirSync(join(home, ".nmzp"), { recursive: true });
      mkdirSync(join(data, "tls"), { recursive: true });
      await writeFile(join(data, "admin.token"), SECRET);
      await writeFile(join(data, "tls", "server.key"), PRIVATE_KEY);
      await writeFile(join(home, ".nmzp", "credentials.json"), credentialBody(SECRET));
      await writeFile(join(data, "note.json"), JSON.stringify({ password: SECRET, ticket: SECRET }));
      const before = await treeSnapshot(root);
      const result = await spawnCli(["doctor", "--json"], childEnv(home, data));
      assert.equal(result.code === 0 || result.code === 1, true);
      assert.equal(`${result.stdout}\n${result.stderr}`.includes(SECRET), false);
      assert.equal(result.stdout.includes("BEGIN PRIVATE KEY"), false);
      const parsed = JSON.parse(result.stdout) as DoctorReport;
      assert.equal(validateDoctorReport(parsed).ok, true, JSON.stringify(validateDoctorReport(parsed)));
      assert.equal(await treeSnapshot(root), before);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("doctor schema negatives", () => {
  it("rejects missing fields, extra fields, bad status, bad id, and a mismatched overall", async () => {
    const { home, data, root } = await tempTree();
    try {
      const report = await doctor(home, data, { now: () => new Date("2026-09-28T00:00:00.000Z") });
      assert.equal(validateDoctorReport(report).ok, true);
      const base = JSON.parse(JSON.stringify(report)) as DoctorReport;
      const cases: unknown[] = [];
      const missing = { ...base } as Partial<DoctorReport>;
      delete missing.schemaVersion;
      cases.push(missing);
      cases.push({ ...base, extra: true });
      cases.push({
        ...base,
        checks: base.checks.map((item, index) => (index === 0 ? { ...item, status: "BAD" } : item)),
      });
      cases.push({
        ...base,
        checks: base.checks.map((item, index) => (index === 0 ? { ...item, id: "not_a_check" } : item)),
      });
      cases.push({ ...base, overall: base.overall === "OK" ? "ERROR" : "OK" });
      assert.equal(cases.length, 5);
      for (const sample of cases) {
        const result = validateDoctorReport(sample);
        assert.equal(result.ok, false);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("status extras", () => {
  it("adds role, service, listeners, and lastHookObserved without writing or secrets", async () => {
    const { root, home, data } = await tempTree();
    try {
      mkdirSync(join(data, "tls"), { recursive: true });
      await writeFile(join(data, "admin.token"), SECRET);
      await writeFile(join(data, "tls", "server.key"), PRIVATE_KEY);
      await writeFile(join(data, "serve.json"), servePointer(process.pid).replace("ab".repeat(32), SECRET));
      await writeFile(
        join(data, "events.jsonl"),
        `${JSON.stringify({ id: "evt", ts: Date.now(), agent: "grok", source: "hook", decision: "allow", redacted: SECRET })}\n`,
      );
      const before = await treeSnapshot(root);
      const extras = await readStatusExtras({
        home,
        dataDir: data,
        env: {},
        events: [{ agent: "claude", ts: Date.now(), source: "hook", redacted: SECRET }],
      });
      assert.equal(JSON.stringify(extras).includes(SECRET), false);
      assert.equal(extras.service === "running" || extras.service === "stopped" || extras.service === null, true);
      assert.equal(Array.isArray(extras.listeners), true);
      assert.equal(await treeSnapshot(root), before);
      await rm(join(data, "serve.json"), { force: true });
      const cli = await spawnCli(["status", "--json"], childEnv(home, data));
      assert.equal(cli.code, 0, cli.stderr);
      const parsed = JSON.parse(cli.stdout) as Record<string, unknown>;
      assert.deepEqual(Object.keys(parsed).slice(0, 6), ["version", "policyVersion", "mode", "stopped", "devices", "events"]);
      assert.deepEqual(Object.keys(parsed).slice(6), ["role", "service", "listeners", "lastHookObserved"]);
      assert.equal(parsed.version, NMZP_VERSION);
      assert.equal(typeof parsed.policyVersion, "number");
      assert.equal(typeof parsed.mode, "string");
      assert.equal(typeof parsed.stopped, "boolean");
      assert.equal(typeof parsed.devices, "number");
      assert.equal(typeof parsed.events, "number");
      assert.equal(`${cli.stdout}${cli.stderr}`.includes(SECRET), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("doctor source stays read-only", () => {
  it("does not call writers, discovery refresh, or hook byte helpers", async () => {
    const files = ["report.ts", "classify.ts", "inspect.ts", "run.ts", "status.ts"];
    const combined = (
      await Promise.all(files.map((file) => readFile(join(coreDir, "doctor", file), "utf8")))
    ).join("\n");
    assert.doesNotMatch(
      combined,
      /\b(mkdir|mkdirSync|writeFile|writeFileSync|appendFile|appendFileSync|rmSync|unlinkSync|chmodSync|renameSync|copyFile|spawn|spawnSync|pinnedHttps|refreshDiscovery|loadOrCreateTls|bootstrapAdmin|enqueueOutbox|drainOutbox|AuditRuntime|new NmzpStore)\s*\(/,
    );
  });
});

describe("packed doctor", () => {
  it("nmzp.mjs doctor --json validates against the schema", async () => {
    const packed = join(coreDir, "..", ".pack", "nmzp", "nmzp.mjs");
    const { root, home, data } = await tempTree();
    try {
      const exists = await readFile(packed).then(
        () => true,
        () => false,
      );
      assert.equal(exists, true, "run node scripts/build.mjs before this test");
      const result = await new Promise<{ stdout: string; stderr: string; code: number }>((resolve) => {
        const child = spawn(process.execPath, [packed, "doctor", "--json"], {
          env: childEnv(home, data),
          windowsHide: true,
          cwd: join(packed, ".."),
        });
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
      assert.equal(result.code === 0 || result.code === 1, true, result.stderr);
      const parsed = JSON.parse(result.stdout) as DoctorReport;
      const validated = validateDoctorReport(parsed);
      assert.equal(validated.ok, true, JSON.stringify(validated));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function credentialBody(token: string): string {
  return JSON.stringify({
    deviceId: "dev_synthetic",
    token,
    url: "https://127.0.0.1:8787",
    caPem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    fingerprintSha256: "ab".repeat(32),
  });
}
