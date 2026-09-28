import assert from "node:assert/strict";
import { readFileSync, symlinkSync } from "node:fs";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { DEFAULT_AUDIT_RETENTION } from "../audit/store.ts";
import {
  AUDIT_DAY_MS,
  AUDIT_MB,
  DEFAULT_BIND,
  DEFAULT_PORT,
  DEFAULT_STORAGE_MODE,
  DEFAULT_VIEWER_PORT,
  itemByKey,
  resolveEffectiveConfig,
  validateConfigShow,
} from "./resolve.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));
const cliSrc = readFileSync(join(coreDir, "..", "cli.ts"), "utf8");

async function isolated(): Promise<{ root: string; home: string; data: string }> {
  const root = await mkdtemp(join(tmpdir(), "nmzp-cfg-"));
  const home = join(root, "home");
  const data = join(root, "data");
  await mkdir(home);
  await mkdir(data);
  return { root, home, data };
}

describe("resolveEffectiveConfig", () => {
  it("defaults match serve/cli and audit store", async () => {
    const { root, home, data } = await isolated();
    try {
      const report = resolveEffectiveConfig({}, { home, dataDir: data });
      assert.equal(validateConfigShow(report).ok, true, JSON.stringify(validateConfigShow(report)));
      assert.equal(itemByKey(report, "NMZP_BIND").value, DEFAULT_BIND);
      assert.equal(itemByKey(report, "NMZP_BIND").value, "0.0.0.0");
      assert.equal(itemByKey(report, "NMZP_PORT").value, DEFAULT_PORT);
      assert.equal(itemByKey(report, "NMZP_PORT").value, 8787);
      assert.equal(itemByKey(report, "NMZP_DATA").value, data);
      assert.equal(itemByKey(report, "NMZP_HOME").value, home);
      assert.equal(itemByKey(report, "NMZP_STORAGE_MODE").value, DEFAULT_STORAGE_MODE);
      assert.equal(itemByKey(report, "NMZP_VIEWER_PORT").value, DEFAULT_VIEWER_PORT);
      assert.equal(itemByKey(report, "NMZP_AUDIT_MAX_RECORDS").value, DEFAULT_AUDIT_RETENTION.maxRecords);
      assert.equal(itemByKey(report, "NMZP_AUDIT_MAX_DAYS").value, DEFAULT_AUDIT_RETENTION.maxAgeMs / AUDIT_DAY_MS);
      assert.equal(itemByKey(report, "NMZP_AUDIT_MAX_MB").value, DEFAULT_AUDIT_RETENTION.maxDbBytes / AUDIT_MB);
      assert.equal(itemByKey(report, "NMZP_AUDIT_MIN_FREE_MB").value, DEFAULT_AUDIT_RETENTION.minFreeBytes / AUDIT_MB);
      assert.equal(itemByKey(report, "NMZP_AUDIT_TOMBSTONE_DAYS").value, DEFAULT_AUDIT_RETENTION.tombstoneMs / AUDIT_DAY_MS);
      assert.match(cliSrc, /process\.env\.NMZP_DATA \|\| join\(homedir\(\), "\.nmzp", "ct-data"\)/);
      assert.match(cliSrc, /process\.env\.NMZP_STORAGE_MODE \?\? "window"/);
      assert.equal(defaultDataFromHomedir(), join(homedir(), ".nmzp", "ct-data"));
      assert.equal(report.items.every((row) => row.source !== "FILE"), true);
      assert.equal(report.items.some((row) => row.key.startsWith("NMZP_TEST_")), false);
      assert.equal(report.items.some((row) => row.key.startsWith("NMZP_PROBE_")), false);
      assert.equal(report.items.some((row) => row.key.startsWith("NMZP_LIVE_")), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("marks ENV source, secrets as isSet, and never echoes secret bytes", async () => {
    const { root, home, data } = await isolated();
    try {
      const secret = "nmzp-cfg-secret-9c4e2b11";
      const report = resolveEffectiveConfig(
        {
          NMZP_BIND: "127.0.0.1",
          NMZP_PORT: "0",
          NMZP_DATA: data,
          NMZP_HOME: home,
          NMZP_UPSTREAM_TOKEN: secret,
          NMZP_VIEWER_CREDENTIAL: secret,
        },
        { home, dataDir: data },
      );
      assert.equal(itemByKey(report, "NMZP_BIND").source, "ENV");
      assert.equal(itemByKey(report, "NMZP_PORT").value, 0);
      assert.equal(itemByKey(report, "NMZP_PORT").valid, true);
      assert.equal(itemByKey(report, "NMZP_UPSTREAM_TOKEN").secret, true);
      assert.equal(itemByKey(report, "NMZP_UPSTREAM_TOKEN").value, null);
      assert.equal(itemByKey(report, "NMZP_UPSTREAM_TOKEN").isSet, true);
      assert.equal(itemByKey(report, "NMZP_VIEWER_CREDENTIAL").value, null);
      assert.equal(itemByKey(report, "NMZP_VIEWER_CREDENTIAL").isSet, true);
      assert.equal(JSON.stringify(report).includes(secret), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects relative data dir, bad bind, bad CIDR, and symlink data dir", async () => {
    const { root, home, data } = await isolated();
    try {
      const relative = resolveEffectiveConfig({ NMZP_DATA: "rel-data" }, { home, dataDir: data });
      assert.equal(itemByKey(relative, "NMZP_DATA").valid, false);
      const bind = resolveEffectiveConfig({ NMZP_BIND: "not a host" }, { home, dataDir: data });
      assert.equal(itemByKey(bind, "NMZP_BIND").valid, false);
      const cidr = resolveEffectiveConfig({ NMZP_VIEWER_ALLOW_CIDR: "999.0.0.0/99" }, { home, dataDir: data });
      assert.equal(itemByKey(cidr, "NMZP_VIEWER_ALLOW_CIDR").valid, false);
      const mode = resolveEffectiveConfig({ NMZP_STORAGE_MODE: "memory" }, { home, dataDir: data });
      assert.equal(itemByKey(mode, "NMZP_STORAGE_MODE").valid, false);
      const audit = resolveEffectiveConfig({ NMZP_AUDIT_MAX_DAYS: "nope" }, { home, dataDir: data });
      assert.equal(itemByKey(audit, "NMZP_AUDIT_MAX_DAYS").valid, false);
      assert.equal(itemByKey(audit, "NMZP_AUDIT_MAX_DAYS").securityRelevant, false);
      if (process.platform === "win32") return;
      const target = join(root, "real");
      const link = join(root, "link");
      await mkdir(target);
      try {
        symlinkSync(target, link);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EPERM" || code === "ENOTSUP") return;
        throw error;
      }
      const linked = resolveEffectiveConfig({ NMZP_DATA: link }, { home, dataDir: data });
      assert.equal(itemByKey(linked, "NMZP_DATA").valid, false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function defaultDataFromHomedir(): string {
  return join(homedir(), ".nmzp", "ct-data");
}
