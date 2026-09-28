import assert from "node:assert/strict";
import { lchownSync, lstatSync, readFileSync, symlinkSync, type Stats } from "node:fs";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve as resolvePath } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { DEFAULT_AUDIT_RETENTION } from "../audit/store.ts";
import { prepareServeProcess } from "./serve-start.ts";
import {
  AUDIT_DAY_MS,
  AUDIT_MB,
  DEFAULT_BIND,
  DEFAULT_PORT,
  DEFAULT_STORAGE_MODE,
  DEFAULT_VIEWER_PORT,
  formatConfigShow,
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

const posixSkip = process.platform === "win32" ? "POSIX cases run on CI ubuntu" : false;

function ancestry(target: string): string[] {
  const rows: string[] = [];
  let cur = resolvePath(target);
  const seen = new Set<string>();
  while (!seen.has(cur)) {
    seen.add(cur);
    rows.push(cur);
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return rows;
}

function nodeStat(uid: number, mode: number, kind: "dir" | "symlink" | "file"): Stats {
  return {
    uid,
    mode,
    isSymbolicLink: () => kind === "symlink",
    isDirectory: () => kind === "dir",
    isFile: () => kind === "file",
    dev: 1,
    ino: 1,
  } as Stats;
}

function scriptedLstat(nodes: Record<string, { uid: number; mode: number; kind: "dir" | "symlink" | "file" }>): (path: string) => Stats {
  return (path: string) => {
    const node = nodes[path];
    if (!node) {
      const error = new Error(`ENOENT ${path}`) as NodeJS.ErrnoException;
      error.code = "ENOENT";
      throw error;
    }
    return nodeStat(node.uid, node.mode, node.kind);
  };
}

describe("port parsing", () => {
  it("accepts trimmed integers and 8787.0, and rejects non-integers", async () => {
    const { root, home, data } = await isolated();
    try {
      const base = { NMZP_BIND: "127.0.0.1", NMZP_DATA: data, NMZP_HOME: home };
      const unset = resolveEffectiveConfig(base, { home, dataDir: data });
      assert.equal(itemByKey(unset, "NMZP_PORT").value, DEFAULT_PORT);
      assert.equal(itemByKey(unset, "NMZP_PORT").valid, true);
      assert.equal(itemByKey(unset, "NMZP_PORT").source, "DEFAULT");
      for (const raw of [" 8787 ", "8787.0"]) {
        const report = resolveEffectiveConfig({ ...base, NMZP_PORT: raw }, { home, dataDir: data });
        assert.equal(itemByKey(report, "NMZP_PORT").valid, true, raw);
        assert.equal(itemByKey(report, "NMZP_PORT").value, 8787, raw);
        const prepared = await prepareServeProcess({ ...base, NMZP_PORT: raw }, () => undefined);
        assert.equal(prepared.ok, true, raw);
        if (prepared.ok) assert.equal(prepared.port, 8787);
      }
      const viewer = resolveEffectiveConfig({ ...base, NMZP_VIEWER_PORT: " 8789 " }, { home, dataDir: data });
      assert.equal(itemByKey(viewer, "NMZP_VIEWER_PORT").valid, true);
      assert.equal(itemByKey(viewer, "NMZP_VIEWER_PORT").value, 8789);
      for (const raw of ["nope", "-1", "65536", "1.5"]) {
        const report = resolveEffectiveConfig({ ...base, NMZP_PORT: raw }, { home, dataDir: data });
        assert.equal(itemByKey(report, "NMZP_PORT").valid, false, raw);
        assert.equal(itemByKey(report, "NMZP_PORT").securityRelevant, true);
        const prepared = await prepareServeProcess({ ...base, NMZP_PORT: raw }, () => undefined);
        assert.equal(prepared.ok, false, raw);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("symlink ancestors", () => {
  it("accepts a root-owned trusted symlink ancestor", { skip: posixSkip }, () => {
    const data = "/home/user/.nmzp/ct-data";
    const [leaf, nmzp, user, home, root] = ancestry(data);
    assert.ok(leaf && nmzp && user && home && root);
    const lstat = scriptedLstat({
      [nmzp]: { uid: 1000, mode: 0o755, kind: "dir" },
      [user]: { uid: 1000, mode: 0o755, kind: "dir" },
      [home]: { uid: 0, mode: 0o777, kind: "symlink" },
      [root]: { uid: 0, mode: 0o755, kind: "dir" },
    });
    const report = resolveEffectiveConfig({}, { home: "/home/user", dataDir: data, lstat });
    assert.equal(itemByKey(report, "NMZP_DATA").source, "DEFAULT");
    assert.equal(itemByKey(report, "NMZP_DATA").value, data);
    assert.equal(itemByKey(report, "NMZP_DATA").valid, true, itemByKey(report, "NMZP_DATA").problem);
  });

  it("rejects a non-root symlink ancestor", { skip: posixSkip }, async () => {
    const { root, home, data } = await isolated();
    try {
      const injected = "/home/user/.nmzp/ct-data";
      const [leaf, nmzp, user, link, top] = ancestry(injected);
      assert.ok(leaf && nmzp && user && link && top);
      const lstat = scriptedLstat({
        [nmzp]: { uid: 1000, mode: 0o755, kind: "dir" },
        [user]: { uid: 1000, mode: 0o755, kind: "dir" },
        [link]: { uid: 1000, mode: 0o777, kind: "symlink" },
        [top]: { uid: 0, mode: 0o755, kind: "dir" },
      });
      const scripted = resolveEffectiveConfig({ NMZP_DATA: injected }, { home, dataDir: data, lstat });
      assert.equal(itemByKey(scripted, "NMZP_DATA").valid, false);
      assert.match(itemByKey(scripted, "NMZP_DATA").problem ?? "", /symlink/);

      const real = join(root, "real");
      const parent = join(root, "parent");
      const linkPath = join(parent, "link");
      await mkdir(real);
      await mkdir(parent);
      symlinkSync(real, linkPath);
      if ((process.getuid?.() ?? -1) === 0) lchownSync(linkPath, 1, 1);
      assert.notEqual(lstatSync(linkPath).uid, 0);
      const linkedData = join(linkPath, "ct-data");
      const live = resolveEffectiveConfig({ NMZP_DATA: linkedData, NMZP_BIND: "127.0.0.1" }, { home, dataDir: data });
      assert.equal(itemByKey(live, "NMZP_DATA").valid, false);
      assert.match(itemByKey(live, "NMZP_DATA").problem ?? "", /symlink/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a symlink as the last path component", { skip: posixSkip }, async () => {
    const { root, home, data } = await isolated();
    try {
      const injected = "/var/lib/nmzp-test";
      const [leaf, parent] = ancestry(injected);
      assert.ok(leaf && parent);
      const lstat = scriptedLstat({
        [leaf]: { uid: 0, mode: 0o777, kind: "symlink" },
        [parent]: { uid: 0, mode: 0o755, kind: "dir" },
      });
      const scripted = resolveEffectiveConfig({ NMZP_DATA: injected }, { home, dataDir: data, lstat });
      assert.equal(itemByKey(scripted, "NMZP_DATA").valid, false);
      assert.match(itemByKey(scripted, "NMZP_DATA").problem ?? "", /symlink/);

      const real = join(root, "real");
      const linkPath = join(root, "data-link");
      await mkdir(real);
      symlinkSync(real, linkPath);
      const live = resolveEffectiveConfig({ NMZP_DATA: linkPath, NMZP_BIND: "127.0.0.1" }, { home, dataDir: data });
      assert.equal(itemByKey(live, "NMZP_DATA").valid, false);
      assert.match(itemByKey(live, "NMZP_DATA").problem ?? "", /symlink/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a root symlink whose parent is group-writable or not root-owned", { skip: posixSkip }, () => {
    const data = "/home/user/.nmzp/ct-data";
    const paths = ancestry(data);
    const home = paths[3];
    const top = paths[4];
    assert.ok(home && top);
    const groupWritable = scriptedLstat({
      [paths[1] ?? ""]: { uid: 1000, mode: 0o755, kind: "dir" },
      [paths[2] ?? ""]: { uid: 1000, mode: 0o755, kind: "dir" },
      [home]: { uid: 0, mode: 0o777, kind: "symlink" },
      [top]: { uid: 0, mode: 0o775, kind: "dir" },
    });
    const wide = resolveEffectiveConfig({}, { home: "/home/user", dataDir: data, lstat: groupWritable });
    assert.equal(itemByKey(wide, "NMZP_DATA").valid, false);
    const userParent = scriptedLstat({
      [paths[1] ?? ""]: { uid: 1000, mode: 0o755, kind: "dir" },
      [paths[2] ?? ""]: { uid: 1000, mode: 0o755, kind: "dir" },
      [home]: { uid: 0, mode: 0o777, kind: "symlink" },
      [top]: { uid: 1000, mode: 0o755, kind: "dir" },
    });
    const owned = resolveEffectiveConfig({}, { home: "/home/user", dataDir: data, lstat: userParent });
    assert.equal(itemByKey(owned, "NMZP_DATA").valid, false);
  });
});

describe("NMZP_PUBLIC_URL userinfo", () => {
  it("rejects userinfo, redacts the value, and keeps a normal https URL", async () => {
    const { root, home, data } = await isolated();
    try {
      const password = "nmzp-puburl-secret-c0ffee11";
      const raw = `https://nmzp-user:${password}@ct.example/n`;
      const report = resolveEffectiveConfig(
        { NMZP_BIND: "127.0.0.1", NMZP_DATA: data, NMZP_HOME: home, NMZP_PUBLIC_URL: raw },
        { home, dataDir: data },
      );
      const row = itemByKey(report, "NMZP_PUBLIC_URL");
      assert.equal(row.valid, false);
      assert.equal(row.securityRelevant, true);
      assert.equal(row.value, "https://ct.example/n");
      assert.match(row.problem ?? "", /userinfo/);
      const shown = `${formatConfigShow(report)}\n${JSON.stringify(report)}`;
      assert.equal(shown.includes(password), false);
      assert.equal(shown.includes("nmzp-user"), false);
      assert.match(shown, /problem=/);
      const plain = resolveEffectiveConfig(
        { NMZP_BIND: "127.0.0.1", NMZP_DATA: data, NMZP_PUBLIC_URL: "https://ct.example/n" },
        { home, dataDir: data },
      );
      assert.equal(itemByKey(plain, "NMZP_PUBLIC_URL").valid, true);
      assert.equal(itemByKey(plain, "NMZP_PUBLIC_URL").value, "https://ct.example/n");
      const http = resolveEffectiveConfig(
        { NMZP_PUBLIC_URL: "http://ct.example/n" },
        { home, dataDir: data },
      );
      assert.equal(itemByKey(http, "NMZP_PUBLIC_URL").valid, false);
      assert.equal(itemByKey(http, "NMZP_PUBLIC_URL").value, "http://ct.example/n");
      const userOnly = resolveEffectiveConfig(
        { NMZP_PUBLIC_URL: `https://nmzp-user@ct.example/n`, NMZP_DATA: data, NMZP_BIND: "127.0.0.1" },
        { home, dataDir: data },
      );
      assert.equal(itemByKey(userOnly, "NMZP_PUBLIC_URL").valid, false);
      assert.equal(itemByKey(userOnly, "NMZP_PUBLIC_URL").value, "https://ct.example/n");
      const passwordOnly = resolveEffectiveConfig(
        { NMZP_PUBLIC_URL: `http://:${password}@ct.example/n`, NMZP_DATA: data },
        { home, dataDir: data },
      );
      assert.equal(itemByKey(passwordOnly, "NMZP_PUBLIC_URL").valid, false);
      assert.equal(itemByKey(passwordOnly, "NMZP_PUBLIC_URL").value, "http://ct.example/n");
      assert.equal(JSON.stringify(passwordOnly).includes(password), false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
