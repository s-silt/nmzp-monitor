import assert from "node:assert/strict";
import cp from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { after, before, describe, it } from "node:test";
import { NMZP_VERSION } from "./constants.ts";
import {
  createProbeController,
  readProbeLock,
  writeProbeLock,
  writeProbeReady,
  type ProbeController,
} from "./install-autostart.ts";
import { FileRollback } from "./install-fs.ts";
import { joinDevice, type JoinOpts } from "./install.ts";

const homes: string[] = [];
const originalSpawn = cp.spawnSync;

function allow(home: string): void {
  homes.push(resolve(home));
}

before(() => {
  cp.spawnSync = ((command: string, args?: readonly string[], options?: { env?: NodeJS.ProcessEnv }) => {
    const list = [...(args ?? [])];
    const script = list.join("\n");
    if (command !== "powershell.exe" || !list.includes("-Command") || !script.includes("SetAccessControl")) {
      throw new Error(`unexpected spawn ${String(command)}`);
    }
    const target = resolve(options?.env?.NMZP_ACL_PATH ?? "");
    const ok = homes.some((home) => target === home || target.startsWith(home + sep));
    if (!ok) throw new Error(`acl outside fixture ${target}`);
    return { status: 0, stdout: "", stderr: "", signal: null, pid: 0, output: [] } as ReturnType<typeof cp.spawnSync>;
  }) as typeof cp.spawnSync;
  syncBuiltinESMExports();
});

after(() => {
  cp.spawnSync = originalSpawn;
  syncBuiltinESMExports();
});

function opts(home: string, extra: Partial<JoinOpts> = {}): JoinOpts {
  allow(home);
  return {
    home,
    bundle: {
      url: "https://synthetic.invalid",
      caPem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
      fingerprintSha256: "ab".repeat(32),
      ticket: "ticket-boundary-1",
    },
    nodePath: process.execPath,
    coreDir: import.meta.dirname,
    os: "linux",
    skipRegister: true,
    skipStartup: true,
    skipProbe: true,
    copyRuntime: async (_core, dest) => {
      fs.mkdirSync(dest, { recursive: true });
      fs.writeFileSync(join(dest, "nmzp.mjs"), "runtime\n");
    },
    transport: {
      async join() {
        return { status: 200, body: JSON.stringify({ deviceId: "dev_boundary", deviceToken: "tok_boundary" }) };
      },
      async policy() {
        return { status: 503, body: "" };
      },
    },
    snapshotGuardStatus: async () => ({}),
    probeController: {
      async isOwnRunning() {
        return false;
      },
      async start() {
        return { ok: true, pid: 1 };
      },
      async stopOwn() {
        return { ok: true, stopped: true };
      },
    },
    ...extra,
  };
}

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "nmzp-boundary-"));
}

describe("installer boundaries", () => {
  it("empty home creates no primary host directory and still joins", async () => {
    const home = await tempHome();
    try {
      const result = await joinDevice(opts(home));
      assert.equal(fs.existsSync(join(home, ".grok")), false, "empty home created .grok");
      assert.equal(fs.existsSync(join(home, ".claude")), false, "empty home created .claude");
      assert.equal(fs.existsSync(join(home, ".codex")), false, "empty home created .codex");
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), true);
      assert.deepEqual(result.skippedHosts, ["grok", "claude", "codex"]);
      assert.equal(result.codexTrust, "skipped");
      assert.equal(result.codexNotice, undefined);
      assert.match(result.warnings?.join("\n") ?? "", /codex/);
      assert.equal((result.warnings ?? []).some((line) => /modified|hook_untrusted|unknown/.test(line)), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("configures an existing host directory and an explicitly requested missing host", async () => {
    const home = await tempHome();
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await writeFile(join(home, ".claude", "settings.json"), JSON.stringify({ extra: "keep" }));
      const result = await joinDevice(opts(home, { requestedHosts: ["grok"] }));
      assert.equal(fs.existsSync(join(home, ".grok", "hooks")), true);
      const claude = JSON.parse(await readFile(join(home, ".claude", "settings.json"), "utf8")) as { extra?: string };
      assert.equal(claude.extra, "keep");
      assert.equal(result.skippedHosts?.includes("grok"), false);
      assert.equal(result.skippedHosts?.includes("claude"), false);
      assert.equal(result.skippedHosts?.includes("codex"), true);
      assert.equal(fs.existsSync(join(home, ".codex")), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("removes a newly created Claude file when a later host write fails and keeps a sibling", async () => {
    const home = await tempHome();
    const originalRename = fs.renameSync;
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await mkdir(join(home, ".codex"), { recursive: true });
      await writeFile(join(home, ".claude", "other.txt"), "SIBLING");
      fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
        const dest = String(to);
        if (dest.includes(`${sep}.codex${sep}hooks.json`) || dest.endsWith(".codex/hooks.json")) {
          throw new Error("rename_codex");
        }
        return originalRename(from, to);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();
      await assert.rejects(() => joinDevice(opts(home)), /atomic_write_failed/);
      assert.equal(fs.existsSync(join(home, ".claude", "settings.json")), false);
      assert.equal(await readFile(join(home, ".claude", "other.txt"), "utf8"), "SIBLING");
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), false);
      assert.equal(fs.existsSync(join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs")), false);
      assert.equal(fs.existsSync(join(home, ".claude")), true);
    } finally {
      fs.renameSync = originalRename;
      syncBuiltinESMExports();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("fresh Claude failure removes the created host directory when it is empty", async () => {
    const home = await tempHome();
    const originalRename = fs.renameSync;
    try {
      fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
        const dest = String(to);
        if (dest.includes(`${sep}.codex${sep}hooks.json`) || dest.endsWith(".codex/hooks.json")) {
          throw new Error("rename_codex");
        }
        return originalRename(from, to);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();
      await assert.rejects(
        () => joinDevice(opts(home, { requestedHosts: ["claude", "codex"] })),
        (error: unknown) => {
          const message = error instanceof Error ? error.message : "";
          assert.match(message, /atomic_write_failed/);
          assert.equal(message.includes("rollback_incomplete"), false, "fresh host rollback reported incomplete");
          return true;
        },
      );
      assert.equal(fs.existsSync(join(home, ".claude")), false, "fresh claude host directory remains");
      assert.equal(fs.existsSync(join(home, ".codex")), false, "fresh codex host directory remains");
    } finally {
      fs.renameSync = originalRename;
      syncBuiltinESMExports();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("rollback removes an empty owned directory and keeps a directory that received an external file", async () => {
    const home = await tempHome();
    allow(home);
    const empty = join(home, "empty-owned");
    const busy = join(home, "external-owned");
    const replaced = join(home, "replaced-dir");
    const tree = join(home, "owned-tree");
    try {
      await mkdir(empty);
      const gone = new FileRollback(join(home, "backup-empty"));
      gone.noteCreatedDir(empty);
      const removedEmpty = gone.rollback();
      assert.equal(removedEmpty.ok, true, "empty directory rollback failed");
      assert.deepEqual(removedEmpty.failed, []);
      assert.equal(fs.existsSync(empty), false, "empty owned directory remains");
      assert.equal(removedEmpty.removed.includes(empty), true);

      await mkdir(busy);
      await mkdir(join(busy, "nested"));
      await writeFile(join(busy, "user.txt"), "KEEP");
      const keptRollback = new FileRollback(join(home, "backup-busy"));
      keptRollback.noteCreatedDir(busy);
      const kept = keptRollback.rollback();
      assert.equal(kept.ok, true, "nonempty directory rollback failed");
      assert.deepEqual(kept.failed, []);
      assert.equal(fs.existsSync(busy), true, "nonempty directory was removed");
      assert.equal(fs.existsSync(join(busy, "nested")), true, "non-tree rollback deleted a child");
      assert.equal(await readFile(join(busy, "user.txt"), "utf8"), "KEEP");
      assert.equal(kept.preservedExternal.includes(busy), true);
      assert.equal(kept.removed.includes(busy), false);

      await mkdir(replaced);
      const replacedRollback = new FileRollback(join(home, "backup-replaced"));
      replacedRollback.noteCreatedDir(replaced);
      fs.rmdirSync(replaced);
      await writeFile(replaced, "NOWFILE");
      const replacedReport = replacedRollback.rollback();
      assert.equal(replacedReport.ok, true, "replaced directory rollback failed");
      assert.equal(await readFile(replaced, "utf8"), "NOWFILE");
      assert.equal(replacedReport.preservedExternal.includes(replaced), true);
      assert.equal(replacedReport.removed.includes(replaced), false);

      await mkdir(tree);
      await writeFile(join(tree, "owned.txt"), "tree");
      const treeRollback = new FileRollback(join(home, "backup-tree"));
      treeRollback.noteCreatedTree(tree);
      const treeReport = treeRollback.rollback();
      assert.equal(treeReport.ok, true, "owned tree rollback failed");
      assert.equal(fs.existsSync(tree), false, "owned tree remains");
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("restores the exact prior Claude bytes when a later write fails", async () => {
    const home = await tempHome();
    const original = JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "echo user" }] }] }, extra: 1 });
    const originalRename = fs.renameSync;
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await mkdir(join(home, ".codex"), { recursive: true });
      await writeFile(join(home, ".claude", "settings.json"), original);
      fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
        const dest = String(to);
        if (dest.includes(`${sep}.codex${sep}hooks.json`)) throw new Error("rename_codex");
        return originalRename(from, to);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();
      await assert.rejects(() => joinDevice(opts(home)), /atomic_write_failed/);
      assert.equal(await readFile(join(home, ".claude", "settings.json"), "utf8"), original);
    } finally {
      fs.renameSync = originalRename;
      syncBuiltinESMExports();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("reports rollback_incomplete and leaves the file when removal fails", async () => {
    const home = await tempHome();
    const originalRename = fs.renameSync;
    const originalRm = fs.rmSync;
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await mkdir(join(home, ".codex"), { recursive: true });
      fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
        const dest = String(to);
        if (dest.includes(`${sep}.codex${sep}hooks.json`)) throw new Error("rename_codex");
        return originalRename(from, to);
      }) as typeof fs.renameSync;
      fs.rmSync = ((target: fs.PathLike, options?: fs.RmOptions) => {
        if (String(target).endsWith("settings.json")) throw new Error("rm_blocked");
        return originalRm(target, options);
      }) as typeof fs.rmSync;
      syncBuiltinESMExports();
      await assert.rejects(() => joinDevice(opts(home)), /atomic_write_failed; rollback_incomplete: .*settings\.json/);
      assert.equal(fs.existsSync(join(home, ".claude", "settings.json")), true);
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync = originalRm;
      syncBuiltinESMExports();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("keeps an external edit made after the snapshot and before the write", async () => {
    const home = await tempHome();
    const claude = join(home, ".claude", "settings.json");
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await writeFile(claude, JSON.stringify({ extra: "before" }));
      const base = opts(home);
      const transport = {
        async join() {
          await writeFile(claude, JSON.stringify({ extra: "USER_NEW" }));
          return { status: 200, body: JSON.stringify({ deviceId: "dev_boundary", deviceToken: "tok_boundary" }) };
        },
        async policy() {
          return { status: 503, body: "" };
        },
      };
      await assert.rejects(() => joinDevice({ ...base, transport }), /host_config_conflict/, "external edit was overwritten");
      assert.equal(await readFile(claude, "utf8"), JSON.stringify({ extra: "USER_NEW" }));
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("does not roll a host file back over a newer external edit", async () => {
    const home = await tempHome();
    const grok = join(home, ".grok", "hooks", "nmzp.json");
    const originalRename = fs.renameSync;
    try {
      await mkdir(join(home, ".grok", "hooks"), { recursive: true });
      await mkdir(join(home, ".claude"), { recursive: true });
      await writeFile(grok, JSON.stringify({ userKey: "keep-me" }));
      fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
        const dest = String(to);
        if (dest.endsWith("settings.json") && dest.includes(".claude")) {
          fs.writeFileSync(grok, "USER_EDIT");
          throw new Error("rename_claude");
        }
        return originalRename(from, to);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();
      await assert.rejects(() => joinDevice(opts(home)), /atomic_write_failed/);
      assert.equal(await readFile(grok, "utf8"), "USER_EDIT", "rolled back over an external edit");
    } finally {
      fs.renameSync = originalRename;
      syncBuiltinESMExports();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("serializes two joins so their runtime copies do not overlap", async () => {
    const home = await tempHome();
    let active = 0;
    let max = 0;
    let release: () => void = () => undefined;
    const hold = new Promise<void>((resolveHold) => {
      release = resolveHold;
    });
    try {
      const first = opts(home, {
        copyRuntime: async (_core, dest) => {
          active += 1;
          max = Math.max(max, active);
          if (active === 1) await hold;
          fs.mkdirSync(dest, { recursive: true });
          fs.writeFileSync(join(dest, "nmzp.mjs"), "runtime\n");
          active -= 1;
        },
      });
      const second = opts(home, {
        bundle: { ...first.bundle, ticket: "ticket-boundary-2" },
        copyRuntime: first.copyRuntime,
      });
      const pending = Promise.all([joinDevice(first), joinDevice(second)]);
      for (let i = 0; active < 1 && i < 50; i++) await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      assert.equal(max, 1);
      assert.equal(active, 1);
      release();
      const [a, b] = await pending;
      assert.equal(a.deviceId, "dev_boundary");
      assert.equal(b.deviceId, "dev_boundary");
      assert.equal(max, 1);
    } finally {
      release();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("keeps a copied runtime entry after the source directory is removed", async () => {
    const home = await tempHome();
    const source = join(home, "source-tree");
    try {
      await mkdir(join(home, ".claude"), { recursive: true });
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "nmzp.mjs"), "source\n");
      const result = await joinDevice(
        opts(home, {
          coreDir: source,
          copyRuntime: async (_core, dest) => {
            fs.mkdirSync(dest, { recursive: true });
            fs.writeFileSync(join(dest, "nmzp.mjs"), "runtime\n");
          },
        }),
      );
      await rm(source, { recursive: true, force: true });
      assert.equal(await readFile(join(result.runtimeDir, "nmzp.mjs"), "utf8"), "runtime\n");
      const settings = JSON.parse(await readFile(join(home, ".claude", "settings.json"), "utf8")) as {
        hooks: { PreToolUse: Array<{ hooks: Array<{ command?: string }> }> };
      };
      const command = settings.hooks.PreToolUse.flatMap((row) => row.hooks.map((hook) => hook.command ?? "")).join("\n");
      const decoded = command.includes("EncodedCommand")
        ? Buffer.from(command.split("EncodedCommand")[1]?.trim().split(/\s+/)[0] ?? "", "base64").toString("utf16le")
        : command;
      const runtime = result.runtimeDir.replace(/\\/g, "/");
      const shown = decoded.replace(/\\/g, "/");
      assert.equal(shown.includes(runtime), true);
      assert.equal(shown.includes(source.replace(/\\/g, "/")), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("warns when Codex trust was modified and does not change config.toml", async () => {
    const home = await tempHome();
    const hooksPath = join(home, ".codex", "hooks.json");
    const toml = join(home, ".codex", "config.toml");
    const before = `[hooks.state.'${hooksPath}:pre_tool_use:0:0']\ntrusted_hash = "sha256:stale"\n`;
    try {
      await mkdir(join(home, ".codex"), { recursive: true });
      await writeFile(toml, before);
      const result = await joinDevice(opts(home));
      assert.equal(await readFile(toml, "utf8"), before);
      assert.equal(result.codexTrust, "modified");
      assert.match(result.codexNotice ?? "", /modified/, "codex modified notice missing");
      assert.match(result.codexNotice ?? "", /\/hooks approve NMZP PreToolUse v1/);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

function pidDead(pid: number, waitMs: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  const started = Date.now();
  const slot = new Int32Array(new SharedArrayBuffer(4));
  do {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    Atomics.wait(slot, 0, 0, 20);
  } while (Date.now() - started < waitMs);
  return false;
}

function probeCommand(entry: string): string {
  return `"${process.execPath}" "${entry}" probe`;
}

interface ProbeRollbackHarness {
  controller: ProbeController;
  initialPid: number;
  order: string[];
  spawns: string[];
  ownedPid: () => number;
  strangerPid: number;
  filesRolledBackBeforeRestore: () => boolean;
  ownedStoppedBeforeRestore: () => boolean;
  killAll: () => void;
}

function installManifestBarrier(onFail: () => void): () => void {
  const original = fs.renameSync;
  fs.renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
    const dest = String(to).replace(/\\/g, "/");
    if (dest.endsWith("/manifest.json")) {
      onFail();
      throw new Error("rename_manifest");
    }
    return original(from, to);
  }) as typeof fs.renameSync;
  syncBuiltinESMExports();
  return () => {
    fs.renameSync = original;
    syncBuiltinESMExports();
  };
}

async function probeRollbackHarness(
  home: string,
  mode: "replace" | "reuse",
  options?: {
    failRestore?: boolean;
    onManifest?: () => void;
    readyTimeoutMs?: number;
    failFileRollback?: boolean;
    failNewStart?: boolean;
    failLockWrite?: boolean;
  },
): Promise<ProbeRollbackHarness> {
  const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
  const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
  const initialEntry = mode === "reuse" ? nextEntry : oldEntry;
  await mkdir(join(home, ".nmzp"), { recursive: true });
  await mkdir(dirname(initialEntry), { recursive: true });
  await writeFile(initialEntry, "prior-runtime\n");
  if (mode === "replace") {
    await writeFile(join(dirname(oldEntry), "marker.txt"), "keep-old-runtime\n");
  }
  const children: Array<ReturnType<typeof cp.spawn>> = [];
  const spawnLive = () => {
    const child = cp.spawn(process.execPath, ["-e", "setInterval(()=>{},1000000)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    children.push(child);
    if (!child.pid) throw new Error("probe_child_missing");
    return child.pid;
  };
  const initialPid = spawnLive();
  const strangerPid = spawnLive();
  const identities = new Map<number, string>([[initialPid, initialEntry]]);
  let trust = true;
  let ownedPid = 0;
  const order: string[] = [];
  const spawns: string[] = [];
  let filesRolledBack = false;
  let ownedStopped = false;
  writeProbeLock(home, {
    pid: initialPid,
    marker: "nmzp-probe",
    version: mode === "reuse" ? NMZP_VERSION : "0.0.1",
    startedAt: Date.now(),
    nonce: "prior-nonce",
    nodePath: process.execPath,
    entry: initialEntry,
  });
  writeProbeReady(home, { pid: initialPid, nonce: "prior-nonce" });
  const controller = createProbeController({
    readyTimeoutMs: options?.readyTimeoutMs ?? 2000,
    inspectPid: async (pid) => {
      const entry = identities.get(pid);
      if (!entry || !trust) {
        return {
          pid,
          exe: process.execPath,
          cmdline: `"${process.execPath}" -e setInterval(()=>{},1000)`,
          createdAt: Date.now(),
        };
      }
      return { pid, exe: process.execPath, cmdline: probeCommand(entry), createdAt: Date.now() };
    },
    spawnProbe: ({ entry, home: probeHome, nonce }) => {
      spawns.push(entry);
      order.push(`spawn:${entry}`);
      const pid = spawnLive();
      identities.set(pid, entry);
      if (entry === oldEntry) {
        filesRolledBack =
          !fs.existsSync(join(home, ".nmzp", "credentials.json")) &&
          !fs.existsSync(join(home, ".nmzp", "manifest.json")) &&
          !fs.existsSync(join(home, ".nmzp", "runtime", NMZP_VERSION)) &&
          fs.existsSync(join(home, ".nmzp", "runtime", "0.0.1", "marker.txt"));
        ownedStopped = pidDead(ownedPid, 1000);
      } else {
        ownedPid = pid;
      }
      const skipReady =
        (options?.failNewStart && entry !== oldEntry) || (options?.failRestore && entry === oldEntry);
      if (!skipReady) writeProbeReady(probeHome, { pid, nonce });
      return {
        pid,
        kill: () => {
          try {
            process.kill(pid);
          } catch {
            /* already stopped */
          }
        },
      };
    },
  });
  const release = installManifestBarrier(() => {
    order.push("manifest-failed");
    options?.onManifest?.();
    if (options?.onManifest) trust = false;
  });
  const originalRm = fs.rmSync;
  let notedFile = false;
  fs.rmSync = ((target: fs.PathLike, rmOptions?: fs.RmOptions) => {
    const dest = String(target).replace(/\\/g, "/");
    if (dest.includes(`/runtime/${NMZP_VERSION}`) && ownedPid > 0 && !pidDead(ownedPid, 0)) {
      order.push("deleted-runtime-while-live");
    }
    if (!notedFile && ownedPid > 0 && (dest.endsWith("/credentials.json") || dest.includes(`/runtime/${NMZP_VERSION}`))) {
      notedFile = true;
      order.push(pidDead(ownedPid, 0) ? "files-after-stop" : "files-before-stop");
    }
    if (options?.failFileRollback && dest.includes(`/runtime/${NMZP_VERSION}`)) throw new Error("rm_runtime_blocked");
    return originalRm(target, rmOptions);
  }) as typeof fs.rmSync;
  const originalWrite = fs.writeFileSync;
  let lockWrites = 0;
  if (options?.failLockWrite) {
    fs.writeFileSync = ((path: fs.PathOrFileDescriptor, data: string | ArrayBufferView, writeOptions?: fs.WriteFileOptions) => {
      if (typeof path === "string" && path.replace(/\\/g, "/").endsWith("/probe.pid")) {
        lockWrites += 1;
        if (lockWrites === 1) {
          const error = new Error("lock_eio") as NodeJS.ErrnoException;
          error.code = "EIO";
          throw error;
        }
      }
      return originalWrite(path, data as never, writeOptions);
    }) as typeof fs.writeFileSync;
  }
  syncBuiltinESMExports();
  let released = false;
  const releaseOnce = () => {
    if (released) return;
    released = true;
    fs.rmSync = originalRm;
    fs.writeFileSync = originalWrite;
    release();
  };
  return {
    controller,
    initialPid,
    order,
    spawns,
    ownedPid: () => ownedPid,
    strangerPid,
    filesRolledBackBeforeRestore: () => filesRolledBack,
    ownedStoppedBeforeRestore: () => ownedStopped,
    killAll: () => {
      releaseOnce();
      for (const child of children) {
        try {
          if (child.pid) process.kill(child.pid);
        } catch {
          /* already stopped */
        }
      }
    },
  };
}

describe("P2 probe rollback", () => {
  it("P2 joinDevice manifest failure after probe upgrade restores the verified prior probe", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    try {
      harness = await probeRollbackHarness(home, "replace");
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /atomic_write_failed/);
      assert.equal(message.includes("rollback_incomplete"), false, "probe recovery was reported incomplete");
      assert.deepEqual(
        harness.order.filter((item) => item.startsWith("spawn:") || item === "manifest-failed" || item.startsWith("files-")),
        [
          `spawn:${join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs")}`,
          "manifest-failed",
          "files-after-stop",
          `spawn:${join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs")}`,
        ],
      );
      assert.equal(harness.filesRolledBackBeforeRestore(), true, "prior probe was restored before file rollback");
      assert.equal(harness.ownedStoppedBeforeRestore(), true, "owned probe was still running at restore");
      assert.equal(pidDead(harness.initialPid, 1000), true, "original prior pid was not stopped");
      const lock = readProbeLock(home);
      assert.equal(lock?.entry, join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs"));
      assert.equal(lock?.version, "0.0.1");
      assert.equal(pidDead(lock?.pid ?? 0, 200), false, "restored probe is not running");
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), false, "credentials survived rollback");
      assert.equal(fs.existsSync(join(home, ".nmzp", "manifest.json")), false, "manifest survived rollback");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice does not stop a probe that already matches the requested runtime", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    try {
      harness = await probeRollbackHarness(home, "reuse");
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /atomic_write_failed/);
      assert.equal(message.includes("rollback_incomplete"), false, "current probe rollback was reported incomplete");
      assert.deepEqual(harness.spawns, []);
      assert.equal(pidDead(harness.initialPid, 200), false, "current probe was stopped");
      assert.equal(readProbeLock(home)?.pid, harness.initialPid);
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), false, "credentials survived rollback");
      assert.equal(fs.existsSync(join(home, ".nmzp", "manifest.json")), false, "manifest survived rollback");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice reports rollback_incomplete when probe recovery fails", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    try {
      harness = await probeRollbackHarness(home, "replace", { failRestore: true, readyTimeoutMs: 200 });
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /atomic_write_failed/);
      assert.match(message, /rollback_incomplete/);
      assert.match(message, /probe_restore_failed/);
      assert.equal(harness.filesRolledBackBeforeRestore(), true, "restore ran before file rollback");
      assert.equal(pidDead(harness.ownedPid(), 1000), true, "owned probe kept running");
      assert.equal(pidDead(harness.initialPid, 1000), true, "prior probe was still the original process");
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), false, "credentials survived rollback");
      assert.notEqual(readProbeLock(home)?.entry, join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs"));
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice does not kill an unverified reused pid and reports rollback_incomplete", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    try {
      harness = await probeRollbackHarness(home, "replace", {
        onManifest: () => {
          writeProbeLock(home, {
            pid: harness?.strangerPid ?? 0,
            marker: "nmzp-probe",
            version: NMZP_VERSION,
            startedAt: Date.now(),
            nonce: "stranger-nonce",
            nodePath: process.execPath,
            entry: join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs"),
          });
        },
      });
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /rollback_incomplete/);
      assert.match(message, /probe_stop_unverified/);
      assert.deepEqual(harness.spawns, [join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs")]);
      assert.equal(pidDead(harness.ownedPid(), 300), false, "unverified owned pid was killed");
      assert.equal(pidDead(harness.strangerPid, 300), false, "stranger pid was killed");
      assert.equal(fs.existsSync(join(home, ".nmzp", "credentials.json")), true, "live probe files were removed");
      assert.equal(fs.existsSync(join(home, ".nmzp", "runtime", NMZP_VERSION)), true, "live probe runtime was removed");
      assert.equal(harness.order.includes("files-after-stop"), false, "files were rolled back while the probe was unverified");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice does not launch the prior probe when file rollback fails", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    try {
      harness = await probeRollbackHarness(home, "replace", { failFileRollback: true });
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /rollback_incomplete/);
      assert.match(message, /probe_restore_blocked/);
      assert.deepEqual(harness.spawns, [nextEntry]);
      assert.equal(harness.order.includes(`spawn:${oldEntry}`), false, "prior probe launched after incomplete file rollback");
      assert.equal(pidDead(harness.ownedPid(), 1000), true, "owned probe kept running");
      assert.equal(harness.order.includes("files-after-stop"), true, "file rollback ran before the owned probe exited");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice lock-write failure stops the child before deleting its runtime", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    const oldEntry = join(home, ".nmzp", "runtime", "0.0.1", "nmzp.mjs");
    try {
      harness = await probeRollbackHarness(home, "replace", { failLockWrite: true });
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /probe_start_failed/);
      assert.equal(message.includes("rollback_incomplete"), false, "settled start failure was reported incomplete");
      assert.deepEqual(
        harness.order.filter((item) => item.startsWith("spawn:") || item.startsWith("files-") || item === "deleted-runtime-while-live"),
        [`spawn:${nextEntry}`, "files-after-stop", `spawn:${oldEntry}`],
      );
      assert.equal(pidDead(harness.ownedPid(), 1000), true, "ready child stayed alive");
      assert.equal(harness.filesRolledBackBeforeRestore(), true, "prior probe started before file rollback");
      assert.equal(readProbeLock(home)?.entry, oldEntry);
      assert.equal(fs.existsSync(join(home, ".nmzp", "runtime", NMZP_VERSION)), false, "new runtime survived a settled rollback");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });

  it("P2 joinDevice does not start the prior probe when a failed start cannot restore files", async () => {
    const home = await tempHome();
    let harness: ProbeRollbackHarness | undefined;
    const nextEntry = join(home, ".nmzp", "runtime", NMZP_VERSION, "nmzp.mjs");
    try {
      harness = await probeRollbackHarness(home, "replace", { failNewStart: true, failFileRollback: true, readyTimeoutMs: 200 });
      let message = "";
      try {
        await joinDevice(opts(home, { skipProbe: false, probeController: harness.controller }));
      } catch (error) {
        message = error instanceof Error ? error.message : "unknown";
      }
      assert.match(message, /probe_start_failed/);
      assert.match(message, /rollback_incomplete/);
      assert.match(message, /probe_restore_blocked/);
      assert.deepEqual(harness.spawns, [nextEntry]);
      assert.equal(pidDead(harness.ownedPid(), 1000), true, "failed child stayed alive");
      assert.equal(harness.order.includes("deleted-runtime-while-live"), false, "live child runtime was deleted");
      assert.equal(fs.existsSync(join(home, ".nmzp", "runtime", NMZP_VERSION)), true, "runtime was removed while rollback was incomplete");
    } finally {
      harness?.killAll();
      await rm(home, { recursive: true, force: true });
    }
  });
});
