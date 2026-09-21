import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256Text } from "./install-fs.ts";
import { hostHookWrite } from "./host-adapters.ts";
import { joinDevice, leaveDevice } from "./install.ts";

const NODE = "/usr/bin/node";
const ENTRY = "/opt/nmzp/nmzp.mjs";

function baseOpts(home: string) {
  return {
    home,
    bundle: { url: "https://synthetic.invalid", caPem: "fixture", fingerprintSha256: "a".repeat(64), ticket: "synthetic-ticket" },
    nodePath: process.execPath,
    coreDir: import.meta.dirname,
    os: "linux" as const,
    skipRegister: true,
    skipStartup: true,
    skipProbe: true,
    copyRuntime: async () => {},
    transport: {
      join: async () => ({ status: 200, body: JSON.stringify({ deviceId: "synthetic", deviceToken: "synthetic-test-only" }) }),
      policy: async () => ({ status: 503, body: "" }),
    },
    snapshotGuardStatus: async () => ({}),
    probeController: { isOwnRunning: async () => false, start: async () => ({ ok: true }), stopOwn: async () => ({ ok: true, stopped: true }) },
  };
}

type Manifest = {
  antigravityPath?: string;
  antigravity?: { created: boolean; writtenSha256: string };
  hostFiles?: Array<{ agent: string; path: string; created: boolean; writtenSha256: string }>;
};

async function manifestOf(home: string): Promise<Manifest> {
  return JSON.parse(await readFile(join(home, ".nmzp", "manifest.json"), "utf8")) as Manifest;
}

describe("re-join keeps track of hook files it wrote earlier, so leave can still clean them", () => {
  it("Antigravity: gate dir removed after join → path carried in manifest → leave removes the file we created", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-carry-agy-"));
    const base = baseOpts(home);
    const hooksPath = join(home, ".gemini", "config", "hooks.json");
    try {
      await mkdir(join(home, ".gemini", "antigravity"), { recursive: true });
      await joinDevice(base);
      assert.ok(existsSync(hooksPath));
      assert.equal((await manifestOf(home)).antigravityPath, hooksPath);

      await rm(join(home, ".gemini", "antigravity"), { recursive: true, force: true });
      await joinDevice(base);
      const m = await manifestOf(home);
      assert.equal(m.antigravityPath, hooksPath, "carried even though the gate is gone");
      assert.equal(m.antigravity?.created, true);
      assert.equal(m.antigravity?.writtenSha256, sha256Text(await readFile(hooksPath, "utf8")));

      await leaveDevice({ home, os: "linux", skipRegister: true, probeController: base.probeController });
      assert.equal(existsSync(hooksPath), false, "leave still removes the file we created");
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  it("hostFiles: entries whose file still exists are carried, entries whose file is gone are dropped", async () => {
    const home = await mkdtemp(join(tmpdir(), "nmzp-carry-hosts-"));
    const base = baseOpts(home);
    const kimiPath = join(home, ".kimi-code", "config.toml");
    const orphanPath = join(home, ".qwen-old", "settings.json");
    const gonePath = join(home, ".trae-old", "hooks.json");
    try {
      await mkdir(join(home, ".kimi-code"), { recursive: true });
      await joinDevice(base);
      let m = await manifestOf(home);
      assert.deepEqual(m.hostFiles?.map((h) => [h.agent, h.path]), [["kimi", kimiPath]]);

      // Simulate a file NMZP wrote under an older gate rule: still on disk, no longer targeted.
      const orphanBody = hostHookWrite("qwen", null, NODE, ENTRY, "linux");
      await mkdir(join(home, ".qwen-old"), { recursive: true });
      await writeFile(orphanPath, orphanBody);
      m.hostFiles!.push({ agent: "qwen", path: orphanPath, created: true, writtenSha256: sha256Text(orphanBody) });
      m.hostFiles!.push({ agent: "trae", path: gonePath, created: true, writtenSha256: sha256Text("x") });
      await writeFile(join(home, ".nmzp", "manifest.json"), JSON.stringify(m, null, 2));

      await joinDevice(base);
      m = await manifestOf(home);
      const paths = m.hostFiles!.map((h) => h.path);
      assert.ok(paths.includes(kimiPath), "current target kept");
      assert.ok(paths.includes(orphanPath), "existing orphan carried");
      assert.equal(paths.includes(gonePath), false, "missing file dropped");
      assert.equal(m.hostFiles!.filter((h) => h.path === orphanPath).length, 1, "no duplicates");
      assert.equal(m.hostFiles!.find((h) => h.path === orphanPath)?.created, true);

      await leaveDevice({ home, os: "linux", skipRegister: true, probeController: base.probeController });
      assert.equal(existsSync(orphanPath), false, "orphan we created and never changed is removed");
      assert.equal(existsSync(kimiPath), false);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});
