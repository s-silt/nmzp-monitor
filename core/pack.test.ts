import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { isPackEntrypoint, packRelease, resolveInsidePackDir } from "./pack.ts";

const coreDir = dirname(fileURLToPath(import.meta.url));

async function fakeRepo(opts?: { ui?: boolean }): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "nmzp-pack-"));
  await mkdir(join(repo, "core"), { recursive: true });
  await writeFile(join(repo, "core", "nmzp.mjs"), "export {}\n");
  await writeFile(join(repo, "core", "nmzp.service"), "[Service]\nExecStart=/usr/local/bin/node x\n");
  await mkdir(join(repo, "src", "lib", "monitor"), { recursive: true });
  await writeFile(join(repo, "src", "lib", "monitor", "engine.ts"), "export {}\n");
  if (opts?.ui !== false) {
    await mkdir(join(repo, "dist", "assets"), { recursive: true });
    await writeFile(join(repo, "dist", "index.html"), "<html><script src='/assets/x.js'></script></html>\n");
    await writeFile(join(repo, "dist", "assets", "x.js"), "console.log(1)\n");
  }
  return repo;
}

describe("pack release", () => {
  it("throws when dist/index.html is missing", async () => {
    const repo = await fakeRepo({ ui: false });
    try {
      await assert.rejects(() => packRelease(repo), /pack_missing_ui_dist/);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("writes a real tgz plus SHA256 and includes the UI", async () => {
    const repo = await fakeRepo();
    try {
      const r = await packRelease(repo);
      assert.equal(existsSync(r.tgz), true);
      const buf = readFileSync(r.tgz);
      assert.equal(buf[0], 0x1f);
      assert.equal(buf[1], 0x8b);
      const tar = gunzipSync(buf);
      assert.ok(tar.includes(Buffer.from("ustar")));
      assert.ok(tar.includes(Buffer.from("index.html")));
      const sums = await readFile(join(repo, ".pack", "SHA256SUMS"), "utf8");
      const hash = createHash("sha256").update(buf).digest("hex");
      assert.ok(sums.includes(hash));
      assert.ok(r.files.some((f) => f.path === "ui/index.html" || f.path.endsWith("index.html")));
      assert.ok(existsSync(join(r.dir, "nmzp.service")));
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("refuses recursive delete outside repo/.pack", () => {
    const repo = join(tmpdir(), "nmzp-pack-root");
    assert.throws(() => resolveInsidePackDir(repo, join(repo, "core")), /pack_rm_outside_pack_dir/);
    assert.throws(() => resolveInsidePackDir(repo, join(repo, ".pack", "nmzp", "..", "..", "core")), /pack_rm_outside_pack_dir/);
    const ok = resolveInsidePackDir(repo, join(repo, ".pack", "nmzp"));
    assert.ok(ok.replace(/\\/g, "/").toLowerCase().includes("/.pack/"));
  });

  it("windows-style argv is treated as the pack entrypoint", () => {
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "C:\\repo\\core\\pack.ts"), true);
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "core/pack.ts", "C:\\repo"), true);
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "C:\\repo\\core\\pack.test.ts"), false);
    assert.equal(isPackEntrypoint(new URL("./pack.ts", import.meta.url).href, process.argv[1] ?? ""), false);
  });

  it("service unit matches CT node, nmzp user, and data/app paths", () => {
    const unit = readFileSync(join(coreDir, "nmzp.service"), "utf8");
    assert.match(unit, /ExecStart=\/usr\/local\/bin\/node /);
    assert.match(unit, /^User=nmzp$/m);
    assert.match(unit, /^Group=nmzp$/m);
    assert.match(unit, /NMZP_DATA=\/var\/lib\/nmzp/);
    assert.match(unit, /WorkingDirectory=\/opt\/nmzp/);
    assert.match(unit, /ReadWritePaths=\/var\/lib\/nmzp/);
    assert.doesNotMatch(unit, /nesting/i);
  });
});

it("packed monitor bridge resolves and experimental components stay outside the release", async () => {
 const repo=await fakeRepo();
 try {
  await writeFile(join(repo,'core','network-evidence.ts'),'export const sample = 42;');
  await mkdir(join(repo,'core','native-agent-sandbox'),{recursive:true});
  await writeFile(join(repo,'core','native-agent-sandbox','unfinished.exe'),'synthetic');
  await writeFile(join(repo,'core','model-gateway.ts'),'throw Error("unfinished");');
  await writeFile(join(repo,'src','lib','monitor','network-evidence.ts'),'export { sample } from "../../../core/network-evidence.ts";');
  const r=await packRelease(repo);
  const {pathToFileURL}=await import('node:url');
  const bridge=await import(pathToFileURL(join(r.dir,'monitor','network-evidence.ts')).href);
  assert.equal(bridge.sample,42);
  assert.ok(!r.files.some(f=>/native-|model-gateway/.test(f.path)));
 } finally { await rm(repo,{recursive:true,force:true}); }
});
