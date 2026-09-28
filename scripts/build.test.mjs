import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { gunzipSync } from "node:zlib";
import { hasImportMetaSyntax, isPackEntrypoint, packRelease, resolveInsidePackDir } from "./release-archive.mjs";

const require = createRequire(import.meta.url);
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const coreDir = join(repoRoot, "core");

async function fakeRepo(opts) {
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

function readTarEntries(tar) {
  const entries = [];
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const nameField = header.subarray(0, 100).toString("utf8").replace(/\0.*/, "");
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*/, "");
    const name = prefix ? `${prefix}/${nameField}` : nameField;
    const modeText = header.subarray(100, 108).toString("utf8").replace(/\0.*/, "").trim();
    const sizeText = header.subarray(124, 136).toString("utf8").replace(/\0.*/, "").trim();
    const mtimeText = header.subarray(136, 148).toString("utf8").replace(/\0.*/, "").trim();
    const storedText = header.subarray(148, 156).toString("utf8").replace(/\0.*/, "").trim();
    if (!/^[0-7]+$/.test(modeText)) throw new Error("tar mode is not octal");
    if (!/^[0-7]+$/.test(sizeText)) throw new Error("tar size is not octal");
    if (!/^[0-7]+$/.test(storedText)) throw new Error("tar checksum is not octal");
    let actual = 0;
    for (let index = 0; index < 512; index++) actual += index >= 148 && index < 156 ? 0x20 : header[index];
    if (actual !== Number.parseInt(storedText, 8)) throw new Error(`tar checksum mismatch for ${name}`);
    const size = Number.parseInt(sizeText, 8);
    if (!Number.isSafeInteger(size)) throw new Error("tar size is not a safe integer");
    const dataEnd = offset + 512 + size;
    if (!Number.isSafeInteger(dataEnd) || dataEnd > tar.length) throw new Error("tar size runs past the buffer end");
    entries.push({
      name,
      mtime: Number.parseInt(mtimeText, 8),
      modeText,
      mode: Number.parseInt(modeText, 8),
      data: Buffer.from(tar.subarray(offset + 512, dataEnd)),
    });
    const padded = Math.ceil(size / 512) * 512;
    const next = offset + 512 + padded;
    if (!Number.isSafeInteger(next) || next > tar.length) break;
    offset = next;
  }
  return entries;
}

function entryByName(entries, name) {
  const found = entries.find((entry) => entry.name === name);
  if (!found) throw new Error(`missing tar entry ${name}`);
  return found;
}

function sha256sumCheck(sumsFile, directory) {
  const text = readFileSync(sumsFile, "utf8");
  if (!text.endsWith("\n")) return false;
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.some((line) => line.length === 0)) return false;
  for (const line of lines) {
    const match = /^([0-9a-f]{64}) {2}([^\r]+)$/.exec(line);
    if (!match?.[1] || !match[2]) return false;
    const target = join(directory, match[2]);
    if (!existsSync(target)) return false;
    const digest = createHash("sha256").update(readFileSync(target)).digest("hex");
    if (digest !== match[1]) return false;
  }
  return true;
}

function bundled(dir) {
  return require(join(dir, "nmzp-main.cjs"));
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
      const sumsPath = join(repo, ".pack", "SHA256SUMS.txt");
      assert.equal(existsSync(sumsPath), true, "missing .pack/SHA256SUMS.txt");
      const sums = await readFile(sumsPath, "utf8");
      const hash = createHash("sha256").update(buf).digest("hex");
      assert.equal(sums, `${hash}  nmzp-core.tgz\n`);
      assert.equal(existsSync(join(repo, ".pack", "SHA256SUMS")), false);
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

  it("includes nested policy runtime modules without shipping their test programs", async () => {
    const repo = await fakeRepo();
    try {
      await mkdir(join(repo, "core", "policy"));
      await writeFile(join(repo, "core", "policy", "nmzp-service.ts"), "export const policyMarker = \"policy-service\";\n");
      await writeFile(join(repo, "core", "policy", "nmzp-service.test.mjs"), "throw Error('test-only');\n");
      await mkdir(join(repo, "core", "audit"));
      await writeFile(join(repo, "core", "audit", "runtime.ts"), "export const auditMarker = \"audit-runtime\";\n");
      await writeFile(join(repo, "core", "audit", "runtime-worker.ts"), "export const workerMarker = \"audit-worker\";\n");
      await writeFile(join(repo, "core", "audit", "events.ts"), "export const eventsMarker = \"audit-events\";\n");
      await writeFile(join(repo, "core", "audit", "runtime.test.mjs"), "throw Error('test-only');\n");
      await writeFile(join(repo, "core", "atomic-file.ts"), "export const atomicMarker = \"atomic\";\n");
      await writeFile(join(repo, "core", "file-lock.ts"), "export const lockMarker = \"lock\";\n");
      await writeFile(
        join(repo, "core", "cli.ts"),
        "export { policyMarker } from \"./policy/nmzp-service.ts\";\nexport { auditMarker } from \"./audit/runtime.ts\";\nexport { workerMarker } from \"./audit/runtime-worker.ts\";\nexport { eventsMarker } from \"./audit/events.ts\";\nexport { atomicMarker } from \"./atomic-file.ts\";\nexport { lockMarker } from \"./file-lock.ts\";\nexport async function main() { return 0; }\n",
      );
      const packed = await packRelease(repo);
      const loaded = bundled(packed.dir);
      assert.equal(loaded.policyMarker, "policy-service");
      assert.equal(loaded.auditMarker, "audit-runtime");
      assert.equal(loaded.workerMarker, "audit-worker");
      assert.equal(loaded.eventsMarker, "audit-events");
      assert.equal(loaded.atomicMarker, "atomic");
      assert.equal(loaded.lockMarker, "lock");
      assert.equal(existsSync(join(packed.dir, "audit", "runtime-worker.cjs")), true);
      assert.ok(!packed.files.some((file) => file.path.includes(".test.")));
      assert.ok(!packed.files.some((file) => file.path.endsWith("nmzp-service.ts") || file.path.endsWith("runtime.test.mjs")));
    } finally { await rm(repo, { recursive: true, force: true }); }
  });

  it("windows-style argv is treated as the pack entrypoint", () => {
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "C:\\repo\\core\\pack.ts"), true);
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "core/pack.ts", "C:\\repo"), true);
    assert.equal(isPackEntrypoint("file:///C:/repo/core/pack.ts", "C:\\repo\\core\\pack.test.ts"), false);
    assert.equal(isPackEntrypoint(new URL("./build.mjs", import.meta.url).href, process.argv[1] ?? ""), false);
  });

  it("copies the nmzp entry bytes onto the executable name", async () => {
    const repo = await fakeRepo();
    try {
      const source = await readFile(join(coreDir, "nmzp.mjs"));
      await writeFile(join(repo, "core", "nmzp.mjs"), source);
      const packed = await packRelease(repo);
      const launcher = await readFile(join(packed.dir, "nmzp"));
      const entry = await readFile(join(packed.dir, "nmzp.mjs"));
      let crlfPairs = 0;
      for (let index = 0; index < source.length; index++) {
        if (source[index] === 0x0d && source[index + 1] === 0x0a) crlfPairs += 1;
      }
      assert.ok(launcher.equals(entry), "nmzp and nmzp.mjs diverged");
      const normalized = Buffer.from(source.toString("latin1").replaceAll("\r\n", "\n"), "latin1");
      assert.equal(launcher.length, source.length - crlfPairs);
      assert.ok(launcher.equals(normalized), "packed entry is not the LF form of the source");
      assert.equal(launcher.includes(0x0d), false, "packed launcher still contains CR");
      assert.ok(launcher.includes(Buffer.from("./cli.ts")));
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
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

  it("repeated pack across a clock change yields a byte-identical archive", async () => {
    const repo = await fakeRepo();
    const realNow = Date.now;
    try {
      await writeFile(join(repo, "core", "cli.ts"), "export const value = 1;\nexport async function main() { return value; }\n");
      await writeFile(join(repo, "core", "B.txt"), "b\n");
      await writeFile(join(repo, "core", "a.txt"), "a\n");
      await mkdir(join(repo, "core", "nested"));
      await writeFile(join(repo, "core", "nested", "leaf.txt"), "leaf\n");
      const firstResult = await packRelease(repo);
      const first = readFileSync(firstResult.tgz);
      const firstHash = createHash("sha256").update(first).digest("hex");
      Date.now = () => realNow() + 5000;
      const second = readFileSync((await packRelease(repo)).tgz);
      const secondHash = createHash("sha256").update(second).digest("hex");
      assert.equal(secondHash, firstHash, "archive bytes differ across a clock change");
      assert.ok(second.equals(first));
      assert.equal(second[9], 255);
      assert.equal(second.readUInt32LE(4), 0);
      const paths = firstResult.files.map((file) => file.path);
      assert.ok(paths.indexOf("B.txt") < paths.indexOf("a.txt"));
      const names = readTarEntries(gunzipSync(first)).map((entry) => entry.name);
      assert.ok(names.indexOf("nmzp/B.txt") < names.indexOf("nmzp/a.txt"));
      assert.ok(names.indexOf("nmzp/nested/") < names.indexOf("nmzp/nested/leaf.txt"));
    } finally {
      Date.now = realNow;
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("changing one input byte changes the archive", async () => {
    const repo = await fakeRepo();
    try {
      const firstHash = createHash("sha256").update(readFileSync((await packRelease(repo)).tgz)).digest("hex");
      const htmlPath = join(repo, "dist", "index.html");
      const html = await readFile(htmlPath);
      html[0] = (html[0] ?? 0) ^ 1;
      await writeFile(htmlPath, html);
      const secondHash = createHash("sha256").update(readFileSync((await packRelease(repo)).tgz)).digest("hex");
      assert.notEqual(secondHash, firstHash);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("invalid SOURCE_DATE_EPOCH is rejected", async () => {
    const previous = process.env.SOURCE_DATE_EPOCH;
    const repos = [];
    try {
      for (const bad of ["abc", "-1", "1e9", "999999999999"]) {
        process.env.SOURCE_DATE_EPOCH = bad;
        const repo = await fakeRepo();
        repos.push(repo);
        await assert.rejects(() => packRelease(repo), /pack_invalid_source_date_epoch/, "invalid SOURCE_DATE_EPOCH was accepted");
        assert.equal(existsSync(join(repo, "nmzp-core.tgz")), false);
        assert.equal(existsSync(join(repo, ".pack")), false);
      }
    } finally {
      if (previous === undefined) delete process.env.SOURCE_DATE_EPOCH;
      else process.env.SOURCE_DATE_EPOCH = previous;
      await Promise.all(repos.map((repo) => rm(repo, { recursive: true, force: true })));
    }
  });

  it("SOURCE_DATE_EPOCH sets every tar header mtime", async () => {
    const previous = process.env.SOURCE_DATE_EPOCH;
    const repo = await fakeRepo();
    try {
      process.env.SOURCE_DATE_EPOCH = "1700000000";
      const tar = gunzipSync(readFileSync((await packRelease(repo)).tgz));
      const entries = readTarEntries(tar);
      assert.ok(entries.length > 1);
      for (const entry of entries) assert.equal(entry.mtime, 1700000000);
    } finally {
      if (previous === undefined) delete process.env.SOURCE_DATE_EPOCH;
      else process.env.SOURCE_DATE_EPOCH = previous;
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("packed launcher has an LF shebang and executable mode", async () => {
    const repo = await fakeRepo();
    const lfRepo = await fakeRepo();
    try {
      const crlf = "#!/usr/bin/env node\r\nconsole.log(1)\r\n";
      const lf = "#!/usr/bin/env node\nconsole.log(1)\n";
      await writeFile(join(repo, "core", "nmzp.mjs"), crlf);
      await writeFile(join(repo, "core", "pack.sh"), "echo ok\r\n");
      await writeFile(join(lfRepo, "core", "nmzp.mjs"), lf);
      await writeFile(join(lfRepo, "core", "pack.sh"), "echo ok\n");
      const packed = await packRelease(repo);
      const entries = readTarEntries(gunzipSync(readFileSync(packed.tgz)));
      assert.equal(entryByName(entries, "nmzp/").modeText, "0000755");
      for (const name of ["nmzp/nmzp", "nmzp/nmzp.mjs"]) {
        const entry = entryByName(entries, name);
        assert.equal(entry.modeText, "0000755", "launcher mode is not 0000755");
        assert.equal(entry.mode, 0o755);
        assert.equal(entry.data.includes(0x0d), false, "packed launcher still contains CR");
        assert.equal(entry.data.subarray(0, 20).toString("utf8"), "#!/usr/bin/env node\n", "packed launcher shebang is not LF");
        const staged = await readFile(join(packed.dir, name.slice("nmzp/".length)));
        assert.ok(staged.equals(entry.data), "staged launcher bytes differ from the archive");
      }
      const script = entryByName(entries, "nmzp/pack.sh");
      assert.equal(script.modeText, "0000755", "launcher mode is not 0000755");
      assert.equal(script.data.toString("utf8"), "echo ok\n");
      const lfArchive = readFileSync((await packRelease(lfRepo)).tgz);
      assert.ok(lfArchive.equals(readFileSync(packed.tgz)), "CRLF and LF launcher inputs produced different archives");
    } finally {
      await rm(repo, { recursive: true, force: true });
      await rm(lfRepo, { recursive: true, force: true });
    }
  });

  it("systemd unit is packed with LF endings", async () => {
    const repo = await fakeRepo();
    const lfRepo = await fakeRepo();
    try {
      const crlf = "[Service]\r\nExecStart=/usr/local/bin/node x\r\n";
      const lf = "[Service]\nExecStart=/usr/local/bin/node x\n";
      await writeFile(join(repo, "core", "nmzp.service"), crlf);
      await writeFile(join(lfRepo, "core", "nmzp.service"), lf);
      const packed = await packRelease(repo);
      const entry = entryByName(readTarEntries(gunzipSync(readFileSync(packed.tgz))), "nmzp/nmzp.service");
      assert.equal(entry.data.includes(0x0d), false, "packed unit still contains CR");
      assert.equal(entry.data.toString("utf8"), lf);
      assert.equal(entry.modeText, "0000644");
      const staged = await readFile(join(packed.dir, "nmzp.service"));
      assert.ok(staged.equals(entry.data));
      const lfArchive = readFileSync((await packRelease(lfRepo)).tgz);
      assert.ok(lfArchive.equals(readFileSync(packed.tgz)));
    } finally {
      await rm(repo, { recursive: true, force: true });
      await rm(lfRepo, { recursive: true, force: true });
    }
  });

  it("binary bytes stay packed unchanged and shipped text is LF", async () => {
    const repo = await fakeRepo();
    try {
      const binary = Buffer.from([0x00, 0x0d, 0x0a, 0x01, 0x23, 0x21]);
      const nulText = Buffer.concat([Buffer.from("export const x = 1;\r\n", "utf8"), Buffer.from([0x00])]);
      const cmd = Buffer.from("echo hi\r\n", "utf8");
      const ps1 = Buffer.from("Write-Host 1\r\n", "utf8");
      const bat = Buffer.from("@echo off\r\n", "utf8");
      await writeFile(join(repo, "core", "payload.bin"), binary);
      await writeFile(join(repo, "core", "weird.bin"), nulText);
      await writeFile(join(repo, "core", "nmzp.cmd"), cmd);
      await writeFile(join(repo, "core", "tool.ps1"), ps1);
      await writeFile(join(repo, "core", "tool.bat"), bat);
      const packed = await packRelease(repo);
      const entries = readTarEntries(gunzipSync(readFileSync(packed.tgz)));
      for (const [name, body] of [
        ["nmzp/payload.bin", binary],
        ["nmzp/weird.bin", nulText],
      ]) {
        const entry = entryByName(entries, name);
        assert.ok(entry.data.equals(body), `${name} bytes changed`);
        assert.equal(entry.modeText, "0000644", `${name} mode changed`);
        const staged = await readFile(join(packed.dir, name.slice("nmzp/".length)));
        assert.ok(staged.equals(body), `${name} staged bytes changed`);
      }
      for (const [name, lf] of [
        ["nmzp/nmzp.cmd", "echo hi\n"],
        ["nmzp/tool.ps1", "Write-Host 1\n"],
        ["nmzp/tool.bat", "@echo off\n"],
      ]) {
        const entry = entryByName(entries, name);
        const expected = Buffer.from(lf, "utf8");
        assert.ok(entry.data.equals(expected), `${name} is not LF`);
        assert.equal(entry.data.includes(0x0d), false, `${name} still contains CR`);
        assert.equal(entry.modeText, "0000644", `${name} mode changed`);
        const staged = await readFile(join(packed.dir, name.slice("nmzp/".length)));
        assert.ok(staged.equals(entry.data), `${name} staged text differs from the archive`);
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("CRLF and LF text sources pack to the same archive", async () => {
    const logical = new Map([
      ["core/cli.ts", "export const value = 1;\nexport function main() { return value; }\n"],
      ["src/lib/monitor/engine.ts", "export const engine = 1;\n"],
      ["core/README.md", "# Note\n\nSame text.\n"],
      ["core/NOTES.txt", "line one\nline two\n"],
      ["core/settings.json", "{\"ok\": true}\n"],
      ["core/config.yaml", "kind: core\n"],
      ["core/config.yml", "kind: core\n"],
      ["core/config.toml", "kind = \"core\"\n"],
      ["dist/index.html", "<html>\n<body>ok</body>\n</html>\n"],
      ["dist/app.css", "body { color: black; }\n"],
      ["dist/icon.svg", "<svg>\n</svg>\n"],
      ["core/LICENSE", "MIT\n"],
      ["core/acorn.LICENSE", "MIT\n"],
    ]);
    const stagedRel = (sourceRel) => {
      if (sourceRel.startsWith("dist/")) return `ui/${sourceRel.slice("dist/".length)}`;
      if (sourceRel.startsWith("src/lib/monitor/")) return `monitor/${sourceRel.slice("src/lib/monitor/".length)}`;
      return sourceRel.slice("core/".length);
    };
    const copied = [...logical.keys()].filter((rel) => rel !== "core/cli.ts" && rel !== "src/lib/monitor/engine.ts");
    const crRepo = await fakeRepo();
    const lfRepo = await fakeRepo();
    try {
      for (const [rel, text] of logical) {
        await writeFile(join(crRepo, rel), Buffer.from(text.replaceAll("\n", "\r\n"), "utf8"));
        await writeFile(join(lfRepo, rel), Buffer.from(text, "utf8"));
      }
      const crPacked = await packRelease(crRepo);
      const lfPacked = await packRelease(lfRepo);
      const crArchive = readFileSync(crPacked.tgz);
      assert.ok(crArchive.equals(readFileSync(lfPacked.tgz)), "CRLF and LF text sources produced different archives");
      const entries = readTarEntries(gunzipSync(crArchive));
      for (const rel of copied) {
        const packedRel = stagedRel(rel);
        const expected = Buffer.from(logical.get(rel) ?? "", "utf8");
        const staged = await readFile(join(crPacked.dir, packedRel));
        const archived = entryByName(entries, `nmzp/${packedRel}`).data;
        assert.equal(staged.includes(0x0d), false, `staged text still contains CR: ${packedRel}`);
        assert.ok(staged.equals(expected), `staged text is not LF: ${packedRel}`);
        assert.ok(staged.equals(archived), `staged text differs from the archive: ${packedRel}`);
      }
      const bundle = await readFile(join(crPacked.dir, "nmzp-main.cjs"));
      assert.equal(bundle.includes(0x0d), false, "bundle still contains CR");
    } finally {
      await rm(crRepo, { recursive: true, force: true });
      await rm(lfRepo, { recursive: true, force: true });
    }
  });

  it("pack writes a release SHA256SUMS.txt that verifies the produced archive", async () => {
    const repo = await fakeRepo();
    try {
      await mkdir(join(repo, ".pack"), { recursive: true });
      await writeFile(join(repo, ".pack", "SHA256SUMS"), "not-a-release-checksum\n");
      const packed = await packRelease(repo);
      const sumsPath = join(repo, ".pack", "SHA256SUMS.txt");
      assert.equal(existsSync(sumsPath), true, "missing .pack/SHA256SUMS.txt");
      assert.equal(resolve(packed.releaseChecksum), resolve(sumsPath));
      const text = await readFile(sumsPath, "utf8");
      const lines = text.split("\n");
      assert.equal(lines.length, 2, "canonical checksum is not exactly one line");
      assert.equal(lines[1], "");
      assert.match(lines[0] ?? "", /^[0-9a-f]{64} {2}nmzp-core\.tgz$/, "canonical checksum line is not the archive filename");
      const packedTgz = readFileSync(join(repo, ".pack", "nmzp-core.tgz"));
      const digest = createHash("sha256").update(packedTgz).digest("hex");
      assert.equal(lines[0], `${digest}  nmzp-core.tgz`, "canonical digest is not the tgz bytes");
      assert.ok(readFileSync(packed.tgz).equals(packedTgz), "root archive is not the packed archive");
      assert.equal(sha256sumCheck(sumsPath, join(repo, ".pack")), true);
      assert.equal(existsSync(join(repo, ".pack", "SHA256SUMS")), false);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("altered archive fails the canonical checksum", async () => {
    const repo = await fakeRepo();
    const dir = await mkdtemp(join(tmpdir(), "nmzp-sums-"));
    try {
      await packRelease(repo);
      const sums = await readFile(join(repo, ".pack", "SHA256SUMS.txt"));
      const source = readFileSync(join(repo, ".pack", "nmzp-core.tgz"));
      const flipped = Buffer.from(source);
      flipped[flipped.length - 1] = (flipped[flipped.length - 1] ?? 0) ^ 0xff;
      await writeFile(join(dir, "nmzp-core.tgz"), flipped);
      await writeFile(join(dir, "SHA256SUMS.txt"), sums);
      assert.equal(sha256sumCheck(join(dir, "SHA256SUMS.txt"), dir), false, "altered archive passed checksum verification");
      assert.equal(
        createHash("sha256").update(source).digest("hex"),
        createHash("sha256").update(readFileSync(join(repo, ".pack", "nmzp-core.tgz"))).digest("hex"),
      );
    } finally {
      await rm(repo, { recursive: true, force: true });
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("per-file manifest verifies relative to the pack directory", async () => {
    const repo = await fakeRepo();
    try {
      const packed = await packRelease(repo);
      const manifestPath = join(repo, ".pack", "nmzp-files.sha256");
      assert.equal(resolve(packed.fileManifest), resolve(manifestPath));
      assert.equal(sha256sumCheck(manifestPath, join(repo, ".pack")), true, "per-file manifest does not verify");
      const rels = (await readFile(manifestPath, "utf8")).trimEnd().split("\n").map((line) => /^[0-9a-f]{64} {2}(.+)$/.exec(line)?.[1] ?? "");
      assert.ok(rels.length > 0);
      assert.ok(rels.every((rel) => rel.startsWith("nmzp/")));
      const sorted = rels.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      assert.deepEqual(rels, sorted);
      assert.ok(!rels.includes("nmzp-core.tgz"));
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });

  it("pack.sh does not re-pack with system tar", () => {
    const text = readFileSync(join(coreDir, "pack.sh"), "utf8");
    assert.equal(/\btar\s/.test(text), false, "source contract: pack.sh invokes tar");
    assert.match(text, /node scripts\/build\.mjs/);
  });

  it("source contract: gitattributes pins LF for shipped scripts and units", () => {
    const text = readFileSync(join(repoRoot, ".gitattributes"), "utf8");
    assert.match(text, /^\*\.sh text eol=lf$/m);
    assert.match(text, /^\*\.service text eol=lf$/m);
    assert.match(text, /^core\/nmzp\.mjs text eol=lf$/m);
    assert.match(text, /^\.gitattributes text eol=lf$/m);
    assert.doesNotMatch(text, /^\* text=auto$/m);
    assert.doesNotMatch(text, /eol=crlf/);
  });

  it("rejects an acorn version other than 8.18.0 before writing the pack", async () => {
    const repo = await fakeRepo();
    try {
      await assert.rejects(() => packRelease(repo, { readAcornVersion: () => "0.0.0" }), /pack_acorn_version_mismatch/);
      assert.equal(existsSync(join(repo, "nmzp-core.tgz")), false);
      assert.equal(existsSync(join(repo, ".pack")), false);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  });
});

it("packed monitor bridge resolves and experimental components stay outside the release", async () => {
  const repo = await fakeRepo();
  try {
    await writeFile(join(repo, "core", "network-evidence.ts"), "export const sample = 42;\n");
    await mkdir(join(repo, "core", "native-agent-sandbox"), { recursive: true });
    await writeFile(join(repo, "core", "native-agent-sandbox", "unfinished.exe"), "synthetic");
    await writeFile(join(repo, "core", "model-gateway.ts"), "throw Error(\"unfinished\");\n");
    await writeFile(join(repo, "src", "lib", "monitor", "network-evidence.ts"), "export { sample } from \"../../../core/network-evidence.ts\";\n");
    await writeFile(join(repo, "core", "cli.ts"), "import { sample } from \"../src/lib/monitor/network-evidence.ts\";\nexport { sample };\nexport async function main() { return sample; }\n");
    const r = await packRelease(repo);
    assert.equal(bundled(r.dir).sample, 42);
    assert.equal(await bundled(r.dir).main(), 42);
    assert.ok(!r.files.some((f) => /native-|model-gateway/.test(f.path)));
  } finally { await rm(repo, { recursive: true, force: true }); }
});

describe("real checkout bundle", { timeout: 300000 }, () => {
  it("is reproducible, has every worker, and keeps machine paths out of the bundles", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-real-pack-"));
    try {
      await cp(join(repoRoot, "core"), join(root, "core"), { recursive: true });
      await mkdir(join(root, "src", "lib"), { recursive: true });
      await cp(join(repoRoot, "src", "lib", "monitor"), join(root, "src", "lib", "monitor"), { recursive: true });
      await cp(join(repoRoot, "dist"), join(root, "dist"), { recursive: true });
      const first = await packRelease(root);
      const firstBytes = readFileSync(first.tgz);
      const secondBytes = readFileSync((await packRelease(root)).tgz);
      assert.ok(firstBytes.equals(secondBytes), "two packs of the same tree differ");
      assert.deepEqual(first.runtimeDeps, ["acorn"]);
      const workers = ["nmzp-main.cjs", "audit/runtime-worker.cjs", "agent-discovery-worker.cjs", "snapshot-status-worker.cjs", "probe-mailbox-worker.cjs"];
      for (const rel of workers) {
        const file = join(first.dir, rel);
        assert.equal(existsSync(file), true, rel);
        const text = readFileSync(file, "utf8");
        assert.equal(hasImportMetaSyntax(text), false, rel);
        const stripped = text.split("|~|/home/").join("");
        assert.equal(stripped.includes("C:/Users"), false, rel);
        assert.equal(stripped.includes("C:\\Users"), false, rel);
        assert.equal(stripped.includes("/home/"), false, rel);
      }
      assert.ok(!first.files.some((file) => /(?:^|\/)(?:native-|model-gateway|protected-session|model-response)|\.test\./.test(file.path)));
      const dbDir = await mkdtemp(join(tmpdir(), "nmzp-audit-bundle-"));
      try {
        const ready = await new Promise((resolveReady, reject) => {
          const worker = new Worker(join(first.dir, "audit", "runtime-worker.cjs"), {
            execArgv: [],
            workerData: { path: join(dbDir, "nmzp.db"), create: true, readOnly: false, retention: { minFreeBytes: 0 } },
          });
          const timer = setTimeout(() => {
            worker.terminate();
            reject(new Error("audit worker timed out"));
          }, 15000);
          worker.on("message", (message) => {
            clearTimeout(timer);
            worker.terminate();
            resolveReady(message);
          });
          worker.on("error", (error) => {
            clearTimeout(timer);
            reject(error);
          });
        });
        assert.equal(ready.ready, true);
      } finally {
        await rm(dbDir, { recursive: true, force: true });
      }
      const help = await new Promise((resolveHelp, reject) => {
        const child = spawn(process.execPath, ["--experimental-strip-types", join(first.dir, "nmzp.mjs")], {
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        child.on("error", reject);
        child.on("close", (code) => resolveHelp({ code, stdout, stderr }));
      });
      assert.equal(help.code, 0, help.stderr);
      assert.match(help.stdout, /^nmzp 0\.2\.6\n/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
