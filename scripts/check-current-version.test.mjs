import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkCurrentMarkers } from "./check-current-version.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const script = join(root, "scripts", "check-current-version.mjs");

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { cwd: root, windowsHide: true });
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
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function writeTree(dir, markerVersion, packageVersion) {
  const { mkdir } = await import("node:fs/promises");
  await mkdir(join(dir, "docs"), { recursive: true });
  await mkdir(join(dir, ".github", "ISSUE_TEMPLATE"), { recursive: true });
  await writeFile(join(dir, "package.json"), `${JSON.stringify({ version: packageVersion })}\n`);
  await writeFile(
    join(dir, "SECURITY.md"),
    `Current release: **${markerVersion}**. License: MIT.\n\nIn NMZP 0.2.4, Antigravity kept an older note.\n\n| Version | Security fixes |\n| --- | --- |\n| ${markerVersion} | Current source tree |\n| 0.2.4 | Previous release line |\n`,
  );
  await writeFile(join(dir, "docs", "limits.md"), `当前版本 ${markerVersion}。其余句子保持原样。\n`);
  await writeFile(join(dir, "docs", "limits.en.md"), `Current version ${markerVersion}. The rest of the sentence stays.\n`);
  await writeFile(join(dir, ".github", "ISSUE_TEMPLATE", "bug_report.yml"), `placeholder: ${markerVersion}\n`);
  await writeFile(
    join(dir, "docs", "GITHUB_METADATA.md"),
    `The source tree package.json version is ${markerVersion}. v0.2.2 and v0.2.3 already exist.\n`,
  );
  await writeFile(
    join(dir, "docs", "install.md"),
    `首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 ${markerVersion}，Node.js 24 或更新。\n从同一个 [v${markerVersion} 发布页](https://github.com/s-silt/nmzp-monitor/releases/tag/v${markerVersion}) 下载。\n历史说明仍可写 0.2.4，这不是当前版本标记。\n`,
  );
  await writeFile(
    join(dir, "docs", "install.en.md"),
    `The quick start on the home page is enough to join one machine. This page is the full core and file layout. Version ${markerVersion}. Node.js 24 or newer.\nDownload from the same [v${markerVersion} release](https://github.com/s-silt/nmzp-monitor/releases/tag/v${markerVersion}).\nHistorical prose may still name 0.2.4.\n`,
  );
}

describe("current version markers", () => {
  test("a mismatched current marker fails and a historical 0.2.4 sentence does not", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-version-"));
    try {
      await writeTree(dir, "0.2.4", "0.2.5");
      const before = await readFile(join(dir, "SECURITY.md"), "utf8");
      const mismatch = checkCurrentMarkers(dir);
      assert.ok(mismatch.some((line) => line.includes("security-current-release") && line.includes("found 0.2.4")));
      const spawned = await run(["--root", dir]);
      assert.equal(spawned.code, 1);
      assert.match(spawned.stderr, /security-current-release/);
      assert.equal(await readFile(join(dir, "SECURITY.md"), "utf8"), before);

      await writeTree(dir, "0.2.5", "0.2.5");
      assert.deepEqual(checkCurrentMarkers(dir), []);
      const historical = await run(["--root", dir]);
      assert.equal(historical.code, 0, historical.stderr);
      const text = await readFile(join(dir, "SECURITY.md"), "utf8");
      assert.match(text, /In NMZP 0\.2\.4, Antigravity/);
      const install = await readFile(join(dir, "docs", "install.md"), "utf8");
      assert.match(install, /历史说明仍可写 0\.2\.4/);
      assert.match(install, /版本 0\.2\.5，/);

      await writeFile(
        join(dir, "docs", "install.md"),
        "首页的「快速开始」够完成一次加入。这里是 CT 与本机文件的完整步骤。版本 0.2.4，Node.js 24 或更新。\n从同一个 [v0.2.4 发布页](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.4) 下载。\n历史说明仍可写 0.2.4，这不是当前版本标记。\n",
      );
      await writeFile(
        join(dir, "docs", "install.en.md"),
        "The quick start on the home page is enough to join one machine. This page is the full core and file layout. Version 0.2.4. Node.js 24 or newer.\nDownload from the same [v0.2.4 release](https://github.com/s-silt/nmzp-monitor/releases/tag/v0.2.4).\nHistorical prose may still name 0.2.4.\n",
      );
      const staleInstall = checkCurrentMarkers(dir);
      assert.ok(staleInstall.some((line) => line.includes("install-zh-current") && line.includes("found 0.2.4")));
      assert.ok(staleInstall.some((line) => line.includes("install-en-release") && line.includes("found 0.2.4")));
      assert.equal(staleInstall.some((line) => line.startsWith("security-")), false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("source contract: this tree's current markers match package 0.2.5", async () => {
    const errors = checkCurrentMarkers(root);
    assert.deepEqual(errors, []);
    const ran = await run([]);
    assert.equal(ran.code, 0, ran.stderr);
    const security = readFileSync(join(root, "SECURITY.md"), "utf8");
    assert.match(security, /In NMZP 0\.2\.4, Antigravity/);
    assert.match(security, /Current release: \*\*0\.2\.5\*\*\./);
  });
});
