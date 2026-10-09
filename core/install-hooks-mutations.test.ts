import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";

const coreDir = dirname(fileURLToPath(import.meta.url));
const copied = [
  "install-hooks.ts",
  "install-hooks.test.ts",
  "hook-emergency-deny.mjs",
  "hook-protocol.ts",
  "egress-schema.ts",
  "auth.ts",
  "hook-alias-keys.ts",
];
const mutations = [
  {
    name: "drop node existence check",
    needle: "if (-not (Test-Path -LiteralPath ${node})) { Exit-NmzpDeny }",
    replacement: "if ($false) { Exit-NmzpDeny }",
    expected: "fail-closed missing node",
  },
  {
    name: "drop entry existence check",
    needle: "if (-not (Test-Path -LiteralPath ${entry})) { Exit-NmzpDeny }",
    replacement: "if ($false) { Exit-NmzpDeny }",
    expected: "fail-closed missing entry",
  },
  {
    name: "pass abnormal exit codes",
    needle: "if ($null -eq $nmzpCode -or ($nmzpCode -ne 0 -and $nmzpCode -ne 2)) { Exit-NmzpDeny }",
    replacement: "if ($false) { Exit-NmzpDeny }",
    expected: "fail-closed empty exit 1",
  },
];

function hash(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function run(cwd: string): { status: number | null; output: string } {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--test",
      "--test-concurrency=1",
      "--test-reporter=tap",
      "--test-name-pattern=fail-closed",
      "core/install-hooks.test.ts",
    ],
    { cwd, env, encoding: "utf8", timeout: 180_000, maxBuffer: 16 * 1024 * 1024 },
  );
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  assert.equal(result.error, undefined, `mutation suite must terminate\n${output}`);
  assert.match(output, /# tests [1-9]/, `child ran no tests\n${output}`);
  assert.doesNotMatch(output, /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION/);
  return { status: result.status, output };
}

it("windows hook fail-closed checks are killed by removing each one", {
  timeout: 240_000,
  skip: process.platform === "win32" ? false : "real powershell.exe hook command requires Windows",
}, async () => {
  const original = await readFile(join(coreDir, "install-hooks.ts"));
  const temp = await mkdtemp(join(tmpdir(), "nmzp-win-hook-mut-"));
  const target = join(temp, "core", "install-hooks.ts");
  try {
    await mkdir(join(temp, "core"), { recursive: true });
    for (const name of copied) await cp(join(coreDir, name), join(temp, "core", name));
    for (const mutation of mutations) {
      assert.equal(original.toString("utf8").split(mutation.needle).length, 2, `${mutation.name}: unique anchor`);
    }
    const baseline = run(temp);
    assert.equal(baseline.status, 0, baseline.output);
    assert.match(baseline.output, /# fail 0\b/);
    for (const mutation of mutations) {
      try {
        await writeFile(target, original.toString("utf8").replace(mutation.needle, mutation.replacement));
        const result = run(temp);
        assert.notEqual(result.status, 0, `${mutation.name}: mutant survived\n${result.output}`);
        assert.ok(
          result.output.split("\n").some((line) => /^\s*not ok \d+ - /.test(line) && line.includes(mutation.expected)),
          `${mutation.name}: intended assertion not reached\n${result.output}`,
        );
        assert.match(result.output, /ERR_ASSERTION/);
      } finally {
        await writeFile(target, original);
        assert.equal(hash(await readFile(target)), hash(original));
      }
    }
    assert.equal(hash(await readFile(join(coreDir, "install-hooks.ts"))), hash(original));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
