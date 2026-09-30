import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const suite = "tests/contract/alias-compatibility.test.mjs";
const aliases = "core/hook-alias-keys.ts";
const adapter = "core/protocol/v2-adapter.ts";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const mutations = [
  { name: "B3 drop nested leaf scanning", file: aliases, needle: "    walkScanLeaves(v, push, seen);", replacement: "    void v; // mutation: omit nested leaves", failedTest: "B3 nested dangerous leaf" },
  { name: "N2 consume workdir as an operational key", file: aliases, needle: '  "directory",', replacement: '  "directory", "workdir",', failedTest: "N2: workdir stays" },
  { name: "B6 compare raw command aliases", file: aliases, needle: "const command = pickDefinedSame(COMMAND_KEYS.map((k) => aliasStr(obj[k])));", replacement: 'const command = pickDefinedSame(COMMAND_KEYS.map((k) => typeof obj[k] === "string" ? obj[k] as string : undefined));', failedTest: "B6 IC-02" },
  { name: "B7 suppress path warnings", file: adapter, needle: 'if (name === "filePath" || name === "cwd") {', replacement: "if (false) {", failedTest: "B7 IC-12" },
  { name: "B7 leak raw diagnostic values into audit", file: adapter, needle: "[{ ...observation.warning }]", replacement: "[{ ...observation.warning, exact: observation.exact }]", failedTest: "B7 audit privacy" },
];

function run(cwd) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--experimental-strip-types", suite], {
    cwd, env, encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("B3/N2/B6/B7 real-suite mutants fail; isolated sources restore to identical hashes", { timeout: 180000 }, async (t) => {
  const tmp = await mkdtemp(join(tmpdir(), "nmzp-alias-mutants-"));
  const originals = new Map();
  try {
    await cp(join(root, "core"), join(tmp, "core"), { recursive: true });
    await mkdir(join(tmp, "src", "lib"), { recursive: true });
    await cp(join(root, "src", "lib", "monitor"), join(tmp, "src", "lib", "monitor"), { recursive: true });
    await cp(join(root, "package.json"), join(tmp, "package.json"));
    await mkdir(join(tmp, "node_modules"), { recursive: true });
    await cp(join(root, "node_modules", "acorn"), join(tmp, "node_modules", "acorn"), { recursive: true });
    await mkdir(dirname(join(tmp, suite)), { recursive: true });
    await cp(join(root, suite), join(tmp, suite));
    for (const file of [aliases, adapter]) originals.set(file, await readFile(join(root, file), "utf8"));
    const baseline = run(tmp);
    assert.equal(baseline.status, 0, baseline.output);
    assert.match(baseline.output, /# pass 7\b/);
    for (const mutation of mutations) {
      const source = originals.get(mutation.file);
      assert.equal(source.split(mutation.needle).length, 2, `${mutation.name}: unique mutation anchor`);
      const target = join(tmp, mutation.file);
      try {
        await writeFile(target, source.replace(mutation.needle, mutation.replacement));
        const red = run(tmp);
        assert.notEqual(red.status, 0, `${mutation.name}: unexpectedly green`);
        assert.ok(red.output.split("\n").some((line) => /^not ok \d+ - /.test(line) && line.includes(mutation.failedTest)), `${mutation.name}: expected case did not fail`);
        assert.match(red.output, /ERR_ASSERTION/, `${mutation.name}: must fail an assertion, not loading`);
        assert.match(red.output, /# fail [1-9]/);
        assert.doesNotMatch(red.output, /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION/);
      } finally {
        await writeFile(target, source);
        assert.equal(hash(await readFile(target)), hash(source), `${mutation.name}: restored hash`);
      }
      const restored = run(tmp);
      assert.equal(restored.status, 0, `${mutation.name}: restored suite\n${restored.output}`);
      t.diagnostic(`${mutation.name}: assertion red, restored hash and 7/7 green`);
    }
    for (const [file, source] of originals) {
      assert.equal(hash(await readFile(join(root, file))), hash(source), `${file}: checkout unchanged by mutants`);
    }
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
