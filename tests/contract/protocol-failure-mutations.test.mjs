import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const targetFile = "core/protocol/v2-adapter.ts";
const suites = [
  "tests/contract/v1-v2-equivalence.test.mjs",
  "tests/contract/render-golden.test.mjs",
  "tests/contract/protocol-failure-boundaries.test.mjs",
];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const mutations = [
  {
    name: "incoming truncation",
    needle: "  if (flags.length) {",
    replacement: "  if (false && flags.length) {",
    expected: "incoming truncation: real hook",
  },
  {
    name: "strict depth off by one",
    needle: "export const MAX_CONTAINER_DEPTH = 64;",
    replacement: "export const MAX_CONTAINER_DEPTH = 65;",
    expected: "strict depth 64/65:",
  },
  {
    name: "Antigravity conflict classification",
    needle: "    return conflict || toolInputHasAliasConflict(toolInput);",
    replacement: "    return false; // mutation: lose Antigravity conflict",
    expected: "Antigravity abe4413:",
  },
  {
    name: "edits alias conflict classification",
    needle: "  if (toolInputHasAliasConflict(toolInput)) return true;",
    replacement:
      "  if (!Array.isArray(toolInput.edits) && toolInputHasAliasConflict(toolInput)) return true;",
    expected: "edits contents/content:",
  },
];

function run(cwd) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(
    process.execPath,
    ["--test", "--test-reporter=tap", "--experimental-strip-types", ...suites],
    {
      cwd,
      env,
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  assert.equal(result.error, undefined, "mutation suite must terminate normally");
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  // IC-15 removed the v1-v2 "container depth 65" known difference, so the selected suites hold 40 tests.
  assert.match(
    output,
    /# tests 40\b/,
    "all 40 selected real assertions must execute, never accept an empty child run\n" + output,
  );
  if (result.status === 0)
    assert.match(output, /# fail 0\b/, "successful child run must have zero failures\n" + output);
  assert.match(output, /# skipped 0\b/, "no skipped child assertions\n" + output);
  assert.match(output, /# cancelled 0\b/, "no cancelled child assertions\n" + output);
  return { status: result.status, output };
}

test(
  "four failure families kill the actual equivalence and rendering assertions, with hash restoration",
  { timeout: 240000 },
  async (t) => {
    const temp = await mkdtemp(join(tmpdir(), "nmzp-real-failure-mutants-"));
    const original = await readFile(join(root, targetFile), "utf8");
    try {
      for (const dir of ["core", "scripts", "tests", "policy-spec", "dist"])
        await cp(join(root, dir), join(temp, dir), { recursive: true });
      await mkdir(join(temp, "src", "lib"), { recursive: true });
      await cp(join(root, "src", "lib", "monitor"), join(temp, "src", "lib", "monitor"), {
        recursive: true,
      });
      await cp(join(root, "contract"), join(temp, "contract"), { recursive: true });
      await cp(join(root, "package.json"), join(temp, "package.json"));
      // Existing dependency tree is used read-only; no package manager or install.
      await symlink(
        join(root, "node_modules"),
        join(temp, "node_modules"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const target = join(temp, targetFile);
      const baseline = run(temp);
      assert.equal(baseline.status, 0, baseline.output);
      assert.match(baseline.output, /# pass 40\b/, "all baseline assertions must pass");
      for (const mutation of mutations) {
        assert.equal(original.split(mutation.needle).length, 2, `${mutation.name}: unique anchor`);
        try {
          await writeFile(target, original.replace(mutation.needle, mutation.replacement));
          const result = run(temp);
          assert.notEqual(result.status, 0, `${mutation.name}: mutant survived`);
          assert.ok(
            result.output
              .split("\n")
              .some((line) => /^not ok \d+ - /.test(line) && line.includes(mutation.expected)),
            `${mutation.name}: intended behavioral assertion not reached\n${result.output}`,
          );
          assert.match(result.output, /ERR_ASSERTION/);
          assert.doesNotMatch(
            result.output,
            /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION/,
          );
        } finally {
          await writeFile(target, original);
          assert.equal(
            hash(await readFile(target)),
            hash(original),
            `${mutation.name}: restored fixture hash`,
          );
        }
        const restored = run(temp);
        assert.equal(
          restored.status,
          0,
          `${mutation.name}: restored real suites\n${restored.output}`,
        );
        assert.match(
          restored.output,
          /# pass 40\b/,
          `${mutation.name}: all restored assertions must pass`,
        );
        t.diagnostic(
          `${mutation.name}: intended assertion failed; hash restored; full selected suites green`,
        );
      }
      assert.equal(
        hash(await readFile(join(root, targetFile))),
        hash(original),
        "checkout source untouched by mutation harness",
      );
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  },
);
