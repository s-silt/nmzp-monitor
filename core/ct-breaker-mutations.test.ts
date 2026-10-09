import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";

const coreDir = dirname(fileURLToPath(import.meta.url));
const copied = ["ct-breaker.ts", "ct-breaker-invariants.test.ts", "constants.ts", "atomic-file.ts"];
const mutations = [
  {
    name: "count http 5xx as connect failure",
    needle: `  // WP-13b: 4xx and 5xx still prove the TCP/TLS connection reached CT.
  return "reset";`,
    replacement: `  // WP-13b: 4xx and 5xx still prove the TCP/TLS connection reached CT.
  if (status >= 500) return "connect-failure";
  return "reset";`,
    expected: "breaker invariant: http 5xx resets",
  },
  {
    name: "open on the first connect failure",
    needle: "return failures >= CT_BREAKER_THRESHOLD;",
    replacement: "return failures >= 1;",
    expected: "breaker invariant: third connect failure opens",
  },
  {
    name: "treat corrupt json as an open breaker",
    needle: "if (error instanceof SyntaxError) return CLOSED_BREAKER;",
    replacement:
      "if (error instanceof SyntaxError) return { consecutiveFailures: CT_BREAKER_THRESHOLD, openUntil: now + CT_BREAKER_OPEN_MS };",
    expected: "breaker invariant: corrupt file is closed",
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
      "core/ct-breaker-invariants.test.ts",
    ],
    { cwd, env, encoding: "utf8", timeout: 60_000, maxBuffer: 8 * 1024 * 1024 },
  );
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  assert.equal(result.error, undefined, `mutation suite must terminate\n${output}`);
  assert.match(output, /# tests [1-9]/, `child ran no tests\n${output}`);
  assert.doesNotMatch(output, /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION/);
  return { status: result.status, output };
}

it(
  "ct breaker invariants are killed by the three specified mutations",
  { timeout: 120_000 },
  async () => {
    const original = await readFile(join(coreDir, "ct-breaker.ts"));
    const temp = await mkdtemp(join(tmpdir(), "nmzp-ct-mut-"));
    const target = join(temp, "core", "ct-breaker.ts");
    try {
      await mkdir(join(temp, "core"), { recursive: true });
      for (const name of copied) await cp(join(coreDir, name), join(temp, "core", name));
      for (const mutation of mutations) {
        assert.equal(
          original.toString("utf8").split(mutation.needle).length,
          2,
          `${mutation.name}: unique anchor`,
        );
      }
      const baseline = run(temp);
      assert.equal(baseline.status, 0, baseline.output);
      assert.match(baseline.output, /# fail 0\b/);
      for (const mutation of mutations) {
        try {
          await writeFile(
            target,
            original.toString("utf8").replace(mutation.needle, mutation.replacement),
          );
          const result = run(temp);
          assert.notEqual(result.status, 0, `${mutation.name}: mutant survived\n${result.output}`);
          assert.ok(
            result.output
              .split("\n")
              .some((line) => /^\s*not ok \d+ - /.test(line) && line.includes(mutation.expected)),
            `${mutation.name}: intended assertion not reached\n${result.output}`,
          );
          assert.match(result.output, /ERR_ASSERTION/);
        } finally {
          await writeFile(target, original);
          assert.equal(hash(await readFile(target)), hash(original));
        }
      }
      assert.equal(hash(await readFile(join(coreDir, "ct-breaker.ts"))), hash(original));
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  },
);
