import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { test } from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const hash = data => createHash("sha256").update(data).digest("hex");
const mutants = [
  { name: "auth bypass", file: "core/serve.ts", pattern: "four v2 routes authenticate", before: "    const token = parseBearer(req.headers.authorization);", after: '    if (requestId) return store.getDevice("a");\n    const token = parseBearer(req.headers.authorization);', expected: /200 !== 401|404 !== 401|400 !== 401/ },
  { name: "trim ETag segments", file: "core/protocol/v2-error.ts", pattern: "policy HTTPS response", before: 'header.split(",")', after: 'header.split(",").map(part => part.trim())', expected: /304 !== 200/ },
  { name: "normalize proof body", file: "core/serve.ts", pattern: "heartbeat alias verifies", before: 'challenges.consume(d.id,d.probeBinding,body.text,req.headers)', after: 'challenges.consume(d.id,d.probeBinding,body.text.replaceAll(" ",""),req.headers)', expected: /401 !== 200/ },
  { name: "ignore immutable evaluation", file: "core/serve.ts", pattern: "receipt real HTTPS differential", before: 'if (ev && receiptEvaluationChanges(receipt, ev.evaluation))', after: 'if (false && ev && receiptEvaluationChanges(receipt, ev.evaluation))', expected: /200 !== 409/ },
];

function run(dir, pattern) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/device-routes.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  return { status: result.status, output: result.stdout + result.stderr };
}

test("device-route actual source mutants fail security boundaries and restore exact bytes", { timeout: 300_000 }, () => {
  // Nested under this checkout so package resolution can reuse installed dependencies on Windows
  // without symlink privileges. Only this test's private directory is ever edited/removed.
  const dir = mkdtempSync(join(root, ".tmp-device-route-mutants-"));
  const originals = new Map(mutants.map(m => [m.file, readFileSync(join(root, m.file))]));
  try {
    for (const folder of ["core", "src", "contract"]) cpSync(join(root, folder), join(dir, folder), { recursive: true });
    cpSync(join(root, "package.json"), join(dir, "package.json"));
    mkdirSync(join(dir, "tests/contract"), { recursive: true });
    for (const file of ["device-routes.test.mjs", "protocol-checks.mjs"]) cpSync(join(root, "tests/contract", file), join(dir, "tests/contract", file));
    for (const mutant of mutants) {
      const file = join(dir, mutant.file), original = originals.get(mutant.file);
      const text = original.toString("utf8");
      assert.equal(text.split(mutant.before).length - 1, 1, mutant.name);
      writeFileSync(file, text.replace(mutant.before, mutant.after));
      const negative = run(dir, mutant.pattern);
      assert.notEqual(negative.status, 0, `${mutant.name}: survived\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `${mutant.name}: not an assertion failure`);
      assert.match(negative.output, mutant.expected, `${mutant.name}: wrong failure\n${negative.output}`);
      writeFileSync(file, original);
      assert.equal(hash(readFileSync(file)), hash(original));
      const positive = run(dir, mutant.pattern);
      assert.equal(positive.status, 0, positive.output);
      assert.match(positive.output, /# pass 1\b/);
      assert.match(positive.output, /# fail 0\b/);
      assert.match(positive.output, /# skipped 0\b/);
    }
    for (const [file, original] of originals) assert.equal(hash(readFileSync(join(root, file))), hash(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
