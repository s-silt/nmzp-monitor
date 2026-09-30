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
  { name: "ignore final serialized binding", file: "core/protocol/rendered-rewrite.ts", pattern: "source/result/finding/revision tampering", before: 'raw.resultViewHash !== hash(JSON.stringify(updatedInput))', after: 'false' },
  { name: "ignore effective copy derivation", file: "core/protocol/rendered-rewrite.ts", pattern: "source/result/finding/revision tampering", before: 'edit.derivation !== leaf.derivation\n        || ', after: '' },
  { name: "skip genuine residue refusal", file: "core/rewrite.ts", pattern: "residue short-circuit", before: 'if (residue) return { ok: false, reason: "sensitive_residue" };', after: 'if (false) return { ok: false, reason: "sensitive_residue" };' },
];
function run(dir, pattern) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/rendered-rewrite.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60_000 });
  assert.equal(r.error, undefined); assert.equal(r.signal, null); return { status: r.status, output: r.stdout + r.stderr };
}
test("rendered evidence source mutants fail binding/residue assertions and restore", { timeout: 300_000 }, () => {
  const dir = mkdtempSync(join(root, ".tmp-rendered-mutants-"));
  const originals = new Map(mutants.map(m => [m.file, readFileSync(join(root, m.file))]));
  try {
    for (const folder of ["core", "src", "contract"]) cpSync(join(root, folder), join(dir, folder), { recursive: true });
    cpSync(join(root, "package.json"), join(dir, "package.json")); mkdirSync(join(dir, "tests/contract"), { recursive: true });
    for (const file of ["rendered-rewrite.test.mjs", "protocol-checks.mjs"]) cpSync(join(root, "tests/contract", file), join(dir, "tests/contract", file));
    for (const mutant of mutants) {
      const path = join(dir, mutant.file), original = originals.get(mutant.file), text = original.toString("utf8");
      const anchor = [...new Set([mutant.before, mutant.before.replaceAll("\n", "\r\n")])].filter(a => text.includes(a));
      assert.equal(anchor.length, 1); assert.equal(text.split(anchor[0]).length - 1, 1);
      writeFileSync(path, text.replace(anchor[0], mutant.after)); const negative = run(dir, mutant.pattern);
      assert.notEqual(negative.status, 0, `${mutant.name} survived\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `${mutant.name}: not an assertion\n${negative.output}`);
      writeFileSync(path, original); assert.equal(hash(readFileSync(path)), hash(original));
      const positive = run(dir, mutant.pattern); assert.equal(positive.status, 0, positive.output);
      for (const expected of [/# pass 1\b/, /# fail 0\b/, /# skipped 0\b/]) assert.match(positive.output, expected);
    }
    for (const [file, original] of originals) assert.equal(hash(readFileSync(join(root, file))), hash(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
