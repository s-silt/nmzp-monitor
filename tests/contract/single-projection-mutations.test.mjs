import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { test } from "node:test";
const root = fileURLToPath(new URL("../../", import.meta.url));
const hash = data => createHash("sha256").update(data).digest("hex");
const file = "core/protocol/rewrite-layout.ts";
const mutants = [
  { name: "drop real content alias rejection", pattern: "single projection rejects", before: 'if (toolInputHasAliasConflict(mapped.toolInput)) return bad("alias_conflict");', after: 'if (false) return bad("alias_conflict");' },
  { name: "drop canonical scalar binding", pattern: "single projection rejects", before: 'if (!scalarProjectionMatches(mapped.toolInput, keys, input[name], v1Str(top[topName])))', after: 'if (false)' },
  { name: "drop ordered content compatibility", pattern: "single projection rejects", before: '|| !contentProjectionMatches(mapped.toolInput, input.contents, v1Str(top.contents))', after: '|| false' },
  { name: "reintroduce legacy CT resolver", pattern: "exact single-projection call counts", before: 'if (toolInputHasAliasConflict(mapped.toolInput))', after: 'resolveEvalBody({ tool_name: event.tool.nativeName, tool_input: mapped.toolInput });\n    if (toolInputHasAliasConflict(mapped.toolInput))' },
  // IC-15 caps admitted sources at depth 64, far below structuredClone's own ceiling, so the old clone-depth mutant is now equivalent and dropped.
  { name: "reuse mutable source without ownership", pattern: "renderer owns immutable source", before: 'const event = structuredClone(source);\n    freezeTree(event);', after: 'const event = source;' },
];
function run(dir, pattern) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/single-projection.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.error, undefined); assert.equal(result.signal, null); return { status: result.status, output: result.stdout + result.stderr };
}
test("single-projection source mutants fail behavioral and exact-count assertions and restore", { timeout: 300_000 }, () => {
  const dir = mkdtempSync(join(root, ".tmp-single-projection-mutants-"));
  const originals = new Map(mutants.map(m => [m.file ?? file, readFileSync(join(root, m.file ?? file))]));
  try {
    for (const folder of ["core", "src", "contract"]) cpSync(join(root, folder), join(dir, folder), { recursive: true });
    cpSync(join(root, "package.json"), join(dir, "package.json")); mkdirSync(join(dir, "tests/contract"), { recursive: true });
    cpSync(join(root, "tests/contract/single-projection.test.mjs"), join(dir, "tests/contract/single-projection.test.mjs"));
    for (const mutant of mutants) {
      const target = mutant.file ?? file, original = originals.get(target);
      const text = original.toString("utf8"), anchors = [...new Set([mutant.before, mutant.before.replaceAll("\n", "\r\n")])].filter(a => text.includes(a));
      assert.equal(anchors.length, 1, mutant.name); assert.equal(text.split(anchors[0]).length - 1, 1, mutant.name);
      writeFileSync(join(dir, target), text.replace(anchors[0], mutant.after));
      const negative = run(dir, mutant.pattern);
      assert.notEqual(negative.status, 0, `${mutant.name} survived\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `${mutant.name}: not a behavioral assertion\n${negative.output}`);
      writeFileSync(join(dir, target), original); assert.equal(hash(readFileSync(join(dir, target))), hash(original));
      const positive = run(dir, mutant.pattern); assert.equal(positive.status, 0, positive.output);
      for (const expected of [/# pass 1\b/, /# fail 0\b/, /# skipped 0\b/]) assert.match(positive.output, expected);
    }
    for (const [target, original] of originals) assert.equal(hash(readFileSync(join(root, target))), hash(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
