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
  { name: "lose boolean residue", file: "core/protocol/rewrite-layout.ts", pattern: "real custom-rule residue", before: 'typeof node.value !== "boolean") return bad("shape");\n        value = node.value;', after: 'typeof node.value !== "boolean") return bad("shape");\n        value = false;' },
  { name: "unbound source", file: "core/protocol/rewrite-layout.ts", pattern: "layout validator rejects", before: 'fragment.source !== node.source || node.source !== path || ', after: '' },
  { name: "drop nonwinning alias", file: "core/protocol/v2-adapter.ts", pattern: "nonwinning scalar aliases", before: '    fields[name] = { value: winner.exact, provenance };\n    mapped.add(provenance);', after: '    fields[name] = { value: winner.exact, provenance };\n    mapped.add(provenance);\n    for (const key of keys) if (typeof exactBag[key] === "string") mapped.add(pointerFor(pathPrefix, key, hostArgMap));' },
  { name: "ignore source presence", file: "core/protocol/rewrite-layout.ts", pattern: "layout sourcePresent preserves", before: 'if ((view !== undefined) !== raw.sourcePresent)', after: 'if (false)' },
];

function run(dir, pattern) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/rewrite-layout.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return { status: result.status, output: result.stdout + result.stderr };
}

test("real layout source mutants fail source/privacy boundaries and restore bytes", { timeout: 300_000 }, () => {
  const dir = mkdtempSync(join(root, ".tmp-layout-mutants-"));
  const originals = new Map(mutants.map(m => [m.file, readFileSync(join(root, m.file))]));
  try {
    for (const folder of ["core", "src", "contract"]) cpSync(join(root, folder), join(dir, folder), { recursive: true });
    cpSync(join(root, "package.json"), join(dir, "package.json"));
    mkdirSync(join(dir, "tests/contract"), { recursive: true });
    for (const file of ["rewrite-layout.test.mjs", "protocol-checks.mjs"]) cpSync(join(root, "tests/contract", file), join(dir, "tests/contract", file));
    for (const mutant of mutants) {
      const file = join(dir, mutant.file), original = originals.get(mutant.file), text = original.toString("utf8");
      const options = [mutant.before, mutant.before.replaceAll("\n", "\r\n")];
      const anchor = [...new Set(options)].filter(a => text.includes(a));
      assert.equal(anchor.length, 1, mutant.name);
      assert.equal(text.split(anchor[0]).length - 1, 1, mutant.name);
      writeFileSync(file, text.replace(anchor[0], mutant.after));
      const negative = run(dir, mutant.pattern);
      assert.notEqual(negative.status, 0, `${mutant.name} survived\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `${mutant.name}: not the behavioral assertion\n${negative.output}`);
      writeFileSync(file, original);
      assert.equal(hash(readFileSync(file)), hash(original));
      const positive = run(dir, mutant.pattern);
      assert.equal(positive.status, 0, positive.output);
      for (const expected of [/# pass 1\b/, /# fail 0\b/, /# skipped 0\b/]) assert.match(positive.output, expected);
    }
    for (const [file, original] of originals) assert.equal(hash(readFileSync(join(root, file))), hash(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
