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
  { name: "restore generic cwd precedence", file: "core/protocol/v2-adapter.ts", pattern: "known mixed-format regressions", before: '    const candidate = selectHookEnvelopeCwd(obj);', after: '    const candidate = typeof obj.cwd === "string" ? { value: obj.cwd, exact: obj.cwd, provenance: "/cwd" } : selectHookEnvelopeCwd(obj);' },
  { name: "trim legacy Antigravity array value", file: "core/hook-protocol.ts", pattern: "cwd actual parser table", before: 'return { value: first, exact: first, provenance: "/workspacePaths/0" };', after: 'return { value: first.trim(), exact: first, provenance: "/workspacePaths/0" };' },
  { name: "infer array from extras", file: "core/protocol/rewrite-layout.ts", pattern: "materializer does not infer array", before: 'const cwd = own(raw, "envelopeCwd") ? resolveRef(event, raw.envelopeCwd) : undefined;', after: 'const guessed = event.extraFields.find(item => item.path === "/workspace_roots/0" || item.path === "/workspacePaths/0");\n    const cwd = own(raw, "envelopeCwd") ? resolveRef(event, raw.envelopeCwd) : guessed ? { value: guessed.value, source: guessed.path } : undefined;' },
];

function run(dir, pattern) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/cwd-parity.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.error, undefined); assert.equal(result.signal, null);
  return { status: result.status, output: result.stdout + result.stderr };
}

test("cwd parity real source mutants fail and restore exact source bytes", { timeout: 300_000 }, () => {
  const dir = mkdtempSync(join(root, ".tmp-cwd-mutants-"));
  const originals = new Map(mutants.map(m => [m.file, readFileSync(join(root, m.file))]));
  try {
    for (const folder of ["core", "src", "contract"]) cpSync(join(root, folder), join(dir, folder), { recursive: true });
    cpSync(join(root, "package.json"), join(dir, "package.json"));
    mkdirSync(join(dir, "tests/contract"), { recursive: true });
    cpSync(join(root, "tests/contract/cwd-parity.test.mjs"), join(dir, "tests/contract/cwd-parity.test.mjs"));
    for (const mutant of mutants) {
      const file = join(dir, mutant.file), original = originals.get(mutant.file), text = original.toString("utf8");
      const anchor = [...new Set([mutant.before, mutant.before.replaceAll("\n", "\r\n")])].filter(a => text.includes(a));
      assert.equal(anchor.length, 1, mutant.name);
      assert.equal(text.split(anchor[0]).length - 1, 1, mutant.name);
      writeFileSync(file, text.replace(anchor[0], mutant.after));
      const negative = run(dir, mutant.pattern);
      assert.notEqual(negative.status, 0, `${mutant.name} survived\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `${mutant.name}: not the behavioral assertion\n${negative.output}`);
      writeFileSync(file, original); assert.equal(hash(readFileSync(file)), hash(original));
      const positive = run(dir, mutant.pattern); assert.equal(positive.status, 0, positive.output);
      for (const expected of [/# pass 1\b/, /# fail 0\b/, /# skipped 0\b/]) assert.match(positive.output, expected);
    }
    for (const [file, original] of originals) assert.equal(hash(readFileSync(join(root, file))), hash(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
