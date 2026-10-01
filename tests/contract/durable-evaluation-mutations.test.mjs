import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, cpSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
// Isolated source copy: never mutate the checkout being reviewed or race other test workers.
test("private evaluation negative controls detect identity, visibility, codec and session-budget regressions", () => {
  const dir = mkdtempSync(join(root, ".durable-mutation-"));
  try {
    for (const name of ["core", "src", "package.json"]) cpSync(join(root, name), join(dir, name), { recursive: true });
    mkdirSync(join(dir, "tests/helpers"), { recursive: true });
    cpSync(join(root, "tests/helpers/cleanup.mjs"), join(dir, "tests/helpers/cleanup.mjs"));
    const mutations = [
      ["core/audit/store.ts", 'const where = ["internal_only=0","seq<=?","seq<?"]', 'const where = ["seq<=?","seq<?"]', "core/audit/evaluation-record.test.mjs", "hidden records survive"],
      ["core/audit/store.ts", 'raw.requestHash !== row.canonical_request_hash || ', '', "core/audit/evaluation-record.test.mjs", "codec and indexed SQL"],
      ["core/audit/evaluation-record.ts", 'Object.keys(v).every(k => required.includes(k) || optional.includes(k))', 'true', "core/audit/evaluation-record.test.mjs", "closed private codec"],
      ["core/evaluation-application.ts", 'if (typeof json !== "string" || Buffer.byteLength(json) > BODY_LIMIT) fail("evaluation_result_too_large");', '/* MUTATION: omitted precommit budget */', "core/evaluation-application.test.mjs", "response budget rejects"],
    ];
    for (const [file, anchor, replacement, target, pattern] of mutations) {
      const path = join(dir, file), original = readFileSync(path), text = original.toString("utf8");
      assert.equal(text.split(anchor).length, 2, `unique anchor: ${file}`);
      writeFileSync(path, text.replace(anchor, replacement));
      const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
      try {
        const result = spawnSync(process.execPath, ["--experimental-strip-types", "--test", `--test-name-pattern=${pattern}`, join(dir, target)], { cwd: dirname(path), env, encoding: "utf8", timeout: 30000, windowsHide: true });
        assert.notEqual(result.status, 0, `mutation survived: ${pattern}`);
        assert.match(result.stdout + result.stderr, /AssertionError|ERR_ASSERTION/, `must be assertion failure: ${pattern}\n${result.stdout}${result.stderr}`);
      } finally { writeFileSync(path, original); }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
