import assert from "node:assert/strict";
import { test } from "node:test";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../../", import.meta.url));
const digest = value => createHash("sha256").update(value).digest("hex");
const mutants = [
  { file: "core/protocol/evaluate-ingress.ts", before: 'if (!sameDeviceId(event.device.id, deviceId)) return { ok: false, code: "unauthorized" };', after: 'if (!sameDeviceId(event.device.id, deviceId)) return { ok: false, code: "bad_schema" };', pattern: "V2 HTTPS authentication", expected: /400 !== 401/ },
  { file: "core/protocol/evaluate-response.ts", before: 'response.eventId !== event.eventId || response.requestHash !== canonicalRequestHash(event)', after: 'response.eventId !== event.eventId', pattern: "real compact HTTPS rewrite", expected: /true !== false/ },
  { file: "core/protocol/evaluate-ingress.ts", before: 'proc: v1Str(event.context.proc)', after: 'proc: undefined', pattern: "genuine PROBE ingress", expected: /AssertionError|ERR_ASSERTION/ },
  { file: "core/evaluation-application.ts", before: 'if (typeof json !== "string" || Buffer.byteLength(json) > BODY_LIMIT) fail("evaluation_result_too_large");', after: '/* mutant removes actual precommit response ceiling */', pattern: "actual complete HTTP response budget", expected: /200 !== 413/ },
];
function run(dir, pattern) {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, "tests/contract/evaluate-routes.test.mjs"], { cwd: dir, env, encoding: "utf8", timeout: 60000, windowsHide: true });
  assert.equal(r.error, undefined); assert.equal(r.signal, null); return { status: r.status, output: r.stdout + r.stderr };
}
test("actual evaluate source mutants fail request binding, PROBE metadata, HTTP status and response budget", { timeout: 300000 }, () => {
  const dir = mkdtempSync(join(root, ".tmp-evaluate-mutants-"));
  const originals = new Map(mutants.map(m => [m.file, readFileSync(join(root, m.file))]));
  try {
    for (const name of ["core", "src", "contract", "package.json"]) cpSync(join(root, name), join(dir, name), { recursive: true });
    mkdirSync(join(dir, "tests/contract"), { recursive: true });
    for (const name of ["evaluate-routes.test.mjs", "protocol-checks.mjs"]) cpSync(join(root, "tests/contract", name), join(dir, "tests/contract", name));
    for (const m of mutants) {
      const file = join(dir, m.file), original = originals.get(m.file), text = original.toString("utf8");
      assert.equal(text.split(m.before).length, 2, m.pattern); writeFileSync(file, text.replace(m.before, m.after));
      const negative = run(dir, m.pattern); assert.notEqual(negative.status, 0, `survived: ${m.pattern}\n${negative.output}`);
      assert.match(negative.output, /ERR_ASSERTION/, `not an assertion: ${m.pattern}\n${negative.output}`);
      assert.match(negative.output, m.expected, `wrong failure: ${m.pattern}\n${negative.output}`);
      writeFileSync(file, original); assert.equal(digest(readFileSync(file)), digest(original));
      const positive = run(dir, m.pattern); assert.equal(positive.status, 0, positive.output);
      assert.match(positive.output, /# pass 1\b/); assert.match(positive.output, /# fail 0\b/); assert.match(positive.output, /# skipped 0\b/);
    }
    for (const [file, original] of originals) assert.equal(digest(readFileSync(join(root, file))), digest(original));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
