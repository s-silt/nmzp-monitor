import assert from "node:assert/strict";
import { it } from "node:test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { packRelease } from "../../scripts/release-archive.mjs";

it("the release tree carries the same proposal parser used by the HTTPS route", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "nmzp-proposal-pack-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = fileURLToPath(new URL("../../", import.meta.url));
  await cp(join(source, "core"), join(root, "core"), { recursive: true });
  await mkdir(join(root, "src", "lib"), { recursive: true });
  await cp(join(source, "src", "lib", "monitor"), join(root, "src", "lib", "monitor"), { recursive: true });
  await mkdir(join(root, "dist"), { recursive: true });
  await writeFile(join(root, "dist", "index.html"), "<!doctype html>\n");
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const packed = await packRelease(root);
  const loaded = createRequire(import.meta.url)(join(packed.dir, "nmzp-main.cjs"));
  const parser = await loaded.loadPolicyProposal(packed.dir);
  assert.equal(parser.PROPOSAL_SCHEMA, "nmzp-policy-proposal/1");
  assert.equal(typeof parser.parsePolicyProposal, "function");
  assert.deepEqual(loaded.formatHookResponse("antigravity", { decision: "allow", reason: "synthetic" }), {
    stdout: "", exitCode: 0,
  }, "packaged antigravity no-decision output is exact empty stdout");
});
