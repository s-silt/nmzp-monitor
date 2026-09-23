import assert from "node:assert/strict";
import { it } from "node:test";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { packRelease } from "../../core/pack.ts";
import { loadPolicyProposal } from "../../core/paths.ts";

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
  const parser = await loadPolicyProposal(packed.dir);
  assert.equal(parser.PROPOSAL_SCHEMA, "nmzp-policy-proposal/1");
  assert.equal(typeof parser.parsePolicyProposal, "function");
  const protocol = await import(pathToFileURL(join(packed.dir, "hook-protocol.ts")).href);
  assert.deepEqual(protocol.formatHookResponse("antigravity", { decision: "allow", reason: "synthetic" }), {
    stdout: '{"decision":"allow"}\n', exitCode: 0,
  }, "the packaged runtime includes the real Antigravity allow protocol repair");
});
