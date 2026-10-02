import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("mutation anchors", () => {
  it("source contract: M20-14b still targets the restrictive mode in writeTlsPart", () => {
    const tls = readFileSync(join(root, "core", "tls.ts"), "utf8");
    const script = readFileSync(join(root, "scripts", "check-mutations.mjs"), "utf8");
    const restrictive = "await atomicWrite(path, body, 0o600);";
    assert.equal(tls.includes(restrictive), true);
    assert.equal(script.includes('id: "M20-14b"'), true);
    assert.equal(script.includes('const tlsBlock = (mode) => `  await atomicWrite(path, body, ${mode});`;'), true);
    assert.equal(script.includes('oldText: tlsBlock("0o600")'), true);
    assert.equal(script.includes('newText: tlsBlock("0o644")'), true);
    assert.equal(script.includes('target: "writes tls key, cert, and pin without group or other permissions"'), true);
    assert.equal(tls.includes("await atomicWrite(path, body, 0o644);"), false);
  });
});

function runSelector(args) {
  return spawnSync(process.execPath, [join(root, "scripts", "check-mutations.mjs"), ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 5_000,
  });
}

describe("check-mutations selector", () => {
  it("lists the H-03 probes without running tests", () => {
    const result = runSelector(["--list"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /H-03-01\r?\nH-03-02\r?\nH-03-03/);
    assert.doesNotMatch(result.stdout, /baselines/);
  });

  it("rejects empty, duplicate, and unknown selections", () => {
    for (const args of [
      ["--only="],
      ["--only=H-03-01,H-03-01"],
      ["--only=H-03-unknown"],
      ["--only=H-03-01", "--only=H-03-02"],
      ["--list", "--only=H-03-01"],
      ["--unknown"],
    ]) {
      const result = runSelector(args);
      assert.notEqual(result.status, 0, args.join(" "));
      assert.match(result.stderr, /--only|--list|expected only|unknown mutant ID/);
    }
  });
});
