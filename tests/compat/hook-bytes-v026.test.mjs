import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { writePolicyCache } from "../../core/policy-cache.ts";
import { deny } from "../../core/hook-renderer.ts";
import { packRelease } from "../../scripts/release-archive.mjs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/hook-bytes-v026.json", import.meta.url), "utf8"));
const golden = JSON.parse(readFileSync(new URL("./fixtures/hook-bytes-golden.json", import.meta.url), "utf8"));

// IC-13: v0.2.6 allowed (or denied for another reason), HEAD denies with bad_hook_json.
const IC13 = [
  "antigravity-alias-conflict",
  "grok-alias-content-contents-secret",
  "grok-alias-contents-content",
  "grok-alias-edits-content-contents",
  "grok-alias-edits-content-contents-secret",
  "claude-alias-content-contents-secret",
  "claude-alias-contents-content",
  "claude-alias-edits-content-contents",
  "claude-alias-edits-content-contents-secret",
  "codex-alias-content-contents-secret",
  "codex-alias-contents-content",
  "codex-alias-edits-content-contents",
  "codex-alias-edits-content-contents-secret",
  "zcode-alias-content-contents-secret",
  "zcode-alias-contents-content",
  "zcode-alias-edits-content-contents",
  "zcode-alias-edits-content-contents-secret",
  "antigravity-alias-targetfile-absolutepath",
  "antigravity-alias-targetfile-absolutepath-env",
  "antigravity-alias-codecontent-content",
  "antigravity-alias-contents-content",
  "antigravity-alias-edits-content-contents",
  "antigravity-alias-write-codecontent-content",
  "kimi-alias-content-contents-secret",
  "kimi-alias-contents-content",
  "kimi-alias-edits-content-contents",
  "kimi-alias-edits-content-contents-secret",
  "trae-alias-content-contents-secret",
  "trae-alias-contents-content",
  "trae-alias-edits-content-contents",
  "trae-alias-edits-content-contents-secret",
  "qwen-alias-content-contents-secret",
  "qwen-alias-contents-content",
  "qwen-alias-edits-content-contents",
  "qwen-alias-edits-content-contents-secret",
  "qoder-alias-content-contents-secret",
  "qoder-alias-contents-content",
  "qoder-alias-edits-content-contents",
  "qoder-alias-edits-content-contents-secret",
  "lingma-alias-content-contents-secret",
  "lingma-alias-contents-content",
  "lingma-alias-edits-content-contents",
  "lingma-alias-edits-content-contents-secret",
  "codebuddy-alias-content-contents-secret",
  "codebuddy-alias-contents-content",
  "codebuddy-alias-edits-content-contents",
  "codebuddy-alias-edits-content-contents-secret",
  "gemini-alias-content-contents-secret",
  "gemini-alias-contents-content",
  "gemini-alias-edits-content-contents",
  "gemini-alias-edits-content-contents-secret",
  "cursor-alias-content-contents-secret",
  "cursor-alias-contents-content",
  "cursor-alias-edits-content-contents",
  "cursor-alias-edits-content-contents-secret",
];

// IC-14: 857f3eb Antigravity host-key placement. [id, v0.2.6 decision, HEAD decision]; "allow" = exit 0, no output.
// Option 2 (union): a re-mapped AbsolutePath claims file_path and is still scanned as content, so only tightenings remain:
// .nmzp / zcode trust paths no longer hidden by an invalid TargetFile; non-string TargetFile scanned;
// re-mapped AbsolutePath conflicts with a literal path/target_file/filePath.
// Fixture-scoped: these probes are examples of the classes, not an exhaustive list.
const IC14_EXPECTED = [
  ["antigravity-alias-targetfile-array-pipe-absolutepath", "allow", "env_piped_outbound"],
  ["antigravity-alias-targetfile-object-pipe-absolutepath", "allow", "env_piped_outbound"],
  ["antigravity-alias-write-targetfile-empty-absolutepath-nmzp", "allow", "monitor_self_tamper"],
  ["antigravity-alias-write-targetfile-null-absolutepath-nmzp", "allow", "monitor_self_tamper"],
  ["antigravity-alias-write-targetfile-number-absolutepath-nmzp", "allow", "monitor_self_tamper"],
  ["antigravity-alias-write-targetfile-empty-absolutepath-zcode-trust", "allow", "zcode_trust_store_tamper"],
  ["antigravity-alias-targetfile-empty-absolutepath-path", "allow", "bad_hook_json"],
  ["antigravity-alias-targetfile-empty-absolutepath-target-file", "allow", "bad_hook_json"],
  ["antigravity-alias-view-file-targetfile-empty-absolutepath-filepath-ssh", "allow", "bad_hook_json"],
];
// Former loosenings (857f3eb alone allowed these); option 2 restores the v0.2.6 bytes exactly.
const IC14_RESTORED = [
  "antigravity-alias-targetfile-empty-absolutepath-pipe",
  "antigravity-alias-targetfile-empty-absolutepath-curl-sh",
  "antigravity-alias-targetfile-null-absolutepath-rm-rf",
  "antigravity-alias-targetfile-empty-absolutepath-drop-host",
  "antigravity-alias-read-url-targetfile-empty-absolutepath-drop-host",
  "antigravity-alias-write-targetfile-empty-absolutepath-poison",
  "antigravity-alias-targetfile-number-absolutepath-pipe",
  "antigravity-alias-targetfile-false-absolutepath-pipe",
  "antigravity-alias-targetfile-empty-array-absolutepath-pipe",
];
const IC14 = IC14_EXPECTED.map(([id]) => id);

// IC-15 option 2: HEAD rejects envelopes deeper than 64 containers as bad_hook_json. v0.2.6 had no limit and
// overflowed its recursive walk only far deeper, at a platform-dependent depth (bootstrap deny).
const IC15_EXPECTED = [
  ["claude-alias-deep-63", "allow", "bad_hook_json"],
  ["claude-alias-deep-4000", "allow", "bad_hook_json"],
  ["claude-alias-deep-6000", "nmzp_hook_bootstrap_failed", "bad_hook_json"],
];
const IC15 = IC15_EXPECTED.map(([id]) => id);

// "allow" = exit 0, no output; otherwise the deny reason in either host's stdout shape.
function decision(bytes) {
  if (bytes.exitCode === 0 && bytes.stdout === "" && bytes.stderr === "") return "allow";
  const out = JSON.parse(bytes.stdout);
  return out.reason ?? out.hookSpecificOutput?.permissionDecisionReason;
}

function rendered(host, reason) {
  const bytes = deny(host, reason);
  return { ...bytes, stderr: bytes.stderr ?? "" };
}

function bytesDiffer(left, right) {
  return left.exitCode !== right.exitCode || left.stdout !== right.stdout || left.stderr !== right.stderr;
}

function runHook(entry, home, argv, stdin) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NMZP_HOME: home };
    for (const key of Object.keys(env)) {
      if (/^(GROK_|CLAUDE_|CURSOR_|CODEX_|ZCODE_|GEMINI_|NMZP_)/.test(key)) delete env[key];
    }
    env.NMZP_HOME = home;
    const child = spawn(process.execPath, ["--experimental-strip-types", entry, ...argv], {
      env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out = [];
    const err = [];
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timeout ${argv.join(" ")}`));
    }, 15000);
    child.stdout.on("data", (data) => out.push(data));
    child.stderr.on("data", (data) => err.push(data));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal) reject(new Error(`${argv.join(" ")}:${signal}`));
      else resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.end(stdin);
  });
}

async function freshHome(root, id) {
  const home = join(root, "homes", id);
  const cache = join(home, ".nmzp", "policy-cache.json");
  await mkdir(join(home, ".nmzp"), { recursive: true });
  await writePolicyCache(cache, { version: 1, mode: "enforcing", stopped: false, customRules: [], updatedAt: 1 });
  return home;
}

describe("v0.2.6 hook-byte fixture", () => {
  test("104 golden cases, 181 unique alias probes, ic13 + ic14 + ic15 is exactly the recorded diff", () => {
    assert.equal(fixture.goldenCases.length, 104);
    assert.deepEqual(
      fixture.goldenCases.map((item) => item.id),
      golden.cases.map((item) => item.id),
    );
    assert.equal(new Set(fixture.goldenCases.map((item) => item.id)).size, 104);
    assert.equal(fixture.aliasProbes.length, 181);
    assert.equal(new Set(fixture.aliasProbes.map((item) => item.id)).size, 181);
    const goldenDiffs = fixture.goldenCases
      .filter((item, index) => bytesDiffer(item, golden.cases[index]))
      .map((item) => item.id);
    const probeDiffs = fixture.aliasProbes.filter((item) => bytesDiffer(item.v026, item.head)).map((item) => item.id);
    const diffs = [...goldenDiffs, ...probeDiffs];
    assert.deepEqual(diffs.filter((id) => !IC14.includes(id) && !IC15.includes(id)), IC13);
    assert.deepEqual(diffs.filter((id) => IC14.includes(id)), IC14);
    assert.deepEqual(diffs.filter((id) => IC15.includes(id)), IC15);
    assert.deepEqual(fixture.ic13, IC13);
    assert.deepEqual(fixture.ic14, IC14);
    assert.deepEqual(fixture.ic15, IC15);
    assert.equal(IC13.length, 55);
  });

  test("every differing HEAD output is that host's bad_hook_json deny", () => {
    const goldenById = new Map(golden.cases.map((item) => [item.id, item]));
    const probeById = new Map(fixture.aliasProbes.map((item) => [item.id, item]));
    for (const id of IC13) {
      const probe = probeById.get(id);
      const item = goldenById.get(id);
      assert.ok(probe || item, id);
      const host = probe ? probe.host : item.host;
      const head = probe ? probe.head : { exitCode: item.exitCode, stdout: item.stdout, stderr: item.stderr };
      const rendered = deny(host, "bad_hook_json");
      assert.equal(head.exitCode, rendered.exitCode, `${id} exit`);
      assert.equal(head.stdout, rendered.stdout, `${id} stdout`);
      assert.equal(head.stderr, rendered.stderr ?? "", `${id} stderr`);
    }
  });

  test("IC-14: recorded v0.2.6 and HEAD decisions for 857f3eb host-key placement", () => {
    for (const [id, v026, head] of IC14_EXPECTED) {
      const probe = fixture.aliasProbes.find((item) => item.id === id);
      assert.ok(probe, id);
      assert.equal(probe.host, "antigravity", id);
      assert.equal(decision(probe.v026), v026, `${id} v026`);
      assert.equal(decision(probe.head), head, `${id} head`);
      if (v026 !== "allow") assert.deepEqual(probe.v026, rendered("antigravity", v026), id);
      if (head !== "allow") assert.deepEqual(probe.head, rendered("antigravity", head), id);
    }
    // Option 2 leaves no loosening in this fixture; the former loosenings are byte-identical to v0.2.6.
    assert.deepEqual(IC14_EXPECTED.filter(([, v026, head]) => v026 !== "allow" && head === "allow"), []);
    for (const id of IC14_RESTORED) {
      const probe = fixture.aliasProbes.find((item) => item.id === id);
      assert.ok(probe, id);
      assert.notEqual(decision(probe.v026), "allow", id);
      assert.deepEqual(probe.head, probe.v026, id);
    }
    // Control: a literal file_path beside the re-mapped AbsolutePath is identical on both trees.
    const control = fixture.aliasProbes.find((item) => item.id === "antigravity-alias-targetfile-empty-absolutepath-file-path");
    assert.ok(control);
    assert.deepEqual(control.head, control.v026);
  });

  test("IC-15: HEAD rejects nesting deeper than 64; v0.2.6 overflowed only far deeper", () => {
    for (const [id, v026, head] of IC15_EXPECTED) {
      const probe = fixture.aliasProbes.find((item) => item.id === id);
      assert.ok(probe, id);
      assert.equal(probe.host, "claude", id);
      assert.equal(decision(probe.v026), v026, `${id} v026`);
      assert.equal(decision(probe.head), head, `${id} head`);
      assert.deepEqual(probe.head, rendered("claude", head), id);
      if (v026 === "nmzp_hook_bootstrap_failed") {
        // v0.2.6 bootstrap path also writes the reason to stderr.
        assert.equal(probe.v026.exitCode, 2, id);
        assert.equal(probe.v026.stdout, rendered("claude", v026).stdout, id);
        assert.equal(probe.v026.stderr, `${v026}\n`, id);
      }
    }
    // Control: depth 64 (root + tool_input + 62 arrays) is the last allowed depth on both trees.
    const control = fixture.aliasProbes.find((item) => item.id === "claude-alias-deep-62");
    assert.ok(control);
    assert.deepEqual(control.head, control.v026);
    assert.equal(decision(control.head), "allow");
  });
});

describe("packed bundle matches v0.2.6 fixture head alias probes", { concurrency: 1, timeout: 300000 }, () => {
  let packedDir;
  let root;

  before(async () => {
    root = await mkdtemp(join(tmpdir(), "nmzp-v026-pack-"));
    const source = fileURLToPath(new URL("../../", import.meta.url));
    await cp(join(source, "core"), join(root, "core"), { recursive: true });
    await mkdir(join(root, "src", "lib"), { recursive: true });
    await cp(join(source, "src", "lib", "monitor"), join(root, "src", "lib", "monitor"), { recursive: true });
    await cp(join(source, "dist"), join(root, "dist"), { recursive: true });
    packedDir = (await packRelease(root)).dir;
  });

  after(async () => {
    if (root) await rm(root, { recursive: true, force: true });
  });

  for (const probe of fixture.aliasProbes) {
    test(probe.id, async () => {
      assert.ok(packedDir, "bundle was not prepared");
      const home = await freshHome(root, probe.id);
      const got = await runHook(join(packedDir, "nmzp.mjs"), home, probe.argv, probe.stdin);
      assert.equal(got.code, probe.head.exitCode, `${probe.id} exit`);
      assert.equal(got.stdout, probe.head.stdout, `${probe.id} stdout`);
      assert.equal(got.stderr, probe.head.stderr, `${probe.id} stderr`);
    });
  }
});
