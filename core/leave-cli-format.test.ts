import assert from "node:assert/strict";
import cp from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { after, it } from "node:test";

const realSpawn = cp.spawnSync;
const scratch = mkdtempSync(join(tmpdir(), "nmzp-leave-cli-"));
const aclHome = resolve(scratch);

cp.spawnSync = ((command: unknown, args?: unknown, options?: { env?: Record<string, string | undefined> }) => {
  const target = options?.env?.NMZP_ACL_PATH;
  assert.equal(command, "powershell.exe", "only permission boundary is mocked");
  assert.equal(typeof target, "string", "ACL target must be owned fixture");
  assert.ok(resolve(String(target)).startsWith(aclHome + sep), "ACL target must be owned fixture");
  const list = Array.isArray(args) ? args : [];
  assert.ok(
    list.includes("-Command") && list.some((arg) => typeof arg === "string" && arg.includes("SetAccessControl")),
    "only known ACL script intercepted",
  );
  return { status: 0, stdout: "", stderr: "", signal: null, pid: 0, output: [] };
}) as unknown as typeof cp.spawnSync;
syncBuiltinESMExports();

const { formatLeaveResult } = await import("./cli.ts");

after(() => {
  cp.spawnSync = realSpawn;
  syncBuiltinESMExports();
  rmSync(scratch, { recursive: true, force: true });
});

it("formatLeaveResult reports failures on stderr with exit code 1 and keeps success text", () => {
  const left = formatLeaveResult("left", { ok: true, removed: ["a", "b"], failed: [], unresolved: [] });
  assert.equal(left.stdout, "left (2 entries)\n");
  assert.equal(left.stderr, "");
  assert.equal(left.exitCode, 0);

  const uninstalled = formatLeaveResult("uninstalled", { ok: true, removed: [], failed: [], unresolved: [] });
  assert.equal(uninstalled.stdout, "uninstalled (0 entries)\n");
  assert.equal(uninstalled.stderr, "");
  assert.equal(uninstalled.exitCode, 0);

  const failed = formatLeaveResult("left", {
    ok: false,
    removed: ["grok:nmzp-entry"],
    failed: [
      { target: "claude:settings.json", reason: "config_corrupt" },
      { target: "codex:hooks.json", reason: "write_failed" },
    ],
    unresolved: [],
  });
  assert.equal(failed.exitCode, 1);
  assert.equal(failed.stdout, "left (1 entries)\n");
  assert.equal(
    failed.stderr,
    "claude:settings.json config_corrupt\ncodex:hooks.json write_failed\nfix the listed host configs by hand and re-run the command\n",
  );

  const named = formatLeaveResult("uninstalled", {
    ok: false,
    removed: ["grok:nmzp-entry"],
    failed: [{ target: "claude:settings.json", reason: "config_corrupt" }],
    unresolved: [],
  });
  assert.equal(named.stdout, "uninstalled (1 entries)\n");
  assert.equal(named.exitCode, 1);
  assert.match(named.stderr, /claude:settings\.json config_corrupt/);
  assert.match(named.stderr, /fix the listed host configs by hand and re-run the command/);
});

it("unresolved nmzp-like entries are listed on stderr without failing", () => {
  const command = "node /tools/nmzp-notes.js hook --agent custom";
  const left = formatLeaveResult("left", {
    ok: true,
    removed: ["grok:nmzp-entry"],
    failed: [],
    unresolved: [{ target: "claude:settings.json", command }],
  });
  assert.equal(left.exitCode, 0);
  assert.equal(left.stdout, "left (1 entries)\n");
  assert.equal(
    left.stderr,
    `claude:settings.json ${command} left untouched (not recognized as NMZP-generated)\n`,
  );

  const failed = formatLeaveResult("uninstalled", {
    ok: false,
    removed: [],
    failed: [{ target: "grok:nmzp.json", reason: "config_corrupt" }],
    unresolved: [{ target: "claude:settings.json", command: command.slice(0, 80) }],
  });
  assert.equal(failed.exitCode, 1);
  assert.equal(failed.stdout, "uninstalled (0 entries)\n");
  assert.match(failed.stderr, /grok:nmzp\.json config_corrupt/);
  assert.match(failed.stderr, /fix the listed host configs by hand and re-run the command/);
  assert.match(failed.stderr, /left untouched \(not recognized as NMZP-generated\)/);
  assert.match(failed.stderr, /claude:settings\.json node \/tools\/nmzp-notes\.js hook --agent custom/);
});
