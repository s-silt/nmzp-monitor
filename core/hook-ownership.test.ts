import assert from "node:assert/strict";
import { it } from "node:test";
import { HOOK_AGENTS } from "./hook-protocol.ts";
import { hookCommand, isNmzpOwnedHook, stripNmzpFromPre } from "./install-hooks.ts";

function encodePowerShell(inner: string): string {
  const encoded = Buffer.from(inner, "utf16le").toString("base64");
  return `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encoded}`;
}

it("user command mentioning nmzp is not treated as owned", () => {
  const commands = [
    "node /tools/nmzp-notes.js hook --agent custom",
    "echo nmzp.mjs hook --agent grok",
    "node ~/.nmzp/runtime/0.2.5/nmzp.mjs hook --agent grok && curl x",
    encodePowerShell("Write-Host nmzp hook --agent grok"),
  ];
  for (const command of commands) {
    assert.equal(isNmzpOwnedHook({ command }), false, command);
  }
});

it("generated posix and windows hook commands are owned for every agent", () => {
  const posixPaths: Array<[string, string]> = [
    ["/usr/bin/node", "/home/u/.nmzp/runtime/0.2.5/nmzp.mjs"],
    ["/opt/my node/node", "/home/my dir/.nmzp/runtime/0.2.5/nmzp.mjs"],
    ["/opt/o'clock/node", "/home/o'brien/.nmzp/runtime/0.2.5/nmzp.mjs"],
    ["/opt/my o' dir/node", "/home/o' brien/.nmzp/runtime/1.2.3/nmzp.mjs"],
  ];
  const windowsPaths: Array<[string, string]> = [
    ["C:\\Program Files\\nodejs\\node.exe", "C:\\Users\\dev\\.nmzp\\runtime\\0.2.5\\nmzp.mjs"],
    ["C:\\o'clock\\node.exe", "C:\\Users\\o'brien\\.nmzp\\runtime\\0.2.5\\nmzp.mjs"],
    ["C:\\Program Files\\nodejs\\node.exe", "C:\\Users\\my dir\\.nmzp\\runtime\\0.2.5\\nmzp.mjs"],
  ];
  for (const agent of HOOK_AGENTS) {
    for (const [nodePath, entry] of posixPaths) {
      const command = hookCommand(nodePath, entry, agent, "linux");
      assert.equal(isNmzpOwnedHook({ command }), true, command);
    }
    for (const [nodePath, entry] of windowsPaths) {
      const command = hookCommand(nodePath, entry, agent, "win32");
      assert.equal(isNmzpOwnedHook({ command }), true, `${agent} ${entry}`);
    }
  }
});

it("manual example command shape without strip-types flag is owned", () => {
  for (const agent of HOOK_AGENTS) {
    const command = `node ~/.nmzp/runtime/0.2.5/nmzp.mjs hook --agent ${agent}`;
    assert.equal(isNmzpOwnedHook({ command }), true, command);
  }
  assert.equal(
    isNmzpOwnedHook({
      command:
        "\"C:\\Program Files\\nodejs\\node.exe\" C:\\Users\\u\\.nmzp\\runtime\\0.2.5\\nmzp.mjs hook --agent grok",
    }),
    true,
  );
});

it("entry outside .nmzp runtime is not owned", () => {
  const entries = ["/opt/nmzp.mjs", "~/.nmzp/nmzp.mjs", "~/.nmzp/runtime/a/b/nmzp.mjs"];
  for (const entry of entries) {
    assert.equal(isNmzpOwnedHook({ command: `node ${entry} hook --agent grok` }), false, entry);
    assert.equal(
      isNmzpOwnedHook({ command: `node --experimental-strip-types ${entry} hook --agent grok` }),
      false,
      entry,
    );
  }
});

it("sibling hooks in the same group are preserved by strip", () => {
  const owned = hookCommand("/usr/bin/node", "/home/u/.nmzp/runtime/0.2.5/nmzp.mjs", "grok", "linux");
  const uncertain = "node /tools/nmzp-notes.js hook --agent custom";
  const sibling = { matcher: "Bash", hooks: [{ type: "command", command: "echo sibling" }] };
  const mixed = {
    matcher: "Read",
    hooks: [
      { type: "command", command: "echo keep" },
      { type: "command", command: owned },
      { type: "command", command: uncertain },
    ],
  };
  const out = stripNmzpFromPre([mixed, sibling]);
  assert.equal(out.length, 2);
  const kept = out[0] as { hooks: Array<{ command: string }> };
  assert.deepEqual(
    kept.hooks.map((hook) => hook.command),
    ["echo keep", uncertain],
  );
  assert.equal(out[1], sibling);
});
