import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluate } from "./engine.ts";

function run(command: string) {
  return evaluate(
    { source: "hook", agent: "claude", cwd: "/home/fixture/project", nativeTool: "Bash", command },
    "enforcing",
    [],
    {},
  );
}

describe("audit false positives", () => {
  it("F1 cat src/dd.ts is not disk_overwrite", () => {
    const result = run("cat src/dd.ts");
    assert.equal(result.rule?.id ?? "none", "none", "F1 cat src/dd.ts is not disk_overwrite");
    assert.notEqual(result.decision, "block");
  });

  it("read-only filename lookalikes are not disk operations", () => {
    const commands = [
      "echo docs/parted",
      "echo 'dd if=/dev/zero of=/dev/sda'",
      "printf '%s' docs/parted",
      "grep dd src/dd.ts",
      "cat docs/parted",
      "head fdisk.txt",
      "tail mkfs.ext4",
      "ls parted",
      "command -v dd",
      "sudo cat src/dd.ts",
      "bash -c 'cat src/dd.ts'",
      "bash -c 'echo docs/parted'",
      "sh -c 'cat docs/mkfs.txt'",
    ];
    for (const command of commands) {
      const result = run(command);
      assert.notEqual(result.rule?.id, "disk_overwrite", command);
      assert.notEqual(result.decision, "block", command);
    }
  });

  it("real disk utilities and supported prefixes still block", () => {
    const commands = [
      "dd if=/dev/zero of=/dev/sda",
      "mkfs.ext4 /dev/sdb1",
      "mkfs.vfat /dev/sdb1",
      "/sbin/mkfs.ext4 /dev/sda1",
      "fdisk /dev/sda",
      "parted /dev/sda mklabel gpt",
      "sudo dd if=/dev/zero of=/dev/sda",
      "sudo -u x dd if=/dev/zero of=/dev/sda",
      "env -i dd if=/dev/zero of=/dev/sda",
      "command dd if=/dev/zero of=/dev/sda",
      "exec dd if=/dev/zero of=/dev/sda",
      "nice dd if=/dev/zero of=/dev/sda",
      "nohup dd if=/dev/zero of=/dev/sda",
      "timeout 5 dd if=/dev/zero of=/dev/sda",
      "time dd if=/dev/zero of=/dev/sda",
      "xargs dd if=/dev/zero of=/dev/sda",
      "busybox dd if=/dev/zero of=/dev/sda",
      "busybox mkfs.vfat /dev/sdb1",
      "doas dd if=/dev/zero of=/dev/sda",
      "ssh host dd if=/dev/zero of=/dev/sda",
      "stdbuf -o0 dd if=/dev/zero of=/dev/sda",
      "watch dd if=/dev/zero of=/dev/sda",
      "eval dd if=/dev/zero of=/dev/sda",
      "eval 'dd if=/dev/zero of=/dev/sda'",
      "bash -c 'dd if=/dev/zero of=/dev/sda'",
      "sh -c 'dd if=/dev/zero of=/dev/sda'",
      "if true; then dd if=/dev/zero of=/dev/sda; fi",
      "\\dd if=/dev/zero of=/dev/sda",
      "echo keep; dd if=/dev/zero of=/dev/sda",
      "FOO=bar dd if=/dev/zero of=/tmp/synthetic.bin",
    ];
    for (const command of commands) {
      const result = run(command);
      assert.equal(result.decision, "block", command);
      assert.equal(result.rule?.id, "disk_overwrite", command);
    }
  });
});
