import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ACL_RESTRICT_PS, atomicWriteFile, type AtomicFs } from "./install-fs.ts";

describe("install-fs safety", () => {
  it("atomic write keeps the previous file if the replacement rename fails", () => {
    const dest = join(tmpdir(), `nmzp-atomic-${process.pid}-${Date.now()}`);
    const files = new Map<string, string>([[dest, "OLD_SECRET_SETTINGS"]]);
    const renamed: Array<[string, string]> = [];
    const io: AtomicFs = {
      mkdirSync: () => undefined,
      writeFileSync: (path, body) => {
        files.set(path, body);
      },
      existsSync: (path) => files.has(path),
      unlinkSync: (path) => {
        files.delete(path);
      },
      renameSync: (from, to) => {
        renamed.push([from, to]);
        if (from === dest) throw new Error("must_not_move_live_path");
        if (to === dest) throw new Error("rename_dest_failed");
        const v = files.get(from);
        if (v === undefined) throw new Error("missing");
        files.delete(from);
        files.set(to, v);
      },
    };
    assert.throws(() => atomicWriteFile(dest, "NEW", 0o600, io), /atomic_write_failed/);
    assert.equal(files.get(dest), "OLD_SECRET_SETTINGS");
    assert.equal(
      renamed.some(([from]) => from === dest),
      false,
    );
    assert.equal([...files.values()].includes("NEW"), false);
  });

  it("atomic write replaces an existing file in one rename onto the live path", () => {
    const dir = join(tmpdir(), `nmzp-atomic-ok-${process.pid}`);
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, "cfg.json");
    writeFileSync(dest, "first");
    try {
      atomicWriteFile(dest, "second");
      assert.equal(readFileSync(dest, "utf8"), "second");
      assert.equal(existsSync(dest), true);
    } finally {
      try {
        writeFileSync(dest, "");
      } catch {
        /* ignore */
      }
    }
  });

  it("ACL script takes the path from env and does not interpolate JSON or invoke subexpressions", () => {
    assert.match(ACL_RESTRICT_PS, /\$env:NMZP_ACL_PATH/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /JSON\.stringify/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /\$\(/);
    assert.doesNotMatch(ACL_RESTRICT_PS, /`/);
  });
});
