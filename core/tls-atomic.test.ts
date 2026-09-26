import assert from "node:assert/strict";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { setAtomicFileIoForTesting } from "./atomic-file.ts";
import { loadOrCreateTls } from "./tls.ts";
import { writeJoinBundleFile } from "./cli.ts";

describe("tls and bundle writes do not follow links", () => {
  afterEach(() => {
    setAtomicFileIoForTesting();
  });

  it("refuses a junction tls directory and leaves the target unchanged", async () => {
    const root = mkdtempSync(join(tmpdir(), "nmzp-tls-link-"));
    try {
      const data = join(root, "data");
      const store = join(root, "store");
      mkdirSync(data);
      mkdirSync(store);
      writeFileSync(join(store, "keep.txt"), "SECRET");
      symlinkSync(store, join(data, "tls"), "junction");
      await assert.rejects(() => loadOrCreateTls(data, ["127.0.0.1"]), /unsafe_symlink/, "tls junction was followed");
      assert.equal(readFileSync(join(store, "keep.txt"), "utf8"), "SECRET");
      assert.equal(lstatSync(join(data, "tls")).isSymbolicLink(), true);
      let key = false;
      try {
        key = lstatSync(join(store, "server.key")).isFile();
      } catch {
        key = false;
      }
      assert.equal(key, false, "tls junction wrote a key");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("leaves an incomplete marker when a later TLS stage fails and does not rotate", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-tls-stage-"));
    let renames = 0;
    try {
      setAtomicFileIoForTesting({
        rename(from, to) {
          renames += 1;
          if (renames >= 2) throw new Error("stage_fault");
          renameSync(from, to);
        },
      });
      await assert.rejects(() => loadOrCreateTls(dir, ["127.0.0.1"]), /tls_incomplete_recoverable/);
      const marker = JSON.parse(readFileSync(join(dir, "tls", "incomplete.json"), "utf8")) as { recoverable?: boolean };
      assert.equal(marker.recoverable, true);
      setAtomicFileIoForTesting();
      const keyBefore = (() => {
        try {
          return readFileSync(join(dir, "tls", "server.key"), "utf8");
        } catch {
          return "";
        }
      })();
      await assert.rejects(() => loadOrCreateTls(dir, ["127.0.0.1", "localhost"]), /tls_incomplete_recoverable/);
      const keyAfter = (() => {
        try {
          return readFileSync(join(dir, "tls", "server.key"), "utf8");
        } catch {
          return "";
        }
      })();
      assert.equal(keyAfter, keyBefore);
    } finally {
      setAtomicFileIoForTesting();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not replace an existing key when the pin does not match", async () => {
    const dir = await mkdtemp(join(tmpdir(), "nmzp-tls-pin-"));
    try {
      const first = await loadOrCreateTls(dir, ["127.0.0.1"]);
      writeFileSync(join(dir, "tls", "pin.json"), JSON.stringify({ fingerprintSha256: "0".repeat(64) }));
      await assert.rejects(() => loadOrCreateTls(dir, ["127.0.0.1"]), /tls pin mismatch/);
      assert.equal(readFileSync(join(dir, "tls", "server.key"), "utf8"), first.keyPem);
      assert.equal(readFileSync(join(dir, "tls", "server.crt"), "utf8"), first.certPem);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses a bundle path reached through a junction and leaves the target unchanged", async () => {
    const root = await mkdtemp(join(tmpdir(), "nmzp-bundle-link-"));
    const real = join(root, "real");
    const link = join(root, "link");
    try {
      mkdirSync(real);
      writeFileSync(join(real, "keep.txt"), "SECRET");
      symlinkSync(real, link, "junction");
      await assert.rejects(() => writeJoinBundleFile(join(link, "bundle.json"), "NEW"), /unsafe_symlink/);
      assert.equal(readFileSync(join(real, "keep.txt"), "utf8"), "SECRET");
      assert.equal(lstatSync(link).isSymbolicLink(), true);
      let written = false;
      try {
        written = lstatSync(join(real, "bundle.json")).isFile();
      } catch {
        written = false;
      }
      assert.equal(written, false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
