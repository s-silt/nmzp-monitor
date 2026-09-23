import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { FilePolicyStore, PolicyFileError } from "./file-store.ts";
import { PolicyPublisher, PolicyPublishError } from "./publisher.ts";
import { createPolicySnapshot } from "./snapshot.ts";

const fixture = (patch = {}) => ({
  version: 7, updatedAt: 100, mode: "enforcing", stopped: false,
  customRules: [{ id: "synthetic_rule", enabled: true, mode: "block", match: "fixture.invalid", kind: "fixture", replaceWith: "" }],
  ...patch,
});
const bodyOf = ({ version: _version, updatedAt: _updatedAt, ...body }) => body;
const operations = (patch = {}) => ({ open: fs.open, lstat: fs.lstat, rename: fs.rename, unlink: fs.unlink, ...patch });
const codeIs = (code) => (e) => (e instanceof PolicyFileError || e instanceof PolicyPublishError) && e.code === code;
const syntheticFailure = () => new Error("synthetic-failure:do-not-expose-path-or-policy");
function wrapHandle(handle, overrides) {
  return new Proxy(handle, { get(target, key) {
    if (Object.hasOwn(overrides, key)) return overrides[key];
    const value = Reflect.get(target, key, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
}
function gate() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
async function setup(t, patch = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), "nmzp-policy-file-test-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const path = join(dir, "policy.json");
  const initial = fixture(patch);
  await fs.writeFile(path, JSON.stringify(initial, null, 2), { mode: 0o600 });
  return { dir, path, initial };
}
async function openStore(context, options = {}) {
  return FilePolicyStore.open({ path: context.path, durability: "file", ...options });
}
function prepare(snapshot) {
  // Synthetic domain validation, NOT a substitute for NMZP's actual catalog checks.
  if (!['enforcing', 'permissive', 'off'].includes(snapshot.policy.mode) || !Array.isArray(snapshot.policy.customRules)) {
    throw new Error("synthetic_domain_rejection");
  }
}
async function publisherFor(store, options = {}) {
  const snapshot = await store.read();
  return PolicyPublisher.open(snapshot.policy, { prepare, persist: store.persist, now: () => 200, ...options });
}
const nextOf = (old, patch = {}) => createPolicySnapshot({ ...old.policy, version: old.policy.version + 1, updatedAt: 200, ...patch });
async function names(dir) { return (await fs.readdir(dir)).sort(); }

// No production HOME, NMZP services, ACL commands or host processes are used here.
describe("plain policy.json file persistence", { timeout: 10000, concurrency: false }, () => {
  it("opens the existing plain JSON without rewriting or wrapping it", async (t) => {
    const c = await setup(t); const before = await fs.readFile(c.path);
    const store = await openStore(c); const loaded = await store.read();
    assert.deepEqual(loaded.policy, c.initial);
    assert.deepEqual(await fs.readFile(c.path), before);
    assert.deepEqual(await names(c.dir), ["policy.json"]);
    assert.equal(store.durability, "file");
  });

  it("rejects missing files without bootstrapping defaults", async (t) => {
    const c = await setup(t); await fs.unlink(c.path);
    await assert.rejects(openStore(c), codeIs("policy_file_read_failed"));
    assert.deepEqual(await names(c.dir), []);
  });

  it("rejects invalid JSON, UTF-8, BOM, root shapes and revision metadata", async (t) => {
    const c = await setup(t);
    const inputs = ["{", "[]", "null", JSON.stringify({ version: 0, updatedAt: 0 }),
      JSON.stringify({ version: 7, updatedAt: -1 }), Buffer.from([0xff]), `\ufeff${JSON.stringify(c.initial)}`];
    for (const input of inputs) {
      await fs.writeFile(c.path, input);
      await assert.rejects(openStore(c), codeIs("policy_file_invalid"));
      assert.deepEqual(await fs.readFile(c.path), Buffer.from(input));
    }
  });

  it("bounds raw bytes independently from normalized snapshot limits", async (t) => {
    const c = await setup(t);
    await fs.writeFile(c.path, " ".repeat(1025));
    await assert.rejects(openStore(c, { maxFileBytes: 1024 }), codeIs("policy_file_too_large"));
    await fs.writeFile(c.path, JSON.stringify(c.initial));
    await assert.rejects(openStore(c, { limits: { maxBytes: 64 } }), codeIs("policy_file_invalid"));
  });

  it("bounds reads even when the stat size is stale", async (t) => {
    const c = await setup(t); await fs.writeFile(c.path, " ".repeat(1025));
    const io = operations({ open: async (...args) => {
      const h = await fs.open(...args);
      return wrapHandle(h, { stat: async () => ({ isFile: () => true, size: 0 }) });
    } });
    await assert.rejects(openStore(c, { maxFileBytes: 1024, operations: io }), codeIs("policy_file_too_large"));
  });

  it("rejects directory and symlink entries before opening them", async (t) => {
    const c = await setup(t);
    await assert.rejects(openStore({ path: c.dir }), codeIs("policy_file_not_regular"));
    let opened = 0;
    // Synthetic symlink stat keeps this check portable without Windows elevation.
    await assert.rejects(openStore(c, { operations: operations({
      lstat: async () => ({ isFile: () => false, isSymbolicLink: () => true }),
      open: async () => { opened++; throw syntheticFailure(); },
    }) }), codeIs("policy_file_not_regular"));
    assert.equal(opened, 0);
  });

  it("does not promote or delete a stale temporary even with a higher version", async (t) => {
    const c = await setup(t); const orphan = join(c.dir, "policy.json.tmp.orphan");
    await fs.writeFile(orphan, JSON.stringify(fixture({ version: 999 })));
    const before = await fs.readFile(orphan);
    assert.equal((await (await openStore(c)).read()).policy.version, 7);
    assert.deepEqual(await fs.readFile(orphan), before);
    await fs.writeFile(c.path, "{");
    await assert.rejects(openStore(c), codeIs("policy_file_invalid"));
    assert.deepEqual(await names(c.dir), ["policy.json", "policy.json.tmp.orphan"]);
  });

  it("requires an absolute explicit path, valid limits and durability", async (t) => {
    const c = await setup(t);
    for (const patch of [{ path: "policy.json" }, { path: "bad\0path" }, { durability: undefined },
      { durability: "best_effort" }, { maxFileBytes: 0 }, { maxFileBytes: 1.5 }, { maxFileBytes: 17 * 1024 * 1024 }]) {
      await assert.rejects(openStore(c, patch), codeIs("policy_file_options"));
    }
  });

  it("writes a complete synced file, renames, verifies, then acknowledges", async (t) => {
    const c = await setup(t); const order = []; let tempClosed = false;
    const store = await openStore(c, { operations: operations({
      open: async (...args) => {
        const h = await fs.open(...args);
        if (args[1] !== "wx") return h;
        assert.equal(args[2], 0o600);
        return wrapHandle(h, {
          writeFile: async (...xs) => { order.push("write"); return h.writeFile(...xs); },
          sync: async () => { order.push("file-sync"); return h.sync(); },
          close: async () => { order.push("file-close"); tempClosed = true; return h.close(); },
        });
      },
      rename: async (source, dest) => { assert.equal(tempClosed, true); order.push("rename"); return fs.rename(source, dest); },
    }) });
    const old = await store.read(); const next = nextOf(old);
    assert.deepEqual(await store.persist(next, old), { kind: "committed" });
    assert.deepEqual(order, ["write", "file-sync", "file-close", "rename"]);
    const raw = JSON.parse(await fs.readFile(c.path, "utf8"));
    assert.deepEqual(raw, next.policy); assert.equal(raw.policy, undefined); assert.equal(raw.hash, undefined);
    assert.deepEqual(await names(c.dir), ["policy.json"]);
  });

  it("rejects forged snapshots, non-successor versions and backwards timestamps", async (t) => {
    const c = await setup(t); const store = await openStore(c); const old = await store.read();
    const raw = await fs.readFile(c.path);
    for (const next of [{ ...nextOf(old), hash: "0".repeat(64) }, nextOf(old, { version: 9 }), nextOf(old, { updatedAt: 99 })]) {
      await assert.rejects(store.persist(next, old), codeIs("policy_file_transition"));
      assert.deepEqual(await fs.readFile(c.path), raw);
    }
  });

  it("detects externally changed authority and never overwrites it", async (t) => {
    const c = await setup(t); const store = await openStore(c); const old = await store.read();
    await fs.writeFile(c.path, JSON.stringify(fixture({ mode: "off" })));
    const changed = await fs.readFile(c.path);
    await assert.rejects(store.persist(nextOf(old), old), codeIs("policy_file_recovery_required"));
    assert.equal(store.recoveryRequired, true);
    assert.deepEqual(await fs.readFile(c.path), changed);
  });

  it("detects an authority change during temporary-file preparation", async (t) => {
    const c = await setup(t); let renamed = false;
    const store = await openStore(c, { operations: operations({
      open: async (...args) => {
        const h = await fs.open(...args); if (args[1] !== "wx") return h;
        return wrapHandle(h, { sync: async () => {
          await h.sync(); await fs.writeFile(c.path, JSON.stringify(fixture({ version: 90 })));
        } });
      },
      rename: async (...args) => { renamed = true; return fs.rename(...args); },
    }) });
    const old = await store.read();
    await assert.rejects(store.persist(nextOf(old), old), codeIs("policy_file_recovery_required"));
    assert.equal(renamed, false); assert.equal((await store.read()).policy.version, 90);
  });

  for (const failurePoint of ["open", "write", "sync", "close"]) {
    it(`known ${failurePoint} failure before rename keeps old bytes and permits retry`, async (t) => {
      const c = await setup(t); let fail = true; let renameCalls = 0;
      const store = await openStore(c, { operations: operations({
        open: async (...args) => {
          if (args[1] === "wx" && failurePoint === "open" && fail) throw syntheticFailure();
          const h = await fs.open(...args); if (args[1] !== "wx") return h;
          let failedClose = false;
          return wrapHandle(h, {
            writeFile: async (buffer) => {
              if (failurePoint === "write" && fail) { await h.writeFile(buffer.subarray(0, 5)); throw syntheticFailure(); }
              return h.writeFile(buffer);
            },
            sync: async () => { if (failurePoint === "sync" && fail) throw syntheticFailure(); return h.sync(); },
            close: async () => {
              if (failurePoint === "close" && fail && !failedClose) { failedClose = true; throw syntheticFailure(); }
              return h.close();
            },
          });
        },
        rename: async (...args) => { renameCalls++; return fs.rename(...args); },
      }) });
      const raw = await fs.readFile(c.path); const old = await store.read(); const next = nextOf(old);
      assert.deepEqual(await store.persist(next, old), { kind: "not_committed" });
      assert.equal(store.recoveryRequired, false); assert.equal(renameCalls, 0);
      assert.deepEqual(await fs.readFile(c.path), raw); assert.deepEqual(await names(c.dir), ["policy.json"]);
      fail = false;
      assert.deepEqual(await store.persist(next, old), { kind: "committed" });
      assert.equal((await store.read()).policy.version, 8);
    });
  }

  for (const didRename of [false, true]) {
    it(`rename error fences even when ${didRename ? "replacement actually happened" : "old file remains"}`, async (t) => {
      const c = await setup(t);
      const store = await openStore(c, { operations: operations({ rename: async (...args) => {
        if (didRename) await fs.rename(...args); throw syntheticFailure();
      } }) });
      const old = await store.read(); const next = nextOf(old);
      await assert.rejects(store.persist(next, old), codeIs("policy_file_recovery_required"));
      assert.equal(store.recoveryRequired, true);
      assert.equal((await store.read()).policy.version, didRename ? 8 : 7);
      await assert.rejects(store.persist(next, old), codeIs("policy_file_recovery_required"));
      assert.deepEqual(await names(c.dir), ["policy.json"]);
    });
  }

  it("strict directory-sync mode does not silently downgrade unsupported preflight", async (t) => {
    const c = await setup(t); let renamed = 0;
    const store = await openStore(c, { durability: "file-and-directory", operations: operations({
      open: async (...args) => { if (String(args[0]) === c.dir) throw syntheticFailure(); return fs.open(...args); },
      rename: async (...args) => { renamed++; return fs.rename(...args); },
    }) });
    const old = await store.read();
    assert.deepEqual(await store.persist(nextOf(old), old), { kind: "not_committed" });
    assert.equal(renamed, 0); assert.equal((await store.read()).policy.version, 7);
  });

  it("directory-sync protocol is preflight, rename, sync; post-rename failure is unknown", async (t) => {
    const c = await setup(t); const order = [];
    // Directory handle is synthetic; actual Windows directory-sync support is not claimed.
    const store = await openStore(c, { durability: "file-and-directory", operations: operations({
      open: async (...args) => {
        if (String(args[0]) !== c.dir) return fs.open(...args);
        return { sync: async () => { order.push("directory-sync"); if (order.length > 1) throw syntheticFailure(); }, close: async () => {} };
      },
      rename: async (...args) => { order.push("rename"); return fs.rename(...args); },
    }) });
    const old = await store.read();
    await assert.rejects(store.persist(nextOf(old), old), codeIs("policy_file_recovery_required"));
    assert.deepEqual(order, ["directory-sync", "rename", "directory-sync"]);
    assert.equal((await store.read()).policy.version, 8);
  });

  it("acknowledges strict durability only after successful directory sync", async (t) => {
    const c = await setup(t); let calls = 0; let closed = 0;
    const io = operations({ open: async (...args) => {
      if (String(args[0]) !== c.dir) return fs.open(...args);
      return { sync: async () => { calls++; }, close: async () => { closed++; } };
    } });
    const store = await openStore(c, { durability: "file-and-directory", operations: io });
    const old = await store.read();
    assert.deepEqual(await store.persist(nextOf(old), old), { kind: "committed" });
    assert.equal(calls, 2); assert.equal(closed, 1);
  });

  it("does not acknowledge a post-rename readback mismatch", async (t) => {
    const c = await setup(t);
    const store = await openStore(c, { operations: operations({ rename: async (...args) => {
      await fs.rename(...args); await fs.writeFile(c.path, JSON.stringify(fixture({ version: 91 })));
    } }) });
    const old = await store.read();
    await assert.rejects(store.persist(nextOf(old), old), codeIs("policy_file_recovery_required"));
    assert.equal((await store.read()).policy.version, 91);
  });

  it("never reports pre-rename failure as safe when old authority is unreadable", async (t) => {
    const c = await setup(t);
    const store = await openStore(c, { operations: operations({ open: async (...args) => {
      if (args[1] === "wx") { await fs.unlink(c.path); throw syntheticFailure(); }
      return fs.open(...args);
    } }) });
    const old = await store.read();
    await assert.rejects(store.persist(nextOf(old), old), codeIs("policy_file_recovery_required"));
    assert.equal(store.recoveryRequired, true);
  });

  it("refuses concurrent direct writes on one instance", async (t) => {
    const c = await setup(t); const entered = gate(); const release = gate();
    t.after(() => release.resolve());
    const store = await openStore(c, { operations: operations({ rename: async (...args) => {
      entered.resolve(); await release.promise; return fs.rename(...args);
    } }) });
    const old = await store.read(); const pending = store.persist(nextOf(old), old);
    await entered.promise;
    await assert.rejects(store.persist(nextOf(old, { mode: "off" }), old), codeIs("policy_file_busy"));
    release.resolve(); await pending;
    assert.equal((await store.read()).policy.mode, "enforcing");
  });

  it("sanitizes backend errors instead of exposing filenames or payloads", async (t) => {
    const c = await setup(t);
    await assert.rejects(openStore(c, { operations: operations({ open: async () => { throw syntheticFailure(); } }) }), (error) => {
      assert.equal(error.code, "policy_file_read_failed");
      assert.ok(!error.message.includes(c.path)); assert.ok(!error.message.includes("do-not-expose"));
      return true;
    });
  });
});

describe("publisher connected to real policy files", { timeout: 10000, concurrency: false }, () => {
  it("publishes real bytes and reloads them through domain preparation", async (t) => {
    const c = await setup(t); const store = await openStore(c); const publisher = await publisherFor(store);
    const pinned = publisher.capture();
    const out = await publisher.publish(7, bodyOf(fixture({ mode: "permissive" })));
    assert.equal(out.conflict, false); assert.equal(pinned.policy.mode, "enforcing");
    const reopened = await publisherFor(await openStore(c));
    assert.equal(reopened.capture().hash, out.snapshot.hash);
    assert.equal(reopened.capture().policy.mode, "permissive");
  });

  it("same-version concurrent publication produces one durable winner", async (t) => {
    const c = await setup(t); const publisher = await publisherFor(await openStore(c));
    const replies = await Promise.all(Array.from({ length: 6 }, (_, i) => publisher.publish(7, bodyOf(fixture({ label: `body-${i}` })))));
    assert.equal(replies.filter((x) => !x.conflict).length, 1);
    assert.equal(replies.filter((x) => x.conflict && x.version === 8).length, 5);
    assert.equal(JSON.parse(await fs.readFile(c.path, "utf8")).label, "body-0");
  });

  it("keeps the previous snapshot while real file replacement is pending", async (t) => {
    const c = await setup(t); const entered = gate(); const release = gate(); t.after(() => release.resolve());
    const store = await openStore(c, { operations: operations({ rename: async (...args) => {
      entered.resolve(); await release.promise; return fs.rename(...args);
    } }) });
    const publisher = await publisherFor(store); const pinned = publisher.capture();
    const pending = publisher.publish(7, bodyOf(fixture({ mode: "off" })));
    await entered.promise;
    assert.equal(publisher.capture(), pinned); assert.equal(JSON.parse(await fs.readFile(c.path, "utf8")).version, 7);
    release.resolve(); await pending;
    assert.equal(publisher.capture().policy.version, 8);
  });

  it("validation failure changes neither disk nor active snapshot", async (t) => {
    const c = await setup(t); const publisher = await publisherFor(await openStore(c));
    const raw = await fs.readFile(c.path); const pinned = publisher.capture();
    await assert.rejects(publisher.publish(7, bodyOf(fixture({ mode: "invalid" }))), /synthetic_domain_rejection/);
    assert.equal(publisher.capture(), pinned); assert.deepEqual(await fs.readFile(c.path), raw);
  });

  it("known file-write failure permits retry without skipping a revision", async (t) => {
    const c = await setup(t); let fail = true;
    const store = await openStore(c, { operations: operations({ open: async (...args) => {
      if (args[1] === "wx" && fail) throw syntheticFailure(); return fs.open(...args);
    } }) });
    const publisher = await publisherFor(store);
    await assert.rejects(publisher.publish(7, bodyOf(fixture())), codeIs("policy_not_committed"));
    assert.equal(publisher.capture().policy.version, 7); fail = false;
    assert.equal((await publisher.publish(7, bodyOf(fixture()))).snapshot.policy.version, 8);
  });

  it("ambiguous commit fences publisher and disk adapter until reopened", async (t) => {
    const c = await setup(t);
    const store = await openStore(c, { operations: operations({ rename: async (...args) => { await fs.rename(...args); throw syntheticFailure(); } }) });
    const publisher = await publisherFor(store); const pinned = publisher.capture();
    await assert.rejects(publisher.publish(7, bodyOf(fixture({ mode: "off" }))), codeIs("policy_recovery_required"));
    assert.throws(() => publisher.capture(), codeIs("policy_recovery_required"));
    assert.equal(store.recoveryRequired, true); assert.equal(pinned.policy.version, 7);
    const replacement = await publisherFor(await openStore(c));
    assert.equal(replacement.capture().policy.version, 8);
    assert.equal((await replacement.publish(8, bodyOf(fixture()))).snapshot.policy.version, 9);
  });

  it("restores old content as a new on-disk version, not a rewind", async (t) => {
    const c = await setup(t); const store = await openStore(c); const publisher = await publisherFor(store);
    const saved = publisher.capture(); await publisher.publish(7, bodyOf(fixture({ mode: "off" })));
    const restored = await publisher.restore(8, saved);
    assert.equal(restored.snapshot.policy.version, 9); assert.equal(restored.snapshot.policy.mode, "enforcing");
    assert.equal((await store.read()).hash, restored.snapshot.hash);
  });

  for (const stage of ["before-rename", "after-rename"]) {
    it(`controlled child exit ${stage} leaves one parseable authority`, async (t) => {
      const c = await setup(t);
      const fileModule = pathToFileURL(fileURLToPath(new URL("./file-store.ts", import.meta.url))).href;
      const publisherModule = pathToFileURL(fileURLToPath(new URL("./publisher.ts", import.meta.url))).href;
      const source = `
        import * as fs from 'node:fs/promises';
        import { FilePolicyStore } from ${JSON.stringify(fileModule)};
        import { PolicyPublisher } from ${JSON.stringify(publisherModule)};
        const store = await FilePolicyStore.open({path: ${JSON.stringify(c.path)}, durability:'file', operations: {
          open:fs.open, lstat:fs.lstat, unlink:fs.unlink,
          rename:async (...args) => { ${stage === "after-rename" ? "await fs.rename(...args);" : ""} process.exit(73); }
        }});
        const loaded = await store.read();
        const publisher = await PolicyPublisher.open(loaded.policy, {
          prepare: s => { if (s.policy.mode !== 'enforcing') throw Error('fixture'); },
          persist:store.persist, now:()=>200
        });
        const {version,updatedAt,...body}=loaded.policy;
        await publisher.publish(version,body);
        process.exit(74);
      `;
      const result = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", source], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
        let stderr = "";
        const timer = setTimeout(() => { child.kill(); reject(new Error("controlled child timed out")); }, 8000);
        child.stderr.on("data", (s) => { stderr = `${stderr}${s}`.slice(-8192); });
        child.on("error", (error) => { clearTimeout(timer); reject(error); });
        child.on("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal, stderr }); });
      });
      assert.equal(result.code, 73, result.stderr); assert.equal(result.signal, null);
      const reopened = await publisherFor(await openStore(c));
      assert.equal(reopened.capture().policy.version, stage === "before-rename" ? 7 : 8);
      const leftovers = (await names(c.dir)).filter((n) => n.startsWith("policy.json.tmp."));
      assert.equal(leftovers.length, stage === "before-rename" ? 1 : 0);
      // This is early child termination, not an OS/hardware power-loss test.
    });
  }
});
