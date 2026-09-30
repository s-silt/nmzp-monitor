// source-contract: parse skip expressions and evaluate them in a tiny VM.
// This file does not import test modules and does not execute ACL bodies.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { describe, it } from "node:test";
import vm from "node:vm";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "acorn";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PARSE = { ecmaVersion: "latest", sourceType: "module" };
const SAFE = new Set([
  "Identifier",
  "Literal",
  "MemberExpression",
  "BinaryExpression",
  "LogicalExpression",
  "ConditionalExpression",
  "UnaryExpression",
  "ChainExpression",
  "ParenthesizedExpression",
]);
const ACL_CALLEE = new Set([
  "joinDevice",
  "runJoin",
  "snapshotGuardApply",
  "snapshotGuardRestore",
  "forceResetTempAcl",
  "cleanupFixture",
  "restrictPath",
  "icacls",
]);
const REVIEWED = [
  "core/network-collect.test.ts",
  "core/install-hooks.test.ts",
  "core/snapshot-guard.test.ts",
  "core/install.test.ts",
  "core/host-files-carry.test.ts",
  "core/codex-hooks.test.ts",
  "core/antigravity-hooks.test.ts",
  "core/host-adapters.test.ts",
  "core/zcode-hooks.test.ts",
];
const CORRUPT_JOIN = "refuses to join over corrupt Claude settings and leaves the original file";
const NTFS_SUITE = "snapshot-guard real NTFS ACL";
const EXPECTED_ACL = [
  ["core/antigravity-hooks.test.ts", "Antigravity hook state and join/leave: only when ~/.gemini exists; created file is removed on leave (Windows real NTFS ACL requires NMZP_TEST_REAL_ACL=1)"],
  ["core/codex-hooks.test.ts", "Codex install and leave only affect owned hook in isolated HOME, rollback retains existing config"],
  ["core/host-adapters.test.ts", "join writes only hosts whose gate exists; leave strips and removes files it created"],
  ["core/host-files-carry.test.ts", "Antigravity: gate dir removed after join → path carried in manifest → leave removes the file we created"],
  ["core/host-files-carry.test.ts", "hostFiles: entries whose file still exists are carried, entries whose file is gone are dropped"],
  ["core/install.test.ts", "access-denied scheduled task falls back to user_startup and does not set taskOk"],
  ["core/install.test.ts", "does not claim protection just because .zcode exists without checkpoints"],
  ["core/install.test.ts", "does not force-overwrite a foreign scheduled task; falls back to user_startup"],
  ["core/install.test.ts", "does not overwrite a foreign same-name Startup launcher"],
  ["core/install.test.ts", "does not overwrite a running same-version runtime"],
  ["core/install.test.ts", "does not overwrite an existing Grok hook file and keeps later user edits on leave"],
  ["core/install.test.ts", "join copies versioned runtime, protects creds, starts hidden probe; leave keeps user edits"],
  ["core/install.test.ts", "join default collector on temp home is read-only and not active"],
  ["core/install.test.ts", "join is idempotent and does not consume a second ticket"],
  ["core/install.test.ts", "join records status and never applies or restores"],
  ["core/install.test.ts", "leave only removes unmodified own startup launcher and does not touch other Startup items"],
  ["core/install.test.ts", "restricts credentials and backups with current-user/SYSTEM ACL on Windows"],
  ["core/install.test.ts", "throws when both scheduled task and user startup fail"],
  ["core/snapshot-guard.test.ts", "blocks independent packer process and loopback upload after lock; control group delivers once"],
  ["core/snapshot-guard.test.ts", "blocks new archives in nested pending and a second subtree, not only the root"],
  ["core/snapshot-guard.test.ts", "blocks reading an existing pending archive for upload after lock without deleting it"],
  ["core/snapshot-guard.test.ts", "CLI status on temp home prints short JSON and does not list archive paths"],
  ["core/snapshot-guard.test.ts", "does not follow a junction to change ACL elsewhere"],
  ["core/snapshot-guard.test.ts", "does not modify ACL when object identity changes before pending recovery"],
  ["core/snapshot-guard.test.ts", "does not revoke a pre-opened handle; documents stop-old-client boundary"],
  ["core/snapshot-guard.test.ts", "does not unlock from a pending journal that lacks expected SDDL"],
  ["core/snapshot-guard.test.ts", "keeps an external ACE after pending recovery and does not force-overwrite"],
  ["core/snapshot-guard.test.ts", "reapply failure rolls back only needAdd and keeps other guarded ACLs"],
  ["core/snapshot-guard.test.ts", "refuses apply when .nmzp is a junction and does not change the junction target"],
  ["core/snapshot-guard.test.ts", "refuses apply when ZCode running cannot be excluded"],
  ["core/snapshot-guard.test.ts", "refuses to overwrite a corrupt manifest and does not adopt it"],
  ["core/snapshot-guard.test.ts", "restore conflicts and keeps an extra external ACE added after apply"],
  ["core/snapshot-guard.test.ts", "restore reports conflict and keeps user ACL when identity/ACL changed after apply"],
  ["core/snapshot-guard.test.ts", "rolls back earlier ACL mutations when a later target fails"],
  ["core/snapshot-guard.test.ts", "treats unmanaged existing deny as external lock: write blocked, coverage unknown, not restored"],
  ["core/snapshot-guard.test.ts", "unprotected temp dir is writable; apply blocks new packs; restore returns write"],
  ["core/zcode-hooks.test.ts", "join writes the ZCode hook only when ~/.zcode/cli exists, keeps plugins/mcp, and leave strips only the owned entry"],
];
const PURE = [
  ["core/install.test.ts", "merges Claude hooks without wiping user entries"],
  ["core/install.test.ts", "rejects corrupt Claude JSON instead of wiping it"],
  ["core/install.test.ts", "hidden launcher body only starts NMZP probe"],
  ["core/install.test.ts", "copyRuntime places a complete ui tree on the runtime for board"],
  ["core/install.test.ts", "standalone apply skips external, degrades missing target, never restores"],
  ["core/snapshot-guard.test.ts", "reports target_missing without creating the real or temp checkpoints"],
  ["core/snapshot-guard.test.ts", "EncodedCommand carries no JSON path payload in argv"],
  ["core/snapshot-guard.test.ts", "pins production target to home/.zcode/v2/checkpoints and rejects other layouts"],
  ["core/host-adapters.test.ts", "probe reports hook_<host> for every extra host: not installed → offline → active on receipt"],
];

function read(rel) {
  return readFileSync(join(root, rel), "utf8");
}

function children(node) {
  const out = [];
  for (const key of Object.keys(node)) {
    if (key === "type" || key === "start" || key === "end") continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) if (item && typeof item.type === "string") out.push(item);
    } else if (value && typeof value.type === "string") out.push(value);
  }
  return out;
}

function assertSafe(node) {
  if (!SAFE.has(node.type)) throw new Error(`unsafe skip syntax ${node.type}`);
  for (const child of children(node)) assertSafe(child);
}

function collectIds(node, out) {
  if (!node || typeof node.type !== "string") return;
  if (node.type === "Identifier") {
    out.add(node.name);
    return;
  }
  if (node.type === "MemberExpression") {
    collectIds(node.object, out);
    if (node.computed) collectIds(node.property, out);
    return;
  }
  for (const child of children(node)) collectIds(child, out);
}

function bindingsOf(ast, js) {
  const map = new Map();
  for (const stmt of ast.body) {
    if (stmt.type !== "VariableDeclaration") continue;
    for (const decl of stmt.declarations) {
      if (decl.id.type === "Identifier" && decl.init) {
        map.set(decl.id.name, {
          name: decl.id.name,
          start: decl.start,
          src: js.slice(decl.init.start, decl.init.end),
          init: decl.init,
        });
      }
    }
  }
  return map;
}

function callbackOf(node) {
  for (let i = node.arguments.length - 1; i >= 0; i--) {
    const arg = node.arguments[i];
    if (arg.type === "ArrowFunctionExpression" || arg.type === "FunctionExpression") return arg;
  }
  return null;
}

function skipOf(node, js) {
  const opt = node.arguments[1];
  if (!opt || opt.type !== "ObjectExpression") return null;
  for (const prop of opt.properties) {
    if (prop.type !== "Property" || prop.computed) continue;
    const key = prop.key.type === "Identifier" ? prop.key.name : prop.key.value;
    if (key === "skip") return { node: prop.value, src: js.slice(prop.value.start, prop.value.end) };
  }
  return null;
}

function titleOf(node) {
  const arg = node.arguments[0];
  return arg && arg.type === "Literal" && typeof arg.value === "string" ? arg.value : null;
}

function collectCalls(ast, js) {
  const calls = [];
  function walk(node, stack) {
    if (!node || typeof node.type !== "string") return;
    if (node.type === "CallExpression") {
      const name = node.callee.type === "Identifier" ? node.callee.name : "";
      if (name === "it" || name === "describe") {
        const fn = callbackOf(node);
        const call = {
          kind: name,
          title: titleOf(node),
          skip: skipOf(node, js),
          ancestors: stack,
          fn,
        };
        calls.push(call);
        if (fn) walk(fn.body, name === "describe" ? stack.concat(call) : stack);
        for (const arg of node.arguments) if (arg !== fn) walk(arg, stack);
        return;
      }
    }
    for (const child of children(node)) walk(child, stack);
  }
  walk(ast, []);
  return calls;
}

function bodyHasAcl(node) {
  let hit = false;
  function walk(current) {
    if (!current || hit || typeof current.type !== "string") return;
    if (current.type === "CallExpression") {
      const name = current.callee.type === "Identifier" ? current.callee.name : "";
      if (ACL_CALLEE.has(name)) hit = true;
    }
    if (current.type === "Literal" && typeof current.value === "string") {
      if (current.value === "icacls" || current.value.includes("snapshot-guard-cli")) hit = true;
    }
    for (const child of children(current)) walk(child);
  }
  walk(node);
  return hit;
}

function platformReturn(node, js) {
  if (node.type !== "IfStatement") return null;
  const block = node.consequent.type === "BlockStatement" ? node.consequent.body : [node.consequent];
  if (block.length !== 1 || block[0].type !== "ReturnStatement" || block[0].argument) return null;
  const test = node.test;
  const bareWin = (test.type === "Identifier" && test.name === "win")
    || (test.type === "UnaryExpression" && test.operator === "!" && test.argument.type === "Identifier" && test.argument.name === "win");
  let compared = false;
  if (test.type === "BinaryExpression" && (test.operator === "===" || test.operator === "!==")) {
    const sides = [test.left, test.right];
    const platform = sides.some((side) => side.type === "MemberExpression" && !side.computed && side.object.type === "Identifier" && side.object.name === "process" && side.property.type === "Identifier" && side.property.name === "platform");
    const win32 = sides.some((side) => side.type === "Literal" && side.value === "win32");
    compared = platform && win32;
  }
  if (!bareWin && !compared) return null;
  return js.slice(node.start, node.end).replace(/\s+/g, " ");
}

function earlyReturns(ast, js) {
  const hits = [];
  function walk(node) {
    if (!node || typeof node.type !== "string") return;
    const text = platformReturn(node, js);
    if (text) hits.push(text);
    for (const child of children(node)) walk(child);
  }
  walk(ast);
  return hits;
}

function effective(call) {
  if (call.skip) return call.skip;
  for (let i = call.ancestors.length - 1; i >= 0; i--) if (call.ancestors[i].skip) return call.ancestors[i].skip;
  return null;
}

function inNtfsSuite(call) {
  return call.title === NTFS_SUITE || call.ancestors.some((parent) => parent.title === NTFS_SUITE);
}

function evalSkip(skip, bindings, platform, env) {
  assertSafe(skip.node);
  const selected = [];
  const seen = new Set();
  const queue = [];
  const ids = new Set();
  collectIds(skip.node, ids);
  for (const id of ids) if (bindings.has(id)) queue.push(id);
  while (queue.length) {
    const id = queue.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const binding = bindings.get(id);
    assertSafe(binding.init);
    selected.push(binding);
    const inner = new Set();
    collectIds(binding.init, inner);
    for (const name of inner) if (bindings.has(name) && !seen.has(name)) queue.push(name);
  }
  selected.sort((a, b) => a.start - b.start);
  const code = `${selected.map((binding) => `const ${binding.name} = (${binding.src});`).join("\n")}\n(${skip.src});`;
  // Watchdog for a whitelisted skip expression, not a latency budget.
  return vm.runInNewContext(code, vm.createContext({ process: { platform, env } }), { timeout: 1_000 });
}

function kindOf(value) {
  if (value === false) return "run";
  if (typeof value === "string" && value.length > 0) return "skip";
  return "invalid";
}

function load(rel) {
  const js = stripTypeScriptTypes(read(rel));
  const ast = parse(js, PARSE);
  return { js, ast, calls: collectCalls(ast, js), bindings: bindingsOf(ast, js) };
}

const docs = new Map(REVIEWED.map((rel) => [rel, load(rel)]));

function findCall(rel, title, kind = "it") {
  const call = docs.get(rel).calls.find((item) => item.kind === kind && item.title === title);
  assert.ok(call, `parser missed ${kind} ${rel} :: ${title}`);
  return call;
}

function aclTests() {
  const found = [];
  for (const rel of REVIEWED) {
    const doc = docs.get(rel);
    for (const call of doc.calls) {
      if (call.kind !== "it" || !call.fn || !bodyHasAcl(call.fn.body)) continue;
      found.push({ rel, title: call.title, call, doc });
    }
  }
  return found;
}

function gate(call, doc, platform, env) {
  const skip = effective(call);
  assert.ok(skip, `${call.title} has no skip expression`);
  return kindOf(evalSkip(skip, doc.bindings, platform, env));
}

describe("source-contract: L-37 test gates", () => {
  it("source-contract: unavailable platforms do not early-return as a pass", () => {
    const hits = [];
    for (const rel of REVIEWED) {
      for (const text of earlyReturns(docs.get(rel).ast, docs.get(rel).js)) hits.push(`${rel}: ${text}`);
    }
    assert.deepEqual(hits, []);
  });

  it("source-contract: Windows-only cases run on Windows and skip elsewhere", () => {
    const cases = [
      ["core/network-collect.test.ts", "observes real loopback sockets for a pid whose CIM identity is injected as .grok/bin/grok.exe", "real loopback TCP observation requires Windows"],
      ["core/install-hooks.test.ts", "allow empty stdout and deny exit 2 with spaced runtime path", "real powershell.exe hook command requires Windows"],
    ];
    for (const [rel, title, reason] of cases) {
      const doc = docs.get(rel);
      const call = findCall(rel, title);
      const skip = effective(call);
      assert.equal(evalSkip(skip, doc.bindings, "win32", {}), false);
      assert.equal(evalSkip(skip, doc.bindings, "linux", {}), reason);
      assert.equal(bodyHasAcl(call.fn.body), false);
    }
  });

  it("source-contract: non-Windows snapshot-guard status skips on Windows with a reason", () => {
    const doc = docs.get("core/snapshot-guard.test.ts");
    const call = findCall("core/snapshot-guard.test.ts", "status on unsupported platform does not claim protection");
    const skip = effective(call);
    assert.equal(evalSkip(skip, doc.bindings, "win32", {}), "unsupported-platform snapshot-guard status runs only off Windows");
    assert.equal(evalSkip(skip, doc.bindings, "linux", {}), false);
  });

  it("source-contract: target_missing status keeps running on Windows and explains other platforms", () => {
    const doc = docs.get("core/snapshot-guard.test.ts");
    const call = findCall("core/snapshot-guard.test.ts", "snapshot-guard missing target and temp status", "describe");
    const skip = effective(call);
    assert.equal(evalSkip(skip, doc.bindings, "linux", {}), "snapshot-guard target_missing status requires Windows");
    assert.equal(evalSkip(skip, doc.bindings, "win32", {}), false);
    assert.equal(evalSkip(skip, doc.bindings, "win32", { NMZP_TEST_REAL_ACL: "1" }), false);
    const inner = findCall("core/snapshot-guard.test.ts", "reports target_missing without creating the real or temp checkpoints");
    assert.equal(bodyHasAcl(inner.fn.body), false);
  });

  it("source-contract: real ACL cases follow the env comparison, not the reason string", () => {
    const found = aclTests().filter((item) => item.title !== CORRUPT_JOIN);
    const cmp = (a, b) => (a[0] + a[1]).localeCompare(b[0] + b[1]);
    assert.deepEqual(found.map((item) => [item.rel, item.title]).sort(cmp), [...EXPECTED_ACL].sort(cmp));
    const failures = [];
    for (const item of found) {
      const win = gate(item.call, item.doc, "win32", {});
      const zero = gate(item.call, item.doc, "win32", { NMZP_TEST_REAL_ACL: "0" });
      const opted = gate(item.call, item.doc, "win32", { NMZP_TEST_REAL_ACL: "1" });
      const linux = gate(item.call, item.doc, "linux", {});
      const linuxExpected = inNtfsSuite(item.call) ? "skip" : "run";
      if (win !== "skip" || zero !== "skip" || opted !== "run" || linux !== linuxExpected) {
        failures.push(`${item.rel} :: ${item.title} win=${win} zero=${zero} opted=${opted} linux=${linux} expectedLinux=${linuxExpected}`);
      }
      const absent = evalSkip(effective(item.call), item.doc.bindings, "win32", {});
      if (typeof absent !== "string" || !absent.includes("NMZP_TEST_REAL_ACL=1")) {
        failures.push(`${item.rel} :: ${item.title} missing opt-in reason`);
      }
    }
    assert.deepEqual(failures, []);
  });

  it("source-contract: reason text without the env comparison stays skipped when opt-in is set", () => {
    const code = 'const realNtfsAclSkip = process.platform === "win32" ? "real NTFS ACL requires NMZP_TEST_REAL_ACL=1" : false;';
    const ast = parse(code, { ecmaVersion: "latest", sourceType: "script" });
    const decl = ast.body[0].declarations[0];
    const bindings = new Map([[decl.id.name, { name: decl.id.name, start: decl.start, src: code.slice(decl.init.start, decl.init.end), init: decl.init }]]);
    const skip = { node: decl.id, src: decl.id.name };
    assert.equal(kindOf(evalSkip(skip, bindings, "win32", { NMZP_TEST_REAL_ACL: "1" })), "skip");
    assert.equal(kindOf(evalSkip(skip, bindings, "linux", {})), "run");
  });

  it("source-contract: corrupt Claude rejection is exempt only while it cannot reach restrictPath", () => {
    const install = read("core/install.ts");
    const corruptAt = install.indexOf('"claude_settings_corrupt"');
    const restrictAt = install.indexOf("restrictPath(nmzp)");
    assert.ok(corruptAt !== -1 && restrictAt !== -1 && corruptAt < restrictAt);
    const call = findCall("core/install.test.ts", CORRUPT_JOIN);
    assert.equal(bodyHasAcl(call.fn.body), true);
    assert.equal(effective(call), null);
  });

  it("source-contract: Windows TAP skip check runs on win32 and skips on linux and darwin", () => {
    const reason = "Windows TAP skip check runs only on Windows";
    const doc = load("scripts/test-gates.test.mjs");
    const call = doc.calls.find((item) => item.kind === "it" && item.title === "unsupported-platform snapshot-guard case reports SKIP on Windows");
    assert.ok(call, "parser missed the Windows TAP skip check");
    const skip = effective(call);
    assert.ok(skip, "Windows TAP check needs an explicit non-Windows skip");
    assert.equal(bodyHasAcl(call.fn.body), false);
    assert.equal(evalSkip(skip, doc.bindings, "win32", {}), false);
    assert.equal(evalSkip(skip, doc.bindings, "linux", {}), reason);
    assert.equal(evalSkip(skip, doc.bindings, "darwin", {}), reason);
  });

  it("source-contract: pure cases are not classified as real ACL", () => {
    const found = aclTests();
    for (const [rel, title] of PURE) {
      findCall(rel, title);
      assert.equal(found.some((item) => item.rel === rel && item.title === title), false, title);
    }
  });

  it("source-contract: verify-package wrapper launches only the reviewed script", () => {
    const src = read("core/native-probe-service/verify-package.test.mjs");
    assert.match(src, /verify-package\.test\.ps1/);
    assert.match(src, /-NoProfile/);
    assert.match(src, /-NonInteractive/);
    assert.match(src, /-File/);
    assert.match(src, /spawnImpl/);
    assert.match(src, /requires Windows PowerShell/);
    assert.match(src, /propagates injected spawn failures/);
    assert.match(src, /propagates injected non-zero exit/);
    assert.match(src, /propagates injected child error events/);
    assert.match(src, /terminates an injected child that never closes/);
    assert.match(src, /refusing to launch any script other than verify-package\.test\.ps1/);
    assert.match(src, /process\.platform === ["']win32["'] \? false : ["']requires Windows PowerShell["']/);
    assert.match(src, /const env = \{ \.\.\.\(options\.env \?\? process\.env\) \};/);
    assert.match(src, /for \(const key of Object\.keys\(env\)\) \{\s*if \(key\.toLowerCase\(\) === ["']psmodulepath["']\) delete env\[key\];\s*\}/);
    assert.match(src, /omits every PSModulePath casing only from the child environment copy/);
    assert.match(src, /child\.kill\(\)/);
    assert.match(src, /timed out after/);
    assert.doesNotMatch(src, /ExecutionPolicy|Bypass|-Command|manage\.ps1|ProbeService|icacls|Set-Acl|restrictPath|NMZP_TEST_REAL_ACL|taskkill|\/IM\b|Stop-Process/);
    assert.doesNotMatch(src, /delete process\.env(?:\.|\[)/);
  });
});

describe("platform skip reported by the runner", () => {
  it("unsupported-platform snapshot-guard case reports SKIP on Windows", {
    timeout: 30_000,
    skip: process.platform === "win32" ? false : "Windows TAP skip check runs only on Windows",
  }, () => {
    const env = { ...process.env };
    delete env.NMZP_TEST_REAL_ACL;
    delete env.NODE_TEST_CONTEXT;
    delete env.NODE_CHANNEL_FD;
    for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
    const child = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--test",
        "--test-reporter",
        "tap",
        "--test-name-pattern",
        "^status on unsupported platform does not claim protection$",
        "core/snapshot-guard.test.ts",
      ],
      { cwd: root, encoding: "utf8", env, timeout: 20_000 },
    );
    const out = `${child.stdout ?? ""}\n${child.stderr ?? ""}`;
    assert.equal(child.error, undefined, `nested runner did not exit normally (${child.error?.code ?? "no-status"}). Standalone TAP requires NODE_TEST_CONTEXT to be unset.\n${out}`);
    assert.equal(child.status, 0, out);
    assert.match(out, /^TAP version 13/m, "nested runner must emit standalone TAP; inherited NODE_TEST_CONTEXT suppresses the file");
    assert.match(out, /# SKIP unsupported-platform snapshot-guard status runs only off Windows/);
    assert.match(out, /^# skipped [1-9]/m);
    assert.doesNotMatch(out, /snapshot-guard real NTFS ACL/);
    assert.doesNotMatch(out, /^# fail [1-9]/m);
  });
});
