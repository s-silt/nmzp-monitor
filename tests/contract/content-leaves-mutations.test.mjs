import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const suite = "tests/contract/content-leaves.test.mjs";
const aliases = "core/hook-alias-keys.ts";
const adapter = "core/protocol/v2-adapter.ts";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const mutations = [
  { name: "inherit host remap prototype keys", file: adapter, from: 'hostArgMap && Object.prototype.hasOwnProperty.call(hostArgMap, first) ? hostArgMap[first] : first', to: 'hostArgMap?.[first] ?? first', test: "content Antigravity prototype-looking" },
  { name: "trim before storage", file: aliases, from: 'leaves.push({ value, tokens });', to: 'leaves.push({ value: value.trim(), tokens });', test: "content exactness:" },
  { name: "drop blank before storage", file: aliases, from: 'if (typeof value === "string") leaves.push', to: 'if (typeof value === "string" && value.trim()) leaves.push', test: "content exactness:" },
  { name: "deduplicate before storage", file: aliases, from: 'leaves.push({ value: item.value, tokens: item.tokens });', to: 'if (!leaves.some((leaf) => leaf.value === item.value)) leaves.push({ value: item.value, tokens: item.tokens });', test: "content exactness:" },
  { name: "reverse top key order", file: aliases, from: 'for (const key of CONTENT_KEYS) push(obj[key], [key]);', to: 'for (const key of [...CONTENT_KEYS].reverse()) push(obj[key], [key]);', test: "content order:" },
  { name: "drop recursive scan", file: aliases, from: 'walkScanLeaves(v, [k], leaves, seen);', to: 'void v;', test: "content order:" },
  { name: "recursively scan edits extras", file: aliases, from: 'if (k === "edits") continue;', to: 'if (false) continue;', test: "content exclusions:" },
  { name: "filter canonical bag metadata", file: aliases, from: 'if (OP_KEYS.has(k)) continue;', to: 'if (OP_KEYS.has(k) || k === "session_id") continue;', test: "content metadata:" },
  { name: "drop host remap", file: adapter, from: 'hostArgMap && Object.prototype.hasOwnProperty.call(hostArgMap, first) ? hostArgMap[first] : first', to: 'first', test: "content Antigravity:" },
  { name: "skip slash escaping", file: adapter, from: 'return token.replaceAll("~", "~0").replaceAll("/", "~1");', to: 'return token.replaceAll("~", "~0");', test: "content pointers:" },
  { name: "forget mapped leaves", file: adapter, from: '    mapped.add(provenance);\n    return { value: leaf.value, provenance };', to: '    return { value: leaf.value, provenance };', test: "content exactness:" },
  { name: "bridge retains duplicates", file: aliases, from: 'if (value && !parts.includes(value)) parts.push(value);', to: 'if (value) parts.push(value);', test: "content exactness:" },
  { name: "bridge skips trim", file: aliases, from: 'const value = aliasStr(leaf.value);', to: 'const value = leaf.value;', test: "content exactness:" },
  { name: "bridge skips join", file: aliases, from: 'return parts.length ? parts.join("\\n") : undefined;', to: 'return parts[0];', test: "content exactness:" },
  { name: "omit strict leaf pointer limit", file: adapter, from: '? (field as CanonicalContents).leaves.map((leaf) => leaf.provenance)', to: '? []', test: "content strict pointers:" },
];
/** Match exactly one reviewed anchor, accepting its LF or CRLF spelling without normalizing the file. */
function replaceUniqueMutation(source, mutation) {
  const text = source.toString("utf8");
  assert.ok(Buffer.from(text, "utf8").equals(source), `${mutation.name}: source must round-trip UTF-8`);
  const anchors = [...new Set([mutation.from, mutation.from.replaceAll("\n", "\r\n")])];
  const matches = anchors.reduce((count, anchor) => count + text.split(anchor).length - 1, 0);
  assert.equal(matches, 1, `${mutation.name}: unique anchor`);
  const anchor = anchors.find((candidate) => text.includes(candidate));
  const replacement = mutation.to.replaceAll("\n", anchor.includes("\r\n") ? "\r\n" : "\n");
  return Buffer.from(text.replace(anchor, replacement), "utf8");
}

function withEol(source, eol) {
  // Only explicit isolated regression fixtures are converted; checkout sources are never normalized.
  return Buffer.from(source.toString("utf8").replaceAll("\r\n", "\n").replaceAll("\n", eol), "utf8");
}

test("mutation anchor portability: LF/CRLF fixtures retain exact restored bytes and uniqueness", async () => {
  const mutation = mutations.find((item) => item.name === "forget mapped leaves");
  const source = await readFile(join(root, adapter));
  const tmp = await mkdtemp(join(tmpdir(), "nmzp-mutation-eol-"));
  const target = join(tmp, "adapter.ts");
  try {
    for (const eol of ["\n", "\r\n"]) {
      const fixture = withEol(source, eol);
      // Deterministically reproduce the original CI bug on the actual reviewed source.
      assert.equal(fixture.toString("utf8").split(mutation.from).length, eol === "\n" ? 2 : 1);
      const anchor = mutation.from.replaceAll("\n", eol);
      const expected = Buffer.from(fixture.toString("utf8").replace(anchor, mutation.to), "utf8");
      await writeFile(target, fixture);
      try {
        await writeFile(target, replaceUniqueMutation(fixture, mutation));
        assert.deepEqual(await readFile(target), expected);
      } finally {
        await writeFile(target, fixture);
        assert.deepEqual(await readFile(target), fixture);
        assert.equal(hash(await readFile(target)), hash(fixture));
      }
    }
    assert.throws(() => replaceUniqueMutation(Buffer.from("missing"), mutation), /unique anchor/);
    const duplicate = Buffer.concat([withEol(source, "\n"), withEol(source, "\r\n")]);
    assert.throws(() => replaceUniqueMutation(duplicate, mutation), /unique anchor/);
    assert.deepEqual(await readFile(join(root, adapter)), source);
  } finally { await rm(tmp, { recursive: true, force: true }); }
});

function run(cwd) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--experimental-strip-types", suite], {
    cwd, env, encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
}

test("content leaves: real suite kills isolated source mutants and restores hashes", { timeout: 180000 }, async (t) => {
  const tmp = await mkdtemp(join(tmpdir(), "nmzp-content-mutants-"));
  const originals = new Map();
  try {
    for (const dir of ["core", "contract"]) await cp(join(root, dir), join(tmp, dir), { recursive: true });
    await mkdir(join(tmp, "src", "lib"), { recursive: true });
    await cp(join(root, "src", "lib", "monitor"), join(tmp, "src", "lib", "monitor"), { recursive: true });
    await cp(join(root, "package.json"), join(tmp, "package.json"));
    await mkdir(join(tmp, "node_modules"), { recursive: true });
    // Copy only already-installed parser/validator dependencies; never install or access the network.
    for (const pkg of ["acorn", "ajv", "fast-deep-equal", "fast-uri", "json-schema-traverse", "require-from-string"]) {
      await cp(join(root, "node_modules", pkg), join(tmp, "node_modules", pkg), { recursive: true });
    }
    await mkdir(join(tmp, "tests", "contract"), { recursive: true });
    for (const file of [suite, "tests/contract/protocol-checks.mjs"]) await cp(join(root, file), join(tmp, file));
    for (const file of [aliases, adapter]) originals.set(file, await readFile(join(root, file)));
    const baseline = run(tmp);
    assert.equal(baseline.status, 0, baseline.output);
    assert.match(baseline.output, /# pass 17\b/);
    for (const mutation of mutations) {
      const original = originals.get(mutation.file);
      const target = join(tmp, mutation.file);
      // Exercise the failing multiline mutation with BOTH EOLs through the real assertions on every OS.
      const fixtures = mutation.name === "forget mapped leaves"
        ? [{ label: "LF", source: withEol(original, "\n") }, { label: "CRLF", source: withEol(original, "\r\n") }]
        : [{ label: "checkout", source: original }];
      try {
        for (const { label, source } of fixtures) {
          try {
            await writeFile(target, replaceUniqueMutation(source, mutation));
            const red = run(tmp);
            assert.notEqual(red.status, 0, `${mutation.name}: survived`);
            assert.ok(red.output.split("\n").some((line) => /^not ok \d+ - /.test(line) && line.includes(mutation.test)), `${mutation.name}: intended test did not fail\n${red.output}`);
            assert.match(red.output, /ERR_ASSERTION/);
            assert.doesNotMatch(red.output, /SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNKNOWN_FILE_EXTENSION/);
          } finally {
            await writeFile(target, source);
            assert.deepEqual(await readFile(target), source);
            assert.equal(hash(await readFile(target)), hash(source));
          }
          const green = run(tmp);
          assert.equal(green.status, 0, green.output);
          assert.match(green.output, /# pass 17\b/);
          t.diagnostic(`${mutation.name} (${label}): assertion red, restored bytes/hash and 17/17 green`);
        }
      } finally {
        await writeFile(target, original);
        assert.deepEqual(await readFile(target), original);
      }
    }
    for (const [file, source] of originals) assert.equal(hash(await readFile(join(root, file))), hash(source));
  } finally { await rm(tmp, { recursive: true, force: true }); }
});
