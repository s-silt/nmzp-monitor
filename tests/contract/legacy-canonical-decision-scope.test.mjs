import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const openapiPath = fileURLToPath(new URL("../../contract/protocol/openapi.yaml", import.meta.url));
const SOURCE_EXTS = [".ts", ".tsx", ".mts", ".mjs", ".cjs"];
const NEEDLES = [
  "toCanonicalDecision",
  "renderCanonicalDecision",
  "canonical-decision.schema.json",
  "canonical-rewrite.schema.json",
];
const ALLOWED = "core/protocol/v2-adapter.ts";
const FORBIDDEN_FILES = new Set(["canonical-decision.schema.json", "canonical-rewrite.schema.json"]);
const FORBIDDEN_COMPONENTS = new Set(["CanonicalDecision", "CanonicalRewrite"]);

function walkSources(dir, hits) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
    const abs = join(dir, ent.name);
    if (ent.isDirectory()) {
      walkSources(abs, hits);
      continue;
    }
    if (!SOURCE_EXTS.some((ext) => ent.name.endsWith(ext))) continue;
    if (ent.name.includes(".test.")) continue;
    const rel = relative(repoRoot, abs).split("\\").join("/");
    if (rel === ALLOWED) continue;
    const text = readFileSync(abs, "utf8");
    for (const needle of NEEDLES) {
      if (text.includes(needle)) hits.push(`${rel}: ${needle}`);
    }
  }
}

test("legacy canonical decision helpers stay inside v2-adapter", () => {
  const hits = [];
  walkSources(join(repoRoot, "core"), hits);
  walkSources(join(repoRoot, "src"), hits);
  assert.deepEqual(hits, []);
});

function decodePointer(token) {
  return token.replaceAll("~1", "/").replaceAll("~0", "~");
}

function pointerGet(doc, pointer) {
  if (pointer === "" || pointer === "#" || pointer === "#/") return doc;
  const raw = pointer.startsWith("#") ? pointer.slice(1) : pointer;
  if (raw === "" || raw === "/") return doc;
  if (!raw.startsWith("/")) return undefined;
  let cur = doc;
  for (const part of raw.split("/").slice(1)) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = cur[decodePointer(part)];
  }
  return cur;
}

function forbiddenRef(ref) {
  const hash = ref.indexOf("#");
  const filePart = hash === -1 ? ref : ref.slice(0, hash);
  const base = filePart.split(/[/\\]/).pop();
  if (base && FORBIDDEN_FILES.has(base)) return true;
  const fragment = hash === -1 ? (ref.startsWith("#") ? ref : "") : ref.slice(hash);
  const marker = "#/components/schemas/";
  if (fragment.startsWith(marker)) {
    const name = decodeURIComponent(fragment.slice(marker.length).split("/")[0]);
    if (FORBIDDEN_COMPONENTS.has(name)) return true;
  }
  return false;
}

test("OpenAPI routes serve CanonicalEvaluateResponseV2 and not legacy decision schemas", () => {
  const openapi = parseYaml(readFileSync(openapiPath, "utf8"));
  const docs = new Map([[openapiPath, openapi]]);
  function docFor(baseFile) {
    if (!docs.has(baseFile)) docs.set(baseFile, JSON.parse(readFileSync(baseFile, "utf8")));
    return docs.get(baseFile);
  }
  function resolveRef(ref, baseFile) {
    if (ref.startsWith("#")) return { node: pointerGet(docFor(baseFile), ref), baseFile };
    const hash = ref.indexOf("#");
    const filePart = hash === -1 ? ref : ref.slice(0, hash);
    const pointer = hash === -1 ? "#" : ref.slice(hash);
    const abs = resolve(dirname(baseFile), filePart);
    return { node: pointerGet(docFor(abs), pointer), baseFile: abs };
  }
  function schemaFile(ref, baseFile) {
    if (ref.startsWith("#/components/schemas/")) {
      const name = decodeURIComponent(ref.slice("#/components/schemas/".length).split("/")[0]);
      const target = openapi.components.schemas[name];
      assert.equal(typeof target?.$ref, "string", name);
      return schemaFile(target.$ref, openapiPath);
    }
    const filePart = ref.split("#")[0];
    assert.ok(filePart, ref);
    return resolve(dirname(baseFile), filePart);
  }

  const operation = openapi.paths["/api/v2/evaluate"].post;
  const response = operation.responses["200"] ?? operation.responses[200];
  const responseRef = response.content["application/json"].schema.$ref;
  const componentRef = openapi.components.schemas.CanonicalEvaluateResponseV2.$ref;
  const responseFile = schemaFile(responseRef, openapiPath);
  assert.equal(responseFile, schemaFile(componentRef, openapiPath));
  assert.equal(JSON.parse(readFileSync(responseFile, "utf8")).title, "CanonicalEvaluateResponseV2");

  const seen = new Set();
  const hits = [];
  function walk(node, baseFile, trail) {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) walk(node[i], baseFile, `${trail}[${i}]`);
      return;
    }
    if (typeof node.$ref === "string") {
      const ref = node.$ref;
      const mark = `${baseFile}\n${ref}`;
      if (forbiddenRef(ref)) hits.push(`${trail} -> ${ref}`);
      else if (!seen.has(mark)) {
        seen.add(mark);
        if (!/^https?:\/\//.test(ref)) {
          const resolved = resolveRef(ref, baseFile);
          if (resolved.node === undefined) hits.push(`unresolved ${trail} -> ${ref}`);
          else walk(resolved.node, resolved.baseFile, `${trail} -> ${ref}`);
        }
      }
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === "$ref") continue;
      walk(value, baseFile, `${trail}/${key}`);
    }
  }
  walk(openapi.paths, openapiPath, "#/paths");
  assert.deepEqual(hits, []);
  assert.ok(
    [...seen].some((mark) => mark.includes("canonical-evaluate-response-v2.schema.json")),
    "evaluate response schema was not followed",
  );
  assert.equal(
    [...seen].some(
      (mark) => mark.includes("canonical-decision.schema.json") || mark.includes("canonical-rewrite.schema.json"),
    ),
    false,
  );
});
