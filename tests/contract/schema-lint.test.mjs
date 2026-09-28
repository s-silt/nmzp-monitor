import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  CROSS_PATH,
  FIXTURE_SCHEMA,
  closedObjectCensus,
  compileAll,
  createAjv,
  customHalfOpenOk,
  evaluateCrossCase,
  kindForNativeName,
  kindTableMatchesFile,
  loadJson,
  loadSchemas,
  openApiRefs,
} from "./protocol-checks.mjs";

describe("protocol schema lint", () => {
  const schemas = loadSchemas();
  const ajv = createAjv(schemas);
  const validators = compileAll(ajv, schemas);
  const manifest = loadJson(join(FIXTURE_SCHEMA, "manifest.json"));

  test("ajv 2020 strict compiles every schema", () => {
    assert.equal(Object.keys(validators).length, Object.keys(schemas).length);
    for (const name of Object.keys(schemas)) {
      assert.equal(typeof validators[name], "function", name);
    }
  });

  test("schema objects are closed except the D9 marker", () => {
    const census = closedObjectCensus(schemas);
    assert.deepEqual(census, { closed: 25, map: 0, d9: 1 });
  });

  test("native-kind-map matches the adapter table", () => {
    const match = kindTableMatchesFile();
    assert.equal(match.ok, true, JSON.stringify(match));
  });

  test("manifest valid fixtures pass schema and custom checks", () => {
    for (const row of manifest.valid) {
      const instance = loadJson(join(FIXTURE_SCHEMA, row.file));
      const ok = validators[row.schema](instance);
      assert.equal(ok, true, `${row.file}: ${JSON.stringify(validators[row.schema].errors)}`);
      assert.equal(customHalfOpenOk(instance, row.schema), true, `${row.file} halfOpen`);
      if (row.schema === "canonical-tool-event.schema.json") {
        assert.equal(kindForNativeName(instance.tool.nativeName), instance.tool.kind, `${row.file} kind`);
      }
    }
  });

  test("manifest invalid fixtures are rejected by schema or custom checks", () => {
    for (const row of manifest.invalid) {
      const instance = loadJson(join(FIXTURE_SCHEMA, row.file));
      const schemaOk = validators[row.schema](instance);
      const customOk = customHalfOpenOk(instance, row.schema);
      assert.equal(schemaOk && customOk, false, `${row.file} was accepted`);
    }
  });

  test("manifest lists every schema fixture file", () => {
    const listed = new Set([...manifest.valid, ...manifest.invalid].map((row) => row.file.replace(/\\/g, "/")));
    const disk = [];
    for (const bucket of ["valid", "invalid"]) {
      for (const name of readdirSync(join(FIXTURE_SCHEMA, bucket))) {
        if (name.endsWith(".json")) disk.push(`${bucket}/${name}`);
      }
    }
    assert.deepEqual([...listed].sort(), disk.sort());
  });

  test("cross-field accept/reject cases match the candidate checker", () => {
    const doc = loadJson(CROSS_PATH);
    const mismatches = [];
    for (const caseRow of doc.cases) {
      let result;
      try {
        result = evaluateCrossCase(caseRow, validators);
      } catch (err) {
        mismatches.push({ id: caseRow.id, error: String(err) });
        continue;
      }
      if (!result.ok) mismatches.push({ id: caseRow.id, kind: caseRow.kind, got: result.got });
    }
    assert.deepEqual(mismatches, []);
  });

  test("openapi.yaml $ref targets resolve locally", () => {
    const { refs, missing } = openApiRefs();
    assert.ok(refs.length > 0, "no $ref found");
    assert.deepEqual(missing, []);
  });
});
