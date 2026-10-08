// Validate HOST_REAL scenarios and unsigned or signed artifacts. No host process is started.
import Ajv2020 from "ajv/dist/2020.js";
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex, versionRangeMatches } from "./host-real-record.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(scriptDir, "..");
const schemaDir = path.join(repoRoot, "contract", "protocol", "schemas");

function loadSchema(name) {
  return JSON.parse(readFileSync(path.join(schemaDir, name), "utf8"));
}

const ajv = new Ajv2020({
  strict: true,
  strictRequired: false,
  strictTypes: false,
  allErrors: true,
  validateFormats: false,
  unicodeRegExp: false,
});
const scenarioValidate = ajv.compile(loadSchema("host-real-scenario.schema.json"));
const artifactValidate = ajv.compile(loadSchema("host-real-artifact.schema.json"));

function formatErrors(errors) {
  return (errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
}

function relPortable(root, file) {
  return path.relative(root, file).split(path.sep).join("/");
}

export function validateScenario(value, file = "<scenario>") {
  if (!scenarioValidate(value)) {
    return { ok: false, errors: [{ file, code: "schema", detail: formatErrors(scenarioValidate.errors) }] };
  }
  return { ok: true, errors: [] };
}

export function validateArtifact(artifact, options = {}) {
  const file = options.file ?? "<artifact>";
  const scenarioRoot = options.scenarioRoot;
  if (!artifactValidate(artifact)) {
    return { ok: false, errors: [{ file, code: "schema", detail: formatErrors(artifactValidate.errors) }] };
  }
  const errors = [];
  if (artifact.recordedBy !== "human") {
    errors.push({ file, code: "recorded_by", detail: String(artifact.recordedBy) });
  }
  if (!versionRangeMatches(artifact.hostVersion, artifact.versionRange)) {
    errors.push({ file, code: "version_range", detail: artifact.hostVersion });
  }
  const seen = new Set();
  for (const action of artifact.actions) {
    if (seen.has(action.action)) errors.push({ file, code: "duplicate_action", detail: action.action });
    seen.add(action.action);
    const expectedId = `${artifact.host}/${action.action.toLowerCase()}`;
    if (action.scenarioId !== expectedId) {
      errors.push({ file, code: "scenario_id", detail: action.scenarioId });
      continue;
    }
    if (!scenarioRoot) {
      errors.push({ file, code: "scenario_missing", detail: action.scenarioId });
      continue;
    }
    const scenarioFile = path.join(scenarioRoot, action.scenarioId, "scenario.json");
    if (!existsSync(scenarioFile)) {
      errors.push({ file, code: "scenario_missing", detail: action.scenarioId });
      continue;
    }
    const hash = sha256Hex(readFileSync(scenarioFile));
    if (hash !== action.scenarioSha256) {
      errors.push({ file, code: "scenario_sha256", detail: action.scenarioId });
    }
  }
  return { ok: errors.length === 0, errors };
}

function walk(dir, pred) {
  const found = [];
  if (!existsSync(dir)) return { ok: true, found };
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch (error) {
      return { ok: false, error: error.message, found };
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) return { ok: false, error: `symlink ${full}`, found };
      if (entry.isDirectory()) stack.push(full);
      else if (pred(entry.name)) found.push(full);
    }
  }
  found.sort((a, b) => a.localeCompare(b));
  return { ok: true, found };
}

function readJson(file) {
  try {
    return { ok: true, value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (error) {
    return { ok: false, detail: error.message };
  }
}

export function checkHostReal(options = {}) {
  const root = options.repoRoot ?? repoRoot;
  const scenarioRoot = options.scenarioRoot ?? path.join(root, "policy-spec", "host-real");
  const evidenceRoot = options.evidenceRoot ?? path.join(root, "evidence", "host-real");
  const errors = [];
  const scenarios = walk(scenarioRoot, (name) => name === "scenario.json");
  if (!scenarios.ok) return { ok: false, errors: [{ file: scenarioRoot, code: "walk", detail: scenarios.error }] };
  for (const file of scenarios.found) {
    const loaded = readJson(file);
    const label = relPortable(root, file);
    if (!loaded.ok) {
      errors.push({ file: label, code: "schema", detail: loaded.detail });
      continue;
    }
    const schema = validateScenario(loaded.value, label);
    errors.push(...schema.errors);
    if (!schema.ok) continue;
    const rel = relPortable(scenarioRoot, path.dirname(file));
    const value = loaded.value;
    if (value.id !== rel || `${value.host}/${value.action.toLowerCase()}` !== rel) {
      errors.push({ file: label, code: "scenario_id", detail: `${value.id} vs ${rel}` });
    }
  }
  if (!existsSync(evidenceRoot)) return { ok: errors.length === 0, errors };
  const artifacts = walk(evidenceRoot, (name) => name.endsWith(".json"));
  if (!artifacts.ok) return { ok: false, errors: [...errors, { file: evidenceRoot, code: "walk", detail: artifacts.error }] };
  for (const file of artifacts.found) {
    const loaded = readJson(file);
    const label = relPortable(root, file);
    if (!loaded.ok) {
      errors.push({ file: label, code: "schema", detail: loaded.detail });
      continue;
    }
    const checked = validateArtifact(loaded.value, { file: label, scenarioRoot });
    errors.push(...checked.errors);
  }
  return { ok: errors.length === 0, errors };
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync.native(fileURLToPath(import.meta.url)) === realpathSync.native(entry);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const result = checkHostReal();
  process.stdout.write(`${JSON.stringify({ ok: result.ok, errorCount: result.errors.length, errors: result.errors })}\n`);
  process.exitCode = result.ok ? 0 : 1;
}
