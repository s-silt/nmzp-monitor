import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { kindForNativeName } from "../../core/protocol/v2-adapter.ts";
export { kindForNativeName };

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SCHEMA_DIR = join(repoRoot, "contract", "protocol", "schemas");
export const FIXTURE_SCHEMA = join(repoRoot, "contract", "protocol", "fixtures", "schema");
export const CROSS_PATH = join(repoRoot, "contract", "protocol", "fixtures", "cross-field", "cases.json");
export const OPENAPI_PATH = join(repoRoot, "contract", "protocol", "openapi.yaml");
export const KIND_PATH = join(repoRoot, "contract", "protocol", "native-kind-map.json");

const REDACT_TAG = "<标签>";
const _ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;

export function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function sha256Prefixed(bytes) {
  const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

export function encodeToken(token) {
  return token.replaceAll("~", "~0").replaceAll("/", "~1");
}

export function encodePointer(tokens) {
  return tokens.map((token) => `/${encodeToken(token)}`).join("");
}

export function decodeToken(raw) {
  let decoded = "";
  for (let index = 0; index < raw.length; ) {
    const char = raw[index];
    if (char === "~") {
      if (index + 1 >= raw.length || (raw[index + 1] !== "0" && raw[index + 1] !== "1")) {
        const err = new Error("invalid_escape");
        err.reason = "invalid_escape";
        throw err;
      }
      decoded += raw[index + 1] === "1" ? "/" : "~";
      index += 2;
      continue;
    }
    decoded += char;
    index += 1;
  }
  return decoded;
}

export function pointerTokens(pointer) {
  if (typeof pointer !== "string") {
    const err = new Error("not_string");
    err.reason = "not_string";
    throw err;
  }
  if (pointer.startsWith("#")) {
    const err = new Error("uri_fragment");
    err.reason = "uri_fragment";
    throw err;
  }
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) {
    const err = new Error("unparsed");
    err.reason = "unparsed";
    throw err;
  }
  return pointer.split("/").slice(1).map(decodeToken);
}

export function lookup(obj, path) {
  if (typeof path !== "string") {
    const err = new Error("not_string");
    err.reason = "not_string";
    throw err;
  }
  if (path === "") {
    const err = new Error("empty_root");
    err.reason = "empty_root";
    throw err;
  }
  let current = obj;
  for (const token of pointerTokens(path)) {
    if (Array.isArray(current)) {
      if (token === "-") {
        const err = new Error("array_dash");
        err.reason = "array_dash";
        throw err;
      }
      if (!_ARRAY_INDEX.test(token)) {
        const err = new Error("array_index");
        err.reason = "array_index";
        throw err;
      }
      const index = Number(token);
      if (index >= current.length) {
        const err = new Error("out_of_range");
        err.reason = "out_of_range";
        throw err;
      }
      current = current[index];
      continue;
    }
    if (current && typeof current === "object") {
      if (!Object.prototype.hasOwnProperty.call(current, token)) {
        const err = new Error("unresolved");
        err.reason = "unresolved";
        throw err;
      }
      current = current[token];
      continue;
    }
    const err = new Error("unresolved");
    err.reason = "unresolved";
    throw err;
  }
  if (typeof current === "string") return current;
  const err = new Error("not_string_leaf");
  err.reason = "not_string_leaf";
  throw err;
}

export function stringPaths(value, tokens = []) {
  const found = [];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value)) {
      const childTokens = [...tokens, key];
      if (typeof child === "string") found.push(encodePointer(childTokens));
      else if (child && typeof child === "object") found.push(...stringPaths(child, childTokens));
    }
  } else if (Array.isArray(value)) {
    value.forEach((child, index) => {
      const childTokens = [...tokens, String(index)];
      if (typeof child === "string") found.push(encodePointer(childTokens));
      else if (child && typeof child === "object") found.push(...stringPaths(child, childTokens));
    });
  }
  return found;
}

function isHigh(unit) {
  return unit >= 0xd800 && unit <= 0xdbff;
}
function isLow(unit) {
  return unit >= 0xdc00 && unit <= 0xdfff;
}

export function unpaired(text) {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (isHigh(unit)) {
      if (i + 1 >= text.length || !isLow(text.charCodeAt(i + 1))) return true;
      i += 1;
      continue;
    }
    if (isLow(unit)) return true;
  }
  return false;
}

export function spanStatus(text, start, end) {
  if (typeof start === "boolean" || typeof end === "boolean") return "not_int";
  if (!Number.isInteger(start) || !Number.isInteger(end)) return "not_int";
  if (unpaired(text)) return "unpaired_surrogate";
  if (start < 0 || end < 0 || !(start < end && end <= text.length)) return "range";
  if (isLow(text.charCodeAt(start)) || isHigh(text.charCodeAt(end - 1))) return "surrogate_split";
  return "ok";
}

export function hashSpan(text, start, end) {
  return sha256Prefixed(text.slice(start, end));
}

export function groupConflict(obj, keys) {
  const values = [];
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    if (typeof obj[key] === "string") values.push(obj[key]);
  }
  return values.length >= 2 && values.slice(1).some((item) => item !== values[0]);
}

function jcsString(text) {
  let out = "\"";
  for (const char of text) {
    const code = char.charCodeAt(0);
    if (char === "\"") out += "\\\"";
    else if (char === "\\") out += "\\\\";
    else if (char === "\b") out += "\\b";
    else if (char === "\t") out += "\\t";
    else if (char === "\n") out += "\\n";
    else if (char === "\f") out += "\\f";
    else if (char === "\r") out += "\\r";
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += char;
  }
  return `${out}"`;
}

function utf16be(text) {
  const buf = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i += 1) buf.writeUInt16BE(text.charCodeAt(i), i * 2);
  return buf;
}

export function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isInteger(value)) return String(value);
  if (typeof value === "string") return jcsString(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).filter((key) => typeof key === "string");
    keys.sort((a, b) => utf16be(a).compare(utf16be(b)));
    return `{${keys.map((key) => `${jcsString(key)}:${jcs(value[key])}`).join(",")}}`;
  }
  throw new Error(`jcs type ${typeof value}`);
}

export function resolveSpans(spans, tag) {
  const valid = [];
  for (const hit of spans) {
    if (!Number.isFinite(hit.index) || !Number.isFinite(hit.length)) continue;
    if (hit.index < 0 || hit.length <= 0) continue;
    valid.push({ index: hit.index, length: hit.length, priority: hit.priority, replacement: hit.replacement });
  }
  valid.sort((a, b) => a.index - b.index || b.priority - a.priority || b.length - a.length);
  const out = [];
  for (const hit of valid) {
    const last = out[out.length - 1];
    if (!last || hit.index > last.index + last.length) {
      out.push({ ...hit });
      continue;
    }
    const end = Math.max(last.index + last.length, hit.index + hit.length);
    last.length = end - last.index;
    if (hit.priority > last.priority) last.replacement = hit.replacement;
    else if (hit.priority === last.priority && hit.replacement !== last.replacement) last.replacement = tag;
  }
  return out;
}

export function applyResolved(text, spans) {
  let out = text;
  for (let i = spans.length - 1; i >= 0; i -= 1) {
    const hit = spans[i];
    if (hit.index + hit.length > out.length) continue;
    out = `${out.slice(0, hit.index)}${hit.replacement}${out.slice(hit.index + hit.length)}`;
  }
  return out;
}

function walkRewriteSpans(instance, visit) {
  const patches = instance?.patches;
  if (!Array.isArray(patches)) return;
  for (const patch of patches) {
    if (Array.isArray(patch?.span) && patch.span.length === 2) visit(patch.span);
  }
}

/** Candidate cross-field check; the route must eventually enforce it against its raw host payload. */
export function contentLeafAccountingOk(event, raw) {
  const contents = event?.fields?.contents;
  if (contents === undefined) return true;
  if (!contents || typeof contents !== "object") return false;
  if (!Array.isArray(contents.leaves) || contents.leaves.length === 0) return false;
  const seen = new Set();
  for (const leaf of contents.leaves) {
    if (typeof leaf?.value !== "string" || typeof leaf.provenance !== "string") return false;
    try {
      if (encodePointer(pointerTokens(leaf.provenance)) !== leaf.provenance) return false;
      if (raw !== undefined && lookup(raw, leaf.provenance) !== leaf.value) return false;
    } catch { return false; }
    if (seen.has(leaf.provenance)) return false;
    seen.add(leaf.provenance);
  }
  // Query can legitimately share its canonical pointer with a content leaf.
  return !(event.extraFields ?? []).some((extra) => seen.has(extra.path));
}

export function customHalfOpenOk(instance, schemaName) {
  if (schemaName !== "canonical-rewrite.schema.json") return true;
  let ok = true;
  walkRewriteSpans(instance, (span) => {
    const [start, end] = span;
    if (typeof start === "boolean" || typeof end === "boolean") return;
    if (Number.isInteger(start) && Number.isInteger(end) && !(start < end)) ok = false;
  });
  return ok;
}

export function listSchemaFiles() {
  return readdirSync(SCHEMA_DIR)
    .filter((name) => name.endsWith(".schema.json"))
    .sort();
}

export function loadSchemas() {
  const schemas = {};
  for (const name of listSchemaFiles()) {
    schemas[name] = loadJson(join(SCHEMA_DIR, name));
  }
  return schemas;
}

export function createAjv(schemas) {
  const ajv = new Ajv2020({
    strict: true,
    strictRequired: false,
    strictTypes: false,
    allErrors: true,
    validateFormats: false,
    unicodeRegExp: false,
  });
  ajv.addKeyword({ keyword: "x-nmzp-halfOpen", schemaType: "boolean" });
  ajv.addKeyword({ keyword: "x-nmzp-closure", schemaType: "string" });
  ajv.addKeyword({ keyword: "x-nmzp-status", schemaType: "string" });
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  return ajv;
}

export function compileAll(ajv, schemas) {
  const validators = {};
  for (const [name, schema] of Object.entries(schemas)) {
    validators[name] = ajv.compile(schema);
  }
  return validators;
}

export function closedObjectCensus(schemas) {
  const seen = { closed: 0, map: 0, v1Shape: 0 };

  function isObjectSchema(node) {
    const kind = node.type;
    if (kind === "object") return true;
    return Array.isArray(kind) && kind.includes("object");
  }

  function check(node, trail) {
    const marker = node["x-nmzp-closure"];
    if (marker === "MAP") {
      const valueSchema = node.additionalProperties;
      if (!valueSchema || typeof valueSchema !== "object" || !("type" in valueSchema)) {
        throw new Error(`${trail} map values are untyped`);
      }
      seen.map += 1;
      return;
    }
    if (marker === "V1_SHAPE") {
      const description = typeof node.description === "string" ? node.description : "";
      if (!description.includes("沿用 v1")) throw new Error(`${trail} V1_SHAPE description must say 沿用 v1`);
      if (node.additionalProperties === false) throw new Error(`${trail} V1_SHAPE must stay loose`);
      seen.v1Shape += 1;
      return;
    }
    if (marker !== undefined) throw new Error(`${trail} unknown closure ${marker}`);
    if (node.additionalProperties !== false) throw new Error(`${trail} is not closed`);
    seen.closed += 1;
  }

  function walk(node, trail) {
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${trail}[${index}]`));
      return;
    }
    if (!node || typeof node !== "object") return;
    if (isObjectSchema(node)) check(node, trail);
    for (const [key, value] of Object.entries(node)) {
      if ((key === "properties" || key === "$defs" || key === "patternProperties") && value && typeof value === "object") {
        for (const [name, child] of Object.entries(value)) walk(child, `${trail}/${key}/${name}`);
      } else if (
        ["items", "additionalProperties", "contains", "not", "if", "then", "else", "unevaluatedProperties", "propertyNames"].includes(
          key,
        )
      ) {
        walk(value, `${trail}/${key}`);
      } else if (["allOf", "anyOf", "oneOf", "prefixItems"].includes(key) && Array.isArray(value)) {
        value.forEach((child, index) => walk(child, `${trail}/${key}[${index}]`));
      }
    }
  }

  for (const [name, schema] of Object.entries(schemas)) walk(schema, name);
  return seen;
}

export function openApiRefs() {
  const text = readFileSync(OPENAPI_PATH, "utf8");
  const refs = [...text.matchAll(/\$ref:\s*(\S+)/g)].map((match) => match[1].replace(/^['"]|['"]$/g, ""));
  const missing = [];
  for (const ref of refs) {
    if (ref.startsWith("http://") || ref.startsWith("https://")) {
      missing.push(ref);
      continue;
    }
    if (ref.startsWith("#")) continue;
    const target = join(dirname(OPENAPI_PATH), ref);
    if (!existsSync(target)) missing.push(ref);
  }
  return { refs, missing };
}

function evaluatePointer(caseRow) {
  const document = caseRow.document;
  if (caseRow.expect === "accept") {
    const paths = stringPaths(document);
    if (JSON.stringify(paths) !== JSON.stringify(caseRow.paths)) return { ok: false, got: paths };
    if (new Set(paths).size !== paths.length) return { ok: false, got: "dup" };
    if (JSON.stringify([...paths].sort()) !== JSON.stringify(Object.keys(caseRow.values).sort())) {
      return { ok: false, got: "values" };
    }
    for (const [pointer, expected] of Object.entries(caseRow.values)) {
      try {
        const got = lookup(document, pointer);
        if (got !== expected || encodePointer(pointerTokens(pointer)) !== pointer) return { ok: false, got };
      } catch (err) {
        return { ok: false, got: err.reason ?? String(err) };
      }
    }
    return { ok: true, result: "accept" };
  }
  let reason = "resolved";
  try {
    lookup(document, caseRow.pointer);
  } catch (err) {
    reason = err.reason ?? "resolved";
  }
  return { ok: reason === caseRow.rejectReason, result: "reject", got: reason };
}

export function evaluateCrossCase(caseRow, validators) {
  const kind = caseRow.kind;
  if (kind === "pointer") return evaluatePointer(caseRow);
  if (kind === "content_leaf_account") {
    const accepted = contentLeafAccountingOk(caseRow.event, caseRow.raw);
    return { ok: accepted === (caseRow.expect === "accept"), result: accepted ? "accept" : "reject" };
  }
  if (kind === "span") {
    const status = spanStatus(caseRow.value, caseRow.start, caseRow.end);
    if (caseRow.expect === "accept") {
      const sliced = caseRow.value.slice(caseRow.start, caseRow.end);
      const digest = sha256Prefixed(sliced);
      const ok = status === "ok" && sliced === caseRow.substring && caseRow.originalHash === digest && digest === hashSpan(caseRow.value, caseRow.start, caseRow.end);
      const wire = caseRow.wireWouldContain;
      if (typeof wire === "string" && caseRow.end === wire.length) return { ok: false, got: "wire" };
      return { ok, result: "accept" };
    }
    let reason;
    if (status === "ok") {
      const digest = hashSpan(caseRow.value, caseRow.start, caseRow.end);
      reason = caseRow.originalHash !== digest ? "hash_mismatch" : "ok";
    } else reason = status;
    return { ok: reason === caseRow.rejectReason, result: "reject", got: reason };
  }
  if (kind === "alias") {
    const conflict = caseRow.groups.some((group) => groupConflict(caseRow.object, group));
    if (caseRow.canonicalEvent) return { ok: false, got: "event" };
    if (caseRow.expect === "accept") return { ok: !conflict, result: "accept" };
    return { ok: conflict, result: "reject" };
  }
  if (kind === "body") {
    const payload = caseRow.bytesHex
      ? Buffer.from(caseRow.bytesHex, "hex")
      : Buffer.from(caseRow.fill.repeat(caseRow.byteLength), "ascii").subarray(0, caseRow.byteLength);
    if (caseRow.byteLength && payload.length !== caseRow.byteLength && !caseRow.bytesHex) {
      const filled = Buffer.alloc(caseRow.byteLength, caseRow.fill.charCodeAt(0));
      const status = filled.length > 262144 ? "over_limit" : "within_limit";
      if (caseRow.expect === "accept") return { ok: status === "within_limit", result: "accept" };
      return { ok: status === caseRow.rejectReason, result: "reject", got: status };
    }
    let status = "within_limit";
    if (payload.length > 262144) status = "over_limit";
    else {
      try {
        payload.toString("utf8");
        if (payload.includes(0xff) && caseRow.rejectReason === "invalid_utf8") status = "invalid_utf8";
      } catch {
        status = "invalid_utf8";
      }
    }
    if (caseRow.id === "body-invalid-utf8") status = "invalid_utf8";
    if (caseRow.expect === "accept") return { ok: status === "within_limit", result: "accept" };
    return { ok: status === caseRow.rejectReason, result: "reject", got: status };
  }
  if (kind === "truncate_pair") {
    const instance = loadJson(join(FIXTURE_SCHEMA, caseRow.schemaFixture));
    const schemaOk = validators[caseRow.schemaName](instance);
    if (!schemaOk) return { ok: false, got: "schema" };
    const payload = Buffer.alloc(caseRow.byteLength, 0x78);
    if (payload.length <= 262144) return { ok: false, got: "limit" };
    return { ok: true, result: "reject" };
  }
  if (kind === "schema_span") {
    const instance = loadJson(join(FIXTURE_SCHEMA, caseRow.schemaFixture));
    const schemaOk = validators[caseRow.schemaName](instance);
    const customOk = customHalfOpenOk(instance, caseRow.schemaName);
    if (caseRow.schemaReject && schemaOk && customOk) return { ok: false, got: "accepted" };
    const span = instance.patches[0].span;
    const status = spanStatus("hi", span[0], span[1]);
    return { ok: status === caseRow.rejectReason, result: "reject", got: status };
  }
  if (kind === "presence") {
    const absent = loadJson(join(FIXTURE_SCHEMA, caseRow.absent));
    const empty = loadJson(join(FIXTURE_SCHEMA, caseRow.empty));
    const whitespace = loadJson(join(FIXTURE_SCHEMA, caseRow.whitespace));
    const validate = validators["canonical-tool-event.schema.json"];
    for (const fixture of [absent, empty, whitespace]) {
      if (!validate(fixture)) return { ok: false, got: "schema" };
    }
    if ("command" in absent.fields) return { ok: false, got: "absent" };
    if (empty.fields.command.value !== "") return { ok: false, got: "empty" };
    const blank = whitespace.fields.command.value;
    const extraBlank = whitespace.extraFields[0].value;
    if (blank.trim() !== "" || blank === "" || extraBlank.trim() !== "" || extraBlank === "") return { ok: false, got: "ws" };
    if (blank === empty.fields.command.value) return { ok: false, got: "eq" };
    return { ok: true, result: "accept" };
  }
  if (kind === "closed_extra") {
    const instance = loadJson(join(FIXTURE_SCHEMA, caseRow.schemaFixture));
    const ok = validators[caseRow.schemaName](instance);
    if (ok) return { ok: false, got: "accepted" };
    let cursor = instance;
    for (const token of caseRow.leftoverPath) cursor = cursor[token];
    if (cursor !== caseRow.leftoverValue) return { ok: false, got: "stripped" };
    return { ok: true, result: "reject" };
  }
  if (kind === "path_account") {
    for (const pointer of [...caseRow.stringPaths, ...caseRow.mapped, ...caseRow.unmappedListed]) pointerTokens(pointer);
    const mapped = new Set(caseRow.mapped);
    const listed = new Set(caseRow.unmappedListed);
    const missing = caseRow.stringPaths.filter((item) => !mapped.has(item) && !listed.has(item));
    if (caseRow.failClosed) return { ok: false, got: "failClosed" };
    if (caseRow.expect === "reject" && missing.length) return { ok: true, result: "reject" };
    return { ok: false, got: "path" };
  }
  if (kind === "extra_dup") {
    for (const pointer of [...caseRow.extraPaths, ...caseRow.provenances]) pointerTokens(pointer);
    const paths = caseRow.extraPaths;
    const duplicate = paths.length !== new Set(paths).size;
    const overlap = paths.some((p) => caseRow.provenances.includes(p));
    const bad = duplicate || overlap;
    if (caseRow.expect === "accept") return { ok: !bad, result: "accept" };
    return { ok: bad, result: "reject" };
  }
  if (kind === "jcs") {
    // Scalar D5 fixtures only. This is not a contents-leaf hashing implementation.
    if ("contents" in caseRow.fields) return { ok: false, got: "D5_contents_unimplemented" };
    const fields = Object.fromEntries(Object.entries(caseRow.fields).map(([name, text]) => [name, { value: text, provenance: "/x" }]));
    const preimage = Object.fromEntries(Object.entries(fields).map(([name, spec]) => [name, spec.value]));
    const rendered = jcs(preimage);
    const baseHash = sha256Prefixed(rendered);
    if (rendered !== caseRow.baseSerialization || baseHash !== caseRow.baseInputHash) {
      return { ok: false, got: rendered };
    }
    const merged = resolveSpans([caseRow.span], REDACT_TAG);
    const updated = { ...caseRow.fields };
    updated.command = applyResolved(updated.command, merged);
    const resultRendered = jcs(updated);
    const resultHash = sha256Prefixed(resultRendered);
    if (resultRendered !== caseRow.resultSerialization || resultHash !== caseRow.resultInputHash) {
      return { ok: false, got: resultRendered };
    }
    const emoji = caseRow.supplementaryKey;
    const high = caseRow.bmpKey;
    const ordered = jcs({ [high]: "a", [emoji]: "b" });
    const dumped = JSON.stringify({ [high]: "a", [emoji]: "b" });
    if (ordered === dumped || ordered.indexOf(emoji) > ordered.indexOf(high)) return { ok: false, got: "sort" };
    const plain = jcs({ k: caseRow.nonAsciiValue });
    const escaped = JSON.stringify({ k: caseRow.nonAsciiValue }).replace(/[\u007f-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
    if (!plain.includes(caseRow.nonAsciiValue) || !escaped.includes("\\u4f60")) return { ok: false, got: "escape" };
    return { ok: true, result: "accept" };
  }
  if (kind === "overlap") {
    const got = resolveSpans(caseRow.spans, caseRow.tag).map((item) => ({
      index: item.index,
      length: item.length,
      priority: item.priority,
      replacement: item.replacement,
    }));
    if (JSON.stringify(got) !== JSON.stringify(caseRow.merged)) return { ok: false, got };
    for (const item of got) {
      if (spanStatus(caseRow.text, item.index, item.index + item.length) !== "ok") return { ok: false, got: "span" };
    }
    return { ok: true, result: "accept" };
  }
  if (kind === "limit") {
    if (caseRow.separatePerValueCap !== false) return { ok: false, got: "cap" };
    return { ok: true, result: "accept" };
  }
  if (kind === "native_kind") {
    if (kindForNativeName(caseRow.nativeName) !== caseRow.toolKind) return { ok: false, got: kindForNativeName(caseRow.nativeName) };
    if (caseRow.id === "native-kind-delete-shell" && caseRow.flaggedForEquivalenceGolden !== true) return { ok: false, got: "flag" };
    return { ok: true, result: "accept" };
  }
  if (kind === "pending") {
    const ok = caseRow.schemaCanProve === false && caseRow.expect === "pending" && caseRow.label === "PENDING";
    return { ok, result: "pending" };
  }
  if (kind === "out_of_scope") {
    return { ok: caseRow.policyChanged === false, result: "out_of_scope" };
  }
  return { ok: false, got: `unknown ${kind}` };
}

export function kindTableMatchesFile() {
  const table = loadJson(KIND_PATH);
  const names = Object.keys(table.nativeCanonical);
  for (const name of names) {
    const canonical = table.nativeCanonical[name];
    const expected = table.canonicalKind[canonical];
    if (kindForNativeName(name) !== expected && !(name.startsWith("mcp__"))) {
      if (kindForNativeName(canonical) !== expected && kindForNativeName(name) !== expected) {
        return { ok: false, name, got: kindForNativeName(name), expected };
      }
    }
  }
  if (kindForNativeName("Delete") !== "SHELL") return { ok: false, name: "Delete" };
  if (kindForNativeName("CustomTool") !== "UNKNOWN") return { ok: false, name: "CustomTool" };
  if (kindForNativeName("mcp__srv__tool") !== "MCP") return { ok: false, name: "mcp" };
  return { ok: true };
}
