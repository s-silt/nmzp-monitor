import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { aggregateOverall, type CheckStatus, type DoctorReport } from "./report.ts";

/**
 * Minimal JSON Schema checker for contract/doctor-report.schema.json.
 * The repository does not depend on a JSON Schema library. Supported keywords:
 * type (including a type array), const, enum, required, properties,
 * additionalProperties:false, items, $ref (local), format:date-time,
 * minLength, minItems.
 * overall vs checks is not expressible in this schema; validateDoctorReport
 * applies the ERROR > WARN > UNKNOWN > OK rule after the schema succeeds.
 */

export function doctorSchemaPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract", "doctor-report.schema.json");
}

export function loadDoctorSchema(): Record<string, unknown> {
  return JSON.parse(readFileSync(doctorSchemaPath(), "utf8")) as Record<string, unknown>;
}

export function validateDoctorReport(
  data: unknown,
  schema: Record<string, unknown> = loadDoctorSchema(),
): { ok: true } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  validateNode(schema, data, "", schema, errors);
  if (errors.length === 0 && isReport(data)) {
    const expected = aggregateOverall(data.checks.map((item) => item.status));
    if (data.overall !== expected) errors.push(`/overall expected ${expected}`);
  }
  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

function isReport(data: unknown): data is DoctorReport {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  const checks = (data as { checks?: unknown }).checks;
  return Array.isArray(checks);
}

function validateNode(
  schema: Record<string, unknown>,
  data: unknown,
  path: string,
  root: Record<string, unknown>,
  errors: string[],
): void {
  if (typeof schema.$ref === "string") {
    const target = resolveRef(root, schema.$ref);
    if (!target) {
      errors.push(`${path || "/"} bad $ref`);
      return;
    }
    validateNode(target, data, path, root, errors);
    return;
  }
  if ("const" in schema && !same(data, schema.const)) {
    errors.push(`${path || "/"} const`);
    return;
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((item) => same(item, data))) {
    errors.push(`${path || "/"} enum`);
    return;
  }
  if (schema.type !== undefined && !typeOk(schema.type, data)) {
    errors.push(`${path || "/"} type`);
    return;
  }
  if (schema.format === "date-time") {
    if (typeof data !== "string" || !dateTimeOk(data)) errors.push(`${path || "/"} format`);
  }
  if (typeof schema.minLength === "number" && typeof data === "string" && data.length < schema.minLength) {
    errors.push(`${path || "/"} minLength`);
  }
  if (typeof schema.minItems === "number" && Array.isArray(data) && data.length < schema.minItems) {
    errors.push(`${path || "/"} minItems`);
  }
  if (schema.type === "object" || (Array.isArray(schema.type) && schema.type.includes("object") && isObject(data))) {
    if (!isObject(data)) return;
    const required = Array.isArray(schema.required) ? schema.required : [];
    for (const key of required) {
      if (typeof key === "string" && !(key in data)) errors.push(`${path}/${key} required`);
    }
    const properties =
      schema.properties && typeof schema.properties === "object" ? (schema.properties as Record<string, unknown>) : {};
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(data)) {
        if (!(key in properties)) errors.push(`${path}/${key} additionalProperties`);
      }
    }
    for (const [key, value] of Object.entries(data)) {
      const child = properties[key];
      if (child && typeof child === "object") validateNode(child as Record<string, unknown>, value, `${path}/${key}`, root, errors);
    }
  }
  if ((schema.type === "array" || (Array.isArray(schema.type) && schema.type.includes("array"))) && Array.isArray(data)) {
    const items = schema.items;
    if (items && typeof items === "object") {
      data.forEach((item, index) => {
        validateNode(items as Record<string, unknown>, item, `${path}/${index}`, root, errors);
      });
    }
  }
}

function resolveRef(root: Record<string, unknown>, ref: string): Record<string, unknown> | null {
  if (!ref.startsWith("#/")) return null;
  let cursor: unknown = root;
  for (const part of ref.slice(2).split("/")) {
    if (!cursor || typeof cursor !== "object" || Array.isArray(cursor) || !(part in cursor)) return null;
    cursor = (cursor as Record<string, unknown>)[part];
  }
  return cursor && typeof cursor === "object" && !Array.isArray(cursor) ? (cursor as Record<string, unknown>) : null;
}

function typeOk(type: unknown, data: unknown): boolean {
  const names = Array.isArray(type) ? type : [type];
  return names.some((name) => {
    if (name === "object") return isObject(data);
    if (name === "array") return Array.isArray(data);
    if (name === "string") return typeof data === "string";
    if (name === "null") return data === null;
    if (name === "boolean") return typeof data === "boolean";
    if (name === "integer") return typeof data === "number" && Number.isInteger(data);
    if (name === "number") return typeof data === "number" && Number.isFinite(data);
    return false;
  });
}

function isObject(data: unknown): data is Record<string, unknown> {
  return !!data && typeof data === "object" && !Array.isArray(data);
}

function same(a: unknown, b: unknown): boolean {
  return Object.is(a, b);
}

function dateTimeOk(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return false;
  return !Number.isNaN(Date.parse(value));
}

export type { CheckStatus };
