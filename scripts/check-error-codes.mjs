// lint:contract: v2Error literals, ErrorCode docs, envelope enum order, generated types.
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import ts from "typescript";

const SOURCE = /\.(ts|tsx|mts|cts|mjs|cjs|js|jsx)$/;

export function parseErrorCodeMembers(text) {
  const start = text.indexOf("\n    ErrorCode:\n");
  if (start < 0) throw new Error("openapi ErrorCode schema is missing");
  const lines = text.slice(start + 1).split(/\r?\n/);
  const section = [lines[0]];
  for (let index = 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^ {4}[A-Za-z]/.test(line)) break;
    section.push(line);
  }
  const members = [];
  let current = null;
  for (const line of section) {
    if (current?.field && !isMemberKey(line) && /^\s+\S/.test(line)) {
      const chunk = line.trim();
      if (current.field === "description") current.description = joinScalar(current.description, chunk);
      else current.remediation = joinScalar(current.remediation, chunk);
      continue;
    }
    if (current) current.field = null;
    const head = line.match(/^ {8}- const:\s*(\S+)\s*$/);
    if (head) {
      if (current) members.push(finishMember(current));
      current = { name: yamlScalar(head[1]), description: "", remediation: "", field: null };
      continue;
    }
    if (!current) continue;
    const description = line.match(/^ {10}description:\s*(.*)$/);
    if (description) {
      const value = description[1].trim();
      if (value === ">" || value === "|" || value === ">-" || value === "|-") current.field = "description";
      else current.description = yamlScalar(value);
      continue;
    }
    const remediation = line.match(/^ {10}x-remediation:\s*(.*)$/);
    if (remediation) {
      const value = remediation[1].trim();
      if (value === ">" || value === "|" || value === ">-" || value === "|-") current.field = "remediation";
      else current.remediation = yamlScalar(value);
    }
  }
  if (current) members.push(finishMember(current));
  if (members.length === 0) throw new Error("openapi ErrorCode has no members");
  return members;
}

export function readCodeEnum(schema) {
  const values = schema?.properties?.error?.properties?.code?.enum;
  if (!Array.isArray(values) || values.some((item) => typeof item !== "string")) {
    throw new Error("error-envelope code enum is missing");
  }
  return values;
}

export function checkMemberDocs(members) {
  const errors = [];
  const seen = new Set();
  for (const member of members) {
    if (seen.has(member.name)) errors.push(`ErrorCode ${member.name} is duplicated`);
    seen.add(member.name);
    if (!member.description) errors.push(`ErrorCode ${member.name} is missing description`);
    if (!member.remediation) errors.push(`ErrorCode ${member.name} is missing x-remediation`);
  }
  return errors;
}

export function checkEnumSync(members, enumValues) {
  const names = members.map((member) => member.name);
  if (names.length === enumValues.length && names.every((name, index) => name === enumValues[index])) return [];
  return [`code enum is out of sync with openapi ErrorCode: openapi [${names.join(", ")}] schema [${enumValues.join(", ")}]`];
}

export function scanV2ErrorCalls(coreRoot, allowed) {
  const allowedSet = new Set(allowed);
  const errors = [];
  for (const file of listCoreSources(coreRoot)) {
    const text = readFileSync(file, "utf8");
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind(file));
    const bindings = collectBindings(source);
    const visit = (node) => {
      if (ts.isCallExpression(node) && isV2ErrorCallee(node.expression, bindings)) {
        const literal = literalCode(node.arguments[0]);
        const where = `${relative(coreRoot, file)}:${lineOf(source, node)}`;
        if (literal.kind !== "literal") errors.push(`${where}: v2Error code argument must be a string literal`);
        else if (!allowedSet.has(literal.value)) errors.push(`${where}: v2Error code "${literal.value}" is not an ErrorCode`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return errors;
}

export function checkGeneratedTypes(root) {
  const result = spawnSync("npm run contract:types:check", {
    cwd: root,
    encoding: "utf8",
    shell: true,
    windowsHide: true,
    env: process.env,
  });
  if (result.status === 0) return [];
  const detail = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  return [`contract:types:check failed${detail ? `: ${detail}` : ""}`];
}

export function checkContract(root, options = {}) {
  const errors = [];
  const openapiPath = options.openapiPath ?? join(root, "contract", "protocol", "openapi.yaml");
  const envelopePath = options.envelopePath ?? join(root, "contract", "protocol", "schemas", "error-envelope.schema.json");
  const coreRoot = options.coreRoot ?? join(root, "core");
  let members;
  try {
    members = parseErrorCodeMembers(readFileSync(openapiPath, "utf8"));
  } catch (err) {
    return { ok: false, errors: [err instanceof Error ? err.message : String(err)] };
  }
  errors.push(...checkMemberDocs(members));
  try {
    const enumValues = readCodeEnum(JSON.parse(readFileSync(envelopePath, "utf8")));
    errors.push(...checkEnumSync(members, enumValues));
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
  }
  try {
    errors.push(...scanV2ErrorCalls(coreRoot, members.map((member) => member.name)));
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
  }
  if (!options.skipTypes) errors.push(...checkGeneratedTypes(root));
  return { ok: errors.length === 0, errors };
}

function finishMember(member) {
  return {
    name: member.name,
    description: member.description.trim(),
    remediation: member.remediation.trim(),
  };
}

function isMemberKey(line) {
  return /^ {10}[A-Za-z0-9_-]+:/.test(line) || /^ {8}- const:/.test(line);
}

function joinScalar(left, right) {
  return left ? `${left} ${right}` : right;
}

function yamlScalar(raw) {
  const text = raw.trim();
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
    return text.slice(1, -1);
  }
  return text;
}

function listCoreSources(coreRoot) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (ent.name === "node_modules" || ent.name === "generated" || ent.name === "dist") continue;
      const abs = join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!SOURCE.test(ent.name) || ent.name.endsWith(".d.ts")) continue;
      if (ent.name.includes(".test.") || ent.name.includes(".spec.")) continue;
      out.push(abs);
    }
  };
  walk(coreRoot);
  out.sort();
  return out;
}

function scriptKind(file) {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (file.endsWith(".ts") || file.endsWith(".mts") || file.endsWith(".cts")) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function collectBindings(source) {
  const names = new Set(["v2Error"]);
  const namespaces = new Set();
  for (const stmt of source.statements) {
    if (!ts.isImportDeclaration(stmt) || !stmt.importClause || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    const moduleText = stmt.moduleSpecifier.text;
    const named = stmt.importClause.namedBindings;
    if (named && ts.isNamedImports(named)) {
      for (const el of named.elements) {
        const imported = (el.propertyName ?? el.name).text;
        if (imported === "v2Error") names.add(el.name.text);
      }
    }
    if (named && ts.isNamespaceImport(named) && moduleText.includes("v2-error")) namespaces.add(named.name.text);
  }
  let grew = true;
  while (grew) {
    grew = false;
    const visit = (node) => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer &&
        ts.isIdentifier(node.initializer) &&
        names.has(node.initializer.text) &&
        !names.has(node.name.text)
      ) {
        names.add(node.name.text);
        grew = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { names, namespaces };
}

function isV2ErrorCallee(expression, bindings) {
  const callee = unwrap(expression);
  if (ts.isIdentifier(callee)) return bindings.names.has(callee.text);
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "v2Error") return false;
  return ts.isIdentifier(callee.expression) && bindings.namespaces.has(callee.expression.text);
}

function unwrap(node) {
  let current = node;
  while (
    current &&
    (ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isNonNullExpression(current))
  ) {
    current = current.expression;
  }
  return current;
}

function literalCode(node) {
  if (!node) return { kind: "missing" };
  const value = unwrap(node);
  if (value && (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value))) {
    return { kind: "literal", value: value.text };
  }
  return { kind: "non-literal" };
}

function lineOf(source, node) {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return import.meta.url === pathToFileURL(resolve(entry)).href;
  }
}

if (invokedDirectly()) {
  const rootFlag = process.argv.indexOf("--root");
  const root = rootFlag >= 0 ? process.argv[rootFlag + 1] : dirname(dirname(fileURLToPath(import.meta.url)));
  if (!root) {
    process.stderr.write("missing --root value\n");
    process.exit(2);
  }
  const result = checkContract(root);
  if (!result.ok) {
    process.stderr.write(`${result.errors.join("\n")}\n`);
    process.exit(1);
  }
}
