import { parse, parseExpressionAt, tokenizer, type Expression, type Node } from "acorn";

/** Parse individual executor call arguments, never a whole program or variable scopes.
 * Shell strings and argv arrays are distinct. Incomplete parsing stays explicit.
 */
export function literalScriptExecutions(command: string): {
  calls: Array<{ command: string; args?: string[] }>;
  incomplete: boolean;
} {
  const calls: Array<{ command: string; args?: string[] }> = [];
  let incomplete = false,
    budget = 16_000;
  const executors = new Map(
    ["execSync", "exec", "spawnSync", "spawn", "execFile", "execFileSync"].map((name) => [name, name]),
  );
  // Preserve named import / destructuring aliases without building a scope graph.
  // Ambiguous bindings stay conservative; this never proves a program harmless.
  if (command.includes("child_process")) {
    const aliases = /\b(execSync|exec|spawnSync|spawn|execFile|execFileSync)\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*)/g;
    for (const match of command.matchAll(aliases)) {
      if (executors.size >= 256) { incomplete = true; break; }
      executors.set(match[2], match[1]);
    }
  }
  const pattern = /(?<![\w$])([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of command.matchAll(pattern)) {
    const executor = executors.get(match[1]);
    if (!executor || (executor === "exec" && !command.includes("child_process"))) continue;
    if (budget <= 0) {
      incomplete = true;
      break;
    }
    const source = command.slice(match.index, match.index + 16_384);
    try {
      const reader = tokenizer(source, { ecmaVersion: "latest" });
      let depth = 0,
        end = 0;
      while (budget-- > 0) {
        const token = reader.getToken();
        if (token.type.label === "eof") break;
        if (token.type.label === "(") depth++;
        if (token.type.label === ")" && --depth === 0) {
          end = token.end;
          break;
        }
      }
      if (!end) {
        incomplete = true;
        continue;
      }
      const expression = parseExpressionAt(source.slice(0, end), 0, { ecmaVersion: "latest" });
      if (expression.type !== "CallExpression") {
        incomplete = true;
        continue;
      }
      const first = expression.arguments[0];
      if (first?.type !== "Literal" || typeof first.value !== "string") {
        incomplete = true;
        continue;
      }
      if (executor === "exec" || executor === "execSync") calls.push({ command: first.value });
      else {
        const args = expression.arguments[1];
        if (
          args?.type !== "ArrayExpression" ||
          !args.elements.every((item) => item?.type === "Literal" && typeof item.value === "string")
        ) {
          incomplete = true;
          continue;
        }
        calls.push({
          command: first.value,
          args: args.elements.map((item) => (item as { value: string }).value),
        });
      }
    } catch {
      incomplete = true;
    }
  }
  return { calls, incomplete };
}

/** This is a proof of a small data-only subset, never a JavaScript interpreter. */
export function isDataProgram(source: string): boolean {
  if (source.length > 16_384) return false;
  try {
    const program = parse(source, { ecmaVersion: "latest", sourceType: "module" });
    const variables = new Set<string>();
    const readers = new Set<string>();
    let budget = 2_000;
    const reserved = new Set(["console", "JSON", "undefined", "NaN", "Infinity"]);
    const bind = (name: string) => {
      if (reserved.has(name) || variables.has(name) || readers.has(name)) return false;
      return true;
    };
    const data = (node: Expression | Node | null | undefined, depth = 0): boolean => {
      if (!node || --budget < 0 || depth > 40) return false;
      const next = (child: Expression | Node | null | undefined) => data(child, depth + 1);
      // Acorn returns ESTree discriminated expressions; all other node kinds fail closed.
      const n = node as Expression;
      switch (n.type) {
        case "Literal":
          return true;
        case "Identifier":
          return variables.has(n.name) || ["undefined", "NaN", "Infinity"].includes(n.name);
        case "TemplateLiteral":
          return n.expressions.every(next);
        case "ArrayExpression":
          return n.elements.every((e) => e === null || next(e));
        case "ObjectExpression":
          return n.properties.every(
            (p) =>
              p.type === "Property" &&
              p.kind === "init" &&
              !p.method &&
              !p.computed &&
              next(p.value),
          );
        case "BinaryExpression":
        case "LogicalExpression":
          return next(n.left) && next(n.right);
        case "UnaryExpression":
          return n.operator !== "delete" && next(n.argument);
        case "ConditionalExpression":
          return next(n.test) && next(n.consequent) && next(n.alternate);
        case "MemberExpression":
          return (
            !n.computed &&
            n.property.type === "Identifier" &&
            n.property.name === "length" &&
            next(n.object)
          );
        case "CallExpression": {
          if (!n.arguments.every(next)) return false;
          if (n.callee.type === "Identifier") return readers.has(n.callee.name);
          if (
            n.callee.type !== "MemberExpression" ||
            n.callee.computed ||
            n.callee.property.type !== "Identifier"
          )
            return false;
          const { object, property } = n.callee;
          if (object.type === "Identifier") {
            if (object.name === "console") return ["log", "error", "warn"].includes(property.name);
            if (object.name === "JSON") return ["parse", "stringify"].includes(property.name);
          }
          return (
            [
              "replace",
              "replaceAll",
              "slice",
              "substring",
              "trim",
              "split",
              "join",
              "includes",
              "startsWith",
              "endsWith",
              "toString",
              "toLowerCase",
              "toUpperCase",
              "exec",
              "test",
            ].includes(property.name) && next(object)
          );
        }
        default:
          return false;
      }
    };
    for (const statement of program.body) {
      if (statement.type === "ImportDeclaration") {
        if (statement.source.value !== "node:fs" && statement.source.value !== "fs") return false;
        for (const specifier of statement.specifiers) {
          if (
            specifier.type !== "ImportSpecifier" ||
            specifier.imported.type !== "Identifier" ||
            !["readFileSync", "existsSync"].includes(specifier.imported.name) ||
            !bind(specifier.local.name)
          )
            return false;
          readers.add(specifier.local.name);
        }
        if (!statement.specifiers.length) return false;
      } else if (statement.type === "VariableDeclaration" && statement.kind === "const") {
        for (const declaration of statement.declarations) {
          if (
            declaration.id.type !== "Identifier" ||
            !bind(declaration.id.name) ||
            !data(declaration.init)
          )
            return false;
          variables.add(declaration.id.name);
        }
      } else if (statement.type === "ExpressionStatement") {
        if (!data(statement.expression)) return false;
      } else if (statement.type !== "EmptyStatement") return false;
    }
    return program.body.length > 0;
  } catch {
    return false;
  }
}
