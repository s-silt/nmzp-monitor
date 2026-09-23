import { parse, type Expression, type Node } from "acorn";

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
