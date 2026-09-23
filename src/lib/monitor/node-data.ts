import { parse, type Expression, type Node } from "acorn";

/** Static executor arguments only. Reuse the shell/argv operand parser at the caller. */
export function literalNodeExecutions(source: string): Array<{ command: string; args?: string[] }> {
  if (source.length > 16_384) return [];
  const calls: Array<{ command: string; args?: string[] }> = [];
  try {
    const root = parse(source, { ecmaVersion: "latest", sourceType: "module" });
    const namespaces = new Set<string>();
    const executors = new Map<string, string>();
    const moduleName = (value: unknown) =>
      value === "child_process" || value === "node:child_process";
    const isProcess = (node: Node): boolean => {
      const expression = node as Expression;
      return (
        (expression.type === "Identifier" && namespaces.has(expression.name)) ||
        (expression.type === "CallExpression" &&
          expression.callee.type === "Identifier" &&
          expression.callee.name === "require" &&
          expression.arguments.length === 1 &&
          expression.arguments[0].type === "Literal" &&
          moduleName(expression.arguments[0].value))
      );
    };
    // Resolve standard child_process bindings; an unrelated RegExp.exec is not an executor.
    for (const statement of root.body) {
      if (statement.type === "ImportDeclaration" && moduleName(statement.source.value)) {
        for (const item of statement.specifiers) {
          if (item.type === "ImportSpecifier" && item.imported.type === "Identifier")
            executors.set(item.local.name, item.imported.name);
          else namespaces.add(item.local.name);
        }
      } else if (statement.type === "VariableDeclaration" && statement.kind === "const") {
        for (const item of statement.declarations) {
          if (!item.init || !isProcess(item.init)) continue;
          if (item.id.type === "Identifier") namespaces.add(item.id.name);
          if (item.id.type === "ObjectPattern")
            for (const property of item.id.properties) {
              if (
                property.type === "Property" &&
                !property.computed &&
                property.key.type === "Identifier" &&
                property.value.type === "Identifier"
              )
                executors.set(property.value.name, property.key.name);
            }
        }
      }
    }
    let budget = 2_000;
    const visit = (value: unknown, depth: number): void => {
      if (--budget < 0 || depth > 40) throw Error("syntax_limit");
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) {
        for (const child of value) visit(child, depth + 1);
        return;
      }
      const node = value as Node;
      if (typeof node.type !== "string") return;
      if (node.type === "CallExpression") {
        const call = node as Extract<Expression, { type: "CallExpression" }>;
        const callee = call.callee;
        const name =
          callee.type === "Identifier"
            ? (executors.get(callee.name) ?? "")
            : callee.type === "MemberExpression" &&
                isProcess(callee.object) &&
                !callee.computed &&
                callee.property.type === "Identifier"
              ? callee.property.name
              : "";
        const first = call.arguments[0];
        if (
          ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"].includes(name) &&
          first?.type === "Literal" &&
          typeof first.value === "string"
        ) {
          if (name === "exec" || name === "execSync") calls.push({ command: first.value });
          else {
            const second = call.arguments[1];
            if (
              second?.type === "ArrayExpression" &&
              second.elements.every(
                (item) => item?.type === "Literal" && typeof item.value === "string",
              )
            ) {
              calls.push({
                command: first.value,
                args: second.elements.map((item) => (item as { value: string }).value),
              });
            }
          }
        }
      }
      for (const child of Object.values(value))
        if (child && typeof child === "object") visit(child, depth + 1);
    };
    visit(root, 0);
    return calls;
  } catch {
    return calls; // Incomplete extraction is supplemented by conservative operand scanning.
  }
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
