import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { parseHookEvent, toolInputToEvalFields } from "./hook-protocol.ts";
import { parseHookPayload } from "../src/lib/monitor/ingest.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const TRUTH = "core/hook-alias-keys.ts";

/**
 * Independent of production constants. These are the alias tables that may exist
 * as quoted arrays only in the single truth module.
 *
 * 原文要求字面量只出现在 hook-protocol.ts。ingest 是 domain、hook-protocol 是 app
 *（auth/newEventId），domain 不能 import app，所以真值模块是无 I/O 的 hook-alias-keys.ts，
 * 由 hook-protocol re-export。
 */
const ALIAS_TABLES: Record<string, readonly string[]> = {
  COMMAND_KEYS: ["command", "cmd"],
  FILE_PATH_KEYS: ["file_path", "filePath", "path", "target_file"],
  DEST_KEYS: ["dest", "host", "hostname"],
  CWD_KEYS: ["working_directory", "workingDirectory", "cwd"],
  CONTENT_KEYS: [
    "contents",
    "content",
    "new_string",
    "old_string",
    "newString",
    "oldString",
    "body",
    "patch",
    "new_source",
    "replacement",
    "file_text",
    "prompt",
  ],
  CONTENT_ALIAS_KEYS: ["contents", "content"],
  TOOL_NAME_KEYS: ["tool_name", "toolName", "tool"],
  EVAL_BRIDGE_TOOL_NAME_KEYS: ["tool_name", "toolName", "tool", "nativeTool"],
  SESSION_ID_KEYS: ["session_id", "sessionId", "conversation_id"],
  EVAL_BRIDGE_SESSION_ID_KEYS: ["sessionId", "session_id"],
  EVENT_ID_KEYS: ["eventId", "event_id"],
  TOOL_USE_ID_KEYS: ["toolUseId", "tool_use_id", "tool_call_id"],
  EVAL_BRIDGE_FILE_PATH_KEYS: ["file_path", "filePath"],
  TOOL_INPUT_BAG_KEYS: ["tool_input", "toolInput", "input"],
};

const CORPUS_CATEGORIES = [
  "normal",
  "risky",
  "boundaries",
  "protected",
  "exemptions",
  "rewrite",
  "privacy",
  "proposal",
  "historical",
  "host-normalization",
];

function scriptKind(fileName: string): ts.ScriptKind {
  if (fileName.endsWith(".mjs") || fileName.endsWith(".js")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function stringArrayLiterals(source: string, fileName = "snippet.ts"): string[][] {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, scriptKind(fileName));
  const out: string[][] = [];
  const visit = (node: ts.Node) => {
    if (ts.isArrayLiteralExpression(node)) {
      const strs: string[] = [];
      let allStrings = node.elements.length > 0;
      for (const el of node.elements) {
        if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) strs.push(el.text);
        else {
          allStrings = false;
          break;
        }
      }
      if (allStrings) out.push(strs);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function groupsMatching(arr: readonly string[]): string[] {
  const set = new Set(arr);
  const hits: string[] = [];
  for (const [name, keys] of Object.entries(ALIAS_TABLES)) {
    if (set.size === keys.length && keys.every((key) => set.has(key))) hits.push(name);
  }
  return hits;
}

/** AST set match of alias groups. Comments/quotes/order do not hide copies. */
export function copiedAliasTables(source: string, fileName = "snippet.ts"): string[] {
  const hits = new Set<string>();
  for (const arr of stringArrayLiterals(source, fileName)) {
    for (const name of groupsMatching(arr)) hits.add(name);
  }
  return [...hits];
}

function posixRel(abs: string): string {
  return abs.slice(repo.length + 1).split("\\").join("/");
}

function walkProd(dir: string, acc: string[]): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (ent.name.startsWith(".") || ent.name === "node_modules" || ent.name === "generated") continue;
    const abs = join(dir, ent.name);
    if (ent.isDirectory()) {
      walkProd(abs, acc);
      continue;
    }
    if (!/\.(ts|mjs)$/.test(ent.name) || ent.name.includes(".test.") || ent.name.endsWith(".d.ts")) continue;
    acc.push(abs);
  }
}

function envelope(toolName: string, toolInput: Record<string, unknown>): string {
  return JSON.stringify({ tool_name: toolName, tool_input: toolInput });
}

function hookEval(raw: string) {
  const parsed = parseHookEvent(raw);
  if (!parsed) return null;
  return toolInputToEvalFields(parsed.toolName, parsed.toolInput);
}

function caseDirs(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const names = entries.map((e) => e.name);
    if (names.includes("input.json")) {
      found.push(dir);
      return;
    }
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.name === "node_modules" || ent.name === ".git") continue;
      walk(join(dir, ent.name));
    }
  };
  walk(root);
  return found;
}

function corpusPayload(input: Record<string, unknown>): string | null {
  if (typeof input.raw === "string") return input.raw;
  if (typeof input.nativeTool !== "string") return null;
  const toolInput: Record<string, unknown> = {};
  if (typeof input.command === "string") toolInput.command = input.command;
  if (typeof input.filePath === "string") toolInput.file_path = input.filePath;
  if (typeof input.contents === "string") toolInput.contents = input.contents;
  if (typeof input.url === "string") toolInput.url = input.url;
  if (typeof input.dest === "string") toolInput.dest = input.dest;
  if (typeof input.cwd === "string") toolInput.cwd = input.cwd;
  return JSON.stringify({ tool_name: input.nativeTool, tool_input: toolInput });
}

describe("alias table static scan", () => {
  it("flags a copied envelope/tool alias table and ignores a file that only imports the names", () => {
    const counterexample = [
      'const COMMAND_KEYS = ["command", /* decoy */ "cmd"] as const;',
      "const SESSION_ID_KEYS = ['session_id', \"sessionId\", 'conversation_id'] as const;",
      "const TOOL_NAME_KEYS = [\n  \"tool_name\",\n  \"toolName\",\n  \"tool\",\n];",
      'const EVENT_ID_KEYS = ["event_id", "eventId"] as const;',
    ].join("\n");
    const hits = copiedAliasTables(counterexample);
    assert.equal(hits.includes("COMMAND_KEYS"), true);
    assert.equal(hits.includes("SESSION_ID_KEYS"), true);
    assert.equal(hits.includes("TOOL_NAME_KEYS"), true);
    assert.equal(hits.includes("EVENT_ID_KEYS"), true);
    assert.deepEqual(copiedAliasTables('import { SESSION_ID_KEYS, COMMAND_KEYS } from "./hook-alias-keys.ts";\n'), []);
    assert.deepEqual(copiedAliasTables("export const leftover = 1;\n"), []);
    assert.deepEqual(copiedAliasTables('// ["command", "cmd"]\nconst x = 1;\n'), []);
  });

  it("core/ and src/lib/monitor/ production sources keep alias arrays in the truth module only", () => {
    const files: string[] = [];
    walkProd(join(repo, "core"), files);
    walkProd(join(repo, "src", "lib", "monitor"), files);
    assert.ok(files.some((f) => posixRel(f) === TRUTH), "truth module missing from walk");

    const copies: Array<{ file: string; tables: string[] }> = [];
    let truthHits: string[] = [];
    for (const abs of files) {
      const rel = posixRel(abs);
      const source = readFileSync(abs, "utf8");
      const hits = copiedAliasTables(source, rel);
      if (rel === TRUTH) {
        truthHits = hits;
        continue;
      }
      if (hits.length) copies.push({ file: rel, tables: hits });
    }

    assert.equal(truthHits.includes("COMMAND_KEYS"), true);
    assert.equal(truthHits.includes("FILE_PATH_KEYS"), true);
    assert.equal(truthHits.includes("SESSION_ID_KEYS"), true);
    assert.equal(truthHits.includes("TOOL_NAME_KEYS"), true);
    assert.equal(truthHits.includes("EVENT_ID_KEYS"), true);
    assert.equal(truthHits.includes("CONTENT_KEYS"), true);
    assert.equal(truthHits.includes("EVAL_BRIDGE_SESSION_ID_KEYS"), true);
    assert.deepEqual(copies, []);
  });

  it("eval-bridge keeps its existing narrow envelope sets and does not grow them", async () => {
    const keys = await import("./hook-alias-keys.ts");
    assert.deepEqual([...keys.EVAL_BRIDGE_TOOL_NAME_KEYS], ["tool_name", "toolName", "tool", "nativeTool"]);
    assert.deepEqual([...keys.EVAL_BRIDGE_SESSION_ID_KEYS], ["sessionId", "session_id"]);
    assert.deepEqual([...keys.EVAL_BRIDGE_FILE_PATH_KEYS], ["file_path", "filePath"]);
    assert.deepEqual([...keys.TOOL_NAME_KEYS], ["tool_name", "toolName", "tool"]);
    assert.deepEqual([...keys.SESSION_ID_KEYS], ["session_id", "sessionId", "conversation_id"]);
    assert.deepEqual([...keys.EVENT_ID_KEYS], ["eventId", "event_id"]);

    const evalSrc = readFileSync(join(here, "eval-bridge.ts"), "utf8");
    assert.equal(evalSrc.includes("EVAL_BRIDGE_TOOL_NAME_KEYS"), true);
    assert.equal(evalSrc.includes("EVAL_BRIDGE_SESSION_ID_KEYS"), true);
    assert.equal(evalSrc.includes("EVAL_BRIDGE_FILE_PATH_KEYS"), true);
    assert.equal(evalSrc.includes("conversation_id"), false);

    const v2Src = readFileSync(join(here, "protocol/v2-adapter.ts"), "utf8");
    assert.equal(v2Src.includes("SESSION_ID_KEYS"), true);
    assert.equal(v2Src.includes("TOOL_NAME_KEYS"), true);
    assert.equal(v2Src.includes("EVENT_ID_KEYS"), true);
    assert.equal(v2Src.includes("TOOL_USE_ID_KEYS"), true);

    const hookSrc = readFileSync(join(here, "hook-protocol.ts"), "utf8");
    assert.equal(/from\s+["']\.\/hook-alias-keys\.ts["']/.test(hookSrc), true);
    const ingestSrc = readFileSync(join(here, "../src/lib/monitor/ingest.ts"), "utf8");
    assert.equal(ingestSrc.includes("toolInputHasAliasConflict"), true);
    assert.equal(ingestSrc.includes("toolInputToEvalFields"), true);
    assert.equal(ingestSrc.includes("CONTENT_KEYS") || ingestSrc.includes("toolInputToEvalFields"), true);
  });
});

describe("hook vs ingest alias differential", () => {
  it("command aliases agree on present, blank, same value, and conflict", () => {
    for (const key of ["command", "cmd"] as const) {
      const raw = envelope("Bash", { [key]: "echo hello" });
      assert.equal(parseHookPayload(raw)?.command, "echo hello", key);
      assert.equal(hookEval(raw)?.command, "echo hello", key);
    }

    const trimmed = envelope("Bash", { command: "  echo hello  " });
    assert.equal(parseHookPayload(trimmed)?.command, "echo hello");
    assert.equal(hookEval(trimmed)?.command, "echo hello");

    const blankFallsBack = envelope("Bash", { command: "   ", cmd: "echo hello" });
    assert.equal(parseHookPayload(blankFallsBack)?.command, "echo hello");
    assert.equal(hookEval(blankFallsBack)?.command, "echo hello");

    const same = envelope("Bash", { command: "echo hello", cmd: " echo hello " });
    assert.equal(parseHookPayload(same)?.command, "echo hello");
    assert.equal(hookEval(same)?.command, "echo hello");

    const conflict = envelope("Bash", { command: "echo safe", cmd: "echo danger" });
    assert.equal(parseHookPayload(conflict), null);
    assert.equal(parseHookEvent(conflict), null);
  });

  it("file path aliases agree on present, blank, same value, and conflict", () => {
    for (const key of ["file_path", "filePath", "path", "target_file"] as const) {
      const raw = envelope("Read", { [key]: "/tmp/a.txt" });
      assert.equal(parseHookPayload(raw)?.filePath, "/tmp/a.txt", key);
      assert.equal(hookEval(raw)?.filePath, "/tmp/a.txt", key);
    }

    const trimmed = envelope("Read", { file_path: "  /tmp/a.txt  " });
    assert.equal(parseHookPayload(trimmed)?.filePath, "/tmp/a.txt");
    assert.equal(hookEval(trimmed)?.filePath, "/tmp/a.txt");

    const blankFallsBack = envelope("Read", { file_path: "  ", target_file: "/tmp/a.txt" });
    assert.equal(parseHookPayload(blankFallsBack)?.filePath, "/tmp/a.txt");
    assert.equal(hookEval(blankFallsBack)?.filePath, "/tmp/a.txt");

    const same = envelope("Read", { file_path: "/tmp/a.txt", filePath: " /tmp/a.txt " });
    assert.equal(parseHookPayload(same)?.filePath, "/tmp/a.txt");
    assert.equal(hookEval(same)?.filePath, "/tmp/a.txt");

    const conflict = envelope("Read", { file_path: "/tmp/a.txt", target_file: "/tmp/b.txt" });
    assert.equal(parseHookPayload(conflict), null);
    assert.equal(parseHookEvent(conflict), null);
  });

  it("dest aliases agree on present, blank, same value, and conflict", () => {
    for (const key of ["dest", "host", "hostname"] as const) {
      const raw = envelope("snapshot", { [key]: "srv.example" });
      assert.equal(parseHookPayload(raw)?.dest, "srv.example", key);
      assert.equal(hookEval(raw)?.dest, "srv.example", key);
    }

    const trimmed = envelope("snapshot", { dest: "  srv.example  " });
    assert.equal(parseHookPayload(trimmed)?.dest, "srv.example");
    assert.equal(hookEval(trimmed)?.dest, "srv.example");

    const blankFallsBack = envelope("snapshot", { dest: "  ", hostname: "srv.example" });
    assert.equal(parseHookPayload(blankFallsBack)?.dest, "srv.example");
    assert.equal(hookEval(blankFallsBack)?.dest, "srv.example");

    const same = envelope("snapshot", { dest: "srv.example", host: " srv.example " });
    assert.equal(parseHookPayload(same)?.dest, "srv.example");
    assert.equal(hookEval(same)?.dest, "srv.example");

    const conflict = envelope("snapshot", { dest: "srv-a", hostname: "srv-b" });
    assert.equal(parseHookPayload(conflict), null);
    assert.equal(parseHookEvent(conflict), null);
  });

  it("url agrees on present, trim, and blank-as-missing", () => {
    const present = envelope("WebFetch", { url: "https://example.test/p" });
    assert.equal(parseHookPayload(present)?.url, "https://example.test/p");
    assert.equal(hookEval(present)?.url, "https://example.test/p");

    const trimmed = envelope("WebFetch", { url: "  https://example.test/p  " });
    assert.equal(parseHookPayload(trimmed)?.url, "https://example.test/p");
    assert.equal(hookEval(trimmed)?.url, "https://example.test/p");

    const blank = envelope("WebFetch", { url: "   ", dest: "srv.example" });
    assert.equal(parseHookPayload(blank)?.url, undefined);
    assert.equal(hookEval(blank)?.url, undefined);
    assert.equal(parseHookPayload(blank)?.dest, "srv.example");
    assert.equal(hookEval(blank)?.dest, "srv.example");
  });

  it("contents/content: same value and blank agree; both reject a conflict as null", () => {
    const same = envelope("Write", { file_path: "/tmp/a.txt", contents: "hello", content: " hello " });
    assert.equal(parseHookPayload(same)?.contents, "hello");
    assert.equal(hookEval(same)?.contents, "hello");

    const blankFallsBack = envelope("Write", { file_path: "/tmp/a.txt", contents: "   ", content: "hello" });
    assert.equal(parseHookPayload(blankFallsBack)?.contents, "hello");
    assert.equal(hookEval(blankFallsBack)?.contents, "hello");

    const conflict = envelope("Write", { file_path: "/tmp/a.txt", contents: "alpha", content: "beta" });
    assert.equal(parseHookPayload(conflict), null);
    assert.equal(parseHookEvent(conflict), null);
  });

  it("replacement/file_text/prompt are scanned on both paths", () => {
    for (const key of ["replacement", "file_text", "prompt"] as const) {
      const extraOnly = envelope("Write", { file_path: "/tmp/a.txt", [key]: "hook-only-body" });
      assert.equal(parseHookPayload(extraOnly)?.contents, "hook-only-body", key);
      assert.equal(hookEval(extraOnly)?.contents, "hook-only-body", key);
    }

    const mixed = envelope("Write", { file_path: "/tmp/a.txt", contents: "keep", prompt: "hook-extra" });
    assert.equal(parseHookPayload(mixed)?.contents, "keep\nhook-extra");
    assert.equal(hookEval(mixed)?.contents, "keep\nhook-extra");
  });

  it("cwd uses working_directory/workingDirectory/cwd on both paths", () => {
    const sharedCwd = envelope("Bash", { command: "echo hello", cwd: "/tmp/shared" });
    assert.equal(parseHookPayload(sharedCwd)?.cwd, "/tmp/shared");
    assert.equal(hookEval(sharedCwd)?.cwd, "/tmp/shared");

    const sharedWorkingDirectory = envelope("Bash", { command: "echo hello", workingDirectory: "/tmp/wd" });
    assert.equal(parseHookPayload(sharedWorkingDirectory)?.cwd, "/tmp/wd");
    assert.equal(hookEval(sharedWorkingDirectory)?.cwd, "/tmp/wd");

    const hookCwd = envelope("Bash", { command: "echo hello", working_directory: "/tmp/hook-cwd" });
    assert.equal(parseHookPayload(hookCwd)?.cwd, "/tmp/hook-cwd");
    assert.equal(hookEval(hookCwd)?.cwd, "/tmp/hook-cwd");

    const workdirIsNotCwd = envelope("Bash", { command: "echo hello", workdir: "/tmp/ingest-only" });
    assert.equal(parseHookPayload(workdirIsNotCwd)?.cwd, undefined);
    assert.equal(hookEval(workdirIsNotCwd)?.cwd, undefined);

    const cwdConflict = envelope("Bash", { command: "echo hello", cwd: "/tmp/a", working_directory: "/tmp/b" });
    assert.equal(parseHookPayload(cwdConflict), null);
    assert.equal(parseHookEvent(cwdConflict), null);

    const blankShared = envelope("Bash", { command: "echo hello", cwd: "  ", workingDirectory: "/tmp/wd" });
    assert.equal(parseHookPayload(blankShared)?.cwd, "/tmp/wd");
    assert.equal(hookEval(blankShared)?.cwd, "/tmp/wd");

    const sameShared = envelope("Bash", { command: "echo hello", cwd: "/tmp/wd", workingDirectory: " /tmp/wd " });
    assert.equal(parseHookPayload(sameShared)?.cwd, "/tmp/wd");
    assert.equal(hookEval(sameShared)?.cwd, "/tmp/wd");
  });

  it("edits[] contents/content conflict is null; matching edits concatenate operands", () => {
    const editConflict = envelope("MultiEdit", {
      file_path: "/tmp/a.txt",
      edits: [{ contents: "safe", content: "rm -rf ~" }],
    });
    assert.equal(parseHookPayload(editConflict), null);
    assert.equal(parseHookEvent(editConflict), null);

    const editOk = envelope("MultiEdit", {
      file_path: "/tmp/a.txt",
      edits: [{ old_string: "alpha", new_string: "beta" }],
    });
    assert.equal(parseHookPayload(editOk)?.contents, "beta\nalpha");
    assert.equal(hookEval(editOk)?.contents, "beta\nalpha");
  });

  it("nested-only tool_input leaf is contents on both paths", () => {
    const raw = envelope("Write", { nested: { value: "synthetic-marker" } });
    assert.equal(parseHookPayload(raw)?.contents, "synthetic-marker");
    assert.equal(hookEval(raw)?.contents, "synthetic-marker");
    const withMeta = JSON.stringify({
      tool_name: "Write",
      agent: "zcode",
      sessionId: "sess-meta",
      tool_input: { nested: { value: "synthetic-marker" } },
    });
    assert.equal(parseHookPayload(withMeta)?.contents, "synthetic-marker");
    assert.equal(hookEval(withMeta)?.contents, "synthetic-marker");
  });

  it("workdir-only tool_input is a content leaf, not cwd", () => {
    const raw = envelope("Write", { workdir: "/tmp/wd-only" });
    const ingest = parseHookPayload(raw);
    const hook = hookEval(raw);
    assert.equal(ingest?.cwd, undefined);
    assert.equal(hook?.cwd, undefined);
    assert.equal(ingest?.contents, "/tmp/wd-only");
    assert.equal(hook?.contents, "/tmp/wd-only");
  });

  it("patch-array-only tool_input is scanned on both paths", () => {
    const raw = envelope("Write", { patch: ["literal-patch-hunk"] });
    assert.equal(parseHookPayload(raw)?.contents, "literal-patch-hunk");
    assert.equal(hookEval(raw)?.contents, "literal-patch-hunk");
  });

  it("nested leaves are scanned on both paths without promoting nested path", () => {
    const raw = envelope("WebFetch", {
      url: "https://example.test/p",
      headers: { Authorization: "Bearer nested-token" },
      meta: { path: "/etc/shadow" },
    });
    const ingest = parseHookPayload(raw);
    const hook = hookEval(raw);
    assert.equal(ingest?.url, "https://example.test/p");
    assert.equal(hook?.url, "https://example.test/p");
    assert.equal(ingest?.filePath, undefined);
    assert.equal(hook?.filePath, undefined);
    assert.equal(ingest?.contents?.includes("Bearer nested-token"), true);
    assert.equal(hook?.contents?.includes("Bearer nested-token"), true);
    assert.equal(ingest?.contents?.includes("/etc/shadow"), true);
    assert.equal(hook?.contents?.includes("/etc/shadow"), true);
  });

  it("ingest keeps extra bags and rejects envelope vs bag filePath conflict", () => {
    const viaArgs = parseHookPayload(JSON.stringify({ tool: "Bash", arguments: { command: "echo via-args" } }));
    assert.equal(viaArgs?.command, "echo via-args");
    const viaParams = parseHookPayload(JSON.stringify({ tool: "Bash", params: { command: "echo via-params" } }));
    assert.equal(viaParams?.command, "echo via-params");
    const viaEvent = parseHookPayload(JSON.stringify({ tool: "Bash", event: { command: "echo via-event" } }));
    assert.equal(viaEvent?.command, "echo via-event");
    assert.equal(
      parseHookPayload(JSON.stringify({ file_path: "/tmp/a.txt", toolInput: { target_file: "/tmp/b.txt" } })),
      null,
    );
  });

  it("standard hook envelopes independently reject alias conflicts on both parsers", () => {
    const commandConflict = envelope("Bash", { command: "echo a", cmd: "echo b" });
    assert.equal(parseHookPayload(commandConflict), null);
    assert.equal(parseHookEvent(commandConflict), null);

    const contentConflict = envelope("Write", { file_path: "/tmp/a.txt", contents: "alpha", content: "beta" });
    assert.equal(parseHookPayload(contentConflict), null);
    assert.equal(parseHookEvent(contentConflict), null);

    const pathConflict = envelope("Read", { file_path: "/tmp/a.txt", target_file: "/tmp/b.txt" });
    assert.equal(parseHookPayload(pathConflict), null);
    assert.equal(parseHookEvent(pathConflict), null);
  });

  it("443 corpus toolInput contents and conflict match on both paths", () => {
    const specRoot = join(repo, "policy-spec");
    const dirs = caseDirs(specRoot).filter((dir) => {
      const id = dir.slice(specRoot.length + 1).split("\\").join("/");
      return CORPUS_CATEGORIES.includes(id.split("/")[0] ?? "");
    });
    assert.equal(dirs.length, 443);

    let compared = 0;
    for (const dir of dirs) {
      const input = JSON.parse(readFileSync(join(dir, "input.json"), "utf8")) as Record<string, unknown>;
      let wrapped: string;
      if (typeof input.raw === "string") {
        const extracted = parseHookEvent(input.raw);
        assert.ok(extracted, `host-normalization raw must parse for field wrap: ${dir}`);
        wrapped = JSON.stringify({ tool_name: extracted.toolName, tool_input: extracted.toolInput });
      } else {
        const built = corpusPayload(input);
        assert.ok(built, `corpus case must wrap: ${dir}`);
        wrapped = built;
      }
      const ingest = parseHookPayload(wrapped);
      const parsed = parseHookEvent(wrapped);
      const hook = parsed ? toolInputToEvalFields(parsed.toolName, parsed.toolInput) : null;
      if (ingest === null && hook === null) {
        assert.equal(parsed, null, dir);
      } else {
        assert.ok(ingest, dir);
        assert.ok(parsed, dir);
        assert.ok(hook, dir);
        assert.equal(ingest!.contents, hook!.contents, dir);
        assert.equal(ingest!.command, hook!.command, dir);
        assert.equal(ingest!.filePath, hook!.filePath, dir);
        assert.equal(ingest!.url, hook!.url, dir);
        assert.equal(ingest!.dest, hook!.dest, dir);
      }
      compared += 1;
    }
    assert.equal(compared, 443);
  });

  it("host-normalization original envelopes are parsed independently", () => {
    const specRoot = join(repo, "policy-spec", "host-normalization");
    const dirs = caseDirs(specRoot);
    assert.ok(dirs.length > 0);
    for (const dir of dirs) {
      const input = JSON.parse(readFileSync(join(dir, "input.json"), "utf8")) as { raw?: string };
      assert.equal(typeof input.raw, "string", dir);
      const ingest = parseHookPayload(input.raw!);
      const hook = parseHookEvent(input.raw!);
      if (input.raw!.includes('"toolCall"')) {
        assert.ok(hook, dir);
        assert.equal(ingest, null, `ingest does not parse Antigravity toolCall: ${dir}`);
        continue;
      }
      assert.ok(hook, dir);
      assert.ok(ingest, dir);
      const fields = toolInputToEvalFields(hook!.toolName, hook!.toolInput);
      assert.equal(ingest!.command, fields.command, dir);
      assert.equal(ingest!.contents, fields.contents, dir);
      assert.equal(ingest!.filePath, fields.filePath, dir);
    }
  });
});

describe("observation vs canonical carriers", () => {
  it("observation rejects eventId vs tool_use_id; hook keeps eventId priority", () => {
    const raw = JSON.stringify({ tool: "Bash", command: "echo ok", eventId: "A", tool_use_id: "B" });
    assert.equal(parseHookPayload(raw), null);
    const hook = parseHookEvent(raw);
    assert.ok(hook);
    assert.equal(hook!.eventId, "A");

    const same = JSON.stringify({ tool: "Bash", command: "echo ok", eventId: "A", tool_use_id: "A" });
    assert.equal(parseHookPayload(same)?.eventId, "A");
    assert.equal(parseHookEvent(same)?.eventId, "A");

    const eventOnly = JSON.stringify({ tool: "Bash", command: "echo ok", eventId: "A" });
    assert.equal(parseHookPayload(eventOnly)?.eventId, "A");

    const toolUseOnly = JSON.stringify({ tool: "Bash", command: "echo ok", tool_use_id: "B" });
    assert.equal(parseHookPayload(toolUseOnly)?.eventId, "B");

    const snakeVsCamel = JSON.stringify({ tool: "Bash", command: "echo ok", event_id: "A", toolUseId: "B" });
    assert.equal(parseHookPayload(snakeVsCamel), null);
    assert.equal(parseHookEvent(snakeVsCamel)?.eventId, "A");

    const callId = JSON.stringify({ tool: "Bash", command: "echo ok", eventId: "A", tool_call_id: "C" });
    assert.equal(parseHookPayload(callId), null);
    assert.equal(parseHookEvent(callId)?.eventId, "A");
  });

  it("observation envelope and extra bags restore workdir cwd and conflict with cwd", () => {
    const topWorkdir = parseHookPayload(JSON.stringify({ tool: "Bash", command: "echo ok", workdir: "/tmp/a" }));
    assert.equal(topWorkdir?.cwd, "/tmp/a");
    assert.equal(topWorkdir?.contents, undefined);

    assert.equal(
      parseHookPayload(JSON.stringify({ tool: "Bash", command: "echo ok", workdir: "/tmp/a", cwd: "/tmp/b" })),
      null,
    );
    assert.equal(
      parseHookPayload(
        JSON.stringify({ tool: "Bash", command: "echo ok", workdir: "/tmp/a", workingDirectory: "/tmp/b" }),
      ),
      null,
    );
    assert.equal(
      parseHookPayload(
        JSON.stringify({ tool: "Bash", command: "echo ok", workdir: "/tmp/a", working_directory: "/tmp/b" }),
      ),
      null,
    );

    const sameCwd = parseHookPayload(
      JSON.stringify({ tool: "Bash", command: "echo ok", workdir: "/tmp/a", cwd: "/tmp/a" }),
    );
    assert.equal(sameCwd?.cwd, "/tmp/a");

    const viaArgs = parseHookPayload(
      JSON.stringify({ tool: "Bash", arguments: { command: "echo ok", workdir: "/tmp/a" } }),
    );
    assert.equal(viaArgs?.cwd, "/tmp/a");
    assert.equal(viaArgs?.contents, undefined);
    const viaParams = parseHookPayload(
      JSON.stringify({ tool: "Bash", params: { command: "echo ok", workdir: "/tmp/a" } }),
    );
    assert.equal(viaParams?.cwd, "/tmp/a");
    const viaEvent = parseHookPayload(
      JSON.stringify({ tool: "Bash", event: { command: "echo ok", workdir: "/tmp/a" } }),
    );
    assert.equal(viaEvent?.cwd, "/tmp/a");

    assert.equal(
      parseHookPayload(
        JSON.stringify({
          tool: "Bash",
          command: "echo ok",
          cwd: "/tmp/b",
          arguments: { command: "echo ok", workdir: "/tmp/a" },
        }),
      ),
      null,
    );

    const extraWorkingDirectory = parseHookPayload(
      JSON.stringify({ tool: "Bash", arguments: { command: "echo ok", workingDirectory: "/tmp/wd" } }),
    );
    assert.equal(extraWorkingDirectory?.cwd, "/tmp/wd");
    const envelopeWorkingDirectory = parseHookPayload(
      JSON.stringify({ tool: "Bash", command: "echo ok", workingDirectory: "/tmp/wd" }),
    );
    assert.equal(envelopeWorkingDirectory?.cwd, "/tmp/wd");
    assert.equal(
      parseHookPayload(
        JSON.stringify({
          tool: "Bash",
          workdir: "/tmp/a",
          arguments: { command: "echo ok", workingDirectory: "/tmp/b" },
        }),
      ),
      null,
    );
  });

  it("canonical tool bags keep workdir as a content leaf and still scan nested/patch", () => {
    const canonicalWorkdir = parseHookPayload(
      JSON.stringify({ tool: "Bash", command: "echo ok", tool_input: { command: "echo ok", workdir: "/tmp/a" } }),
    );
    assert.equal(canonicalWorkdir?.cwd, undefined);
    assert.equal(canonicalWorkdir?.contents, "/tmp/a");

    const viaToolInput = parseHookPayload(
      JSON.stringify({ tool_name: "Bash", toolInput: { command: "echo ok", workdir: "/tmp/ingest-only" } }),
    );
    assert.equal(viaToolInput?.cwd, undefined);
    assert.equal(viaToolInput?.contents, "/tmp/ingest-only");

    const viaInput = parseHookPayload(
      JSON.stringify({ tool: "Bash", command: "echo ok", input: { command: "echo ok", workdir: "/tmp/a" } }),
    );
    assert.equal(viaInput?.cwd, undefined);
    assert.equal(viaInput?.contents, "/tmp/a");

    const envelopeCwdCanonicalWorkdir = parseHookPayload(
      JSON.stringify({
        tool: "Bash",
        cwd: "/tmp/b",
        tool_input: { command: "echo ok", workdir: "/tmp/a" },
      }),
    );
    assert.equal(envelopeCwdCanonicalWorkdir?.cwd, "/tmp/b");
    assert.equal(envelopeCwdCanonicalWorkdir?.contents, "/tmp/a");

    const nested = parseHookPayload(envelope("Write", { nested: { value: "synthetic-marker" } }));
    assert.equal(nested?.contents, "synthetic-marker");
    const patch = parseHookPayload(envelope("Write", { patch: ["literal-patch-hunk"] }));
    assert.equal(patch?.contents, "literal-patch-hunk");
    const workdirOnly = parseHookPayload(envelope("Write", { workdir: "/tmp/wd-only" }));
    assert.equal(workdirOnly?.cwd, undefined);
    assert.equal(workdirOnly?.contents, "/tmp/wd-only");
  });

  it("observation extra bags exclude envelope metadata from contents", () => {
    const viaArgs = parseHookPayload(
      JSON.stringify({ tool: "Write", contents: "hello", arguments: { contents: "hello", sessionId: "s1" } }),
    );
    assert.equal(viaArgs?.contents, "hello");
    assert.equal(viaArgs?.sessionId, "s1");

    const viaParams = parseHookPayload(
      JSON.stringify({ tool: "Write", contents: "hello", params: { contents: "hello", session_id: "s1" } }),
    );
    assert.equal(viaParams?.contents, "hello");
    assert.equal(viaParams?.sessionId, "s1");

    const viaEvent = parseHookPayload(
      JSON.stringify({ tool: "Write", contents: "hello", event: { contents: "hello", session: "s1" } }),
    );
    assert.equal(viaEvent?.contents, "hello");
    assert.equal(viaEvent?.sessionId, "s1");

    const viaConversation = parseHookPayload(
      JSON.stringify({
        tool: "Write",
        contents: "hello",
        arguments: { contents: "hello", conversation_id: "c1" },
      }),
    );
    assert.equal(viaConversation?.contents, "hello");
    assert.equal(viaConversation?.sessionId, "c1");

    const viaEventId = parseHookPayload(
      JSON.stringify({ tool: "Write", contents: "hello", arguments: { contents: "hello", eventId: "E1" } }),
    );
    assert.equal(viaEventId?.contents, "hello");
    assert.equal(viaEventId?.eventId, "E1");

    const viaToolUse = parseHookPayload(
      JSON.stringify({ tool: "Write", contents: "hello", arguments: { contents: "hello", tool_use_id: "TU1" } }),
    );
    assert.equal(viaToolUse?.contents, "hello");
    assert.equal(viaToolUse?.eventId, "TU1");

    assert.equal(
      parseHookPayload(
        JSON.stringify({
          tool: "Write",
          contents: "hello",
          sessionId: "s0",
          arguments: { contents: "hello", sessionId: "s1" },
        }),
      ),
      null,
    );
  });

  it("observation hookBlind metadata stays outside contents while canonical leaves remain scanned", () => {
    for (const carrier of ["arguments", "params", "event"]) {
      for (const key of ["hookBlind", "hook_blind"]) {
        const result = parseHookPayload(JSON.stringify({
          tool: "Write", contents: "hello", [carrier]: { contents: "hello", [key]: "true" },
        }));
        assert.equal(result?.contents, "hello");
        assert.equal(result?.hookBlind, true);
      }
    }
    const canonical = parseHookPayload(JSON.stringify({
      tool: "Write", tool_input: { contents: "hello", hookBlind: "true" },
    }));
    assert.equal(canonical?.contents, "hello\ntrue");
  });

  it("canonical tool bags still scan unknown string leaves including sessionId", () => {
    const canonicalSession = parseHookPayload(
      JSON.stringify({ tool: "Write", tool_input: { contents: "hello", sessionId: "s1" } }),
    );
    assert.equal(canonicalSession?.contents, "hello\ns1");
    assert.equal(canonicalSession?.sessionId, "s1");

    const canonicalConversation = parseHookPayload(
      JSON.stringify({ tool_name: "Write", toolInput: { contents: "hello", conversation_id: "c1" } }),
    );
    assert.equal(canonicalConversation?.contents, "hello\nc1");
    assert.equal(canonicalConversation?.sessionId, "c1");

    const canonicalEvent = parseHookPayload(
      JSON.stringify({ tool: "Write", input: { contents: "hello", eventId: "E1" } }),
    );
    assert.equal(canonicalEvent?.contents, "hello\nE1");
    assert.equal(canonicalEvent?.eventId, "E1");
  });

  it("observation extra bags still extract replacement/file_text/prompt, nested, and patch", () => {
    const replacement = parseHookPayload(
      JSON.stringify({ tool: "Write", arguments: { replacement: "via-args-repl" } }),
    );
    assert.equal(replacement?.contents, "via-args-repl");
    const fileText = parseHookPayload(JSON.stringify({ tool: "Write", params: { file_text: "via-params-text" } }));
    assert.equal(fileText?.contents, "via-params-text");
    const prompt = parseHookPayload(JSON.stringify({ tool: "Write", event: { prompt: "via-event-prompt" } }));
    assert.equal(prompt?.contents, "via-event-prompt");

    const nested = parseHookPayload(
      JSON.stringify({ tool: "Write", arguments: { contents: "keep", nested: { value: "obs-nested" } } }),
    );
    assert.equal(nested?.contents, "keep\nobs-nested");

    const patch = parseHookPayload(
      JSON.stringify({ tool: "Write", arguments: { patch: ["obs-patch-hunk"] } }),
    );
    assert.equal(patch?.contents, "obs-patch-hunk");

    const mixed = parseHookPayload(
      JSON.stringify({
        tool: "Write",
        arguments: { contents: "keep", prompt: "hook-extra", sessionId: "s1" },
      }),
    );
    assert.equal(mixed?.contents, "keep\nhook-extra");
    assert.equal(mixed?.sessionId, "s1");
  });

  it("top vs extra bag operational conflicts still reject", () => {
    assert.equal(
      parseHookPayload(JSON.stringify({ file_path: "/tmp/a.txt", arguments: { target_file: "/tmp/b.txt" } })),
      null,
    );
    assert.equal(
      parseHookPayload(JSON.stringify({ tool: "Write", contents: "hello", arguments: { contents: "other" } })),
      null,
    );
    assert.equal(
      parseHookPayload(
        JSON.stringify({ tool: "Bash", command: "echo ok", params: { command: "echo other" } }),
      ),
      null,
    );
  });
});
