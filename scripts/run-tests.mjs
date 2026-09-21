#!/usr/bin/env node
import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const SKIP = new Set(["node_modules", "dist", ".pack", ".output", ".nitro", ".vercel", ".git"]);

async function collect(dir, acc) {
  let ents;
  try {
    ents = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of ents) {
    if (SKIP.has(e.name) || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await collect(p, acc);
    else if (/\.(test|spec)\.(ts|mts|js|mjs|cjs)$/.test(e.name)) acc.push(p);
  }
}

const files = [];
await collect(root, files);
files.sort();
if (!files.length) {
  process.stderr.write("run-tests: no tests found\n");
  process.exit(1);
}
process.stdout.write(`run-tests: ${files.length} files\n${files.map((f) => f.slice(root.length + 1)).join("\n")}\n`);
const child = spawn(process.execPath, ["--experimental-strip-types", "--test", "--test-timeout=60000", ...files], {
  stdio: "inherit",
  cwd: root,
  windowsHide: true,
});
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
