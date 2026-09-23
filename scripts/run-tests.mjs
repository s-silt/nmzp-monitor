#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const SKIP = new Set(["node_modules", "dist", ".pack", ".output", ".nitro", ".vercel", ".git"]);

async function walk(dir, acc) {
  let ents;
  try {
    ents = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of ents) {
    if (SKIP.has(e.name) || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, acc);
    else if (/\.(test|spec)\.(ts|mts|js|mjs|cjs)$/.test(e.name)) acc.push(p);
  }
}

export async function collectTestFiles(dir) {
  const acc = [];
  await walk(dir, acc);
  acc.sort();
  return acc;
}

export function runTests(files, options = {}) {
  const spawnImpl = options.spawnImpl ?? spawn;
  const exit = options.exit ?? ((code) => process.exit(code));
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const kill = options.kill ?? ((signal) => process.kill(process.pid, signal));
  const execPath = options.execPath ?? process.execPath;
  const cwd = options.cwd ?? root;
  const env = options.env ?? process.env;
  if (!files.length) {
    stderr.write("run-tests: no tests found\n");
    exit(1);
    return undefined;
  }
  stdout.write(`run-tests: ${files.length} files\n${files.map((f) => f.slice(root.length + 1)).join("\n")}\n`);
  const child = spawnImpl(
    execPath,
    ["--experimental-strip-types", "--test", "--test-concurrency=1", "--test-timeout=60000", ...files],
    {
      stdio: options.stdio ?? "inherit",
      cwd,
      env,
      windowsHide: true,
    },
  );
  child.on("exit", (code, signal) => {
    if (signal) kill(signal);
    exit(code ?? 1);
  });
  return child;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return import.meta.url === pathToFileURL(entry).href;
  }
}

if (invokedDirectly()) {
  const files = await collectTestFiles(root);
  runTests(files);
}
