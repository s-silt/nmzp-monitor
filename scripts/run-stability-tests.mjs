#!/usr/bin/env node
import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Explicit allowlist: adding a file requires reviewing its imports and side
// effects. No recursive test discovery, npm lifecycle scripts, or host ACL work.
const FILES = Object.freeze([
  "core/audit/worker-channel.test.mjs",
  "core/audit/runtime-drain.test.mjs",
  "core/audit/runtime.test.mjs",
  "core/audit/json-codec.test.ts",
  "core/audit/recent-events.test.ts",
]);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--list")) {
  process.stderr.write("Usage: node scripts/run-stability-tests.mjs [--list]\n");
  process.exitCode = 2;
} else {
  try {
    const canonicalRoot = await realpath(root);
    for (const file of FILES) {
      const path = resolve(root, file);
      const info = await lstat(path);
      const inside = relative(canonicalRoot, await realpath(path));
      if (!info.isFile() || info.isSymbolicLink() || isAbsolute(inside) || inside === ".." || inside.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) {
        throw new Error(`Invalid stability test path: ${file}`);
      }
    }
    process.stdout.write(`Core audit stability: ${FILES.length} explicitly selected files\n${FILES.join("\n")}\n`);
    if (args[0] !== "--list") {
      if (Number(process.versions.node.split(".")[0]) < 24) {
        throw new Error("Node.js >=24 is required; this runner does not lower the project requirement");
      }
      const exitCode = await new Promise((resolveExit, reject) => {
        const child = spawn(process.execPath, [
          "--experimental-strip-types", "--test", "--test-concurrency=2", "--test-timeout=60000", ...FILES,
        ], { cwd: root, stdio: "inherit", shell: false, windowsHide: true });
        child.once("error", reject);
        child.once("exit", (code, signal) => {
          if (signal) process.stderr.write(`Stability tests terminated by ${signal}\n`);
          resolveExit(code ?? 1);
        });
      });
      process.exitCode = exitCode;
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Stability runner failed"}\n`);
    process.exitCode = 1;
  }
}
