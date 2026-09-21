#!/usr/bin/env node
/**
 * Entry only. Body limit: 413 when n > INGEST_MAX_RAW (core/constants.ts BODY_LIMIT).
 * Probe: hasJoined; otherwise fail("not joined"). Join is one-shot, no popup.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const flagged =
  process.execArgv.some((a) => a.includes("strip-types")) ||
  /\bstrip-types\b/.test(process.env.NODE_OPTIONS ?? "");

if (!flagged) {
  const self = fileURLToPath(import.meta.url);
  const child = spawn(process.execPath, ["--experimental-strip-types", self, ...process.argv.slice(2)], {
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
} else {
  const { main } = await import("./cli.ts");
  await main(process.argv.slice(2));
}
