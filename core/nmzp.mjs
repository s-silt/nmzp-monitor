#!/usr/bin/env node
/**
 * Entry only. Body limit: 413 when n > INGEST_MAX_RAW (core/constants.ts BODY_LIMIT).
 * Probe: hasJoined; otherwise fail("not joined"). Join is one-shot, no popup.
 * Hook bootstrap failures use EMERGENCY_DENY and do not import protocol modules.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { emergencyDeny } from "./hook-emergency-deny.mjs";

async function emitEmergency(denial) {
  await new Promise((resolve) => {
    process.stdout.write(denial.stdout, () => {
      if (!denial.stderr) return resolve();
      process.stderr.write(denial.stderr, () => resolve());
    });
  });
  process.exit(denial.exitCode);
}

const flagged =
  process.execArgv.some((a) => a.includes("strip-types")) ||
  /\bstrip-types\b/.test(process.env.NODE_OPTIONS ?? "");

const self = fileURLToPath(import.meta.url);
const bundledMain = join(dirname(self), "nmzp-main.cjs");

if (existsSync(bundledMain)) {
  try {
    const loaded = createRequire(import.meta.url)(bundledMain);
    const main = loaded && (loaded.main || (loaded.default && loaded.default.main));
    if (typeof main !== "function") throw new Error("nmzp_main_missing");
    await main(process.argv.slice(2));
  } catch (err) {
    const argv = process.argv.slice(2);
    if (argv[0] === "hook") await emitEmergency(emergencyDeny(argv));
    else throw err;
  }
} else if (!flagged) {
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", self, ...process.argv.slice(2)],
    {
      stdio: "inherit",
      windowsHide: true,
    },
  );
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
} else {
  try {
    const { main } = await import("./cli.ts");
    await main(process.argv.slice(2));
  } catch (err) {
    const argv = process.argv.slice(2);
    if (argv[0] === "hook") await emitEmergency(emergencyDeny(argv));
    else throw err;
  }
}
