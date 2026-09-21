/** Child-only read-only snapshot status. Prints one public JSON object to stdout. */
import { snapshotGuardStatus, publicSnapshotGuardStatus } from "./snapshot-guard.ts";

function argHome(argv: string[]): string | undefined {
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--home" && argv[i + 1]) return argv[i + 1];
  }
  return undefined;
}

const home = argHome(process.argv.slice(2));
if (!home || home.includes("\0") || home === "[object Object]") {
  process.stdout.write(`${JSON.stringify({ error: "path_invalid" })}\n`);
  process.exit(1);
}

try {
  const st = await snapshotGuardStatus({ home });
  process.stdout.write(`${JSON.stringify(publicSnapshotGuardStatus(st))}\n`);
  process.exit(0);
} catch {
  process.stdout.write(`${JSON.stringify({ error: "status_failed" })}\n`);
  process.exit(1);
}
