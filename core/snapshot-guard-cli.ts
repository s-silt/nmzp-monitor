import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseSnapshotGuardCli,
  publicSnapshotGuardStatus,
  snapshotGuardApply,
  snapshotGuardRestore,
  snapshotGuardStatus,
} from "./snapshot-guard.ts";

export async function snapshotGuardCliMain(argv: string[]): Promise<number> {
  const parsed = parseSnapshotGuardCli(argv);
  if (!parsed.ok) {
    process.stderr.write(`${parsed.error}\n`);
    return 2;
  }
  const fn =
    parsed.cmd === "status" ? snapshotGuardStatus : parsed.cmd === "apply" ? snapshotGuardApply : snapshotGuardRestore;
  const status = await fn({ home: parsed.home });
  process.stdout.write(`${JSON.stringify(publicSnapshotGuardStatus(status))}\n`);
  if (parsed.cmd === "status") return 0;
  if (parsed.cmd === "restore") return status.error ? 1 : 0;
  if (status.error || !status.active) return 1;
  return 0;
}

function isCliEntrypoint(metaUrl: string, argv1?: string): boolean {
  if (!argv1) return false;
  try {
    return resolve(fileURLToPath(metaUrl)).toLowerCase() === resolve(argv1).toLowerCase();
  } catch {
    return false;
  }
}

if (isCliEntrypoint(import.meta.url, process.argv[1])) {
  process.exit(await snapshotGuardCliMain(process.argv.slice(2)));
}
