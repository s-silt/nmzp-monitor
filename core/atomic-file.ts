import { renameSync, unlinkSync, writeFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

function discardOwnTemp(path: string): void {
  try { unlinkSync(path); } catch { /* Never remove the destination after a failed rename. */ }
}

export async function atomicWrite(path: string, data: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  await writeFile(temporary, data, { mode });
  try { renameSync(temporary, path); }
  catch (error) { discardOwnTemp(temporary); throw error instanceof Error ? error : new Error("atomic_write_failed"); }
}

export function atomicReplaceSync(path: string, data: string, mode = 0o600): void {
  const temporary = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  writeFileSync(temporary, data, { mode });
  try { renameSync(temporary, path); }
  catch (error) { discardOwnTemp(temporary); throw error instanceof Error ? error : new Error("atomic_write_failed"); }
}
