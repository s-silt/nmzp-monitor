import { closeSync, fstatSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";
import { randomUUID } from "node:crypto";

/** Cooperating processes only. No age/PID-based stealing; crash leftovers need offline review. */
export class PolicyWriterLease {
  readonly #path: string;
  readonly #fd: number;
  #closed = false;
  readonly #exit = () => { this.close(); };

  constructor(path: string) {
    this.#path = path;
    try { this.#fd = openSync(path, "wx", 0o600); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("policy_writer_busy");
      throw new Error("policy_writer_unavailable");
    }
    try { writeSync(this.#fd, JSON.stringify({ pid: process.pid, owner: randomUUID() })); }
    catch { this.close(); throw new Error("policy_writer_unavailable"); }
    process.once("exit", this.#exit);
  }

  assertOwned(): void {
    if (this.#closed) throw new Error("policy_writer_closed");
    try {
      const held = fstatSync(this.#fd);
      const named = lstatSync(this.#path);
      if (!named.isFile() || named.isSymbolicLink() || held.dev !== named.dev || held.ino !== named.ino) {
        throw new Error("identity");
      }
    } catch { throw new Error("policy_recovery_required"); }
  }

  close(): void {
    if (this.#closed) return;
    process.off("exit", this.#exit);
    try { this.assertOwned(); unlinkSync(this.#path); } catch { /* Never remove a replacement owner's lock. */ }
    this.#closed = true;
    closeSync(this.#fd);
  }
}
