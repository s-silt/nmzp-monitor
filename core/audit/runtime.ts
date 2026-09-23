import { Worker } from "node:worker_threads";
import type { Enforcement, StoredEvent } from "../schema.ts";
import type { AuditQuery, AuditRetention, AuditStore } from "./store.ts";
import { AuditWorkerChannel } from "./worker-channel.ts";

/** Live audit I/O facade. The channel owns only worker lifecycle, not storage policy. */
export class AuditRuntime {
  readonly #channel: AuditWorkerChannel;

  private constructor(channel: AuditWorkerChannel) {
    this.#channel = channel;
  }

  static async open(path: string, options: { create?: boolean; readOnly?: boolean; retention?: AuditRetention } = {}): Promise<AuditRuntime> {
    const worker = new Worker(new URL("./runtime-worker.ts", import.meta.url), {
      execArgv: ["--experimental-strip-types"],
      workerData: { path, create: options.create === true, readOnly: options.readOnly === true, retention: options.retention ?? {} },
    });
    return new AuditRuntime(await AuditWorkerChannel.open(worker));
  }

  append(event: StoredEvent): ReturnType<AuditStore["append"]> { return this.#channel.call("append", event); }
  get(machineId: string, id: string): ReturnType<AuditStore["get"]> { return this.#channel.call("get", machineId, id); }
  recent(limit: number): ReturnType<AuditStore["recent"]> { return this.#channel.call("recent", limit); }
  query(input: AuditQuery): ReturnType<AuditStore["query"]> { return this.#channel.call("query", input); }
  status(): Promise<ReturnType<AuditStore["status"]>> { return this.#channel.call("status"); }
  maintenanceStep(): Promise<ReturnType<AuditStore["maintenanceStep"]>> { return this.#channel.call("maintenance"); }
  deletionHighWatermark(): Promise<number> { return this.#channel.call("deletionHighWatermark"); }
  deletionCountAfter(deletionId: number, highWatermark: number): Promise<number> {
    return this.#channel.call("deletionCountAfter", deletionId, highWatermark);
  }
  getTombstone(machineId: string, id: string): ReturnType<AuditStore["getTombstone"]> {
    return this.#channel.call("getTombstone", machineId, id);
  }
  updateReceipt(machineId: string, id: string, enforcement: Enforcement): ReturnType<AuditStore["updateReceipt"]> {
    return this.#channel.call("updateReceipt", machineId, id, enforcement);
  }
  confirmBackfillReceipt(machineId: string, id: string, evaluation: string, enforcement: Enforcement):
    ReturnType<AuditStore["confirmBackfillReceipt"]> {
    return this.#channel.call("confirmBackfillReceipt", machineId, id, evaluation, enforcement);
  }
  clear(): Promise<number> { return this.#channel.call("clear"); }

  close(): Promise<void> {
    return this.#channel.close();
  }
}
