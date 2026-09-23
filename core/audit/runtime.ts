import { Worker } from "node:worker_threads";
import type { Enforcement, StoredEvent } from "../schema.ts";
import type { AuditQuery, AuditRetention, AuditStore } from "./store.ts";

type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> };
const MAX_PENDING = 32;
const OPERATION_TIMEOUT_MS = 30_000;

/** Live audit I/O lane. Offline migration can use AuditStore directly. */
export class AuditRuntime {
  readonly #worker: Worker;
  readonly #pending = new Map<number, Pending>();
  #nextId = 0;
  #closed = false;
  #failure: Error | undefined;

  private constructor(worker: Worker) {
    this.#worker = worker;
    worker.on("message", (message: { id?: number; value?: unknown; error?: string }) => {
      if (message.id === undefined) return;
      const pending = this.#pending.get(message.id);
      if (!pending) return;
      this.#pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(message.error));
      else pending.resolve(message.value);
    });
    worker.on("error", (error) => this.#fail(error));
    worker.on("exit", (code) => this.#fail(new Error(`audit_worker_exited:${code}`)));
  }

  static async open(path: string, options: { create?: boolean; readOnly?: boolean; retention?: AuditRetention } = {}): Promise<AuditRuntime> {
    const worker = new Worker(new URL("./runtime-worker.ts", import.meta.url), {
      execArgv: ["--experimental-strip-types"],
      workerData: { path, create: options.create === true, readOnly: options.readOnly === true, retention: options.retention ?? {} },
    });
    const runtime = new AuditRuntime(worker);
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("audit_worker_start_timeout")), OPERATION_TIMEOUT_MS);
        const ready = (message: { ready?: boolean; error?: string }) => {
          if (message.ready === undefined) return;
          cleanup();
          if (message.ready) resolve(); else reject(new Error(message.error ?? "audit_worker_open_failed"));
        };
        const failed = (error: Error) => { cleanup(); reject(error); };
        const exited = (code: number) => { cleanup(); reject(new Error(`audit_worker_exited:${code}`)); };
        const cleanup = () => {
          clearTimeout(timer);
          worker.off("message", ready);
          worker.off("error", failed);
          worker.off("exit", exited);
        };
        worker.on("message", ready);
        worker.once("error", failed);
        worker.once("exit", exited);
      });
      return runtime;
    } catch (error) {
      await worker.terminate();
      throw error;
    }
  }

  #fail(error: Error): void {
    if (this.#closed || this.#failure) return;
    this.#failure = error;
    for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.#pending.clear();
  }

  #call<T>(operation: string, ...args: unknown[]): Promise<T> {
    if (this.#closed) return Promise.reject(new Error("audit_worker_closed"));
    if (this.#failure) return Promise.reject(this.#failure);
    if (this.#pending.size >= MAX_PENDING) return Promise.reject(new Error("audit_queue_full"));
    const id = ++this.#nextId;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#fail(new Error("audit_worker_timeout"));
        void this.#worker.terminate();
      }, OPERATION_TIMEOUT_MS);
      this.#pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer });
      try { this.#worker.postMessage({ id, operation, args }); }
      catch (error) { this.#pending.delete(id); clearTimeout(timer); reject(error as Error); }
    });
  }

  append(event: StoredEvent): ReturnType<AuditStore["append"]> { return this.#call("append", event); }
  get(machineId: string, id: string): ReturnType<AuditStore["get"]> { return this.#call("get", machineId, id); }
  recent(limit: number): ReturnType<AuditStore["recent"]> { return this.#call("recent", limit); }
  query(input: AuditQuery): ReturnType<AuditStore["query"]> { return this.#call("query", input); }
  status(): Promise<ReturnType<AuditStore["status"]>> { return this.#call("status"); }
  maintenanceStep(): Promise<ReturnType<AuditStore["maintenanceStep"]>> { return this.#call("maintenance"); }
  deletionHighWatermark(): Promise<number> { return this.#call("deletionHighWatermark"); }
  deletionCountAfter(deletionId: number, highWatermark: number): Promise<number> {
    return this.#call("deletionCountAfter", deletionId, highWatermark);
  }
  getTombstone(machineId: string, id: string): ReturnType<AuditStore["getTombstone"]> {
    return this.#call("getTombstone", machineId, id);
  }
  updateReceipt(machineId: string, id: string, enforcement: Enforcement): ReturnType<AuditStore["updateReceipt"]> {
    return this.#call("updateReceipt", machineId, id, enforcement);
  }
  confirmBackfillReceipt(machineId: string, id: string, evaluation: string, enforcement: Enforcement):
    ReturnType<AuditStore["confirmBackfillReceipt"]> {
    return this.#call("confirmBackfillReceipt", machineId, id, evaluation, enforcement);
  }
  clear(): Promise<number> { return this.#call("clear"); }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await Promise.allSettled([...this.#pending.values()].map((pending) => new Promise<void>((resolve) => {
      const done = pending.resolve;
      const fail = pending.reject;
      pending.resolve = (value) => { done(value); resolve(); };
      pending.reject = (error) => { fail(error); resolve(); };
    })));
    await this.#worker.terminate();
  }
}
