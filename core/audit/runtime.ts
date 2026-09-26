import { Worker } from "node:worker_threads";
import type { Enforcement, StoredEvent } from "../schema.ts";
import type { AuditQuery, AuditRetention, AuditStore } from "./store.ts";
import { AuditWorkerChannel, type AuditWorkerPort } from "./worker-channel.ts";

const DEFAULT_RECOVERY_DELAYS_MS = [500, 1000, 2000, 4000, 8000];

export interface AuditWorkerData {
  path: string;
  create: boolean;
  readOnly: boolean;
  retention: AuditRetention;
}

/** Test-only factory. Production uses the built-in runtime worker. Never set from HTTP, env, or CLI. */
export type AuditWorkerSpawn = (workerData: AuditWorkerData) => AuditWorkerPort;

export type AuditRuntimeState = "ready" | "recovering" | "failed" | "closed";

export interface AuditRuntimeOptions {
  create?: boolean;
  readOnly?: boolean;
  retention?: AuditRetention;
  /** Test-only worker factory. Never set from HTTP, environment, or CLI. */
  spawn?: AuditWorkerSpawn;
  /** Test-only delay schedule. Its length is the attempt cap. Omitted means the production schedule. */
  recoveryDelaysMs?: number[];
}

function defaultSpawn(workerData: AuditWorkerData): AuditWorkerPort {
  return new Worker(new URL("./runtime-worker.ts", import.meta.url), {
    execArgv: ["--experimental-strip-types"],
    workerData,
  });
}

function recoveryDelays(input: number[] | undefined): readonly number[] {
  if (input === undefined) return DEFAULT_RECOVERY_DELAYS_MS;
  if (input.every((ms) => Number.isSafeInteger(ms) && ms >= 0)) return input.slice();
  return DEFAULT_RECOVERY_DELAYS_MS;
}

/**
 * Live audit I/O facade. A failed channel is replaced in-process after it terminates.
 * Calls that were in flight on the failed channel are not replayed.
 */
export class AuditRuntime {
  readonly #path: string;
  readonly #create: boolean;
  readonly #readOnly: boolean;
  readonly #retention: AuditRetention;
  readonly #spawn: AuditWorkerSpawn;
  readonly #delays: readonly number[];
  readonly #fatalListeners = new Set<(error: Error) => void>();
  #channel: AuditWorkerChannel | undefined;
  #reconciler: ((channel: AuditWorkerChannel) => Promise<void>) | undefined;
  #state: AuditRuntimeState = "ready";
  #closed = false;
  #closePromise: Promise<void> | undefined;
  #recovery: Promise<void> | undefined;
  #opening: Promise<AuditWorkerChannel> | undefined;
  #backoffTimer: ReturnType<typeof setTimeout> | undefined;
  #backoffResolve: (() => void) | undefined;
  #fatalSent = false;

  private constructor(path: string, options: AuditRuntimeOptions) {
    this.#path = path;
    this.#create = options.create === true;
    this.#readOnly = options.readOnly === true;
    this.#retention = options.retention ?? {};
    this.#spawn = options.spawn ?? defaultSpawn;
    this.#delays = recoveryDelays(options.recoveryDelaysMs);
  }

  static async open(path: string, options: AuditRuntimeOptions = {}): Promise<AuditRuntime> {
    const runtime = new AuditRuntime(path, options);
    runtime.#channel = await runtime.#openChannel(runtime.#initialData());
    return runtime;
  }

  get state(): AuditRuntimeState {
    return this.#state;
  }

  /** Reloads projections from the replacement channel before the runtime becomes ready again. */
  setReconciler(reconciler: (channel: AuditWorkerChannel) => Promise<void>): void {
    this.#reconciler = reconciler;
  }

  onFatal(listener: (error: Error) => void): void {
    this.#fatalListeners.add(listener);
    if (this.#fatalSent) listener(new Error("audit_worker_unrecoverable"));
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

  close(): Promise<void> {
    this.#closePromise ??= this.#shutdown();
    return this.#closePromise;
  }

  #initialData(): AuditWorkerData {
    return { path: this.#path, create: this.#create, readOnly: this.#readOnly, retention: this.#retention };
  }

  #replacementData(): AuditWorkerData {
    return { path: this.#path, create: false, readOnly: this.#readOnly, retention: this.#retention };
  }

  #blockedMessage(): string {
    if (this.#state === "recovering") return "audit_worker_recovering";
    if (this.#state === "failed") return "audit_worker_unavailable";
    return "audit_worker_closed";
  }

  #call<T>(operation: string, ...args: unknown[]): Promise<T> {
    if (this.#state !== "ready" || !this.#channel) return Promise.reject(new Error(this.#blockedMessage()));
    return this.#channel.call<T>(operation, ...args);
  }

  #openChannel(data: AuditWorkerData): Promise<AuditWorkerChannel> {
    const worker = this.#spawn(data);
    const opening = AuditWorkerChannel.open(worker, { onFailure: (error) => this.#onChannelFailure(error) });
    this.#opening = opening;
    return opening.finally(() => {
      if (this.#opening === opening) this.#opening = undefined;
    });
  }

  async #openReplacement(): Promise<AuditWorkerChannel | undefined> {
    try {
      return await this.#openChannel(this.#replacementData());
    } catch {
      return undefined;
    }
  }

  #onChannelFailure(_error: Error): void {
    if (this.#closed || this.#state !== "ready" || !this.#channel) return;
    const failed = this.#channel;
    this.#state = "recovering";
    this.#recovery = this.#recover(failed);
  }

  #backoff(ms: number): Promise<void> {
    if (this.#closed) return Promise.resolve();
    return new Promise((resolve) => {
      this.#backoffResolve = resolve;
      this.#backoffTimer = setTimeout(() => {
        this.#backoffTimer = undefined;
        this.#backoffResolve = undefined;
        resolve();
      }, ms);
    });
  }

  #cancelBackoff(): void {
    if (this.#backoffTimer) clearTimeout(this.#backoffTimer);
    this.#backoffTimer = undefined;
    const resolve = this.#backoffResolve;
    this.#backoffResolve = undefined;
    resolve?.();
  }

  #emitFatal(): void {
    if (this.#fatalSent) return;
    this.#fatalSent = true;
    const error = new Error("audit_worker_unrecoverable");
    for (const listener of this.#fatalListeners) {
      try { listener(error); } catch { /* a listener must not wedge recovery */ }
    }
  }

  async #recover(failed: AuditWorkerChannel): Promise<void> {
    try {
      await failed.close().catch(() => undefined);
      if (this.#channel === failed) this.#channel = undefined;
      for (let attempt = 0; attempt < this.#delays.length; attempt += 1) {
        if (this.#closed) return;
        await this.#backoff(this.#delays[attempt] ?? 0);
        if (this.#closed) return;
        const opened = await this.#openReplacement();
        if (this.#closed) {
          if (opened) await opened.close().catch(() => undefined);
          return;
        }
        if (!opened) continue;
        try {
          if (this.#reconciler) await this.#reconciler(opened);
        } catch {
          await opened.close().catch(() => undefined);
          continue;
        }
        if (this.#closed) {
          await opened.close().catch(() => undefined);
          return;
        }
        this.#channel = opened;
        this.#state = "ready";
        return;
      }
      if (!this.#closed) {
        this.#state = "failed";
        this.#emitFatal();
      }
    } catch {
      if (!this.#closed && this.#state !== "ready") {
        this.#state = "failed";
        this.#emitFatal();
      }
    }
  }

  async #shutdown(): Promise<void> {
    this.#closed = true;
    this.#state = "closed";
    this.#cancelBackoff();
    if (this.#recovery) await this.#recovery;
    if (this.#channel) await this.#channel.close();
  }
}
