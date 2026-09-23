import type { Worker } from "node:worker_threads";

/** Internal transport seam. Never exposed as an HTTP option or worker-path override. */
export type AuditWorkerPort = Pick<Worker, "on" | "off" | "postMessage" | "terminate">;

type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  done: Promise<void>;
  finish: () => void;
};

type State = "starting" | "open" | "closing" | "closed" | "failed";
const MAX_PENDING = 32;
const TIMEOUT_MS = 30_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error("audit_worker_failed");
}

/**
 * One worker, one bounded request lane. A close stops admission, NOT settlement.
 * Each accepted request settles once; every close caller awaits the same drain
 * and termination. A transport failure never retries an operation whose commit
 * status may be unknown. Per-operation errors do not poison a healthy worker.
 */
export class AuditWorkerChannel {
  readonly #worker: AuditWorkerPort;
  readonly #pending = new Map<number, Pending>();
  readonly #ready: Promise<void>;
  #startup: { resolve: () => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> } | undefined;
  #state: State = "starting";
  #nextId = 0;
  #failure: Error | undefined;
  #exited = false;
  #termination: Promise<void> | undefined;
  #closing: Promise<void> | undefined;

  private constructor(worker: AuditWorkerPort) {
    this.#worker = worker;
    this.#ready = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(new Error("audit_worker_start_timeout")), TIMEOUT_MS);
      this.#startup = { resolve, reject, timer };
    });
    worker.on("message", this.#onMessage);
    worker.on("error", this.#onError);
    worker.on("messageerror", this.#onMessageError);
    worker.on("exit", this.#onExit);
  }

  static async open(worker: AuditWorkerPort): Promise<AuditWorkerChannel> {
    const channel = new AuditWorkerChannel(worker);
    try {
      await channel.#ready;
      if (channel.#failure) throw channel.#failure;
      return channel;
    } catch (error) {
      // Preserve the startup cause; cleanup is still awaited, never abandoned.
      try { await channel.#terminate(); } catch { /* original startup error wins */ }
      throw error;
    }
  }

  #settleStartup(error?: Error): void {
    const startup = this.#startup;
    if (!startup) return;
    this.#startup = undefined;
    clearTimeout(startup.timer);
    if (error) startup.reject(error);
    else startup.resolve();
  }

  #onMessage = (message: unknown): void => {
    if (this.#failure || this.#state === "closed") return;
    if (!isRecord(message)) {
      this.#fail(new Error("audit_worker_protocol_error"));
      return;
    }
    if (this.#state === "starting") {
      if (message.ready === true && message.error === undefined) {
        this.#state = "open";
        this.#settleStartup();
      } else if (message.ready === false && (message.error === undefined || typeof message.error === "string")) {
        this.#fail(new Error(message.error || "audit_worker_open_failed"));
      } else {
        this.#fail(new Error("audit_worker_protocol_error"));
      }
      return;
    }
    if (!Number.isSafeInteger(message.id) || (message.id as number) < 1) {
      this.#fail(new Error("audit_worker_protocol_error"));
      return;
    }
    const id = message.id as number;
    // A duplicate/late reply must not settle another call or reopen the channel.
    if (!this.#pending.has(id)) return;
    if (typeof message.error === "string" && message.error.length > 0 && !Object.hasOwn(message, "value")) {
      this.#settle(id, undefined, new Error(message.error));
    } else if (message.error === undefined && Object.hasOwn(message, "value")) {
      this.#settle(id, message.value);
    } else {
      this.#fail(new Error("audit_worker_protocol_error"));
    }
  };

  #onError = (error: Error): void => { this.#fail(asError(error)); };
  #onMessageError = (): void => { this.#fail(new Error("audit_worker_message_error")); };
  #onExit = (code: number): void => {
    this.#exited = true;
    // Exit code zero still loses pending replies. Only an empty closing lane
    // makes an exit expected; an idle OPEN worker exiting is also a failure.
    if (this.#state !== "closed" && !(this.#state === "closing" && this.#pending.size === 0)) {
      this.#fail(new Error(`audit_worker_exited:${code}`));
    }
    this.#detach();
  };

  #settle(id: number, value?: unknown, error?: Error): void {
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    if (error) pending.reject(error);
    else pending.resolve(value);
    pending.finish();
  }

  #fail(error: Error): void {
    if (this.#state === "closed" || this.#failure) return;
    this.#failure = error;
    if (this.#state !== "closing") this.#state = "failed";
    this.#settleStartup(error);
    for (const id of this.#pending.keys()) this.#settle(id, undefined, error);
    // Memoize cleanup. Observe its rejection now; close() also awaits the same
    // promise so a termination error is not an unhandled rejection or success.
    void this.#terminate().catch(() => undefined);
  }

  #terminate(): Promise<void> {
    if (!this.#termination) {
      this.#termination = Promise.resolve().then(async () => {
        if (!this.#exited) await this.#worker.terminate();
        this.#detach();
      });
    }
    return this.#termination;
  }

  #detach(): void {
    this.#worker.off("message", this.#onMessage);
    this.#worker.off("error", this.#onError);
    this.#worker.off("messageerror", this.#onMessageError);
    this.#worker.off("exit", this.#onExit);
  }

  call<T>(operation: string, ...args: unknown[]): Promise<T> {
    if (this.#state === "closing" || this.#state === "closed") {
      return Promise.reject(new Error("audit_worker_closed"));
    }
    if (this.#failure) return Promise.reject(this.#failure);
    if (this.#state !== "open") return Promise.reject(new Error("audit_worker_not_ready"));
    if (this.#pending.size >= MAX_PENDING) return Promise.reject(new Error("audit_queue_full"));
    const id = ++this.#nextId;
    let finish!: () => void;
    const done = new Promise<void>((resolve) => { finish = resolve; });
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(new Error("audit_worker_timeout")), TIMEOUT_MS);
      this.#pending.set(id, { resolve: (value) => resolve(value as T), reject, timer, done, finish });
      try {
        this.#worker.postMessage({ id, operation, args });
      } catch (error) {
        // A synchronous clone/send error did not enqueue this request. It must
        // free its slot and timer without disabling unrelated accepted calls.
        this.#settle(id, undefined, asError(error));
      }
    });
  }

  /**
   * Resolve after resources are released, NOT as proof all writes succeeded.
   * Request promises carry their own failures. Drain remains protected by each
   * request's original deadline; termination itself awaits Node's exit promise.
   */
  close(): Promise<void> {
    if (this.#closing) return this.#closing;
    this.#state = "closing";
    const drained = Promise.all([...this.#pending.values()].map((pending) => pending.done));
    this.#closing = (async () => {
      await drained;
      await this.#terminate();
      this.#state = "closed";
    })();
    return this.#closing;
  }
}
