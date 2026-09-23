import { parentPort, workerData } from "node:worker_threads";
import type { Enforcement, StoredEvent } from "../schema.ts";
import { AuditStore, type AuditQuery, type AuditRetention } from "./store.ts";

interface WorkerConfig {
  path: string;
  create: boolean;
  readOnly: boolean;
  retention: AuditRetention;
}

interface Request {
  id: number;
  operation: string;
  args: unknown[];
}

const config = workerData as WorkerConfig;
const port = parentPort;
if (!port) throw new Error("audit_worker_port_missing");

try {
  const store = config.create
    ? AuditStore.create(config.path, config.retention)
    : AuditStore.open(config.path, config.readOnly, config.retention);
  port.postMessage({ ready: true });
  // One ordered lane keeps reads, writes and cleanup consistent even when callers overlap.
  let tail: Promise<unknown> = Promise.resolve();
  port.on("message", (request: Request) => {
    tail = tail.then(async () => {
      const { id, operation, args } = request;
      try {
        let value: unknown;
        switch (operation) {
          case "append": value = await store.append(args[0] as StoredEvent); break;
          case "get": value = await store.get(args[0] as string, args[1] as string); break;
          case "recent": value = await store.recent(args[0] as number); break;
          case "query": value = await store.query(args[0] as AuditQuery); break;
          case "status": value = store.status(); break;
          case "maintenance": value = store.maintenanceStep(); break;
          case "deletionHighWatermark": value = store.deletionHighWatermark(); break;
          case "deletionCountAfter": value = store.deletionCountAfter(args[0] as number, args[1] as number); break;
          case "getTombstone": value = await store.getTombstone(args[0] as string, args[1] as string); break;
          case "updateReceipt": value = await store.updateReceipt(args[0] as string, args[1] as string, args[2] as Enforcement); break;
          case "confirmBackfillReceipt": value = await store.confirmBackfillReceipt(args[0] as string, args[1] as string,
            args[2] as string, args[3] as Enforcement); break;
          case "clear": value = store.clear(); break;
          default: throw new Error("audit_worker_operation_invalid");
        }
        port.postMessage({ id, value });
      } catch (error) {
        port.postMessage({ id, error: error instanceof Error ? error.message : "audit_worker_failed" });
      }
    });
  });
} catch (error) {
  port.postMessage({ ready: false, error: error instanceof Error ? error.message : "audit_worker_open_failed" });
}
