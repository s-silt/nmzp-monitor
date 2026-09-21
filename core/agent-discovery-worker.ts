import { parentPort, workerData } from "node:worker_threads";
import { scanMetadata, type ScanInput } from "./agent-discovery-scan.ts";
if (parentPort) {
  try {
    parentPort.postMessage(scanMetadata(workerData as ScanInput));
  } catch {
    parentPort.postMessage({ error: "metadata_failed" });
  }
}
