import { request } from "node:https";
import type { ServerResponse } from "node:http";
import type { TLSSocket } from "node:tls";
import { pipeline } from "node:stream/promises";
import { assertPin, type PinRequest } from "./https-client.ts";

/** Authenticated admin export forwarding with backpressure, pinning, deadline and cancellation. */
export async function forwardPinnedExport(options: PinRequest, downstream: ServerResponse): Promise<void> {
  const url = new URL(options.url);
  if (url.protocol !== "https:" || !options.caPem) throw new Error("https pin required");
  if (!/^[a-f0-9]{64}$/i.test(options.fingerprintSha256.replace(/:/g, ""))) throw new Error("tls pin required");
  await new Promise<void>((resolve, reject) => {
    const upstream = request(url, {
      method: "GET", ca: options.caPem, rejectUnauthorized: true, agent: false, headers: options.headers,
    });
    const timer = setTimeout(() => upstream.destroy(new Error("export_timeout")), options.timeoutMs ?? 300_000);
    const cancel = () => { if (!downstream.writableFinished) upstream.destroy(new Error("export_cancelled")); };
    downstream.once("close", cancel);
    const finish = (error?: Error) => {
      clearTimeout(timer);
      downstream.off("close", cancel);
      if (error) reject(error); else resolve();
    };
    upstream.once("error", finish);
    upstream.on("socket", (socket: TLSSocket) => {
      socket.once("secureConnect", () => {
        try { assertPin(socket, options.fingerprintSha256); upstream.end(); }
        catch (error) { upstream.destroy(error instanceof Error ? error : new Error("tls pin failed")); }
      });
    });
    upstream.once("response", (response) => {
      downstream.writeHead(response.statusCode ?? 502, {
        "content-type": response.headers["content-type"] ?? "application/octet-stream",
        "cache-control": "no-store", "x-content-type-options": "nosniff",
        ...(response.headers["content-encoding"] ? { "content-encoding": response.headers["content-encoding"] } : {}),
      });
      void pipeline(response, downstream).then(() => finish(), (error: Error) => finish(error));
    });
  });
}
