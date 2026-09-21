import {
  discoveryHome,
  readDiscovery,
  readManualPaths,
  setManualPaths,
  requestDiscoveryRefresh,
  refreshDiscovery,
} from "./agent-discovery.ts";
/** Only call AFTER loopback Host/Origin and local admin session checks. Never forward paths to CT. */
export async function discoveryLocalRequest(
  method: string,
  path: string,
  body: unknown,
  home = discoveryHome(),
): Promise<{ status: number; body: unknown }> {
  if (method === "GET" && path === "/api/v1/local/discovery")
    return { status: 200, body: { snapshot: readDiscovery(home), paths: readManualPaths(home) } };
  if (method === "POST" && path === "/api/v1/local/discovery/refresh") {
    requestDiscoveryRefresh(home);
    void refreshDiscovery(home).catch(() => {});
    return { status: 202, body: { ok: true, status: "requested" } };
  }
  if (method === "PUT" && path === "/api/v1/local/discovery/paths") {
    try {
      setManualPaths(home, body);
      void refreshDiscovery(home).catch(() => {});
      return { status: 202, body: { ok: true, status: "requested" } };
    } catch {
      return { status: 400, body: { ok: false, error: "invalid_paths" } };
    }
  }
  return { status: 404, body: { ok: false, error: "not_found" } };
}
