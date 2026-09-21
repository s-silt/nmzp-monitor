import {archivePolicy,type ArchiveUploadPolicy,githubPolicy,type GithubUploadPolicy} from "./egress-evidence.ts";
import type { CustomPrivacyRule, Intervention } from "./types";
import type { PolicyExemption, PolicyOverrides } from "./policy-schema.ts";

export interface ApiCapability {
  supported: boolean;
  active: boolean;
  lastSuccess?: number;
  error?: string;
}

export interface ApiAgentProc {
  agent: string;
  pid: number;
  ppid: number;
  bin: string;
}

export interface ApiDevice {
  id: string;
  hostname: string;
  ip: string;
  user: string;
  os: "linux" | "darwin" | "win32";
  lastSeen: number;
  attachedAt: number;
  status: "online" | "dark" | "archived";
  capabilities: Array<{ id: string } & ApiCapability>;
  agents: string[];
  agentProcs?: ApiAgentProc[];
  discovery?: unknown;
  probeProtection?: unknown;
  snapshotGuard?: unknown;
  network?: unknown;
  lastPolicyVersion?: number;
  networkOwnerCount?: number;
}

export type AccessRole = "viewer" | "admin";

export interface ApiState {
  archiveUpload?:ArchiveUploadPolicy;
  githubUpload?:GithubUploadPolicy;
  /** Server window metadata; missing on old releases, never assumed complete. */
  evidenceWindow?: unknown;
  serverTime: number;
  policyVersion: number;
  mode: Intervention;
  stopped: boolean;
  customRules: CustomPrivacyRule[];
  devices: ApiDevice[];
  events: unknown[];
  networkHistory?: unknown[];
  eventEndpoints?: Record<string, unknown>;
  deviceNetwork?: Record<string, unknown>;
  capabilities: Record<string, ApiCapability>;
  /** Old authenticated 200 payloads without this field are treated as admin. */
  access: AccessRole;
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
}

const TOKEN_KEY = "nmzp-admin-token";

export function getAdminToken(): string {
  if (typeof sessionStorage === "undefined") return "";
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

export function setAdminToken(token: string) {
  if (typeof sessionStorage === "undefined") return;
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

function headers(extra?: Record<string, string>): HeadersInit {
  const h: Record<string, string> = { ...(extra ?? {}) };
  const t = getAdminToken();
  if (t) h.authorization = `Bearer ${t}`;
  return h;
}

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { ok: false, error: "bad_json", status: res.status };
  }
}

export async function login(token: string): Promise<boolean> {
  const res = await fetch("/api/v1/session", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) return false;
  setAdminToken(token);
  if (typeof localStorage !== "undefined") {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      /* ignore */
    }
  }
  return true;
}

const MODES = new Set(["enforcing", "permissive", "off"]);

export function parseApiState(raw: unknown): ApiState | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const s = raw as Record<string, unknown>;
  if (typeof s.policyVersion !== "number" || !Number.isFinite(s.policyVersion)) return null;
  if (typeof s.stopped !== "boolean") return null;
  if (typeof s.mode !== "string" || !MODES.has(s.mode)) return null;
  if (!Array.isArray(s.devices) || !Array.isArray(s.events)) return null;
  if (s.customRules !== undefined && !Array.isArray(s.customRules)) return null;
  return {
    evidenceWindow: s.evidenceWindow,
    serverTime: typeof s.serverTime === "number" && Number.isFinite(s.serverTime) ? s.serverTime : 0,
    policyVersion: s.policyVersion,
    mode: s.mode as ApiState["mode"],
    archiveUpload:archivePolicy(s.archiveUpload),
    githubUpload:githubPolicy(s.githubUpload),
    stopped: s.stopped,
    customRules: (s.customRules as ApiState["customRules"]) ?? [],
    devices: s.devices as ApiState["devices"],
    events: s.events,
    networkHistory: Array.isArray(s.networkHistory) ? s.networkHistory : [],
    eventEndpoints:
      s.eventEndpoints && typeof s.eventEndpoints === "object" && !Array.isArray(s.eventEndpoints)
        ? (s.eventEndpoints as Record<string, unknown>)
        : undefined,
    deviceNetwork:
      s.deviceNetwork && typeof s.deviceNetwork === "object" && !Array.isArray(s.deviceNetwork)
        ? (s.deviceNetwork as Record<string, unknown>)
        : undefined,
    capabilities: s.capabilities && typeof s.capabilities === "object" && !Array.isArray(s.capabilities) ? (s.capabilities as ApiState["capabilities"]) : {},
    access: parseAccess(s.access),
    overrides: (s.overrides as ApiState["overrides"]) ?? undefined,
    exemptions: Array.isArray(s.exemptions) ? (s.exemptions as ApiState["exemptions"]) : undefined,
  };
}

/** Legacy authenticated 200 with no access → admin. Unknown nonempty values never become admin. */
export function parseAccess(v: unknown): AccessRole {
  if (v === undefined || v === null || v === "") return "admin";
  if (v === "admin") return "admin";
  return "viewer";
}

export async function fetchState(): Promise<{ ok: true; state: ApiState } | { ok: false; status: number }> {
  const res = await fetch("/api/v1/state", { credentials: "include", headers: headers() });
  if (!res.ok) return { ok: false, status: res.status };
  const parsed = parseApiState(await parse(res));
  if (!parsed) return { ok: false, status: res.status || 200 };
  return { ok: true, state: parsed };
}

export async function putPolicy(body: {
  githubUpload?:GithubUploadPolicy;
  archiveUpload?:ArchiveUploadPolicy;
  expectedVersion: number;
  mode?: Intervention;
  customRules?: CustomPrivacyRule[];
  stopped?: boolean;
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
}): Promise<{
  ok: true;
  version: number;
  mode: Intervention;
  stopped: boolean;
  customRules: CustomPrivacyRule[];
  overrides?: PolicyOverrides;
  exemptions?: PolicyExemption[];
} | { ok: false; status: number; error?: string }> {
  const res = await fetch("/api/v1/policy", {
    method: "PUT",
    credentials: "include",
    headers: headers({ "content-type": "application/json" }),
    body: JSON.stringify(body),
  });
  const data = (await parse(res)) as {
    version?: number;
    mode?: Intervention;
    stopped?: boolean;
    customRules?: CustomPrivacyRule[];
    overrides?: PolicyOverrides;
    exemptions?: PolicyExemption[];
    error?: string;
  };
  if (!res.ok) return { ok: false, status: res.status, error: data.error };
  return {
    ok: true,
    version: data.version!,
    mode: data.mode!,
    stopped: data.stopped!,
    customRules: data.customRules ?? [],
    overrides: data.overrides,
    exemptions: data.exemptions,
  };
}

export async function clearEventsApi(): Promise<boolean> {
  const res = await fetch("/api/v1/events", { method: "DELETE", credentials: "include", headers: headers() });
  return res.ok;
}

export async function exportApi(): Promise<string> {
  const res = await fetch("/api/v1/export", { credentials: "include", headers: headers() });
  if (!res.ok) throw new Error("export_failed");
  return JSON.stringify(await parse(res));
}

/** Drop leftover demo switches so they cannot revive seed data. */
export function clearDemoResidue() {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem("nmzp-demo");
  } catch {
    /* ignore */
  }
  try {
    const url = new URL(window.location.href);
    if (url.searchParams.has("demo")) {
      url.searchParams.delete("demo");
      const next = `${url.pathname}${url.search}${url.hash}`;
      window.history.replaceState({}, "", next);
    }
  } catch {
    /* ignore */
  }
}
