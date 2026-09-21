import {archivePolicy,parseArchivePolicy,githubPolicy,parseGithubPolicy} from "./egress-schema.ts";
import {parseProbeBinding,checkProbeBinding,type ProbeBinding} from "./probe-auth.ts";
import {activeOwnerGrants, type NetworkOwnerGrant} from "./network-owner-schema.ts";
import { parsePolicyExemptions, parsePolicyOverrides, policyExemptions, policyOverrides, type PolicyOverrides } from "./policy-schema.ts";
import {parseDiscovery} from "./agent-discovery-schema.ts";
import type {EvidenceWindow} from "./evidence-window.ts";
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { newEventId, sha256Hex } from "./auth.ts";
import { ARCHIVE_AFTER_MS, MAX_EVENTS, OFFLINE_AFTER_MS } from "./constants.ts";
import type {
  CustomPrivacyRule,
  DeviceRecord,
  Enforcement,
  NetworkHistoryRow,
  NetworkSampleReport,
  PolicyState,
  SnapshotGuardReport,
  StopState,
  StoredEvent,
} from "./schema.ts";
import { parseSnapshotGuardReport } from "./schema.ts";
import {
  MAX_NETWORK_HISTORY,
  mergeHeartbeatNetwork,
  parseNetworkHistoryRow,
  parseNetworkSampleReport,
  upsertNetworkHistory,
} from "./network-evidence.ts";

export type {
  CustomPrivacyRule,
  DeviceRecord,
  Enforcement,
  PolicyState,
  SnapshotGuardReport,
  StoredEvent,
} from "./schema.ts";
export { parseSnapshotGuardReport } from "./schema.ts";
export { mergeHeartbeatNetwork } from "./network-evidence.ts";

export type MachineStatus = "online" | "dark" | "archived";

export interface JoinTicket {
  hash: string;
  expiresAt: number;
  consumed: boolean;
}

export interface MetaState {
  adminTokenHash: string;
  tickets: JoinTicket[];
}

export interface ServePointer {
  pid: number;
  host: string;
  port: number;
  url: string;
  fingerprintSha256: string;
  startedAt: number;
}

const DEFAULT_POLICY: PolicyState = {
  version: 1,
  mode: "enforcing",
  customRules: [],
  stopped: false,
  updatedAt: 0,
};

export function deriveDeviceStatus(lastSeen: number, now = Date.now()): MachineStatus {
  if (now - lastSeen >= ARCHIVE_AFTER_MS) return "archived";
  if (now - lastSeen > OFFLINE_AFTER_MS) return "dark";
  return "online";
}

function projectDeviceRecord(d: DeviceRecord): DeviceRecord {
  const snapshotGuard = parseSnapshotGuardReport((d as { snapshotGuard?: unknown }).snapshotGuard);
  const network = parseNetworkSampleReport((d as { network?: unknown }).network, { relaxTime: true });
  const discovery = parseDiscovery(d.discovery);
  const next: DeviceRecord = { ...d, probeBinding:parseProbeBinding(d.probeBinding), networkOwners: activeOwnerGrants(d.networkOwners) };
  if (snapshotGuard) next.snapshotGuard = snapshotGuard;
  else delete next.snapshotGuard;
  if (discovery) next.discovery = discovery; else delete next.discovery;
  if (network) next.network = network;
  else delete next.network;
  return next;
}

/** pollOnly keeps last confirmed report and lastVerified. Non-poll missing/invalid clears. */
export function mergeHeartbeatSnapshotGuard(
  prev: SnapshotGuardReport | undefined,
  incoming: unknown,
  pollOnly: boolean,
): SnapshotGuardReport | undefined {
  if (pollOnly) return prev ? parseSnapshotGuardReport(prev) : undefined;
  return parseSnapshotGuardReport(incoming);
}

export function deriveStopState(
  policy: PolicyState,
  device: Pick<DeviceRecord, "lastSeen" | "stoppedAck" | "stopAckVersion">,
  now = Date.now(),
): StopState {
  const status = deriveDeviceStatus(device.lastSeen, now);
  if (status === "dark" || status === "archived") return "offline";
  if (!policy.stopped) return "running";
  if (device.stoppedAck && (device.stopAckVersion ?? 0) >= policy.version) return "stop_confirmed";
  return "stop_pending";
}

function cleanupTmp(tmp: string): void {
  try {
    unlinkSync(tmp);
  } catch {
    /* keep destination; only discard our tmp */
  }
}

/** Replace dest via tmp+rename. On failure keep dest, delete tmp, throw. Never unlink dest. */
export async function atomicWrite(path: string, data: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  await writeFile(tmp, data, { mode });
  try {
    renameSync(tmp, path);
  } catch (e) {
    cleanupTmp(tmp);
    throw e instanceof Error ? e : new Error("atomic_write_failed");
  }
}

function atomicReplaceSync(path: string, data: string, mode = 0o600): void {
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  writeFileSync(tmp, data, { mode });
  try {
    renameSync(tmp, path);
  } catch (e) {
    cleanupTmp(tmp);
    throw e instanceof Error ? e : new Error("atomic_write_failed");
  }
}

async function readJsonStrict<T>(path: string): Promise<{ missing: true } | { value: T }> {
  try {
    const raw = await readFile(path, "utf8");
    try {
      return { value: JSON.parse(raw) as T };
    } catch {
      throw new Error(`corrupt_json:${path}`);
    }
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === "ENOENT") return { missing: true };
    if (typeof err.message === "string" && err.message.startsWith("corrupt_json:")) throw e;
    throw e;
  }
}

export async function withFileLock<T>(
  dir: string,
  fn: () => Promise<T>,
  opts?: { timeoutMs?: number },
): Promise<T> {
  await mkdir(dir, { recursive: true });
  const lockPath = join(dir, ".lock");
  const timeoutMs = opts?.timeoutMs ?? 12_000;
  const start = Date.now();
  while (true) {
    let fd: number;
    try {
      fd = openSync(lockPath, "wx");
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code !== "EEXIST") throw e;
      try {
        const st = statSync(lockPath);
        if (Date.now() - st.mtimeMs > 30_000) {
          try {
            unlinkSync(lockPath);
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* ignore */
      }
      if (Date.now() - start > timeoutMs) throw new Error("lock_timeout");
      await new Promise((r) => setTimeout(r, 15 + Math.random() * 40));
      continue;
    }
    try {
      writeSync(fd, Buffer.from(String(process.pid)));
      return await fn();
    } finally {
      closeSync(fd);
      try {
        unlinkSync(lockPath);
      } catch {
        /* ignore */
      }
    }
  }
}

export class NmzpStore {
  readonly dir: string;
  private policy!: PolicyState;
  private devices = new Map<string, DeviceRecord>();
  private events: StoredEvent[] = [];
  private networkHistory: NetworkHistoryRow[] = [];
  private meta!: MetaState;
  private dedup = new Map<string, StoredEvent>();
  private mutex: Promise<unknown> = Promise.resolve();
  private droppedSinceLoad = 0;
  private invalidLinesOnLoad = 0;
  private loadedAt = Date.now();
  private networkMirrorState: "current" | "repair_required" = "current";

  constructor(dir: string) {
    this.dir = dir;
  }

  policyPath(): string {
    return join(this.dir, "policy.json");
  }
  devicesPath(): string {
    return join(this.dir, "devices.json");
  }
  eventsPath(): string {
    return join(this.dir, "events.jsonl");
  }
  networkPath(): string {
    return join(this.dir, "network.jsonl");
  }
  metaPath(): string {
    return join(this.dir, "meta.json");
  }
  adminTokenPath(): string {
    return join(this.dir, "admin.token");
  }

  async load(opts?: { defaultRules?: CustomPrivacyRule[]; defaultOverrides?: PolicyOverrides }): Promise<void> {
    mkdirSync(this.dir, { recursive: true });
    const policyFile = await readJsonStrict<PolicyState>(this.policyPath());
    if ("missing" in policyFile) {
      const next: PolicyState = {
        ...DEFAULT_POLICY,
        customRules: (opts?.defaultRules ?? []).map((r) => ({ ...r })),
        updatedAt: Date.now(),
      };
      const seeded = opts?.defaultOverrides !== undefined ? parsePolicyOverrides(opts.defaultOverrides) : undefined;
      if (seeded) next.overrides = seeded;
      await atomicWrite(this.policyPath(), JSON.stringify(next, null, 2));
      this.policy = next;
    } else {
      this.policy = policyFile.value;
      if (!this.policy.version || this.policy.version < 1) throw new Error("corrupt_json:policy.version");
      if (this.policy.mode !== "enforcing" && this.policy.mode !== "permissive" && this.policy.mode !== "off") {
        throw new Error("corrupt_json:policy.mode");
      }
      if (!Array.isArray(this.policy.customRules)) throw new Error("corrupt_json:policy.customRules");
    }
    if(this.policy.githubUpload!==undefined&&!parseGithubPolicy(this.policy.githubUpload))throw new Error("corrupt_json:policy.githubUpload");
    if(this.policy.archiveUpload!==undefined&&!parseArchivePolicy(this.policy.archiveUpload))throw new Error("corrupt_json:policy.archiveUpload");
    if (this.policy.overrides !== undefined && !parsePolicyOverrides(this.policy.overrides)) throw new Error("corrupt_json:policy.overrides");
    if (this.policy.exemptions !== undefined && !parsePolicyExemptions(this.policy.exemptions)) throw new Error("corrupt_json:policy.exemptions");
    const devicesFile = await readJsonStrict<{ devices?: DeviceRecord[]; snapshotVersion?: number; networkHistory?: unknown[] }>(this.devicesPath());
    this.devices.clear();
    if (!("missing" in devicesFile)) {
      for (const d of devicesFile.value.devices ?? []) {
        if (!d || typeof d.id !== "string") continue;
        this.devices.set(d.id, projectDeviceRecord(d));
      }
    }
    const metaFile = await readJsonStrict<MetaState>(this.metaPath());
    this.meta = "missing" in metaFile ? { adminTokenHash: "", tickets: [] } : metaFile.value;
    if (!Array.isArray(this.meta.tickets)) this.meta.tickets = [];
    this.events = [];
    this.dedup.clear();
    this.droppedSinceLoad = 0;
    this.invalidLinesOnLoad = 0;
    this.loadedAt = Date.now();
    if (existsSync(this.eventsPath())) {
      const raw = await readFile(this.eventsPath(), "utf8");
      for (const line of raw.split(/\n/)) {
        const t = line.trim();
        if (!t) continue;
        try {
          const ev = JSON.parse(t) as StoredEvent;
          if (ev && typeof ev.id === "string" && typeof ev.redacted === "string") {
            this.events.push(ev);
            if (ev.machineId) this.dedup.set(`${ev.machineId}:${ev.id}`, ev);
          } else this.invalidLinesOnLoad++;
        } catch {
          this.invalidLinesOnLoad++;
        }
      }
      if (this.events.length > MAX_EVENTS) {
        this.droppedSinceLoad += this.events.length - MAX_EVENTS;
        this.events = this.events.slice(-MAX_EVENTS);
        this.dedup = new Map(this.events.map(e=>[`${e.machineId}:${e.id}`,e]));
        this.rewriteEventsSync();
      }
    }
    this.networkHistory = [];
    const snapshot = "missing" in devicesFile ? undefined : devicesFile.value;
    const canonical = snapshot?.snapshotVersion === 1;
    if (snapshot?.snapshotVersion !== undefined && !canonical) throw new Error("unknown_device_snapshot_version");
    if (canonical) {
      if (!Array.isArray(snapshot.networkHistory) || snapshot.networkHistory.length > MAX_NETWORK_HISTORY) throw new Error("corrupt_network_snapshot");
      for (const raw of snapshot.networkHistory) {
        const row = parseNetworkHistoryRow(raw, {relaxTime:true});
        if (!row) throw new Error("corrupt_network_snapshot");
        this.networkHistory.push(row);
      }
    } else if (existsSync(this.networkPath())) {
      const raw = await readFile(this.networkPath(), "utf8");
      for (const line of raw.split(/\n/)) {
        const t = line.trim();
        if (!t) continue;
        try {
          const row = parseNetworkHistoryRow(JSON.parse(t) as unknown, { relaxTime: true });
          if (row) this.networkHistory.push(row);
          else this.invalidLinesOnLoad++;
        } catch {
          this.invalidLinesOnLoad++;
        }
      }
      if (this.networkHistory.length > MAX_NETWORK_HISTORY) {
        this.networkHistory = this.networkHistory.slice(-MAX_NETWORK_HISTORY);
        this.rewriteNetworkSync();
      }
    }
    // The atomic devices snapshot is the sole commit point. Never ingest an ahead mirror after a crash.
    if (!canonical) await this.saveDevices();
    try { if (existsSync(this.networkPath()) || this.networkHistory.length) this.rewriteNetworkSync(); this.networkMirrorState = "current"; }
    catch { this.networkMirrorState = "repair_required"; }
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.mutex.then(fn, fn);
    this.mutex = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async savePolicy(): Promise<void> {
    await atomicWrite(this.policyPath(), JSON.stringify(this.policy, null, 2));
  }
  async saveDevices(): Promise<void> {
    await this.writeDeviceSnapshot(this.devices, this.networkHistory);
  }
  private async writeDeviceSnapshot(devices: Map<string, DeviceRecord>, history: NetworkHistoryRow[]): Promise<void> {
    await atomicWrite(this.devicesPath(), JSON.stringify({snapshotVersion:1, devices:[...devices.values()], networkHistory:history}, null, 2));
  }
  async saveMeta(): Promise<void> {
    await atomicWrite(this.metaPath(), JSON.stringify(this.meta, null, 2));
  }
  private async rewriteEvents(): Promise<void> {
    this.rewriteEventsSync();
  }

  private rewriteEventsSync(): void {
    const body = this.events.map((e) => JSON.stringify(e)).join("\n") + (this.events.length ? "\n" : "");
    atomicReplaceSync(this.eventsPath(), body, 0o600);
  }

  private rewriteNetworkSync(): void {
    const body =
      this.networkHistory.map((e) => JSON.stringify(e)).join("\n") + (this.networkHistory.length ? "\n" : "");
    atomicReplaceSync(this.networkPath(), body, 0o600);
  }

  getPolicy(): PolicyState {
    return {
      ...this.policy,
      githubUpload:githubPolicy(this.policy.githubUpload),
      archiveUpload:archivePolicy(this.policy.archiveUpload),
      customRules: this.policy.customRules.map((r) => ({ ...r })),
      overrides: policyOverrides(this.policy.overrides),
      exemptions: policyExemptions(this.policy.exemptions),
    };
  }

  async casPolicy(expectedVersion: number, patch: Partial<Pick<PolicyState, "mode" | "customRules" | "stopped" | "archiveUpload" | "githubUpload" | "overrides" | "exemptions">>): Promise<PolicyState | { conflict: true; version: number }> {
    return this.enqueue(async () => {
      if (this.policy.version !== expectedVersion) return { conflict: true as const, version: this.policy.version };
      const next: PolicyState = {
        ...this.policy,
        customRules: this.policy.customRules.map((r) => ({ ...r })),
      };
      if (patch.mode) {
        if (patch.stopped) next.previousMode = patch.mode;
        next.mode = patch.mode;
      }
      if(patch.githubUpload!==undefined){const gh=parseGithubPolicy(patch.githubUpload);if(!gh)throw Error("invalid_github_policy");next.githubUpload=gh;}
      if(patch.archiveUpload!==undefined){const archive=parseArchivePolicy(patch.archiveUpload);if(!archive)throw new Error("invalid_archive_policy");next.archiveUpload=archive;}
      if (patch.customRules) next.customRules = patch.customRules.map((r) => ({ ...r }));
      if (patch.overrides !== undefined) {
        const o = parsePolicyOverrides(patch.overrides);
        if (!o) throw new Error("invalid_policy_overrides");
        next.overrides = o;
      }
      if (patch.exemptions !== undefined) {
        const e = parsePolicyExemptions(patch.exemptions);
        if (!e) throw new Error("invalid_policy_exemptions");
        next.exemptions = e;
      }
      if (typeof patch.stopped === "boolean") {
        if (patch.stopped && !next.stopped) next.previousMode = next.mode;
        if (!patch.stopped && next.stopped) next.mode = next.previousMode ?? next.mode;
        next.stopped = patch.stopped;
        if (patch.stopped) next.mode = "off";
      }
      next.version += 1;
      next.updatedAt = Date.now();
      await atomicWrite(this.policyPath(), JSON.stringify(next, null, 2));
      this.policy = next;
      return this.getPolicy();
    });
  }

  async stop(): Promise<PolicyState> {
    const cur = this.getPolicy();
    const next = await this.casPolicy(cur.version, { stopped: true });
    if ("conflict" in next) throw new Error("policy cas conflict");
    return next;
  }

  async resume(): Promise<PolicyState> {
    const cur = this.getPolicy();
    const next = await this.casPolicy(cur.version, { stopped: false });
    if ("conflict" in next) throw new Error("policy cas conflict");
    return next;
  }

  listDevices(now = Date.now()): Array<DeviceRecord & { status: MachineStatus; stopState: StopState }> {
    const policy = this.policy;
    return [...this.devices.values()].map((d) => ({
      ...d,
      status: deriveDeviceStatus(d.lastSeen, now),
      stopState: deriveStopState(policy, d, now),
    }));
  }

  async withMutex<T>(fn: () => Promise<T> | T): Promise<T> {
    return this.enqueue(async () => fn());
  }

  getEventUnlocked(deviceId: string, eventId: string): StoredEvent | undefined {
    return this.dedup.get(`${deviceId}:${eventId}`);
  }

  appendEventUnlocked(ev: StoredEvent): StoredEvent {
    const key = `${ev.machineId}:${ev.id}`;
    const prev = this.dedup.get(key);
    if (prev) return { ...prev, duplicate: true };
    const next = [...this.events, ev];
    const drop = Math.max(0, next.length - MAX_EVENTS);
    if (drop) {
      atomicReplaceSync(this.eventsPath(), next.slice(drop).map(e=>JSON.stringify(e)).join("\n")+"\n",0o600);
    } else {
      appendFileSync(this.eventsPath(), JSON.stringify(ev)+"\n",{mode:0o600});
    }
    // Publish only after the disk operation succeeds; a failed write must remain retryable.
    this.events = next.slice(drop);
    this.droppedSinceLoad += drop;
    this.dedup = new Map(this.events.map(e=>[`${e.machineId}:${e.id}`,e]));
    return ev;
  }

  getDevice(id: string): DeviceRecord | undefined {
    return this.devices.get(id);
  }

  findDeviceByToken(token: string): DeviceRecord | undefined {
    const h = sha256Hex(token);
    for (const d of this.devices.values()) {
      if (d.tokenHash === h) return d;
    }
    return undefined;
  }

  async putDevice(d: DeviceRecord): Promise<void> {
    await this.enqueue(async () => {
      const candidates = new Map(this.devices);
      candidates.set(d.id, projectDeviceRecord(d));
      await this.writeDeviceSnapshot(candidates, this.networkHistory);
      this.devices = candidates;
    });
  }

  /** Called only after CT admin authentication; serialized with heartbeats and revocations. */
  async updateNetworkOwner(id: string, grant: NetworkOwnerGrant | undefined, revokeId?: string): Promise<boolean> {
    return this.enqueue(async () => {
      const cur = this.devices.get(id); if (!cur) return false;
      const owners = activeOwnerGrants(cur.networkOwners).filter(g => g.id !== revokeId);
      if (grant) { if (owners.length >= 8) return false; owners.push(grant); }
      const candidates = new Map(this.devices);
      candidates.set(id, {...cur,networkOwners:owners});
      await this.writeDeviceSnapshot(candidates,this.networkHistory);this.devices=candidates;return true;
    });
  }

  async bindProbe(id:string,binding:ProbeBinding|"revoke"):Promise<boolean> {
    return this.enqueue(async()=>{
      const cur=this.devices.get(id);if(!cur||binding==="revoke"&&!cur.probeBinding)return false;
      const next=binding==="revoke"?{...cur.probeBinding!,revoked:true,lastAuthenticatedAt:null}:parseProbeBinding({...binding,registeredAt:Math.max(binding.registeredAt,(cur.probeBinding?.registeredAt??0)+1)});
      const candidates=new Map(this.devices);candidates.set(id,{...cur,probeBinding:next});
      await this.writeDeviceSnapshot(candidates,this.networkHistory);this.devices=candidates;return true;
    });
  }

  async touchDevice(
    id: string,
    patch: Partial<
      Pick<
        DeviceRecord,
        | "hostname"
        | "ip"
        | "lastSeen"
        | "lastPolicyVersion"
        | "capabilities"
        | "agents"
        | "agentProcs"
        | "user"
        | "stoppedAck"
        | "stopAckVersion"
        | "discovery"
        | "snapshotGuard"
        | "network"
      >
    >,
    expectedProbeKey?:string|null,
  ): Promise<DeviceRecord | undefined> {
    return this.enqueue(async () => {
      const cur = this.devices.get(id);
      if (!cur) return undefined;
      if(expectedProbeKey!==undefined)checkProbeBinding(cur.probeBinding,expectedProbeKey);
      const next: DeviceRecord = { ...cur, ...patch };
      if(expectedProbeKey&&cur.probeBinding)next.probeBinding={...cur.probeBinding,lastAuthenticatedAt:Date.now()};
      if (Object.hasOwn(patch,"discovery")) {const parsed=parseDiscovery(patch.discovery);if(parsed)next.discovery=parsed;else delete next.discovery;}
      if (Object.prototype.hasOwnProperty.call(patch, "snapshotGuard")) {
        const parsed = parseSnapshotGuardReport(patch.snapshotGuard);
        if (parsed) next.snapshotGuard = parsed;
        else delete next.snapshotGuard;
      }
      if (Object.prototype.hasOwnProperty.call(patch, "network")) {
        const parsed = parseNetworkSampleReport(patch.network, { relaxTime: true });
        if (parsed) next.network = parsed;
        else delete next.network;
      }
      const candidates = new Map(this.devices);
      candidates.set(id, next);
      await this.writeDeviceSnapshot(candidates, this.networkHistory);
      this.devices = candidates;
      return next;
    });
  }

  listNetworkHistory(limit = MAX_NETWORK_HISTORY): NetworkHistoryRow[] {
    return this.networkHistory.slice(-limit);
  }

  async applyNetworkSample(deviceId: string, incoming: unknown, pollOnly: boolean, now = Date.now(), expectedProbeKey?:string|null): Promise<NetworkSampleReport | undefined> {
    return this.enqueue(async () => {
      const cur = this.devices.get(deviceId);
      if (!cur) return undefined;
      if(expectedProbeKey!==undefined)checkProbeBinding(cur.probeBinding,expectedProbeKey);
      const merged = mergeHeartbeatNetwork(cur.network, incoming, pollOnly, now);
      const next: DeviceRecord = { ...cur };
      if (merged) next.network = merged;
      else delete next.network;
      const candidates = new Map(this.devices);
      candidates.set(deviceId, next);
      const history = merged && !pollOnly && ["ok", "partial", "truncated"].includes(merged.status)
        ? upsertNetworkHistory(this.networkHistory, deviceId, merged, () => `net_${newEventId()}`, MAX_NETWORK_HISTORY)
        : this.networkHistory;
      try {
        atomicReplaceSync(this.networkPath(), history.map(e=>JSON.stringify(e)).join("\n")+(history.length?"\n":""), 0o600);
        await this.writeDeviceSnapshot(candidates, history);
      } catch {
        // A mirror may be ahead, but both public memory and the canonical snapshot stay at the last commit.
        this.networkMirrorState = "repair_required";
        throw new Error("network_commit_failed");
      }
      this.devices = candidates;
      this.networkHistory = history;
      this.networkMirrorState = "current";
      return merged;
    });
  }

  getEvent(deviceId: string, eventId: string): StoredEvent | undefined {
    return this.dedup.get(`${deviceId}:${eventId}`);
  }

  listEvents(limit = MAX_EVENTS): StoredEvent[] {
    const rows = this.events.slice(-limit);
    return rows;
  }

  async appendEvent(ev: StoredEvent): Promise<StoredEvent> {
    return this.enqueue(async () => this.appendEventUnlocked(ev));
  }

  evidenceWindow(): EvidenceWindow {
    const timestamps = this.events.map(e=>e.ts).filter(Number.isFinite);
    return {limit:MAX_EVENTS,retained:this.events.length,droppedSinceLoad:this.droppedSinceLoad,invalidLinesOnLoad:this.invalidLinesOnLoad,loadedAt:this.loadedAt,historyCompleteness:"unknown",receiptDelivery:"best_effort",networkMirrorState:this.networkMirrorState,
      ...(timestamps.length ? {oldestTs:Math.min(...timestamps),newestTs:Math.max(...timestamps)} : {})};
  }

  async updateReceipt(deviceId: string, eventId: string, enforcement: Enforcement): Promise<StoredEvent | { error: "not_found" | "forbidden" }> {
    return this.enqueue(async () => {
      const key = `${deviceId}:${eventId}`;
      const ev = this.dedup.get(key);
      if (!ev) return { error: "not_found" as const };
      if (ev.machineId !== deviceId || ev.layer === "model_response") return { error: "forbidden" as const };
      const next = {...ev,enforcement};
      const rows = this.events.map(e => e.id === eventId && e.machineId === deviceId ? next : e);
      atomicReplaceSync(this.eventsPath(), rows.map(e=>JSON.stringify(e)).join("\n")+(rows.length ? "\n" : ""));
      this.events = rows;
      this.dedup.set(key,next);
      return next;
    });
  }

  async clearEvents(): Promise<void> {
    await this.enqueue(async () => {
      atomicReplaceSync(this.eventsPath(), "");
      this.events = [];
      this.dedup.clear();
    });
  }

  adminHash(): string {
    return this.meta.adminTokenHash;
  }

  async setAdminHash(hash: string): Promise<void> {
    return this.enqueue(async () => {
      const next: MetaState = { adminTokenHash: hash, tickets: this.meta.tickets.map((t) => ({ ...t })) };
      await atomicWrite(this.metaPath(), JSON.stringify(next, null, 2));
      this.meta = next;
    });
  }

  async addTicket(hash: string, ttlMs: number): Promise<void> {
    return this.enqueue(async () => {
      const now = Date.now();
      const next: MetaState = {
        adminTokenHash: this.meta.adminTokenHash,
        tickets: this.meta.tickets.filter((t) => !t.consumed && t.expiresAt > now),
      };
      next.tickets.push({ hash, expiresAt: now + ttlMs, consumed: false });
      await atomicWrite(this.metaPath(), JSON.stringify(next, null, 2));
      this.meta = next;
    });
  }

  async consumeTicket(token: string): Promise<boolean> {
    return this.enqueue(async () => {
      const h = sha256Hex(token);
      const now = Date.now();
      const next: MetaState = {
        adminTokenHash: this.meta.adminTokenHash,
        tickets: this.meta.tickets.map((t) => ({ ...t })),
      };
      const t = next.tickets.find((x) => x.hash === h && !x.consumed && x.expiresAt > now);
      if (!t) return false;
      t.consumed = true;
      await atomicWrite(this.metaPath(), JSON.stringify(next, null, 2));
      this.meta = next;
      return true;
    });
  }
}

export function servePointerPath(dir: string): string {
  return join(dir, "serve.json");
}

export async function writeServePointer(dir: string, pointer: ServePointer): Promise<void> {
  await atomicWrite(servePointerPath(dir), JSON.stringify(pointer));
}

export async function readServePointer(dir: string): Promise<ServePointer | null> {
  const file = await readJsonStrict<ServePointer>(servePointerPath(dir));
  if ("missing" in file) return null;
  const v = file.value;
  if (!v || typeof v.url !== "string" || typeof v.port !== "number" || typeof v.fingerprintSha256 !== "string") {
    throw new Error("corrupt_json:serve.json");
  }
  return v;
}

export function removeServePointer(dir: string): void {
  try {
    unlinkSync(servePointerPath(dir));
  } catch {
    /* missing is fine */
  }
}

export async function bootstrapAdmin(store: NmzpStore, existing?: string): Promise<{ token: string; created: boolean }> {
  const path = store.adminTokenPath();
  if (existing) {
    await store.setAdminHash(sha256Hex(existing));
    await atomicWrite(path, existing + "\n", 0o600);
    return { token: existing, created: false };
  }
  try {
    const raw = (await readFile(path, "utf8")).trim();
    if (raw) {
      await store.setAdminHash(sha256Hex(raw));
      return { token: raw, created: false };
    }
  } catch {
    /* create */
  }
  const { newSecret } = await import("./auth.ts");
  const token = newSecret(32);
  await atomicWrite(path, token + "\n", 0o600);
  await store.setAdminHash(sha256Hex(token));
  return { token, created: true };
}
