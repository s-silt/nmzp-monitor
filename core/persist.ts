import { NmzpPolicyService, policyRulesHash } from "./policy/nmzp-service.ts";
import { PolicyHistory } from "./policy/history.ts";
import { type AuditQuery, type AuditRetention } from "./audit/store.ts";
import { AuditRuntime } from "./audit/runtime.ts";
import { AuditEvents } from "./audit/events.ts";
import { atomicWrite, atomicReplaceSync } from "./atomic-file.ts";
import { PolicyWriterLease } from "./policy/writer-lease.ts";
import { createNmzpPolicyDomain } from "./policy/nmzp-domain.ts";
import { createPolicySnapshot } from "./policy/snapshot.ts";
import type { PolicyFileOperations } from "./policy/file-store.ts";
import { loadMonitor, type MonitorMods } from "./paths.ts";
import { fileURLToPath } from "node:url";
import {parseProbeBinding,checkProbeBinding,type ProbeBinding} from "./probe-auth.ts";
import {activeOwnerGrants, type NetworkOwnerGrant} from "./network-owner-schema.ts";
import { parsePolicyOverrides, type PolicyOverrides } from "./policy-schema.ts";
import {parseDiscovery} from "./agent-discovery-schema.ts";
import type {EvidenceWindow} from "./evidence-window.ts";
import {
  existsSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { newEventId, sha256Hex } from "./auth.ts";
import { ARCHIVE_AFTER_MS, MAX_EVENTS, OFFLINE_AFTER_MS } from "./constants.ts";
import { NMZP_VERSION } from "./constants.ts";
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

export { atomicWrite } from "./atomic-file.ts";

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

export { withFileLock } from "./file-lock.ts";

export interface StoreLoadOptions {
  defaultRules?: CustomPrivacyRule[];
  defaultOverrides?: PolicyOverrides;
  policySource?: MonitorMods;
  policyFileOperations?: PolicyFileOperations;
  /** One-time inspection snapshot; no bootstrap, repair or writes. Not a transaction across files. */
  readOnly?: boolean;
  /** Window keeps the existing 2,000-row JSONL behavior. SQLite is explicit opt-in. */
  storageMode?: "window" | "sqlite";
  auditRetention?: AuditRetention;
}

export class NmzpStore {
  readonly dir: string;
  private policyService!: NmzpPolicyService;
  private policyHistory?: PolicyHistory<PolicyState>;
  private auditEvents?: AuditEvents;
  private policyLease?: PolicyWriterLease;
  private closing = false;
  private readOnly = false;
  private storageMode: "window" | "sqlite" = "window";
  private loaded = false;
  private policyTail: Promise<unknown> = Promise.resolve();
  private devices = new Map<string, DeviceRecord>();
  private networkHistory: NetworkHistoryRow[] = [];
  private meta!: MetaState;
  private mutex: Promise<unknown> = Promise.resolve();
  private invalidLinesOnLoad = 0;
  private networkMirrorState: "current" | "repair_required" = "current";

  constructor(dir: string) {
    this.dir = resolve(dir);
  }

  policyPath(): string {
    return join(this.dir, "policy.json");
  }
  policyHistoryPath(): string { return join(this.dir, "nmzp.db"); }
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

  async load(opts?: StoreLoadOptions): Promise<void> {
    if (this.loaded || this.policyLease || this.closing) throw new Error("policy_store_already_loaded");
    this.readOnly = opts?.readOnly === true;
    this.storageMode = opts?.storageMode ?? "window";
    if (!this.readOnly) {
      mkdirSync(this.dir, { recursive: true });
      this.policyLease = new PolicyWriterLease(join(this.dir, ".policy-writer.lock"));
    }
    try {
      if (!this.readOnly && existsSync(servePointerPath(this.dir))) {
        throw new Error("policy_existing_serve_pointer");
      }
      await this.loadOwned(opts);
      this.loaded = true;
    } catch (error) {
      await this.auditEvents?.close();
      this.auditEvents = undefined;
      this.policyHistory?.close();
      this.policyHistory = undefined;
      this.policyLease?.close();
      this.policyLease = undefined;
      throw error;
    }
  }

  private async loadOwned(opts?: StoreLoadOptions): Promise<void> {
    if (this.storageMode === "sqlite" && existsSync(join(this.dir, ".nmzp-migration.json"))) {
      const marker = await readJsonStrict<{state?: string}>(join(this.dir, ".nmzp-migration.json"));
      if ("missing" in marker || marker.value.state !== "complete") throw new Error("migration_incomplete");
    }
    const source = opts?.policySource ?? await loadMonitor(dirname(fileURLToPath(import.meta.url)));
    const domain = createNmzpPolicyDomain(source);
    const missing = await lstat(this.policyPath()).then(() => false, (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return true;
      throw error;
    });
    if (missing) {
      if (this.readOnly) throw new Error("policy_file_missing");
      const next: PolicyState = {
        ...DEFAULT_POLICY,
        customRules: (opts?.defaultRules ?? []).map((r) => ({ ...r })),
        updatedAt: Date.now(),
      };
      const seeded = opts?.defaultOverrides !== undefined ? parsePolicyOverrides(opts.defaultOverrides) : undefined;
      if (seeded) next.overrides = seeded;
      domain.prepare(createPolicySnapshot(next));
      this.policyLease!.assertOwned();
      // Exclusive bootstrap cannot replace an unexpected file. A partial bootstrap is
      // left for explicit recovery, never treated as a missing/default policy on restart.
      const file = await open(this.policyPath(), "wx", 0o600);
      try { await file.writeFile(JSON.stringify(next, null, 2)); await file.sync(); }
      finally { await file.close(); }
    }
    const file = { path: this.policyPath(), durability: "file" as const, operations: opts?.policyFileOperations };
    // Validate the actual policy against the trusted catalog before opening any
    // historical database or changing an existing legacy directory.
    const validated = await NmzpPolicyService.open({ file, source });
    if (this.storageMode === "sqlite") {
      if (!existsSync(this.policyHistoryPath())) {
        if (!missing || this.readOnly) throw new Error("policy_history_migration_required");
        this.policyLease!.assertOwned();
        this.policyHistory = PolicyHistory.create(this.policyHistoryPath(), validated.capture(), policyRulesHash(source), NMZP_VERSION);
      } else {
        this.policyHistory = PolicyHistory.open(this.policyHistoryPath(), this.readOnly);
      }
      this.policyService = await NmzpPolicyService.open({file, source, history:this.policyHistory});
    } else {
      if (existsSync(this.policyHistoryPath())) throw new Error("storage_mode_mismatch");
      this.policyService = validated;
    }
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
    this.invalidLinesOnLoad = 0;
    const runtime = this.storageMode === "sqlite" ? await AuditRuntime.open(this.policyHistoryPath(), {
      create: missing && !this.readOnly, readOnly: this.readOnly, retention: opts?.auditRetention,
    }) : undefined;
    try {this.auditEvents = await AuditEvents.open(this.eventsPath(), {runtime,readOnly:this.readOnly});}
    catch (error) {await runtime?.close();throw error;}
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
        if (!this.readOnly) this.rewriteNetworkSync();
      }
    }
    // The atomic devices snapshot is the sole commit point. Never ingest an ahead mirror after a crash.
    if (!canonical && !this.readOnly) await this.saveDevices();
    if (!this.readOnly) try { if (existsSync(this.networkPath()) || this.networkHistory.length) this.rewriteNetworkSync(); this.networkMirrorState = "current"; }
    catch { this.networkMirrorState = "repair_required"; }
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    this.assertWritable();
    const run = this.mutex.then(fn, fn);
    this.mutex = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** Compatibility entry point: all accepted policy writes are already durable. */
  async savePolicy(): Promise<void> {
    this.assertWritable();
    this.getPolicy();
    if (this.policyService.pendingCount) throw new Error("policy_write_pending");
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    await Promise.all([this.mutex, this.policyTail]);
    await this.auditEvents?.close();
    this.policyHistory?.close();
    this.policyLease?.close();
  }

  private assertPolicyReadable(): void {
    if (this.closing || !this.loaded) throw new Error("policy_writer_closed");
    if (!this.readOnly) this.policyLease!.assertOwned();
  }

  assertWritable(): void {
    if (this.readOnly) throw new Error("store_read_only");
    if (this.closing || !this.policyLease) throw new Error("policy_writer_closed");
    this.policyLease.assertOwned();
  }

  capturePolicy() {
    this.assertPolicyReadable();
    return this.policyService.capture();
  }
  listPolicyHistory(beforeVersion?: number, limit?: number) {
    this.assertPolicyReadable();
    return this.policyService.listHistory(beforeVersion, limit);
  }
  getStorageMode(): "window" | "sqlite" { return this.storageMode; }
  async queryAudit(query: AuditQuery) {
    this.assertPolicyReadable();
    if (!this.auditEvents?.runtime) throw new Error("storage_not_enabled");
    return this.auditEvents.runtime.query(query);
  }
  auditStatus() {
    this.assertPolicyReadable();
    if (!this.auditEvents?.runtime) throw new Error("storage_not_enabled");
    return this.auditEvents.runtime.status();
  }
  async maintainAuditRetentionStep():Promise<number> {
    return this.enqueue(async()=>{
      this.assertWritable();
      return this.auditEvents!.maintain();
    });
  }
  auditDeletionHighWatermark() {
    this.assertPolicyReadable();
    if (!this.auditEvents?.runtime) throw new Error("storage_not_enabled");
    return this.auditEvents.runtime.deletionHighWatermark();
  }
  auditDeletionsAfter(deletionId:number,highWatermark:number) {
    this.assertPolicyReadable();
    if (!this.auditEvents?.runtime) throw new Error("storage_not_enabled");
    return this.auditEvents.runtime.deletionCountAfter(deletionId,highWatermark);
  }
  async getAuditTombstone(machineId:string,eventId:string) {
    this.assertPolicyReadable();
    return this.auditEvents?.runtime?.getTombstone(machineId,eventId);
  }
  async confirmBackfillReceipt(machineId:string,eventId:string,evaluation:string,enforcement:Enforcement) {
    return this.enqueue(async()=>{
      return this.auditEvents!.confirmBackfillReceipt(machineId,eventId,evaluation,enforcement);
    });
  }
  getHistoricalPolicy(version: number) {
    this.assertPolicyReadable();
    return this.policyService.getHistorical(version);
  }
  async restorePolicy(expectedVersion: number, sourceVersion: number) {
    this.assertWritable();
    const result = this.policyService.restoreVersion(expectedVersion, sourceVersion);
    this.policyTail = Promise.allSettled([this.policyTail, result]);
    return result;
  }
  async saveDevices(): Promise<void> {
    this.assertWritable();
    await this.writeDeviceSnapshot(this.devices, this.networkHistory);
  }
  private async writeDeviceSnapshot(devices: Map<string, DeviceRecord>, history: NetworkHistoryRow[]): Promise<void> {
    await atomicWrite(this.devicesPath(), JSON.stringify({snapshotVersion:1, devices:[...devices.values()], networkHistory:history}, null, 2));
  }
  async saveMeta(): Promise<void> {
    this.assertWritable();
    await atomicWrite(this.metaPath(), JSON.stringify(this.meta, null, 2));
  }
  private rewriteNetworkSync(): void {
    const body =
      this.networkHistory.map((e) => JSON.stringify(e)).join("\n") + (this.networkHistory.length ? "\n" : "");
    atomicReplaceSync(this.networkPath(), body, 0o600);
  }

  getPolicy(): PolicyState {
    this.assertPolicyReadable();
    return this.policyService.getPolicy();
  }

  async casPolicy(expectedVersion: number, patch: Partial<Pick<PolicyState, "mode" | "customRules" | "stopped" | "archiveUpload" | "githubUpload" | "overrides" | "exemptions">>): Promise<PolicyState | { conflict: true; version: number }> {
    this.assertWritable();
    this.assertPolicyReadable();
    // The publisher captures/validates synchronously and owns the bounded queue.
    const result = this.policyService.casPolicy(expectedVersion, patch);
    this.policyTail = Promise.allSettled([this.policyTail, result]);
    return result;
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
    const policy = this.getPolicy();
    return [...this.devices.values()].map((d) => ({
      ...d,
      status: deriveDeviceStatus(d.lastSeen, now),
      stopState: deriveStopState(policy, d, now),
    }));
  }

  async withMutex<T>(fn: () => Promise<T> | T): Promise<T> {
    return this.enqueue(async () => fn());
  }

  async getEventUnlocked(deviceId: string, eventId: string): Promise<StoredEvent | undefined> {
    return this.auditEvents!.get(deviceId,eventId);
  }

  async appendEventUnlocked(ev: StoredEvent): Promise<StoredEvent> {
    this.assertWritable();
    return this.auditEvents!.append(ev);
  }

  previewPolicyPatch(expectedVersion: number, patch: Partial<Pick<PolicyState, "customRules" | "overrides" | "exemptions">>) {
    this.assertPolicyReadable();
    return this.policyService.previewPatch(expectedVersion, patch);
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

  async getEvent(deviceId: string, eventId: string): Promise<StoredEvent | undefined> {
    return this.getEventUnlocked(deviceId,eventId);
  }

  listEvents(limit = MAX_EVENTS): StoredEvent[] {
    return this.auditEvents!.list(limit);
  }

  async appendEvent(ev: StoredEvent): Promise<StoredEvent> {
    return this.enqueue(async () => this.appendEventUnlocked(ev));
  }

  evidenceWindow(): EvidenceWindow {
    return this.auditEvents!.evidenceWindow(this.networkMirrorState,this.invalidLinesOnLoad);
  }

  async updateReceipt(deviceId: string, eventId: string, enforcement: Enforcement): Promise<StoredEvent | { error: "not_found" | "forbidden" }> {
    return this.enqueue(async () => this.auditEvents!.updateReceipt(deviceId,eventId,enforcement));
  }

  async clearEvents(): Promise<void> {
    await this.enqueue(async () => this.auditEvents!.clear());
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
  store.assertWritable();
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
