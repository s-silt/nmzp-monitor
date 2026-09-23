import { createHash } from "node:crypto";
import { lstatSync, statSync } from "node:fs";
import { stat, statfs } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { dirname, isAbsolute } from "node:path";
import type { Enforcement, StoredEvent } from "../schema.ts";
import { decodeJson, encodeJson } from "./json-codec.ts";

export interface AuditQuery {
  limit: number;
  highWatermark?: number;
  beforeSeq?: number;
  machineId?: string;
  agent?: string;
  decision?: string;
  risk?: string;
  ruleId?: string;
  fromTs?: number;
  toTs?: number;
}

export interface AuditPage {
  events: StoredEvent[];
  highWatermark: number;
  nextBeforeSeq: number | null;
}

type Row = Record<string, unknown>;

export interface AuditRetention {
  maxRecords?: number;
  /** Age of locally ingested records; zero disables time pruning. */
  maxAgeMs?: number;
  maxDbBytes?: number;
  minFreeBytes?: number;
  tombstoneMs?: number;
}

function limits(input:AuditRetention={}):Required<AuditRetention> {
  const out={maxRecords:input.maxRecords??100_000,maxAgeMs:input.maxAgeMs??30*86400_000,
    maxDbBytes:input.maxDbBytes??1024*1024*1024,minFreeBytes:input.minFreeBytes??256*1024*1024,
    tombstoneMs:input.tombstoneMs??90*86400_000};
  for(const value of Object.values(out))if(!Number.isSafeInteger(value)||value<0)throw new Error("audit_retention_invalid");
  if(out.maxRecords<1 || out.maxRecords>10_000_000)throw new Error("audit_retention_invalid");
  return out;
}

/** One SQLite backend for policy and audit; no full-file event rewrites. */
export class AuditStore {
  readonly #path: string;
  readonly #readOnly: boolean;
  readonly #limits: Required<AuditRetention>;

  private constructor(path: string, readOnly = false, options:AuditRetention={}) {
    this.#path = path; this.#readOnly = readOnly; this.#limits=limits(options);
  }

  static create(path: string, options:AuditRetention={}): AuditStore {
    if (!isAbsolute(path)) throw new Error("audit_path_required");
    const store = new AuditStore(path,false,options);
    store.#db(true, (db) => {
      db.exec(`CREATE TABLE IF NOT EXISTS audit_meta(format_version INTEGER NOT NULL CHECK(format_version=1),retained_count INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit_events(
          seq INTEGER PRIMARY KEY AUTOINCREMENT, machine_id TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL,
          ingested_at INTEGER NOT NULL,
          agent TEXT NOT NULL, risk TEXT NOT NULL, decision TEXT NOT NULL, rule_id TEXT,
          policy_version INTEGER NOT NULL, policy_hash TEXT, layer TEXT NOT NULL,
          request_hash TEXT,
          enforcement TEXT NOT NULL, format_version INTEGER NOT NULL, codec TEXT NOT NULL,
          raw_bytes INTEGER NOT NULL, body BLOB NOT NULL, body_hash TEXT NOT NULL,
          UNIQUE(machine_id,id));
        CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events(ts,seq);
        CREATE INDEX IF NOT EXISTS audit_events_machine ON audit_events(machine_id,seq);
        CREATE INDEX IF NOT EXISTS audit_events_agent ON audit_events(agent,seq);
        CREATE INDEX IF NOT EXISTS audit_events_decision ON audit_events(decision,seq);
        CREATE INDEX IF NOT EXISTS audit_events_ingested ON audit_events(ingested_at,seq);
        CREATE INDEX IF NOT EXISTS audit_events_policy_version ON audit_events(policy_version);
        CREATE TABLE IF NOT EXISTS audit_deletions(id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
          reason TEXT NOT NULL, first_seq INTEGER, last_seq INTEGER, count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_tombstones(machine_id TEXT NOT NULL,id TEXT NOT NULL,request_hash TEXT,
          policy_version INTEGER NOT NULL,policy_hash TEXT,deleted_at INTEGER NOT NULL,reason TEXT NOT NULL,
          PRIMARY KEY(machine_id,id));
        CREATE INDEX IF NOT EXISTS audit_tombstones_deleted ON audit_tombstones(deleted_at);`);
      if (!db.prepare("SELECT format_version FROM audit_meta").get()) db.exec("INSERT INTO audit_meta(format_version,retained_count) VALUES(1,0)");
    });
    return store;
  }

  static open(path: string, readOnly = false, options:AuditRetention={}): AuditStore {
    if (!isAbsolute(path)) throw new Error("audit_path_required");
    const entry = lstatSync(path);
    if (!entry.isFile() || entry.isSymbolicLink()) throw new Error("audit_not_regular");
    const store = new AuditStore(path, readOnly, options);
    store.#db(false, (db) => {
      if (db.prepare("SELECT format_version FROM audit_meta").get()?.format_version !== 1) throw new Error("audit_schema_invalid");
    });
    return store;
  }

  #db<T>(write: boolean, fn: (db: DatabaseSync) => T): T {
    if (write && this.#readOnly) throw new Error("audit_read_only");
    const db = new DatabaseSync(this.#path, {readOnly: !write});
    try {
      if (write) db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000");
      return fn(db);
    } finally { db.close(); }
  }

  async #event(row: Row): Promise<StoredEvent> {
    const bytes = Buffer.from(row.body as Uint8Array);
    if (createHash("sha256").update(bytes).digest("hex") !== row.body_hash) throw new Error("audit_corrupt");
    let raw: unknown;
    try {
      raw = await decodeJson({version:row.format_version as 1,codec:row.codec as "json"|"gzip",
        rawBytes:row.raw_bytes as number,data:bytes});
    } catch { throw new Error("audit_corrupt"); }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("audit_corrupt");
    const ev = raw as StoredEvent;
    if (ev.id !== row.id || ev.machineId !== row.machine_id || ev.ts !== row.ts || ev.policyVersion !== row.policy_version) {
      throw new Error("audit_corrupt");
    }
    return {...ev,enforcement:row.enforcement as Enforcement};
  }

  async append(event: StoredEvent): Promise<{inserted:boolean;event:StoredEvent;pruned?:Array<{machineId:string;id:string}>}> {
    if (!event || typeof event.id !== "string" || !event.id || typeof event.machineId !== "string" || !event.machineId
      || !Number.isSafeInteger(event.ts) || !Number.isSafeInteger(event.policyVersion)) throw new Error("audit_event_invalid");
    let canonical: string;
    try { canonical = JSON.stringify(event); }
    catch { throw new Error("audit_event_invalid"); }
    if (Buffer.byteLength(canonical,"utf8") > 1024*1024) throw new Error("audit_event_too_large");
    const owned = JSON.parse(canonical) as StoredEvent;
    const encoded = await encodeJson(owned);
    const bodyHash = createHash("sha256").update(encoded.data).digest("hex");
    const existingTombstone=this.#db(false,(db)=>db.prepare("SELECT id FROM audit_tombstones WHERE machine_id=? AND id=?").get(owned.machineId,owned.id));
    if(existingTombstone)throw new Error("audit_event_expired");
    const existing = this.#db(false, (db) => db.prepare("SELECT seq,body_hash FROM audit_events WHERE machine_id=? AND id=?").get(owned.machineId,owned.id));
    if (existing) {
      if (existing.body_hash !== bodyHash) throw new Error("audit_event_conflict");
      return {inserted:false,event:(await this.get(owned.machineId,owned.id))!};
    }
    const estimated=encoded.data.length*2+65536;
    const disk=await stat(this.#path);
    const journal=await stat(`${this.#path}-journal`).then((s)=>s.size,()=>0);
    const free=await statfs(dirname(this.#path));
    if(disk.size+journal+estimated>this.#limits.maxDbBytes || Number(free.bavail)*Number(free.bsize)<this.#limits.minFreeBytes+estimated){
      throw new Error("audit_capacity_exceeded");
    }
    return this.#db(true, (db) => {
      db.exec("BEGIN IMMEDIATE");
      try {
        db.prepare(`INSERT INTO audit_events(machine_id,id,ts,ingested_at,agent,risk,decision,rule_id,policy_version,policy_hash,layer,request_hash,enforcement,format_version,codec,raw_bytes,body,body_hash)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(owned.machineId,owned.id,owned.ts,Date.now(),owned.agent,owned.risk,owned.decision,owned.ruleId??null,
          owned.policyVersion,owned.policyHash??null,owned.layer,owned.requestHash??null,owned.enforcement,encoded.version,encoded.codec,encoded.rawBytes,encoded.data,bodyHash);
        db.exec("UPDATE audit_meta SET retained_count=retained_count+1");
        const pruned:Array<{machineId:string;id:string}>=[];
        this.#prune(db,Date.now(),false,pruned);
        db.exec("COMMIT");
        return {inserted:true,event:owned,pruned};
      } catch (error) {
        try{db.exec("ROLLBACK");}catch{/* SQLite may already have rolled back */}
        if (String(error).includes("UNIQUE")) throw new Error("audit_event_conflict");
        throw error;
      }
    });
  }

  #prune(db:DatabaseSync,now:number,allowBacklog=false,removed?:Array<{machineId:string;id:string}>):number {
    const count=Number(db.prepare("SELECT retained_count AS n FROM audit_meta").get()!.n);
    const excess=Math.max(0,count-this.#limits.maxRecords);
    if(excess>100 && !allowBacklog)throw new Error("audit_retention_pending");
    const old=this.#limits.maxAgeMs>0 ? db.prepare("SELECT seq FROM audit_events WHERE ingested_at<? ORDER BY seq LIMIT 100").all(now-this.#limits.maxAgeMs) : [];
    const oldest=excess>0?db.prepare("SELECT seq FROM audit_events ORDER BY seq LIMIT ?").all(Math.min(excess,100)):[];
    const ids=new Set<number>([...old,...oldest].map((r)=>r.seq as number));
    if(!ids.size){
      if(this.#limits.tombstoneMs>0)db.prepare("DELETE FROM audit_tombstones WHERE deleted_at<?").run(now-this.#limits.tombstoneMs);
      return 0;
    }
    const candidates=[...ids].sort((a,b)=>a-b).slice(0,100);
    const choose=db.prepare("SELECT * FROM audit_events WHERE seq=?");
    const tomb=db.prepare("INSERT OR IGNORE INTO audit_tombstones(machine_id,id,request_hash,policy_version,policy_hash,deleted_at,reason) VALUES(?,?,?,?,?,?,?)");
    const del=db.prepare("DELETE FROM audit_events WHERE seq=?");
    for(const seq of candidates){
      const row=choose.get(seq)!;
      const reason=old.some((r)=>r.seq===seq)?"max_age":"max_records";
      removed?.push({machineId:row.machine_id as string,id:row.id as string});
      tomb.run(row.machine_id as string,row.id as string,row.request_hash as string|null,row.policy_version as number,row.policy_hash as string|null,now,reason);
      del.run(seq);
      db.prepare("INSERT INTO audit_deletions(at,reason,first_seq,last_seq,count) VALUES(?,?,?,?,1)").run(now,reason,seq,seq);
    }
    db.prepare("UPDATE audit_meta SET retained_count=retained_count-?").run(candidates.length);
    if(this.#limits.tombstoneMs>0)db.prepare("DELETE FROM audit_tombstones WHERE deleted_at<?").run(now-this.#limits.tombstoneMs);
    return candidates.length;
  }

  maintenanceStep(now=Date.now()):{removed:number;identities:Array<{machineId:string;id:string}>} {
    return this.#db(true,(db)=>{
      db.exec("BEGIN IMMEDIATE");
      try{const identities:Array<{machineId:string;id:string}>=[];
        const removed=this.#prune(db,now,true,identities);db.exec("COMMIT");return {removed,identities};}
      catch(error){try{db.exec("ROLLBACK");}catch{/* SQLite may already have rolled back */}throw error;}
    });
  }

  async getTombstone(machineId:string,id:string):Promise<{reason:string;policyVersion:number;requestHash?:string}|undefined>{
    const row=this.#db(false,(db)=>db.prepare("SELECT reason,policy_version,request_hash FROM audit_tombstones WHERE machine_id=? AND id=?").get(machineId,id));
    return row?{reason:row.reason as string,policyVersion:row.policy_version as number,
      ...(row.request_hash?{requestHash:row.request_hash as string}:{})}:undefined;
  }

  status(){
    return this.#db(false,(db)=>{
      const retained=Number(db.prepare("SELECT retained_count AS n FROM audit_meta").get()!.n);
      const deleted=Number(db.prepare("SELECT coalesce(sum(count),0) AS n FROM audit_deletions").get()!.n);
      const tombstones=Number(db.prepare("SELECT count(*) AS n FROM audit_tombstones").get()!.n);
      const aged=this.#limits.maxAgeMs>0 ? Number(db.prepare("SELECT count(*) AS n FROM audit_events WHERE ingested_at<?")
        .get(Date.now()-this.#limits.maxAgeMs)!.n) : 0;
      const pages=Number(db.prepare("PRAGMA freelist_count").get()!.freelist_count);
      const pageSize=Number(db.prepare("PRAGMA page_size").get()!.page_size);
      return {retained,deleted,tombstones,retentionPending:Math.max(aged,retained-this.#limits.maxRecords,0),
        dbBytes:statSync(this.#path).size,reusableBytes:pages*pageSize,
        limits:this.#limits,physicalShrink:"manual_vacuum_required" as const};
    });
  }

  deletionHighWatermark():number {
    return this.#db(false,(db)=>Number(db.prepare("SELECT coalesce(max(id),0) AS n FROM audit_deletions").get()!.n));
  }
  deletionCountAfter(deletionId:number,highWatermark:number):number {
    if(!Number.isSafeInteger(deletionId)||!Number.isSafeInteger(highWatermark))throw new Error("audit_query_invalid");
    return this.#db(false,(db)=>Number(db.prepare("SELECT coalesce(sum(count),0) AS n FROM audit_deletions WHERE id>? AND first_seq<=?")
      .get(deletionId,highWatermark)!.n));
  }

  async get(machineId: string, id: string): Promise<StoredEvent | undefined> {
    const row = this.#db(false, (db) => db.prepare("SELECT * FROM audit_events WHERE machine_id=? AND id=?").get(machineId,id));
    return row ? this.#event(row) : undefined;
  }

  async recent(limit: number): Promise<StoredEvent[]> {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > 2000) throw new Error("audit_limit_invalid");
    const rows = this.#db(false, (db) => db.prepare("SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?").all(limit));
    const out: StoredEvent[] = [];
    for (const row of rows.reverse()) out.push(await this.#event(row));
    return out;
  }

  async updateReceipt(machineId: string, id: string, enforcement: Enforcement): Promise<StoredEvent | {error:"not_found"|"forbidden"}> {
    const row = this.#db(false, (db) => db.prepare("SELECT layer FROM audit_events WHERE machine_id=? AND id=?").get(machineId,id));
    if (!row) return {error:"not_found"};
    if (row.layer === "model_response") return {error:"forbidden"};
    this.#db(true, (db) => db.prepare("UPDATE audit_events SET enforcement=? WHERE machine_id=? AND id=?").run(enforcement,machineId,id));
    return (await this.get(machineId,id))!;
  }

  async confirmBackfillReceipt(machineId:string,id:string,evaluation:string,enforcement:Enforcement):Promise<
    {event:StoredEvent;duplicate:boolean}|{error:"not_found"|"forbidden"|"conflict"|"evaluation_immutable"}> {
    const original=await this.get(machineId,id);
    if(!original)return {error:"not_found"};
    if(original.layer==="model_response")return {error:"forbidden"};
    if(original.evaluation!==evaluation)return {error:"evaluation_immutable"};
    const outcome=this.#db(true,(db)=>{
      db.exec("BEGIN IMMEDIATE");
      try{
        const row=db.prepare("SELECT enforcement FROM audit_events WHERE machine_id=? AND id=?").get(machineId,id);
        if(!row){db.exec("ROLLBACK");return "not_found" as const;}
        if(row.enforcement===enforcement){db.exec("COMMIT");return "duplicate" as const;}
        if(!["pending_verify","offline","timeout","failed","degraded"].includes(row.enforcement as string)){
          db.exec("ROLLBACK");return "conflict" as const;
        }
        db.prepare("UPDATE audit_events SET enforcement=? WHERE machine_id=? AND id=?").run(enforcement,machineId,id);
        db.exec("COMMIT");return "updated" as const;
      }catch(error){try{db.exec("ROLLBACK");}catch{/* SQLite may already have rolled back */}throw error;}
    });
    if(outcome==="not_found"||outcome==="conflict")return {error:outcome};
    return {event:(await this.get(machineId,id))!,duplicate:outcome==="duplicate"};
  }

  async query(input: AuditQuery): Promise<AuditPage> {
    const {limit} = input;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 25) throw new Error("audit_query_invalid");
    const high = input.highWatermark ?? this.#db(false,(db)=>Number(db.prepare("SELECT coalesce(max(seq),0) AS n FROM audit_events").get()!.n));
    const before = input.beforeSeq ?? Number.MAX_SAFE_INTEGER;
    if (!Number.isSafeInteger(high) || high < 0 || !Number.isSafeInteger(before) || before < 1) throw new Error("audit_query_invalid");
    const where = ["seq<=?","seq<?"];
    const args: Array<string|number> = [high,before];
    for (const [key,col] of [["machineId","machine_id"],["agent","agent"],["decision","decision"],["risk","risk"],["ruleId","rule_id"]] as const) {
      const value = input[key];
      if (value !== undefined) {if (!value || value.length > 128) throw new Error("audit_query_invalid");where.push(`${col}=?`);args.push(value);}
    }
    if (input.fromTs !== undefined) {if (!Number.isSafeInteger(input.fromTs)) throw new Error("audit_query_invalid");where.push("ts>=?");args.push(input.fromTs);}
    if (input.toTs !== undefined) {if (!Number.isSafeInteger(input.toTs)) throw new Error("audit_query_invalid");where.push("ts<=?");args.push(input.toTs);}
    const rows = this.#db(false,(db)=>db.prepare(`SELECT * FROM audit_events WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT ?`).all(...args,limit));
    const events: StoredEvent[] = [];
    for (const row of rows) events.push(await this.#event(row));
    return {events,highWatermark:high,nextBeforeSeq:rows.length===limit?rows.at(-1)!.seq as number:null};
  }

  clear(reason = "admin_clear"): number {
    return this.#db(true,(db)=>{
      db.exec("BEGIN IMMEDIATE");
      try {
        const span = db.prepare("SELECT min(seq) AS first,max(seq) AS last,count(*) AS n FROM audit_events").get()!;
        db.prepare("INSERT OR IGNORE INTO audit_tombstones(machine_id,id,request_hash,policy_version,policy_hash,deleted_at,reason) SELECT machine_id,id,request_hash,policy_version,policy_hash,?,? FROM audit_events")
          .run(Date.now(),reason);
        db.exec("DELETE FROM audit_events");
        db.exec("UPDATE audit_meta SET retained_count=0");
        if (Number(span.n)>0) db.prepare("INSERT INTO audit_deletions(at,reason,first_seq,last_seq,count) VALUES(?,?,?,?,?)")
          .run(Date.now(),reason,span.first as number,span.last as number,span.n as number);
        db.exec("COMMIT");
        return Number(span.n);
      } catch(error) {try{db.exec("ROLLBACK");}catch{/* SQLite may already have rolled back */}throw error;}
    });
  }
}
