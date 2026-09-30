import type { EvaluationRecord, EvaluationIdentity } from "./evaluation-record.ts";
import { appendFileSync, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { atomicReplaceSync } from "../atomic-file.ts";
import { MAX_EVENTS } from "../constants.ts";
import type { EvidenceWindow } from "../evidence-window.ts";
import type { Enforcement, StoredEvent } from "../schema.ts";
import { RecentEvents } from "./recent-events.ts";
import type { AuditRuntime } from "./runtime.ts";

const eventKey = (machineId: string, id: string) => JSON.stringify([machineId, id]);

/** Owns the legacy window or the SQLite-backed recent projection, never both. */
export class AuditEvents {
  readonly runtime?: AuditRuntime;
  readonly #path: string;
  #recent?: RecentEvents<StoredEvent>;
  #events: StoredEvent[] = [];
  #dedup = new Map<string, StoredEvent>();
  #droppedSinceLoad = 0;
  #invalidLinesOnLoad = 0;
  readonly loadedAt = Date.now();

  private constructor(path: string, runtime?: AuditRuntime) { this.#path = path; this.runtime = runtime; }

  static async open(path: string, options: { runtime?: AuditRuntime; readOnly?: boolean } = {}): Promise<AuditEvents> {
    const log = new AuditEvents(path,options.runtime);
    if (options.runtime) {
      const runtime = options.runtime;
      runtime.setReconciler(async (channel) => {
        log.#replaceProjection(await channel.call<StoredEvent[]>("recent", MAX_EVENTS));
      });
      log.#replaceProjection(await runtime.recent(MAX_EVENTS));
    } else if (existsSync(path)) {
      const raw = await readFile(path,"utf8");
      for (const line of raw.split(/\n/)) {
        const text=line.trim();
        if(!text)continue;
        try {
          const event=JSON.parse(text) as StoredEvent;
          if(event && typeof event.id==="string" && typeof event.redacted==="string") {
            log.#events.push(event);
            if(event.machineId)log.#dedup.set(eventKey(event.machineId,event.id),event);
          } else log.#invalidLinesOnLoad++;
        } catch {log.#invalidLinesOnLoad++;}
      }
      if(log.#events.length>MAX_EVENTS){
        log.#droppedSinceLoad+=log.#events.length-MAX_EVENTS;
        log.#events=log.#events.slice(-MAX_EVENTS);
        log.#dedup=new Map(log.#events.map((event)=>[eventKey(event.machineId,event.id),event]));
        if(!options.readOnly)log.#rewrite();
      }
    }
    return log;
  }

  list(limit=MAX_EVENTS):StoredEvent[]{return this.#events.slice(-limit);}
  evidenceWindow(networkMirrorState:EvidenceWindow["networkMirrorState"],otherInvalidLines=0):EvidenceWindow {
    const timestamps=this.#events.map((event)=>event.ts).filter(Number.isFinite);
    return {limit:MAX_EVENTS,retained:this.#events.length,droppedSinceLoad:this.#droppedSinceLoad,
      invalidLinesOnLoad:this.#invalidLinesOnLoad+otherInvalidLines,loadedAt:this.loadedAt,
      historyCompleteness:"unknown",receiptDelivery:"best_effort",networkMirrorState,
      ...(timestamps.length?{oldestTs:Math.min(...timestamps),newestTs:Math.max(...timestamps)}:{})};
  }

  async get(machineId:string,id:string):Promise<StoredEvent|undefined>{
    const runtime = this.runtime;
    if (runtime && runtime.state !== "ready") {
      const message = runtime.state === "recovering" ? "audit_worker_recovering"
        : runtime.state === "failed" ? "audit_worker_unavailable" : "audit_worker_closed";
      throw new Error(message);
    }
    return this.#dedup.get(eventKey(machineId,id))??await runtime?.get(machineId,id);
  }

  async lookupIdentity(machineId: string, id: string): Promise<EvaluationIdentity | undefined> {
    if (this.runtime) return this.runtime.lookupIdentity(machineId, id);
    const event = await this.get(machineId, id);
    return event ? { kind: "event", originProtocol: "v1", event } : undefined;
  }

  async appendEvaluation(record: EvaluationRecord): Promise<EvaluationRecord> {
    if (!this.runtime) throw new Error("storage_not_enabled");
    const result = await this.runtime.appendEvaluation(record);
    this.#dropRecent(result.pruned);
    // Hidden rows never enter the cache or displace a public event, including after recovery.
    if (result.inserted && result.record.publicEvent) this.#publish(result.record.publicEvent);
    return result.record;
  }

  #publish(event: StoredEvent): void {
    const added = this.#recent!.append(event);
    this.#events = this.#recent!.list();
    this.#dedup.set(eventKey(event.machineId,event.id),event);
    if (added.inserted && added.evicted) {
      this.#dedup.delete(eventKey(added.evicted.machineId,added.evicted.id)); this.#droppedSinceLoad++;
    }
  }

  async append(event:StoredEvent):Promise<StoredEvent>{
    if(this.runtime){
      const result=await this.runtime.append(event);
      if(!result.inserted)return {...result.event,duplicate:true};
      this.#dropRecent(result.pruned??[]);
      const added=this.#recent!.append(result.event);
      this.#events=this.#recent!.list();
      this.#dedup.set(eventKey(event.machineId,event.id),result.event);
      if(added.inserted&&added.evicted){
        this.#dedup.delete(eventKey(added.evicted.machineId,added.evicted.id));
        this.#droppedSinceLoad++;
      }
      return result.event;
    }
    const key=eventKey(event.machineId,event.id);
    const previous=this.#dedup.get(key);
    if(previous)return {...previous,duplicate:true};
    const next=[...this.#events,event];
    const drop=Math.max(0,next.length-MAX_EVENTS);
    if(drop)atomicReplaceSync(this.#path,next.slice(drop).map((row)=>JSON.stringify(row)).join("\n")+"\n",0o600);
    else appendFileSync(this.#path,JSON.stringify(event)+"\n",{mode:0o600});
    this.#events=next.slice(drop);
    this.#droppedSinceLoad+=drop;
    this.#dedup=new Map(this.#events.map((row)=>[eventKey(row.machineId,row.id),row]));
    return event;
  }

  async updateReceipt(machineId:string,id:string,enforcement:Enforcement):Promise<StoredEvent|{error:"not_found"|"forbidden"}>{
    if(this.runtime){
      const result=await this.runtime.updateReceipt(machineId,id,enforcement);
      if("error" in result)return result;
      if(this.#recent!.update(result))this.#dedup.set(eventKey(machineId,id),result);
      this.#events=this.#recent!.list();
      return result;
    }
    const key=eventKey(machineId,id),event=this.#dedup.get(key);
    if(!event)return {error:"not_found"};
    if(event.machineId!==machineId||event.layer==="model_response")return {error:"forbidden"};
    const next={...event,enforcement};
    const rows=this.#events.map((row)=>row.id===id&&row.machineId===machineId?next:row);
    atomicReplaceSync(this.#path,rows.map((row)=>JSON.stringify(row)).join("\n")+(rows.length?"\n":""));
    this.#events=rows;this.#dedup.set(key,next);
    return next;
  }

  async confirmBackfillReceipt(machineId:string,id:string,evaluation:string,enforcement:Enforcement){
    if(!this.runtime)throw new Error("storage_not_enabled");
    const result=await this.runtime.confirmBackfillReceipt(machineId,id,evaluation,enforcement);
    if("event" in result){
      if(this.#recent!.update(result.event))this.#dedup.set(eventKey(machineId,id),result.event);
      this.#events=this.#recent!.list();
    }
    return result;
  }

  async maintain(onBatch?: (needsFollowup: boolean) => void):Promise<number>{
    if(!this.runtime)return 0;
    const result=await this.runtime.maintenanceStep();
    this.#dropRecent(result.identities);
    onBatch?.(result.needsFollowup);
    return result.removed;
  }

  async clear():Promise<void>{
    if(this.runtime){await this.runtime.clear();this.#recent!.clear();}
    else atomicReplaceSync(this.#path,"");
    this.#events=[];this.#dedup.clear();
  }

  async close():Promise<void>{await this.runtime?.close();}

  #replaceProjection(rows: StoredEvent[]): void {
    const recent = new RecentEvents<StoredEvent>(MAX_EVENTS);
    for (const event of rows) recent.append(event);
    this.#recent = recent;
    this.#events = recent.list();
    this.#dedup = new Map(this.#events.map((event) => [eventKey(event.machineId,event.id), event]));
    this.#droppedSinceLoad = 0;
  }

  #rewrite():void{
    atomicReplaceSync(this.#path,this.#events.map((event)=>JSON.stringify(event)).join("\n")+(this.#events.length?"\n":""),0o600);
  }

  #dropRecent(identities:Array<{machineId:string;id:string}>):void{
    if(!identities.length)return;
    const removed=new Set(identities.map(({machineId,id})=>JSON.stringify([machineId,id])));
    const kept=this.#events.filter(({machineId,id})=>!removed.has(JSON.stringify([machineId,id])));
    if(kept.length===this.#events.length)return;
    this.#recent=new RecentEvents<StoredEvent>(MAX_EVENTS);
    for(const event of kept)this.#recent.append(event);
    this.#events=this.#recent.list();
    this.#dedup=new Map(this.#events.map((event)=>[eventKey(event.machineId,event.id),event]));
  }
}
