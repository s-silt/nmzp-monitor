import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, createReadStream, existsSync } from "node:fs";
import { copyFile, lstat, mkdir, open, readFile, rename, statfs, unlink } from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { TextDecoder } from "node:util";
import { AuditStore } from "./audit/store.ts";
import { NMZP_VERSION } from "./constants.ts";
import { atomicWrite } from "./atomic-file.ts";
import { servePointerPath } from "./persist.ts";
import { createNmzpPolicyDomain, type NmzpPolicySource } from "./policy/nmzp-domain.ts";
import { FilePolicyStore } from "./policy/file-store.ts";
import { PolicyHistory } from "./policy/history.ts";
import { policyRulesHash } from "./policy/nmzp-service.ts";
import { PolicyWriterLease } from "./policy/writer-lease.ts";
import type { PolicyState, StoredEvent } from "./schema.ts";

const LEGACY_FILES = ["policy.json","events.jsonl","devices.json","network.jsonl","meta.json"] as const;
const MAX_LINE = 1024 * 1024;
const MAX_EVENTS_TO_SCAN = 1_000_000;
const MARKER = ".nmzp-migration.json";
const BACKUP = ".nmzp-migration-backup";

export interface LegacyFileFact {bytes:number;sha256:string}
export interface MigrationPreflight {
  dataDir:string;
  files:Record<string,LegacyFileFact>;
  policyVersion:number|null;
  policyHash:string|null;
  events:{valid:number;invalid:number;duplicate:number;conflict:number;missingHistory:number;incompleteTail:boolean};
  estimatedRequiredBytes:number;
  availableBytes:number|null;
  issues:string[];
  canMigrate:boolean;
}
interface Manifest {formatVersion:1;state:"preparing"|"backup_done"|"importing"|"complete";files:Record<string,LegacyFileFact>;
  policyVersion:number;policyHash:string;backupDir:string;imported:number;completedAt?:number}

function directory(dir:string):string {
  if (!isAbsolute(dir) || !dir.trim() || dir.includes("\0")) throw new Error("explicit_data_dir_required");
  return resolve(dir);
}

async function fileFact(path:string):Promise<LegacyFileFact|undefined> {
  let size:number;
  try {const entry=await lstat(path);if(!entry.isFile() || entry.isSymbolicLink())throw new Error("migration_nonregular_file");size=entry.size;}
  catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return undefined;throw error;}
  const sha=createHash("sha256");
  for await(const chunk of createReadStream(path)) sha.update(chunk as Buffer);
  return {bytes:size,sha256:sha.digest("hex")};
}

async function* boundedLines(path:string):AsyncGenerator<Buffer> {
  let carry=Buffer.alloc(0);
  for await(const chunk of createReadStream(path,{highWaterMark:64*1024})) {
    const bytes=Buffer.concat([carry,chunk as Buffer]);
    let start=0;
    for(let i=0;i<bytes.length;i++) if(bytes[i]===10){
      const line=bytes.subarray(start,i);
      if(line.length>MAX_LINE)throw new Error("migration_line_too_large");
      yield line;
      start=i+1;
    }
    carry=Buffer.from(bytes.subarray(start));
    if(carry.length>MAX_LINE)throw new Error("migration_line_too_large");
  }
  if(carry.length)yield carry;
}

function decodeLine(line:Buffer):StoredEvent {
  const raw=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(line);
  const event=JSON.parse(raw) as StoredEvent;
  if(!event || typeof event!=="object" || Array.isArray(event) || typeof event.id!=="string" || !event.id
    || typeof event.machineId!=="string" || !event.machineId || typeof event.redacted!=="string"
    || typeof event.agent!=="string" || typeof event.layer!=="string" || typeof event.enforcement!=="string"
    || !Number.isSafeInteger(event.ts) || !Number.isSafeInteger(event.policyVersion)) throw new Error("migration_invalid_event");
  return event;
}

export async function preflightDataDir<Rule extends {id:string}>(rawDir:string,source:NmzpPolicySource<Rule>):Promise<MigrationPreflight> {
  const dir=directory(rawDir);
  const issues:string[]=[];
  const files:Record<string,LegacyFileFact>={};
  for(const name of LEGACY_FILES){const fact=await fileFact(join(dir,name));if(fact)files[name]=fact;}
  let policyVersion:number|null=null,policyHash:string|null=null;
  if(!files["policy.json"])issues.push("policy_missing");
  else try {
    const file=await FilePolicyStore.open<PolicyState>({path:join(dir,"policy.json"),durability:"file"});
    const snapshot=await file.read();
    createNmzpPolicyDomain(source).prepare(snapshot);
    policyVersion=snapshot.policy.version;
    policyHash=snapshot.hash;
  } catch(error){issues.push(`policy_invalid:${error instanceof Error?error.message:"unknown"}`);}
  const events={valid:0,invalid:0,duplicate:0,conflict:0,missingHistory:0,incompleteTail:false};
  if(files["events.jsonl"]){
    const seen=new Map<string,string>();
    let lastHadNewline=true;
    const handle=await open(join(dir,"events.jsonl"),"r");
    try {if(files["events.jsonl"].bytes){const b=Buffer.alloc(1);await handle.read(b,0,1,files["events.jsonl"].bytes-1);lastHadNewline=b[0]===10;}}
    finally {await handle.close();}
    let index=0;
    try {for await(const line of boundedLines(join(dir,"events.jsonl"))){
      index++;
      if(index>MAX_EVENTS_TO_SCAN){issues.push("event_count_limit");break;}
      if(!line.length)continue;
      try {
        const ev=decodeLine(line);
        events.valid++;
        if(ev.policyVersion!==policyVersion || !ev.policyHash)events.missingHistory++;
        const key=`${ev.machineId.length}:${ev.machineId}${ev.id}`;
        const hash=createHash("sha256").update(JSON.stringify(ev)).digest("hex");
        const prior=seen.get(key);
        if(prior){if(prior===hash)events.duplicate++;else events.conflict++;}
        else seen.set(key,hash);
      } catch {events.invalid++;if(!lastHadNewline)events.incompleteTail=true;}
    }} catch(error){issues.push(error instanceof Error?error.message:"event_scan_failed");}
    if(events.invalid)issues.push("invalid_event_records");
    if(events.conflict)issues.push("conflicting_event_ids");
    if(events.valid-events.duplicate>100_000)issues.push("event_count_exceeds_default_retention");
  }
  const total=Object.values(files).reduce((sum,f)=>sum+f.bytes,0);
  const estimatedRequiredBytes=total*2+32*1024*1024;
  let availableBytes:number|null=null;
  try {const fs=await statfs(dir);availableBytes=Number(fs.bavail)*Number(fs.bsize);if(availableBytes<estimatedRequiredBytes)issues.push("insufficient_space");}
  catch{issues.push("space_unknown");}
  return {dataDir:dir,files,policyVersion,policyHash,events,estimatedRequiredBytes,availableBytes,issues,canMigrate:issues.length===0};
}

async function readManifest(path:string):Promise<Manifest|undefined> {
  try {const value=JSON.parse(await readFile(path,"utf8")) as Manifest;
    if(value.formatVersion!==1 || !["preparing","backup_done","importing","complete"].includes(value.state)
      || !value.files || !value.backupDir || !Number.isSafeInteger(value.policyVersion))throw new Error("migration_manifest_invalid");
    return value;
  } catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")return undefined;throw error;}
}
async function saveManifest(path:string,value:Manifest):Promise<void>{await atomicWrite(path,JSON.stringify(value),0o600);}

/** Test-only fault hook; never read from CLI/configuration. */
export interface MigrationOptions {afterImported?:(count:number)=>void}

export async function migrateDataDir<Rule extends {id:string}>(rawDir:string,source:NmzpPolicySource<Rule>,options:MigrationOptions={}):Promise<{state:"complete";historyBaselineVersion:number;imported:number}> {
  const dir=directory(rawDir);
  const lease=new PolicyWriterLease(join(dir,".policy-writer.lock"));
  try {
    if(existsSync(servePointerPath(dir)))throw new Error("migration_live_writer_possible");
    const report=await preflightDataDir(dir,source);
    if(!report.canMigrate || report.policyVersion===null || report.policyHash===null)throw new Error(`migration_preflight_failed:${report.issues.join(",")}`);
    const marker=join(dir,MARKER);
    let manifest=await readManifest(marker);
    if(manifest){
      for(const [name,fact] of Object.entries(manifest.files)) if(report.files[name]?.sha256!==fact.sha256 || report.files[name]?.bytes!==fact.bytes)throw new Error("migration_source_changed");
      if(manifest.policyHash!==report.policyHash || manifest.policyVersion!==report.policyVersion)throw new Error("migration_source_changed");
      if(manifest.state==="complete")return {state:"complete",historyBaselineVersion:manifest.policyVersion,imported:manifest.imported};
    } else {
      manifest={formatVersion:1,state:"preparing",files:report.files,policyVersion:report.policyVersion,policyHash:report.policyHash,
        backupDir:BACKUP,imported:0};
      const handle=await open(marker,"wx",0o600);
      try{await handle.writeFile(JSON.stringify(manifest));await handle.sync();}finally{await handle.close();}
    }
    const backup=join(dir,BACKUP);
    await mkdir(backup,{recursive:true,mode:0o700});
    for(const [name,fact] of Object.entries(manifest.files)){
      if(!LEGACY_FILES.includes(name as typeof LEGACY_FILES[number]) || basename(name)!==name)throw new Error("migration_manifest_invalid");
      const target=join(backup,name);
      const prior=await fileFact(target);
      if(!prior)await copyFile(join(dir,name),target);
      const copied=await fileFact(target);
      if(copied?.sha256!==fact.sha256 || copied.bytes!==fact.bytes)throw new Error("migration_backup_mismatch");
    }
    manifest.state="backup_done";await saveManifest(marker,manifest);
    lease.assertOwned();
    const file=await FilePolicyStore.open<PolicyState>({path:join(dir,"policy.json"),durability:"file"});
    const initial=await file.read();
    const dbPath=join(dir,"nmzp.db");
    const history=existsSync(dbPath)?PolicyHistory.open<PolicyState>(dbPath)
      :PolicyHistory.create(dbPath,initial,policyRulesHash(source),NMZP_VERSION);
    try {if(history.current().hash!==initial.hash)throw new Error("migration_policy_mismatch");}
    finally {history.close();}
    const audit=AuditStore.create(dbPath);
    manifest.state="importing";await saveManifest(marker,manifest);
    let imported=0;
    if(report.files["events.jsonl"])for await(const line of boundedLines(join(dir,"events.jsonl"))){
      if(!line.length)continue;
      const result=await audit.append(decodeLine(line));
      if(result.inserted)imported++;
      options.afterImported?.(imported);
    }
    for(const [name,fact] of Object.entries(manifest.files)){
      const current=await fileFact(join(dir,name));
      if(current?.sha256!==fact.sha256 || current.bytes!==fact.bytes)throw new Error("migration_source_changed");
    }
    const expected=report.events.valid-report.events.duplicate;
    if(audit.status().retained!==expected)throw new Error("migration_import_mismatch");
    manifest.imported=expected;
    manifest.state="complete";manifest.completedAt=Date.now();await saveManifest(marker,manifest);
    return {state:"complete",historyBaselineVersion:manifest.policyVersion,imported:manifest.imported};
  } finally {lease.close();}
}

/** Explicit offline repair of policy.json from the single committed SQLite pointer. */
export async function recoverPolicyProjection<Rule extends {id:string}>(rawDir:string,source:NmzpPolicySource<Rule>):Promise<{recovered:boolean;backupPath:string;version:number}> {
  const dir=directory(rawDir);
  const lease=new PolicyWriterLease(join(dir,".policy-writer.lock"));
  try {
    if(existsSync(servePointerPath(dir)))throw new Error("migration_live_writer_possible");
    const marker=await readManifest(join(dir,MARKER));
    if(marker && marker.state!=="complete")throw new Error("migration_incomplete");
    const history=PolicyHistory.open<PolicyState>(join(dir,"nmzp.db"),true);
    const current=history.current();
    history.close();
    createNmzpPolicyDomain(source).prepare(current);
    const path=join(dir,"policy.json");
    try {
      const projected=await (await FilePolicyStore.open<PolicyState>({path,durability:"file"})).read();
      if(projected.hash===current.hash)return {recovered:false,backupPath:"",version:current.policy.version};
    } catch { /* preserve unreadable projection before repair */ }
    const backupPath=join(dir,`policy-recovery-backup-${Date.now()}-${randomUUID()}.json`);
    await copyFile(path,backupPath,fsConstants.COPYFILE_EXCL);
    const before=await fileFact(path),backed=await fileFact(backupPath);
    if(!before || before.sha256!==backed?.sha256 || before.bytes!==backed.bytes)throw new Error("recovery_backup_mismatch");
    lease.assertOwned();
    const temporary=`${path}.recover.${randomUUID()}`;
    const file=await open(temporary,"wx",0o600);
    let renamed=false;
    try {
      await file.writeFile(`${JSON.stringify(current.policy)}\n`);
      await file.sync();
      await file.close();
      await rename(temporary,path);
      renamed=true;
    } finally {
      try{await file.close();}catch{/* already closed after rename */}
      if(!renamed)await unlink(temporary).catch(()=>undefined);
    }
    const verified=await (await FilePolicyStore.open<PolicyState>({path,durability:"file"})).read();
    if(verified.hash!==current.hash)throw new Error("policy_recovery_required");
    return {recovered:true,backupPath,version:current.policy.version};
  } finally {lease.close();}
}
