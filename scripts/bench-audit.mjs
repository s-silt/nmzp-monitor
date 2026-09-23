// Synthetic, isolated storage benchmark. No host data or network access.
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";
import { AuditStore } from "../core/audit/store.ts";

const count=Number(process.argv[2]??1000);
if(!Number.isSafeInteger(count)||count<1||count>200_000)throw new Error("count must be 1..200000");
const dir=await mkdtemp(join(tmpdir(),"nmzp-audit-bench-"));
let peakRss=process.memoryUsage().rss;
const sample=setInterval(()=>{peakRss=Math.max(peakRss,process.memoryUsage().rss);},100);
let seed=123456789;
function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
function body(i){const n=i%20<7?80:i%20<15?700:3500;let s="";
  while(s.length<n)s+=`${rand().toString(36)}:${rand().toString(36)} `;
  return s.slice(0,n);
}
try{
  const path=join(dir,"bench.db"),store=AuditStore.create(path,{maxRecords:Math.max(100_000,count+1),maxAgeMs:0,
    maxDbBytes:4*1024**3,minFreeBytes:0});
  const start=performance.now();
  for(let i=0;i<count;i++){
    const payload=body(i);
    await store.append({id:`e${i}`,ts:1_790_000_000_000+i,machineId:`device-${i%10}`,
      agent:i%5===0?"codex":"grok",sessionId:`s${i%100}`,layer:"app_pre",tool:i%3===0?"Bash":"Read",
      nativeTool:i%3===0?"Bash":"Read",input:payload,risk:i%10===0?"high":"info",
      decision:i%10===0?"block":"allow",category:"other",workdirScope:"project",redacted:payload,
      policyVersion:1,evaluation:i%10===0?"block":"allow",enforcement:"pending_verify"});
    if((i+1)%10_000===0)process.stderr.write(`inserted ${i+1}\n`);
  }
  const writeMs=performance.now()-start;
  const receiptStart=performance.now();
  for(let i=0;i<Math.min(100,count);i++)await store.updateReceipt(`device-${i%10}`,`e${i}`,"delivered");
  const receiptMs=performance.now()-receiptStart;
  const queryStart=performance.now();
  for(let i=0;i<100;i++)await store.query({limit:25,agent:"grok",decision:"allow",risk:"info"});
  const queryMs=performance.now()-queryStart;
  const exportStart=performance.now();let exported=0,beforeSeq,hasMore=true;
  while(hasMore){const page=await store.query({limit:25,highWatermark:count,beforeSeq});
    for(const event of page.events){JSON.stringify(event);exported++;}
    beforeSeq=page.nextBeforeSeq??undefined;
    hasMore=beforeSeq!==undefined;
  }
  const exportMs=performance.now()-exportStart;
  const size=(await stat(path)).size;
  const db=new DatabaseSync(path,{readOnly:true});
  let compression;
  try {compression=db.prepare("SELECT sum(raw_bytes) AS rawBytes,sum(length(body)) AS storedBodyBytes,sum(CASE WHEN codec='gzip' THEN 1 ELSE 0 END) AS gzipRows FROM audit_events").get();}
  finally {db.close();}
  clearInterval(sample);
  process.stdout.write(JSON.stringify({count,distribution:"35% 80 chars; 40% 700; 25% 3500; seeded varied alphanumeric",
    writeMs,receipt100Ms:receiptMs,query100Ms:queryMs,serializeAllMs:exportMs,exported,
    dbBytes:size,peakRssBytes:peakRss,compression,storage:store.status()})+"\n");
}finally{clearInterval(sample);await rm(dir,{recursive:true,force:true});}
