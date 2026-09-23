// Real loopback HTTPS export of synthetic rows; reads response as a stream.
import { mkdtemp, rm } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { startServer } from "../core/serve.ts";

const count=Number(process.argv[2]??1000);
if(!Number.isSafeInteger(count)||count<1||count>10_000)throw new Error("count must be 1..10000");
const root=await mkdtemp(join(tmpdir(),"nmzp-export-bench-"));let server;
let seed=42;function rand(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
function body(i){let s="";const n=i%20<7?80:i%20<15?700:3500;
  while(s.length<n)s+=`${rand().toString(36)}:${rand().toString(36)} `;return s.slice(0,n);}
async function download(path){
  const start=performance.now();
  return new Promise((resolve,reject)=>{
    const req=httpsRequest(server.url+path,{ca:server.tls.certPem,
      headers:{authorization:`Bearer ${server.adminToken}`}},(res)=>{
      let bytes=0;
      res.on("data",(chunk)=>{bytes+=chunk.length;});
      res.on("end",()=>resolve({status:res.statusCode,bytes,elapsedMs:performance.now()-start}));
      res.on("error",reject);
    });req.on("error",reject);req.end();
  });
}
try{
  server=await startServer({dataDir:join(root,"ct"),host:"127.0.0.1",port:0,
    coreDir:fileURLToPath(new URL("../core/",import.meta.url)),uiDir:null,storageMode:"sqlite"});
  for(let i=0;i<count;i++){
    const value=body(i);
    await server.store.appendEvent({id:`e${i}`,ts:1_790_000_000_000+i,machineId:"synthetic",agent:"grok",
      sessionId:"s",layer:"app_pre",tool:"Read",nativeTool:"Read",input:value,risk:"info",decision:"allow",
      category:"other",workdirScope:"project",redacted:value,policyVersion:1,evaluation:"allow",enforcement:"delivered"});
  }
  const plain=await download("/api/v1/audit/export?format=jsonl&gzip=0");
  const gzip=await download("/api/v1/audit/export?format=jsonl&gzip=1");
  process.stdout.write(JSON.stringify({count,distribution:"35% 80 chars; 40% 700; 25% 3500; seeded varied alphanumeric",
    plain,gzip})+"\n");
}finally{await server?.close();await rm(root,{recursive:true,force:true});}
