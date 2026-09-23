// Loopback-only synthetic Hook latency, including receipt settlement.
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { startServer } from "../core/serve.ts";
import { pinnedHttps } from "../core/https-client.ts";
import { runHook, settleHookAfterStdout } from "../core/hook.ts";

const coreDir=fileURLToPath(new URL("../core/",import.meta.url));
const samples=Number(process.argv[2]??30);
if(!Number.isSafeInteger(samples)||samples<1||samples>100)throw new Error("samples must be 1..100");
function percentile(sorted,q){return sorted[Math.ceil(sorted.length*q)-1];}
async function run(mode){
  const root=await mkdtemp(join(tmpdir(),`nmzp-hook-bench-${mode}-`));
  let server;
  try {
    server=await startServer({dataDir:join(root,"ct"),host:"127.0.0.1",port:0,coreDir,uiDir:null,storageMode:mode});
    const request=async(path,body,token=server.adminToken)=>{
      const r=await pinnedHttps({url:server.url+path,method:"POST",body:JSON.stringify(body),
        headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},
        caPem:server.tls.certPem,fingerprintSha256:server.tls.fingerprintSha256,timeoutMs:5000});
      if(r.status!==200)throw new Error(`${path}:${r.status}`);
      return JSON.parse(r.body);
    };
    const ticket=await request("/api/v1/ticket",{});
    const joined=await request("/api/v1/join",{ticket:ticket.ticket,hostname:"synthetic",os:"win32",user:"fixture"});
    const home=join(root,"device");await mkdir(join(home,".nmzp"),{recursive:true});
    await writeFile(join(home,".nmzp","credentials.json"),JSON.stringify({deviceId:joined.deviceId,
      token:joined.deviceToken,url:server.url,caPem:server.tls.certPem,fingerprintSha256:server.tls.fingerprintSha256}));
    const times=[];
    for(let i=0;i<samples;i++){
      const start=performance.now();
      const result=await runHook({home,coreDir,argv:["--agent","grok"],
        stdin:JSON.stringify({eventId:`latency-${i}`,tool_name:"Read",tool_input:{file_path:`synthetic-${i}.txt`}})});
      await settleHookAfterStdout({home,result});
      times.push(performance.now()-start);
    }
    times.sort((a,b)=>a-b);
    return {mode,samples,p50Ms:percentile(times,.5),p95Ms:percentile(times,.95),maxMs:times.at(-1)};
  }finally{await server?.close();await rm(root,{recursive:true,force:true});}
}
process.stdout.write(JSON.stringify({window:await run("window"),sqlite:await run("sqlite")})+"\n");
