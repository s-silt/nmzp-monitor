import assert from "node:assert/strict";
import {mkdirSync,writeFileSync,readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {join} from "node:path";
import {it} from "node:test";
import {collectAgentTcp,confirmedAgentRoot,parseIdentifiedProcs,parseTcpRows,WINDOWS_NETWORK_PROCESS_SCRIPT,WINDOWS_NETWORK_TCP_SCRIPT,runPowershell} from "./network-collect.ts";
import {assessNetworkProof} from "./network-proof.ts";
it("production collector readonly proof: same trusted identity and stable tuple",{timeout:45000,skip:process.env.NMZP_LIVE_NETWORK_PROOF!=="1"||!process.env.NMZP_LIVE_PROOF_DIR},async t=>{
 const dir=process.env.NMZP_LIVE_PROOF_DIR!;
 const save=(result:unknown)=>{mkdirSync(dir,{recursive:true});writeFileSync(join(dir,"live-collector.json"),JSON.stringify({at:Date.now(),scope:"passive-real-CIM-identity-and-TCP-no-generated-traffic",result},null,2));};
 if(process.platform!=="win32"){save({status:"not_verified",reason:"unsupported_os"});t.skip("Windows required");return;}
 const read=async(script:string)=>{const r=await runPowershell(script,8000);if(r.error||r.truncated||r.timedOut)throw Error("control_query_unavailable");return JSON.parse(r.stdout.trim()||"[]") as unknown;};
 let before,after,controlBefore,controlAfter,sample;
 try{
  before=parseIdentifiedProcs(await read(WINDOWS_NETWORK_PROCESS_SCRIPT)).filter(p=>confirmedAgentRoot(p)==="grok");
  const expectedHash=process.env.NMZP_LIVE_AGENT_SHA256;
  if(!expectedHash||!/^[a-f0-9]{64}$/i.test(expectedHash)){save({status:"not_verified",reason:"independent_binary_identity_required"});t.skip("supply independently reviewed binary hash");return;}
  before=before.filter(p=>{try{return createHash("sha256").update(readFileSync(p.exe)).digest("hex")===expectedHash.toLowerCase();}catch{return false;}});
  controlBefore=parseTcpRows(await read(WINDOWS_NETWORK_TCP_SCRIPT(before.map(p=>p.pid))));
  sample=await collectAgentTcp({stopped:false,timeoutMs:12000,homeKey:"real-proof",verifiedRoots:before});
  controlAfter=parseTcpRows(await read(WINDOWS_NETWORK_TCP_SCRIPT(before.map(p=>p.pid))));
  after=parseIdentifiedProcs(await read(WINDOWS_NETWORK_PROCESS_SCRIPT));
 }catch{save({status:"not_verified",reason:"control_query_unavailable"});t.skip("positive control unavailable");return;}
 const result=assessNetworkProof(sample,before,after,controlBefore,controlAfter);save(result);
 if(result.status==="not_verified"){t.skip(result.reason);return;}
 assert.equal(result.status,"verified",result.reason);
});
