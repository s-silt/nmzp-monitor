import {execFile} from 'node:child_process';import {readFile,writeFile} from 'node:fs/promises';import {join} from 'node:path';import {createPrivateKey,createPublicKey} from 'node:crypto';
import {loadCreds} from './hook.ts';import {probeTick} from './probe.ts';import {newProbeBinding,protectedHeartbeat} from './probe-auth.ts';import {parseDiscovery} from './agent-discovery-schema.ts';import {mailboxFailure,MAILBOX_LIMIT} from './probe-mailbox.ts';
const [home,mailbox]=process.argv.slice(2);
if(process.platform!=='win32'||!home||!mailbox)throw Error('service_arguments');
const creds=await loadCreds(home);if(!creds)throw Error('service_not_joined');
const privateKey=await readFile(join(home,'probe-private.pem'),'utf8');
const binding=newProbeBinding(createPublicKey(createPrivateKey(privateKey)).export({format:'der',type:'spki'}).toString('base64'));
async function tick(){
 const result=await probeTick({home,coreDir:import.meta.dirname,heartbeat:body=>protectedHeartbeat(creds!,privateKey,binding.keyId,body),collectDiscovery:()=>new Promise(resolve=>{
  execFile(process.execPath,['--experimental-strip-types',join(import.meta.dirname,'probe-mailbox-worker.ts'),mailbox],{windowsHide:true,timeout:2500,maxBuffer:MAILBOX_LIMIT+1,cwd:import.meta.dirname},(err,stdout)=>{
   if(err){resolve(mailboxFailure(err.killed?'timeout':'error'));return;}try{resolve(parseDiscovery(JSON.parse(stdout))??mailboxFailure());}catch{resolve(mailboxFailure());}
  });
 })});
 // Private local readiness only; not an assertion of ACL acceptance.
 await writeFile(join(home,'health.json'),JSON.stringify({checkedAt:Date.now(),ok:result.ok,keyId:binding.keyId,error:result.ok?undefined:'heartbeat_rejected_or_unavailable'}));
}
for(;;){await tick();await new Promise(r=>setTimeout(r,30000));}
