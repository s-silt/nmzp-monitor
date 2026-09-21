/** Experimental owned-session controller. Never elevates itself or starts UAC.
 * A reviewed native helper is started manually in a separate elevated console.
 * Runtime material stays under a new local temporary HOME, never beside source.
 */
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {createServer,createConnection,type Socket} from 'node:net';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {lstat,readFile,writeFile,mkdir,mkdtemp,realpath} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {startModelGateway,type ModelGatewayEvent,type CreateUpstreamRequest} from './model-gateway.ts';
import {NmzpStore} from './persist.ts';
import {storeResponseObservation} from './model-response-audit.ts';
import {OwnedAcpClient,terminalText,type PermissionPrompt} from './protected-session-acp.ts';
import {createInterface} from 'node:readline/promises';
const execFileAsync=promisify(execFile);
const hex=()=>randomBytes(32).toString('hex');
const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
export interface WorkspaceFile {path:string;base64:string}
export interface SessionSettings {
 nativeHelper:string;grokExecutable:string;grokSha256:string;upstreamOrigin:string;model:string;
 workspace:string;files:string[];tools?:{name:string;path:string;sha256:string}[];prompt?:string;deadlineMs?:number;interactionMode?:'acp'|'headless';
}
export function safeWorkspacePath(p:string):boolean {
 return p.length>0&&p.length<=180&&p.split('/').every(s=>/^[a-zA-Z0-9_.-]+$/.test(s)&&s!=='.'&&s!=='..'&&!s.endsWith('.')&&!/^(con|prn|aux|nul|com[0-9]|lpt[0-9])([.]|$)/i.test(s)&&!/^([.]env([.]|$)|[.]git$|[.]grok$|[.]ssh$|[.]codex$)/i.test(s));
}
export function validateWorkspaceFiles(raw:unknown):WorkspaceFile[] {
 if(!Array.isArray(raw)||raw.length>128)throw Error('workspace_file_limit');
 const seen=new Set<string>();let bytes=0;
 return raw.map(v=>{
  if(!v||typeof v!=='object'||Object.keys(v).sort().join(',')!=='base64,path'||typeof v.path!=='string'||!safeWorkspacePath(v.path)||seen.has(v.path.toLowerCase())||typeof v.base64!=='string'||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v.base64))throw Error('workspace_schema');
  seen.add(v.path.toLowerCase());bytes+=Buffer.from(v.base64,'base64').length;if(bytes>131072)throw Error('workspace_byte_limit');
  return {path:v.path,base64:v.base64};
 });
}
async function noLinks(path:string):Promise<void> {
 let p=resolve(path);for(;;){const st=await lstat(p);if(st.isSymbolicLink()||st.isFile()&&st.nlink!==1)throw Error('file_link_refused');const parent=dirname(p);if(parent===p)break;p=parent;}
}
export async function collectWorkspace(root:string,paths:string[]):Promise<WorkspaceFile[]> {
 if(!Array.isArray(paths)||paths.length>128)throw Error('workspace_file_limit');
 await noLinks(root);const base=await realpath(root), rows:WorkspaceFile[]=[];let total=0;
 for(const path of paths){if(!safeWorkspacePath(path))throw Error('workspace_path');const f=join(base,...path.split('/'));await noLinks(f);const st=await lstat(f);if(!st.isFile()||st.size>131072||(total+=st.size)>131072)throw Error('workspace_byte_limit');rows.push({path,base64:(await readFile(f)).toString('base64')});}
 return validateWorkspaceFiles(rows);
}
export function makeNativeRequest(settings:SessionSettings,identity:{pid:number;creationTime:string},gateway:{port:number;sessionToken:string},files:WorkspaceFile[],pipe:string,controlToken:string) {
 if(!/^[a-f0-9]{64}$/i.test(settings.grokSha256)||!/^[a-zA-Z0-9_.:/-]{1,128}$/.test(settings.model)||!/^\d{1,19}$/.test(identity.creationTime)||BigInt(identity.creationTime)<=0n||!Number.isInteger(identity.pid)||identity.pid<=0||!Number.isInteger(gateway.port)||gateway.port<1||gateway.port>65535||!/^[a-f0-9]{64}$/.test(gateway.sessionToken)||!/^nmzp-owned-[a-f0-9]{64}$/.test(pipe)||!/^[a-f0-9]{64}$/.test(controlToken))throw Error('session_contract');
 const prompt=settings.prompt??'';if(typeof prompt!=='string'||prompt.length>16384||prompt.includes('\0'))throw Error('prompt_limit');
 const tools=settings.tools??[];const names=new Set(['grok.exe']);if(tools.length>8)throw Error('tool_limit');
 for(const t of tools){if(!/^[a-zA-Z0-9_-]+[.]exe$/.test(t.name)||!safeWorkspacePath(t.name)||names.has(t.name.toLowerCase())||!/^[a-f0-9]{64}$/i.test(t.sha256))throw Error('tool_contract');names.add(t.name.toLowerCase());}
 const mode=settings.interactionMode??'acp';if(!['acp','headless'].includes(mode)||!prompt.trim())throw Error('interaction_mode_and_prompt_required');
 return {appcontainer_kind:'lpac',network_mode:'brokered',executable:resolve(settings.grokExecutable),gateway_port:gateway.port,controller_pid:identity.pid,controller_creation_time:identity.creationTime,deadline_ms:Math.min(600000,Math.max(1000,settings.deadlineMs??300000)),grok_session:{mode,model:settings.model,session_token:gateway.sessionToken,executable_sha256:settings.grokSha256,prompt,pipe,control_token:controlToken,files:validateWorkspaceFiles(files),tools}};
}
function isObject(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==='object'&&!Array.isArray(v);}
export function validateNativeResult(v:unknown):Record<string,unknown>{
 if(!isObject(v)||typeof v.ok!=='boolean'||typeof v.exit_code!=='number'||typeof v.error_code!=='string'||v.error_code.length>100||!isObject(v.extra))throw Error('native_result_schema');
 if(v.ok&&(v.in_job!==true||v.appcontainer_kind!=='lpac'||v.lpac_all_application_packages_opt_out!==true||v.kill_on_close_set!==true||v.ui_limits_set!==true||v.handle_whitelist_explicit!==true||v.payload_token_is_elevated!==false||v.payload_admin_sid_enabled!==false||v.extra.lease_bound!==true||v.extra.lease_network_ready!==true||v.extra.lease_close!==true||v.extra.cleanup_required===true||v.degraded_to_normal_process!==false))throw Error('native_result_proofs');
 // No stdout, stderr, error text, SIDs, arbitrary extra objects or model content persisted here.
 return {ok:v.ok,exitCode:v.exit_code,errorCode:v.error_code,cleanupRequired:v.extra.cleanup_required===true,leaseClosed:v.extra.lease_close===true,productionReady:false};
}
export async function runProtectedSession(settings:SessionSettings,opts:{upstreamToken?:string;createUpstreamRequest?:CreateUpstreamRequest;onEvent?:(e:ModelGatewayEvent)=>unknown;onOutput?:(stream:'stdout'|'stderr',text:string)=>void;onWaiting?:(requestPath:string)=>void;onPermission?:(p:PermissionPrompt,signal:AbortSignal)=>Promise<string|null>}={}) {
 if(process.platform!=='win32')throw Error('windows_required');
 await noLinks(settings.nativeHelper);await noLinks(settings.grokExecutable);
 if(sha(await readFile(settings.grokExecutable)).toLowerCase()!==settings.grokSha256.toLowerCase())throw Error('grok_hash_mismatch');
 const {stdout}=await execFileAsync(settings.nativeHelper,['--controller-identity',String(process.pid)],{windowsHide:true,timeout:5000,maxBuffer:8192,env:{SystemRoot:process.env.SystemRoot,PATH:join(process.env.SystemRoot??'C:\\Windows','System32')}});
 const identity=JSON.parse(stdout);if(identity.ordinary!==true||identity.pid!==process.pid||identity.ownedWfpBuildEnabled!==true)throw Error('ordinary_controller_and_reviewed_native_build_required');
 const files=await collectWorkspace(settings.workspace,settings.files);
 const root=await mkdtemp(join(tmpdir(),'nmzp-owned-controller-'));await noLinks(root);
 const pipeName='nmzp-owned-'+hex(), controlToken=hex();
 const requestPath=join(root,'request.json'),resultDir=join(root,'workspace-result');
 // The fixture factory is a callable trusted in-process dependency, never a JSON/config field.
 const gateway=await startModelGateway({sessionToken:hex(),upstreamOrigin:settings.upstreamOrigin,upstreamToken:opts.upstreamToken,createUpstreamRequest:opts.createUpstreamRequest,allowedRoutes:['/v1/chat/completions'],maxInflight:2,maxConnections:4,onEvent:opts.onEvent});
 let socket:Socket|undefined,hello=false,running=false,workspace:WorkspaceFile[]|undefined,settled=false;
 let resolveResult!:(r:Record<string,unknown>)=>void,rejectResult!:(e:Error)=>void;
 const completed=new Promise<Record<string,unknown>>((res,rej)=>{resolveResult=res;rejectResult=rej;});
 // Attach immediately; a startup failure must not create an unhandled rejected promise.
 void completed.catch(()=>{});
 const fail=(code:string)=>{if(!settled){settled=true;rejectResult(Error(code));}socket?.destroy();};
 const sendInput=(data:Buffer)=>{if(hello&&running&&socket&&!settled){for(let i=0;i<data.length;i+=4096){if(!socket.write(JSON.stringify({type:'stdin',base64:data.subarray(i,i+4096).toString('base64')})+'\n')){fail('approval_input_backpressure');break;}}}};
 const acp=(settings.interactionMode??'acp')==='acp'?new OwnedAcpClient({write:sendInput,eof:()=>socket?.write(JSON.stringify({type:'stdin_eof'})+'\n'),fail,text:t=>opts.onOutput?.('stdout',t),permission:opts.onPermission},settings.deadlineMs):undefined;
 const server=createServer(peer=>{
  if(socket){peer.destroy();return;}socket=peer;let pending='';peer.setEncoding('utf8');peer.setTimeout(15000,()=>{if(!hello)fail('native_handshake_timeout');});
  peer.on('error',()=>fail('native_channel_error'));peer.on('close',()=>{if(!settled)fail('native_channel_lost');});
  peer.on('data',data=>{
   try{
    pending+=data;if(pending.length>262144)throw Error();let end;
    while((end=pending.indexOf('\n'))>=0){const raw=pending.slice(0,end);pending=pending.slice(end+1);const m:unknown=JSON.parse(raw);if(!isObject(m))throw Error();
     if(!hello){if(m.type!=='hello'||m.version!==1||typeof m.token!=='string'||m.token.length!==64||!timingSafeEqual(Buffer.from(m.token),Buffer.from(controlToken)))throw Error();hello=true;peer.write(JSON.stringify({type:'start'})+'\n');continue;}
     if(m.type==='running'){if(running||!Number.isInteger(m.pid)||Number(m.pid)<=0||typeof m.workspace!=='string'||!m.workspace||m.workspace.length>500)throw Error();running=true;if(acp)void acp.start(m.workspace,settings.prompt??'');}
     else if(m.type==='stdout'||m.type==='stderr'){if(!running||typeof m.text!=='string'||m.text.length>2048)throw Error();if(acp&&m.type==='stdout')acp.feed(m.text);else opts.onOutput?.(m.type,terminalText(m.text));}
     else if(m.type==='workspace'){if(!running||workspace)throw Error();workspace=validateWorkspaceFiles(m.files);}
     else if(m.type==='result'){const result=validateNativeResult(m.result);if(result.ok===true&&(!running||!workspace))throw Error();settled=true;resolveResult(result);}
     else throw Error();
    }
   }catch{fail('native_protocol_refused');}
  });
 });
 const input=(data:Buffer)=>{if(!acp)sendInput(data);};
 const stop=()=>fail('operator_cancelled');
 const budget=setTimeout(()=>fail('session_deadline'),Math.min(600000,Math.max(1000,settings.deadlineMs??300000))+30000);
 // Verify the actual listener continues to accept connections; if it dies, disconnect the native control channel.
 let probe:Socket|undefined;
 const health=setInterval(()=>{const a=gateway.status().audit;if(a.failed||a.timedOut||a.dropped)fail('audit_sink_gap');if(!probe&&!settled){probe=createConnection({host:'127.0.0.1',port:gateway.port});probe.setTimeout(1000,()=>{fail('gateway_unavailable');probe?.destroy();});probe.once('connect',()=>probe?.destroy());probe.once('error',()=>fail('gateway_unavailable'));probe.once('close',()=>{probe=undefined;});}},1000);
 try{
  await new Promise<void>((res,rej)=>{server.once('error',rej);server.listen('\\\\.\\pipe\\'+pipeName,res);});
  const req=makeNativeRequest(settings,identity,gateway,files,pipeName,controlToken);
  const bytes=JSON.stringify(req);if(Buffer.byteLength(bytes)>262144)throw Error('native_request_limit');
  await writeFile(requestPath,bytes,{flag:'wx',mode:0o600});
  opts.onWaiting?.(requestPath);process.stdin.on('data',input);process.once('SIGINT',stop);process.once('SIGTERM',stop);
  const result=await completed;
  const auditDeadline=Date.now()+1500;
  while(gateway.status().audit.pending&&Date.now()<auditDeadline)await new Promise(r=>setTimeout(r,20));
  const audit=gateway.status().audit;if(audit.pending||audit.failed||audit.timedOut||audit.dropped)throw Error('audit_sink_gap');
  if(workspace){await mkdir(resultDir);for(const row of workspace){const p=join(resultDir,...row.path.split('/'));await mkdir(dirname(p),{recursive:true});await writeFile(p,Buffer.from(row.base64,'base64'),{flag:'wx'});}}
  const deleted=files.filter(f=>!workspace?.some(w=>w.path.toLowerCase()===f.path.toLowerCase())).map(f=>f.path);
  await writeFile(join(root,'result.json'),JSON.stringify({...result,workspaceExported:!!workspace,deleted:workspace?deleted:[],gatewayAudit:gateway.status().audit},null,2),{flag:'wx'});
  return {directory:root,result};
 }catch(e){
  const code=e instanceof Error&&/^[a-z_]{1,80}$/.test(e.message)?e.message:'controller_failure';
  await writeFile(join(root,'failure.json'),JSON.stringify({ok:false,code,productionReady:false,nativeCleanup:'verify-native-receipt'}),{flag:'wx'}).catch(()=>{});
  throw Error(code);
 }finally{
  clearTimeout(budget);clearInterval(health);probe?.destroy();acp?.close();process.stdin.off('data',input);process.off('SIGINT',stop);process.off('SIGTERM',stop);process.stdin.pause();
  socket?.destroy();await new Promise<void>(res=>server.close(()=>res()));await gateway.close();
  // Invalidate disposable launch credentials, preserving a reviewable receipt and workspace result.
  await writeFile(requestPath,JSON.stringify({expired:true,productionReady:false}),{mode:0o600}).catch(()=>{});
 }
}
async function main(){
 if(process.argv[2]!=='--config'||!process.argv[3])throw Error('usage: node core/protected-session-controller.ts --config trusted-settings.json');
 const upstreamToken=process.env.NMZP_UPSTREAM_TOKEN;delete process.env.NMZP_UPSTREAM_TOKEN;
 const settings=JSON.parse(await readFile(resolve(process.argv[3]),'utf8')) as SessionSettings;
 const auditRoot=await mkdtemp(join(tmpdir(),'nmzp-owned-audit-'));const store=new NmzpStore(auditRoot);await store.load();
 const sessionId='owned_'+hex();
 const result=await runProtectedSession(settings,{upstreamToken,onPermission:consolePermission,onEvent:e=>storeResponseObservation(store,{machineId:'owned-controller',sessionId,agent:'grok',proc:'grok.exe'},e),onOutput:(stream,text)=>process[stream].write(text),onWaiting:p=>{
  // No elevation launch and no secret in the command. Human reviews the existing native build first.
  process.stderr.write(`Awaiting reviewed native helper in a separate elevated console:\n& '${settings.nativeHelper.replaceAll("'","''")}' --privileged-init --execute-payload --config '${p.replaceAll("'","''")}'\n`);
 }});
 process.stdout.write(JSON.stringify({...result,auditDirectory:auditRoot})+'\n');
 if(result.result.ok!==true||result.result.exitCode!==0)process.exitCode=1;
}
export async function consolePermission(p:PermissionPrompt,signal?:AbortSignal):Promise<string|null>{
 if(!process.stdin.isTTY)return null;
 const rl=createInterface({input:process.stdin,output:process.stderr});const abort=new AbortController();const timer=setTimeout(()=>abort.abort(),55000);
 const cancel=()=>abort.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)abort.abort();
 try{process.stderr.write(`\nGrok requests permission (untrusted tool text):\n${p.title}\n${p.input}\n`);p.options.forEach((o,i)=>process.stderr.write(`${i+1}. ${o.kind}: ${o.name}\n`));const value=await rl.question('Choose one action; Enter cancels: ',{signal:abort.signal});return p.options[Number(value)-1]?.optionId??null;}catch{return null;}finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);rl.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)void main().catch(()=>{process.stderr.write('Protected session failed; no fallback launch. Inspect local result/OS evidence.\n');process.exitCode=1;});
