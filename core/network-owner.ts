import {createHash} from "node:crypto";
import {createReadStream} from "node:fs";
import {lstat, realpath, readFile, mkdir, writeFile} from "node:fs/promises";
import {join, win32} from "node:path";
import {loadCreds, type DeviceCreds} from "./hook.ts";
import {pinnedHttps} from "./https-client.ts";
import {activeOwnerGrants, parseOwnerGrant, type NetworkOwnerGrant} from "./network-owner-schema.ts";
import {collectAgentTcp, parseIdentifiedProcs, runPowershell, WINDOWS_NETWORK_IDENTITY_SCRIPT,
  type IdentifiedProc, type NetworkCollectDeps} from "./network-collect.ts";
import type {NetworkSampleReport} from "./schema.ts";

const normalize = (p: string) => win32.normalize(p).toLowerCase();
export const ownerPathHash = (p: string) => createHash("sha256").update(normalize(p)).digest("hex");
const allowedNames = {grok:["grok.exe","grok-cli.exe","grok-build.exe"],claude:["claude.exe","claude-code.exe"],codex:["codex.exe","codex-cli.exe"]};
export function ownerPathAllowed(agent: NetworkOwnerGrant["agent"], exe: string): boolean {
  return /^[a-z]:[\\/]/i.test(exe) && exe.length <= 512 && !/[\x00-\x1f]/.test(exe) &&
    !/(^|[\\/])node_modules([\\/]|$)/i.test(exe) && allowedNames[agent]?.includes(win32.basename(exe).toLowerCase());
}
/** Name is only an exclusion check. Approval + independently supplied hash are mandatory. */
export async function hashOwnerFile(exe: string): Promise<string> {
  const before = await lstat(exe);
  if (!before.isFile() || before.isSymbolicLink() || before.size > 512 * 1024 * 1024 ||
      normalize(await realpath(exe)) !== normalize(exe)) throw Error("owner_file_invalid");
  const input = createReadStream(exe); const hash = createHash("sha256");
  const timer = setTimeout(() => input.destroy(Error("owner_hash_timeout")), 2500);
  try {
    let size=0;
    for await (const chunk of input) {size += chunk.length;if(size > 512*1024*1024)throw Error("owner_file_invalid");hash.update(chunk);}
    const after=await lstat(exe);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino) throw Error("owner_file_changed");
    return hash.digest("hex");
  } finally {clearTimeout(timer);input.destroy();}
}
async function exactProcesses(pids: number[]): Promise<IdentifiedProc[]> {
  const r = await runPowershell(WINDOWS_NETWORK_IDENTITY_SCRIPT(pids), 2500, 32768);
  if(r.error || r.timedOut || r.truncated) throw Error("owner_identity_unavailable");
  return parseIdentifiedProcs(JSON.parse(r.stdout || "[]"));
}
async function ownersRequest(creds: DeviceCreds, method = "GET", body?: unknown, token = creds.token) {
  const r=await pinnedHttps({url:creds.url+"/api/v1/network-owners",method,
    caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256,timeoutMs:2000,maxBodyBytes:16384,
    headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},body:body===undefined?undefined:JSON.stringify(body)});
  if(r.status!==200)throw Error("owner_authority_unavailable");
  return JSON.parse(r.body);
}
const pathFile=(home:string,id:string)=>join(home,".nmzp","network-owners",id+".json");
export interface NetworkOwnerDeps {
  /** OS seams for synthetic fixtures; CT authority and production probe wiring remain real. */
  hash?: typeof hashOwnerFile;
  processes?: typeof exactProcesses;
  network?: NetworkCollectDeps;
  now?: ()=>number;
}
async function resolveOwners(home:string,grants:NetworkOwnerGrant[],deps:NetworkOwnerDeps) {
  const roots:Array<NetworkOwnerGrant & {exe:string}>=[];
  for(const grant of grants){
    const file=pathFile(home,grant.id);if((await lstat(file)).size>4096)throw Error("owner_path_invalid");
    const {exe}=JSON.parse(await readFile(file,"utf8"));
    if(typeof exe!=="string" || !ownerPathAllowed(grant.agent,exe) || ownerPathHash(exe)!==grant.pathHash ||
       await (deps.hash??hashOwnerFile)(exe)!==grant.sha256)throw Error("owner_hash_mismatch");
    roots.push({...grant,exe});
  }
  if(!roots.length)return roots;
  const procs=await (deps.processes??exactProcesses)(roots.map(r=>r.pid));
  if(roots.some(r=>!procs.some(p=>p.pid===r.pid&&p.startedAt===r.startedAt&&normalize(p.exe)===normalize(r.exe))))throw Error("owner_identity_changed");
  return roots;
}
/** Called by the ordinary heartbeat. No grant -> no OS sampling. Revoke/change -> discard sample. */
export async function collectOwnedAgentTcp(opts:{home:string;creds:DeviceCreds;deps?:NetworkOwnerDeps}):Promise<NetworkSampleReport>{
  const deps=opts.deps??{};const now=deps.now??Date.now;
  const fail=(error:string):NetworkSampleReport=>({status:"not_sampled",observedAt:now(),connections:[],error});
  if(process.platform!=="win32"&&!deps.processes)return {status:"unsupported",observedAt:now(),connections:[],error:"unsupported"};
  try{
    const grants=activeOwnerGrants((await ownersRequest(opts.creds)).grants,now());
    if(!grants.length)return fail("no_confirmed_agent");
    const roots=await resolveOwners(opts.home,grants,deps);
    const report=await collectAgentTcp({stopped:false,homeKey:opts.home,verifiedRoots:roots,deps:deps.network});
    await resolveOwners(opts.home,grants,deps);
    const after=activeOwnerGrants((await ownersRequest(opts.creds)).grants,now());
    if(grants.some(g=>!after.some(a=>JSON.stringify(a)===JSON.stringify(g))))return fail("owner_revoked");
    if(grants.some(g=>g.expiresAt<=now()))return fail("owner_expired");
    return report;
  }catch(e){const code=e instanceof Error && /^owner_[a-z_]+$/.test(e.message)?e.message:"owner_identity_unavailable";return fail(code);}
}
/** Local CLI only. Admin credential is used for this request and is never stored on the device. */
export async function approveNetworkOwner(home:string, raw:unknown, adminToken:string, deps:NetworkOwnerDeps={}) {
  const creds=await loadCreds(home);if(!creds)throw Error("not_joined");
  const r=raw as NetworkOwnerGrant & {exe:string;durationMs:number};const now=Date.now();
  const checked=parseOwnerGrant({...r,id:"00000000-0000-0000-0000-000000000000",pathHash:typeof r?.exe==="string"?ownerPathHash(r.exe):"",approvedAt:now,expiresAt:now+r?.durationMs});
  if(!checked||!ownerPathAllowed(checked.agent,r.exe))throw Error("owner_claim_invalid");
  if(await(deps.hash??hashOwnerFile)(r.exe)!==checked.sha256)throw Error("owner_hash_mismatch");
  const procs=await(deps.processes??exactProcesses)([checked.pid]);
  if(!procs.some(p=>p.pid===checked.pid&&p.startedAt===checked.startedAt&&normalize(p.exe)===normalize(r.exe)))throw Error("owner_identity_changed");
  const result=await ownersRequest(creds,"POST",{deviceId:creds.deviceId,action:"approve",claim:checked},adminToken);
  const grant=parseOwnerGrant(result.grant);if(!grant)throw Error("owner_authority_unavailable");
  await mkdir(join(home,".nmzp","network-owners"),{recursive:true});
  await writeFile(pathFile(home,grant.id),JSON.stringify({exe:r.exe}),{mode:0o600,flag:"wx"});
  return grant;
}
export async function networkOwnerCli(argv:string[],home:string):Promise<void>{
  const creds=await loadCreds(home);if(!creds)throw Error("not_joined");
  if(argv[0]==="status"){process.stdout.write(JSON.stringify(await ownersRequest(creds))+"\n");return;}
  const pos=argv.indexOf("--token-file");if(pos<0||!argv[pos+1])throw Error("admin_token_file_required");
  const token=(await readFile(argv[pos+1],"utf8")).trim();
  if(argv[0]==="approve"&&argv[1]){
    if((await lstat(argv[1])).size>8192)throw Error("owner_claim_invalid");
    const grant=await approveNetworkOwner(home,JSON.parse(await readFile(argv[1],"utf8")),token);
    process.stdout.write(JSON.stringify(grant)+"\n");
  }else if(argv[0]==="revoke"&&argv[1]){
    await ownersRequest(creds,"POST",{deviceId:creds.deviceId,action:"revoke",id:argv[1]},token);
    process.stdout.write("revoked\n");
  }else throw Error("usage: network-owner status|approve <local-claim.json>|revoke <id> --token-file <admin.token>");
}
