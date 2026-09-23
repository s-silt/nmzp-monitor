import assert from 'node:assert/strict';import {it} from 'node:test';
import {generateKeyPairSync,sign} from 'node:crypto';import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {newProbeBinding,parseProbeBinding,ProbeChallenges,proofMessage,protectedHeartbeat,publicProbeProtection} from './probe-auth.ts';
import {startServer} from './serve.ts';import {startLanViewer} from './lan-viewer.ts';import {sha256Hex} from './auth.ts';import {pinnedHttps} from './https-client.ts';import {NmzpStore} from './persist.ts';import {probeTick} from './probe.ts';import {probeProtectionText} from './probe-protection.ts';
function keys(){const k=generateKeyPairSync('ed25519');return {publicKey:k.publicKey.export({format:'der',type:'spki'}).toString('base64'),privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}).toString()};}
it('challenge binds device/key/body; single use, expiry, capacity, restart and revoked keys fail closed',()=>{
 const k=keys(),b=newProbeBinding(k.publicKey),c=new ProbeChallenges(),now=Date.now();
 const proof=(nonce:string,body='{}')=>({'x-nmzp-challenge':nonce,'x-nmzp-signature':sign(null,proofMessage('device',b.keyId,nonce,body),k.privateKey).toString('base64')});
 let n=c.issue('device',b,now)!;assert.equal(c.consume('other',b,'{}',proof(n.nonce),now),false);assert.equal(c.consume('device',b,'{}',proof(n.nonce),now),true);assert.equal(c.consume('device',b,'{}',proof(n.nonce),now),false);
 n=c.issue('device',b,now)!;assert.equal(c.consume('device',b,'{"forged":true}',proof(n.nonce),now),false);
 n=c.issue('device',b,now)!;assert.equal(c.consume('device',b,'{}',proof(n.nonce),now+60000),false);
 n=c.issue('device',b,now)!;assert.equal(new ProbeChallenges().consume('device',b,'{}',proof(n.nonce),now),false);assert.equal(c.consume('device',{...b,revoked:true},'{}',proof(n.nonce),now),false);
 n=c.issue('device',b,now)!;assert.equal(c.consume('device',newProbeBinding(keys().publicKey),'{}',proof(n.nonce),now),false);
 n=c.issue('device',b,now)!;assert.equal(c.consume('device',{...b,registeredAt:b.registeredAt+1},'{}',proof(n.nonce),now),false);
 for(let i=0;i<4;i++)assert.ok(c.issue('device',b,now));assert.equal(c.issue('device',b,now),null);assert.ok(c.issue('device',b,now+60000));
 const full=new ProbeChallenges();for(let i=0;i<1024;i++)assert.ok(full.issue(String(i),b,now));assert.equal(full.issue('next',b,now),null);assert.ok(full.issue('next',b,now+60000));
 assert.throws(()=>parseProbeBinding({}),/invalid_probe_binding/);assert.throws(()=>newProbeBinding('junk'),/invalid_probe_binding/);
 assert.equal(publicProbeProtection({...b,lastAuthenticatedAt:now},now+90001).identity,'stale');assert.match(probeProtectionText(publicProbeProtection(b),'zh'),/等待/);
});
it('isolated TLS: admin enroll -> actual probeTick signs -> store/API/LAN; stolen token, rotation, revocation, restart',async()=>{
 const home=await mkdtemp(join(tmpdir(),'nmzp-service-auth-')),data=join(home,'ct'),srv=await startServer({dataDir:data,host:'127.0.0.1',port:0,coreDir:import.meta.dirname,uiDir:null});
 const k=keys(),binding=newProbeBinding(k.publicKey),creds={deviceId:'device',token:'fixture-token',url:srv.url,caPem:srv.tls.certPem,fingerprintSha256:srv.tls.fingerprintSha256};
 const pin={caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256};
 const api=(path:string,method='GET',body?:unknown,token=creds.token)=>pinnedHttps({url:srv.url+path,method,body:body===undefined?undefined:JSON.stringify(body),headers:{authorization:`Bearer ${token}`},...pin});
 const viewer=await startLanViewer({host:'127.0.0.1',port:0,allowedCidrs:['127.0.0.0/8'],uiDir:home,ctUrl:srv.url,...pin,adminToken:srv.adminToken});
 await mkdir(join(home,'.nmzp'));await writeFile(join(home,'.nmzp','credentials.json'),JSON.stringify(creds));
 await srv.store.putDevice({id:'device',tokenHash:sha256Hex(creds.token),hostname:'fixture',user:'fixture',ip:'127.0.0.1',os:'win32',attachedAt:Date.now(),lastSeen:1,lastPolicyVersion:1,agents:[],capabilities:[]});
 try {
  const enroll={deviceId:'device',action:'enroll',publicKey:k.publicKey};
  assert.equal((await api('/api/v1/probe/binding','POST',enroll)).status,401);
  assert.equal((await api('/api/v1/probe/binding','POST',enroll,srv.adminToken)).status,200);
  assert.equal((await api('/api/v1/heartbeat','POST',{probeBinding:undefined,capabilities:[{id:'fake',active:true}]})).status,401);assert.equal(srv.store.getDevice('device')!.lastSeen,1);
  const tick=()=>probeTick({home,heartbeat:body=>protectedHeartbeat(creds,k.privateKey,binding.keyId,body),collectDiscovery:async()=>({schemaVersion:1,platform:'win32',checkedAt:Date.now(),completedAt:Date.now(),status:'error',items:[],sources:[]}),collectSnapshotGuard:async()=>({error:'unsupported'}),collectNetwork:async()=>({status:'unsupported',startedAt:Date.now(),finishedAt:Date.now(),connections:[],attribution:'none'} as never)});
  assert.equal((await tick()).ok,true);
  assert.ok(srv.store.getDevice('device')!.probeBinding!.lastAuthenticatedAt);
  await srv.store.stop();assert.deepEqual(await tick(),{ok:true,pollOnly:true});await srv.store.resume();
  for(const path of ['/api/v1/state','/api/v1/export']){
   const ct=(await api(path,'GET',undefined,srv.adminToken)).body;assert.match(ct,/signature_required/);assert.doesNotMatch(ct,/publicKey|probeBinding|BEGIN PRIVATE/);
   const lan=await(await fetch(viewer.url+path)).text();assert.match(lan,/signature_required/);assert.doesNotMatch(lan,/publicKey|probeBinding|BEGIN PRIVATE/);
  }
  assert.equal((await fetch(viewer.url+'/api/v1/probe/binding',{method:'POST',body:'{}'})).status,405);
  const restored=new NmzpStore(data);await restored.load({readOnly:true});assert.equal(restored.getDevice('device')!.probeBinding!.keyId,binding.keyId);
  const c=JSON.parse((await api('/api/v1/probe/challenge')).body),body='{}',signature=sign(null,proofMessage('device',binding.keyId,c.nonce,body),k.privateKey).toString('base64');
  const replay=()=>pinnedHttps({url:srv.url+'/api/v1/heartbeat',method:'POST',body,headers:{authorization:`Bearer ${creds.token}`,'x-nmzp-challenge':c.nonce,'x-nmzp-signature':signature},...pin});
  assert.equal((await replay()).status,200);assert.equal((await replay()).status,401);
  await api('/api/v1/probe/binding','POST',{...enroll,publicKey:keys().publicKey},srv.adminToken);await assert.rejects(protectedHeartbeat(creds,k.privateKey,binding.keyId,'{}'),/probe_challenge_invalid/);
  await assert.rejects(srv.store.touchDevice('device',{lastSeen:2},binding.keyId),/probe_binding_changed/);await assert.rejects(srv.store.touchDevice('device',{lastSeen:2},null),/probe_binding_changed/);
  await api('/api/v1/probe/binding','POST',{deviceId:'device',action:'revoke'},srv.adminToken);
  assert.equal((await api('/api/v1/heartbeat','POST',{})).status,401);assert.equal((await api('/api/v1/probe/challenge')).status,403);
 }finally{await viewer.close();await srv.close();await rm(home,{recursive:true,force:true});}
});
