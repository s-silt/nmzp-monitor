import assert from 'node:assert/strict';import {it} from 'node:test';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {startServer} from './serve.ts';import {startLanViewer} from './lan-viewer.ts';import {pinnedHttps} from './https-client.ts';import {sha256Hex} from './auth.ts';
import {NmzpStore} from './persist.ts';import {probeTick} from './probe.ts';import {scanMetadata} from './agent-discovery-scan.ts';
import {approveNetworkOwner,collectOwnedAgentTcp,hashOwnerFile,ownerPathAllowed,ownerPathHash,type NetworkOwnerDeps} from './network-owner.ts';
import {activeOwnerGrants,OWNER_MAX_MS} from './network-owner-schema.ts';import {sampleView,networkOwnerMessage} from '../src/lib/monitor/network-view.ts';
import type {Machine} from '../src/lib/monitor/types.ts';
it('CT admin authority → local hash/PID verification → ordinary probe → persisted API/LAN; revocation and impersonation fail closed',async t=>{
 const home=await mkdtemp(join(tmpdir(),'nmzp-owner-'));const data=join(home,'ct');
 const srv=await startServer({dataDir:data,host:'127.0.0.1',port:0,coreDir:import.meta.dirname,uiDir:null});
 const creds={deviceId:'owner-device',token:'fixture-device-token',url:srv.url,caPem:srv.tls.certPem,fingerprintSha256:srv.tls.fingerprintSha256};
 const pin={caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256};
 const api=async(path:string,method='GET',body?:unknown,token=srv.adminToken)=>pinnedHttps({url:srv.url+path,method,...pin,headers:{authorization:`Bearer ${token}`},body:body===undefined?undefined:JSON.stringify(body)});
 const viewer=await startLanViewer({host:'127.0.0.1',port:0,allowedCidrs:['127.0.0.0/8'],uiDir:home,ctUrl:srv.url,...pin,adminToken:srv.adminToken});
 const exe=join(home,'PRIVATE_PATH','grok.exe');await mkdir(join(home,'PRIVATE_PATH'));await writeFile(exe,'synthetic executable metadata fixture, never run');
 await mkdir(join(home,'.nmzp'));await writeFile(join(home,'.nmzp','credentials.json'),JSON.stringify(creds));
 const now=Date.now(),startedAt=now-1000,pid=321;
 await srv.store.putDevice({id:creds.deviceId,tokenHash:sha256Hex(creds.token),hostname:'PRIVATE_USER-PC',user:'PRIVATE_USER',ip:'127.0.0.1',os:'win32',attachedAt:now,lastSeen:now,lastPolicyVersion:1,agents:[],capabilities:[]});
 const row={pid,ppid:1,name:'grok.exe',exe,startedAt};let changedStart=false,tcpCalls=0,afterTcp:undefined|(()=>Promise<void>);
 const deps:NetworkOwnerDeps={processes:async()=>[{...row,startedAt:changedStart?startedAt+1:startedAt}],network:{platform:'win32',run:async(kind,script)=>{
   assert.doesNotMatch(script,/CommandLine/);if(kind==='tcp'){
     tcpCalls++;await afterTcp?.();
     return {stdout:JSON.stringify([{pid,LocalAddress:'127.0.0.1',LocalPort:54321,RemoteAddress:'127.0.0.1',RemotePort:18888,State:'Established'},
       {pid:999,LocalAddress:'127.0.0.1',LocalPort:55555,RemoteAddress:'127.0.0.1',RemotePort:18888,State:'Established'}])};
   }
   assert.match(script,/ProcessId=321/);return {stdout:JSON.stringify([row,{...row,pid:999,ppid:321,name:'node.exe',exe:'C:\\Unrelated\\node.exe'}])};
 }}};
 const claim={agent:'grok' as const,exe,pid,startedAt,sha256:await hashOwnerFile(exe),durationMs:60000};
 let grant:Awaited<ReturnType<typeof approveNetworkOwner>>;
 const collect=()=>collectOwnedAgentTcp({home,creds,deps});
 const approve=async()=>grant=await approveNetworkOwner(home,claim,srv.adminToken,deps);
 const revoke=async()=>{assert.equal((await api('/api/v1/network-owners','POST',{deviceId:creds.deviceId,action:'revoke',id:grant.id})).status,200);};
 try{
  await t.test('unapproved metadata and device token cannot grant authority',async()=>{
    assert.equal((await collect()).error,'no_confirmed_agent');assert.equal(tcpCalls,0);
    await assert.rejects(approveNetworkOwner(home,claim,creds.token,deps),/owner_authority_unavailable/);
    assert.equal((await api('/api/v1/heartbeat','POST',{networkOwners:[claim]},creds.token)).status,200);
    assert.equal(activeOwnerGrants(srv.store.getDevice(creds.deviceId)?.networkOwners).length,0);
    assert.equal((await api('/api/v1/network-owners','POST',{deviceId:creds.deviceId,action:'approve',claim:{...claim,pathHash:ownerPathHash(exe),expiresAt:now+OWNER_MAX_MS*2}})).status,400);
    assert.equal((await api('/api/v1/network-owners','POST',null)).status,400);
  });
  await t.test('approved custom path samples only exact PID, with real binary hashing and ordinary probe upload',async()=>{
    await approve();
    const discovery=scanMetadata({home,key:'fixture',now:Date.now(),manual:[],pathDirs:[],packageRoots:[],extensionRoots:[],pythonRoots:[],os:{records:[],files:[],processes:[],states:{}}});
    const tick=await probeTick({home,networkOwnerDeps:deps,collectDiscovery:async()=>discovery,collectSnapshotGuard:async()=>({error:'unsupported'})});
    assert.equal(tick.ok,true);assert.equal(tcpCalls,1);
    const network=srv.store.getDevice(creds.deviceId)!.network!;assert.equal(network.status,'ok');assert.equal(network.connections.length,1);assert.equal(network.connections[0].pid,pid);
    const restored=new NmzpStore(data);await restored.load({readOnly:true});assert.equal(restored.getDevice(creds.deviceId)!.network?.connections.length,1);assert.equal(restored.getDevice(creds.deviceId)!.networkOwners?.[0].id,grant.id);
    const result=JSON.parse((await api('/api/v1/state')).body);assert.equal(result.deviceNetwork[creds.deviceId].connections.length,1);
    const lan=await(await fetch(viewer.url+'/api/v1/state')).json();assert.equal(lan.access,'viewer');assert.equal(lan.deviceNetwork[creds.deviceId].connections.length,1);
    const frontend=sampleView({...lan.devices[0],network:lan.deviceNetwork[creds.deviceId]} as Machine,Date.now());assert.equal(frontend.status,'ok');assert.equal(frontend.connections[0].agent,'grok');
    const exported=(await api('/api/v1/export')).body;
    for(const raw of [JSON.stringify(result),JSON.stringify(lan),exported]){assert.doesNotMatch(raw,/PRIVATE_PATH|PRIVATE_USER|networkOwners|pathHash/);assert.ok(!raw.includes(claim.sha256));}
    assert.equal((await fetch(viewer.url+'/api/v1/network-owners')).status,404);
    assert.equal((await fetch(viewer.url+'/api/v1/network-owners',{method:'POST',body:'{}'})).status,405);
  });
  await t.test('reused PID or exited process cannot obtain even a TCP query',async()=>{
    const count=tcpCalls;changedStart=true;assert.equal((await collect()).error,'owner_identity_changed');changedStart=false;
    assert.equal((await collectOwnedAgentTcp({home,creds,deps:{...deps,processes:async()=>[]}})).error,'owner_identity_changed');assert.equal(tcpCalls,count);
  });
  await t.test('renamed fake, file replacement and shared hosts fail identity approval',async()=>{
    const count=tcpCalls;await writeFile(exe,'changed counterfeit');assert.equal((await collect()).error,'owner_hash_mismatch');assert.equal(tcpCalls,count);
    await assert.rejects(approveNetworkOwner(home,claim,srv.adminToken,deps),/owner_hash_mismatch/);
    for(const base of ['node.exe','python.exe','Code.exe','Electron.exe','msedge.exe','cmd.exe'])assert.equal(ownerPathAllowed('grok','C:\\Tools\\'+base),false);
    await writeFile(exe,'synthetic executable metadata fixture, never run');
  });
  await t.test('binary change or grant revoke DURING collection discards all sampled sockets',async()=>{
    afterTcp=async()=>{await writeFile(exe,'changed after sampling');};assert.equal((await collect()).error,'owner_hash_mismatch');
    await writeFile(exe,'synthetic executable metadata fixture, never run');
    afterTcp=revoke;const sample=await collect();assert.equal(sample.error,'owner_revoked');assert.equal(sample.connections.length,0);afterTcp=undefined;
    assert.match(networkOwnerMessage(sample.error,'zh')!,/结果已丢弃/);assert.equal(networkOwnerMessage('PRIVATE_PATH','zh'),null);
    const count=tcpCalls;assert.equal((await collect()).error,'no_confirmed_agent');assert.equal(tcpCalls,count);
  });
  await t.test('expiry, stopped policy, identity access failure and local mapping tamper cannot reuse approval',async()=>{
    await approve();const count=tcpCalls;
    assert.equal((await collectOwnedAgentTcp({home,creds,deps:{...deps,now:()=>grant.expiresAt+1}})).error,'no_confirmed_agent');
    await srv.store.stop();assert.equal((await collect()).error,'no_confirmed_agent');await srv.store.resume();
    assert.equal((await collectOwnedAgentTcp({home,creds,deps:{...deps,processes:async()=>{throw Error('private access denied');}}})).error,'owner_identity_unavailable');
    await writeFile(join(home,'.nmzp','network-owners',grant.id+'.json'),JSON.stringify({exe:'C:\\Fake\\grok.exe'}));assert.equal((await collect()).error,'owner_hash_mismatch');assert.equal(tcpCalls,count);
    await revoke();
  });
 }finally{await viewer.close();await srv.close();await rm(home,{recursive:true,force:true});}
});
