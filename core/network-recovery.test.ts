import assert from 'node:assert/strict';
import {it} from 'node:test';
import {mkdtemp,rm,mkdir,rename,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {NmzpStore} from './persist.ts';
const now=Date.now();
const device={id:'dev_fixture',tokenHash:'synthetic',hostname:'fixture',ip:'127.0.0.1',user:'fixture',os:'win32' as const,attachedAt:now,lastSeen:now,lastPolicyVersion:1,capabilities:[],agents:[]};
const sample={status:'ok',observedAt:now,connections:[{localIp:'127.0.0.1',localPort:41000,remoteIp:'203.0.113.8',remotePort:443,state:'Established',role:'egress',observedAt:now,pid:123,ppid:1,processStartedAt:now-1000,bin:'grok.exe',agent:'grok'}]};
it('network mirror failure never publishes a sample or history; restart and retry preserve one tuple',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nmzp-network-recovery-'));try{
  const s=new NmzpStore(dir);await s.load();await s.putDevice(device);
  if(await readFile(s.networkPath()).then(()=>true,()=>false))await rename(s.networkPath(),s.networkPath()+'.old');
  await mkdir(s.networkPath());await assert.rejects(s.applyNetworkSample(device.id,sample,false,now));
  assert.equal(s.getDevice(device.id)?.network,undefined);assert.equal(s.listNetworkHistory().length,0);
  await rm(s.networkPath(),{recursive:true});
  const recovered=new NmzpStore(dir);await recovered.load();assert.equal(recovered.getDevice(device.id)?.network,undefined);
  await recovered.applyNetworkSample(device.id,sample,false,now);await recovered.applyNetworkSample(device.id,sample,false,now);
  assert.equal(recovered.listNetworkHistory().length,1);
 }finally{await rm(dir,{recursive:true,force:true});}
});
it('device commit failure after mirror write restores authoritative history on restart; put/touch remain unchanged',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nmzp-network-commit-'));try{
  const s=new NmzpStore(dir);await s.load();await s.putDevice(device);
  await rename(s.devicesPath(),s.devicesPath()+'.saved');await mkdir(s.devicesPath());
  await assert.rejects(s.applyNetworkSample(device.id,sample,false,now));
  assert.equal(s.getDevice(device.id)?.network,undefined);assert.equal(s.listNetworkHistory().length,0);
  await assert.rejects(s.touchDevice(device.id,{hostname:'must-not-publish'}));assert.equal(s.getDevice(device.id)?.hostname,'fixture');
  await assert.rejects(s.putDevice({...device,id:'not-saved'}));assert.equal(s.getDevice('not-saved'),undefined);
  await rm(s.devicesPath(),{recursive:true});await rename(s.devicesPath()+'.saved',s.devicesPath());
  const restart=new NmzpStore(dir);await restart.load();
  assert.equal(restart.getDevice(device.id)?.network,undefined);assert.equal(restart.listNetworkHistory().length,0);
  assert.equal((await readFile(restart.networkPath(),'utf8')).trim(),'');
  await restart.applyNetworkSample(device.id,sample,false,now);await restart.applyNetworkSample(device.id,sample,false,now);
  const final=new NmzpStore(dir);await final.load();assert.equal(final.listNetworkHistory().length,1);assert.equal(final.getDevice(device.id)?.network?.connections.length,1);
 }finally{await rm(dir,{recursive:true,force:true});}
});
