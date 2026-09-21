import {it} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,writeFile,rm} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';
import {readMailbox,MAILBOX_LIMIT} from './probe-mailbox.ts';import {scanMetadata} from './agent-discovery-scan.ts';import {parseProbeProtection,probeProtectionText} from './probe-protection.ts';
it('user mailbox only supplies bounded discovery; protection/network/commands cannot cross this boundary',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nmzp-mailbox-')),file=join(dir,'discovery.json');
 try{
  assert.equal(readMailbox(file).status,'error');await writeFile(file,'{bad json');assert.equal(readMailbox(file).status,'error');
  await writeFile(file,' '.repeat(MAILBOX_LIMIT+1));assert.equal(readMailbox(file).status,'error');
  const old=Date.now()-360000,base=scanMetadata({home:dir,key:'fixture',now:old,manual:[],pathDirs:[],packageRoots:[],extensionRoots:[],pythonRoots:[],os:{records:[{adapterId:"zcode-desktop",source:"registry",sourceId:"synthetic",version:"1.2.3"}],files:[],processes:[],states:{}}});
  await writeFile(file,JSON.stringify({...base,checkedAt:old,completedAt:old,items:base.items.map(i=>({...i,identity:"corroborated",scopeEligible:true,protection:"verified"})),probeBinding:{publicKey:'fake'},network:{connections:[{secret:'SECRET'}]},command:'launch.exe',capabilities:[{active:true}]}));
  const parsed=readMailbox(file);assert.equal(parsed.completedAt,old);assert.doesNotMatch(JSON.stringify(parsed),/SECRET|command|capabilities|probeBinding/);
  assert.equal(parsed.items.length,1);assert.equal(parsed.items.every(x=>x.scopeEligible===false&&x.protection==='not_verified'&&x.identity==='candidate'),true);
  await writeFile(file,JSON.stringify({...base,completedAt:Date.now()+120000}));assert.equal(readMailbox(file).status,'error');
 }finally{await rm(dir,{recursive:true,force:true});}
});
it('frontend projection sanitizes fields and expires signature evidence without resetting timestamps',()=>{
 const now=Date.now(),raw={mode:'signature_required',identity:'authenticated',lastAuthenticatedAt:now,isolation:'not_verified',discoverySource:'user_metadata',privateKey:'SECRET'};
 assert.equal(parseProbeProtection(raw,now+90001)?.identity,'stale');assert.doesNotMatch(JSON.stringify(parseProbeProtection(raw)),/SECRET|privateKey/);
 assert.match(probeProtectionText(raw,'zh',now),/本机隔离待原机验收/);assert.match(probeProtectionText(raw,'zh',now+90001),/过期/);
 assert.match(probeProtectionText(undefined,'zh'),/未验证/);assert.equal(parseProbeProtection({...raw,isolation:'verified'}),undefined);
});
