import assert from 'node:assert/strict';import {it} from 'node:test';
import {mkdtempSync,rmSync} from 'node:fs';import {join} from 'node:path';import {tmpdir} from 'node:os';
import {scanMetadata,type ScanInput} from './agent-discovery-scan.ts';
import {windowsDiscoveryScript} from './agent-discovery-windows.ts';
import {runDiscoveryOs} from './agent-discovery.ts';
import {runPowershell} from './network-collect.ts';
const zcodeMain={path:'C:/Synthetic/ZCode/ZCode.exe',product:'ZCode',description:'ZCode',version:'3.12.3.7463'};
const zcodeUninstall={path:'C:/Synthetic/ZCode/Uninstall ZCode.exe',product:'ZCode',description:'ZCode Desktop App',version:'3.12.3'};
function registryScan(files:ScanInput['os']['files'],records?:ScanInput['os']['records']):{home:string,input:ScanInput,clean:()=>void}{
 const home=mkdtempSync(join(tmpdir(),'nmzp-registry-'));
 const input:ScanInput={home,key:'fixture',now:1_700_000_000_000,manual:[],pathDirs:[],packageRoots:[],extensionRoots:[],pythonRoots:[],
  os:{records:records??[{adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_LOCAL_MACHINE/Synthetic/ZCode',version:'3.12.3',entryCandidates:[zcodeMain.path,zcodeUninstall.path]}],files,processes:[],states:{}}};
 return {home,input,clean:()=>rmSync(home,{recursive:true,force:true})};
}
it('registry-only ZCode persists version, stable redacted identity and unresolved entry; nearby ambiguity stays candidate',()=>{
 const home=mkdtempSync(join(tmpdir(),'nmzp-registry-'));
 try{
  const input:ScanInput={home,key:'fixture',now:Date.now(),manual:[],pathDirs:[],packageRoots:[],extensionRoots:[],pythonRoots:[],
    os:{records:[{adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_LOCAL_MACHINE/PRIVATE_USER/ZCode',version:'3.12.3',location:''}],files:[],processes:[],states:{}}};
  const a=scanMetadata(input).items;assert.equal(a.length,1);assert.equal(a[0].version,'3.12.3');assert.equal(a[0].identity,'candidate');
  assert.equal(a[0].installation,'candidate');assert.equal(a[0].running,'unknown');assert.ok(a[0].reasons.includes('entry_unresolved'));
  assert.ok(!JSON.stringify(a).includes('PRIVATE_USER'));assert.equal(a[0].scopeEligible,false);
  input.os.records[0].entryCandidates=['C:/ZCode/ZCode.exe','C:/ZCode/uninstall.exe'];
  input.os.files=[{path:'C:/ZCode/ZCode.exe',product:'ZCode',signature:'Valid'}];
  const b=scanMetadata(input).items;assert.equal(b.length,1);assert.equal(b[0].instanceId,a[0].instanceId);assert.equal(b[0].identity,'corroborated');assert.equal(b[0].scopeEligible,false);
  input.os.records.push({...input.os.records[0],sourceId:'HKEY_CURRENT_USER/PRIVATE_USER/ZCode',entryCandidates:[]});
  const c=scanMetadata(input).items;assert.equal(c.length,2);assert.notEqual(c[0].instanceId,c[1].instanceId);
  input.os.files.push({path:'C:/ZCode/uninstall.exe',product:'ZCode',signature:'Valid'});
  const all=scanMetadata(input).items;const d=all.find(i=>i.instanceId===a[0].instanceId)!;
  assert.equal(all.length,2);assert.equal(all.filter(i=>i.installation==='present').length,0);
  assert.equal(d.identity,'candidate');assert.ok(d.reasons.includes('entry_unresolved'));
 }finally{rmSync(home,{recursive:true,force:true});}
});
it('one registry plus main and uninstaller files yields a single unresolved candidate, not two present installs',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,1);
  assert.equal(items.filter(i=>i.installation==='present').length,0);
  assert.equal(items[0].installation,'candidate');
  assert.equal(items[0].identity,'candidate');
  assert.equal(items[0].running,'unknown');
  assert.equal(items[0].version,'3.12.3');
  assert.equal(items[0].scopeEligible,false);
  assert.equal(items[0].protection,'not_verified');
  assert.ok(items[0].reasons.includes('entry_unresolved'));
  assert.ok(items[0].evidence.includes('uninstall_record'));
  assert.ok(!items[0].evidence.includes('file_metadata'));
 }finally{f.clean();}
});
it('unique matching entry completes the same registry instance with stable id and version',()=>{
 const f=registryScan([]);
 try{
  const a=scanMetadata(f.input).items;
  assert.equal(a.length,1);
  f.input.os.files=[{...zcodeMain}];
  const b=scanMetadata(f.input).items;
  assert.equal(b.length,1);
  assert.equal(b[0].instanceId,a[0].instanceId);
  assert.equal(b[0].identity,'corroborated');
  assert.equal(b[0].installation,'present');
  assert.equal(b[0].version,'3.12.3');
  assert.equal(b[0].running,'not_observed');
  assert.equal(b[0].scopeEligible,false);
  assert.equal(b[0].protection,'not_verified');
 }finally{f.clean();}
});
it('independent portable install is not merged into an ambiguous registry group',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall,{path:'C:/Portable/ZCode/ZCode.exe',product:'ZCode',description:'ZCode',version:'3.12.3.7463'}]);
 try{
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,2);
  const grouped=items.find(i=>i.sources.includes('registry'))!;
  const portable=items.find(i=>i.instanceId!==grouped.instanceId)!;
  assert.equal(grouped.installation,'candidate');
  assert.ok(grouped.reasons.includes('entry_unresolved'));
  assert.equal(portable.installation,'present');
  assert.ok(portable.sources.includes('path'));
  assert.equal(portable.scopeEligible,false);
  assert.equal(portable.protection,'not_verified');
 }finally{f.clean();}
});
it('independent registry sources remain distinct identities',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall,{path:'C:/Users/Synthetic/ZCode/ZCode.exe',product:'ZCode',version:'3.12.3'}],[
  {adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_LOCAL_MACHINE/Synthetic/ZCode',version:'3.12.3',entryCandidates:[zcodeMain.path,zcodeUninstall.path]},
  {adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_CURRENT_USER/Synthetic/ZCode',version:'3.12.3',entryCandidates:['C:/Users/Synthetic/ZCode/ZCode.exe']},
 ]);
 try{
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,2);
  assert.notEqual(items[0].instanceId,items[1].instanceId);
  const unresolved=items.find(i=>i.reasons.includes('entry_unresolved'));
  const present=items.find(i=>i.installation==='present');
  assert.ok(unresolved);
  assert.ok(present);
  assert.notEqual(unresolved.instanceId,present.instanceId);
  assert.equal(unresolved.installation,'candidate');
  assert.equal(present.identity,'corroborated');
 }finally{f.clean();}
});
it('entryCandidate file order does not change grouped identity or counts',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  const a=scanMetadata(f.input).items;
  f.input.os.files=[zcodeUninstall,zcodeMain];
  const b=scanMetadata(f.input).items;
  assert.equal(a.length,1);
  assert.equal(b.length,1);
  assert.equal(a[0].instanceId,b[0].instanceId);
  assert.equal(a[0].installation,b[0].installation);
  assert.equal(a[0].identity,b[0].identity);
  assert.equal(a.filter(i=>i.installation==='present').length,0);
  assert.equal(b.filter(i=>i.installation==='present').length,0);
 }finally{f.clean();}
});
function assertUntrustedCandidate(item:{installation:string,identity:string,scopeEligible:boolean,protection:string,integration:string,reasons:string[],evidence:string[]}){
 assert.equal(item.installation,'candidate');
 assert.equal(item.identity,'candidate');
 assert.equal(item.scopeEligible,false);
 assert.equal(item.protection,'not_verified');
 assert.equal(item.integration,'not_bound');
 assert.ok(item.reasons.includes('entry_unresolved'));
 assert.ok(!item.evidence.includes('file_metadata'));
}
function procIds(item:{processes:Array<{pid:number,startedAt:number}>}){
 return item.processes.map(p=>`${p.pid}:${p.startedAt}`).sort();
}
it('ambiguous registry plus matching stable processes is one candidate/observed with PID+startedAt and no trust',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  f.input.os.processes=[
   {pid:4100,path:zcodeMain.path,startedAt:1_700_000_010_000},
   {pid:4101,path:zcodeMain.path,startedAt:1_700_000_010_100},
   {pid:4102,path:zcodeMain.path,startedAt:1_700_000_010_200},
  ];
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,1);
  assert.equal(items[0].running,'observed');
  assert.equal(items[0].processes.length,3);
  assert.deepEqual(procIds(items[0]),['4100:1700000010000','4101:1700000010100','4102:1700000010200']);
  assertUntrustedCandidate(items[0]);
  assert.ok(!items[0].reasons.includes('runtime_unattributed'));
  assert.ok(!JSON.stringify(items[0].processes).includes('ZCode.exe'));
  assert.ok(!JSON.stringify(items[0]).includes('C:/Synthetic'));
 }finally{f.clean();}
});
it('ambiguous registry without processes stays unknown and untrusted',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,1);
  assert.equal(items[0].running,'unknown');
  assert.deepEqual(items[0].processes,[]);
  assertUntrustedCandidate(items[0]);
  assert.ok(items[0].reasons.includes('runtime_unattributed'));
 }finally{f.clean();}
});
it('process on an unmatched path is not attributed to the unresolved registry',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  f.input.os.processes=[{pid:9,path:'C:/Windows/System32/notepad.exe',startedAt:1_700_000_000_009}];
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,1);
  assert.equal(items[0].running,'unknown');
  assert.deepEqual(items[0].processes,[]);
  assertUntrustedCandidate(items[0]);
 }finally{f.clean();}
});
it('file metadata errors do not attach candidate processes',()=>{
 const f=registryScan([{...zcodeMain,error:'pe_read'},{...zcodeUninstall,error:'pe_read'}]);
 try{
  f.input.os.processes=[{pid:4100,path:zcodeMain.path,startedAt:1_700_000_010_000}];
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,1);
  assert.equal(items[0].running,'unknown');
  assert.deepEqual(items[0].processes,[]);
  assertUntrustedCandidate(items[0]);
 }finally{f.clean();}
});
it('the same file owned by multiple unresolved registries is not copied onto both',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall],[
  {adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_LOCAL_MACHINE/Synthetic/ZCode',version:'3.12.3',entryCandidates:[zcodeMain.path,zcodeUninstall.path]},
  {adapterId:'zcode-desktop',source:'registry',sourceId:'HKEY_CURRENT_USER/Synthetic/ZCode',version:'3.12.3',entryCandidates:[zcodeMain.path,zcodeUninstall.path]},
 ]);
 try{
  f.input.os.processes=[{pid:77,path:zcodeMain.path,startedAt:5}];
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,2);
  assert.notEqual(items[0].instanceId,items[1].instanceId);
  assert.ok(items.every(i=>i.running==='unknown' && i.processes.length===0 && i.installation==='candidate'));
  assertUntrustedCandidate(items[0]);
  assertUntrustedCandidate(items[1]);
 }finally{f.clean();}
});
it('entryCandidate file order does not change candidate process attachment',()=>{
 const f=registryScan([zcodeMain,zcodeUninstall]);
 try{
  f.input.os.processes=[
   {pid:4100,path:zcodeMain.path,startedAt:1_700_000_010_000},
   {pid:4101,path:zcodeMain.path,startedAt:1_700_000_010_100},
  ];
  const a=scanMetadata(f.input).items;
  f.input.os.files=[zcodeUninstall,zcodeMain];
  const b=scanMetadata(f.input).items;
  assert.equal(a.length,1);
  assert.equal(b.length,1);
  assert.equal(a[0].instanceId,b[0].instanceId);
  assert.equal(a[0].running,'observed');
  assert.equal(b[0].running,'observed');
  assert.deepEqual(procIds(a[0]),procIds(b[0]));
  assert.deepEqual(procIds(a[0]),['4100:1700000010000','4101:1700000010100']);
  assertUntrustedCandidate(a[0]);
  assertUntrustedCandidate(b[0]);
 }finally{f.clean();}
});
it('portable install keeps its own observed processes away from an ambiguous registry group',()=>{
 const portable={path:'C:/Portable/ZCode/ZCode.exe',product:'ZCode',description:'ZCode',version:'3.12.3.7463'};
 const f=registryScan([zcodeMain,zcodeUninstall,portable]);
 try{
  f.input.os.processes=[
   {pid:4100,path:zcodeMain.path,startedAt:10},
   {pid:8800,path:portable.path,startedAt:11},
  ];
  const items=scanMetadata(f.input).items;
  assert.equal(items.length,2);
  const grouped=items.find(i=>i.sources.includes('registry'))!;
  const port=items.find(i=>i.instanceId!==grouped.instanceId)!;
  assert.equal(grouped.running,'observed');
  assert.deepEqual(procIds(grouped),['4100:10']);
  assertUntrustedCandidate(grouped);
  assert.equal(port.installation,'present');
  assert.equal(port.running,'observed');
  assert.deepEqual(procIds(port),['8800:11']);
  assert.equal(port.scopeEligible,false);
 }finally{f.clean();}
});
it('generated Windows source parses without executing any candidate; timeout preserves completed registry phase',{skip:process.platform!=='win32'},async()=>{
 const script=windowsDiscoveryScript([], 'C:\\Synthetic');const b64=Buffer.from(script,'utf8').toString('base64');
 const result=await runPowershell(`$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')),[ref]$t,[ref]$e);if($e.Count){exit 1};Write-Output 'syntax-ok'`,8000);
 assert.equal(result.error,undefined);assert.match(result.stdout,/syntax-ok/);
 const partial=JSON.stringify({records:[{adapterId:'zcode-desktop',source:'registry',sourceId:'fixture',version:'3.12.3'}],files:[],processes:[],states:{registry:'ok',appx:'partial',processes:'partial',path:'partial'}});
 const os=await runDiscoveryOs(`Write-Output '${partial}';Start-Sleep -Seconds 30`,2000);
 assert.equal(os.records.length,1);assert.equal(os.states.registry,'ok');assert.equal(os.states.appx,'timeout');assert.equal(os.states.processes,'timeout');assert.equal(os.states.path,'timeout');
});
