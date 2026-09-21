import assert from 'node:assert/strict';
import {it} from 'node:test';
import {mkdtemp,writeFile,rm,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {safeWorkspacePath,validateWorkspaceFiles,collectWorkspace,makeNativeRequest,validateNativeResult,type SessionSettings} from './protected-session-controller.ts';
it('controller contract fixes native scope, uses exact FILETIME and excludes approval bypass/upstream secrets',()=>{
 const settings:SessionSettings={nativeHelper:'native.exe',grokExecutable:'grok.exe',grokSha256:'a'.repeat(64),upstreamOrigin:'https://provider.invalid',model:'nmzp-proof',workspace:'fixture',files:['main.js'],prompt:'Edit main.js using normal approvals.'};
 const req=makeNativeRequest(settings,{pid:123,creationTime:'134030000000000001'},{port:31415,sessionToken:'b'.repeat(64)},[{path:'main.js',base64:Buffer.from('console.log(1)').toString('base64')}],'nmzp-owned-'+'c'.repeat(64),'d'.repeat(64));
 assert.equal(req.controller_creation_time,'134030000000000001');assert.equal(req.network_mode,'brokered');assert.equal(req.appcontainer_kind,'lpac');assert.ok(!JSON.stringify(req).includes(settings.upstreamOrigin));assert.ok(!('arguments' in req));
 for(const path of ['../secret','C:/secret','a:stream','.env','.env.local','a/.git/config','a/.grok/config.toml','a/CON.txt','a/..','a/','a\\b','a\n'])assert.equal(safeWorkspacePath(path),false,path);
 assert.throws(()=>makeNativeRequest({...settings,model:'bad\nfield'},{pid:123,creationTime:'1'},{port:1,sessionToken:'b'.repeat(64)},[],'nmzp-owned-'+'c'.repeat(64),'d'.repeat(64)));
 assert.throws(()=>validateWorkspaceFiles([{path:'x',base64:'',secret:'must drop'}]));assert.throws(()=>validateWorkspaceFiles([{path:'X',base64:''},{path:'x',base64:''}]));
 assert.throws(()=>validateNativeResult({ok:true,exit_code:0,error_code:'',extra:{}}));
 assert.deepEqual(validateNativeResult({ok:false,exit_code:1,error_code:'lease_prepare',extra:{cleanup_required:true},stdout:'SECRET'}),{ok:false,exitCode:1,errorCode:'lease_prepare',cleanupRequired:true,leaseClosed:false,productionReady:false});
});
it('workspace input is explicit, bounded, and rejects hard links; it never rewrites source',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nmzp-controller-input-'));try{
  await writeFile(join(dir,'main.js'),'console.log(1)');await writeFile(join(dir,'.env'),'DO_NOT_COPY');
  const files=await collectWorkspace(dir,['main.js']);assert.equal(files.length,1);assert.equal(Buffer.from(files[0]!.base64,'base64').toString(),'console.log(1)');
  await assert.rejects(collectWorkspace(dir,['.env']));await link(join(dir,'main.js'),join(dir,'linked.js'));await assert.rejects(collectWorkspace(dir,['linked.js']));
 }finally{await rm(dir,{recursive:true,force:true});}
});
