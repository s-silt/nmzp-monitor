import {it} from 'node:test';import assert from 'node:assert/strict';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {join} from 'node:path';
it('Windows observation-only rejects Apply even for admin, reads status, and safely removes exact synthetic legacy objects',{skip:process.platform!=='win32',timeout:30000},async()=>{
 const r=await promisify(execFile)('powershell.exe',['-NoProfile','-NonInteractive','-File',join(import.meta.dirname,'storage-firewall.test.ps1')],{windowsHide:true,timeout:25000});const j=JSON.parse(r.stdout);assert.equal(j.ok,true);assert.ok(j.checks>=20);assert.equal(j.osFirewallWrites,0);
});
