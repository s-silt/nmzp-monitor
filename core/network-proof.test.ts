import assert from 'node:assert/strict';
import {it} from 'node:test';
import {assessNetworkProof} from './network-proof.ts';
import type {NetworkSampleReport} from './schema.ts';
it('live proof requires same stable real identity and socket; failures cannot pass and missing controls stay unverified',()=>{
 const proc={pid:123,ppid:1,name:'grok.exe',exe:'C:\\Users\\Fixture\\.grok\\bin\\grok.exe',startedAt:1000};
 const socket={pid:123,localIp:'127.0.0.1',localPort:12000,remoteIp:'127.0.0.1',remotePort:13000,state:'Established'};
 const sample:NetworkSampleReport={status:'ok',observedAt:2000,connections:[{...socket,ppid:1,processStartedAt:1000,bin:'grok.exe',agent:'grok',role:'egress',observedAt:2000}]};
 const check=(s:NetworkSampleReport)=>assessNetworkProof(s,[proc],[proc],[socket],[socket]);
 assert.equal(check(sample).status,'verified');
 for(const status of ['timeout','permission','partial','not_sampled','error','truncated'] as const)assert.equal(check({...sample,status,connections:[]}).status,'failed');
 assert.equal(check({...sample,connections:[]}).status,'failed');
 assert.equal(check({...sample,connections:[{...sample.connections[0]!,remotePort:13001}]}).status,'failed');
 assert.equal(check({...sample,connections:[{...sample.connections[0]!,processStartedAt:999}]}).status,'failed');
 assert.equal(assessNetworkProof(sample,[proc],[{...proc,startedAt:1001}],[socket],[socket]).status,'not_verified');
 assert.equal(assessNetworkProof(sample,[],[],[],[]).status,'not_verified');
});
