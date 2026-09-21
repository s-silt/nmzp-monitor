import assert from 'node:assert/strict';import {it} from 'node:test';import {setImmediate as tick} from 'node:timers/promises';
import {OwnedAcpClient} from './protected-session-acp.ts';
it('ACP keeps filesystem/terminal inside the job and requires explicit single-use permission',async()=>{
 const sent:any[]=[];let chosen!:(s:string|null)=>void,eof=0,failed='';const output:string[]=[];
 const c=new OwnedAcpClient({write:b=>sent.push(JSON.parse(b.toString())),eof:()=>eof++,fail:code=>{failed=code;},text:s=>output.push(s),permission:async p=>{assert.deepEqual(p.options.map(o=>o.kind),['allow_once','reject_once']);return new Promise(r=>{chosen=r;});}});
 const feed=(m:unknown)=>c.feed(JSON.stringify({jsonrpc:'2.0',...m as object})+'\n');
 const run=c.start('C:\\owned\\workspace','synthetic');assert.equal(sent[0].params.clientCapabilities.terminal,false);assert.equal(sent[0].params.clientCapabilities.fs.readTextFile,false);
 feed({id:1,result:{protocolVersion:1}});await tick();assert.equal(sent[1].method,'session/new');assert.deepEqual(sent[1].params.mcpServers,[]);
 feed({id:2,result:{sessionId:'owned'}});await tick();assert.equal(sent[2].method,'session/prompt');
 feed({id:'outside',method:'fs/read_text_file',params:{path:'C:\\private'}});assert.equal(sent.at(-1).error.code,-32601);
 feed({id:'permission',method:'session/request_permission',params:{sessionId:'owned',toolCall:{title:'Synthetic edit',rawInput:{path:'answer.js'}},options:[{optionId:'yes',name:'One edit',kind:'allow_once'},{optionId:'all',name:'Always',kind:'allow_always'},{optionId:'no',name:'Reject',kind:'reject_once'}]}});
 assert.equal(sent.filter(m=>m.id==='permission').length,0);chosen('yes');await tick();assert.equal(sent.at(-1).result.outcome.optionId,'yes');
 feed({method:'session/update',params:{sessionId:'owned',update:{sessionUpdate:'agent_message_chunk',content:{type:'text',text:'ok\u001b[2J'}}}});assert.deepEqual(output,['ok[2J']);
 feed({id:3,result:{stopReason:'end_turn'}});await run;assert.equal(eof,1);assert.equal(failed,'');
});
it('ACP without a human callback cancels permission and malformed frames fail closed',async()=>{
 const sent:any[]=[];let failure='';const c=new OwnedAcpClient({write:b=>sent.push(JSON.parse(b.toString())),eof:()=>{},fail:s=>{failure=s;},text:()=>{}});
 c.feed(JSON.stringify({jsonrpc:'2.0',id:7,method:'session/request_permission',params:{}})+'\n');assert.equal(sent.at(-1).result.outcome.outcome,'cancelled');
 c.feed('{bad}\n');assert.equal(failure,'acp_protocol_refused');c.close();
});
