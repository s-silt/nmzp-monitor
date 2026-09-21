import assert from 'node:assert/strict';
import {it} from 'node:test';
import {createServer} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {startModelGateway,loopbackHttpFactory,type ModelGatewayEvent} from './model-gateway.ts';
import {NmzpStore} from './persist.ts';
import {storeResponseObservation} from './model-response-audit.ts';
import {exportBundleShape} from './export.ts';
it('real cancel, timeout and upstream disconnect remain failed in audit/export; async sink failures are visible',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nmzp-response-fault-'));const store=new NmzpStore(dir);await store.load();
 let mode='cancel';const events:ModelGatewayEvent[]=[];const receipts:Promise<void>[]=[];
 const upstream=createServer((_req,res)=>{
  res.writeHead(200,{'content-type':'text/event-stream'});
  res.write('data: '+JSON.stringify({choices:[{delta:{content:'PRIVATE_RESPONSE_MARKER'}}]})+'\n\n');
  if(mode==='disconnect')setTimeout(()=>res.destroy(),30);
 });
 await new Promise<void>(r=>upstream.listen(0,'127.0.0.1',r));const addr=upstream.address();if(!addr||typeof addr==='string')throw Error('listen');
 const gw=await startModelGateway({upstreamOrigin:`http://127.0.0.1:${addr.port}`,createUpstreamRequest:loopbackHttpFactory,streamIdleMs:100,onEvent:e=>{
  events.push(e);if(e.responseObservation){const p=storeResponseObservation(store,{machineId:'fixture',sessionId:'synthetic',agent:'grok'},e);receipts.push(p);return p;}
 }});
 const request=()=>fetch(gw.url+'/v1/chat/completions',{method:'POST',headers:{authorization:`Bearer ${gw.sessionToken}`,'content-type':'application/json'},body:JSON.stringify({model:'synthetic',stream:true,messages:[{role:'user',content:'hello'}]})});
 try{
  for(const m of ['cancel','timeout','disconnect']){
   mode=m;const response=await request();const reader=response.body!.getReader();await reader.read();
   if(m==='cancel')await reader.cancel();else await assert.rejects(async()=>{while(!(await reader.read()).done){ /* Drain until the transport failure is surfaced. */ }});
   const deadline=Date.now()+1500;while(events.filter(e=>e.responseObservation).length<receipts.length||receipts.length<['cancel','timeout','disconnect'].indexOf(m)+1){if(Date.now()>deadline)throw Error('missing event');await new Promise(r=>setTimeout(r,10));}
  }
  await Promise.all(receipts);assert.equal(store.listEvents().length,3);
  assert.deepEqual(store.listEvents().map(e=>e.enforcement),['failed','timeout','failed']);
  assert.ok(events.filter(e=>e.responseObservation).every(e=>!e.transport?.clientWriteComplete));
  assert.ok(!JSON.stringify(exportBundleShape(store)).includes('PRIVATE_RESPONSE_MARKER'));
 }finally{await gw.close();upstream.closeAllConnections();await new Promise<void>(r=>upstream.close(()=>r()));await rm(dir,{recursive:true,force:true});}
 const bad=await startModelGateway({upstreamOrigin:'https://example.invalid',onEvent:async()=>{throw Error('SECRET_ERROR_BODY');}});
 try{
  await fetch(bad.url,{method:'GET'});await new Promise(r=>setTimeout(r,20));
  assert.equal(bad.status().audit.failed,1);assert.equal(bad.status().audit.pending,0);assert.ok(!JSON.stringify(bad.status()).includes('SECRET_ERROR_BODY'));
 }finally{await bad.close();}
 const hung=await startModelGateway({upstreamOrigin:'https://example.invalid',onEvent:()=>new Promise(()=>{})});
 try{
  for(let n=0;n<35;n++)await fetch(hung.url,{method:'GET'});
  assert.equal(hung.status().audit.pending,32);assert.equal(hung.status().audit.dropped,3);
  await new Promise(r=>setTimeout(r,1050));assert.equal(hung.status().audit.timedOut,32);
 }finally{await hung.close();}
});
