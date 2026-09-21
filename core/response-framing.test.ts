import assert from 'node:assert/strict';
import {it} from 'node:test';
import {createServer,request} from 'node:http';
import {connect} from 'node:net';
import {startModelGateway,loopbackHttpFactory} from './model-gateway.ts';
it('raw HTTP/1.1 framing and Node HTTP client distinguish complete, timeout and truncated streams',async()=>{
  let mode='complete';
  const upstream=createServer((_req,res)=>{
    res.writeHead(200,{'content-type':'text/event-stream'});
    res.write('data: {"choices":[{"delta":{"content":"synthetic"}}]}\n\n');
    if(mode==='complete')res.end('data: [DONE]\n\n');
    if(mode==='disconnect')setTimeout(()=>res.destroy(),30);
  });
  await new Promise<void>(r=>upstream.listen(0,'127.0.0.1',r));
  const addr=upstream.address();if(!addr||typeof addr==='string')throw Error('listen');
  const gw=await startModelGateway({upstreamOrigin:`http://127.0.0.1:${addr.port}`,createUpstreamRequest:loopbackHttpFactory,streamIdleMs:100});
  const body=JSON.stringify({model:'synthetic',stream:true,messages:[{role:'user',content:'hello'}]});
  const u=new URL(gw.url);const headers={authorization:`Bearer ${gw.sessionToken}`,'content-type':'application/json','content-length':Buffer.byteLength(body)};
  try{
    for(const current of ['complete','timeout','disconnect']){
      mode=current;
      const raw=await new Promise<string>((resolve,reject)=>{
        const sock=connect(Number(u.port),'127.0.0.1');let data='';
        sock.setTimeout(2000,()=>sock.destroy(Error('fixture timeout')));
        sock.setEncoding('utf8');sock.on('data',s=>data+=s);sock.on('error',reject);sock.on('close',()=>resolve(data));
        sock.on('connect',()=>sock.write(`POST /v1/chat/completions HTTP/1.1\r\nHost: ${u.host}\r\nAuthorization: ${headers.authorization}\r\nContent-Type: application/json\r\nContent-Length: ${headers['content-length']}\r\nConnection: close\r\n\r\n${body}`));
      });
      const split=raw.indexOf('\r\n\r\n');assert.ok(split>0);
      assert.match(raw.slice(0,split),/HTTP\/1.1 200/);
      assert.match(raw.slice(0,split),/transfer-encoding: chunked/i);
      assert.doesNotMatch(raw.slice(0,split),/content-length:/i);
      assert.match(raw.slice(split+4),/synthetic/);
      assert.equal(raw.endsWith('\r\n0\r\n\r\n'),current==='complete',current);
      const outcome=await new Promise<{complete:boolean;aborted:boolean;error:boolean;body:string}>((resolve,reject)=>{
        const req=request(gw.url+'/v1/chat/completions',{method:'POST',headers},res=>{
          let aborted=false,error=false,data='';res.setEncoding('utf8');res.on('data',s=>data+=s);
          res.on('aborted',()=>aborted=true);res.on('error',()=>error=true);
          res.on('close',()=>resolve({complete:res.complete,aborted,error,body:data}));
        });req.on('error',reject);req.end(body);
      });
      assert.match(outcome.body,/synthetic/);assert.equal(outcome.complete,current==='complete');
      assert.equal(outcome.aborted,current!=='complete');assert.equal(outcome.error,current!=='complete');
      const fetched=await fetch(gw.url+'/v1/chat/completions',{method:'POST',headers:{...headers,'content-length':String(headers['content-length']),connection:'close'},body});
      if(current==='complete')assert.match(await fetched.text(),/synthetic/);
      else await assert.rejects(fetched.text());
    }
  }finally{await gw.close();upstream.closeAllConnections();await new Promise<void>(r=>upstream.close(()=>r()));}
});
