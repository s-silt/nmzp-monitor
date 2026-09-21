/** ACP client with no host filesystem or terminal execution capability.
 * Tool execution stays in the native LPAC/job; permission decisions stay human-owned.
 */
export interface PermissionPrompt {title:string;input:string;options:{optionId:string;name:string;kind:'allow_once'|'reject_once'}[]}
interface AcpIo {write:(data:Buffer)=>void;eof:()=>void;fail:(code:string)=>void;text:(text:string)=>void;permission?:(p:PermissionPrompt,signal:AbortSignal)=>Promise<string|null>}
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
export const terminalText=(s:string)=>s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g,'');
export class OwnedAcpClient {
 private pending='';private sequence=0;private session='';private active=false;private closed=false;
 private waiters=new Map<number,{resolve:(v:Record<string,unknown>)=>void;reject:()=>void;timer:ReturnType<typeof setTimeout>}>();
 private io:AcpIo;private budgetMs:number;private permissionAbort?:AbortController;
 constructor(io:AcpIo,budgetMs=300000){this.io=io;this.budgetMs=budgetMs;}
 private send(m:unknown){if(!this.closed)this.io.write(Buffer.from(JSON.stringify({jsonrpc:'2.0',...m as object})+'\n'));}
 private request(method:string,params:unknown,timeout=15000):Promise<Record<string,unknown>>{
  if(this.closed||this.waiters.size>=8)return Promise.reject(Error('acp_closed'));
  const id=++this.sequence;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.waiters.delete(id);reject(Error('acp_timeout'));},timeout);this.waiters.set(id,{resolve,reject:()=>reject(Error('acp_request_failed')),timer});this.send({id,method,params});});
 }
 async start(cwd:string,prompt:string){
  try{
   const init=await this.request('initialize',{protocolVersion:1,clientCapabilities:{fs:{readTextFile:false,writeTextFile:false},terminal:false},clientInfo:{name:'nmzp-owned-controller',version:'1'}});
   if(init.protocolVersion!==1)throw Error();
   const s=await this.request('session/new',{cwd,mcpServers:[]});
   if(typeof s.sessionId!=='string'||!s.sessionId||s.sessionId.length>128)throw Error();this.session=s.sessionId;
   const result=await this.request('session/prompt',{sessionId:this.session,prompt:[{type:'text',text:prompt}]},this.budgetMs);
   if(result.stopReason!=='end_turn')throw Error();
   this.io.eof();this.close();
  }catch{if(!this.closed){this.io.fail('acp_session_failed');this.close();}}
 }
 feed(text:string){
  if(this.closed)return;
  try{
   this.pending+=text;if(this.pending.length>262144)throw Error();let n;
   while((n=this.pending.indexOf('\n'))>=0){const line=this.pending.slice(0,n);this.pending=this.pending.slice(n+1);if(!line.trim())continue;const m:unknown=JSON.parse(line);if(!obj(m)||m.jsonrpc!=='2.0')throw Error();
    if(typeof m.method==='string'){
     if(m.method==='session/update'&&obj(m.params)&&m.params.sessionId===this.session&&obj(m.params.update)){
      const u=m.params.update;if(u.sessionUpdate==='agent_message_chunk'&&obj(u.content)&&u.content.type==='text'&&typeof u.content.text==='string')this.io.text(terminalText(u.content.text));
     }else if(m.method==='session/request_permission'&&(typeof m.id==='number'||typeof m.id==='string'))void this.ask(m.id,m.params);
     else if(m.id!==undefined)this.send({id:m.id,error:{code:-32601,message:'Client capability not provided'}});
    }else if(typeof m.id==='number'){
     const w=this.waiters.get(m.id);if(!w)throw Error();this.waiters.delete(m.id);clearTimeout(w.timer);
     if(m.error||!obj(m.result))w.reject();else w.resolve(m.result);
    }else throw Error();
   }
  }catch{this.io.fail('acp_protocol_refused');this.close();}
 }
 private async ask(id:string|number,raw:unknown){
  const cancel=()=>this.send({id,result:{outcome:{outcome:'cancelled'}}});
  if(this.active||!obj(raw)||raw.sessionId!==this.session||!obj(raw.toolCall)||!Array.isArray(raw.options)||raw.options.length>8||!this.io.permission){cancel();return;}
  const options:PermissionPrompt['options']=[];const ids=new Set<string>();
  for(const o of raw.options){if(!obj(o)||typeof o.optionId!=='string'||o.optionId.length>128||ids.has(o.optionId)||typeof o.name!=='string'||o.name.length>128){cancel();return;}ids.add(o.optionId);if(o.kind==='allow_once'||o.kind==='reject_once')options.push({optionId:o.optionId,name:terminalText(o.name),kind:o.kind});}
  if(!options.length){cancel();return;}
  const abort=new AbortController();this.permissionAbort=abort;
  let timer:ReturnType<typeof setTimeout>|undefined;this.active=true;
  try{
   const title=typeof raw.toolCall.title==='string'?raw.toolCall.title.slice(0,700):'Tool permission';
   const input=JSON.stringify(raw.toolCall.rawInput??{});if(input.length>16384){cancel();return;}
   const selected=await Promise.race([this.io.permission({title:terminalText(title),input:terminalText(input),options},abort.signal),new Promise<null>(r=>{abort.signal.addEventListener('abort',()=>r(null),{once:true});timer=setTimeout(()=>abort.abort(),60000);timer.unref();})]);
   if(this.closed)return;const choice=options.find(o=>o.optionId===selected);
   if(!choice){cancel();return;}this.send({id,result:{outcome:{outcome:'selected',optionId:choice.optionId}}});
  }catch{cancel();}finally{if(timer)clearTimeout(timer);this.active=false;}
 }
 close(){if(this.closed)return;this.closed=true;this.permissionAbort?.abort();for(const w of this.waiters.values()){clearTimeout(w.timer);w.reject();}this.waiters.clear();}
}
