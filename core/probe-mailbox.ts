import {openSync,closeSync,fstatSync,readSync,lstatSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {parseDiscovery,DISCOVERY_SOURCES,type DiscoverySnapshot} from './agent-discovery-schema.ts';
export const MAILBOX_LIMIT=524288;
export function mailboxFailure(status:'error'|'timeout'|'permission'='error'):DiscoverySnapshot {const now=Date.now();return {schemaVersion:1,platform:'win32',checkedAt:now,completedAt:now,status,sources:DISCOVERY_SOURCES.map(id=>({id,status})),items:[]};}
/** Runs in a disposable, deadline-limited child; never consumes arbitrary commands or protection claims. */
export function readMailbox(file:string):DiscoverySnapshot {
 let fd:number|undefined;
 try {
  for(let p=resolve(file);;p=dirname(p)){if(lstatSync(p).isSymbolicLink())return mailboxFailure();if(p===dirname(p))break;}
  fd=openSync(file,'r');const st=fstatSync(fd);if(!st.isFile()||st.size>MAILBOX_LIMIT)return mailboxFailure();
  const buf=Buffer.alloc(MAILBOX_LIMIT+1);let total=0,n=0;
  while(total<buf.length&&(n=readSync(fd,buf,total,buf.length-total,null))>0)total+=n;
  if(total>MAILBOX_LIMIT)return mailboxFailure();
  const s=parseDiscovery(JSON.parse(buf.subarray(0,total).toString('utf8')));if(!s)return mailboxFailure();
  // Signatures authenticate the service, not the user-writable collector's assertions.
  return {...s,receivedAt:undefined,items:s.items.map(i=>({...i,identity:'candidate',reasons:[...new Set([...i.reasons,'instance_not_bound' as const])]}))};
 }catch(e){return mailboxFailure((e as NodeJS.ErrnoException).code==='EACCES'?'permission':'error');}finally{if(fd!==undefined)closeSync(fd);}
}
