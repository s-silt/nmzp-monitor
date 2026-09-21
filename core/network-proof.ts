import {confirmedAgentRoot,identityKey,type IdentifiedProc} from './network-collect.ts';
import {isEgressTcp} from './network-evidence.ts';
import type {NetworkSampleReport} from './schema.ts';
export interface ProofSocket {pid:number;localIp:string;localPort:number;remoteIp:string;remotePort:number;state:string}
const key=(r:ProofSocket)=>[r.pid,r.localIp,r.localPort,r.remoteIp,r.remotePort,r.state.toLowerCase()].join('|');
/** A passive positive control is valid only across the collector's whole sampling interval. */
export function assessNetworkProof(sample:NetworkSampleReport,before:IdentifiedProc[],after:IdentifiedProc[],beforeSockets:ProofSocket[],afterSockets:ProofSocket[]):{status:'verified'|'failed'|'not_verified';reason:string;matched:number}{
 const stable=new Map(before.filter(p=>confirmedAgentRoot(p)==='grok'&&after.some(a=>identityKey(a)===identityKey(p))).map(p=>[p.pid,p]));
 const end=new Set(afterSockets.map(key));
 const control=beforeSockets.filter(s=>stable.has(s.pid)&&isEgressTcp(s.state,s.remoteIp,s.remotePort)&&end.has(key(s)));
 if(!control.length)return {status:'not_verified',reason:'no_stable_trusted_socket_control',matched:0};
 if(sample.status!=='ok')return {status:'failed',reason:'collector_'+sample.status,matched:0};
 const matched=control.filter(c=>sample.connections.some(s=>s.pid===c.pid&&s.agent==='grok'&&s.processStartedAt===stable.get(c.pid)!.startedAt&&key(s)===key(c))).length;
 return {status:matched?'verified':'failed',reason:matched?'same_identity_and_tuple':'positive_control_tuple_missing',matched};
}
