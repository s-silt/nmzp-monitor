export interface ProbeProtection { mode:'legacy'|'signature_required'|'revoked'; identity:'unverified'|'awaiting_signature'|'authenticated'|'stale'; lastAuthenticatedAt:number|null; isolation:'not_verified'; discoverySource:'user_metadata'|'legacy' }
export function parseProbeProtection(raw:unknown,now=Date.now()):ProbeProtection|undefined {
 if(!raw||typeof raw!=='object')return undefined;const r=raw as ProbeProtection;
 if(!['legacy','signature_required','revoked'].includes(r.mode)||!['unverified','awaiting_signature','authenticated','stale'].includes(r.identity)||r.isolation!=='not_verified'||!['user_metadata','legacy'].includes(r.discoverySource)||(r.lastAuthenticatedAt!==null&&(!Number.isSafeInteger(r.lastAuthenticatedAt)||r.lastAuthenticatedAt<=0||r.lastAuthenticatedAt>now+30000)))return undefined;
 return {mode:r.mode,identity:r.mode!=='signature_required'?'unverified':r.lastAuthenticatedAt===null?'awaiting_signature':now-r.lastAuthenticatedAt>90000?'stale':'authenticated',lastAuthenticatedAt:r.lastAuthenticatedAt,isolation:'not_verified',discoverySource:r.discoverySource};
}
export function probeProtectionText(raw:unknown,lang:string,now=Date.now()):string {
 const p=parseProbeProtection(raw,now),zh=lang==='zh';
 if(!p||p.mode==='legacy')return zh?'探针：用户态凭据，未验证独立身份':'Probe: user credentials; independent identity unverified';
 if(p.mode==='revoked')return zh?'探针：服务身份已撤销':'Probe: service identity revoked';
 const status=p.identity==='authenticated'?(zh?'近期签名已验证':'recent signature verified'):p.identity==='stale'?(zh?'签名证据已过期':'signature evidence stale'):(zh?'等待签名心跳':'awaiting signed heartbeat');
 return zh?`探针：${status}；本机隔离待原机验收；发现来自用户元数据`:`Probe: ${status}; OS isolation awaits acceptance; discovery is user metadata`;
}
