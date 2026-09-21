import {createHash, createPublicKey, randomBytes, sign, verify} from 'node:crypto';
import type {IncomingHttpHeaders} from 'node:http';
import {pinnedHttps} from './https-client.ts';
import type {DeviceCreds} from './hook.ts';

export interface ProbeBinding { keyId:string; publicKey:string; registeredAt:number; revoked:boolean; lastAuthenticatedAt:number|null }
export interface ProbeProtection { mode:'legacy'|'signature_required'|'revoked'; identity:'unverified'|'awaiting_signature'|'authenticated'|'stale'; lastAuthenticatedAt:number|null; isolation:'not_verified'; discoverySource:'user_metadata'|'legacy' }
export function parseProbeBinding(raw:unknown):ProbeBinding|undefined {
  if(raw===undefined)return undefined;
  if(!raw||typeof raw!=='object')throw Error('invalid_probe_binding');
  const r=raw as ProbeBinding;
  if(typeof r.publicKey!=='string'||! /^[A-Za-z0-9+/]{58}[AEIMQUYcgkosw048]=$/.test(r.publicKey))throw Error('invalid_probe_binding');
  const der=Buffer.from(r.publicKey,'base64');
  const key=createPublicKey({key:der,format:'der',type:'spki'});
  if(key.asymmetricKeyType!=='ed25519'||der.toString('base64')!==r.publicKey||key.export({format:'der',type:'spki'}).toString('base64')!==r.publicKey)throw Error('invalid_probe_binding');
  const keyId=createHash('sha256').update(der).digest('hex');
  if(r.keyId!==keyId||!Number.isSafeInteger(r.registeredAt)||r.registeredAt<=0||typeof r.revoked!=='boolean'||(r.lastAuthenticatedAt!==null&&(!Number.isSafeInteger(r.lastAuthenticatedAt)||r.lastAuthenticatedAt<=0)))throw Error('invalid_probe_binding');
  return {keyId,publicKey:r.publicKey,registeredAt:r.registeredAt,revoked:r.revoked,lastAuthenticatedAt:r.lastAuthenticatedAt};
}
export function newProbeBinding(publicKey:string,now=Date.now()):ProbeBinding {
  return parseProbeBinding({publicKey,keyId:createHash('sha256').update(Buffer.from(publicKey,'base64')).digest('hex'),registeredAt:now,revoked:false,lastAuthenticatedAt:null})!;
}
export function publicProbeProtection(binding?:ProbeBinding,now=Date.now()):ProbeProtection {
  return {mode:binding?(binding.revoked?'revoked':'signature_required'):'legacy',identity:!binding||binding.revoked?'unverified':binding.lastAuthenticatedAt===null?'awaiting_signature':now-binding.lastAuthenticatedAt>90_000?'stale':'authenticated',lastAuthenticatedAt:binding?.lastAuthenticatedAt??null,isolation:'not_verified',discoverySource:binding?'user_metadata':'legacy'};
}
/** Compare inside the store queue, including legacy -> required races. */
export function checkProbeBinding(binding:ProbeBinding|undefined,expected:string|null):void {
  if(binding?.revoked||(binding?binding.keyId+':'+binding.registeredAt:null)!==expected)throw Error('probe_binding_changed');
}
export const PROBE_PATH='/api/v1/heartbeat';
export function proofMessage(deviceId:string,keyId:string,nonce:string,body:string):Buffer {
  return Buffer.from(JSON.stringify(['NMZP-PROBE-1',deviceId,keyId,nonce,'POST',PROBE_PATH,createHash('sha256').update(body,'utf8').digest('hex')]));
}
export class ProbeChallenges {
  private rows=new Map<string,{deviceId:string;keyId:string;registeredAt:number;expiresAt:number}>();
  issue(deviceId:string,binding:ProbeBinding,now=Date.now()) {
    for(const [nonce,row] of this.rows)if(row.expiresAt<=now)this.rows.delete(nonce);
    if(binding.revoked||this.rows.size>=1024||[...this.rows.values()].filter(x=>x.deviceId===deviceId).length>=4)return null;
    const nonce=randomBytes(32).toString('hex'),expiresAt=now+60_000;
    this.rows.set(nonce,{deviceId,keyId:binding.keyId,registeredAt:binding.registeredAt,expiresAt});return {nonce,keyId:binding.keyId,expiresAt};
  }
  consume(deviceId:string,binding:ProbeBinding,body:string,headers:IncomingHttpHeaders,now=Date.now()):boolean {
    const nonce=headers['x-nmzp-challenge'],signature=headers['x-nmzp-signature'];
    if(typeof nonce!=='string'||typeof signature!=='string'||! /^[a-f0-9]{64}$/.test(nonce))return false;
    const row=this.rows.get(nonce);
    // A different device cannot burn another device's challenge.
    if(!row||row.deviceId!==deviceId)return false;
    this.rows.delete(nonce);
    if(binding.revoked||row.keyId!==binding.keyId||row.registeredAt!==binding.registeredAt||row.expiresAt<=now||! /^[A-Za-z0-9+/]{86}==$/.test(signature))return false;
    try{return verify(null,proofMessage(deviceId,binding.keyId,nonce,body),createPublicKey({key:Buffer.from(binding.publicKey,'base64'),format:'der',type:'spki'}),Buffer.from(signature,'base64'));}catch{return false;}
  }
}
/** No retry with bearer-only auth. Pin validation happens before each body is sent. */
export async function protectedHeartbeat(creds:DeviceCreds,privateKey:string,keyId:string,body:string) {
  const pin={caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256};
  const auth={authorization:`Bearer ${creds.token}`};
  const response=await pinnedHttps({url:creds.url+'/api/v1/probe/challenge',method:'GET',headers:auth,...pin});
  if(response.status!==200)throw Error('probe_challenge_rejected');
  const c=JSON.parse(response.body);
  if(c.keyId!==keyId||typeof c.nonce!=='string'||! /^[a-f0-9]{64}$/.test(c.nonce))throw Error('probe_challenge_invalid');
  const signature=sign(null,proofMessage(creds.deviceId,keyId,c.nonce,body),privateKey).toString('base64');
  return pinnedHttps({url:creds.url+PROBE_PATH,method:'POST',body,headers:{...auth,'content-type':'application/json','x-nmzp-challenge':c.nonce,'x-nmzp-signature':signature},...pin});
}
