import {generateKeyPairSync,createPublicKey} from 'node:crypto';import {readFile,writeFile} from 'node:fs/promises';import {join} from 'node:path';import {newProbeBinding} from './probe-auth.ts';import {loadCreds} from './hook.ts';import {pinnedHttps} from './https-client.ts';
const [action,home]=process.argv.slice(2);if(!home||!['init','enroll','revoke'].includes(action))throw Error('service_setup_arguments');
if(action==='init'){
 const keys=generateKeyPairSync('ed25519');const pub=keys.publicKey.export({format:'der',type:'spki'}).toString('base64');
 await writeFile(join(home,'probe-private.pem'),keys.privateKey.export({format:'pem',type:'pkcs8'}),{flag:'wx',mode:0o600});
 const creds=await loadCreds(home);if(!creds)throw Error('service_credentials_missing');
 await writeFile(join(home,'enrollment.json'),JSON.stringify({deviceId:creds.deviceId,publicKey:pub,keyId:newProbeBinding(pub).keyId},null,2),{flag:'wx',mode:0o600});
 process.stdout.write('Service key created in private directory. CT enrollment remains explicit.\n');
}else{
 const creds=await loadCreds(home);if(!creds)throw Error('service_credentials_missing');
 let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>4096)throw Error('admin_token_limit');}
 const token=input.trim();if(!token||/[\r\n]/.test(token))throw Error('admin_token_required_on_stdin');
 const publicKey=createPublicKey(await readFile(join(home,'probe-private.pem'),'utf8')).export({format:'der',type:'spki'}).toString('base64');
 const r=await pinnedHttps({url:creds.url+'/api/v1/probe/binding',method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({deviceId:creds.deviceId,action,publicKey}),caPem:creds.caPem,fingerprintSha256:creds.fingerprintSha256});
 if(r.status!==200)throw Error('probe_binding_request_rejected');process.stdout.write('Core binding updated. No OS isolation acceptance is implied.\n');
}
