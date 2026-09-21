import {join,resolve} from 'node:path';import {homedir} from 'node:os';import {lstat,writeFile,rename} from 'node:fs/promises';import {refreshDiscovery} from './agent-discovery.ts';
// Explicit unprivileged collector. No service keys, token loading or core requests.
const file=process.argv[2];if(process.platform!=='win32'||!file||process.argv.length!==3)throw Error('usage: probe-user-main.ts <installer-mailbox-directory>');
const dir=resolve(file);if(!(await lstat(dir)).isDirectory()||(await lstat(dir)).isSymbolicLink())throw Error('invalid_mailbox_directory');
for(;;){
 const snapshot=await refreshDiscovery(process.env.NMZP_HOME||homedir());
 const temp=join(dir,`discovery.${process.pid}.tmp`);await writeFile(temp,JSON.stringify(snapshot),{flag:'wx'});
 await rename(temp,join(dir,'discovery.json'));await new Promise(r=>setTimeout(r,60000));
}
