import {readdir,readFile,writeFile,mkdir,copyFile,lstat} from 'node:fs/promises';import {resolve,join,relative} from 'node:path';import {createHash} from 'node:crypto';
// Explicit builder: takes an already reviewed ordinary .pack/nmzp release and a native build.
const [runtime,node,host,out]=process.argv.slice(2);if(!out)throw Error('usage: package.mjs <.pack/nmzp> <reviewed-node.exe> <ProbeService.exe> <new-output-directory>');
const dest=resolve(out);await mkdir(dest);await mkdir(join(dest,'runtime'));
const files=[];
async function copy(src,target,rel){if(!(await lstat(src)).isFile())throw Error('not_regular_file');await copyFile(src,target,1);const buf=await readFile(target);files.push([createHash('sha256').update(buf).digest('hex'),rel]);}
async function walk(src,dst){for(const ent of await readdir(src,{withFileTypes:true})){if(ent.isSymbolicLink())throw Error('package_link');if(ent.name==='ui')continue;const p=join(src,ent.name),target=join(dst,ent.name);if(ent.isDirectory()){await mkdir(target);await walk(p,target);}else await copy(p,target,relative(dest,target).replaceAll('\\','/'));}}
await walk(resolve(runtime),join(dest,'runtime'));await copy(resolve(node),join(dest,'node.exe'),'node.exe');await copy(resolve(host),join(dest,'ProbeService.exe'),'ProbeService.exe');
files.sort((a,b)=>a[1].localeCompare(b[1]));const manifest=files.map(([hash,path])=>`${hash}\t${path}\n`).join('');await writeFile(join(dest,'manifest.tsv'),manifest,{flag:'wx'});
process.stdout.write(JSON.stringify({directory:dest,manifestSha256:createHash('sha256').update(manifest).digest('hex'),files:files.length})+'\n');
