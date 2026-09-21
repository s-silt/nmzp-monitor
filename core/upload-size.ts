import {lstat} from 'node:fs/promises';
import {isAbsolute,resolve,parse,dirname} from 'node:path';
import {type UploadSizeEvidence,egressOperation} from './egress-schema.ts';
const ARCHIVE=/\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz|zst)(?:\.enc)?$/i;
/** Inspect only explicit, single-command local file operands. No expansion, execution or content reads. */
export function explicitUploadArchive(command:string):string|undefined {
 if(command.length>8192||/[\r\n;|&`$<>]/.test(command)||egressOperation(command)!=='upload')return;
 const tokens=command.match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+/g)?.map(s=>/^['"]/.test(s)?s.slice(1,-1):s);
 if(!tokens||!/^curl(?:\.exe)?$/i.test(tokens[0]))return;
 const files:string[]=[];
 for(let i=1;i<tokens.length;i++){
  const t=tokens[i];let v:string|undefined;
  if(['-T','--upload-file'].includes(t))v=tokens[++i];
  else if(['-d','--data','--data-binary','--data-raw','--data-ascii'].includes(t)){const next=tokens[++i];if(next?.startsWith('@'))v=next.slice(1);}
  else if(['-F','--form'].includes(t)){const next=tokens[++i];if(next&&/^[a-zA-Z0-9_-]+=@/.test(next))v=next.slice(next.indexOf('@')+1);}
  if(v)files.push(v);
 }
 if(files.length!==1||!ARCHIVE.test(files[0])||/[*?\[\]\x00-\x1f]/.test(files[0]))return;
 return files[0];
}
export async function observeUploadSize(command:string,cwd?:string):Promise<UploadSizeEvidence|undefined>{
 if(egressOperation(command)!=='upload')return;
 const unknown=():UploadSizeEvidence=>({status:'unknown',checkedAt:Date.now(),source:'local_hook_stat',reason:'unresolved_source'});
 const operand=explicitUploadArchive(command);if(!operand||!cwd||!isAbsolute(cwd)||/^[/\\]{2}/.test(operand)||/^[/\\]{2}/.test(cwd))return unknown();
 const path=resolve(cwd,operand);if(process.platform==='win32'&&(!/^[A-Za-z]:\\/.test(path)||path.slice(2).includes(':')))return unknown();
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{return await Promise.race([new Promise<UploadSizeEvidence>(r=>{timer=setTimeout(()=>r(unknown()),300);}), (async()=>{
   let current=path;for(let n=0;n<64;n++){const st=await lstat(current);if(st.isSymbolicLink())return unknown();if(current===path&&(!st.isFile()||!Number.isSafeInteger(st.size)))return unknown();if(current===parse(current).root)break;current=dirname(current);if(n===63)return unknown();}
   const stat=await lstat(path);return {status:'observed' as const,bytes:stat.size,checkedAt:Date.now(),source:'local_hook_stat' as const,reason:'explicit_archive' as const};
 })()]);}catch{return unknown();}finally{clearTimeout(timer);}
}
