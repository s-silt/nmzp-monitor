import { closeSync, fstatSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Cross-process lock held for the full callback; never remove a replacement lock. */
export async function withFileLock<T>(dir: string, fn: () => Promise<T>, opts?: { timeoutMs?: number }): Promise<T> {
  await mkdir(dir,{recursive:true});
  const lockPath=join(dir,".lock"),timeoutMs=opts?.timeoutMs??12_000,start=Date.now();
  while(true){
    let fd:number;
    try{fd=openSync(lockPath,"wx");}
    catch(error){
      if((error as NodeJS.ErrnoException).code!=="EEXIST")throw error;
      if(Date.now()-start>timeoutMs)throw new Error("lock_timeout");
      await new Promise((resolve)=>setTimeout(resolve,15+Math.random()*40));
      continue;
    }
    try{
      writeSync(fd,Buffer.from(String(process.pid)));
      return await fn();
    }finally{
      try{
        const held=fstatSync(fd),named=lstatSync(lockPath);
        if(named.isFile()&&!named.isSymbolicLink()&&held.dev===named.dev&&held.ino===named.ino)unlinkSync(lockPath);
      }catch{/* Never unlink a replacement lock. */}
      closeSync(fd);
    }
  }
}
