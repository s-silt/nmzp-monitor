// Isolated synthetic mutation probes. Mutants never touch the checkout.
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root=await mkdtemp(join(tmpdir(),"nmzp-mutations-"));
const outcomes=[];
async function probe(name,sourcePath,oldText,newText,check){
  const dir=join(root,name);await (await import("node:fs/promises")).mkdir(dir);
  if(name==="policy-pointer")await writeFile(join(dir,"snapshot.ts"),await readFile("core/policy/snapshot.ts"));
  const original=await readFile(sourcePath,"utf8");
  assert.equal(original.split(oldText).length,2,`mutation target changed: ${name}`);
  const mutant=original.replace(oldText,newText);
  const path=join(dir,sourcePath.split(/[\\/]/).at(-1));
  await writeFile(path,mutant);
  let detected=false,reason="";
  try{const module=await import(pathToFileURL(path).href);await check(module,dir);}
  catch(error){
    if(error instanceof assert.AssertionError){detected=true;reason="target_assertion";}
    else throw error; // syntax, import or timeout are not detections
  }
  outcomes.push({name,source:sourcePath,oldText,newText,targetAssertion:check.toString(),detected,reason});
  assert.equal(detected,true,`mutation survived: ${name}`);
}
try{
  await probe("backfill-extra-fields","core/audit/backfill.ts",
    '!keys(raw,["kind","eventId","payload"])','false',
    (module)=>{
      const payload={eventId:"e",ts:1,agent:"grok",tool:"Read",decision:"allow",risk:"info",policyVersion:1};
      assert.equal(module.parseBackfill({kind:"event",eventId:"e",payload,tool_input:{secret:"DO_NOT_SEND"}}),null);
    });
  await probe("compression-without-benefit","core/audit/json-codec.ts",
    'compressed.length < rawBytes && rawBytes - compressed.length >= minSavings','true',
    async(module)=>{
      const encoded=await module.encodeJson({text:"x".repeat(5000)},{minSavingsBytes:1_000_000});
      assert.equal(encoded.codec,"json");
    });
  await probe("policy-pointer","core/policy/history.ts",
    'db.prepare("UPDATE policy_current SET version=? WHERE singleton=1").run(next.policy.version);',
    '/* mutant omits current pointer update */',
    (module,dir)=>{
      const snapshotModulePromise=import(pathToFileURL(join(dir,"snapshot.ts")).href);
      return snapshotModulePromise.then(({createPolicySnapshot})=>{
        const p=(version)=>createPolicySnapshot({version,updatedAt:version,mode:"enforcing"});
        const history=module.PolicyHistory.create(join(dir,"test.db"),p(1),"rules","engine");
        try{assert.equal(history.commit(p(2),p(1),"rules","engine"),"committed");
          assert.equal(history.current().policy.version,2);}finally{history.close();}
      });
    });
  process.stdout.write(JSON.stringify({isolationRoot:root,outcomes},null,2)+"\n");
}finally{await rm(root,{recursive:true,force:true});}
