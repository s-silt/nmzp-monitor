/** Portable public schema. No raw model text or arbitrary error strings are permitted. */
export interface ResponseEvidence {
 ruleVersion:'nmzp-response-1';
 coverage:'complete'|'malformed'|'truncated'|'interrupted'|'unsupported';
 action:'alert_only';
 observationRecorded:true;
 findings:Array<{category:'suspected_instruction_hijack'|'suspected_secret_upload';position:number;source:'text'|'tool'}>;
 transport:{upstreamComplete:boolean;clientWriteComplete:boolean;outcome:'complete'|'cancelled'|'timeout'|'upstream_error'|'gateway_closed'|'output_limit'|'unknown'};
}
export function parseResponseEvidence(raw:unknown):ResponseEvidence|undefined{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))return;
 const r=raw as Record<string,any>;
 if(r.ruleVersion!=='nmzp-response-1'||r.action!=='alert_only'||r.observationRecorded!==true||!['complete','malformed','truncated','interrupted','unsupported'].includes(r.coverage)||!Array.isArray(r.findings)||r.findings.length>16)return;
 const transport=r.transport;
 if(!transport||typeof transport!=='object'||typeof transport.upstreamComplete!=='boolean'||typeof transport.clientWriteComplete!=='boolean'||!['complete','cancelled','timeout','upstream_error','gateway_closed','output_limit','unknown'].includes(transport.outcome))return;
 if(transport.outcome==='complete'&&(!transport.upstreamComplete||!transport.clientWriteComplete))return;
 const findings:ResponseEvidence['findings']=[];
 for(const f of r.findings){
  if(!f||!['suspected_instruction_hijack','suspected_secret_upload'].includes(f.category)||!['text','tool'].includes(f.source)||!Number.isSafeInteger(f.position)||f.position<0||f.position>262144)return;
  findings.push({category:f.category,position:f.position,source:f.source});
 }
 return {ruleVersion:'nmzp-response-1',coverage:r.coverage,action:'alert_only',observationRecorded:true,findings,transport:{upstreamComplete:transport.upstreamComplete,clientWriteComplete:transport.clientWriteComplete,outcome:transport.outcome}};
}
