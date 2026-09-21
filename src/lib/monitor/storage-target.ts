/** Official endpoint shapes checked 2026-09-20. No DNS lookup or payload inspection. */
export function storageProvider(value:string):'oss'|'cos'|undefined {
 let h:string;try{const u=new URL(value.includes('://')?value:`https://${value}`);if(!['http:','https:'].includes(u.protocol))return;h=u.hostname.toLowerCase().replace(/\.$/,'');}catch{return;}
 if(h.length>253||!h.split('.').every(s=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s)))return;
 if(/(?:^|\.)oss-[a-z0-9]+(?:-[a-z0-9]+)*\.aliyuncs\.com$/.test(h)||/(?:^|\.)[a-z0-9]+(?:-[a-z0-9]+)*\.oss\.aliyuncs\.com$/.test(h))return 'oss';
 if(/(?:^|\.)cos\.(?:[a-z0-9]+(?:-[a-z0-9]+)*)\.myqcloud\.com$/.test(h)||/(?:^|\.)cos-internal\.accelerate\.tencentcos\.cn$/.test(h))return 'cos';
}
/** Endpoint restriction, not an assertion that any request is an upload. */
export function storageTarget(input:{tool:string;command?:string;url?:string;dest?:string}):'oss'|'cos'|undefined {
 if(!['Bash','WebFetch','MCP'].includes(input.tool))return;
 for(const value of [input.url,input.dest]){if(value){const p=storageProvider(value);if(p)return p;}}
 const c=input.command??'';
 if(input.tool==='Bash'&&!/\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|ossutil|coscli|coscmd|requests\.(?:get|post|put)|https?\.request|fetch)\b/i.test(c))return;
 for(const url of c.match(/https?:\/\/[^\s'"<>]+/gi)??[]){const p=storageProvider(url);if(p)return p;}
}
