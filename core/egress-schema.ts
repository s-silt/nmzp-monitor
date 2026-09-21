export const LARGE_ARCHIVE_BYTES = 200 * 1024 * 1024;
export const GITHUB_AGENT_IDS=['zcode','codex','grok','claude','antigravity','cursor','copilot','windsurf','gemini','aider','qwen','cline','trae','kimi','qoder','lingma','codebuddy'] as const;
export interface GithubUploadPolicy {mode:'selected'|'unlimited';agents:string[]}
export function parseGithubPolicy(raw:unknown):GithubUploadPolicy|undefined {
 if(!raw||typeof raw!=='object')return;const r=raw as GithubUploadPolicy;
 if(!['selected','unlimited'].includes(r.mode)||!Array.isArray(r.agents)||r.agents.length>GITHUB_AGENT_IDS.length||new Set(r.agents).size!==r.agents.length||r.agents.some(a=>!GITHUB_AGENT_IDS.includes(a as typeof GITHUB_AGENT_IDS[number])))return;
 return {mode:r.mode,agents:[...r.agents]};
}
export function githubPolicy(raw:unknown):GithubUploadPolicy{return parseGithubPolicy(raw)??{mode:'selected',agents:[...GITHUB_AGENT_IDS]};}
export interface ArchiveUploadPolicy {thresholdMiB:number;action:'warn'|'block'}
export const DEFAULT_ARCHIVE_POLICY:ArchiveUploadPolicy={thresholdMiB:200,action:'warn'};
export function parseArchivePolicy(raw:unknown):ArchiveUploadPolicy|undefined {
 if(!raw||typeof raw!=='object')return;const r=raw as ArchiveUploadPolicy;
 if(!Number.isSafeInteger(r.thresholdMiB)||r.thresholdMiB<1||r.thresholdMiB>1048576||!['warn','block'].includes(r.action))return;
 return {thresholdMiB:r.thresholdMiB,action:r.action};
}
export function archivePolicy(raw:unknown):ArchiveUploadPolicy{return parseArchivePolicy(raw)??{...DEFAULT_ARCHIVE_POLICY};}
export interface UploadSizeEvidence {
 status:'observed'|'unknown';
 bytes?:number;
 checkedAt:number;
 source:'local_hook_stat';
 reason:'explicit_archive'|'unresolved_source';
}
export interface EgressEvidence {
 /** Present for observation-only releases; absent on historical events. */
 observationOnly?:true;
 operation:'git_push'|'upload'|'local_archive'|'storage_access';
 interaction:'host_prompt_available'|'noninteractive_reported'|'background_reported'|'unknown';
 authorization:'risk_blocked'|'not_required'|'policy_inactive'|'not_observed';
 basis:'storage_endpoint'|'correlation'|'local_only'|'existing_policy'|'large_archive'|'github_agent';
 uploadSize?:UploadSizeEvidence;
 archivePolicy?:ArchiveUploadPolicy;
 github?:'unlimited'|'agent_allowed'|'agent_denied'|'target_unknown';
}
export function parseUploadSize(raw:unknown, now=Date.now()):UploadSizeEvidence|undefined {
 if(!raw||typeof raw!=='object')return;const r=raw as UploadSizeEvidence;
 if(r.source!=='local_hook_stat'||!Number.isSafeInteger(r.checkedAt)||r.checkedAt<0||r.checkedAt>now+30000)return;
 if(r.status==='observed'&&r.reason==='explicit_archive'&&Number.isSafeInteger(r.bytes)&&r.bytes!>=0)return {status:r.status,bytes:r.bytes,checkedAt:r.checkedAt,source:r.source,reason:r.reason};
 if(r.status==='unknown'&&r.reason==='unresolved_source')return {status:r.status,checkedAt:r.checkedAt,source:r.source,reason:r.reason};
}
export function parseEgressEvidence(raw:unknown):EgressEvidence|undefined {
 if(!raw||typeof raw!=='object')return;const r=raw as EgressEvidence;
 if(!['git_push','upload','local_archive','storage_access'].includes(r.operation)||!['host_prompt_available','noninteractive_reported','background_reported','unknown'].includes(r.interaction)||!['risk_blocked','not_required','policy_inactive','not_observed'].includes(r.authorization)||!['storage_endpoint','correlation','local_only','existing_policy','large_archive','github_agent'].includes(r.basis))return;
 const uploadSize=parseUploadSize(r.uploadSize);
 const policy=parseArchivePolicy(r.archivePolicy);
 const github=r.github&&['unlimited','agent_allowed','agent_denied','target_unknown'].includes(r.github)?r.github:undefined;
 return {...(r.observationOnly===true?{observationOnly:true as const}:{}),operation:r.operation,interaction:r.interaction,authorization:r.authorization,basis:r.basis,...(uploadSize?{uploadSize}:{}),...(policy?{archivePolicy:policy}:{}),...(github?{github}:{})};
}
export function permissionMode(raw:unknown):string|undefined{return typeof raw==='string'&&['default','plan','acceptEdits','auto','dontAsk','bypassPermissions'].includes(raw)?raw:undefined;}
/** Bounded command hints, not a shell parser or background network interceptor. */
export function egressOperation(command:string):EgressEvidence['operation']|undefined {
 if(/(?:^|[;&|])\s*git(?:\.exe)?\s+(?:(?:-C|-c|--git-dir|--work-tree)\s+\S+\s+)*push\b/i.test(command))return 'git_push';
 if(/\b(curl|wget)\b[^\r\n]*(?:--upload-file\b|\s-T(?:\s|\S)|--data(?:-binary|-raw|-ascii|-urlencode)?(?:\s+|=)['"]?@|\s-d\s*['"]?@|--form(?:\s+|=)\S+=@|\s-F\s*\S+=@|--post-file\b)|\b(?:rclone)\b|\baws\s+s3\s+(?:cp|sync)\b|\bgh\s+(?:release\s+upload|gist\s+create)\b|\b(?:Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]*-InFile\b/i.test(command))return 'upload';
 if(/^\s*(?:scp|rsync)\b[^\r\n]*\s+[^\s:]+:[^\s]+\s*$/i.test(command))return 'upload';
 if(/\b(?:tar|zip|7z|cpio)\b|\bgit\s+(?:archive|bundle)\b/i.test(command))return 'local_archive';
}
export function egressInteraction(agent:unknown,mode:unknown,source:unknown,blind:unknown):EgressEvidence['interaction'] {
 if(source==='probe'||blind===true)return 'background_reported';
 const m=permissionMode(mode);
 if(agent==='claude'&&source==='hook'&&['default','plan','acceptEdits'].includes(m??''))return 'host_prompt_available';
 if(['auto','dontAsk','bypassPermissions'].includes(m??''))return 'noninteractive_reported';
 return 'unknown';
}
