export {parseEgressEvidence} from '../../../core/egress-schema.ts';
export type {EgressEvidence} from '../../../core/egress-schema.ts';
export {archivePolicy,parseArchivePolicy,githubPolicy,GITHUB_AGENT_IDS} from '../../../core/egress-schema.ts';
export type {ArchiveUploadPolicy,GithubUploadPolicy} from '../../../core/egress-schema.ts';
import {type EgressEvidence} from '../../../core/egress-schema.ts';
export function archiveAlert(e:EgressEvidence):string|undefined {
 if(e.github==='unlimited'||e.uploadSize?.status!=='observed'||!e.archivePolicy||e.uploadSize.bytes!<=e.archivePolicy.thresholdMiB*1024*1024)return;
 if(e.observationOnly)return `压缩包超过 ${e.archivePolicy.thresholdMiB} MiB；观察模式，仅提醒，不拦截`;
 return `压缩包超过 ${e.archivePolicy.thresholdMiB} MiB；设置为${e.archivePolicy.action==='warn'?'提醒，不单独阻断':'拦截（需策略处于执行模式）'}`;
}
export function egressText(e:EgressEvidence):string {
 const interaction={host_prompt_available:'宿主报告可询问，未证明实际询问或批准',noninteractive_reported:'宿主报告无提示/自动模式',background_reported:'报告为后台操作',unknown:'交互状态未知'}[e.interaction];
 const auth={risk_blocked:'策略拒绝；返回拒绝不等于操作系统已阻断',not_required:'本地打包不等于上传',policy_inactive:'策略未执行拦截',not_observed:'没有观察到用户授权；本轮未新增通用上传阻断'}[e.authorization];
 const size=e.uploadSize?.status==='observed'?`压缩包 ${(e.uploadSize.bytes!/1024/1024).toFixed(1)} MiB；${archiveAlert(e)??'未超过当时阈值或阈值未知'}；大小来自 Hook 文件元数据报告，文件之后可能变化。`:e.operation==='upload'||e.operation==='storage_access'?'上传大小未知；不能据此判断低于阈值。':'';
 const observation=e.observationOnly?'观察模式：OSS/COS、工具名单和压缩包大小只记录提醒，不新增拦截。':'';
 const gh=e.github?{unlimited:'GitHub 无限制：跳过 Agent 名单和压缩包大小策略，独立安全规则保留。',agent_allowed:'GitHub Agent 在允许名单内，仍适用大小策略。',agent_denied:'GitHub Agent 不在允许名单。',target_unknown:'目的仓库无法从命令确认，不授予 GitHub 无限制例外；请使用显式目标。'}[e.github]:'';
 return `${observation}${interaction}；${auth}。${e.basis==='storage_endpoint'?'观察到 OSS/COS 存储端点访问；不证明发生上传。':''}${gh}${e.github==='unlimited'?'':size}`;
}
