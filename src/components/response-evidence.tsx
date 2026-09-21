import {useMonitor} from '@/lib/monitor/store';
import type {ResponseEvidence} from '@/lib/monitor/response-evidence';
export function ResponseEvidenceDetails({evidence}:{evidence:ResponseEvidence}){
 const zh=useMonitor(s=>s.locale)==='zh';
 const coverage={complete:'完整',malformed:'格式异常',truncated:'检测达到大小上限',interrupted:'响应中断',unsupported:'协议未覆盖'};
 const outcome={complete:'本地写入完成',cancelled:'客户端取消',timeout:'超时',upstream_error:'上游异常断开',gateway_closed:'网关关闭',output_limit:'转发大小超限',unknown:'未知'};
 const yes=(v:boolean)=>zh?(v?'是':'否'):(v?'yes':'no');
 return <div className="space-y-1 break-words text-xs" data-testid="response-evidence">
  <p>{zh?'仅告警；来源主机不代表恶意归属。':'Alert only; upstream host is not attribution.'}</p>
  <p>{zh?'观察覆盖':'Observation coverage'}: {zh?coverage[evidence.coverage]:evidence.coverage}</p>
  <p>{zh?'上游读取完整':'Upstream fully read'}: {yes(evidence.transport.upstreamComplete)} · {zh?'客户端连接写入完成':'Client socket write finished'}: {yes(evidence.transport.clientWriteComplete)}</p>
  <p>{zh?'传输结果':'Transport outcome'}: {zh?outcome[evidence.transport.outcome]:evidence.transport.outcome}</p>
  <p>{zh?'写入完成不证明客户端应用已读取。':'A finished write does not prove the client application read it.'}</p>
  <p>{zh?'观察事件已入库；规则版本':'Observation recorded; rule version'}: {evidence.ruleVersion}</p>
  <ul>{evidence.findings.map((f,i)=><li key={i}>{zh?(f.category==='suspected_instruction_hijack'?'疑似指令劫持':'疑似秘密上传'):f.category} · {f.source} · {zh?'位置':'position'} {f.position}</li>)}</ul>
 </div>;
}
