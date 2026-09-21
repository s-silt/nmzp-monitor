import {useMonitor} from '@/lib/monitor/store';
export function EvidenceWindowNotice(){
 const window=useMonitor(s=>s.evidenceWindow);const zh=useMonitor(s=>s.locale)==='zh';
 return <aside className="rounded-lg border border-line p-3 text-xs text-muted" data-testid="evidence-window">
  {!window?<p>{zh?'审计保留窗口：未采集。':'Audit retention window: not collected.'}</p>:<>
   <p>{zh?'全服务审计窗口（非当前筛选统计）':'Server audit window (not current filter)'}: {window.retained}/{window.limit}</p>
   <p>{zh?'本次加载以来淘汰':'Dropped since load'}: {window.droppedSinceLoad} · {zh?'加载时损坏行':'Invalid lines on load'}: {window.invalidLinesOnLoad}</p>
   <p>{zh?'历史完整性未知；执行回执尽力发送，缺失不等于已拦截。':'History completeness unknown; receipts are best effort. Missing receipts do not prove blocking.'}</p>
   {window.networkMirrorState==='repair_required'&&<p className="text-warn">{zh?'网络持久化镜像待恢复；当前显示最后已提交快照。':'Network mirror needs recovery; showing last committed snapshot.'}</p>}
  </>}
 </aside>;
}
