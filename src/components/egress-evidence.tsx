import { egressText } from "@/lib/monitor/egress-evidence";
import type { AuditEvent } from "@/lib/monitor/types";
import { useT } from "@/lib/monitor/store";

export function EgressEvidenceDetails({ event }: { event: AuditEvent }) {
  const tx = useT();
  if (!event.egress) return null;
  return (
    <div role="note" className="space-y-1 text-xs text-muted border-t border-line/60 pt-2 mt-2 break-words">
      <p className="font-mono text-fg/90">{egressText(event.egress)}</p>
      <p className="text-[11px] text-subtle leading-relaxed">
        {tx("egressObservationNotice")}
      </p>
    </div>
  );
}
