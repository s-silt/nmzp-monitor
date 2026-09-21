import { createFileRoute } from "@tanstack/react-router";
import { EventRow } from "@/components/event-row";
import { useFilteredEvents, useT } from "@/lib/monitor/store";

export const Route = createFileRoute("/tap")({ component: TapPage });

export function TapPage() {
  const tx = useT();
  const events = useFilteredEvents();
  const rows = [...events].reverse().slice(0, 80);
  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-fg">{tx("navTap")}</h1>
        <p className="mt-1 text-sm text-muted">{tx("tapHint")}</p>
      </div>
      <section className="rounded-2xl bg-surface p-5 shadow-[var(--shadow-border)]">
        {rows.length === 0 ? (
          <p className="py-16 text-center text-sm text-muted">{tx("tapEmpty")}</p>
        ) : (
          <div>
            {rows.map((event) => (
              <EventRow key={event.id} event={event} dense />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
