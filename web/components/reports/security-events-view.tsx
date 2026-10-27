"use client";

import { useState } from "react";
import { ListChecks } from "lucide-react";
import { Button } from "@/components/ui/button";
import { groupSecurityEvents, type SecurityEvent } from "@/lib/security-events";

export function SecurityEventsView({ events }: { events: SecurityEvent[] }) {
  const [pages, setPages] = useState<Record<string, number>>({});
  const groups = groupSecurityEvents(events);
  return <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="security-events-title">
    <div className="flex items-center gap-3">
      <ListChecks size={22} className="text-sky-200" aria-hidden="true" />
      <h2 id="security-events-title" className="text-xl font-semibold text-white">События безопасности</h2>
    </div>
    <p className="mt-2 text-sm leading-6 text-slate-300">Собрано записей: {events.length}. Это выборка последних сообщений доступных журналов, а не полный журнал за период.</p>
    <div className="mt-5 space-y-6">
      {groups.map((group) => {
        const page = pages[group.source] ?? 0;
        const first = page * 5;
        return <section key={group.source} aria-label={group.title}>
          <h3 className="font-semibold text-sky-100">{group.title} · {group.events.length}</h3>
          <p className="mt-1 text-sm leading-6 text-slate-300">{group.description}</p>
          <ol start={first + 1} className="mt-3 space-y-3">
            {group.events.slice(first, first + 5).map((event, index) => <li key={`${group.source}-${first + index}`} className="rounded-md border border-slate-800 bg-slate-900/60 p-4 text-sm">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="font-semibold text-white">{event.title}</p>
                {event.time ? <p className="text-xs text-slate-400">Время в журнале: {event.time}</p> : null}
              </div>
              {event.fields.length ? <dl className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                {event.fields.map((field) => <div key={field.label} className="min-w-0"><dt className="text-xs text-slate-400">{field.label}</dt><dd className="mt-1 break-words text-slate-100">{field.value}</dd></div>)}
              </dl> : <p className="mt-2 text-slate-300">Подробности этого события находятся в исходной записи.</p>}
              <details className="mt-3">
                <summary className="cursor-pointer text-xs text-sky-200 focus-visible:outline-2 focus-visible:outline-sky-300">Исходная запись журнала</summary>
                <pre className="mt-2 whitespace-pre-wrap break-all rounded-md bg-slate-950 p-3 text-xs leading-5 text-slate-300">{event.raw || "Пустая запись"}</pre>
              </details>
            </li>)}
          </ol>
          {group.events.length > 5 ? <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button variant="secondary" disabled={page === 0} onClick={() => setPages((previous) => ({ ...previous, [group.source]: page - 1 }))} aria-label={`Предыдущие записи: ${group.title}`}>Назад</Button>
            <span className="text-sm text-slate-300" role="status">{first + 1}–{Math.min(first + 5, group.events.length)} из {group.events.length}</span>
            <Button variant="secondary" disabled={first + 5 >= group.events.length} onClick={() => setPages((previous) => ({ ...previous, [group.source]: page + 1 }))} aria-label={`Следующие записи: ${group.title}`}>Далее</Button>
          </div> : null}
        </section>;
      })}
    </div>
  </section>;
}
