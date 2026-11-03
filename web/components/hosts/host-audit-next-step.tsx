"use client";

import { ArrowRight, CircleAlert, ClipboardCheck, Server, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { HostSourceGuidance } from "@/components/hosts/host-source-guidance";
import { selectHostAuditNextStep } from "@/lib/host-audit-workflow";
import type { DashboardHostEvidence } from "@/lib/dashboard-evidence-status";

type Host = { alias: string; riskSummary?: DashboardHostEvidence["riskSummary"] };

export function HostAuditNextStep({
  hosts, host, onSelectHost, controlReady, activeJob, recoveryRequired,
}: {
  hosts: Host[];
  host: Host | null;
  onSelectHost: (alias: string) => void;
  controlReady: boolean;
  activeJob: boolean;
  recoveryRequired: boolean;
}) {
  const next = selectHostAuditNextStep({
    alias: host?.alias ?? null,
    riskSummary: host?.riskSummary,
    controlReady, activeJob, recoveryRequired,
  });
  const tone = next.tone === "critical" ? "border-red-400/35 bg-red-500/10"
    : next.tone === "attention" ? "border-amber-400/25 bg-amber-500/5"
      : "border-sky-400/20 bg-sky-400/5";
  return (
    <section id="host-audit-flow" aria-labelledby="host-audit-flow-title" className={`scroll-mt-6 rounded-xl border p-4 sm:p-5 ${tone}`}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-sky-200">Маршрут проверки</p>
          <h2 id="host-audit-flow-title" className="mt-1 text-xl font-semibold text-white">Следующее действие</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Подсказки основаны на сохранённых результатах выбранного хоста. Они не запускают проверки и не разрешают изменять настройки.
          </p>
        </div>
        {hosts.length > 0 ? (
          <label className="block min-w-0 w-full sm:w-72">
            <span className="text-xs font-semibold text-slate-300">Выбранный хост</span>
            <Select value={host?.alias ?? ""} onValueChange={onSelectHost} aria-label="Выберите хост для маршрута проверки"
              className="mt-2 h-10 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100">
              {hosts.map(item => <option key={item.alias} value={item.alias}>{item.alias}</option>)}
            </Select>
          </label>
        ) : null}
      </div>
      <div className="mt-4 flex flex-col gap-3 rounded-lg border border-slate-700/70 bg-slate-950/60 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {next.tone === "critical" ? <CircleAlert size={18} className="shrink-0 text-red-300" aria-hidden="true" />
              : next.tone === "attention" ? <CircleAlert size={18} className="shrink-0 text-amber-200" aria-hidden="true" />
                : <ClipboardCheck size={18} className="shrink-0 text-sky-200" aria-hidden="true" />}
            <h3 className="font-semibold text-slate-100">{next.title}</h3>
          </div>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">{next.detail}</p>
        </div>
        {next.href ? <LinkButton href={next.href} variant={next.tone === "critical" ? "danger" : "secondary"}
          className="self-start sm:self-center whitespace-nowrap">
          {next.action}<ArrowRight size={16} aria-hidden="true" />
        </LinkButton> : null}
      </div>
      <HostSourceGuidance alias={host?.alias ?? null} />
      <div className="mt-3 grid gap-2 text-xs leading-5 text-slate-400 md:grid-cols-3">
        <div className="flex gap-2 rounded-lg border border-slate-800/80 p-3">
          <Server size={17} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div><p className="font-semibold text-slate-200">1. Подключение</p><p>Проверка SSH, учётной записи и необходимых инструментов.</p></div>
        </div>
        <div className="flex gap-2 rounded-lg border border-slate-800/80 p-3">
          <ShieldCheck size={17} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div><p className="font-semibold text-slate-200">2. Доказательства</p><p>Выбранный аудит, источник, полнота, свежесть и технические наблюдения.</p></div>
        </div>
        <div className="flex gap-2 rounded-lg border border-slate-800/80 p-3">
          <ClipboardCheck size={17} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div><p className="font-semibold text-slate-200">3. Решение и проверка</p><p>Разбор находок, согласование изменений, повторный аудит и отчёт.</p></div>
        </div>
      </div>
    </section>
  );
}
