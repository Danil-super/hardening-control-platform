import { Activity, FileText, Layers, Radar, ShieldAlert } from "lucide-react";
import { DemoHostCard } from "@/components/dashboard/demo-host-card";
import { ProcessStrip } from "@/components/dashboard/process-strip";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { auditProfiles } from "@/data/profiles";
import { demoFindings } from "@/data/findings";
import { remediations } from "@/data/remediations";

export default function Home() {
  return (
    <div className="space-y-8">
      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-6 shadow-xl shadow-black/20">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <span className="rounded-md border border-emerald-400/40 bg-emerald-500/15 px-2 py-1 text-xs font-semibold uppercase text-emerald-100">
                Демо-режим
              </span>
              <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300">
                без изменений реальной ОС
              </span>
            </div>
            <h1 className="mt-5 max-w-4xl text-4xl font-semibold tracking-normal text-white sm:text-5xl">
              Hardening Control Platform
            </h1>
            <p className="mt-4 max-w-3xl text-lg leading-8 text-slate-300">
              Платформа аудита и безопасного харденинга Linux-серверов: профиль, результаты проверок, план исправлений,
              резервные копии, повторный аудит и отчет “до/после”.
            </p>
          </div>
          <LinkButton href="/profiles">Выбрать профиль</LinkButton>
        </div>
      </section>

      <DemoHostCard />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Профили" value={auditProfiles.length} detail="Linux, SSH, веб, Docker" icon={<Layers size={20} />} />
        <SummaryCard label="Демо-проблемы" value={demoFindings.length} detail="Реалистичные риски Linux" icon={<Activity size={20} />} />
        <SummaryCard label="Исправления" value={remediations.length} detail="Резервные копии и откат описаны" icon={<ShieldAlert size={20} />} />
        <SummaryCard label="Отчеты" value="До/после" detail="Экспорт JSON готов" icon={<FileText size={20} />} />
      </div>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-white">Процесс</h2>
          <ProcessStrip />
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Radar className="text-sky-200" size={24} aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Будущий агент</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Архитектура подготовлена под локальный Python-агент для Ubuntu/Debian, Lynis/OpenSCAP, резервные копии,
            исправления и откат.
          </p>
          <LinkButton href="/agent" variant="secondary" className="mt-4 w-full">Открыть контракт</LinkButton>
        </div>
      </section>
    </div>
  );
}
