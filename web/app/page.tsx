import { Activity, FileInput, FileText, Layers, Radar, Server, ShieldAlert, Wrench } from "lucide-react";
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

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Server size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-lg font-semibold text-white">0. Подключить хосты сети</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            На главном компьютере настройте Ansible inventory, проверьте SSH и запускайте audit-only playbook'и.
          </p>
          <LinkButton href="/hosts" variant="secondary" className="mt-4 w-full">Открыть хосты</LinkButton>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Radar size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-lg font-semibold text-white">1. Быстро показать демо</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Запустите демо-аудит, посмотрите риски и сформируйте отчет “до/после” без системных команд.
          </p>
          <LinkButton href="/audit/basic_linux" variant="secondary" className="mt-4 w-full">Запустить демо-аудит</LinkButton>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <FileInput size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-lg font-semibold text-white">2. Проверить реальный хост</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Импортируйте JSON локального агента. Это audit-only режим: агент читает настройки и ничего не исправляет.
          </p>
          <LinkButton href="/agent/import" variant="secondary" className="mt-4 w-full">Импорт агента</LinkButton>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Wrench size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-lg font-semibold text-white">3. Спланировать изменения</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Выберите действия, проверьте риск, файлы, бэкапы и откат. Демо-кнопка формирует отчет, а не меняет ОС.
          </p>
          <LinkButton href="/remediation" variant="secondary" className="mt-4 w-full">Открыть план</LinkButton>
        </div>
      </section>

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
          <h2 className="mt-4 text-xl font-semibold text-white">Локальный Linux-агент</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Python-агент уже работает в audit-only режиме, поддерживает Lynis и OpenSCAP как внешние источники и
            импортирует результаты в сайт.
          </p>
          <LinkButton href="/agent" variant="secondary" className="mt-4 w-full">Открыть агента</LinkButton>
        </div>
      </section>
    </div>
  );
}
