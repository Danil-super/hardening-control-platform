import { Database, LockKeyhole, Server, ShieldCheck } from "lucide-react";

const hostFacts = [
  {
    label: "Целевой сервер",
    value: "demo-ubuntu-24.04.local",
    icon: Server,
  },
  {
    label: "Источник аудита",
    value: "Демонстрационный движок",
    icon: Database,
  },
  {
    label: "Режим выполнения",
    value: "Демонстрационный аудит",
    icon: ShieldCheck,
  },
  {
    label: "Ограничение MVP",
    value: "Реальная ОС не изменяется",
    icon: LockKeyhole,
  },
];

export function DemoHostCard({ compact = false }: { compact?: boolean }) {
  return (
    <section className="rounded-md border border-sky-400/25 bg-slate-950/75 p-5 shadow-xl shadow-black/10">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase text-sky-200">Демо-хост / источник аудита</p>
          <h2 className="mt-2 text-xl font-semibold text-white">Как выполняется аудит в MVP</h2>
        </div>
        <span className="w-fit rounded-md border border-emerald-400/40 bg-emerald-500/15 px-2 py-1 text-xs font-semibold uppercase text-emerald-100">
          Безопасная имитация
        </span>
      </div>

      <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-300">
        Платформа показывает полный сценарий аудита и харденинга на демонстрационном Ubuntu/Debian-хосте.
        Проверки берутся из локального демонстрационного движка, поэтому сайт можно безопасно запускать на Vercel без
        root-доступа, системных команд и изменения реального сервера.
      </p>

      <div className={`mt-5 grid gap-3 ${compact ? "md:grid-cols-2" : "md:grid-cols-2 xl:grid-cols-4"}`}>
        {hostFacts.map((fact) => {
          const Icon = fact.icon;
          return (
            <div key={fact.label} className="rounded-md border border-slate-800 bg-slate-900/80 p-4">
              <div className="flex items-center gap-2 text-sky-200">
                <Icon size={17} aria-hidden="true" />
                <span className="text-xs font-semibold uppercase">{fact.label}</span>
              </div>
              <p className="mt-3 text-sm font-semibold text-white">{fact.value}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}
