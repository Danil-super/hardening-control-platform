import { DatabaseBackup, FileCheck, ListChecks, Radar, ShieldCheck, Wrench } from "lucide-react";

const steps = [
  { label: "Аудит", detail: "Запуск демо-проверок или импорт отчета агента", icon: Radar },
  { label: "Находки", detail: "Риски, статусы, источники и рекомендации", icon: ListChecks },
  { label: "План", detail: "Выбор действий без автоматического изменения ОС", icon: Wrench },
  { label: "Бэкапы", detail: "Именованные записи для файлов и действий", icon: DatabaseBackup },
  { label: "Повтор", detail: "Сравнение оценки после выбранного плана", icon: ShieldCheck },
  { label: "Отчет", detail: "JSON/HTML для демонстрации и защиты", icon: FileCheck },
];

export function ProcessStrip() {
  return (
    <div className="grid gap-3 rounded-md border border-slate-800 bg-slate-950/70 p-3 md:grid-cols-2 xl:grid-cols-3">
      {steps.map((step, index) => {
        const Icon = step.icon;
        return (
          <div key={step.label} className="rounded-md border border-slate-800 bg-slate-900/80 p-4">
            <div className="flex items-center gap-3">
              <span className="flex h-8 w-8 items-center justify-center rounded-md bg-sky-400 text-sm font-semibold text-slate-950">
                {index + 1}
              </span>
              <Icon size={18} className="text-sky-200" aria-hidden="true" />
              <p className="font-semibold text-white">{step.label}</p>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-400">{step.detail}</p>
          </div>
        );
      })}
    </div>
  );
}
