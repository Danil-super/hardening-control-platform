import { ArrowRight, CheckCircle2, MonitorPlay, ServerCog } from "lucide-react";
import { DemoHostCard } from "@/components/dashboard/demo-host-card";
import { LinkButton } from "@/components/ui/button";

const demoSteps = [
  {
    title: "Открыть профили аудита",
    text: "Перейдите в раздел “Профили” и выберите сценарий проверки: базовый Linux, SSH, веб-сервер или Docker-хост.",
  },
  {
    title: "Запустить демо-аудит",
    text: "На странице профиля нажмите “Запустить аудит”. Платформа покажет этапы проверки и сформирует findings из mock-движка.",
  },
  {
    title: "Изучить результаты",
    text: "На странице результатов посмотрите оценку защищенности, количество рисков и таблицу найденных проблем.",
  },
  {
    title: "Выбрать исправления",
    text: "В планировщике исправлений отметьте действия. Для каждого действия видны риск, затрагиваемые файлы, backup и rollback.",
  },
  {
    title: "Применить демо-сценарий",
    text: "Нажмите “Применить демо”. Сайт имитирует создание резервной копии, применение исправлений, проверку и повторный аудит.",
  },
  {
    title: "Открыть отчет",
    text: "В разделе “Отчеты” сравните состояние до/после, список исправленных проблем, оставшиеся риски и JSON-экспорт.",
  },
];

const realAgentSteps = [
  "Web Platform отправляет профиль аудита локальному Linux Agent.",
  "Agent определяет ОС через /etc/os-release и выполняет реальные проверки.",
  "Agent возвращает findings в JSON-формате.",
  "Пользователь выбирает remediation в веб-интерфейсе.",
  "Agent создает backup, применяет исправления и выполняет validation.",
  "Платформа формирует отчет “до/после” по реальным данным.",
];

export default function GuidePage() {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">Инструкция и сценарий демонстрации</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            Эта страница объясняет, как показывать MVP на защите и почему аудит сейчас работает через демонстрационный
            источник данных, а не через реальный Linux-сервер.
          </p>
        </div>
        <LinkButton href="/profiles">Начать демонстрацию</LinkButton>
      </div>

      <DemoHostCard />

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <MonitorPlay className="text-sky-200" size={24} aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Как показать работу сайта</h2>
          </div>

          <div className="mt-5 space-y-3">
            {demoSteps.map((step, index) => (
              <article key={step.title} className="rounded-md border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-start gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-sky-400 text-sm font-bold text-slate-950">
                    {index + 1}
                  </span>
                  <div>
                    <h3 className="font-semibold text-white">{step.title}</h3>
                    <p className="mt-1 text-sm leading-6 text-slate-400">{step.text}</p>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>

        <aside className="h-fit rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Что сказать на защите</h2>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            “Первая версия платформы работает в безопасном демо-режиме. Она показывает полный цикл управления
            харденингом: выбор профиля, аудит, найденные проблемы, план исправлений, имитацию backup, повторный аудит
            и отчет. Реальное изменение Linux-хоста вынесено в будущий локальный Agent.”
          </p>
          <div className="mt-5 rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
            Важно подчеркнуть: MVP не является заменой Lynis или OpenSCAP. Это управляющий слой и демонстрационный
            интерфейс, готовый к подключению агентского модуля.
          </div>
        </aside>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <div className="flex items-center gap-3">
          <ServerCog className="text-sky-200" size={24} aria-hidden="true" />
          <h2 className="text-xl font-semibold text-white">Как это станет реальным аудитом</h2>
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {realAgentSteps.map((step, index) => (
            <div key={step} className="rounded-md border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center gap-2 text-emerald-200">
                <CheckCircle2 size={17} aria-hidden="true" />
                <span className="text-xs font-semibold uppercase">Этап {index + 1}</span>
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-300">{step}</p>
            </div>
          ))}
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-end gap-3">
        <LinkButton href="/agent" variant="secondary">Посмотреть будущий Agent</LinkButton>
        <LinkButton href="/profiles">
          Перейти к профилям
          <ArrowRight size={16} aria-hidden="true" />
        </LinkButton>
      </div>
    </div>
  );
}
