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
    text: "На странице профиля нажмите “Запустить аудит”. Платформа покажет этапы проверки и сформирует результаты из демонстрационного движка.",
  },
  {
    title: "Изучить результаты",
    text: "На странице результатов посмотрите оценку защищенности, количество рисков и таблицу найденных проблем.",
  },
  {
    title: "Выбрать исправления",
    text: "В планировщике исправлений отметьте действия. Для каждого действия видны риск, затрагиваемые файлы, резервная копия и откат.",
  },
  {
    title: "Сформировать демо-отчет",
    text: "Нажмите “Сформировать демо-отчет”. Сайт имитирует резервные копии, проверку и повторный аудит без изменения ОС.",
  },
  {
    title: "Открыть отчет",
    text: "В разделе “Отчеты” сравните состояние до/после, список исправленных проблем, оставшиеся риски и JSON-экспорт.",
  },
];

const realAgentSteps = [
  "Запустить локальный bridge: python3 server.py в папке agent.",
  "Открыть /agent/import и выбрать профиль аудита.",
  "Нажать “Получить аудит от агента”; агент только читает настройки и возвращает JSON.",
  "При необходимости включить Lynis или OpenSCAP как внешние источники.",
  "Сохранить импорт в истории и сравнить два audit-only отчета.",
  "План исправлений скачать отдельно; реальные изменения ОС сейчас не выполняются.",
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
            “Платформа разделяет демонстрационный сценарий и реальный audit-only агент. На Vercel сайт безопасно
            показывает полный цикл харденинга, а локальный Python-агент уже умеет проверять Linux-хост без исправлений
            и импортировать JSON-отчет в интерфейс.”
          </p>
          <div className="mt-5 rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
            Важно подчеркнуть: MVP не является заменой Lynis или OpenSCAP. Это управляющий слой, который умеет принимать
            результаты локального агента и внешних сканеров.
          </div>
        </aside>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <div className="flex items-center gap-3">
          <ServerCog className="text-sky-200" size={24} aria-hidden="true" />
          <h2 className="text-xl font-semibold text-white">Как сделать реальный аудит без исправления</h2>
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
        <LinkButton href="/agent" variant="secondary">Посмотреть Linux-агент</LinkButton>
        <LinkButton href="/profiles">
          Перейти к профилям
          <ArrowRight size={16} aria-hidden="true" />
        </LinkButton>
      </div>
    </div>
  );
}
