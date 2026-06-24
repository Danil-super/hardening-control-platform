import { ArrowRight, CheckCircle2, KeyRound, ServerCog, ShieldCheck, Terminal } from "lucide-react";
import { LinkButton } from "@/components/ui/button";

const setupSteps = [
  "Запустите сайт на главном сервере: cd web && npm run dev:lan.",
  "Откройте /login и войдите с паролем из web/.env.local.",
  "На странице /hosts проверьте Ansible control node.",
  "Добавьте Linux-хост вручную или через автообнаружение локальной сети.",
  "Настройте SSH-ключи с главного сервера на целевой хост.",
  "Запустите Ansible ping, затем SSH-аудит Ansible.",
  "Откройте созданный JSON-отчет в разделе “Отчеты”.",
];

const rules = [
  {
    icon: ServerCog,
    title: "Один главный сервер",
    text: "Веб-интерфейс, Ansible, inventory, журнал и отчеты находятся на control node.",
  },
  {
    icon: KeyRound,
    title: "Подключение по SSH",
    text: "Хосты управляются через SSH-ключи. Постоянные агенты и фоновые сервисы на них не устанавливаются.",
  },
  {
    icon: ShieldCheck,
    title: "Базовый аудит",
    text: "SSH-аудит применяет локальные правила конфигурации: SSH, firewall, sudo, сервисы, обновления и опасные порты.",
  },
  {
    icon: Terminal,
    title: "Отчеты локально",
    text: "Результаты сохраняются на главном сервере в ansible/reports и открываются через веб-интерфейс.",
  },
];

export default function GuidePage() {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">Инструкция</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            Короткий рабочий сценарий для централизованного управления Linux-хостами через Ansible и SSH.
          </p>
        </div>
        <LinkButton href="/hosts">Открыть управление</LinkButton>
      </div>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Как начать</h2>
          <div className="mt-5 space-y-3">
            {setupSteps.map((step, index) => (
              <article key={step} className="rounded-md border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-start gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-sky-400 text-sm font-bold text-slate-950">
                    {index + 1}
                  </span>
                  <p className="text-sm leading-6 text-slate-300">{step}</p>
                </div>
              </article>
            ))}
          </div>
        </div>

        <aside className="h-fit rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Команды на главном сервере</h2>
          <div className="mt-4 space-y-3">
            <code className="block rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
              ssh-keygen -t ed25519 -C hcp-control
            </code>
            <code className="block rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
              ssh-copy-id user@192.168.1.10
            </code>
            <code className="block rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
              ansible all -i ansible/inventory.ini -m ping
            </code>
          </div>
        </aside>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Правила работы платформы</h2>
        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {rules.map((rule) => {
            const Icon = rule.icon;
            return (
              <div key={rule.title} className="rounded-md border border-slate-800 bg-slate-900/70 p-4">
                <Icon size={20} className="text-sky-200" aria-hidden="true" />
                <h3 className="mt-3 font-semibold text-white">{rule.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">{rule.text}</p>
              </div>
            );
          })}
        </div>
      </section>

      <section className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-5">
        <div className="flex items-start gap-3">
          <CheckCircle2 size={22} className="mt-0.5 text-emerald-200" aria-hidden="true" />
          <div>
            <h2 className="text-lg font-semibold text-white">Коротко</h2>
            <p className="mt-2 text-sm leading-6 text-emerald-100">
              Веб-интерфейс не является агентом. Он управляет Ansible на главном сервере, а Ansible подключается к
              Linux-хостам по SSH и сохраняет отчеты локально.
            </p>
          </div>
        </div>
      </section>

      <div className="flex justify-end">
        <LinkButton href="/hosts">
          Перейти к хостам
          <ArrowRight size={16} aria-hidden="true" />
        </LinkButton>
      </div>
    </div>
  );
}
