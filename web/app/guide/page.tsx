import { ArrowRight, CheckCircle2, KeyRound, ServerCog, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";

const manualUrl = "https://github.com/Danil-super/hardening-control-platform/blob/main/docs/ubuntu-astra-setup.md";
const setupSteps = [
  "Выберите Astra в результатах сканирования или введите её адрес вручную.",
  "Введите логин и пароль администратора Astra прямо на сайте. Входить через терминал и создавать ключи вручную не нужно.",
  "При первом входе вставьте отпечаток из доверенной консоли этой Astra или реестра и нажмите «Сверить и сохранить». HCP сам сравнит его с ключом сервера по сети. Затем нажмите «Подключить хост».",
  "HCP сам войдёт по паролю, создаст отдельную пару на Ubuntu, установит публичный ключ на Astra, проверит доступ и сохранит хост.",
  "Дождитесь сообщения об успешном подключении. Выберите хост и профиль, затем запустите аудит.",
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
    title: "Версионированные профили",
    text: "Выбранный профиль загружается из локального YAML-набора правил: Linux, SSH, web-сервер или Docker-host.",
  },
  {
    icon: ShieldCheck,
    title: "Проверяемые изменения",
    text: "Изменения firewall сохраняют резервную копию, запускают повторный аудит и могут быть откачены из панели.",
  },
];

export default function GuidePage() {
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Начало работы</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Подключение и работа с хостами</h1>
          <p className="mt-2 max-w-3xl text-slate-400">На странице «Хосты» сначала идёт сканирование сети, затем форма подключения с одноразовым паролем и отдельным ключом. Все команды с местом выполнения и ожидаемым результатом собраны в основной инструкции.</p>
        </div>
        <LinkButton href="/hosts">Открыть управление</LinkButton>
      </div>

      <section id="host-onboarding" className="grid scroll-mt-6 gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Единый порядок подключения</h2>
          <a href={`${manualUrl}#host-onboarding`} className="mt-3 inline-block text-sm text-sky-300 underline underline-offset-4">Полная инструкция Ubuntu → Astra на GitHub</a>
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

        <aside className="h-fit space-y-5 rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div>
            <h2 className="text-xl font-semibold text-white">Где выполняются действия</h2>
            <dl className="mt-4 space-y-3 text-sm leading-6 text-slate-400">
              <div><dt className="font-semibold text-slate-200">На Ubuntu</dt><dd>Установка HCP, хранение индивидуальных приватных ключей, отчёты и резервные копии.</dd></div>
              <div><dt className="font-semibold text-slate-200">На Astra</dt><dd>Работающий SSH и учётная запись с административным доступом. HCP устанавливает ей публичный ключ и проверяет права.</dd></div>
              <div><dt className="font-semibold text-slate-200">На сайте</dt><dd>Выбор хоста, сверка ключа Astra до передачи пароля, установка индивидуального ключа доступа и запуск аудита.</dd></div>
            </dl>
          </div>
          <p className="text-sm leading-6 text-slate-400">Сначала HCP сверяет ключ сервера Astra с доверенным источником, затем входит по паролю и создаёт индивидуальную пару доступа. Приватный ключ остаётся на Ubuntu; на Astra передаётся только публичный. Перезапуск и повторное нажатие не меняют пару.</p>
          <p className="text-sm leading-6 text-slate-400">При сверке должны совпасть два отпечатка одного ключа Astra: из её консоли и полученный HCP по сети. Собственный ключ Ubuntu здесь не участвует. После сохранения проверка выполняется автоматически.</p>
          <a href={`${manualUrl}#host-trust-fleet`} className="inline-block text-sm text-sky-300 underline underline-offset-4">Как подготовить доверенные ключи для многих хостов</a>
          <p className="text-sm leading-6 text-slate-400">Пароль администратора используется только при первом подключении и не сохраняется. Затем HCP работает через индивидуальный ключ.</p>
        </aside>
      </section>

      <section id="sudo-access" className="scroll-mt-6 rounded-xl border border-sky-400/20 bg-sky-400/5 p-5">
        <h2 className="text-xl font-semibold text-white">Административный доступ</h2>
        <p className="mt-3 text-sm leading-6 text-slate-300">Используйте root с разрешённым SSH-входом или администратора с настроенным беспарольным sudo. При подключении HCP проверяет выполнение модуля Ansible с правами root. Отдельных переключателей sudo в форме нет.</p>
        <p className="mt-3 text-sm leading-6 text-slate-300">Для существующего хоста откройте «Настроить», укажите административную учётную запись и нажмите «Сохранить подключение». Если меняется пользователь SSH, введите его пароль для установки отдельного ключа. История хоста сохраняется.</p>
        <a href={`${manualUrl}#sudo-access`} className="mt-4 inline-block text-sm text-sky-300 underline underline-offset-4">Подготовка административной учётной записи</a>
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
          <h2 className="text-lg font-semibold text-white">Важно</h2>
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
