import { ArrowRight, CheckCircle2, KeyRound, ServerCog, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";

const manualUrl = "https://github.com/Danil-super/hardening-control-platform/blob/main/docs/ubuntu-astra-setup.md";
const greenboneContainersUrl = "https://greenbone.github.io/docs/latest/22.4/container/index.html";
const greenboneFeedsUrl = "https://greenbone.github.io/docs/latest/22.4/container/workflows.html";
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
          <p className="text-sm leading-6 text-slate-400">Пароль администратора используется только при первом подключении и не сохраняется. Затем HCP работает через индивидуальный ключ; для хоста с обычным sudo она запросит пароль снова только перед ручной привилегированной операцией.</p>
        </aside>
      </section>

      <section id="sudo-access" className="scroll-mt-6 rounded-xl border border-sky-400/20 bg-sky-400/5 p-5">
        <h2 className="text-xl font-semibold text-white">Административный доступ</h2>
        <p className="mt-3 text-sm leading-6 text-slate-300">Используйте root с разрешённым SSH-входом или администратора, у которого работает <code>sudo su</code>. При подключении HCP проверяет выполнение модуля Ansible с правами root, не меняет sudoers и не хранит пароль. Для ручного аудита или изменения такого хоста введите пароль sudo в появившееся поле.</p>
        <p className="mt-3 text-sm leading-6 text-slate-300">Для существующего хоста откройте «Настроить», укажите административную учётную запись и нажмите «Сохранить подключение». Если меняется пользователь SSH, введите его пароль для установки отдельного ключа. История хоста сохраняется.</p>
        <a href={`${manualUrl}#sudo-access`} className="mt-4 inline-block text-sm text-sky-300 underline underline-offset-4">Подготовка административной учётной записи</a>
      </section>

      <section id="greenbone" className="scroll-mt-6 rounded-xl border border-violet-400/20 bg-violet-500/5 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-violet-200">Сетевое сканирование</p>
            <h2 className="mt-2 text-xl font-semibold text-white">Greenbone / OpenVAS: от запуска до XML</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Greenbone — самостоятельный сетевой сканер. Он видит сетевые службы, версии и известные уязвимости, а HCP принимает только его завершённый XML-отчёт. Это разделение не даёт HCP незаметно запускать активное сетевое сканирование.</p>
          </div>
          <LinkButton href="/hosts" variant="secondary">Перейти к импорту XML</LinkButton>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">1. Разверните сканер отдельно</h3>
            <p className="mt-2 text-sm leading-6 text-slate-400">Подходит отдельная VM или control node, если на нём хватает ресурсов. По документации Greenbone требуется минимум 4 ГБ RAM и 20 ГБ диска; для нормальной работы рекомендуется 8 ГБ и 60 ГБ. Целевая Astra ничего для этого не устанавливает.</p>
            <pre className="mt-3 overflow-x-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300"><code>{`export DOWNLOAD_DIR="$HOME/greenbone-community-edition"
mkdir -p "$DOWNLOAD_DIR"
curl -f -O -L https://greenbone.github.io/docs/latest/_static/compose.yaml --output-dir "$DOWNLOAD_DIR"
docker compose -f "$DOWNLOAD_DIR/compose.yaml" pull
docker compose -f "$DOWNLOAD_DIR/compose.yaml" up -d`}</code></pre>
            <p className="mt-3 text-sm leading-6 text-slate-400">После запуска откройте <code>https://127.0.0.1</code> на машине со сканером. В официальном Compose первый локальный вход — <code>admin</code>/<code>admin</code>; браузер предупредит о самоподписанном сертификате. Сразу смените пароль администратора. Для первой загрузки feeds может потребоваться от нескольких минут до нескольких часов.</p>
          </article>

          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">2. Дождитесь готовности баз</h3>
            <p className="mt-2 text-sm leading-6 text-slate-400">Сканирование нельзя считать готовым сразу после старта контейнеров: Greenbone сначала загружает и индексирует VT, CVE и конфигурации. Пока данные загружаются, задачи могут быть в очереди или давать неполные результаты.</p>
            <pre className="mt-3 overflow-x-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300"><code>{`docker compose -f "$DOWNLOAD_DIR/compose.yaml" logs -f ospd-openvas gvmd`}</code></pre>
            <p className="mt-3 text-sm leading-6 text-slate-400">При регулярном обновлении сначала подтягиваются образы с feeds, затем работающие службы сами загружают их в память и БД. Не запускайте новый аудит, пока эта загрузка не закончится.</p>
          </article>

          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">3. Создайте и запустите задачу</h3>
            <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm leading-6 text-slate-400">
              <li>В GSA создайте <strong>Target</strong> с точным IP-адресом выбранной Astra, а не всей сетью.</li>
              <li>Создайте <strong>Task</strong>, привяжите к ней этот Target и разрешённую конфигурацию сканирования. Для первого стенда используйте только свою тестовую VM и не добавляйте учётные данные Greenbone.</li>
              <li>Запустите Task, дождитесь статуса <code>Done</code>. Статус <code>Running</code>, <code>Interrupted</code> или очередь не подходят для итогового импорта.</li>
            </ol>
          </article>

          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">4. Скачайте правильный файл и импортируйте</h3>
            <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm leading-6 text-slate-400">
              <li>В GSA откройте <strong>Scans → Reports</strong>, выберите завершённый report и скачайте формат <strong>XML</strong>.</li>
              <li>Не используйте PDF, CSV, архив, экспорт задачи или отчёт с фильтром, скрывающим результаты.</li>
              <li>В HCP: «Хосты» → выберите ту же Astra → «Сетевой сканер Greenbone / OpenVAS» → загрузите XML.</li>
            </ol>
            <p className="mt-3 text-sm leading-6 text-slate-400">HCP сверяет IP выбранного хоста, отбрасывает чужие результаты и сохраняет OID, CVE, порт, severity и QoD. Низкий QoD и неполный XML требуют ручной проверки, а не считаются подтверждённой уязвимостью.</p>
          </article>
        </div>
        <p className="mt-4 text-sm leading-6 text-slate-400">Официальные источники: <a className="text-sky-300 underline underline-offset-4" href={greenboneContainersUrl} target="_blank" rel="noreferrer">развёртывание Greenbone Community Containers</a> и <a className="text-sky-300 underline underline-offset-4" href={greenboneFeedsUrl} target="_blank" rel="noreferrer">обновление feeds</a>.</p>
      </section>

      <section id="firewall" className="scroll-mt-6 rounded-xl border border-amber-400/25 bg-amber-500/5 p-5">
        <p className="text-xs font-semibold uppercase tracking-wide text-amber-200">Контролируемое изменение</p>
        <h2 className="mt-2 text-xl font-semibold text-white">Как безопасно закрыть тестовый порт</h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">HCP меняет только один активный UFW или firewalld. Перед применением он проверяет актуальное состояние firewall и список открытых портов, создаёт резервную копию, затем выполняет правило. Текущий SSH-порт управления блокируется защитой.</p>
        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">Рекомендуемый первый опыт</h3>
            <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm leading-6 text-slate-400">
              <li>Создайте снимок Astra VM и оставьте доступ к её консоли.</li>
              <li>На тестовой Astra временно поднимите сервис на безопасном порту, например <code>python3 -m http.server 8088 --bind 0.0.0.0</code>.</li>
              <li>С control node убедитесь, что порт 8088 виден: <code>nmap -Pn -p 8088 IP_ASTRA</code>.</li>
              <li>В HCP выберите «Закрыть порт», укажите <code>8088</code>/<code>TCP</code>, причину и точный alias хоста.</li>
              <li>Нажмите «1. Проверить», затем «2. Применить». После этого повторите Nmap: порт должен перестать быть доступным извне.</li>
              <li>Нажмите «Откатить» у появившейся транзакции и повторите Nmap: исходная доступность должна вернуться.</li>
            </ol>
          </article>
          <article className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <h3 className="font-semibold text-white">Что может остановить изменение</h3>
            <ul className="mt-2 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-400">
              <li>Нет одного активного поддерживаемого UFW или firewalld, либо активны оба.</li>
              <li>Не удалось подтвердить состояние firewall или перечень открытых портов в исходном аудите.</li>
              <li>Выбран SSH-порт, адрес управления для блокировки, неправильный alias или слишком короткая причина.</li>
              <li>Для firewalld временные и постоянные правила различаются: сначала их нужно согласовать вручную.</li>
            </ul>
            <p className="mt-3 text-sm leading-6 text-slate-400">Неполнота несвязанной проверки профиля — например, отсутствующий auditd или особенность <code>sshd -T</code> — отображается как ограничение отчёта, но не мешает этой операции, если firewall и порты подтверждены.</p>
          </article>
        </div>
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
