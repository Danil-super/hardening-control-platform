import { LinkButton } from "@/components/ui/button";

const installCommands = `GREENBONE_DIR="$HOME/greenbone-community-edition"
mkdir -p "$GREENBONE_DIR"
curl -fL https://greenbone.github.io/docs/latest/_static/compose.yaml -o "$GREENBONE_DIR/compose.yaml"
docker compose -p greenbone-community-edition -f "$GREENBONE_DIR/compose.yaml" pull
docker compose -p greenbone-community-edition -f "$GREENBONE_DIR/compose.yaml" up -d`;

const feedCommands = `GREENBONE_DIR="$HOME/greenbone-community-edition"
docker compose -p greenbone-community-edition -f "$GREENBONE_DIR/compose.yaml" logs -f ospd-openvas gvmd`;

function Commands({ children }: { children: string }) {
  return <pre className="mt-3 max-w-full overflow-x-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs leading-5 text-slate-300"><code>{children}</code></pre>;
}

export function GreenboneGuide() {
  return (
    <section id="greenbone" className="min-w-0 scroll-mt-6 rounded-xl border border-sky-400/20 bg-slate-950/70 p-4 sm:p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Сетевое сканирование</p>
          <h2 className="mt-2 text-xl font-semibold text-white">Greenbone / OpenVAS: где и что выполнять</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Для стенда Ubuntu → Astra: установите сканер на управляющей Ubuntu, проверьте из него Astra и загрузите результат в HCP. У Greenbone свой веб-интерфейс; HCP принимает готовый XML-отчёт.</p>
        </div>
        <LinkButton href="/hosts" variant="secondary">К импорту XML</LinkButton>
      </div>

      <dl className="mt-4 grid gap-3 text-sm leading-6 md:grid-cols-3">
        <div className="rounded-md border border-slate-800 bg-slate-900/70 p-3"><dt className="font-semibold text-sky-200">Ubuntu — управляющая машина</dt><dd className="mt-1 text-slate-300">Здесь уже работает HCP. Здесь же запускаются контейнеры Greenbone отдельным Docker-проектом. Все команды ниже вводите в обычном терминале Ubuntu, вне контейнера HCP.</dd></div>
        <div className="rounded-md border border-slate-800 bg-slate-900/70 p-3"><dt className="font-semibold text-sky-200">Astra — проверяемая ВМ</dt><dd className="mt-1 text-slate-300">Включите ВМ и возьмите её IP со страницы «Хосты» HCP. На Astra устанавливать Greenbone и выполнять команды из этой инструкции не нужно.</dd></div>
        <div className="rounded-md border border-slate-800 bg-slate-900/70 p-3"><dt className="font-semibold text-sky-200">Браузер на Ubuntu — два сайта</dt><dd className="mt-1 text-slate-300">Greenbone: <code>https://localhost</code> — создать и запустить задачу. HCP: <code>http://localhost:3000</code> — импортировать XML. <code>localhost</code> означает машину, на которой открыт браузер.</dd></div>
      </dl>

      <ol className="mt-5 divide-y divide-slate-800 text-sm leading-6 text-slate-300">
        <li className="min-w-0 pb-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Терминал Ubuntu</p>
          <h3 className="mt-1 font-semibold text-white">1. Установите и запустите Greenbone</h3>
          <p className="mt-2">Проверьте, что работают <code>docker version</code> и <code>docker compose version</code>, установлен <code>curl</code> и есть доступ в интернет. Для сканера нужны дополнительные ресурсы сверх HCP: минимум 2 CPU, 4 ГБ RAM и 20 ГБ диска; рекомендуется 4 CPU, 8 ГБ и 60 ГБ.</p>
          <Commands>{installCommands}</Commands>
          <p className="mt-2 text-slate-400">Выполняйте строки по порядку в одном терминале. Файл Greenbone будет в домашнем каталоге Ubuntu, отдельно от проекта HCP. Если Greenbone уже установлен, переходите к шагу 2.</p>
        </li>
        <li className="min-w-0 py-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Браузер и терминал Ubuntu</p>
          <h3 className="mt-1 font-semibold text-white">2. Откройте Greenbone и дождитесь баз</h3>
          <p className="mt-2">Перед входом проверьте готовность менеджера в терминале Ubuntu:</p>
          <Commands>{`GREENBONE_DIR="$HOME/greenbone-community-edition"
docker compose -p greenbone-community-edition -f "$GREENBONE_DIR/compose.yaml" ps gvmd`}</Commands>
          <p className="mt-2">Дождитесь <code>healthy</code> у <code>gvmd</code>. Страница входа может открыться раньше менеджера: в это время возможна ошибка <code>GMP error during authentication</code>. После готовности обновите страницу и повторите вход. Если статус стал <code>unhealthy</code> или ошибка сохраняется при <code>healthy</code>, проверьте логи <code>gvmd</code> и <code>gsad</code>.</p>
          <p className="mt-2">Откройте <a className="text-sky-300 underline underline-offset-4" href="https://localhost" target="_blank" rel="noreferrer">https://localhost</a>. Для новой установки из официального Compose первый вход — <code>admin</code> / <code>admin</code>; сразу смените пароль в интерфейсе. Локальная установка использует самоподписанный сертификат.</p>
          <p className="mt-2">Загрузка и индексация баз проверок (feeds) может занимать от нескольких минут до нескольких часов. Запущенные контейнеры ещё не означают готовность сканера. Ход загрузки смотрите в терминале:</p>
          <Commands>{feedCommands}</Commands>
          <p className="mt-2 text-slate-400"><code>Ctrl+C</code> завершает просмотр логов, контейнеры продолжают работать. Переходите дальше после загрузки баз: в Greenbone должны стать доступны сканер и конфигурация <code>Full and fast</code>.</p>
        </li>
        <li className="py-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Сайт Greenbone · https://localhost</p>
          <h3 className="mt-1 font-semibold text-white">3. Укажите Astra как цель</h3>
          <p className="mt-2">Откройте <strong>Configuration → Targets → New Target</strong>. Задайте имя, например «Astra», а в поле <strong>Hosts</strong> укажите один IP проверяемой Astra из HCP. Берите адрес именно той машины, которую хотите проверить, а не адрес Ubuntu со сканером или <code>localhost</code>. Для нескольких хостов повторяйте этот порядок с адресом каждого хоста.</p>
          <p className="mt-2 text-slate-400">Первую сетевую проверку выполните без учётных данных Astra. SSH-подключение HCP и ключи HCP здесь не используются. Сканер должен иметь сетевой доступ к Astra из своих контейнеров.</p>
        </li>
        <li className="py-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Сайт Greenbone</p>
          <h3 className="mt-1 font-semibold text-white">4. Создайте задачу и дождитесь завершения</h3>
          <p className="mt-2">Откройте <strong>Scans → Tasks → New Task</strong>. Выберите созданную цель «Astra», сканер по умолчанию и конфигурацию <strong>Full and fast</strong>. Сохраните задачу, нажмите запуск и дождитесь статуса <strong>Done</strong>.</p>
          <p className="mt-2 text-slate-400">Если конфигурации нет в списке, вернитесь к загрузке баз в шаге 2. Объём проверки зависит от выбранной конфигурации и списка портов; такой запуск не гарантирует обнаружение всех уязвимостей ОС.</p>
        </li>
        <li className="py-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Сайт Greenbone → файл на Ubuntu</p>
          <h3 className="mt-1 font-semibold text-white">5. Скачайте отчёт в XML</h3>
          <p className="mt-2">В <strong>Scans → Reports</strong> откройте отчёт завершённой задачи. Нажмите значок карандаша <strong>Edit Filter</strong>: задайте <strong>QoD = 0</strong>, включите все уровни <strong>Critical, High, Medium, Low, Log, False Pos.</strong> и нажмите <strong>Update</strong>. Сверьте счётчик Results: показанное число должно совпадать с общим количеством записей.</p>
          <p className="mt-2">Нажмите <strong>Download filtered Report</strong> и в поле <strong>Report Format</strong> выберите точное название <strong>XML</strong>, затем <strong>OK</strong>. <strong>Anonymous XML</strong> обезличивает адреса и для импорта не подходит. Если он уже скачан, просто повторите экспорт готового отчёта в XML — запускать сканирование заново не нужно.</p>
          <p className="mt-2 text-slate-400">Нужен отчёт проверки, а не экспорт настроек задачи. PDF, CSV и архив не подходят. Если выгружена только часть результатов, HCP отметит отчёт как неполный; записи с низким QoD сохраняются как требующие проверки.</p>
          <p className="mt-2 text-slate-400">Файл <code>.xml</code> сохранится на компьютере, где открыт браузер, обычно в папке «Загрузки» Ubuntu. Переносить его на Astra не нужно.</p>
        </li>
        <li className="pt-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Сайт HCP · http://localhost:3000</p>
          <h3 className="mt-1 font-semibold text-white">6. Загрузите XML для того же хоста</h3>
          <p className="mt-2">Откройте <strong>Хосты → Настроить</strong> у той Astra, которую сканировали. Разверните <strong>«Сетевой сканер Greenbone / OpenVAS — импорт XML»</strong>, выберите скачанный <code>.xml</code> до 20 МБ и нажмите <strong>«Импортировать XML»</strong>. После импорта откройте отчёт HCP.</p>
          <p className="mt-2 text-slate-400">HCP сверит адрес цели и сохранит результаты для выбранного хоста. Кнопка импорта не запускает новую проверку Greenbone.</p>
        </li>
      </ol>

      <details className="mt-5 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-sm leading-6 text-slate-300">
        <summary className="cursor-pointer font-semibold text-slate-100">Если Greenbone установлен на отдельной Ubuntu-ВМ</summary>
        <p className="mt-3">Все команды шагов 1–2 выполняйте в терминале этой ВМ со сканером. Astra остаётся целью. Чтобы открыть Greenbone в браузере управляющей Ubuntu, создайте на ней SSH-туннель к ВМ сканера:</p>
        <Commands>{"ssh -N -L 9443:localhost:443 SCANNER_USER@SCANNER_HOST"}</Commands>
        <p className="mt-2">Замените <code>SCANNER_USER</code> на имя пользователя ВМ сканера, а <code>SCANNER_HOST</code> — на адрес этой ВМ. Пока терминал с туннелем открыт, Greenbone доступен на управляющей Ubuntu по <code>https://localhost:9443</code>. Шаги 3–5 выполняйте там. HCP остаётся по своему прежнему адресу; XML выбирайте из загрузок этого браузера.</p>
      </details>
      <p className="mt-4 text-xs leading-5 text-slate-400">Официальная документация: <a className="text-sky-300 underline underline-offset-4" href="https://greenbone.github.io/docs/latest/22.4/container/index.html" target="_blank" rel="noreferrer">установка Greenbone</a>, <a className="text-sky-300 underline underline-offset-4" href="https://greenbone.github.io/docs/latest/22.4/container/workflows.html" target="_blank" rel="noreferrer">загрузка и обновление баз</a>. Команды выше выполняются вручную: открытие инструкции ничего не устанавливает.</p>
    </section>
  );
}
