import { CheckCircle2, Shield, Terminal } from "lucide-react";
import { LinkButton } from "@/components/ui/button";

const auditRequest = `POST /agent/audit
{
  "profileId": "basic_linux",
  "mode": "audit_only"
}`;

const auditResponse = `{
  "auditId": "agent_audit_basic_linux_20260602150000",
  "createdAt": "2026-06-02T15:00:00+00:00",
  "hostname": "ubuntu-server",
  "os": "Ubuntu 24.04",
  "profileId": "basic_linux",
  "mode": "agent",
  "agent": {
    "version": "0.3.0",
    "safeMode": true,
    "remediationEnabled": false,
    "integrations": {
      "lynis": {
        "enabled": true,
        "findings": 4
      },
      "openscap": {
        "enabled": true,
        "findings": 6
      }
    }
  },
  "findings": [],
  "summary": {
    "high": 3,
    "medium": 7,
    "low": 5,
    "score": 68
  }
}`;

const remediateRequest = `POST /agent/remediate
{
  "auditId": "audit_001",
  "remediationIds": ["disable_ssh_root_login", "enable_ufw"],
  "createBackup": true
}`;

const installCommands = `cd agent
./install.sh --dry-run
sudo ./install.sh --enable --start
./doctor.sh
curl http://127.0.0.1:8765/health
sudo systemctl status hcp-agent-bridge.service
sudo ./uninstall.sh --dry-run
sudo ./uninstall.sh --remove-files`;

const currentChecks = [
  "Определение ОС через /etc/os-release",
  "Проверка sshd_config: прямой вход root, вход по паролю и пустые пароли",
  "Проверка UFW, fail2ban и unattended-upgrades",
  "Ограниченная проверка world-writable файлов",
  "Статическая проверка Nginx: раскрытие версии, защитные заголовки и HTTPS",
  "Проверка Docker-контейнеров, если командная строка Docker доступна",
  "Опциональный импорт результатов Lynis и OpenSCAP / SCAP Security Guide",
];

export default function AgentPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Локальный Linux-агент</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Первая версия агента уже поддерживает безопасный режим “только аудит”. Он читает локальные конфигурации,
          выполняет безвредные проверки и возвращает JSON. Изменения ОС, исправления и откат пока не выполняются.
        </p>
      </div>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Terminal size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Запуск агента в режиме “только аудит”</h2>
          <pre className="mt-4 overflow-x-auto rounded-md bg-slate-900 p-4 text-sm text-slate-200">
            <code>{`cd agent
python3 agent.py audit --profile basic_linux --pretty
python3 agent.py audit --profile basic_linux --include-lynis --pretty
python3 agent.py audit --profile basic_linux --include-openscap --pretty
python3 agent.py audit --profile ssh_security --pretty
python3 agent.py audit --profile web_server --pretty
python3 agent.py audit --profile docker_host --pretty`}</code>
          </pre>
          <div className="mt-4 rounded-md border border-emerald-400/30 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
            Агент безопасен для запуска: он не изменяет файлы, не перезапускает службы и не включает межсетевой экран.
          </div>
          <LinkButton href="/agent/import" className="mt-4 w-full">
            Открыть импорт результатов агента
          </LinkButton>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Shield size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Что проверяется сейчас</h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {currentChecks.map((check) => (
              <li key={check} className="flex gap-2">
                <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-emerald-200" aria-hidden="true" />
                <span>{check}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Что пока не выполняется</h2>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Команды `remediate` и `rollback` сейчас возвращают JSON со статусом `not_implemented`. Это сделано намеренно:
          сначала агент должен безопасно собирать факты и отдавать отчет, а реальные изменения будут добавляться только
          после реализации резервных копий и отката.
        </p>
      </section>

      <section className="rounded-md border border-sky-400/25 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Автоматизация импорта</h2>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Для автоматической связки запустите локальный промежуточный сервер: `python3 server.py`. После этого страница
            импорта сможет получить отчет по адресу `http://127.0.0.1:8765/audit?profile=basic_linux`. Расширенный аудит
            Lynis включается через `includeLynis=1`, а OpenSCAP через `includeOpenScap=1` или переключатели на странице импорта.
          </p>
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Жизненный цикл агента</h2>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            В репозитории есть `agent/install.sh` и шаблон systemd unit. Скрипт копирует агента в `/opt`,
            регистрирует локальный сервис и по умолчанию слушает только `127.0.0.1`. Перед установкой можно выполнить
            dry-run, чтобы увидеть план без изменения системы.
          </p>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            `doctor.sh` проверяет синтаксис, выполняет тестовый аудит и пробует обратиться к `/health`.
            `uninstall.sh` останавливает сервис, снимает автозапуск и удаляет unit-файл; установленные файлы удаляются
            только при явном флаге `--remove-files`.
          </p>
          <div className="mt-4 rounded-md border border-emerald-400/30 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
            Установленный сервис остается в режиме “только аудит”: он читает настройки и отдает JSON, но не применяет
            исправления и не меняет ОС.
          </div>
        </div>
        <pre className="overflow-x-auto rounded-md border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-200">
          <code>{installCommands}</code>
        </pre>
      </section>

      <section className="grid gap-5 lg:grid-cols-3">
        {[auditRequest, auditResponse, remediateRequest].map((code, index) => (
          <pre key={index} className="overflow-x-auto rounded-md border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-200">
            <code>{code}</code>
          </pre>
        ))}
      </section>
    </div>
  );
}
