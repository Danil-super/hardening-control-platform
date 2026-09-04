# Hardening Control Platform

Рабочая локальная платформа для безагентного аудита и контролируемого харденинга Linux-серверов через Ansible и SSH. Control node ведет inventory, запускает разрешенные playbook'и, хранит отчеты и не устанавливает постоянный агент на целевые хосты.

Платформа предназначена для приватной сети и активов, на проверку и изменение которых есть разрешение. Это не публичный сканер, IDS или SIEM.

## Возможности

- Реальные профили аудита: базовый Linux, SSH, web-сервер, Docker-host.
- Проверка SSH-доступа, системных фактов, портов, сервисов и логов через Ansible.
- Инвентарь пакетов, CycloneDX SBOM и CVE-сопоставление через Trivy; OSV остаётся резервным online-адаптером.
- OpenSCAP/SSG-проверка подготовленного хоста, импорт сетевых отчётов Greenbone и отправка SBOM в Dependency-Track.
- История JSON-отчетов по каждому управляемому хосту.
- Обратимые firewall-изменения: dry-run, typed confirmation, backup, повторный аудит и rollback.
- SQLite для транзакций и append-only hash-chain журнала действий.
- Периодический аудит через `systemd timer` и `flock` — без зависимости от памяти Next.js.
- Docker-стенд для воспроизводимой проверки сценария «до/после».

## Стек

- Next.js App Router, TypeScript, Tailwind CSS
- Node.js built-in SQLite (`node:sqlite`)
- Ansible, SSH, Nmap, Lynis, ssh-audit, OpenSCAP, Trivy
- Docker Compose и systemd для локального развертывания

## Быстрый запуск для разработки

```bash
cd web
npm ci
cp .env.example .env.local
npm run dev
```

В `web/.env.local` задайте:

```env
HCP_ADMIN_PASSWORD=your-local-password
HCP_AUTH_SECRET=at-least-32-random-characters
HCP_AUDIT_HMAC_KEY=separate-at-least-32-random-characters
```

Сборка и проверки:

```bash
cd web
npm run typecheck
npm test
npm run build
```

## Работа с реальным хостом

1. Подготовьте inventory и отдельный SSH-ключ узла управления:

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
ssh-keygen -t ed25519 -C hcp-control
```

2. Откройте `/hosts` и пройдите «Мастер первого SSH-подключения»: он выдаст публичный ключ узла управления и команду для добавления через консоль ВМ или уже существующий временный доступ. Пароль в платформу не передаётся.
3. Сверьте fingerprint SSH-сервера через консоль гипервизора, панель провайдера или утверждённый реестр. Вставьте его в мастер; ключ попадёт в persistent `known_hosts` только после повторного совпадения.
4. Выполните preflight. Только успешное подключение можно добавить в inventory, затем выберите профиль.
5. Запустите аудит. Отчеты сохраняются в `ansible/reports/` или `HCP_REPORTS_DIR`.
6. Для обратимого firewall-изменения сначала выполните «План», затем «Применить». Потребуются причина и точный alias хоста.

Подробный сценарий — в [docs/site-guide.md](docs/site-guide.md).

## Профили

Правила хранятся в `ansible/audit-rules/` и загружаются по `audit_profile`:

- `basic-linux.yml` — базовые настройки Linux, firewall, аккаунты и обновления;
- `ssh-security.yml` — политика SSH и защита от перебора;
- `web-server.yml` — активные web-сервисы, Nginx/Apache banner hardening и опасные порты;
- `docker-host.yml` — Docker Engine, `docker.sock`, privileged containers и Docker API-порты.

Каждый профиль выполняется на целевом хосте, а не моделируется в браузере.

## Контролируемые изменения и откат

В панели доступны только операции с воспроизводимым rollback:

- закрыть конкретный TCP/UDP-порт через активный UFW/firewalld (порт SSH 22 защищен от автоматического закрытия);
- заблокировать IPv4-адрес через активный UFW/firewalld.

Перед изменением `backup-remediation.yml` архивирует `/etc/ufw` и `/etc/firewalld` на целевом хосте в `/var/lib/hcp-backups/<transaction-id>/`. `rollback-remediation.yml` восстанавливает архив и перезагружает firewall. Пакетные обновления и остановка сервисов намеренно не автоматизированы: для них нужен отдельный approval workflow и план отката.

## Контейнерный control node

Подготовка и запуск production-контура описаны в [deployment/README.md](deployment/README.md). Compose хранит SQLite, отчеты, историю и подтверждённые SSH host keys в Docker volume; private key подключается как локальный secret-файл, а интерфейс по умолчанию слушает только `127.0.0.1`.

## CVE-аудит в локальной и изолированной сети

Без интернета полностью работают SSH-подключение, Ansible-аудиты, отчеты и controlled remediation. Основной CVE-контур — Trivy и сохранённый CycloneDX SBOM; он работает без выхода в интернет при заранее импортированной локальной базе.

- Для сети с контролируемым выходом оставьте `HCP_OSV_MODE=online` и разрешите узлу управления только HTTPS к `api.osv.dev`, либо укажите доверенный внутренний OSV-совместимый прокси в `HCP_OSV_BASE_URL`.
- Для изолированной сети укажите `HCP_OSV_MODE=offline`. Платформа не делает сетевой запрос, формирует отчёт об инвентаре и явно помечает, что CVE не сопоставлены — это не «чистый» результат.
- Для полноценного air-gap CVE-аудита установите `HCP_CVE_PROVIDER=trivy`, `HCP_TRIVY_MODE=offline` и укажите внутренние OCI-зеркала баз Trivy. При отсутствии базы платформа явно пометит отчёт как неполный.
- Полная установка и правила интерпретации четырёх источников — в [docs/audit-integrations.md](docs/audit-integrations.md).

## Периодический аудит

Скопируйте units из `deployment/systemd/` в `/etc/systemd/system/`, задайте при необходимости `HCP_SCHEDULE_PROFILE` и `HCP_SCHEDULE_LIMIT` в compose environment, затем включите timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hcp-scheduled-audit.timer
systemctl list-timers hcp-scheduled-audit.timer
```

Timer запускает `/usr/local/bin/hcp-scheduled-audit` внутри контейнера; `flock` не дает двум проверкам одного расписания пересечься.

При использовании операции «Блок IP» укажите IP control node в `HCP_CONTROL_IPS` (через запятую для нескольких). Платформа также защищает IP самого целевого хоста от автоматической блокировки.

## Лабораторный стенд

Стенд поднимает отдельный SSH-хост с намеренно небезопасной конфигурацией и Telnet listener на порту 23:

```bash
./deployment/lab/up.sh
```

После запуска откройте `http://127.0.0.1:3001`, войдите с `lab-only-password`, выберите `lab-insecure` и запустите базовый аудит. Лабораторный ключ и `known_hosts` создаются в игнорируемом каталоге `.lab/`.

## Ограничения текущей версии

- Пока используется локальная одноадминистраторская аутентификация; RBAC, отзыв сессий и MFA — следующий этап.
- Не публикуйте интерфейс в интернет без TLS reverse proxy, VPN и усиленной авторизации.
- CVE через OSV — предварительная проверка: дистрибутивные backport-исправления нужно сверять по vendor security tracker. В `HCP_OSV_MODE=offline` CVE вообще не сопоставляются — отчёт явно помечается как неполный.
- Пользовательские audit YAML отключены по умолчанию. В development их можно включить `HCP_ENABLE_CUSTOM_AUDITS=true`; response-playbook'и из браузера не запускаются.

Архитектура: [docs/architecture.md](docs/architecture.md). Дипломное описание: [docs/diploma-description.md](docs/diploma-description.md).
