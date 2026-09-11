# Контейнерное развертывание control node

Для HCP на Ubuntu и проверяемых Astra Linux используйте [единый порядок установки](../docs/ubuntu-astra-setup.md). Команды резервного копирования и восстановления: [отдельная инструкция](../docs/backup-restore.md). Если Docker требует прав администратора, добавляйте `sudo` к командам `docker` ниже.

Этот вариант запускается на выделенном Linux-хосте в приватной сети. Не публикуйте порт 3000 напрямую в интернет: оставьте loopback-привязку и при необходимости поставьте перед ним HTTPS reverse proxy с отдельной аутентификацией.

## Подготовка

Образ control node уже содержит Ansible, Lynis, Nmap, `ssh-audit 3.3.0`, OpenSCAP и Trivy. SSH-сканер устанавливается из [PyPI](https://pypi.org/project/ssh-audit/3.3.0/) в отдельный Python venv; пакет `ssh-audit 2.5` из Debian bookworm не поддерживает необходимый формат результатов. HCP проверяет версию и наличие `--skip-rate-test` до подключения к хосту и всегда отключает тест частоты подключений. OpenSCAP не устанавливается на управляемые ВМ автоматически: для точной SCAP-проверки его и SSG content заранее готовят только на тех хостах, где это одобрено.

При запуске без Docker установите поддерживаемый SSH-сканер на управляющей машине:

```bash
sudo apt-get install python3-venv
sudo python3 -m venv /opt/hcp-tools/ssh-audit
sudo /opt/hcp-tools/ssh-audit/bin/pip install --only-binary=:all: ssh-audit==3.3.0
```

Задайте `HCP_SSH_AUDIT_BIN=/opt/hcp-tools/ssh-audit/bin/ssh-audit` в окружении сервиса HCP. Установка требует доступа к PyPI; сам SSH-аудит работает внутри локальной сети.

```bash
cp .env.production.example .env
cp ansible/inventory.example.ini ansible/inventory.ini
mkdir -p secrets
chmod 700 secrets
ssh-keygen -t ed25519 -N '' -f secrets/hcp-control -C hcp-control
install -m 600 /dev/null secrets/known_hosts
chmod 600 .env secrets/hcp-control
```

Перед добавлением ключей хостов в `secrets/known_hosts` сверяйте fingerprint через консоль или доверенный канал. Например, после проверки fingerprint:

```bash
ssh-keyscan -H 192.168.56.101 192.168.56.102 >> secrets/known_hosts
chmod 600 secrets/known_hosts
```

После запуска этот начальный файл переносится в постоянный volume. Для новых хостов используйте «Мастер первого SSH-подключения» в `/hosts`: он показывает публичный ключ узла управления, сохраняет только независимо подтверждённый ключ сервера и не принимает пароль от SSH. Не редактируйте `known_hosts` внутри контейнера вручную.

Заполните `.env` уникальными `HCP_ADMIN_PASSWORD`, `HCP_AUTH_SECRET`, `HCP_AUDIT_HMAC_KEY` и `HCP_SCHEDULE_API_KEY`, затем настройте начальные хосты в `ansible/inventory.ini`. `HCP_AUDIT_HMAC_KEY` защищает hash-chain журнал от незаметного пересчёта при изменении SQLite-файла; `HCP_SCHEDULE_API_KEY` разрешает внутренним заданиям обращаться к API. Парольная фраза SSH-ключа не поддерживается без ssh-agent, поэтому используется отдельный незашифрованный ключ с правами 600.

## Запуск

```bash
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 180
docker compose logs -f hcp
```

Откройте `http://127.0.0.1:3000` на control node либо используйте SSH-туннель. Отчёты, SQLite, журнал, `known_hosts` и рабочий inventory сохраняются в volume `hcp-runtime`. Файл `ansible/inventory.ini` — только начальный seed; рабочая копия `/var/lib/hcp/inventory.ini` связана с `/app/ansible/inventory.ini` и доступна пользователю `node` для сохранения через панель. Последующие изменения seed не заменяют рабочую копию.

Первый прогон выполните по [инструкции стенда](lab/README.md): она разделяет быстрые контейнерные проверки и полноценные испытания на ВМ.

## Изолированная сеть и CVE

Общий пакетный CVE-аудит HCP выполняет Trivy. Для Astra доступен отдельный OVAL-аудит с локальным XML или HTTPS-источником: [настройка базы Astra](../docs/astra-audit.md). Его параметры не меняются переключателем Trivy. Если для Trivy доступно внутреннее OCI-зеркало, задайте его и используйте сетевой режим:

```env
HCP_TRIVY_MODE=online
HCP_TRIVY_DB_REPOSITORY=registry.security.intra/trivy-db
HCP_TRIVY_JAVA_DB_REPOSITORY=registry.security.intra/trivy-java-db
HCP_TRIVY_MAX_DB_AGE_HOURS=168
```

Для полностью изолированного режима сначала загрузите базу в `/var/lib/hcp/trivy-cache` в окно обновления, затем выберите «Локальная база» в интерфейсе. Один адрес зеркала не заполняет cache. В offline-режиме Trivy не обновляет базы. Если cache отсутствует или недоступен, HCP создаёт неполный отчёт с ручной проверкой. Возраст базы контролируется по `HCP_TRIVY_MAX_DB_AGE_HOURS`; при превышении лимита отчёт тоже помечается частичным. Переключатель относится к Trivy, а не ко всем интеграциям и обновлениям ОС.

Dependency-Track не запускается по умолчанию. После заполнения его пароля БД включите отдельный профиль: `docker compose --profile dependency-track up -d --build`. Подробные инструкции для OpenSCAP, Trivy, Greenbone и Dependency-Track — в [docs/audit-integrations.md](../docs/audit-integrations.md).

## Периодический аудит через systemd

Планировщик не работает внутри памяти веб-процесса. На control node установите units, которые вызывают отдельный Ansible-процесс в контейнере:

```bash
sudo cp deployment/systemd/hcp-scheduled-audit.service /etc/systemd/system/
sudo cp deployment/systemd/hcp-scheduled-audit.timer /etc/systemd/system/
sudo cp deployment/systemd/hcp-deep-audit.service /etc/systemd/system/
sudo cp deployment/systemd/hcp-deep-audit.timer /etc/systemd/system/
sudo systemctl edit hcp-scheduled-audit.service
sudo systemctl edit hcp-deep-audit.service
```

Для обоих сервисов добавьте `[Service]` и `WorkingDirectory=/абсолютный/путь/hardening-control-platform`; без override используется `/opt/hardening-control-platform`. Проверьте `/usr/bin/docker` командой `command -v docker`. Units выполняют сканеры через `docker compose exec --user node`, чтобы созданные отчёты оставались доступны веб-приложению. После настройки:

```bash
sudo systemctl daemon-reload
sudo systemctl start hcp-scheduled-audit.service hcp-deep-audit.service
sudo systemctl enable --now hcp-scheduled-audit.timer hcp-deep-audit.timer
systemctl list-timers 'hcp-*audit.timer'
```

`hcp-scheduled-audit.timer` запускает `basic_linux` для группы `linux_hosts` каждые 15 минут. `hcp-deep-audit.timer` запускает инвентарь пакетов и Trivy ежедневно в 02:30. OpenSCAP не включён в него по умолчанию: для него нужно сначала подготовить подходящие хосты и отдельную inventory-группу.

Отдельный OVAL-аудит Astra не входит в штатное расписание; запускайте его из «Хостов». Для группы только с Astra не считайте плановую задачу `packages` заменой этому аудиту. При выборе конфигурационного OpenSCAP для такой группы можно задать `HCP_DEEP_SCHEDULE_TASKS=openscap` в override сервиса.

Чтобы выбрать профиль или группы, задайте в `.env`:

```env
HCP_SCHEDULE_PROFILE=ssh_security
HCP_SCHEDULE_LIMIT=production_linux
HCP_SCHEDULE_DEEP_LIMIT=package_audit_hosts
```

После изменения выполните `docker compose up -d` и перезапустите оба timer. Внутренний `flock` блокирует параллельные плановые запуски.

Чтобы добавить OpenSCAP к глубокому запуску, создайте override `sudo systemctl edit hcp-deep-audit.service`:

```ini
[Service]
Environment=HCP_DEEP_SCHEDULE_TASKS=packages,openscap
```

Затем выполните `sudo systemctl daemon-reload && sudo systemctl restart hcp-deep-audit.timer`. Не включайте OpenSCAP для общей группы разнородных серверов: datastream и профиль должны соответствовать ОС и роли хоста.

Плановый OpenSCAP вызывает внутренний API с `HCP_SCHEDULE_API_KEY`, получает хосты выбранной группы и применяет профиль/исключения из SQLite по каждому хосту. Для него, как и для Trivy, должен работать сервис HCP. Прямой запуск `ansible-playbook openscap-audit.yml` читает только переданные переменные и не применяет сохранённые исключения.

## Обязательные меры перед эксплуатацией

- Используйте отдельный SSH-ключ и отдельного технического пользователя. Полный набор текущих Ansible-проверок требует удалённого Python с `sudo` без пароля: подготовка такого доступа даёт широкие привилегии, поэтому control node должен администрироваться как привилегированный узел.
- Фиксируйте SSH host keys через мастер или начальный `secrets/known_hosts`; в репозитории включена строгая проверка ключей и после запуска ключи хранятся в persistent volume.
- Ограничьте доступ к панели VPN или reverse proxy с TLS. Не меняйте `HCP_BIND_ADDRESS` на `0.0.0.0` без firewall и TLS.
- Сохраните резервную копию рабочего inventory из volume и всего Docker volume; автоматическая ротация отчётов пока не реализована.
- Response-действия панели ограничены обратимыми firewall-операциями. Перед применением обязательно выполните dry-run и проверьте созданную резервную копию; обновления пакетов и управление сервисами выполняйте по отдельной ручной процедуре.
- Nmap и временный Lynis запускайте только для активов, на проверку которых есть разрешение. Временный Lynis выполняет код на ВМ, но удаляет каталог сразу после получения отчета.
- Проверка образов/снимков гипервизора не реализована. В текущем проекте OpenSCAP работает на подготовленной гостевой ОС, Trivy — на control node по собранному списку пакетов.
