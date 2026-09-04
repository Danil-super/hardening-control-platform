# Контейнерное развертывание control node

Этот вариант запускается на выделенном Linux-хосте в приватной сети. Не публикуйте порт 3000 напрямую в интернет: оставьте loopback-привязку и при необходимости поставьте перед ним HTTPS reverse proxy с отдельной аутентификацией.

## Подготовка

Образ control node уже содержит Ansible, Lynis, Nmap и `ssh-audit`. Они выполняются внутри контейнера HCP; на управляемые ВМ эти пакеты не устанавливаются.

```bash
cp .env.production.example .env
cp ansible/inventory.example.ini ansible/inventory.ini
mkdir -p secrets
install -m 600 ~/.ssh/hcp-control secrets/hcp-control
install -m 600 /dev/null secrets/known_hosts
```

Перед добавлением ключей хостов в `secrets/known_hosts` сверяйте fingerprint через консоль или доверенный канал. Например, после проверки fingerprint:

```bash
ssh-keyscan -H 192.168.56.101 192.168.56.102 >> secrets/known_hosts
chmod 600 secrets/known_hosts
```

После запуска этот начальный файл переносится в постоянный volume. Для новых хостов используйте «Мастер первого SSH-подключения» в `/hosts`: он показывает публичный ключ узла управления, сохраняет только независимо подтверждённый ключ сервера и не принимает пароль от SSH. Не редактируйте `known_hosts` внутри контейнера вручную.

Заполните `.env` уникальными `HCP_ADMIN_PASSWORD`, `HCP_AUTH_SECRET` и `HCP_AUDIT_HMAC_KEY`, затем настройте целевые хосты в `ansible/inventory.ini`. Последний ключ защищает hash-chain журнал от незаметного пересчета при изменении SQLite-файла.

## Запуск

```bash
docker compose up -d --build
docker compose logs -f hcp
```

Откройте `http://127.0.0.1:3000` на control node либо используйте SSH-туннель. Отчеты, SQLite-база транзакций и append-only журнал сохраняются в именованном volume `hcp-runtime`.

## Изолированная сеть и CVE

По умолчанию `HCP_OSV_MODE=online` обращается к `https://api.osv.dev/v1` только при запуске проверки пакетов и CVE. Остальные функции не требуют интернета. Для изолированного контура задайте в `.env`:

```env
HCP_OSV_MODE=offline
```

Тогда платформа не выполняет исходящее соединение и создаёт отчёт «инвентарь есть, CVE не сопоставлены». Если в сети есть доверенный API-proxy, совместимый с OSV `/v1/querybatch` и `/v1/vulns/{id}`, оставьте `online` и укажите его базовый URL:

```env
HCP_OSV_MODE=online
HCP_OSV_BASE_URL=https://osv-proxy.security.intra/v1
```

## Периодический аудит через systemd

Планировщик не работает внутри памяти веб-процесса. На control node установите units, которые вызывают отдельный Ansible-процесс в контейнере:

```bash
sudo cp deployment/systemd/hcp-scheduled-audit.service /etc/systemd/system/
sudo cp deployment/systemd/hcp-scheduled-audit.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hcp-scheduled-audit.timer
systemctl list-timers hcp-scheduled-audit.timer
```

По умолчанию timer запускает каждые 15 минут `basic_linux` для группы `linux_hosts`. Чтобы выбрать профиль или группу, добавьте в environment сервиса `hcp` в `docker-compose.yml`:

```yaml
HCP_SCHEDULE_PROFILE: ssh_security
HCP_SCHEDULE_LIMIT: production_linux
```

После изменения выполните `docker compose up -d` и `sudo systemctl restart hcp-scheduled-audit.timer`. Внутренний `flock` блокирует параллельные плановые запуски.

## Обязательные меры перед эксплуатацией

- Используйте отдельный SSH-ключ и отдельного технического пользователя; выдавайте `sudo` только на нужные команды.
- Фиксируйте SSH host keys через мастер или начальный `secrets/known_hosts`; в репозитории включена строгая проверка ключей и после запуска ключи хранятся в persistent volume.
- Ограничьте доступ к панели VPN или reverse proxy с TLS. Не меняйте `HCP_BIND_ADDRESS` на `0.0.0.0` без firewall и TLS.
- Сохраните резервную копию inventory и Docker volume, настройте ротацию отчетов.
- Response-действия панели ограничены обратимыми firewall-операциями. Перед применением обязательно выполните dry-run и проверьте созданную резервную копию; обновления пакетов и управление сервисами выполняйте по отдельной ручной процедуре.
- Nmap и временный Lynis запускайте только для активов, на проверку которых есть разрешение. Временный Lynis выполняет код на ВМ, но удаляет каталог сразу после получения отчета.
- OpenSCAP/Trivy для образов ВМ разворачивайте отдельным scanner worker с доступом только к API снимков гипервизора; не добавляйте их в гостевые ОС.
