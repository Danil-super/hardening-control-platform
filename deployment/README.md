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

Заполните `.env` уникальными `HCP_ADMIN_PASSWORD` и `HCP_AUTH_SECRET`, затем настройте целевые хосты в `ansible/inventory.ini`.

## Запуск

```bash
docker compose up -d --build
docker compose logs -f hcp
```

Откройте `http://127.0.0.1:3000` на control node либо используйте SSH-туннель. Отчеты и локальная история запусков сохраняются в именованном volume `hcp-runtime`.

## Обязательные меры перед эксплуатацией

- Используйте отдельный SSH-ключ и отдельного технического пользователя; выдавайте `sudo` только на нужные команды.
- Фиксируйте SSH host keys в `secrets/known_hosts`; в репозитории включена строгая проверка ключей.
- Ограничьте доступ к панели VPN или reverse proxy с TLS. Не меняйте `HCP_BIND_ADDRESS` на `0.0.0.0` без firewall и TLS.
- Сохраните резервную копию inventory и Docker volume, настройте ротацию отчетов.
- Не включайте response-действия для критичных систем, пока не будет согласован план отката и approval workflow.
- Nmap и временный Lynis запускайте только для активов, на проверку которых есть разрешение. Временный Lynis выполняет код на ВМ, но удаляет каталог сразу после получения отчета.
- OpenSCAP/Trivy для образов ВМ разворачивайте отдельным scanner worker с доступом только к API снимков гипервизора; не добавляйте их в гостевые ОС.
