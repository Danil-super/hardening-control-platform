# Hardening Control Platform

Локальная панель аудита Linux-хостов. HCP подключается к ним по SSH, собирает отчёты и помогает планировать исправления.

<a name="короткая-инструкция-запустить-и-обновлять-hcp-локально"></a>

## Первая установка

Выполняйте команды на компьютере, где будет работать HCP. Рекомендуется Ubuntu 24.04 с Git, OpenSSL и Docker Compose v2.20+. Для первой сборки нужен интернет. [Установка Docker Engine и Compose на Ubuntu](https://docs.docker.com/engine/install/ubuntu/).

1. Скачайте проект и подготовьте начальные файлы.

   ```bash
   git clone https://github.com/Danil-super/hardening-control-platform.git
   cd hardening-control-platform
   install -m 600 .env.production.example .env
   cp ansible/inventory.example.ini ansible/inventory.ini
   install -d -m 700 secrets
   install -m 600 /dev/null secrets/known_hosts
   ```

2. Откройте `.env` в редакторе и замените три значения.

   | Переменная | Что указать |
   | --- | --- |
   | `HCP_ADMIN_PASSWORD` | Уникальный пароль для входа в HCP |
   | `HCP_AUTH_SECRET` | Случайный ключ для сеансов |
   | `HCP_AUDIT_HMAC_KEY` | Другой случайный ключ для журнала аудита |

   Для каждого значения можно отдельно выполнить `openssl rand -hex 32`. Сохраните файл `.env` локально.

3. Соберите и запустите панель из каталога проекта. Если Docker требует повышенных прав, добавляйте `sudo` перед командами `docker`.

   ```bash
   docker compose config --quiet
   docker compose up -d --build --wait --wait-timeout 180 hcp
   docker compose ps hcp
   ```

   Когда сервис покажет `healthy`, откройте [127.0.0.1:3000](http://127.0.0.1:3000/login) в браузере на этом компьютере. Войдите с паролем из `HCP_ADMIN_PASSWORD`.

4. Откройте **Хосты → Подключить хост**. Укажите адрес и SSH-пользователя целевой машины, затем сверьте отпечаток её SSH-ключа. Подробности есть в инструкции для [Linux](docs/linux-setup.md) и [Astra Linux](docs/ubuntu-astra-setup.md#host-onboarding).

## Повторный локальный запуск

Откройте терминал **в уже установленном каталоге проекта** и запустите существующий контейнер.

```bash
docker compose start hcp
docker compose ps hcp
```

Когда сервис покажет `healthy`, откройте [панель](http://127.0.0.1:3000/login). Для остановки выполните `docker compose stop hcp`. Хосты, отчёты и настройки сохраняются в томе Docker `hcp-runtime`. Если контейнер удалён командой `docker compose down`, снова выполните команду сборки и запуска с прежним `.env`.

<a name="если-платформа-уже-была-запущена"></a>

## Обновление

В каталоге проекта на ветке `main` с чистым рабочим деревом выполните:

```bash
git pull --ff-only
docker compose up -d --build --wait --wait-timeout 180 hcp
```

Используйте прежний `.env` и тот же том. Для обновления с резервной копией следуйте [инструкции бэкапа](docs/backup-restore.md).

## Диагностика и документация

Если панель не открывается, проверьте `docker compose ps hcp` и `docker compose logs --tail=80 hcp`.

Если SSH к ВМ доступен из Ubuntu и недоступен из контейнера, укажите в `.env` `COMPOSE_FILE=docker-compose.yml:docker-compose.host-network.yml` и выполните `docker compose up -d hcp`. Этот режим требует Linux и Compose v2.24.4+.

- [Сеть Docker и VMware](docs/ubuntu-astra-setup.md#3-сеть-ubuntu--astra)
- [Проверки, сценарии и отчёты](docs/site-guide.md)
- [Источники CVE и интеграции](docs/audit-integrations.md)
- [Настройка расписания и развёртывание](deployment/README.md)
