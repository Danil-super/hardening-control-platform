# Hardening Control Platform Web

Веб-интерфейс для главного Ansible-сервера: inventory, SSH-проверки, запуск разрешенных playbook'ов и просмотр локальных JSON-отчетов.

## Запуск

Установить зависимости:

```bash
npm install
```

Создать локальные переменные для защищенной Ansible-панели:

```bash
cp .env.example .env.local
```

В `.env.local` задайте `HCP_ADMIN_PASSWORD` и `HCP_AUTH_SECRET`.

Запустить сервер разработки:

```bash
npm run dev
```

Собрать проект:

```bash
npm run build
```

Основные маршруты:

- `/` переход к управлению хостами
- `/login` вход администратора
- `/hosts` локальный центр Ansible: добавление хостов, inventory, SSH-аудит и response-playbook'и
- `/playbooks` создание, проверка и запуск Ansible playbook'ов
- `/reports` реальные Ansible-отчеты
- `/guide` инструкция по работе

Управление доступно при локальном запуске сайта на главном сервере в сети. На управляемые хосты постоянные агенты не устанавливаются: Ansible подключается к ним по SSH.

Добавление хоста выполняется через форму `/hosts`: сначала preflight-проверка SSH/Python/sudo, затем сохранение в
`ansible/inventory.ini`. Сканирование сети только помогает найти SSH-доступные IP.

Кнопка `CVE пакеты` сначала собирает package inventory по SSH без установки ПО на хост, затем главный сервер проверяет
пакеты через OSV.dev и сохраняет CVE-отчет в `ansible/reports/<host>-vulnerabilities.json`.

## Vercel

Используйте стандартный preset Next.js. Если деплой выполняется из корня репозитория, укажите `web` как корневую директорию проекта.
