# Hardening Control Platform

Веб-платформа для централизованного аудита и безопасного управления Linux-серверами через Ansible и SSH.

Один главный сервер ведет inventory, обнаруживает SSH-доступные Linux-хосты, запускает Ansible playbook'и по SSH и сохраняет JSON-отчеты локально. Постоянные агенты на управляемые хосты не устанавливаются.

## Стек

- Next.js App Router
- TypeScript
- Tailwind CSS
- lucide-react
- Ansible для централизованного локального управления хостами в сети

## Запуск сайта

```bash
cd web
npm ci
cp .env.example .env.local
npm run dev
```

В `web/.env.local` задайте локальный пароль администратора для Ansible-панели:

```env
HCP_ADMIN_PASSWORD=your-local-password
HCP_AUTH_SECRET=your-random-secret
```

Пароль защищает `/hosts`, реальные Ansible-отчеты и `/api/ansible/*`.

Для доступа к сайту с других устройств в локальной сети:

```bash
cd web
npm run dev:lan
```

Сборка:

```bash
cd web
npm run build
```

## Основные экраны

- `/` переход к управлению хостами.
- `/login` вход администратора.
- `/hosts` локальная Ansible-панель: добавление хостов, inventory, SSH-аудит и response-playbook'и.
- `/playbooks` список, создание, syntax-check и запуск Ansible playbook'ов.
- `/reports` реальные Ansible-отчеты из `ansible/reports`.
- `/guide` краткая инструкция по работе.

## Краткая инструкция по работе

1. Запустите сайт на главном сервере и войдите через `/login`.
2. Откройте `/hosts` и проверьте Ansible control node.
3. Добавьте Linux-хост: alias, IP/hostname, SSH user, port, group и sudo.
4. Нажмите `Проверить`, чтобы проверить SSH, Python и sudo без сохранения в inventory.
5. Сохраните хост и запустите Ansible ping, затем SSH-аудит Ansible.
6. Запустите CVE-аудит пакетов, чтобы собрать package inventory и проверить версии через OSV.dev.
7. Откройте созданный отчет в `/reports`. Каждый запуск сохраняется отдельно; история конкретной машины доступна по кнопке «История» в таблице хостов.

Для стенда дополнительные проверки выполняются только с control node: `ssh-audit` проверяет криптографию SSH, Nmap — доступные TCP-сервисы, а Lynis передается во временный каталог ВМ и удаляется после аудита. OpenSCAP и Trivy для виртуальных машин предназначены для отдельного offline-worker'а, который сканирует снимки дисков, а не работающие гостевые ОС.

Сканирование локальной сети на `/hosts` является вспомогательным действием: оно ищет SSH-доступные IP и подставляет
их в форму добавления, но не сохраняет хосты автоматически.

## Создание новых playbook'ов

Откройте `/playbooks`, выберите шаблон и создайте playbook. Пользовательские файлы сохраняются в:

```text
ansible/playbooks/custom/<id>.yml
ansible/playbooks/custom/<id>.meta.json
```

Перед запуском используйте `Syntax-check`. Response-playbook'и запускаются только с явным `Limit`, например `server1`
или `linux_hosts`.

## Локальная сеть и Ansible

На главном сервере установите Ansible, создайте inventory и проверьте SSH-доступ:

```bash
sudo apt install ansible openssh-client python3
cp ansible/inventory.example.ini ansible/inventory.ini
ansible all -i ansible/inventory.ini -m ping
```

### SSH-доступ

Рекомендуемый способ подключения — SSH-ключи с главного сервера:

```bash
ssh-keygen -t ed25519 -C hcp-control
ssh-copy-id danil@192.168.1.10
ssh danil@192.168.1.10
ansible all -i ansible/inventory.ini -m ping
```

На целевом Linux-хосте должен быть включен SSH:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Парольный режим возможен для ручной проверки через `ansible --ask-pass --ask-become-pass`, но веб-панель рассчитана на ключевой SSH-доступ.

Собрать факты без установки агентов:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/collect-facts.yml
```

Запустить безагентный аудит:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/agentless-audit.yml -e audit_profile=basic_linux
```

Запустить response-playbook для выбранного хоста:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-dangerous-ports.yml --limit server1
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-port.yml --limit server1 -e target_port=23 -e target_protocol=tcp
ansible-playbook -i ansible/inventory.ini ansible/playbooks/update-package.yml --limit server1 -e package_name=openssl
ansible-playbook -i ansible/inventory.ini ansible/playbooks/block-ip.yml --limit server1 -e block_ip=192.168.1.50
ansible-playbook -i ansible/inventory.ini ansible/playbooks/stop-service.yml --limit server1 -e service_name=nginx
```

На сайте откройте `/hosts`, чтобы проверить Ansible control node, выполнить ping, запустить безагентный аудит и выполнить разрешенные response-playbook'и. Реальные отчеты сохраняются в `ansible/reports/` и не отправляются в GitHub.

Журнал инцидентов сохраняется локально в `ansible/incidents.json`, настройки планировщика — в `ansible/scheduler.json`.

На странице `/hosts` также есть автообнаружение хостов: платформа определяет локальную приватную подсеть, сканирует SSH-порт 22 и может добавить найденные IP в `ansible/inventory.ini`. Сканирование ограничено подсетями `/24`-`/30` и предназначено только для вашей локальной сети.

## Термины

- Аудит: проверка системы на небезопасные настройки.
- Результат проверки: найденная проблема, успешная проверка или пункт для ручного анализа.
- Исправление: действие для устранения найденной проблемы.
- Резервная копия: сохранение состояния перед изменением.
- Откат: возврат изменения к предыдущему состоянию.
- Профиль: набор правил под сценарий аудита.
- Главный сервер: компьютер, на котором запущены сайт, Ansible, inventory и отчеты.
- Безагентный аудит: проверка хостов по SSH без установки постоянного ПО на целевые устройства.
- Response-playbook: заранее разрешенное действие реагирования, например закрытие опасных портов.

## Контейнерный control node

Платформа не предназначена для Vercel: ей нужен приватный Linux control node с SSH-доступом к управляемым хостам.
Подготовленный контейнерный вариант описан в [deployment/README.md](deployment/README.md). Он хранит отчеты и журнал запусков в Docker volume, использует SSH-ключ из локального secret-файла и по умолчанию открывает веб-интерфейс только на `127.0.0.1`.

## Границы текущего production-режима

- В Docker Compose отключено создание и запуск пользовательских YAML playbook'ов из браузера; доступны только встроенные проверенные действия.
- Response-playbook'и действительно изменяют Linux-хосты. Перед их запуском нужны проверка отчета, резервная копия и окно обслуживания.
- Пока нет многопользовательской авторизации, RBAC, внешнего TLS-прокси, очереди заданий и неизменяемого журнала аудита. Поэтому не размещайте панель в интернете и не подключайте к ней критичные production-серверы до внедрения этих механизмов.
- Нет постоянных агентов на управляемых хостах: базовая платформа использует SSH и Ansible.

## Roadmap

См. `docs/future-roadmap.md`.
