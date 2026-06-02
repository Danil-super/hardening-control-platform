# Linux-агент

Это первая безопасная версия локального Linux-агента для Hardening Control Platform.

Агент работает в режиме “только аудит”: читает доступные конфигурации, выполняет безопасные команды проверки и возвращает JSON. Он не изменяет ОС, не перезапускает службы, не включает межсетевой экран и не применяет исправления.

## Запуск

```bash
python3 agent.py audit --profile basic_linux --pretty
python3 agent.py audit --profile basic_linux --include-lynis --pretty
python3 agent.py audit --profile basic_linux --include-lynis --lynis-report-path ~/lynis-report.dat --pretty
python3 agent.py audit --profile ssh_security --pretty
python3 agent.py audit --profile web_server --pretty
python3 agent.py audit --profile docker_host --pretty
```

## Автоматический импорт в сайт

Запустите локальный промежуточный сервер:

```bash
python3 server.py
```

Остановить сервер можно через `Ctrl+C`. Это штатное завершение.

По умолчанию он слушает:

```text
http://127.0.0.1:8765
```

Доступные endpoints:

- `GET /health`
- `GET /profiles`
- `GET /audit?profile=basic_linux`
- `GET /audit?profile=basic_linux&includeLynis=1`
- `POST /audit` с JSON `{ "profileId": "basic_linux" }`

После запуска сервера откройте на сайте страницу `/agent/import` и нажмите `Получить аудит от агента`.
Импортированные отчеты сохраняются в истории браузера; на этой же странице можно сравнить два отчета.

Ручной вариант без промежуточного сервера:

```bash
python3 agent.py audit --profile basic_linux --pretty > agent-report.json
```

Затем загрузите `agent-report.json` на странице `/agent/import`.

Если вы уже находитесь в папке `agent`, повторно выполнять `cd agent` не нужно.

## Установка как systemd-сервис

Перед установкой можно посмотреть план действий без изменения системы:

```bash
./install.sh --dry-run
```

Установка файлов агента и unit-файла:

```bash
sudo ./install.sh
```

Установка с автозапуском и немедленным стартом:

```bash
sudo ./install.sh --enable --start
```

После запуска проверьте состояние:

```bash
./doctor.sh
curl http://127.0.0.1:8765/health
sudo systemctl status hcp-agent-bridge.service
```

По умолчанию сервис слушает только `127.0.0.1`, то есть не открывает внешний сетевой доступ.

## Диагностика

Скрипт `doctor.sh` проверяет наличие Python, синтаксис агента, выполняет один audit-only запуск и проверяет `/health`, если промежуточный сервер уже запущен:

```bash
./doctor.sh
./doctor.sh --profile ssh_security
```

## Удаление сервиса

Перед удалением можно посмотреть план:

```bash
sudo ./uninstall.sh --dry-run
```

Удалить unit-файл, остановить сервис и снять автозапуск:

```bash
sudo ./uninstall.sh
```

Удалить также установленные файлы агента:

```bash
sudo ./uninstall.sh --remove-files
```

Поддерживаемые профили:

- `basic_linux`
- `ssh_security`
- `web_server`
- `docker_host`

## Что проверяется сейчас

- `/etc/os-release` для определения ОС.
- `/etc/ssh/sshd_config` для проверки прямого входа root, входа по паролю и пустых паролей.
- `ufw status` для состояния UFW.
- наличие `fail2ban-client`.
- `/etc/apt/apt.conf.d/20auto-upgrades` и `apt-check` для обновлений.
- ограниченная проверка world-writable файлов в `/tmp` и `/var/tmp`.
- Nginx-конфигурации для раскрытия версии, защитных заголовков и HTTPS.
- Командная строка Docker для привилегированных контейнеров, docker.sock и root-пользователя, если Docker доступен.
- Опциональный запуск Lynis с нормализацией предупреждений и рекомендаций в единый формат отчета.
- Чтение `lynis-report.dat` из `/var/log`, домашнего каталога или явно указанного `--lynis-report-path`.

## Безопасность

Команды `remediate` и `rollback` пока являются безопасной заглушкой:

```bash
python3 agent.py remediate --audit audit_001 --remediation disable_ssh_root_login
python3 agent.py rollback --backup backup_2026_06_02_001
```

Они возвращают JSON со статусом `not_implemented` и не выполняют системные изменения.

## Будущее развитие

- Реальный менеджер резервных копий.
- Реальный менеджер исправлений.
- Менеджер отката.
- Интеграция OpenSCAP/SCAP Security Guide.
- YAML-правила для пользовательских проверок.
