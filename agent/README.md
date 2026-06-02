# Linux Agent

Это первая безопасная версия локального Linux Agent для Hardening Control Platform.

Агент работает в режиме `audit-only`: читает доступные конфигурации, выполняет безопасные команды проверки и возвращает JSON. Он не изменяет ОС, не перезапускает службы, не включает firewall и не применяет remediation.

## Запуск

```bash
python3 agent.py audit --profile basic_linux --pretty
python3 agent.py audit --profile ssh_security --pretty
python3 agent.py audit --profile web_server --pretty
python3 agent.py audit --profile docker_host --pretty
```

Поддерживаемые профили:

- `basic_linux`
- `ssh_security`
- `web_server`
- `docker_host`

## Что проверяется сейчас

- `/etc/os-release` для определения ОС.
- `/etc/ssh/sshd_config` для проверки root login, password auth и пустых паролей.
- `ufw status` для состояния UFW.
- наличие `fail2ban-client`.
- `/etc/apt/apt.conf.d/20auto-upgrades` и `apt-check` для обновлений.
- ограниченная проверка world-writable файлов в `/tmp` и `/var/tmp`.
- Nginx-конфигурации для server tokens, security headers и HTTPS.
- Docker CLI для privileged containers, docker.sock и root user, если Docker доступен.

## Безопасность

Команды `remediate` и `rollback` пока являются no-op:

```bash
python3 agent.py remediate --audit audit_001 --remediation disable_ssh_root_login
python3 agent.py rollback --backup backup_2026_06_02_001
```

Они возвращают JSON со статусом `not_implemented` и не выполняют системные изменения.

## Будущее развитие

- Реальный Backup Manager.
- Реальный Remediation Manager.
- Rollback Manager.
- Интеграция Lynis.
- Интеграция OpenSCAP.
- YAML-правила для пользовательских проверок.
