# Ansible control node

Этот каталог предназначен для главного компьютера в локальной сети. На нем запускаются сайт, Ansible и playbook'и для безагентного мониторинга Linux-хостов по SSH.

## Установка на главном компьютере

```bash
sudo apt update
sudo apt install ansible openssh-client python3
```

Скопируйте пример inventory:

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
```

Отредактируйте `ansible/inventory.ini`: укажите IP-адреса, SSH-пользователя и способ повышения прав.

Проверьте доступность хостов:

```bash
ansible all -i ansible/inventory.ini -m ping
```

## SSH-ключи

На главном сервере создайте ключ и добавьте его на каждый управляемый Linux-хост:

```bash
ssh-keygen -t ed25519 -C hcp-control
ssh-copy-id danil@192.168.1.10
ssh danil@192.168.1.10
```

Если на хосте не установлен SSH-сервер:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Парольный режим подходит только для ручной отладки: `ansible all -i ansible/inventory.ini -m ping --ask-pass --ask-become-pass`.

## Безагентный режим

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/collect-facts.yml
ansible-playbook -i ansible/inventory.ini ansible/playbooks/agentless-audit.yml -e audit_profile=basic_linux
ansible-playbook -i ansible/inventory.ini ansible/playbooks/package-inventory.yml --limit server1
ansible-playbook -i ansible/inventory.ini ansible/playbooks/collect-security-events.yml
```

Эти playbook'и ничего не устанавливают на хосты. Ansible подключается по SSH, собирает факты, проверяет открытые порты, firewall и сохраняет JSON-отчеты на главном компьютере в `ansible/reports/`.

### Граница безагентной модели

На целевой ВМ не должны появляться scanner-пакеты, службы, таймеры, агенты или постоянные файлы платформы. Во время проверки Ansible лишь выполняет по SSH штатные команды уже установленной ОС (`ss`, `sshd`, `systemctl`, `dpkg-query`, `journalctl`/чтение логов) и кратковременный код на системном `python3`; он не сохраняется на ВМ. Правила оценки, интерфейс, Ansible, ключи доступа, хранилище отчетов и любые дополнительные сетевые сканеры находятся на главной машине.

## Дополнительные инструменты на control node

Для стенда установите инструменты **только на главной машине**:

```bash
sudo apt update
sudo apt install lynis nmap ssh-audit
```

- `SSH crypto` запускает `ssh-audit` с control node и проверяет сетевую криптографическую конфигурацию SSH. Подключение к SSH-порту не требует учетной записи на ВМ и ничего на ней не изменяет.
- `Порты` запускает Nmap с control node только для выбранного inventory-хоста. Проверяются top-100 TCP-портов в режиме TCP connect scan; действие требует подтверждения в UI.
- `Lynis временно` копирует `/usr/sbin/lynis` и его данные из `/usr/share/lynis` с control node во временный каталог выбранной ВМ, запускает его с `sudo`, получает только машиночитаемый отчет и удаляет временный каталог в блоке `always`. Это **не установка** Lynis, но временное выполнение его кода на ВМ необходимо для глубокого аудита ОС.

Все три действия создают отдельный JSON-отчет в `ansible/reports/`. Нормализация результатов и хранение отчетов выполняются на control node.

## OpenSCAP и Trivy

`Проверить SSG-профиль OpenSCAP` доступна из панели как отдельный audit. Для корректного результата на ВМ заранее должны быть подготовлены `oscap`, SSG datastream и согласованный профиль. HCP не устанавливает их автоматически и не угадывает datastream: задайте `HCP_OPENSCAP_DATASTREAM` и `HCP_OPENSCAP_PROFILE` на control node. Во время запуска создаётся только временный ARF, который затем удаляется с ВМ.

Проверка пакетов создаёт CycloneDX SBOM и запускает Trivy на control node. В изолированной сети используйте `HCP_TRIVY_MODE=offline` и внутреннее зеркало его баз. Без готовой базы отчёт помечается неполным, а не безопасным. Полная процедура — в `docs/audit-integrations.md`.

## Базовый аудит конфигурации

Основной аудит выполняет `ansible/playbooks/agentless-audit.yml`. Он не использует внешнюю CVE-БД: playbook собирает состояние Linux-хоста и загружает набор локальных правил, соответствующий `audit_profile`.

Доступные правила: `basic-linux.yml`, `ssh-security.yml`, `web-server.yml` и `docker-host.yml`. Все наборы версионированы и являются реальными Ansible-проверками, а не данными интерфейса.

Сейчас проверяются:

- опасные открытые порты;
- ключевые параметры SSH: root login, парольный вход, пустые пароли, MaxAuthTries;
- активность firewall через ufw или firewalld;
- наличие fail2ban и auditd;
- механизм автоматических security-обновлений;
- доступные обновления пакетов;
- sudo-группы и NOPASSWD;
- учетные записи без пароля;
- последние неудачные попытки входа;
- небезопасные world-writable директории.

Чтобы добавить новое правило, начните с подходящего файла в `ansible/audit-rules/`. Если правило требует нового способа сбора данных, добавьте короткую проверку в `agentless-audit.yml` и сохраните результат как `finding` с evidence и recommendation.

OpenSCAP не используется как обязательный механизм аудита, потому что он требует scanner/content на проверяемой системе или отдельного offline-образа. Архитектура платформы остается без установки ПО на целевые хосты: Ansible собирает данные по SSH, а анализ выполняется правилами на главном сервере.

## Response-playbook

Панель запускает только обратимые firewall-действия через транзакционный контур: dry-run, backup, применение, audit «после» и rollback. При ручном запуске playbook'ов соблюдайте тот же порядок:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/backup-remediation.yml --limit server1 \
  -e transaction_id=txn-example-001 -e remediation_action=closePort
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-port.yml --limit server1 \
  -e target_port=23 -e target_protocol=tcp
ansible-playbook -i ansible/inventory.ini ansible/playbooks/rollback-remediation.yml --limit server1 \
  -e transaction_id=txn-example-001 -e remediation_action=closePort
```

`backup-remediation.yml` архивирует конфигурации UFW/firewalld на целевом хосте. `rollback-remediation.yml` восстанавливает этот архив и перезагружает firewall. Не запускайте автоматически обновление пакетов и остановку сервисов: общий надежный откат таких действий требует отдельной процедуры.

## Важно

- Безагентные audit playbook'и используют `changed_when: false`.
- Система не устанавливает постоянные агенты на управляемые хосты.
- Response-playbook'и отделены от аудита и требуют явного выбора хоста или группы.
- Реальные исправления нужно запускать только после анализа отчета, backup-плана и подтверждения администратора.
