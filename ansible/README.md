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

## Offline-контур образов ВМ

Для будущего production-развертывания OpenSCAP и Trivy нужно запускать не через SSH на работающем сервере, а на копии снимка диска, доступной control node или отдельному scanner worker. Это подходит только для виртуальных серверов с API гипервизора; физические серверы продолжают проверяться Ansible по SSH.

1. Гипервизор создает read-only snapshot/clone диска и передает его worker'у.
2. Worker запускает `oscap-vm` для CIS/SCAP и `trivy vm` для CVE образа.
3. Worker сохраняет отчеты в хранилище HCP и удаляет рабочую копию снимка.

Этот контур намеренно не подключен к кнопке аудита: ему нужны доступ к API гипервизора, политика хранения снимков и отдельные права. Он не должен устанавливать OpenSCAP или Trivy в гостевой ОС.

## Базовый аудит конфигурации

Основной аудит выполняет `ansible/playbooks/agentless-audit.yml`. Он не использует внешнюю CVE-БД: playbook собирает состояние Linux-хоста и применяет локальные правила из `ansible/audit-rules/basic-linux.yml`.

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

Чтобы добавить новое правило, начните с `ansible/audit-rules/basic-linux.yml`. Если правило требует нового способа сбора данных, добавьте короткую проверку в `agentless-audit.yml` и сохраните результат как `finding` с evidence и recommendation.

OpenSCAP не используется как обязательный механизм аудита, потому что он требует scanner/content на проверяемой системе или отдельного offline-образа. Архитектура платформы остается без установки ПО на целевые хосты: Ansible собирает данные по SSH, а анализ выполняется правилами на главном сервере.

## Response-playbook

Response-playbook может менять настройки хоста, поэтому запускайте его только с `--limit` и после проверки отчета:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-dangerous-ports.yml --limit server1
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-port.yml --limit server1 -e target_port=23 -e target_protocol=tcp
ansible-playbook -i ansible/inventory.ini ansible/playbooks/update-package.yml --limit server1 -e package_name=openssl
ansible-playbook -i ansible/inventory.ini ansible/playbooks/block-ip.yml --limit server1 -e block_ip=192.168.1.50
ansible-playbook -i ansible/inventory.ini ansible/playbooks/stop-service.yml --limit server1 -e service_name=nginx
```

`close-dangerous-ports.yml` блокирует распространенные опасные порты через активный `ufw` или `firewalld`. Если поддерживаемый firewall не активен, playbook выводит предупреждение и не закрывает порты.

## Важно

- Безагентные audit playbook'и используют `changed_when: false`.
- Система не устанавливает постоянные агенты на управляемые хосты.
- Response-playbook'и отделены от аудита и требуют явного выбора хоста или группы.
- Реальные исправления нужно запускать только после анализа отчета, backup-плана и подтверждения администратора.
