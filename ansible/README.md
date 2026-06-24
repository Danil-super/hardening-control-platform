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
