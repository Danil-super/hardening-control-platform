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

## Безагентный режим

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/collect-facts.yml
ansible-playbook -i ansible/inventory.ini ansible/playbooks/agentless-audit.yml -e audit_profile=basic_linux
```

Эти playbook'и ничего не устанавливают на хосты. Ansible подключается по SSH, собирает факты, проверяет открытые порты, firewall и сохраняет JSON-отчеты на главном компьютере в `ansible/reports/`.

## Response-playbook

Response-playbook может менять настройки хоста, поэтому запускайте его только с `--limit` и после проверки отчета:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/close-dangerous-ports.yml --limit server1
```

`close-dangerous-ports.yml` блокирует распространенные опасные порты через активный `ufw` или `firewalld`. Если поддерживаемый firewall не активен, playbook выводит предупреждение и не закрывает порты.

## Опциональный audit-only агент

Агент не обязателен для базовой работы платформы. Его можно использовать как расширенный локальный сборщик, если нужны более глубокие проверки или интеграции.

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/install-agent.yml
ansible-playbook -i ansible/inventory.ini ansible/playbooks/audit-lynis.yml -e audit_profile=basic_linux
ansible-playbook -i ansible/inventory.ini ansible/playbooks/audit-openscap.yml -e audit_profile=basic_linux
```

Playbook установки создает `/opt/hcp-agent` и копирует туда `agent.py` и `server.py`.

## Важно

- Безагентные audit playbook'и используют `changed_when: false`.
- Базовый режим не требует установки постоянного агента на каждый хост.
- Response-playbook'и отделены от аудита и требуют явного выбора хоста или группы.
- Реальные исправления нужно запускать только после анализа отчета, backup-плана и подтверждения администратора.
