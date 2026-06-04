# Ansible control node

Этот каталог предназначен для главного компьютера в локальной сети. На нем запускаются сайт, Ansible и playbook'и для удаленного audit-only мониторинга Linux-хостов.

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

## Установка audit-only агента на хосты

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/install-agent.yml
```

Playbook создает `/opt/hcp-agent` и копирует туда `agent.py` и `server.py`. Он не меняет security-настройки ОС.

## Audit-only запуск

Базовый аудит:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/audit.yml -e audit_profile=basic_linux
```

Аудит с Lynis:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/audit-lynis.yml -e audit_profile=basic_linux
```

Аудит с Lynis и OpenSCAP:

```bash
ansible-playbook -i ansible/inventory.ini ansible/playbooks/audit-openscap.yml -e audit_profile=basic_linux
```

Отчеты сохраняются на главном компьютере в `ansible/reports/`.

## Важно

- Audit playbook'и используют `changed_when: false`.
- Они запускают `agent.py audit` и возвращают JSON.
- Они не выполняют `remediate`, не меняют firewall, SSH, Nginx или Docker.
- Реальные исправления нужно добавлять отдельными playbook'ами только после backup, `--check` и подтверждения администратора.
