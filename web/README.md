# Hardening Control Platform Web

Локальный интерфейс control node для inventory, безагентного Ansible-аудита, отчетов и транзакционных firewall-изменений.

```bash
npm ci
cp .env.example .env.local
npm run typecheck
npm test
npm run dev
```

Задайте `HCP_ADMIN_PASSWORD`, отдельный `HCP_AUTH_SECRET` и `HCP_AUDIT_HMAC_KEY` в `.env.local`. Для контейнерного окружения также передаются `HCP_STATE_DIR`, `HCP_REPORTS_DIR` и путь к SSH-ключу.

Основные маршруты:

- `/hosts` — добавление хостов, preflight, профили и контролируемые remediation-транзакции;
- `/playbooks` — только встроенные audit-playbook'и; пользовательские read-only аудиты доступны в development лишь с `HCP_ENABLE_CUSTOM_AUDITS=true`;
- `/reports` — реальные JSON-отчеты;
- `/api/ansible/incidents` — append-only журнал с проверкой hash-chain целостности.

Интерфейс нужно запускать только в локальном приватном контуре с доступом по SSH к управляемым хостам. Он не предназначен для Vercel или публичного размещения.
