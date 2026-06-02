# API-контракт агента

Первая версия агента поддерживает безопасный режим “только аудит” и возвращает JSON. Изменения ОС, исправления и откат пока не выполняются.

## Аудит

```http
POST /agent/audit
```

## Локальный промежуточный сервер

Для автоматического импорта веб-интерфейс может обращаться к локальному промежуточному серверу агента:

```bash
cd agent
python3 server.py
```

Локальные endpoints:

```http
GET http://127.0.0.1:8765/health
GET http://127.0.0.1:8765/profiles
GET http://127.0.0.1:8765/audit?profile=basic_linux
GET http://127.0.0.1:8765/audit?profile=basic_linux&includeLynis=1
POST http://127.0.0.1:8765/audit
```

Тело POST-запроса:

```json
{
  "profileId": "basic_linux",
  "includeLynis": true
}
```

Запрос:

```json
{
  "profileId": "basic_linux",
  "mode": "audit_only",
  "includeLynis": true
}
```

Ответ:

```json
{
  "auditId": "agent_audit_basic_linux_20260602150000",
  "createdAt": "2026-06-02T15:00:00+00:00",
  "hostname": "ubuntu-server",
  "os": "Ubuntu 24.04",
  "profileId": "basic_linux",
  "mode": "agent",
  "agent": {
    "version": "0.2.0",
    "safeMode": true,
    "remediationEnabled": false,
    "user": "admin",
    "integrations": {
      "lynis": {
        "enabled": true,
        "findings": 4
      }
    }
  },
  "findings": [],
  "summary": {
    "high": 3,
    "medium": 7,
    "low": 5,
    "score": 68
  }
}
```

## Исправления

В версии `0.2.0` исправления являются безопасной заглушкой и не изменяют ОС.

```http
POST /agent/remediate
```

Запрос:

```json
{
  "auditId": "audit_001",
  "remediationIds": ["disable_ssh_root_login", "enable_ufw"],
  "createBackup": true
}
```

Ответ:

```json
{
  "status": "not_implemented",
  "command": "remediate",
  "createdAt": "2026-06-02T15:00:00+00:00",
  "message": "Первая версия агента поддерживает только безопасный audit-only режим. Изменения ОС не выполняются.",
  "audit": "audit_001",
  "remediation": "disable_ssh_root_login",
  "backup": null
}
```
