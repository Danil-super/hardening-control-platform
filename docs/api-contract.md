# Agent API Contract

Первая версия агента поддерживает безопасный `audit-only` режим и возвращает JSON. Изменения ОС, remediation и rollback пока не выполняются.

## Audit

```http
POST /agent/audit
```

## Local Agent Bridge

Для автоматического импорта веб-интерфейс может обращаться к локальному bridge-серверу агента:

```bash
cd agent
python3 server.py
```

Endpoints:

```http
GET http://127.0.0.1:8765/health
GET http://127.0.0.1:8765/profiles
GET http://127.0.0.1:8765/audit?profile=basic_linux
POST http://127.0.0.1:8765/audit
```

POST body:

```json
{
  "profileId": "basic_linux"
}
```

Request:

```json
{
  "profileId": "basic_linux",
  "mode": "audit_only"
}
```

Response:

```json
{
  "auditId": "agent_audit_basic_linux_20260602150000",
  "createdAt": "2026-06-02T15:00:00+00:00",
  "hostname": "ubuntu-server",
  "os": "Ubuntu 24.04",
  "profileId": "basic_linux",
  "mode": "agent",
  "agent": {
    "version": "0.1.0",
    "safeMode": true,
    "remediationEnabled": false,
    "user": "admin"
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

## Remediation

В версии `0.1.0` remediation является no-op и не изменяет ОС.

```http
POST /agent/remediate
```

Request:

```json
{
  "auditId": "audit_001",
  "remediationIds": ["disable_ssh_root_login", "enable_ufw"],
  "createBackup": true
}
```

Response:

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
