# Agent API Contract

The first version does not call a real agent. The contract below defines the planned JSON shape.

## Audit

```http
POST /agent/audit
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
  "auditId": "audit_001",
  "hostname": "ubuntu-server",
  "os": "Ubuntu 24.04",
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
  "status": "success",
  "backupId": "backup_2026_06_02_001",
  "applied": ["disable_ssh_root_login", "enable_ufw"],
  "failed": [],
  "validation": "passed"
}
```
