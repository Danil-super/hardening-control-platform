# Future Linux Agent

This directory is a placeholder for the future local Linux Agent used by Hardening Control Platform.

The MVP web application does not execute system commands and does not change the host operating system. In the next stage the agent is expected to run on Ubuntu/Debian and return JSON results to the web platform.

Planned modules:

- OS detection through `/etc/os-release`
- Lynis runner and parser
- Optional OpenSCAP runner
- Custom YAML rule engine
- Backup manager
- Remediation manager
- Rollback manager

Example future commands:

```bash
python3 agent.py audit --profile basic_linux
python3 agent.py remediate --audit audit_001 --remediation disable_ssh_root_login
python3 agent.py rollback --backup backup_2026_06_02_001
```
