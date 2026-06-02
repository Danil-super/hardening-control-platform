# Architecture

Hardening Control Platform is split into a web demo platform and a future local Linux Agent.

```text
Web Platform
  Dashboard
  Profiles
  Demo Audit Engine
  Findings Viewer
  Remediation Planner
  Backup Simulation
  Before/After Report
  Export JSON

Future Linux Agent
  OS Detection
  Lynis Runner
  OpenSCAP Runner
  Custom Rule Engine
  Backup Manager
  Remediation Manager
  Rollback Manager
```

The MVP keeps all audit data in local TypeScript modules. Remediation is simulated in the browser: selected actions produce backup records, mark matching findings as fixed, rerun the demo audit model and generate a before/after report.

The web layer is prepared for agent integration by using typed entities: `AuditProfile`, `Finding`, `Remediation`, `AuditReport`, `BackupRecord` and `BeforeAfterReport`.
