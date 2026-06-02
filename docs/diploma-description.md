# Diploma Description

Topic: development of an extensible web platform for auditing and secure hardening of Linux servers with support for remediation, backup, rollback and before/after reporting.

The project demonstrates a complete security workflow without requiring root access or a live Linux target:

1. Select an audit profile.
2. Run a demo audit.
3. Review findings and risk levels.
4. Select remediation actions.
5. Simulate backup and remediation.
6. Run a demo re-audit.
7. Export the before/after report.

The MVP is intentionally a browser-safe demo suitable for GitHub and Vercel. It is not a replacement for Lynis, OpenSCAP or SCAP Security Guide; it is a management and demonstration layer that can later integrate these tools through a local agent.
