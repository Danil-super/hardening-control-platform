"""Placeholder for the future Hardening Control Platform Linux Agent."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def main() -> None:
    parser = argparse.ArgumentParser(description="Future Linux Agent placeholder")
    parser.add_argument("command", choices=["audit", "remediate", "rollback"])
    parser.add_argument("--profile", default="basic_linux")
    parser.add_argument("--audit")
    parser.add_argument("--remediation")
    parser.add_argument("--backup")
    args = parser.parse_args()

    print(
        json.dumps(
            {
                "status": "placeholder",
                "command": args.command,
                "profile": args.profile,
                "audit": args.audit,
                "remediation": args.remediation,
                "backup": args.backup,
                "createdAt": datetime.now(timezone.utc).isoformat(),
                "message": "Real host checks and changes are intentionally not implemented in MVP.",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
