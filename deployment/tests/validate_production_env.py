#!/usr/bin/env python3
"""Read-only local release preflight for HCP .env secrets and exposure.

This does NOT attest randomness, Docker health, SSH identity, CVE coverage or
network isolation. It emits field names and codes, never secret values.
"""
import argparse
import json
import os
import re
import stat
import sys

MAX_BYTES = 65536
REQUIRED = {
    "HCP_ADMIN_PASSWORD": 16,
    "HCP_AUTH_SECRET": 32,
    "HCP_AUDIT_HMAC_KEY": 32,
    "HCP_SCHEDULE_API_KEY": 32,
}
PLACEHOLDER = re.compile(
    r"(replace.with|change.?me|your.?password|your.?secret|example|test.?password)",
    re.I,
)
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def read_env_file(path):
    original = os.lstat(path)
    if not stat.S_ISREG(original.st_mode):
        raise ValueError("env_not_regular")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("env_not_regular")
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(original, field) for field in fields):
            raise ValueError("env_changed")
        if before.st_size < 1 or before.st_size > MAX_BYTES:
            raise ValueError("env_size_invalid")
        if before.st_mode & 0o077:
            raise ValueError("env_permissions_too_open")
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(descriptor, min(16384, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if (len(data) != before.st_size or
                any(getattr(before, field) != getattr(after, field) or
                    getattr(after, field) != getattr(current, field)
                    for field in fields)):
            raise ValueError("env_changed")
        text = data.decode("utf-8", "strict")
        values = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            name = name.strip()
            if not separator or not KEY.fullmatch(name) or name in values:
                raise ValueError("env_syntax_or_duplicate")
            value = value.strip()
            if value and value[0] in ("'", '"'):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ValueError("env_unsupported_quoting")
                value = value[1:-1]
            values[name] = value
        return values
    finally:
        os.close(descriptor)


def assess(values, with_dependency_track=False):
    issues = []
    observations = []

    def problem(field, code):
        issues.append({"field": field, "code": code, "severity": "blocker"})

    all_secrets = dict(REQUIRED)
    if with_dependency_track:
        all_secrets["HCP_DEPENDENCY_TRACK_DB_PASSWORD"] = 20

    seen = {}
    for field, minimum in all_secrets.items():
        value = values.get(field)
        if not isinstance(value, str) or not value:
            problem(field, "secret_missing")
            continue
        if (len(value.encode("utf-8")) < minimum or PLACEHOLDER.search(value)
                or len(set(value)) < 6):
            problem(field, "secret_weak_or_template")
        if value in seen:
            problem(field, "secret_matches_other_field")
        else:
            seen[value] = field

    bind = values.get("HCP_BIND_ADDRESS", "127.0.0.1")
    if bind not in ("127.0.0.1", "::1", "localhost"):
        observations.append({"field": "HCP_BIND_ADDRESS",
                             "code": "remote_bind_requires_independent_network_review",
                             "severity": "warning"})
    if values.get("HCP_TRUSTED_TLS_PROXY", "").lower() == "true":
        observations.append({"field": "HCP_TRUSTED_TLS_PROXY",
                             "code": "reverse_proxy_must_overwrite_forwarded_headers",
                             "severity": "warning"})
    return {
        "schemaVersion": 1, "status": "blocked" if issues else "passed",
        "checks": {"requiredSecretFields": len(all_secrets), "fileReadOnly": True},
        "blockers": issues, "warnings": observations,
        "note": "Static configuration only; does not certify runtime, randomness, network protection or CVE coverage.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=".env", help="Local .env path; never logged")
    parser.add_argument("--with-dependency-track", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = assess(read_env_file(args.env), args.with_dependency_track)
    except (OSError, ValueError, UnicodeError) as error:
        code = str(error) if isinstance(error, ValueError) and str(error).startswith("env_") else "env_unreadable"
        result = {
            "schemaVersion": 1, "status": "blocked",
            "checks": {"fileReadOnly": True},
            "blockers": [{"field": ".env", "code": code, "severity": "blocker"}],
            "warnings": [], "note": "No secret contents are logged.",
        }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("Production env preflight: " + result["status"])
        for item in result["blockers"] + result["warnings"]:
            print(item["severity"] + ": " + item["field"] + " (" + item["code"] + ")")
        print(result["note"])
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
