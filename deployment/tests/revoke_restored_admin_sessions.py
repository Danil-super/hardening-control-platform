#!/usr/bin/env python3
"""Explicit local session revocation for a STOPPED, ISOLATED restored HCP DB.

The default mode only previews session-row counts. Apply deletes ONLY rows
from admin_sessions after matching the operator's exact current DB SHA-256.
No secrets, token hashes, user data or local paths appear in output.
Not an online logout and not a substitute for verifying the HMAC audit chain.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from urllib.parse import quote

CHUNK = 1024 * 1024
MAX_DB = 8 * 1024**3
SHA = re.compile(r"^[a-f0-9]{64}$")
CONFIRM = "INVALIDATE_ONLY_ISOLATED_RESTORED_HCP_SESSIONS"
REQUIRED_COLUMNS = {"token_hash", "credential_generation", "created_at", "expires_at"}


class GateFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def demand(valid, code):
    if not valid:
        raise GateFailure(code)


def snapshot_db(runtime):
    base = Path(runtime)
    mode = os.lstat(base)
    demand(stat.S_ISDIR(mode.st_mode), "restored_directory_invalid")
    base_fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        first = os.fstat(base_fd)
        demand((first.st_ino, first.st_dev) == (mode.st_ino, mode.st_dev),
               "restored_directory_changed")
        for suffix in ("-wal", "-shm"):
            try:
                os.stat("hcp.sqlite" + suffix, dir_fd=base_fd, follow_symlinks=False)
                raise GateFailure("sqlite_wal_requires_offline_review")
            except FileNotFoundError:
                pass
        fd = os.open("hcp.sqlite", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), dir_fd=base_fd)
        try:
            original = os.fstat(fd)
            demand(stat.S_ISREG(original.st_mode) and 0 < original.st_size <= MAX_DB
                   and (original.st_mode & 0o077) == 0,
                   "sqlite_file_not_private_regular")
            sha = hashlib.sha256()
            amount = 0
            while True:
                part = os.read(fd, CHUNK)
                if not part:
                    break
                amount += len(part)
                demand(amount <= MAX_DB, "sqlite_too_large")
                sha.update(part)
            current = os.fstat(fd)
            demand(amount == original.st_size and all(
                getattr(original, field) == getattr(current, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
                "sqlite_changed_during_read")
            return sha.hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(base_fd)


def sql_uri(runtime, readonly):
    path = Path(runtime) / "hcp.sqlite"
    query = "?mode=ro&immutable=1" if readonly else "?mode=rw"
    return "file:" + quote(os.path.abspath(str(path))) + query


def validate_schema(conn):
    rows = conn.execute("PRAGMA table_info(admin_sessions)").fetchall()
    demand({row[1] for row in rows} == REQUIRED_COLUMNS,
           "session_schema_unexpected")


def count_sessions(conn):
    validate_schema(conn)
    result = conn.execute("SELECT COUNT(*) FROM admin_sessions").fetchone()
    demand(result and type(result[0]) is int and result[0] >= 0,
           "session_count_invalid")
    return result[0]


def preview(runtime):
    digest = snapshot_db(runtime)
    conn = sqlite3.connect(sql_uri(runtime, True), uri=True, timeout=3)
    try:
        before = conn.execute("PRAGMA integrity_check").fetchone()
        demand(before and before[0] == "ok", "sqlite_integrity_failed")
        total = count_sessions(conn)
    finally:
        conn.close()
    demand(digest == snapshot_db(runtime), "sqlite_changed_during_preview")
    return {"schemaVersion": 1, "status": "preview-only",
            "databaseSha256": digest, "storedSessionHashes": total,
            "revocationPerformed": False, "databaseRestorationVerified": False}


def revoke(runtime, expected_sha):
    demand(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha),
           "expected_sqlite_digest_invalid")
    observed_sha = snapshot_db(runtime)
    demand(observed_sha == expected_sha, "sqlite_digest_mismatch")
    conn = sqlite3.connect(sql_uri(runtime, False), uri=True, timeout=5,
                           isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("BEGIN IMMEDIATE")
        validate_schema(conn)
        # A transactional exclusive test plus the previous operator gate is
        # required; only this table is edited, no audit-chain entries rewritten.
        current = count_sessions(conn)
        conn.execute("DELETE FROM admin_sessions")
        demand(count_sessions(conn) == 0, "session_revocation_incomplete")
        conn.execute("COMMIT")
    except BaseException:
        with conn:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    verified = preview(runtime)
    demand(verified["storedSessionHashes"] == 0,
           "session_revocation_postcheck_failed")
    return {
        "schemaVersion": 1,
        "status": "restored-admin-session-hashes-revoked",
        "sessionsRemoved": current,
        "remainingSessionHashes": 0,
        "databaseSha256Before": observed_sha,
        "databaseSha256After": verified["databaseSha256"],
        "performedAtUtc": datetime.now(timezone.utc).isoformat(),
        "revocationPerformed": True,
        "hmacChainVerified": False,
        "oldBrowserCookiesTested": False,
        "originalControllerIsolationIndependentlyVerified": False,
        "limitations": [
            "This edits ONLY admin_sessions in an operator-declared isolated stopped restoration.",
            "The tool cannot independently prove that the path is not the active production volume.",
            "Old cookies must be tested against the restored server after startup.",
            "HMAC audit chain, login and remote SSH are separate release acceptance gates.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restored-runtime", required=True,
                        help="Existing isolated offline volume path, not original production data")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-isolated-stopped", action="store_true")
    parser.add_argument("--confirm-text", help="Required typed revocation confirmation")
    parser.add_argument("--expected-db-sha256",
                        help="Current exact digest from a separate read-only preview")
    parser.add_argument("--output", help="New JSON protocol outside runtime")
    args = parser.parse_args(argv)
    if args.apply:
        demand(args.confirm_isolated_stopped and args.confirm_text == CONFIRM,
               "explicit_isolated_restore_confirmation_required")
        demand(bool(args.output), "private_revocation_receipt_required")
        output = os.path.abspath(args.output)
        demand(os.path.dirname(output) != os.path.abspath(args.restored_runtime),
               "receipt_must_be_outside_runtime")
        demand(not os.path.lexists(output), "receipt_already_exists")
        result = revoke(args.restored_runtime, args.expected_db_sha256)
        descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
    else:
        result = preview(args.restored_runtime)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (GateFailure, OSError, sqlite3.Error, UnicodeError, ValueError) as exc:
        code = exc.code if isinstance(exc, GateFailure) else "restored_db_unavailable"
        print(json.dumps({"schemaVersion": 1, "status": "blocked",
                          "reasonCode": code, "revocationVerified": False}))
        sys.exit(1)
