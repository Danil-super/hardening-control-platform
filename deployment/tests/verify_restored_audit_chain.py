#!/usr/bin/env python3
"""Read-only HMAC audit-chain check for an isolated, stopped restored HCP DB.

Exact supported encoding: state-store.ts hash_version 2 canonical JSON, and
legacy version 1's top-level JSON.stringify replacer array. Only event counts
and digests, never payload, secrets, keys, paths or token hashes are emitted.
A valid chain signed by the same local key is NOT independent attestation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import quote
from validate_production_env import read_env_file

LIMIT = 1000000
SHA = re.compile(r"^[a-f0-9]{64}$")
REQUIRED = {"created_at", "event_type", "entity_id", "payload_json",
            "previous_hash", "entry_hash", "hash_version"}


class ChainFailure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def demand(condition, code):
    if not condition:
        raise ChainFailure(code)


def sort_keys(value):
    return sorted(value, key=lambda item: item.encode("utf-16-be", "surrogatepass"))


def canonical(value):
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sort_keys(value)}
    return value


def legacy(value, allowed):
    if isinstance(value, list):
        return [legacy(item, allowed) for item in value]
    if isinstance(value, dict):
        return {key: legacy(value[key], allowed)
                for key in allowed if key in value}
    return value


def js_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8", "strict")


def calculate_hash(event, key, version):
    if version == 2:
        encoded = js_json(canonical(event))
    elif version == 1:
        encoded = js_json(legacy(event, sort_keys(event)))
    else:
        raise ChainFailure("audit_hash_version_unsupported")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def sqlite_digest(runtime):
    base = Path(runtime)
    before_dir = os.lstat(base)
    demand(stat.S_ISDIR(before_dir.st_mode), "restored_directory_invalid")
    root = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY |
                   getattr(os, "O_NOFOLLOW", 0))
    try:
        dirstat = os.fstat(root)
        demand((dirstat.st_ino, dirstat.st_dev) ==
               (before_dir.st_ino, before_dir.st_dev),
               "restored_directory_changed")
        for suffix in ("-wal", "-shm"):
            try:
                os.stat("hcp.sqlite" + suffix, dir_fd=root,
                        follow_symlinks=False)
                raise ChainFailure("sqlite_wal_needs_separate_recovery")
            except FileNotFoundError:
                pass
        fd = os.open("hcp.sqlite", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), dir_fd=root)
        try:
            st = os.fstat(fd)
            demand(stat.S_ISREG(st.st_mode) and st.st_size > 0
                   and st.st_size <= 8 * 1024**3 and not (st.st_mode & 0o077),
                   "restored_sqlite_unsafe")
            sha = hashlib.sha256()
            size = 0
            while True:
                data = os.read(fd, 1048576)
                if not data:
                    break
                sha.update(data)
                size += len(data)
                demand(size <= 8 * 1024**3, "restored_sqlite_too_large")
            final = os.fstat(fd)
            demand(size == st.st_size and all(
                getattr(st, field) == getattr(final, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
                "restored_sqlite_changed")
            return sha.hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(root)


def verify_events(runtime, key, *, require_payload_protection=False):
    demand(type(key) is bytes and len(key) >= 32, "audit_key_missing_or_short")
    before_sha = sqlite_digest(runtime)
    uri = "file:" + quote(os.path.abspath(os.path.join(runtime, "hcp.sqlite"))) + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    previous = None
    entries = 0
    legacy_count = 0
    try:
        sanity = conn.execute("PRAGMA integrity_check").fetchone()
        demand(sanity and sanity[0] == "ok", "sqlite_integrity_check_failed")
        columns = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)")}
        demand(REQUIRED.issubset(columns), "audit_table_schema_unexpected")
        cursor = conn.execute("""SELECT created_at, event_type, entity_id,
              payload_json, previous_hash, entry_hash, hash_version
              FROM audit_events ORDER BY rowid ASC""")
        for row in cursor:
            entries += 1
            demand(entries <= LIMIT, "audit_event_count_exceeds_limit")
            when, event_type, entity_id, payload_json, claimed_prev, claimed_hash, version = row
            demand(type(version) is int and version in (1, 2),
                   "audit_hash_version_unsupported")
            demand(isinstance(payload_json, str) and len(payload_json) <= 4 * 1024 * 1024,
                   "audit_payload_invalid_or_oversize")
            try:
                payload = json.loads(payload_json)
            except (ValueError, TypeError):
                raise ChainFailure("audit_payload_invalid_or_oversize")
            demand(isinstance(claimed_hash, str) and SHA.fullmatch(claimed_hash),
                   "audit_entry_hash_malformed")
            demand(claimed_prev == previous, "audit_chain_previous_hash_mismatch")
            event = {
                "createdAt": when, "eventType": event_type,
                "entityId": entity_id, "payload": payload,
                "previousHash": previous,
            }
            try:
                expected = calculate_hash(event, key, version)
            except (UnicodeError, ValueError, TypeError, OverflowError):
                raise ChainFailure("audit_json_encoding_invalid")
            demand(hmac.compare_digest(expected, claimed_hash),
                   "audit_entry_hmac_mismatch")
            if version == 1:
                legacy_count += 1
            previous = claimed_hash
        demand(entries > 0, "audit_history_empty")
        if require_payload_protection:
            demand(legacy_count == 0, "legacy_entries_payload_not_fully_protected")
    except sqlite3.DatabaseError:
        raise ChainFailure("audit_chain_database_error")
    finally:
        conn.close()
    demand(before_sha == sqlite_digest(runtime), "sqlite_changed_during_audit_verification")
    return {
        "schemaVersion": 1,
        "status": "hmac-chain-valid-with-stated-legacy-limits",
        "scope": "restored-HCP-audit-events-chain-only",
        "entries": entries,
        "legacyEntries": legacy_count,
        "payloadProtectedForAllEntries": legacy_count == 0,
        "lastEntryHash": previous,
        "restoredDatabaseSha256": before_sha,
        "checkedAtUtc": datetime.now(timezone.utc).isoformat(),
        "usedOriginalHcpAuditKey": "operator-supplied-from-restored-env",
        "publisherOrOperatorAuthenticated": False,
        "restoredLoginVerified": False,
        "sshRestorationVerified": False,
        "limitations": [
            "Matches hashes against the key inside the operator-provided protected .env; not independent authenticity.",
            "Legacy version 1 hash uses a JSON replacer and does not protect all nested payload fields.",
            "Does not prove old sessions were revoked, reports unchanged, or SSH/firewall restored.",
            "Requires an isolated stopped restored controller and an independent operational drill.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restored-runtime", required=True)
    parser.add_argument("--env", required=True, help="Private restored .env, never logged")
    parser.add_argument("--require-payload-protection", action="store_true",
                        help="Fail if any legacy v1 audit records exist")
    parser.add_argument("--acknowledge-stopped", action="store_true")
    parser.add_argument("--output", help="New private JSON protocol outside the restored volume")
    args = parser.parse_args(argv)
    demand(args.acknowledge_stopped, "isolated_stopped_restore_ack_required")
    values = read_env_file(args.env)
    key = values.get("HCP_AUDIT_HMAC_KEY")
    demand(type(key) is str and len(key.encode("utf-8")) >= 32,
           "audit_key_missing_or_short")
    result = verify_events(args.restored_runtime, key.encode("utf-8"),
                           require_payload_protection=args.require_payload_protection)
    if args.output:
        target = os.path.abspath(args.output)
        demand(os.path.dirname(target) not in
               (os.path.abspath(args.restored_runtime),
                os.path.abspath(os.path.dirname(args.env))),
               "output_must_be_separate_from_private_inputs")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode())
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(fd)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ChainFailure, OSError, ValueError, UnicodeError, sqlite3.Error) as error:
        code = error.code if isinstance(error, ChainFailure) else "audit_evidence_unreadable"
        print(json.dumps({"schemaVersion": 1, "status": "blocked",
                          "reasonCode": code, "hmacChainVerified": False}))
        sys.exit(1)
