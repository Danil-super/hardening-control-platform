#!/usr/bin/env python3
"""Read-only byte comparison of restored HCP runtime to a validated backup.

Runs on a NEW isolated control node, with HCP stopped. No Docker/SSH/network
commands, no extraction and no disclosure of private report, key or DB values.
This verifies critical bytes and SQLite structural integrity, not the HMAC
audit chain or actual host reachability.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tarfile
import time
from urllib.parse import quote

from verify_backup_bundle import (
    VerificationFailure, ensure, verify as verify_backup,
    normalized_tar_name, open_bundle, open_member, ensure_unchanged,
)

CHUNK = 1024 * 1024
MAX_CRITICAL_FILES = 150000
MAX_CRITICAL_BYTES = 96 * 1024**3


def is_critical(name):
    return name in ("hcp.sqlite", "inventory.ini", "known_hosts") or (
        name.startswith(("reports/", "ssh-host-keys/", "sbom/")))


def read_restored(root, target):
    """Open each target component using O_NOFOLLOW beneath a fixed root FD."""
    parts = target.split("/")
    ensure(parts and all(piece not in ("", ".", "..") for piece in parts),
           "restored_path_invalid")
    root_info = os.lstat(root)
    ensure(stat.S_ISDIR(root_info.st_mode), "restored_root_not_directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    current = os.open(root, flags)
    try:
        root_fd_stat = os.fstat(current)
        ensure((root_fd_stat.st_dev, root_fd_stat.st_ino) ==
               (root_info.st_dev, root_info.st_ino),
               "restored_root_changed")
        for piece in parts[:-1]:
            next_fd = os.open(piece, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_NONBLOCK", 0), dir_fd=current)
        try:
            original = os.fstat(file_fd)
            ensure(stat.S_ISREG(original.st_mode), "restored_critical_file_not_regular")
            if not target.endswith(".pub"):
                ensure(not (original.st_mode & 0o077),
                       "restored_private_file_permissions")
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(file_fd, CHUNK)
                if not chunk:
                    break
                length += len(chunk)
                ensure(length <= MAX_CRITICAL_BYTES, "restored_file_too_large")
                digest.update(chunk)
            ensure(length == original.st_size, "restored_critical_file_changed")
            ensure_unchanged(file_fd, original)
            return digest.hexdigest(), length
        finally:
            os.close(file_fd)
    finally:
        os.close(current)


def compare_runtime(backup_dir, restored_dir, require_enrolled_host=False):
    backup = verify_backup(backup_dir)
    tar_root = open_bundle(backup_dir)
    seen = set()
    count = 0
    critical_bytes = 0
    matched = {"sqlite": 0, "inventory": 0, "sshTrust": 0,
               "hostKeyFiles": 0, "reports": 0, "sbom": 0}
    archived_wal = False
    root = str(restored_dir)
    try:
        fd, original = open_member(tar_root, "runtime.tar.gz")
        try:
            with os.fdopen(os.dup(fd), "rb") as stream:
                try:
                    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
                        for item in archive:
                            name = normalized_tar_name(item.name)
                            if name in ("hcp.sqlite-wal", "hcp.sqlite-shm"):
                                archived_wal = True
                            if not is_critical(name):
                                continue
                            # A selected path must be a regular file. Never
                            # follow a symlink or reconstruct devices/links.
                            ensure(item.isfile(), "backup_critical_member_not_regular")
                            ensure(name not in seen, "backup_critical_duplicate")
                            seen.add(name)
                            count += 1
                            ensure(count <= MAX_CRITICAL_FILES, "critical_file_count_limit")
                            critical_bytes += item.size
                            ensure(critical_bytes <= MAX_CRITICAL_BYTES,
                                   "critical_data_size_limit")
                            extracted = archive.extractfile(item)
                            ensure(extracted is not None, "archive_critical_data_unreadable")
                            source_sha = hashlib.sha256()
                            bytes_read = 0
                            while True:
                                piece = extracted.read(CHUNK)
                                if not piece:
                                    break
                                bytes_read += len(piece)
                                ensure(bytes_read <= item.size,
                                       "archive_critical_data_invalid")
                                source_sha.update(piece)
                            ensure(bytes_read == item.size,
                                   "archive_critical_data_truncated")
                            target_sha, target_size = read_restored(root, name)
                            ensure(target_sha == source_sha.hexdigest()
                                   and target_size == item.size,
                                   "restored_file_mismatch")
                            if name == "hcp.sqlite":
                                matched["sqlite"] += 1
                            elif name == "inventory.ini":
                                matched["inventory"] += 1
                            elif name == "known_hosts":
                                matched["sshTrust"] += 1
                            elif name.startswith("ssh-host-keys/"):
                                matched["hostKeyFiles"] += 1
                            elif name.startswith("reports/"):
                                matched["reports"] += 1
                            elif name.startswith("sbom/"):
                                matched["sbom"] += 1
                except (tarfile.TarError, EOFError, ValueError, OSError):
                    raise VerificationFailure("runtime_archive_unreadable")
            ensure_unchanged(fd, original)
        finally:
            os.close(fd)
    finally:
        os.close(tar_root)
    ensure(matched["sqlite"] == matched["inventory"] == matched["sshTrust"] == 1,
           "restored_essential_files_missing")
    ensure(not archived_wal, "sqlite_wal_requires_separate_checkpoint_review")
    if require_enrolled_host:
        ensure(matched["hostKeyFiles"] > 0 and matched["reports"] > 0,
               "restored_host_or_report_evidence_missing")
    return backup, matched, count, critical_bytes


def sqlite_integrity(restored_dir):
    """Open immutable SQLite read-only after the service has been stopped.

    A WAL file is a separate case and must not be silently ignored via immutable.
    """
    db = os.path.join(str(restored_dir), "hcp.sqlite")
    for suffix in ("-wal", "-shm"):
        if os.path.lexists(db + suffix):
            raise VerificationFailure("sqlite_wal_requires_separate_checkpoint_review")
    info = os.lstat(db)
    ensure(stat.S_ISREG(info.st_mode) and not (info.st_mode & 0o077),
           "sqlite_file_unsafe")
    uri = "file:" + quote(os.path.abspath(db)) + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    deadline = time.monotonic() + 60
    connection.set_progress_handler(lambda: time.monotonic() > deadline, 2000)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchall()
        ensure(len(result) == 1 and result[0][0] == "ok",
               "sqlite_integrity_check_failed")
        count = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        ensure(type(count) is int and count > 0, "sqlite_schema_empty")
        return {"integrityCheck": "ok", "tableCount": count}
    except (sqlite3.DatabaseError, sqlite3.OperationalError):
        raise VerificationFailure("sqlite_integrity_check_failed")
    finally:
        connection.close()


def assess(backup_dir, restored_dir, require_enrolled_host=False):
    preflight, matched, count, critical_bytes = compare_runtime(
        backup_dir, restored_dir, require_enrolled_host)
    db = sqlite_integrity(restored_dir)
    return {
        "schemaVersion": 1,
        "status": "critical-runtime-bytes-match-backup",
        "scope": "read-only-post-restore-runtime-and-sqlite-sanity",
        "sourceManifestSha256": preflight["manifestSha256"],
        "criticalFileCount": count,
        "criticalBytesCompared": critical_bytes,
        "categories": matched,
        "sqlite": db,
        "checkedAtUtc": datetime.now(timezone.utc).isoformat(),
        "observedNewControllerHealthy": False,
        "actualLoginVerified": False,
        "auditHmacChainVerified": False,
        "sessionsRevokedVerified": False,
        "sshReconnectVerified": False,
        "restoredCveCoverageVerified": False,
        "limitations": [
            "This confirms selected critical bytes and read-only SQLite integrity only.",
            "HCP must be stopped; the tool records the operator's assurance, not process-state proof.",
            "Runtime data outside critical paths, HMAC chain, auth, firewall backups and external scanners are not verified.",
            "Use a separate isolated control node to test actual login, reports and fresh SSH audit.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--restored-runtime", required=True,
                        help="Existing stopped restored HCP runtime mount (not production)")
    parser.add_argument("--acknowledge-stopped", action="store_true",
                        help="Required: operator verified this is an isolated stopped restore")
    parser.add_argument("--require-enrolled-host", action="store_true",
                        help="Release acceptance requires at least one key and one report")
    parser.add_argument("--output", help="Optional new private JSON file")
    args = parser.parse_args(argv)
    ensure(args.acknowledge_stopped, "stopped_restore_acknowledgement_required")
    report = assess(args.backup_dir, args.restored_runtime, args.require_enrolled_host)
    if args.output:
        target = os.path.abspath(args.output)
        ensure(os.path.dirname(target) not in
               (os.path.abspath(args.backup_dir), os.path.abspath(args.restored_runtime)),
               "output_must_be_outside_evidence_and_restored_runtime")
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (VerificationFailure, OSError, sqlite3.DatabaseError, UnicodeError, ValueError) as error:
        code = error.code if isinstance(error, VerificationFailure) else "runtime_unreadable_or_invalid"
        print(json.dumps({"schemaVersion": 1, "status": "blocked",
                          "reasonCode": code, "restorationVerified": False}))
        sys.exit(1)
