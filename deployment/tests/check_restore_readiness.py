#!/usr/bin/env python3
"""One read-only HCP restore preflight combining archived bytes, SQLite and HMAC.

For a separate STOPPED restored control node only. This cannot attest Docker
health, browser authorization, physical SSH, vendor images or firewall rollback.
Independent manifest and audit-head pins must be retained outside the backup;
otherwise an untrusted self-consistent copy cannot pass the strict preflight.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import re
import sys
import time
from pathlib import Path

from validate_production_env import read_env_file
from verify_backup_bundle import VerificationFailure, verify as check_backup
from verify_restored_runtime import assess as check_runtime
from verify_restored_audit_chain import ChainFailure, verify_events as check_audit

SHA = re.compile(r"^[a-f0-9]{64}$")
MAX_PINNED_ENTRIES = 1000000


class ReadinessFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise ReadinessFailure(code)


def optional_operator_pins(manifest_sha, audit_sha, audit_entries):
    if manifest_sha is not None:
        require(isinstance(manifest_sha, str) and SHA.fullmatch(manifest_sha),
                "manifest_anchor_format_invalid")
    require((audit_sha is None) == (audit_entries is None),
            "audit_anchor_requires_head_and_count")
    if audit_sha is not None:
        require(isinstance(audit_sha, str) and SHA.fullmatch(audit_sha),
                "audit_anchor_format_invalid")
        require(type(audit_entries) is int and 0 < audit_entries <= MAX_PINNED_ENTRIES,
                "audit_anchor_count_invalid")


def external_output_allowed(output, inputs):
    target = os.path.abspath(output)
    parent = os.path.realpath(os.path.dirname(target))
    for candidate in inputs:
        source = os.path.realpath(candidate)
        require(os.path.commonpath((parent, source)) != source,
                "receipt_location_inside_private_input")
    return target


def run_preflight(backup, runtime, env_file, *,
                  manifest_sha=None, audit_head=None, audit_entries=None,
                  require_full_payload=False):
    optional_operator_pins(manifest_sha, audit_head, audit_entries)
    moments = {}
    begin = time.monotonic()
    # Pre-verify the operator pin against the complete archive before
    # inspecting restored bytes. The second validation in check_runtime is
    # deliberately independent; it detects changes during the operation.
    backup_record = check_backup(backup, manifest_sha)
    moments["archive"] = time.monotonic() - begin
    restored = check_runtime(backup, runtime, require_enrolled_host=True)
    moments["restored"] = time.monotonic() - begin - moments["archive"]
    require(restored["sourceManifestSha256"] == backup_record["manifestSha256"],
            "source_manifest_changed_between_checks")
    values = read_env_file(env_file)
    key = values.get("HCP_AUDIT_HMAC_KEY")
    require(isinstance(key, str) and len(key.encode("utf-8")) >= 32,
            "audit_hmac_key_missing_or_short")
    audit = check_audit(runtime, key.encode("utf-8"),
                        require_payload_protection=require_full_payload)
    moments["hmac"] = time.monotonic() - begin - moments["archive"] - moments["restored"]
    if audit_head is not None:
        require(audit["entries"] == audit_entries, "audit_anchor_entry_count_mismatch")
        require(audit["lastEntryHash"] == audit_head, "audit_anchor_head_mismatch")
    problems = []
    if manifest_sha is None:
        problems.append("independent_manifest_pin_missing")
    if audit_head is None:
        problems.append("independent_audit_head_pin_missing")
    if not audit["payloadProtectedForAllEntries"]:
        problems.append("legacy_audit_payload_not_fully_protected")
    status = ("local-preflight-complete-live-recovery-unverified"
              if not problems else "local-preflight-incomplete-authority")
    return {
        "schemaVersion": 1,
        "status": status,
        "scope": "stopped-isolated-restored-controller-archive-sqlite-audit",
        "operatorHasVerifiedLiveService": False,
        "originalAdminCookieRevocationVerified": False,
        "restoredSshReconnectVerified": False,
        "firewallRollbackVerified": False,
        "completeRecoveryVerified": False,
        "manifestSha256": backup_record["manifestSha256"],
        "backupArchiveSha256": backup_record["archiveSha256"],
        "criticalFilesCompared": restored["criticalFileCount"],
        "criticalBytesCompared": restored["criticalBytesCompared"],
        "restoredCategories": restored["categories"],
        "sqliteIntegrity": restored["sqlite"]["integrityCheck"],
        "auditHmac": {
            "entries": audit["entries"],
            "legacyEntries": audit["legacyEntries"],
            "payloadProtectedForAllEntries": audit["payloadProtectedForAllEntries"],
            "lastEntryHash": audit["lastEntryHash"],
        },
        "operatorSuppliedIndependentManifestPinMatched": manifest_sha is not None,
        "operatorSuppliedIndependentAuditHeadMatched": audit_head is not None,
        "reviewRequired": problems,
        "elapsedSeconds": {key: round(value, 3) for key, value in moments.items()},
        "checkedAtUtc": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "No original backups or restored HCP state were modified; all checks are read-only.",
            "An operator must independently establish the actual trust and storage of external pins.",
            "A self-consistent HMAC chain without a prior head/count cannot detect deletion of its valid tail.",
            "The recovered browser, HTTPS, HCP session, real SSH and firewall must be tested independently.",
            "Not native Astra 1.7.6.15 acceptance or certification of all CVEs.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--restored-runtime", required=True)
    parser.add_argument("--env", required=True, help="Original protected restored .env")
    parser.add_argument("--expected-manifest-sha256",
                        help="Externally retained SHA-256 of the original backup SHA256SUMS")
    parser.add_argument("--expected-head-hmac",
                        help="Externally retained original last HMAC from the stopped controller")
    parser.add_argument("--expected-entry-count", type=int,
                        help="Externally retained exact original HMAC event count")
    parser.add_argument("--require-full-payload-protection", action="store_true")
    parser.add_argument("--acknowledge-isolated-stopped", action="store_true")
    parser.add_argument("--output", help="New private JSON receipt outside all inputs")
    args = parser.parse_args(argv)
    require(args.acknowledge_isolated_stopped,
            "stopped_isolated_restore_acknowledgement_required")
    outcome = run_preflight(
        args.backup_dir, args.restored_runtime, args.env,
        manifest_sha=args.expected_manifest_sha256,
        audit_head=args.expected_head_hmac, audit_entries=args.expected_entry_count,
        require_full_payload=args.require_full_payload_protection,
    )
    if args.output:
        path = external_output_allowed(args.output, [
            args.backup_dir, args.restored_runtime, os.path.dirname(args.env),
        ])
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write((json.dumps(outcome, ensure_ascii=False, indent=2) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    print(json.dumps(outcome, ensure_ascii=False, sort_keys=True))
    return 0 if not outcome["reviewRequired"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ReadinessFailure, VerificationFailure, ChainFailure, OSError,
            ValueError, UnicodeError) as error:
        reason = error.code if hasattr(error, "code") else "restore_preflight_unreadable"
        print(json.dumps({"schemaVersion": 1, "status": "blocked",
                          "reasonCode": reason, "completeRecoveryVerified": False}))
        sys.exit(1)
