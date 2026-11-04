#!/usr/bin/env python3
"""Fail-closed, operator-run Astra SE 1.7.6.15 native experiment acceptance.

This combines independent image pinning, three original HCP SCAP reports,
native guest identity and a NEW post-restoration SSH observation. It never
modifies a remote guest or claims issuer authentication or full CVE coverage.
Raw machine-id, host address, credentials and original reports stay private.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone

from measure_astra_baseline import read_report
from pin_astra17_vm_image import hash_image
from verify_astra_17_experiment import (
    read_identity, verify_experiment, native_observation, native_field,
    FINGERPRINT,
)

HOST = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$")
USER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
MAX_SSH_BYTES = 128 * 1024
REMOTE_OBSERVATION = (
    "cat /etc/os-release; printf '\\nRELEASE='; cat /etc/astra_version; "
    "printf '\\nKERNEL='; uname -r; printf 'MACHINE_ID='; "
    "cat /etc/machine-id"
)


class AcceptanceError(ValueError):
    pass


def demand(ok, reason):
    if not ok:
        raise AcceptanceError(reason)


def private_regular(path, size=1024 * 1024):
    info = os.lstat(path)
    demand(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= size
           and not (info.st_mode & 0o077), "private_ssh_input_unsafe")


def authorized_key_fingerprints(known_hosts_file, host, port, runner=subprocess.run):
    """Extract pinned key fingerprints via ssh-keygen -F, including hashed host names."""
    demand(HOST.fullmatch(host) is not None and type(port) is int and 1 <= port <= 65535,
           "invalid_ssh_endpoint")
    private_regular(known_hosts_file)
    lookup = host if port == 22 else "[{}]:{}".format(host, port)
    result = runner(
        ["ssh-keygen", "-F", lookup, "-f", str(known_hosts_file)],
        capture_output=True, timeout=12, check=False,
    )
    demand(result.returncode == 0 and len(result.stdout) <= MAX_SSH_BYTES,
           "ssh_host_key_not_independently_pinned")
    fingerprints = set()
    for line in result.stdout.splitlines():
        if line.startswith(b"#") or not line.strip():
            continue
        columns = line.split()
        demand(len(columns) >= 3, "ssh_known_hosts_record_malformed")
        # ssh-keygen -F produces the matching line, not a full trust chain.
        try:
            key = base64.b64decode(columns[2], validate=True)
        except (ValueError, base64.binascii.Error):
            raise AcceptanceError("ssh_known_hosts_key_invalid")
        digest = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
        fingerprints.add("SHA256:" + digest)
    demand(fingerprints, "ssh_host_key_not_independently_pinned")
    return fingerprints


def post_restore_ssh(host, port, user, private_key, known_hosts_file,
                     expected_fingerprint, runner=subprocess.run):
    """Fresh read-only SSH probe. Strict pinned host key; no password or agent."""
    demand(HOST.fullmatch(host) is not None and USER.fullmatch(user) is not None,
           "invalid_ssh_endpoint")
    demand(type(port) is int and 1 <= port <= 65535, "invalid_ssh_port")
    demand(isinstance(expected_fingerprint, str)
           and FINGERPRINT.fullmatch(expected_fingerprint) is not None,
           "invalid_expected_host_fingerprint")
    private_regular(private_key, 1048576)
    pinned = authorized_key_fingerprints(known_hosts_file, host, port, runner)
    demand(pinned == {expected_fingerprint},
           "ssh_pinned_host_key_not_exactly_expected")
    command = [
        "ssh", "-F", "/dev/null", "-i", str(private_key), "-p", str(port),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
        "-o", "CanonicalizeHostname=no", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UserKnownHostsFile=" + str(known_hosts_file),
        "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
        "{}@{}".format(user, host), REMOTE_OBSERVATION,
    ]
    try:
        result = runner(command, capture_output=True, timeout=35, check=False)
    except subprocess.TimeoutExpired:
        raise AcceptanceError("post_restore_ssh_timeout")
    demand(result.returncode == 0 and len(result.stdout) <= MAX_SSH_BYTES,
           "post_restore_ssh_identity_unavailable")
    try:
        return result.stdout.decode("utf-8", "strict")
    except UnicodeError:
        raise AcceptanceError("post_restore_ssh_identity_invalid")


def assess_image(ova, evidence):
    image_bytes, image_sha = hash_image(ova)
    report, report_sha = read_report(evidence)
    name = Path(ova).name
    demand(re.fullmatch(r"alse-1\.7\.6\.uu2-(base|adv|max)-virtualbox-mg15\.3\.1-amd64\.ova", name)
           is not None, "unrecognised_astra_17_image")
    demand(report.get("schemaVersion") == 1
           and report.get("imageName") == name
           and report.get("status") == "local-bytes-match-recorded-pin"
           and report.get("fileSizeBytes") == image_bytes
           and report.get("sha256") == image_sha
           and report.get("publisherSignatureVerified") is False
           and report.get("nativeGuestVerified") is False,
           "image_bytes_not_bound_to_local_pin")
    return {"imageSha256": image_sha, "imageBytes": image_bytes,
            "imageEvidenceSha256": report_sha,
            "declaredProtectionMode": report.get("securityLevelCandidate"),
            "publisherSignatureVerified": False}


def check_oval(report, reference_sha, host_alias):
    """Real separate OVAL result; scope and scanner completion, not all-CVE recall."""
    demand(SHA.fullmatch(reference_sha) is not None, "invalid_oval_digest_pin")
    scanner = report.get("scanner")
    demand(isinstance(scanner, dict)
           and report.get("mode") == "astra-oval"
           and report.get("inventoryHost") == host_alias,
           "oval_missing_or_wrong_host")
    database = scanner.get("database")
    demand(isinstance(database, dict)
           and database.get("sha256") == reference_sha
           and database.get("checksumVerified") is True,
           "oval_database_sha256_does_not_match_pin")
    host = scanner.get("hostIdentity")
    demand(isinstance(host, dict) and host.get("id") == "astra"
           and str(host.get("astraVersion", "")).startswith("1.7.6.15"),
           "oval_wrong_native_release")
    total, evaluated = scanner.get("definitionCount"), scanner.get("evaluatedDefinitionCount")
    demand(type(total) is int and type(evaluated) is int
           and total > 0 and total == evaluated
           and scanner.get("evaluationPerformed") is True
           and scanner.get("available") is True
           and scanner.get("exitCode") in (0, 2)
           and scanner.get("partial") is False
           and isinstance(scanner.get("definitionResults"), list)
           and len(scanner["definitionResults"]) == total
           and len({item.get("id") for item in scanner["definitionResults"]
                    if isinstance(item, dict)}) == total,
           "oval_incomplete_native_evaluation")
    demand(report.get("partial") is not True, "oval_report_partial")
    return {"databaseSha256": reference_sha, "defined": total,
            "evaluated": evaluated, "partial": False,
            "scope": "exact-observed-Astra-1.7-OVAL-only",
            "publisherSignatureVerified": False, "fullCveCoverageVerified": False}


def verify_all(image, image_evidence, before, changed, restored, facts, native_text,
               post_text, fingerprint, oval, oval_pin):
    image_record = assess_image(image, image_evidence)
    originals = [read_report(path) for path in (before, changed, restored, facts, oval)]
    a, b, c, facts_value, oval_value = [item[0] for item in originals]
    hashes = {"before": originals[0][1], "changed": originals[1][1],
              "restored": originals[2][1], "facts": originals[3][1],
              "identity": hashlib.sha256(native_text.encode("utf-8")).hexdigest()}
    measured = verify_experiment(a, b, c, facts_value, native_text, fingerprint, hashes)
    demand(measured["observedChangeIn18Rules"], "no_observed_controlled_change")
    before_id = native_observation(native_text, fingerprint)
    after_id = native_observation(post_text, fingerprint)
    demand(before_id == after_id, "post_restore_guest_identity_changed")
    oval_record = check_oval(oval_value, oval_pin, a["inventoryHost"])
    demand(measured["restorationMatchesBaseline18Rules"],
           "baseline_rule_statuses_not_restored")
    return {
        "schemaVersion": 1,
        "status": "astra-17-native-evidence-bounded-acceptance",
        "scope": "only-exact-Astra-SE-1.7.6.15-18-rule-and-one-OVAL-source",
        "image": image_record, "experiment": measured,
        "oval": {**oval_record, "reportSha256": originals[4][1]},
        "postRestoreSsh": {
            "freshPinnedSshConnectionObserved": True,
            "sameMachineIdAndKernel": True,
            "samePinnedHostKey": True,
            "observationSha256": hashlib.sha256(post_text.encode("utf-8")).hexdigest(),
        },
        "realGuestVersionCrosschecked": True,
        "fullSystemRollbackVerified": False,
        "independentVendorSignatureVerified": False,
        "generalCveCoverageVerified": False,
        "operatorSignoffReceived": False,
        "checkedAtUtc": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "Only exactly 18 HCP configuration rules and this exact OVAL source were evaluated.",
            "Matching restored rule statuses and SSH access do not establish full system rollback.",
            "Pinned image bytes and vendor OVAL hashes do not independently authenticate the publisher.",
            "The operator must independently document VM snapshot, security level and approval.",
        ],
    }


def write_exclusive(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "image-evidence", "before", "changed", "restored",
                 "facts", "native-identity", "oval"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--oval-sha256", required=True)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-private-key", required=True)
    parser.add_argument("--ssh-known-hosts", required=True)
    parser.add_argument("--ssh-fingerprint", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    files = [getattr(args, name.replace("-", "_")) for name in
             ("image", "image-evidence", "before", "changed", "restored",
              "facts", "native-identity", "oval", "ssh-private-key",
              "ssh-known-hosts", "output")]
    demand(len({os.path.abspath(p) for p in files}) == len(files),
           "input_output_paths_must_be_distinct")
    native_text, _ = read_identity(args.native_identity)
    post_text = post_restore_ssh(args.ssh_host, args.ssh_port, args.ssh_user,
                                args.ssh_private_key, args.ssh_known_hosts,
                                args.ssh_fingerprint)
    result = verify_all(args.image, args.image_evidence, args.before,
                        args.changed, args.restored, args.facts, native_text,
                        post_text, args.ssh_fingerprint, args.oval, args.oval_sha256)
    write_exclusive(args.output, result)
    print("PASS: native Astra 1.7.6.15 evidence consistent; scoped only.")
    print("LIMIT: full OS rollback, independent vendor signatures and all-CVE coverage unverified.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        # Never print paths, machine IDs, SSH errors, private keys or native output.
        print("FAIL: " + (str(exc) if isinstance(exc, AcceptanceError)
                          else "native_acceptance_evidence_invalid"), file=sys.stderr)
        sys.exit(1)
