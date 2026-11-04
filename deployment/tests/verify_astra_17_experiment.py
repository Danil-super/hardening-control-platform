#!/usr/bin/env python3
"""Read-only Astra SE 1.7.6.15 native-identity gate for three HCP audit reports.

This tool crosschecks actual SSH-observed machine-id and release evidence with
the HCP asset binding. It cannot independently attest a vendor's image,
prove an administrator did not spoof OS files, or certify full system recovery.
Never upload the input identity text: it contains the raw machine-id.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys

from measure_astra_baseline import measure_three_stage, parse_date, read_report, require

EXPECTED_RELEASE = "1.7.6.15"
EXPECTED_ARCH = "x86_64"
MAX_IDENTITY_BYTES = 128 * 1024
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")
MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
ASSET_KEY = b"hardening-control-platform/asset-identity/v1"


def read_identity(path):
    """Read a bounded regular original native SSH observation, never a link."""
    path = Path(path)
    original = os.lstat(path)
    require(stat.S_ISREG(original.st_mode)
            and 0 < original.st_size <= MAX_IDENTITY_BYTES,
            "Native identity must be a bounded regular text file, not a symlink")
    require(original.st_mode & 0o077 == 0,
            "Native machine identity observation must not be accessible by group or other users")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        first = os.fstat(descriptor)
        require(first.st_ino == original.st_ino and first.st_dev == original.st_dev,
                "Identity input changed during opening")
        raw = bytearray()
        while len(raw) <= MAX_IDENTITY_BYTES:
            piece = os.read(descriptor, min(4096, MAX_IDENTITY_BYTES + 1 - len(raw)))
            if not piece:
                break
            raw.extend(piece)
        final = os.fstat(descriptor)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == original.st_size and len(raw) <= MAX_IDENTITY_BYTES and all(
            getattr(original, key) == getattr(first, key)
            == getattr(final, key) == getattr(current, key) for key in keys),
            "Native identity input changed while reading")
    finally:
        os.close(descriptor)
    return raw.decode("utf-8", "strict"), hashlib.sha256(raw).hexdigest()


def native_field(text, name):
    matches = re.findall(r"^" + re.escape(name) + r"=(.*)$", text, flags=re.MULTILINE)
    require(len(matches) == 1 and 0 < len(matches[0]) <= 200,
            "Native identity field missing, duplicated or malformed: " + name)
    return matches[0].strip().strip('"').strip("'")


def native_observation(text, observed_fingerprint):
    require(FINGERPRINT.fullmatch(observed_fingerprint) is not None,
            "SSH host key fingerprint must come from a separately checked connection")
    require(native_field(text, "ID").lower() == "astra",
            "Native OS ID is not Astra Linux")
    require(native_field(text, "RELEASE") == EXPECTED_RELEASE,
            "Native Astra release is not the required 1.7.6.15")
    kernel = native_field(text, "KERNEL")
    require(re.fullmatch(r"[A-Za-z0-9_.+:-]{1,120}", kernel) is not None,
            "Native kernel version is malformed")
    machine = native_field(text, "MACHINE_ID")
    require(MACHINE_ID.fullmatch(machine) is not None and machine != "0" * 32,
            "Native system machine-id is malformed")
    machine_hash = hmac.new(ASSET_KEY, machine.encode("ascii"), hashlib.sha256).hexdigest()
    # Node's JSON.stringify([hash, fingerprint]) is compact UTF-8 JSON.
    asset = "asset-" + hashlib.sha256(
        json.dumps([machine_hash, observed_fingerprint],
                   ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"assetId": asset, "machineIdSha256": machine_hash,
            "sshHostKeyFingerprint": observed_fingerprint,
            "kernel": kernel, "release": EXPECTED_RELEASE}


def verify_experiment(before, changed, restored, facts, identity_text, fingerprint,
                      hashes):
    """Crosscheck HCP source-bound reports against a native guest observation."""
    metrics = measure_three_stage(before, changed, restored, hashes["before"],
                                  hashes["changed"], hashes["restored"])
    observed = native_observation(identity_text, fingerprint)
    binding = before.get("assetBinding")
    require(isinstance(binding, dict) and binding.get("version") == 1
            and binding.get("status") == "verified"
            and binding.get("assetId") == observed["assetId"]
            and binding.get("machineIdSha256") == observed["machineIdSha256"]
            and binding.get("sshHostKeyFingerprint") == fingerprint,
            "Native guest identity and HCP verified binding do not match")
    for report in (changed, restored):
        own = report.get("assetBinding")
        require(isinstance(own, dict) and
                all(own.get(field) == binding.get(field) for field in (
                    "assetId", "generation", "machineIdSha256",
                    "sshHostKeyFingerprint", "connectionId", "alias")),
                "Audit phases do not share one verified asset connection and identity")
    require(binding.get("alias") == metrics["source"]["hostAlias"],
            "Verified asset alias is inconsistent with reports")
    require(isinstance(facts, dict)
            and facts.get("mode") == "facts"
            and facts.get("inventoryHost") == binding["alias"],
            "Host facts must belong to exactly the same inventory alias")
    require(isinstance(facts.get("os"), str) and re.search(
        r"\bAstra Linux 1\.7(?:\b|[_\s-])", facts["os"], flags=re.IGNORECASE),
        "Facts did not identify an Astra Linux 1.7 host")
    require(facts.get("architecture") == EXPECTED_ARCH,
            "Facts architecture differs from required Astra x86_64")
    require(facts.get("kernel") == observed["kernel"],
            "Native kernel does not match the HCP facts report")
    require(parse_date(facts.get("createdAt")) <=
            parse_date(before.get("createdAt")),
            "HCP facts must be captured no later than the baseline")
    facts_binding = facts.get("assetBinding")
    if facts_binding is not None:
        require(isinstance(facts_binding, dict) and facts_binding.get("assetId")
                == observed["assetId"],
                "Facts report is attached to a different identity")
    metrics["nativeReleaseCrosscheck"] = {
        "declaredRelease": EXPECTED_RELEASE,
        "nativeOsId": "astra", "architecture": EXPECTED_ARCH,
        "kernel": observed["kernel"],
        "factsSha256": hashes["facts"],
        "identityObservationSha256": hashes["identity"],
        "machineIdMatchedBinding": True,
        "sshFingerprintMatchedBinding": True,
        "vendorImageAttested": False,
        "scope": "captured-SSH-and-HCP-evidence-only",
        "limitations": [
            "Inputs require an independently pinned SSH host key and original native guest observation",
            "The command does not execute SSH, attest an OS publisher or prove that the guest files are unmodified",
            "Full CVE completeness, protected modes, firewall and network restoration remain separate tests",
        ],
    }
    return metrics


def write_exclusive(path, result):
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        os.unlink(str(path))
        raise
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--changed", required=True)
    parser.add_argument("--restored", required=True)
    parser.add_argument("--facts", required=True)
    parser.add_argument("--native-identity", required=True)
    parser.add_argument("--ssh-fingerprint", required=True,
                        help="Previously verified SSH server-key SHA256 fingerprint; not a secret")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    files = [args.before, args.changed, args.restored,
             args.facts, args.native_identity, args.output]
    require(len({os.path.abspath(p) for p in files}) == len(files),
            "Source evidence and output paths must all be distinct")
    before, a_sha = read_report(args.before)
    changed, b_sha = read_report(args.changed)
    restored, c_sha = read_report(args.restored)
    facts, facts_sha = read_report(args.facts)
    identity, identity_sha = read_identity(args.native_identity)
    result = verify_experiment(before, changed, restored, facts, identity,
                               args.ssh_fingerprint,
                               {"before": a_sha, "changed": b_sha,
                                "restored": c_sha, "facts": facts_sha,
                                "identity": identity_sha})
    write_exclusive(args.output, result)
    if not result["restorationMatchesBaseline18Rules"]:
        print("FAIL: baseline rule statuses were not restored. Evidence saved.", file=sys.stderr)
        return 2
    print("PASS: Astra 1.7.6.15 source-bound identities and 18-rule transition are consistent.")
    print("LIMIT: Publisher authenticity and full OS restoration require separate acceptance.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        # Never write the original identity text, machine-id or private key.
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
