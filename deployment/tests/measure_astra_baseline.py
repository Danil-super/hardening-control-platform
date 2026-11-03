#!/usr/bin/env python3
"""Compare two real, source-bound HCP Astra OpenSCAP baseline reports.

Only the same verified asset, same 18-rule profile, same stable input bundle
identity and complete, strictly comparable passes are accepted. OpenSCAP
timestamps may change each compiled datastream SHA without changing the
underlying profile. Each raw execution digest remains separate evidence.
This does not claim a full
CVE audit or that any remediation was caused by HCP.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = "xccdf_org.hcp_profile_astra_baseline"
PREFIX = "openscap_xccdf_org.hcp_rule_"
SHA = re.compile(r"^sha256:[a-f0-9]{64}$")
BUNDLE = re.compile(r"^bundle-sha256:[a-f0-9]{64}$")
ASSET = re.compile(r"^asset-[a-f0-9]{64}$")
MAX_INPUT = 32 * 1024 * 1024
EXPECTED_RULES = 18


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_report(path):
    path = Path(path)
    before = os.lstat(str(path))
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_INPUT,
            "Expected a bounded regular JSON report, not a symlink or special file")
    digest = hashlib.sha256()
    chunks = []
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
        require(opened.st_dev == before.st_dev and opened.st_ino == before.st_ino
                and stat.S_ISREG(opened.st_mode), "Report was replaced during opening")
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            require(size <= MAX_INPUT, "Report exceeded input budget")
            digest.update(chunk)
            chunks.append(chunk)
        after, current = os.fstat(fd), os.lstat(str(path))
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(size == before.st_size and all(
            getattr(before, key) == getattr(after, key) == getattr(current, key)
            for key in keys), "Report changed while reading")
    finally:
        os.close(fd)
    report = json.loads(b"".join(chunks).decode("utf-8", "strict"))
    require(isinstance(report, dict), "Report JSON must be an object")
    return report, digest.hexdigest()


def parse_date(value):
    require(isinstance(value, str) and len(value) <= 40, "Report timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid report timestamp")
    require(parsed.tzinfo is not None, "Report timestamp needs a timezone")
    return parsed.astimezone(timezone.utc)


def parse_report(report):
    require(report.get("mode") == "openscap", "Only OpenSCAP reports are comparable")
    require("partial" not in report or report.get("partial") is False,
            "Partial audit cannot prove a baseline transition")
    scanner = report.get("scanner")
    require(isinstance(scanner, dict), "OpenSCAP scanner evidence missing")
    require(scanner.get("profile") == PROFILE, "Astra 18-rule profile mismatch")
    require(scanner.get("datastream") == "/__hcp_builtin__/astra-baseline.xml",
            "Only the HCP Astra built-in datastream can be compared")
    checksum = scanner.get("datastreamChecksum")
    require(isinstance(checksum, str) and SHA.fullmatch(checksum),
            "Missing executed datastream SHA-256")
    bundle = scanner.get("contentIdentity")
    require(isinstance(bundle, str) and BUNDLE.fullmatch(bundle),
            "Stable HCP Astra source bundle identity unavailable")
    require(scanner.get("scannerExitCode") in (0, 2)
            and type(scanner.get("scannerExitCode")) is int,
            "Native OpenSCAP execution did not complete")
    require(scanner.get("partial") is False, "Scanner did not prove complete evaluation")
    binding = report.get("assetBinding")
    require(isinstance(binding, dict) and binding.get("version") == 1
            and binding.get("status") == "verified", "Verified asset binding is required")
    asset = binding.get("assetId")
    generation = binding.get("generation")
    require(isinstance(asset, str) and ASSET.fullmatch(asset)
            and type(generation) is int and generation > 0,
            "Invalid asset identity or generation")
    alias = report.get("inventoryHost")
    require(isinstance(alias, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", alias),
            "Report inventory host alias is invalid")
    at = parse_date(report.get("createdAt"))
    raw_findings = report.get("findings")
    require(isinstance(raw_findings, list) and len(raw_findings) == EXPECTED_RULES,
            "Incomplete or changed Astra baseline rule set")
    statuses = {}
    for item in raw_findings:
        require(isinstance(item, dict), "Malformed rule finding")
        identifier, status = item.get("id"), item.get("status")
        require(isinstance(identifier, str)
                and identifier.startswith(PREFIX) and len(identifier) <= 140
                and re.fullmatch(r"[a-zA-Z0-9_]+", identifier[len(PREFIX):]),
                "Non-Astra profile rule encountered")
        require(status in ("passed", "failed"), "Rule result unresolved; do not claim improvement")
        require(identifier not in statuses, "Duplicate rule identity")
        statuses[identifier] = status
    counts = scanner.get("ruleResultCounts")
    require(isinstance(counts, dict)
            and counts.get("pass") == sum(v == "passed" for v in statuses.values())
            and counts.get("fail") == sum(v == "failed" for v in statuses.values())
            and sum(v for v in counts.values() if type(v) is int) == EXPECTED_RULES,
            "Native rule counters and normalized findings disagree")
    return {"alias": alias, "asset": asset, "generation": generation,
            "checksum": checksum, "bundle": bundle, "at": at, "statuses": statuses}


def measure(before, after, before_sha, after_sha):
    a, b = parse_report(before), parse_report(after)
    require((a["alias"], a["asset"], a["generation"]) ==
            (b["alias"], b["asset"], b["generation"]),
            "Different host, asset or binding generation")
    require(a["bundle"] == b["bundle"], "Different Astra source bundle content")
    require(set(a["statuses"]) == set(b["statuses"]), "Non-identical tested rule identities")
    require(a["at"] < b["at"], "Post-audit must follow the baseline")
    changed_to_pass = sorted(rule for rule in a["statuses"]
                             if a["statuses"][rule] == "failed" and b["statuses"][rule] == "passed")
    changed_to_fail = sorted(rule for rule in a["statuses"]
                             if a["statuses"][rule] == "passed" and b["statuses"][rule] == "failed")
    first_fail = sum(x == "failed" for x in a["statuses"].values())
    final_fail = sum(x == "failed" for x in b["statuses"].values())
    return {
        "schemaVersion": 1,
        "scope": "astra-builtin-18-rule-profile-paired-observation-only",
        "completeComparableRuleCount": EXPECTED_RULES,
        "source": {
            "beforeSha256": before_sha, "afterSha256": after_sha,
            "sourceBundleSha256": a["bundle"],
            "executedDatastreamSha256Before": a["checksum"],
            "executedDatastreamSha256After": b["checksum"],
            "assetId": a["asset"],
            "assetGeneration": a["generation"], "hostAlias": a["alias"],
            "beforeAt": a["at"].isoformat(), "afterAt": b["at"].isoformat(),
        },
        "beforeFailed": first_fail, "afterFailed": final_fail,
        "observedFailedToPassed": len(changed_to_pass),
        "observedPassedToFailed": len(changed_to_fail),
        "improvedRules": changed_to_pass,
        "regressedRules": changed_to_fail,
        "netFailedRuleChange": final_fail - first_fail,
        "claimLimits": [
            "Pairwise result for exactly 18 unchanged HCP Astra configuration rules",
            "Not a percentage of all Linux/CVE vulnerabilities, exploitation likelihood or overall host security",
            "No causal attribution or remediation safety claim without a separately documented intervention",
            "No measured time savings without independent manual-workflow observations",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    require(os.path.abspath(args.output) not in
            (os.path.abspath(args.before), os.path.abspath(args.after)),
            "Refusing to overwrite source evidence")
    a, a_sha = read_report(args.before)
    b, b_sha = read_report(args.after)
    result = measure(a, b, a_sha, b_sha)
    output = Path(args.output)
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(descriptor)
    except BaseException:
        os.unlink(str(output))
        raise
    finally:
        os.close(descriptor)
    print("PASS: independently comparable 18-rule Astra observations; digest-bound output saved.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
