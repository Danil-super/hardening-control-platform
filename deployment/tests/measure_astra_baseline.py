#!/usr/bin/env python3
"""Compare source-bound HCP Astra OpenSCAP reports (two or three observations).

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


def measure_three_stage(before, changed, restored, before_sha, changed_sha, restored_sha):
    """Evaluate three original HCP reports; never infer causality or full restoration."""
    baseline_changed = measure(before, changed, before_sha, changed_sha)
    changed_restored = measure(changed, restored, changed_sha, restored_sha)
    baseline_restored = measure(before, restored, before_sha, restored_sha)

    # All pairwise calls enforce the same verified asset/generation, exact
    # source bundle, 18 rule IDs and strictly ordered observations.
    def transitions(pair):
        return {key: pair[key] for key in (
            "beforeFailed", "afterFailed", "observedFailedToPassed",
            "observedPassedToFailed", "improvedRules", "regressedRules",
            "netFailedRuleChange")}

    restored_match = (baseline_restored["observedFailedToPassed"] == 0
                      and baseline_restored["observedPassedToFailed"] == 0)
    changed_rules = (baseline_changed["observedFailedToPassed"] > 0
                     or baseline_changed["observedPassedToFailed"] > 0)
    first = baseline_changed["source"]
    second = changed_restored["source"]
    return {
        "schemaVersion": 2,
        "scope": "astra-builtin-18-rule-three-observation-evidence-only",
        "completeComparableRuleCount": EXPECTED_RULES,
        "source": {
            "baselineSha256": before_sha, "changedSha256": changed_sha,
            "restoredSha256": restored_sha,
            "sourceBundleSha256": first["sourceBundleSha256"],
            "assetId": first["assetId"], "assetGeneration": first["assetGeneration"],
            "hostAlias": first["hostAlias"],
            "executedDatastreamSha256Baseline": first["executedDatastreamSha256Before"],
            "executedDatastreamSha256Changed": first["executedDatastreamSha256After"],
            "executedDatastreamSha256Restored": second["executedDatastreamSha256After"],
            "baselineAt": first["beforeAt"], "changedAt": first["afterAt"],
            "restoredAt": second["afterAt"],
        },
        "baselineToChanged": transitions(baseline_changed),
        "changedToRestored": transitions(changed_restored),
        "baselineToRestored": transitions(baseline_restored),
        "observedChangeIn18Rules": changed_rules,
        "restorationMatchesBaseline18Rules": restored_match,
        "status": "same-18-rule-statuses-observed" if restored_match else "rules-not-restored",
        "claimLimits": [
            "Result compares only the same 18 Astra HCP configuration rules.",
            "Matching rule statuses do not prove identical OS, kernel, firewall or SSH reachability.",
            "Observed change is not proof of a specific remediation or its causal effect.",
            "No full-CVE coverage, general security score, precision, recall or time savings measured.",
            "Synthetic fixtures test the parser only; real Astra 1.7 requires authorized native evidence.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--restored", help="Optional third original audit after rollback")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    paths = [args.before, args.after, args.output]
    if args.restored:
        paths.append(args.restored)
    require(len({os.path.abspath(value) for value in paths}) == len(paths),
            "Source evidence and output paths must be distinct")
    a, a_sha = read_report(args.before)
    b, b_sha = read_report(args.after)
    if args.restored:
        restored, restored_sha = read_report(args.restored)
        result = measure_three_stage(a, b, restored, a_sha, b_sha, restored_sha)
    else:
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
    if args.restored and not result["restorationMatchesBaseline18Rules"]:
        print("FAIL: 18-rule states differ from baseline; evidence saved for review.", file=sys.stderr)
        return 2
    print("PASS: independently comparable Astra observations; scoped digest-bound output saved.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
