#!/usr/bin/env python3
"""Allowlist-only failure summary; NEVER publish private raw VM logs, identity or SSH."""
import json
from pathlib import Path
import re
import sys

SAFE_CHECKS = {
    "Official fixed Astra 1.7.6.UU2 image bytes match source catalog": "image_sha256_verified",
    "Native guest release preflight recorded": "native_release_observed_but_not_yet_accepted",
    "Native guest cloud-init failure; no audit claimed": "cloud_init_failed",
    "Native Astra 1.7.6.15 identity observed before final cloud-init": "native_release_17_observed",
    "Actual native guest cloud-init completed": "cloud_init_completed",
    "Genuine Astra SE 1.7.6.15 guest kernel and SSH key verified": "guest_identity_checked",
    "Real Astra 1.7 native facts and installed packages": "facts_collected",
    "Real Astra 1.7.6.15 source-bound pass/fail/restore": "three_stage_observed",
    "Actual 18-rule original HCP source-bound measurement": "three_stage_compared",
    "Complete Astra 1.7 publisher OVAL XML checksum and structure": "oval_source_checked",
    "Genuine Astra 1.7 full native OVAL evaluation": "oval_evaluated",
    "Production normalization retains original Astra 1.7 OVAL": "oval_published",
}
SAFE_STAGES = {
    "users_groups", "ssh", "set_hostname", "update_hostname", "update_etc_hosts",
    "growpart", "resizefs", "mounts", "package_update_upgrade_install",
    "runcmd", "scripts_user", "scripts_per_boot", "scripts_per_instance",
    "scripts_per_once", "final_message", "phone_home", "ssh_import_id",
    "network", "write_files", "timezone", "locale",
}
SAFE_ERRORS = {"RuntimeError", "ValueError", "AssertionError",
               "TimeoutExpired", "InterruptedError", "KeyboardInterrupt",
               "OSError", "CalledProcessError"}
SAFE_FAILURE_CLASSES = {
    "script_process_failed", "permission_denied", "missing_file",
    "invalid_executable", "python_exception",
}
SAFE_INTERPRETERS = {"shell", "python", "other", "none", "unreadable"}


def summary(private):
    status = private.get("status")
    if status not in ("failed", "cancelled", "running"):
        status = "unknown"
    raw_checks = private.get("checks")
    checks = raw_checks if isinstance(raw_checks, list) else []
    normalized = []
    modules = []
    once_present = None
    once_count = None
    once_executable = None
    interpreter_types = []
    classes = []
    observed_release = None
    observed_build = None
    point_matches_expected = None
    build_matches_expected = None
    guest_os_id_astra = None
    version_matches_expected = None
    for item in checks[-30:]:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name in SAFE_CHECKS:
            normalized.append(SAFE_CHECKS[name])
        if name == "Native guest release preflight recorded":
            candidate = item.get("detail")
            if isinstance(candidate, dict):
                value = candidate.get("observedReleaseToken")
                # Only a narrowly formatted numeric version can leave the
                # private runner. Never reuse raw identity, machine ID,
                # arbitrary hostname or error messages from its JSON.
                if isinstance(value, str) and len(value) <= 64 and re.fullmatch(
                    r"[0-9]+(?:\.[A-Za-z0-9]+){1,7}(?:[+._-][A-Za-z0-9]+)*",
                    value,
                ):
                    observed_release = value
                build = candidate.get("observedBuildVersionToken")
                if isinstance(build, str) and len(build) <= 64 and re.fullmatch(
                    r"[0-9]+(?:\.[A-Za-z0-9]+){1,7}(?:[+._-][A-Za-z0-9]+)*",
                    build,
                ):
                    observed_build = build
                point_matches_expected = (
                    candidate["pointReleaseMatchesExpected"]
                    if type(candidate.get("pointReleaseMatchesExpected")) is bool else None
                )
                build_matches_expected = (
                    candidate["buildVersionMatchesExpected"]
                    if type(candidate.get("buildVersionMatchesExpected")) is bool else None
                )
                guest_os_id_astra = (candidate["guestOsIdIsAstra"]
                                     if type(candidate.get("guestOsIdIsAstra")) is bool
                                     else None)
                version_matches_expected = (
                    candidate["exactRequiredReleaseObserved"]
                    if type(candidate.get("exactRequiredReleaseObserved")) is bool
                    else None
                )
        if name == "Native guest cloud-init failure; no audit claimed":
            detail = item.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("reportedModuleNames"), list):
                modules = sorted({x for x in detail["reportedModuleNames"]
                                  if isinstance(x, str) and x in SAFE_STAGES})
            if isinstance(detail, dict):
                presence = detail.get("perOnceDirectoryPresent")
                once_present = presence if type(presence) is bool else None
                count = detail.get("perOnceScriptCount")
                once_count = count if type(count) is int and 0 <= count <= 1000 else None
                executable_count = detail.get("perOnceExecutableCount")
                once_executable = (executable_count if type(executable_count) is int
                                   and 0 <= executable_count <= 1000 else None)
                types = detail.get("perOnceInterpreterCategories")
                if isinstance(types, list):
                    interpreter_types = sorted({name for name in types
                                               if isinstance(name, str)
                                               and name in SAFE_INTERPRETERS})
                provided = detail.get("failureClasses")
                if isinstance(provided, list):
                    classes = sorted({x for x in provided
                                      if isinstance(x, str) and x in SAFE_FAILURE_CLASSES})
    err = private.get("error")
    error_type = err.get("type") if isinstance(err, dict) else None
    # The full error.message may contain raw guest stdout/stderr, SSH paths,
    # machine-id, target details or source contents. Always discard it.
    return {
        "schemaVersion": 1,
        "status": "native-astra17-unverified",
        "runState": status,
        "nativeAcceptancePassed": False,
        "completedSafeStageNames": normalized,
        "observedGuestRelease": observed_release,
        "observedGuestBuildVersion": observed_build,
        "pointReleaseMatchesExpected": point_matches_expected,
        "buildVersionMatchesExpected": build_matches_expected,
        "guestOsIdIsAstra": guest_os_id_astra,
        "exactRelease117615Observed": version_matches_expected,
        "cloudInitFailingModuleNames": modules,
        "cloudInitPerOnceDirectoryPresent": once_present,
        "cloudInitPerOnceScriptCount": once_count,
        "cloudInitPerOnceExecutableCount": once_executable,
        "cloudInitPerOnceInterpreterCategories": interpreter_types,
        "cloudInitFailureCategories": classes,
        "failureClass": error_type if error_type in SAFE_ERRORS else "unknown",
        "rawGuestOutputPublished": False,
        "notes": ("Only an allowlisted diagnostic summary; no raw identity, "
                  "configuration, private SSH keys or VM disk published."),
    }


def main(argv):
    if len(argv) != 3:
        raise ValueError("expected private input and public output")
    src, dest = map(Path, argv[1:])
    # Source is a runner-generated file, only the small summary is uploaded.
    if src.stat().st_size > 1024 * 1024:
        raise ValueError("protocol too large")
    private = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(private, dict):
        raise ValueError("protocol not object")
    result = summary(private)
    with dest.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    dest.chmod(0o600)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, TypeError):
        # Even on failure, stdout/stderr contain no private paths.
        print("Native Astra private diagnostic could not be safely published.", file=sys.stderr)
        sys.exit(1)
