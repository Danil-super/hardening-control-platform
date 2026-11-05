#!/usr/bin/env python3
"""Read-only, privacy-preserving failure evidence from a disposable Astra guest.

The original /var/log/cloud-init*.log may contain user-data, hostnames, private
paths and secrets. Raw log lines must NEVER be returned to the host runner,
saved as CI artifacts, printed, or used as an acceptance override.
"""
import json
import re
import shlex
from types import SimpleNamespace

SAFE_CLASSES = frozenset({
    "script_process_failed", "network_unavailable", "name_resolution_failure",
    "package_repository_failure", "package_install_failure",
    "service_failure", "permission_denied", "security_policy_denied",
    "security_policy_referenced",
    "missing_file", "missing_command", "read_only_file_system",
    "disk_full", "invalid_executable", "shell_syntax_error",
})
PUBLIC_KEYS = frozenset({
    "schemaVersion", "status", "cloudLogReadable", "outputLogReadable",
    "cloudLogClasses", "outputLogClasses", "observedNonzeroExitCodes",
    "perOnceFailureMarkerSeen", "defaultRoutePresent", "resolverConfigured",
    "rootFreeMiB",
})
GUEST_PROBE = r'''
import json, os, re, stat

PATTERNS = {
  "script_process_failed": r"run[- ]?parts|ScriptFailure|non[- ]zero exit status|failed with exit code",
  "network_unavailable": r"Network is unreachable|No route to host|Connection (?:refused|timed out)",
  "name_resolution_failure": r"Temporary failure resolving|Name or service not known|Could not resolve",
  "package_repository_failure": r"Failed to fetch|Some index files failed to download|does not have a Release file|Hash Sum mismatch",
  "package_install_failure": r"Unable to locate package|Sub-process /usr/bin/dpkg returned an error code|dpkg: error processing",
  "service_failure": r"Failed to start|Failed to enable unit|Unit .{0,100} not found",
  "permission_denied": r"Permission denied|PermissionError|Operation not permitted",
  # A simple mention of PARSEC does NOT prove that any access was denied.
  "security_policy_referenced": r"\bPARSEC\b|Mandatory Access Control",
  "security_policy_denied": (
      r"(?:PARSEC|Mandatory Access Control)[^\r\n]{0,120}"
      r"(?:access denied|permission denied|отказано)"
      r"|(?:access denied|отказано)[^\r\n]{0,120}(?:PARSEC|Mandatory Access Control)"
      r"|access denied by (?:a )?policy"
  ),
  "missing_file": r"FileNotFoundError|No such file or directory",
  "missing_command": r"command not found",
  "read_only_file_system": r"Read-only file system",
  "disk_full": r"No space left on device|Disk quota exceeded",
  "invalid_executable": r"Exec format error|bad interpreter",
  "shell_syntax_error": r"syntax error near unexpected token|unexpected EOF while looking for matching",
}
def log_tail(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 32 * 1024 * 1024:
                return None
            os.lseek(fd, max(0, st.st_size - 262144), os.SEEK_SET)
            return os.read(fd, 262144).decode("utf-8", "replace")
        finally:
            os.close(fd)
    except OSError:
        return None
def categories(content):
    if content is None:
        return []
    return sorted(k for k, regex in PATTERNS.items()
                  if re.search(regex, content, re.IGNORECASE))
def default_route_present():
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            return any(len(row.split()) >= 3 and row.split()[1] == "00000000"
                       for row in list(f)[:128])
    except (OSError, UnicodeError):
        return None
def resolver_present():
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            return any(line.lstrip().startswith("nameserver ") for line in list(f)[:128])
    except OSError:
        return None
def root_free_mib():
    try:
        st = os.statvfs("/")
        return min(2147483647, (st.f_bavail * st.f_frsize) // (1024 * 1024))
    except OSError:
        return None
cloud_log = log_tail("/var/log/cloud-init.log")
output_log = log_tail("/var/log/cloud-init-output.log")
all_text = (cloud_log or "") + "\n" + (output_log or "")
# Exit statuses may belong to other commands; DO NOT call these per-once
# script exit codes or assert causality from their presence.
codes = sorted({int(x) for x in re.findall(
    r"(?:Exit code:|exit status|exited with status)\s*([0-9]{1,3})",
    all_text, re.IGNORECASE) if 1 <= int(x) <= 255})[:8]
out = {
    "schemaVersion": 1,
    "status": "sanitized-guest-log-observation",
    "cloudLogReadable": cloud_log is not None,
    "outputLogReadable": output_log is not None,
    "cloudLogClasses": categories(cloud_log),
    "outputLogClasses": categories(output_log),
    "observedNonzeroExitCodes": codes,
    "perOnceFailureMarkerSeen": bool(cloud_log and re.search(
        r"config-scripts-per-once:\s*FAIL", cloud_log, re.IGNORECASE)),
    "defaultRoutePresent": default_route_present(),
    "resolverConfigured": resolver_present(),
    "rootFreeMiB": root_free_mib(),
}
# Strict fixed-schema aggregates ONLY. No source paths, script names,
# log excerpts, host identity, hostname, URL or user-data can leave guest.
print(json.dumps(out, sort_keys=True))
'''

def validated_evidence(result):
    """Fail closed against unexpected JSON or guest output injection."""
    if not isinstance(result, str) or len(result.encode("utf-8")) > 4096:
        raise ValueError("diagnostic_output_invalid")
    try:
        doc = json.loads(result)
    except (ValueError, TypeError):
        raise ValueError("diagnostic_output_invalid")
    if type(doc) is not dict or set(doc) != PUBLIC_KEYS:
        raise ValueError("diagnostic_schema_invalid")
    if doc["schemaVersion"] != 1 or doc["status"] != "sanitized-guest-log-observation":
        raise ValueError("diagnostic_version_invalid")
    for field in ("cloudLogReadable", "outputLogReadable", "perOnceFailureMarkerSeen"):
        if type(doc[field]) is not bool:
            raise ValueError("diagnostic_boolean_invalid")
    for field in ("defaultRoutePresent", "resolverConfigured"):
        if doc[field] is not None and type(doc[field]) is not bool:
            raise ValueError("diagnostic_boolean_invalid")
    free = doc["rootFreeMiB"]
    if free is not None and (type(free) is not int or not 0 <= free <= 2147483647):
        raise ValueError("diagnostic_storage_invalid")
    for field in ("cloudLogClasses", "outputLogClasses"):
        values = doc[field]
        if (type(values) is not list or len(values) > len(SAFE_CLASSES)
                or any(type(v) is not str or v not in SAFE_CLASSES for v in values)
                or values != sorted(set(values))):
            raise ValueError("diagnostic_categories_invalid")
    codes = doc["observedNonzeroExitCodes"]
    if (type(codes) is not list or len(codes) > 8
            or any(type(x) is not int or not 1 <= x <= 255 for x in codes)
            or codes != sorted(set(codes))):
        raise ValueError("diagnostic_exit_codes_invalid")
    return doc

def collect_guest_evidence(remote):
    """Run only standard-library read-only log inspection in guest."""
    result = remote("sudo python3 -c " + shlex.quote(GUEST_PROBE), timeout=30)
    return validated_evidence(result.stdout)
