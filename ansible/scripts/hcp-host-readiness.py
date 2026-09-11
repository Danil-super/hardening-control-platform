#!/usr/bin/env python3
"""Collect bounded, read-only host facts; compatible with Python 3.5+.

This is a readiness probe, not a vulnerability or compliance assessment.  It
never installs tools, changes configuration, or contacts a network service.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess


SCHEMA_VERSION = 1
COMMAND_TIMEOUT = 5
MAX_OVAL_FILES = 32
MAX_OVAL_FILE_BYTES = 64 * 1024 * 1024
MAX_OVAL_TOTAL_BYTES = 256 * 1024 * 1024
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
OS_RELEASE_FIELDS = frozenset((
    "ID", "ID_LIKE", "NAME", "PRETTY_NAME", "VERSION_ID", "VERSION",
    "VERSION_CODENAME", "UBUNTU_CODENAME", "CODENAME", "BUILD_ID",
    "VARIANT", "VARIANT_ID",
))
TOOL_NAMES = (
    "python3", "ss", "sshd", "systemctl", "dpkg-query", "rpm", "oscap",
    "firewall-cmd", "ufw", "iptables", "nft",
)


def read_text(path, errors, optional=False, max_bytes=65536):
    """Read a small local fact file without following any commands in it."""
    try:
        with open(str(path), "rb") as source:
            data = source.read(max_bytes + 1)
    except FileNotFoundError:
        if not optional:
            errors.append("{}: file is missing".format(path))
        return None
    except OSError:
        errors.append("{}: file cannot be read".format(path))
        return None
    if len(data) > max_bytes:
        errors.append("{}: file exceeds the size limit".format(path))
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("{}: invalid UTF-8".format(path))
        return None


def parse_os_release(text, errors):
    result = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw = stripped.split("=", 1)
        if key not in OS_RELEASE_FIELDS:
            continue
        try:
            values = shlex.split(raw, comments=False, posix=True)
        except ValueError:
            errors.append("os-release: malformed {} value".format(key))
            continue
        if len(values) > 1 or (values and len(values[0]) > 512):
            errors.append("os-release: invalid {} value".format(key))
            continue
        result[key] = values[0] if values else ""
    if not result.get("ID"):
        errors.append("os-release: distribution ID is unavailable")
    return result


def run_query(argv, errors, label):
    environment = dict(os.environ)
    environment.update({
        "PATH": SAFE_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "SYSTEMD_PAGER": "",
        "SYSTEMD_COLORS": "0",
    })
    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=COMMAND_TIMEOUT,
            env=environment, cwd="/", check=False,
        )
        # Decode explicitly: Python 3.5 has no subprocess encoding/errors
        # options, and the host's C locale must not discard Cyrillic output.
        result.stdout = result.stdout.decode("utf-8", "replace")
        result.stderr = result.stderr.decode("utf-8", "replace")
        return result
    except subprocess.TimeoutExpired:
        errors.append("{}: status query timed out after {}s".format(label, COMMAND_TIMEOUT))
    except OSError:
        errors.append("{}: status query could not start".format(label))
    return None


def ufw_state(binary, errors):
    if binary is None:
        return "missing"
    result = run_query([binary, "status"], errors, "ufw")
    if result is None:
        return "unknown"
    # An active/exited ufw.service does not establish that UFW is enabled.
    first_line = next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")
    if result.returncode == 0 and first_line in ("Status: active", "Status: inactive"):
        return first_line.split(": ", 1)[1]
    errors.append("ufw: status could not be established (exit {})".format(result.returncode))
    return "unknown"


def firewalld_state(binary, errors):
    if binary is None:
        return "missing"
    result = run_query([binary, "--state"], errors, "firewalld")
    if result is None:
        return "unknown"
    if result.returncode == 0 and result.stdout.strip() == "running":
        return "active"
    # NOT_RUNNING is 252; a D-Bus or permission failure is not an inactive firewall.
    output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode == 252 and output == "not running":
        return "inactive"
    errors.append("firewalld: status could not be established (exit {})".format(result.returncode))
    return "unknown"


def netfilter_persistent_state(systemctl, errors):
    if systemctl is None:
        installed = shutil.which("netfilter-persistent", path=SAFE_PATH) is not None or any(
            Path(path).exists() for path in (
                "/etc/init.d/netfilter-persistent",
                "/etc/systemd/system/netfilter-persistent.service",
                "/lib/systemd/system/netfilter-persistent.service",
                "/usr/lib/systemd/system/netfilter-persistent.service",
            )
        )
        if not installed:
            return "missing"
        errors.append("netfilter-persistent: systemctl is unavailable; service state is unknown")
        return "unknown"
    result = run_query([
        systemctl, "show", "--property=LoadState", "--property=ActiveState",
        "--", "netfilter-persistent.service",
    ], errors, "netfilter-persistent")
    if result is None:
        return "unknown"
    properties = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if result.returncode == 0 and properties.get("LoadState") == "not-found":
        return "missing"
    if result.returncode == 0 and properties.get("LoadState") in ("loaded", "masked"):
        state = properties.get("ActiveState")
        if state in ("active", "inactive"):
            return state
    errors.append("netfilter-persistent: service state could not be established (exit {})".format(result.returncode))
    return "unknown"


def fingerprint_candidate(path, byte_budget):
    """Hash a bounded regular file; never parse or execute package content."""
    entry = {"path": path, "status": "unreadable", "sha256": None}
    consumed = 0
    if not os.path.isabs(path) or ".." in path.split("/") or "\x00" in path:
        entry["status"] = "invalid_path"
        return entry, consumed
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                entry["status"] = "not_regular"
                return entry, consumed
            entry["bytes"] = before.st_size
            if before.st_size > MAX_OVAL_FILE_BYTES:
                entry["status"] = "skipped_size_limit"
                return entry, consumed
            if before.st_size > byte_budget:
                entry["status"] = "skipped_budget_limit"
                return entry, consumed
            limit = min(MAX_OVAL_FILE_BYTES, byte_budget)
            digest = hashlib.sha256()
            while consumed <= limit:
                block = source.read(min(1024 * 1024, limit - consumed + 1))
                if not block:
                    break
                consumed += len(block)
                digest.update(block)
            after = os.fstat(source.fileno())
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if consumed > limit or consumed != before.st_size or identity(before) != identity(after):
                entry["status"] = "changed_during_read"
                return entry, consumed
            entry.update(status="hashed", sha256=digest.hexdigest())
    except OSError:
        # Includes missing files, unreadable paths and rejected symlinks.
        pass
    return entry, consumed


def collect_oval_metadata():
    """Describe local oval-db records without asserting vendor trust or CVEs."""
    result = {
        "package": "oval-db", "status": "unknown", "version": None,
        "architecture": None, "candidateFiles": [], "candidateCount": 0,
        "filesTruncated": False, "errors": [],
        "vendorSignature": "not_checked", "releaseApplicability": "not_checked",
        "vulnerabilityAssessment": "not_run",
    }
    binary = shutil.which("dpkg-query", path=SAFE_PATH)
    if binary is None:
        result["status"] = "package_manager_unavailable"
        return result
    package = run_query([binary, "-W", "-f=${Status}\t${Version}\t${Architecture}\n", "--", "oval-db"],
                        result["errors"], "oval-db package")
    if package is None:
        return result
    if package.returncode == 1 and "no packages found matching oval-db" in package.stderr:
        result["status"] = "not_installed"
        return result
    fields = package.stdout.strip().split("\t")
    if package.returncode != 0 or len(fields) != 3 or any(not value or len(value) > 256 or "\n" in value for value in fields):
        result["errors"].append("oval-db: package metadata unavailable or malformed (exit {})".format(package.returncode))
        return result
    package_status = fields[0].split()
    if len(package_status) != 3 or package_status[0] not in ("unknown", "install", "hold", "deinstall", "purge"):
        result["errors"].append("oval-db: unrecognized package status")
        return result
    if package_status[1:] != ["ok", "installed"]:
        result["status"] = "not_installed" if package_status[1] == "ok" and package_status[2] in ("config-files", "not-installed") else "unknown"
        if result["status"] == "unknown":
            result["errors"].append("oval-db: package is not in a confirmed installed state")
        return result
    result.update(status="installed", version=fields[1], architecture=fields[2])
    files = run_query([binary, "-L", "--", "oval-db"], result["errors"], "oval-db files")
    if files is None:
        return result
    if files.returncode != 0 or len(files.stdout) > 1024 * 1024:
        result["errors"].append("oval-db: package file list unavailable or exceeds the size limit")
        return result
    # Suffixes identify candidates only; compressed bytes are hashed as stored.
    candidates = sorted(set(path for path in files.stdout.splitlines()
                            if path.lower().endswith((".xml", ".xml.gz", ".xml.bz2", ".xml.xz"))))
    result.update(candidateCount=len(candidates), filesTruncated=len(candidates) > MAX_OVAL_FILES)
    budget = MAX_OVAL_TOTAL_BYTES
    for path in candidates[:MAX_OVAL_FILES]:
        entry, consumed = fingerprint_candidate(path, max(0, budget))
        budget -= consumed
        result["candidateFiles"].append(entry)
    return result


def collect_readiness():
    errors = []
    os_release_text = read_text("/etc/os-release", errors)
    os_release = parse_os_release(os_release_text, errors) if os_release_text is not None else {}
    astra_version = read_text("/etc/astra_version", errors, optional=True, max_bytes=4096)
    if astra_version is not None:
        astra_version = astra_version.strip()
        if not astra_version or len(astra_version) > 512:
            errors.append("/etc/astra_version: version is empty or exceeds the size limit")
            astra_version = None
    init_system = read_text("/proc/1/comm", errors, max_bytes=1024)
    tools = {name: shutil.which(name, path=SAFE_PATH) for name in TOOL_NAMES}
    uid = os.geteuid()
    if uid != 0:
        errors.append("Root privileges are required for complete readiness checks (effectiveUid={})".format(uid))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "osRelease": os_release,
        "astraVersion": astra_version,
        "kernel": platform.release(),
        "pythonVersion": platform.python_version(),
        "effectiveUid": uid,
        "initSystem": init_system.strip() if init_system is not None else None,
        "tools": tools,
        "firewall": {
            "ufw": ufw_state(tools["ufw"], errors),
            "firewalld": firewalld_state(tools["firewall-cmd"], errors),
            "netfilterPersistent": netfilter_persistent_state(tools["systemctl"], errors),
        },
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-oval-metadata", action="store_true",
                        help="Include local oval-db package metadata and bounded file digests; does not run a CVE audit")
    args = parser.parse_args()
    report = collect_readiness()
    if args.include_oval_metadata:
        report["localOval"] = collect_oval_metadata()
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
