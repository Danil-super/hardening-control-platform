#!/usr/bin/env python3
"""Read installed DEB/RPM/APK metadata without updating packages or repositories.

Target compatibility: Python 3.5+. Repository/vendor fields are observations,
not signature verification. Keep source versions native to their ecosystem.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_METADATA = 64 * 1024 * 1024
MAX_PACKAGES = 250000
MANAGERS = {
    "debian": "dpkg", "ubuntu": "dpkg", "astra": "dpkg", "astralinux": "dpkg",
    "rhel": "rpm", "redhat": "rpm", "redhatenterpriseserver": "rpm",
    "centos": "rpm", "centos-stream": "rpm", "rocky": "rpm", "almalinux": "rpm", "alma": "rpm",
    "fedora": "rpm", "ol": "rpm", "amzn": "rpm", "sles": "rpm", "sled": "rpm",
    "opensuse": "rpm", "opensuse-leap": "rpm", "opensuse-tumbleweed": "rpm",
    "slem": "rpm", "photon": "rpm", "cbl-mariner": "rpm", "azurelinux": "rpm",
    "alt": "rpm", "altlinux": "rpm", "redos": "rpm", "rosa": "rpm",
    "alpine": "apk", "wolfi": "apk", "chainguard": "apk",
}
DATABASES = {
    "dpkg": ("/var/lib/dpkg/status",),
    "rpm": ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite",
            "/usr/lib/sysimage/rpm/Packages", "/var/lib/rpm/Packages",
            "/usr/lib/sysimage/rpm/Packages.db", "/var/lib/rpm/Packages.db",
            "/usr/share/rpm/rpmdb.sqlite"),
    "apk": ("/lib/apk/db/installed", "/usr/lib/apk/db/installed"),
}


def run(command):
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        output = completed.stdout.decode("utf-8", "replace") if isinstance(completed.stdout, bytes) else completed.stdout
        error = completed.stderr.decode("utf-8", "replace") if isinstance(completed.stderr, bytes) else completed.stderr
        if len(output.encode("utf-8")) > MAX_METADATA:
            return None, "", "Package metadata exceeds the collection budget"
        return completed.returncode, output.rstrip("\n"), error.strip()
    except Exception as exc:
        return None, "", str(exc)


def read_text(path, limit=MAX_METADATA):
    with open(path, encoding="utf-8", errors="strict") as handle:
        value = handle.read(limit + 1)
    if len(value.encode("utf-8")) > limit:
        raise ValueError("Metadata exceeds the collection budget: " + path)
    return value


def read_os_release():
    # Do not merge /etc and /usr/lib: the administrator's file has precedence.
    path = "/etc/os-release" if os.path.lexists("/etc/os-release") else "/usr/lib/os-release"
    text = read_text(path, 65536)
    values = {}
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        key, separator, value = raw.partition("=")
        if not separator or not re.match(r"^[A-Z][A-Z0-9_]*$", key):
            raise ValueError("Unrecognized os-release assignment")
        fields = shlex.split(value, comments=False, posix=True)
        if len(fields) > 1:
            raise ValueError("Unquoted whitespace in os-release")
        # shlex parses quoting only; it never expands variables or executes text.
        values[key] = fields[0] if fields else ""
    return values


def database_paths(manager):
    return [entry for entry in DATABASES[manager] if os.path.isfile(entry)]


def select_manager(os_release):
    exact = MANAGERS.get(os_release.get("ID", "").lower())
    if exact:
        return exact, "os-id"
    relatives = {MANAGERS[value] for value in os_release.get("ID_LIKE", "").lower().split() if value in MANAGERS}
    if len(relatives) == 1:
        return relatives.pop(), "id-like-collection-only"
    candidates = [manager for manager in DATABASES if database_paths(manager)]
    if len(candidates) == 1:
        return candidates[0], "native-database"
    if len(candidates) > 1 or len(relatives) > 1:
        raise ValueError("Ambiguous native package manager; installed tools alone do not establish the OS package database")
    raise ValueError("No supported native package database (dpkg/rpm/apk) found")


def database_snapshot(manager):
    result = []
    entries = database_paths(manager)
    for entry in list(entries):
        # SQLite may update WAL before the primary RPM DB changes.
        entries.extend(item for item in (entry + "-wal", entry + "-journal") if os.path.isfile(item))
    for entry in entries:
        stat = os.stat(entry)
        result.append((entry, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
    return result


def debian_packages():
    code, output, error = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Maintainer}\t${Origin}\n"])
    packages = []
    if code != 0:
        return packages, error or "dpkg-query failed"
    for line in output.splitlines():
        parts = line.split("\t")
        status = parts[0]
        if len(status) != 3 or status[0] not in "uihrp" or status[1] not in "ncHUFWti" or status[2] not in " R":
            return packages, "Unrecognized dpkg package status"
        if status[1] in "nc" and status[2] == " ":
            continue
        if len(parts) != 8 or not all(parts[1:6]):
            return packages, "Incomplete dpkg package/source metadata"
        packages.append({"name": parts[1], "version": parts[2], "arch": parts[3], "manager": "dpkg",
                         "sourceName": parts[4], "sourceVersion": parts[5], "sourceEpochKnown": True,
                         "dpkgStatus": status, "maintainer": parts[6], "origin": parts[7]})
    return packages, ""


def rpm_packages():
    tag_code, tag_output, _ = run(["rpm", "--querytags"])
    tags = set(tag_output.upper().split()) if tag_code == 0 else set()
    epoch_tag = "EPOCHNUM" if "EPOCHNUM" in tags else "EPOCH"
    fields = ["NAME", epoch_tag, "VERSION", "RELEASE", "ARCH", "SOURCERPM", "VENDOR", "PACKAGER", "DISTRIBUTION"]
    modularity_queried = "MODULARITYLABEL" in tags
    fields.append("MODULARITYLABEL" if modularity_queried else None)
    query = "\t".join("%{" + field + "}" if field else "(none)" for field in fields) + "\n"
    code, output, error = run(["rpm", "-qa", "--qf", query])
    packages = []
    if code != 0:
        return packages, error or "RPM query failed"
    for line in output.splitlines():
        parts = ["" if value == "(none)" else value for value in line.split("\t")]
        if len(parts) != len(fields) or not all(parts[index] for index in (0, 2, 3)):
            return packages, "Incomplete RPM package metadata"
        name, epoch, version, release, arch, source_rpm, vendor, packager, distribution, modularity = parts
        if epoch and not re.match(r"^[0-9]+$", epoch):
            return packages, "Unrecognized RPM epoch"
        source = re.match(r"^(.+)-([^-]+)-([^-]+)\.(?:src|nosrc)\.rpm$", source_rpm)
        packages.append({"name": name, "version": (epoch + ":" if epoch not in ("", "0") else "") + version + "-" + release,
                         "arch": arch or "None", "manager": "rpm", "sourceRpm": source_rpm,
                         "sourceName": source.group(1) if source else "",
                         # SOURCERPM contains no source epoch. Never pretend the
                         # binary epoch is an independently observed source epoch.
                         "sourceVersion": source.group(2) + "-" + source.group(3) if source else "",
                         "sourceEpochKnown": False, "vendor": vendor, "maintainer": vendor,
                         "packager": packager, "distribution": distribution,
                         "modularityLabel": modularity, "rpmModularityQueried": modularity_queried,
                         "rpmRepositoryEvidence": "not-recorded-in-rpmdb"})
    return packages, ""


def apk_packages():
    paths = database_paths("apk")
    if not paths:
        return [], "APK installed database is unavailable"
    # /lib and /usr/lib may name the same database through a standard symlink.
    if len(paths) > 1 and not all(os.path.samefile(paths[0], item) for item in paths[1:]):
        return [], "Conflicting APK installed databases"
    text = read_text(paths[0])
    packages, fields = [], {}

    def append_package():
        if not fields:
            return
        if not all(fields.get(key) for key in ("P", "V", "A", "o")):
            raise ValueError("Incomplete APK name/version/architecture/source origin")
        if not re.match(r"^[0-9][0-9A-Za-z._+~]*-r[0-9]+$", fields["V"]):
            raise ValueError("Unrecognized APK version")
        packages.append({"name": fields["P"], "version": fields["V"], "arch": fields["A"], "manager": "apk",
                         "sourceName": fields["o"], "sourceVersion": fields["V"], "sourceEpochKnown": True,
                         "apkOrigin": fields["o"], "maintainer": fields.get("m", ""),
                         "apkCommit": fields.get("c", "")})
    try:
        for line in text.splitlines():
            if not line:
                append_package()
                fields = {}
            elif len(line) > 1 and line[1] == ":" and line[0] in ("P", "V", "A", "o", "m", "c"):
                if line[0] in fields:
                    raise ValueError("Duplicate APK package metadata field")
                fields[line[0]] = line[2:]
        append_package()
    except ValueError as exc:
        return packages, str(exc)
    return packages, ""


def apk_repositories(os_release):
    """Capture configured release hints, never credentials or installed origin."""
    try:
        text = read_text("/etc/apk/repositories", 65536)
    except (OSError, ValueError, UnicodeError):
        return {"status": "unavailable", "branches": [], "unknownEntries": 0}
    branches, unknown, count = set(), 0, 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        count += 1
        value = line.split(None, 1)[1] if line.startswith("@") and len(line.split(None, 1)) == 2 else line
        try:
            parsed = urlsplit(value)
            branch = re.search(r"/(v[0-9]+\.[0-9]+|edge)/(?:main|community|testing)(?:/|$)", parsed.path)
            if branch:
                branches.add(branch.group(1))
            elif os_release.get("ID") == "wolfi" and parsed.path.rstrip("/").endswith("/os"):
                branches.add("rolling")
            else:
                unknown += 1
        except ValueError:
            unknown += 1
    return {"status": "observed" if count else "empty", "branches": sorted(branches), "unknownEntries": unknown,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "scope": "configured-repositories; installed-origin-not-attested"}


def collect():
    os_release, packages, error, manager, selection = {}, [], "", None, None
    extra = {}
    try:
        os_release = read_os_release()
        manager, selection = select_manager(os_release)
        command = {"dpkg": "dpkg-query", "rpm": "rpm", "apk": "apk"}[manager]
        if not shutil.which(command):
            raise ValueError("The native package manager is unavailable: " + command)
        before = database_snapshot(manager)
        if not before:
            raise ValueError("The selected native package database is unavailable: " + manager)
        packages, error = {"dpkg": debian_packages, "rpm": rpm_packages, "apk": apk_packages}[manager]()
        if manager == "apk":
            extra["apkRepositories"] = apk_repositories(os_release)
        if before != database_snapshot(manager):
            error = "The native package database changed during collection; repeat the inventory"
        if len(packages) > MAX_PACKAGES:
            packages, error = [], "Package count exceeds the collection budget"
    except (OSError, ValueError, UnicodeError) as exc:
        error = str(exc)
    if not packages and not error:
        error = "Package inventory is empty"
    try:
        astra_version = read_text("/etc/astra_version", 4096).strip() or None
    except (OSError, ValueError, UnicodeError):
        astra_version = None
    partial_reasons = [error] if error else []
    unsettled = [item for item in packages if item["manager"] == "dpkg" and (item["dpkgStatus"][1] != "i" or item["dpkgStatus"][2] != " ")]
    if unsettled:
        partial_reasons.append("dpkg reports {} packages in an incomplete or error state; their files may already be present. Complete package recovery and collect the inventory again.".format(len(unsettled)))
    created_at = datetime.now(timezone.utc).isoformat()
    inventory = {"osRelease": os_release, "astraVersion": astra_version, "packageCount": len(packages), "manager": manager,
                 "managerSelection": selection, "collectorVersion": 2, "error": error, "partial": bool(partial_reasons), "partialReasons": partial_reasons}
    inventory.update(extra)
    return {"schemaVersion": 1, "action": "packageInventory", "runId": os.environ.get("REPORT_RUN_ID"),
            "inventoryHost": os.environ.get("INVENTORY_HOST"), "auditId": "packages_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "createdAt": created_at, "hostname": socket.gethostname(),
            "os": os_release.get("PRETTY_NAME") or os_release.get("NAME") or "Unknown Linux",
            "profileId": "packages", "mode": "packages", "partial": bool(partial_reasons), "packageInventory": inventory,
            "summary": {"score": None, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(packages)},
            "findings": [], "packages": packages}


def main():
    print(json.dumps(collect(), ensure_ascii=True))


if __name__ == "__main__":
    main()
