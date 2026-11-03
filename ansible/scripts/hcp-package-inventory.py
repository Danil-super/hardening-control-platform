#!/usr/bin/env python3
"""Read installed DEB/RPM/APK metadata without updating packages or repositories.

Target compatibility: Python 3.5+. Repository/vendor fields are observations,
not signature verification. Keep source versions native to their ecosystem.
"""
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

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
RPM_BACKENDS = {"sqlite": "rpmdb.sqlite", "ndb": "Packages.db", "bdb": "Packages", "bdb_ro": "Packages"}
RPM_DATABASE_QUERY = "%{_dbpath}\n%{?_db_backend}\nHCP-RPM-DATABASE-END"


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


def database_snapshot(manager, exclude=(), paths=None):
    result = []
    entries = [entry for entry in (database_paths(manager) if paths is None else paths) if entry not in exclude]
    for entry in list(entries):
        # SQLite may update WAL before the primary RPM DB changes.
        entries.extend(item for item in (entry + "-wal", entry + "-journal") if os.path.isfile(item))
    for entry in entries:
        stat = os.stat(entry)
        result.append((entry, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns))
    return result


class DatabaseConsistency:
    """Observe SQLite commits without mistaking reader bookkeeping for writes.

    RPM's SQLite reader can change WAL ctime and shared-memory metadata without
    changing a package. PRAGMA data_version, on the same persistent read-only
    connection, observes commits by other connections including write/revert.
    Do not BEGIN a read transaction here: that would hide commits from this
    observer. Path/inode checks also reject database replacement or migration.
    Other native backends retain their physical database snapshot guard.
    """
    def __init__(self, manager, candidates=None):
        self.manager = manager
        self.candidates = candidates
        self.sqlite_paths = set()
        self.connections = []
        self.sqlite_error = ()

    def current_paths(self):
        if self.candidates is None:
            return database_paths(self.manager)
        return [path for path in self.candidates if os.path.isfile(path)]

    def snapshot(self):
        if self.candidates is not None:
            return database_snapshot(self.manager, self.sqlite_paths, self.current_paths())
        if self.sqlite_paths:
            return database_snapshot(self.manager, self.sqlite_paths)
        return database_snapshot(self.manager)

    @staticmethod
    def identities(paths):
        result = []
        for path in sorted(paths):
            stat = os.stat(path)
            result.append((path, os.path.realpath(path), stat.st_dev, stat.st_ino))
        return result

    @staticmethod
    def data_version(connection):
        row = connection.execute("PRAGMA data_version").fetchone()
        if row is None or len(row) != 1 or not isinstance(row[0], int):
            raise ValueError("SQLite cannot observe package database commits")
        return row[0]

    def __enter__(self):
        try:
            if self.manager == "rpm":
                self.paths = set(self.current_paths())
                self.sqlite_paths = {path for path in self.paths if path.endswith("rpmdb.sqlite")}
            if self.sqlite_paths:
                try:
                    import sqlite3
                except ImportError:
                    raise ValueError("Python SQLite support is required to verify RPM database consistency")
                self.sqlite_error = sqlite3.Error
                self.before_identities = self.identities(self.sqlite_paths)
                # Standard /var/lib and /usr/lib aliases may name one database.
                for path in sorted({item[1] for item in self.before_identities}):
                    connection = sqlite3.connect("file:" + quote(path, safe="/") + "?mode=ro",
                                                 uri=True, timeout=5, isolation_level=None)
                    self.connections.append((connection, None))
                    self.connections[-1] = (connection, self.data_version(connection))
                if self.before_identities != self.identities(self.sqlite_paths):
                    raise ValueError("The native package database changed while opening its consistency observer")
            self.before = self.snapshot()
            if not self.before and not self.sqlite_paths:
                raise ValueError("The selected native package database is unavailable: " + self.manager)
            return self
        except BaseException as exc:
            self.close()
            if isinstance(exc, self.sqlite_error):
                raise ValueError("Cannot verify SQLite RPM database consistency: " + str(exc))
            raise

    def unchanged(self):
        try:
            if self.sqlite_paths:
                if self.paths != set(self.current_paths()) or self.before_identities != self.identities(self.sqlite_paths):
                    return False
                if any(before != self.data_version(connection) for connection, before in self.connections):
                    return False
            return self.before == self.snapshot()
        except self.sqlite_error as exc:
            raise ValueError("Cannot verify SQLite RPM database consistency: " + str(exc))

    def close(self):
        for connection, unused in self.connections:
            connection.close()
        self.connections = []

    def __exit__(self, unused_type, unused_value, unused_traceback):
        self.close()


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




def debian_apt_repository_observation(os_release):
    """Read APT's configured package *index hints*, not an installed-package
    origin, trusted Release signature, or package archive verification.

    No apt-get update, arbitrary user URL, network access or package changes.
    Returned summaries omit all repository URLs, paths, usernames and tokens.
    """
    base = {"schemaVersion": 1, "status": "unavailable", "releaseCodename": os_release.get("VERSION_CODENAME") or None,
            "indexEntries": 0, "debianLabelEntries": 0, "otherLabelEntries": 0,
            "unknownLabelEntries": 0, "suites": [], "releaseLabels": [],
            "suiteConsistent": False, "policySha256": None,
            "publisherAuthenticated": False, "repositorySignatureVerified": False,
            "installedPackageOriginVerified": False,
            "scope": "apt-cache-policy-index-metadata-only; no-installed-origin-or-signature-attestation"}
    if os_release.get("ID") != "debian":
        return base
    codename = base["releaseCodename"]
    if not isinstance(codename, str) or not re.match(r"^[a-z][a-z0-9-]{1,31}$", codename):
        return base
    if not shutil.which("apt-cache"):
        return base
    code, output, error = run(["env", "LC_ALL=C", "apt-cache",
                              "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "policy"])
    if code != 0 or not isinstance(output, str) or len(output.encode("utf-8")) > 512 * 1024:
        return base

    # Accept only APT's release metadata lines between the documented package
    # files and pinned package sections. Pin priorities and URLs are ignored.
    active, fields, invalid = False, [], False
    for line in output.splitlines():
        if line == "Package files:":
            active = True
            continue
        if line == "Pinned packages:":
            active = False
            break
        if not active or not re.match(r"^\s+release\s+", line):
            continue
        raw = line.strip()[len("release "):]
        # /var/lib/dpkg/status appears as "release a=now". It is NOT an
        # APT repository and must not become a malformed publisher claim.
        if raw == "a=now":
            continue
        props = {}
        for piece in raw.split(","):
            key, sep, val = piece.strip().partition("=")
            if (not sep or key in props or key not in ("v", "o", "a", "n", "l", "c", "b")
                    or len(val) > 80 or not re.match(r"^[A-Za-z0-9.+_~:/ -]+$", val)):
                invalid = True
                break
            props[key] = val
        if invalid:
            break
        # Only entries with an explicit release label and suite are comparable.
        # This does not assert that APT verified Release signatures.
        if (not props.get("n") or not props.get("o")
                or not re.match(r"^[a-z][a-z0-9-]{1,31}$", props["n"])):
            invalid = True
            break
        fields.append(props)
        if len(fields) > 1024:
            invalid = True
            break
    if invalid or not fields:
        return dict(base, status="ambiguous", policySha256=hashlib.sha256(output.encode("utf-8")).hexdigest())

    suites = sorted(set(item["n"] for item in fields))
    # Never publish arbitrary labels from untrusted indexes: they may contain
    # infrastructure names or operator-specific data.
    labels = []
    if any(item["o"] == "Debian" for item in fields):
        labels.append("Debian")
    if any(item["o"] != "Debian" for item in fields):
        labels.append("other-label-observed")
    allowed = set((codename, codename + "-security", codename + "-updates", codename + "-backports"))
    consistent = bool(fields) and all(item["n"] in allowed for item in fields)
    official = sum(1 for item in fields if item["o"] == "Debian")
    return dict(base, status="observed", indexEntries=len(fields),
                debianLabelEntries=official,
                otherLabelEntries=sum(1 for item in fields if item["o"] not in ("Debian",)),
                unknownLabelEntries=0,
                suites=suites[:32], releaseLabels=labels[:32],
                suiteConsistent=consistent and len(suites) <= 32 and len(labels) <= 32,
                policySha256=hashlib.sha256(output.encode("utf-8")).hexdigest())


# Read-only Debian archive signature verification. This verifies a cached
# InRelease signature with the guest's installed archive keyring, NOT the
# external authenticity of that keyring, package-list hashes or installed .deb.
DEBIAN_INRELEASE_DIR = "/var/lib/apt/lists"
DEBIAN_ARCHIVE_KEYRING = "/usr/share/keyrings/debian-archive-keyring.gpg"
DEBIAN_INRELEASE_MAX_BYTES = 4 * 1024 * 1024
DEBIAN_KEYRING_MAX_BYTES = 4 * 1024 * 1024


def _private_cached_regular(path, maximum):
    """No links/special files, bounded bytes and in-place mutation detection."""
    original = os.lstat(path)
    if not stat.S_ISREG(original.st_mode) or original.st_size < 1 or original.st_size > maximum:
        raise ValueError("Cached Debian release/keyring file is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_ino != original.st_ino
                or before.st_dev != original.st_dev or before.st_size != original.st_size):
            raise ValueError("Cached Debian file was replaced before opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if (len(value) != before.st_size
                or any(getattr(before, key) != getattr(after, key)
                       or getattr(after, key) != getattr(current, key) for key in keys)):
            raise ValueError("Cached Debian file changed during verification")
        return value
    finally:
        os.close(descriptor)


def _debian_inrelease_headers(raw, codename):
    """Parse conservative signed cleartext. No unsigned fields are accepted."""
    text = raw.decode("utf-8", "strict")
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        raise ValueError("Cached release is not PGP cleartext")
    beginning = text.find("\n\n")
    ending = text.find("\n-----BEGIN PGP SIGNATURE-----")
    if beginning < 0 or ending <= beginning:
        raise ValueError("PGP release markers are incomplete")
    headers = {}
    for line in text[beginning + 2:ending].splitlines():
        if line.startswith("- "):
            line = line[2:]
        if not line or line[0] in " \t":
            continue
        key, separator, value = line.partition(":")
        if separator and key in ("Origin", "Label", "Suite", "Codename", "Date", "Valid-Until"):
            if key in headers or len(value) > 180:
                raise ValueError("Duplicate or oversized signed Release field")
            headers[key] = value.strip()
    allowed = (codename, codename + "-security", codename + "-updates", codename + "-backports")
    release = headers.get("Codename")
    if release not in allowed:
        raise ValueError("Cached signed release does not match exact OS codename")
    # Debian's official backports suite has the distinct, signed
    # 'Origin: Debian Backports'. Never accept it for base/security/updates.
    expected_origin = "Debian Backports" if release == codename + "-backports" else "Debian"
    if headers.get("Origin") != expected_origin:
        raise ValueError("Cached signed release Origin differs from its exact suite")
    if not headers.get("Date"):
        raise ValueError("Signed release has no publication date")
    # Do not treat Valid-Until or Date as independently publisher-fresh.
    return headers["Codename"]


def debian_cached_inrelease_signatures(os_release):
    """Observe local gpgv verification against the installed Debian keyring.

    This is intentionally NOT a publisher trust anchor: the archive keyring is
    part of the host's own installed software and is not independently pinned.
    No package-index chain, installed archive or remote URL is authenticated.
    """
    base = {
        "schemaVersion": 1, "status": "unavailable", "releaseCodename": os_release.get("VERSION_CODENAME") or None,
        "candidateFiles": 0, "validLocalSignatures": 0, "invalidOrUnverifiable": 0,
        "signedReleases": [], "signerFingerprints": [], "inReleaseSha256": [],
        "localKeyringSha256": None, "localSignatureVerified": False,
        "publisherAuthenticated": False, "publisherFreshnessVerified": False,
        "packageIndexHashesVerified": False, "installedPackageOriginVerified": False,
        "remediationAuthorized": False,
        "scope": "cached-inrelease-gpgv-installed-archive-keyring-only",
    }
    if os_release.get("ID") != "debian":
        return base
    codename = base["releaseCodename"]
    if not isinstance(codename, str) or not re.match(r"^[a-z][a-z0-9-]{1,31}$", codename):
        return base
    if not shutil.which("gpgv"):
        return base
    try:
        directory = os.lstat(DEBIAN_INRELEASE_DIR)
        if not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode):
            return base
        keyring_path = DEBIAN_ARCHIVE_KEYRING
        # On modern Debian, the .gpg compatibility name is legitimately a
        # same-directory link to the .pgp binary archive keyring. Accept ONLY
        # this exact fixed alias; no arbitrary filesystem traversal or URL.
        if stat.S_ISLNK(os.lstat(keyring_path).st_mode):
            if (os.path.basename(keyring_path) != "debian-archive-keyring.gpg"
                    or os.readlink(keyring_path) != "debian-archive-keyring.pgp"):
                raise ValueError("Unsupported Debian archive keyring symlink")
            keyring_path = os.path.join(os.path.dirname(keyring_path), "debian-archive-keyring.pgp")
        keyring = _private_cached_regular(keyring_path, DEBIAN_KEYRING_MAX_BYTES)
        base["localKeyringSha256"] = hashlib.sha256(keyring).hexdigest()
        names = os.listdir(DEBIAN_INRELEASE_DIR)
        if len(names) > 20000:
            return dict(base, status="ambiguous")
        allowed = {codename, codename + "-security", codename + "-updates", codename + "-backports"}
        selected = []
        for name in names:
            if len(name) > 360 or not re.match(r"^[A-Za-z0-9._-]+$", name):
                continue
            part = re.search(r"_dists_([a-z][a-z0-9-]{1,31})_InRelease$", name)
            if part and part.group(1) in allowed:
                selected.append(name)
        if len(selected) > 12:
            return dict(base, status="ambiguous", candidateFiles=len(selected))
        if not selected:
            return base
        base["candidateFiles"] = len(selected)
        for name in sorted(selected):
            filename = os.path.join(DEBIAN_INRELEASE_DIR, name)
            before = _private_cached_regular(filename, DEBIAN_INRELEASE_MAX_BYTES)
            signed_release = _debian_inrelease_headers(before, codename)
            # No shell and no network. A result is valid only when gpgv actually
            # checked the *same* bytes later returned by the bounded reader.
            check = subprocess.run(
                ["gpgv", "--status-fd", "1", "--keyring", keyring_path, filename],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False,
            )
            after = _private_cached_regular(filename, DEBIAN_INRELEASE_MAX_BYTES)
            if _private_cached_regular(keyring_path, DEBIAN_KEYRING_MAX_BYTES) != keyring:
                raise ValueError("Debian archive keyring changed during verification")
            if before != after:
                raise ValueError("Cached signed Release changed during gpgv")
            output = check.stdout[:65536].decode("ascii", "replace")
            fingerprints = re.findall(r"^\[GNUPG:\] VALIDSIG ([A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\s", output, re.M)
            good = "[GNUPG:] GOODSIG " in output
            if (check.returncode != 0 or not good or not fingerprints
                    or any("[GNUPG:] " + label in output for label in (
                        "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"))):
                base["invalidOrUnverifiable"] += 1
                continue
            base["validLocalSignatures"] += 1
            base["signedReleases"].append(signed_release)
            base["signerFingerprints"].extend(x.lower() for x in fingerprints)
            base["inReleaseSha256"].append(hashlib.sha256(before).hexdigest())
        base["signerFingerprints"] = sorted(set(base["signerFingerprints"]))[:16]
        base["signedReleases"] = sorted(set(base["signedReleases"]))
        base["inReleaseSha256"].sort()
        # Only an observation that every selected cached InRelease was
        # cryptographically verified with the LOCAL keyring earns this status.
        base["localSignatureVerified"] = base["validLocalSignatures"] == len(selected)
        base["status"] = "verified_with_local_keyring" if base["localSignatureVerified"] else "partial"
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        base["status"] = "unavailable"
        base["localSignatureVerified"] = False
    return base



# The *selected APT package index* verification is distinct from the local
# gpgv observation. InRelease SHA256 can cover uncompressed Packages bytes
# even if APT stores them as .lz4. apt-helper cat-file is APT's read-only
# decompressor. No package is installed/downloaded, and no URL is fetched.
DEBIAN_INDEX_MAX_FILES = 8
DEBIAN_INDEX_MAX_ENCODED_BYTES = 64 * 1024 * 1024
DEBIAN_INDEX_MAX_DECODED_BYTES = 160 * 1024 * 1024
DEBIAN_INDEX_MAX_DURATION = 35


def _debian_signed_package_hashes(raw, codename):
    """Only accept a bounded SHA256 stanza inside a verified InRelease.

    Keys are exact main/binary-amd64/Packages-style relative filenames;
    never parse a path containing traversal, comments or arbitrary URLs.
    """
    release = _debian_inrelease_headers(raw, codename)
    text = raw.decode("utf-8", "strict")
    start = text.find("\n\n")
    end = text.find("\n-----BEGIN PGP SIGNATURE-----")
    signed = text[start + 2:end]
    inside = False
    found = {}
    saw_sha256 = False
    for line in signed.splitlines():
        if line == "SHA256:":
            if saw_sha256:
                raise ValueError("Duplicate SHA256 section in signed release")
            saw_sha256, inside = True, True
            continue
        if not inside:
            continue
        if line and line[0] not in " \t":
            break
        parts = line.strip().split()
        if not parts:
            continue
        if len(parts) != 3 or not re.match(r"^[a-f0-9]{64}$", parts[0], re.I) or not re.match(r"^[0-9]{1,12}$", parts[1]):
            raise ValueError("Malformed SHA256 entry in signed Debian Release")
        key = parts[2]
        if not re.match(r"^[a-z][a-z0-9-]{0,31}/binary-[a-z0-9]{2,20}/Packages$", key):
            continue
        if key in found:
            raise ValueError("Duplicate package-index SHA256 key in signed Release")
        length = int(parts[1])
        if length < 1 or length > DEBIAN_INDEX_MAX_DECODED_BYTES:
            # An index too large for this probe is not silently declared good.
            found[key] = (parts[0].lower(), length)
            continue
        found[key] = (parts[0].lower(), length)
        if len(found) > 1024:
            raise ValueError("Excessive Packages SHA256 entry count")
    if not saw_sha256:
        raise ValueError("Signed Debian Release has no SHA256 section")
    return release, found


# Compare only exact installed dpkg name/architecture/version tuples with
# records observed in a locally hash-verified Packages index. This establishes
# a candidate RECORD in a local cache, not the origin of the installed .deb.
DEBIAN_CANDIDATE_SCOPE = "installed-dpkg-version-in-locally-verified-Packages-record-v1"
DEBIAN_CANDIDATE_MAX_LINE = 2 * 1024 * 1024
DEBIAN_CANDIDATE_MAX_RECORDS = 1000000


def _debian_installed_candidate_keys(packages):
    if not isinstance(packages, list) or len(packages) > MAX_PACKAGES:
        raise ValueError("Invalid installed dpkg candidate inventory")
    keys = set()
    for item in packages:
        if not isinstance(item, dict):
            raise ValueError("Invalid installed package metadata")
        if item.get("manager") != "dpkg" or item.get("dpkgStatus") != "ii ":
            continue
        name, arch, version = item.get("name"), item.get("arch"), item.get("version")
        if not all(isinstance(x, str) for x in (name, arch, version)):
            raise ValueError("Invalid installed dpkg candidate types")
        if name.endswith(":" + arch):
            name = name[:-(len(arch) + 1)]
        if (not re.match(r"^[a-z0-9][a-z0-9.+-]{0,254}$", name)
                or not re.match(r"^[a-z0-9][a-z0-9-]{0,31}$", arch)
                or len(version) > 256 or not re.match(r"^[0-9][A-Za-z0-9.+:~\-]*$", version)):
            raise ValueError("Unsupported installed dpkg candidate identity")
        keys.add((name, arch, version))
    return keys


class _DebianPackageCandidateScanner:
    """Bounded RFC822-like Packages stanza reader; never retains descriptions.

    Only exact package, version and architecture metadata is compared. A
    matching index record does not attest that the installed .deb came from it.
    """
    def __init__(self, installed):
        self.installed = installed
        self.buffer = b""
        self.fields = {}
        self.record_count = 0
        self.matched = set()

    def _finish_record(self):
        if not self.fields:
            return
        self.record_count += 1
        if self.record_count > DEBIAN_CANDIDATE_MAX_RECORDS:
            raise ValueError("Debian index record budget exceeded")
        if all(field in self.fields for field in ("Package", "Version", "Architecture")):
            identity = (self.fields["Package"], self.fields["Architecture"], self.fields["Version"])
            if identity in self.installed:
                self.matched.add(identity)
        self.fields = {}

    def _line(self, raw):
        if len(raw) > DEBIAN_CANDIDATE_MAX_LINE or raw.endswith(b"\r"):
            raise ValueError("Oversized or malformed Debian package record line")
        if not raw:
            self._finish_record()
            return
        if raw[:1] in (b" ", b"\t"):
            return
        for key in (b"Package", b"Version", b"Architecture"):
            if raw.startswith(key + b":"):
                if not raw.startswith(key + b": ") or key.decode("ascii") in self.fields:
                    raise ValueError("Ambiguous Debian package record identity")
                value = raw[len(key) + 2:].decode("utf-8", "strict")
                if not value or len(value) > 512 or "\x00" in value:
                    raise ValueError("Invalid Debian package record identity")
                self.fields[key.decode("ascii")] = value
                return

    def feed(self, chunk):
        self.buffer += chunk
        if len(self.buffer) > DEBIAN_CANDIDATE_MAX_LINE + 65536:
            raise ValueError("Debian package record line exceeded memory budget")
        while True:
            offset = self.buffer.find(b"\n")
            if offset < 0:
                break
            line = self.buffer[:offset]
            self.buffer = self.buffer[offset + 1:]
            self._line(line)

    def finish(self):
        if self.buffer:
            self._line(self.buffer)
        self.buffer = b""
        self._finish_record()
        return self.matched


def _debian_candidate_summary(eligible, matched=None):
    base = {
        "schemaVersion": 1, "status": "unavailable", "eligibleInstalled": len(eligible),
        "exactInstalledVersionCandidates": 0, "matchedIdentitySha256": None,
        "scope": DEBIAN_CANDIDATE_SCOPE, "publisherAuthenticated": False,
        "installedPackageOriginVerified": False, "remediationAuthorized": False,
    }
    if matched is not None:
        # Canonical identity digest is a commitment, not a publisher signature.
        canonical = json.dumps(sorted(matched), ensure_ascii=True, separators=(",", ":")).encode("ascii")
        base["status"] = "candidate_record_match" if matched else "no_exact_match"
        base["exactInstalledVersionCandidates"] = len(matched)
        base["matchedIdentitySha256"] = hashlib.sha256(canonical).hexdigest()
    return base


def _debian_apt_helper_sha256(filename, installed_candidates=None):
    """Bounded decompression and hashing with a hard time and byte budget.

    APT helper is fixed at the distribution's local path and invoked without
    a shell, network or unbounded stdout capture. This never writes caches.
    """
    executable = "/usr/lib/apt/apt-helper"
    if not os.path.isfile(executable):
        raise ValueError("APT helper is missing")
    process = subprocess.Popen(
        [executable, "cat-file", filename], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
    )
    digest = hashlib.sha256()
    matcher = _DebianPackageCandidateScanner(installed_candidates) if installed_candidates is not None else None
    total = 0
    deadline = time.monotonic() + DEBIAN_INDEX_MAX_DURATION
    poller = selectors.DefaultSelector()
    try:
        poller.register(process.stdout, selectors.EVENT_READ)
        while poller.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("APT decompression exceeded time budget")
            for key, unused in poller.select(min(remaining, 0.5)):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    poller.unregister(key.fileobj)
                    continue
                total += len(block)
                if total > DEBIAN_INDEX_MAX_DECODED_BYTES:
                    raise ValueError("APT decompression exceeded decoded byte budget")
                digest.update(block)
                if matcher is not None:
                    matcher.feed(block)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if process.returncode != 0 or total == 0:
            raise ValueError("APT decompression failed")
        if matcher is not None:
            return digest.hexdigest(), total, matcher.finish()
        return digest.hexdigest(), total
    finally:
        poller.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def debian_cached_package_index_hashes(os_release, signed_summary, installed_packages=None):
    """Verify locally cached *uncompressed* Packages against signed Release.

    A local gpgv verification and selected fixed Debian suite are prerequisites.
    The installed archive keyring itself is NOT independently authenticated.
    No installed .deb or individual installed-package provenance is attested.
    """
    codename = os_release.get("VERSION_CODENAME")
    result = {
        "schemaVersion": 1, "status": "unavailable", "releaseCodename": codename,
        "candidateIndexes": 0, "matchedIndexes": 0, "missingSignedHashes": 0,
        "mismatchedIndexes": 0, "indexRecords": [],
        "verifiedAgainstLocallySignedRelease": False,
        "publisherAuthenticated": False, "keyringIndependentlyAuthenticated": False,
        "publisherFreshnessVerified": False, "installedPackageOriginVerified": False,
        "remediationAuthorized": False,
        "scope": "cached-debian-packages-uncompressed-sha256-locally-signed-release-v1",
    }
    if (os_release.get("ID") != "debian" or not isinstance(codename, str)
            or not re.match(r"^[a-z][a-z0-9-]{1,31}$", codename)
            or not isinstance(signed_summary, dict)
            or signed_summary.get("status") != "verified_with_local_keyring"
            or signed_summary.get("localSignatureVerified") is not True
            or signed_summary.get("publisherAuthenticated") is not False
            or signed_summary.get("installedPackageOriginVerified") is not False):
        return result
    try:
        installed_keys = _debian_installed_candidate_keys(installed_packages) if installed_packages is not None else None
        if installed_keys is not None:
            result["installedVersionCandidates"] = _debian_candidate_summary(installed_keys)
        keyring_path = DEBIAN_ARCHIVE_KEYRING
        if stat.S_ISLNK(os.lstat(keyring_path).st_mode):
            if (os.path.basename(keyring_path) != "debian-archive-keyring.gpg"
                    or os.readlink(keyring_path) != "debian-archive-keyring.pgp"):
                raise ValueError("Unexpected local Debian archive keyring link")
            keyring_path = os.path.join(os.path.dirname(keyring_path), "debian-archive-keyring.pgp")
        keyring = _private_cached_regular(keyring_path, DEBIAN_KEYRING_MAX_BYTES)
        if hashlib.sha256(keyring).hexdigest() != signed_summary.get("localKeyringSha256"):
            raise ValueError("Cached Debian signer keyring changed")
        # The previous gpgv phase attested an exact multiset of cached
        # InRelease files. A vanished file must not turn the remaining subset
        # into a fresh success when the package indexes are checked.
        expected_digests = signed_summary.get("inReleaseSha256")
        if (not isinstance(expected_digests, list) or not expected_digests
                or len(expected_digests) > 12
                or signed_summary.get("candidateFiles") != len(expected_digests)
                or signed_summary.get("validLocalSignatures") != len(expected_digests)
                or any(not isinstance(digest, str)
                       or not re.match(r"^[a-f0-9]{64}$", digest)
                       for digest in expected_digests)):
            raise ValueError("Invalid prior InRelease signature inventory")
        names = os.listdir(DEBIAN_INRELEASE_DIR)
        if len(names) > 20000:
            raise ValueError("Too many local APT files")
        release_map = {}
        observed_digests = []
        accepted_suites = {codename, codename + "-security", codename + "-updates", codename + "-backports"}
        for name in names:
            if len(name) > 360 or not re.match(r"^[A-Za-z0-9._-]+$", name):
                continue
            matched = re.search(r"_dists_([a-z][a-z0-9-]{1,31})_InRelease$", name)
            if not matched or matched.group(1) not in accepted_suites:
                continue
            full = os.path.join(DEBIAN_INRELEASE_DIR, name)
            raw = _private_cached_regular(full, DEBIAN_INRELEASE_MAX_BYTES)
            release_digest = hashlib.sha256(raw).hexdigest()
            if release_digest not in expected_digests:
                raise ValueError("Unrecognized InRelease digest")
            release, hashes = _debian_signed_package_hashes(raw, codename)
            check = subprocess.run(
                ["gpgv", "--status-fd", "1", "--keyring", keyring_path, full],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=False,
            )
            status = check.stdout[:65536].decode("ascii", "replace")
            if (check.returncode != 0 or "[GNUPG:] GOODSIG " not in status
                    or not re.search(r"^\[GNUPG:\] VALIDSIG (?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\s", status, re.M)
                    or any("[GNUPG:] " + word in status for word in (
                        "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"))):
                raise ValueError("Cached Debian release signature no longer verifies")
            if _private_cached_regular(full, DEBIAN_INRELEASE_MAX_BYTES) != raw:
                raise ValueError("InRelease changed during index validation")
            prefix = name[:-len("InRelease")]
            if prefix in release_map:
                raise ValueError("Ambiguous Debian release cache prefix")
            release_map[prefix] = (release, hashes, release_digest)
            observed_digests.append(release_digest)
        if sorted(observed_digests) != sorted(expected_digests):
            raise ValueError("Cached InRelease set changed between audit phases")
        observed = []
        for name in names:
            if len(name) > 360 or not re.match(r"^[A-Za-z0-9._-]+$", name):
                continue
            match = re.search(
                r"_dists_([a-z][a-z0-9-]{1,31})_([a-z][a-z0-9-]{0,31})_binary-([a-z0-9]{2,20})_Packages(?:\.(lz4|gz|xz))?$",
                name,
            )
            if not match or match.group(1) not in accepted_suites:
                continue
            index_prefix = name[:match.start(2)]
            key = match.group(2) + "/binary-" + match.group(3) + "/Packages"
            if index_prefix not in release_map or release_map[index_prefix][0] != match.group(1):
                continue
            observed.append((name, match.group(1), match.group(2), match.group(3), key, index_prefix))
        if len(observed) > DEBIAN_INDEX_MAX_FILES:
            return dict(result, status="budget_exceeded", candidateIndexes=len(observed))
        if not observed:
            return result
        result["candidateIndexes"] = len(observed)
        matched_installed = set()
        for name, release, component, arch, relative, prefix in sorted(observed):
            expected = release_map[prefix][1].get(relative)
            if not expected:
                result["missingSignedHashes"] += 1
                continue
            filename = os.path.join(DEBIAN_INRELEASE_DIR, name)
            packed = _private_cached_regular(filename, DEBIAN_INDEX_MAX_ENCODED_BYTES)
            if installed_keys is None:
                actual_digest, actual_length = _debian_apt_helper_sha256(filename)
                index_candidates = set()
            else:
                actual_digest, actual_length, index_candidates = _debian_apt_helper_sha256(
                    filename, installed_keys)
            if _private_cached_regular(filename, DEBIAN_INDEX_MAX_ENCODED_BYTES) != packed:
                raise ValueError("Package index changed while decompressing")
            if actual_digest != expected[0] or actual_length != expected[1]:
                result["mismatchedIndexes"] += 1
                continue
            matched_installed.update(index_candidates)
            result["matchedIndexes"] += 1
            result["indexRecords"].append({
                "suite": release, "component": component, "architecture": arch,
                "releaseSha256": release_map[prefix][2], "packagesSha256": actual_digest,
                "packagesBytes": actual_length,
            })
        if hashlib.sha256(_private_cached_regular(keyring_path, DEBIAN_KEYRING_MAX_BYTES)).hexdigest() != signed_summary.get("localKeyringSha256"):
            raise ValueError("Signer keyring changed during package index validation")
        result["verifiedAgainstLocallySignedRelease"] = (
            result["matchedIndexes"] == result["candidateIndexes"] and result["candidateIndexes"] > 0)
        result["status"] = "locally_hash_matched" if result["verifiedAgainstLocallySignedRelease"] else "partial"
        if installed_keys is not None and result["verifiedAgainstLocallySignedRelease"]:
            result["installedVersionCandidates"] = _debian_candidate_summary(installed_keys, matched_installed)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        # Do not publish partial success on a potentially changed/ambiguous input.
        result["status"] = "unavailable"
        result["verifiedAgainstLocallySignedRelease"] = False
        result["matchedIndexes"] = 0
        result["indexRecords"] = []
    return result


def resolve_rpm_database():
    """Resolve only RPM's native directory and three supported backend files.

    The sentinel preserves empty/trailing fields through run()'s newline trim.
    Native --dbpath and --define argv pin subsequent queries to this observed
    database. No shell, directory walk, DB creation or implicit fallback.
    """
    code, output, error = run(["rpm", "--eval", RPM_DATABASE_QUERY])
    values = output.split("\n")
    if code != 0 or len(values) != 3 or values[2] != "HCP-RPM-DATABASE-END":
        raise ValueError("Cannot resolve the native RPM database configuration: " + (error or "invalid macro response"))
    path, backend = values[:2]
    def validate_path(value):
        # RPM can expand --dbpath again, including %[expression] and bare
        # %macros. Reject any remaining percent, even through a symlink target.
        if (not os.path.isabs(value) or len(value.encode("utf-8")) > 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
                or "\ufffd" in value or "%" in value):
            raise ValueError("The native RPM database path is unresolved, non-absolute or unsupported")
    validate_path(path)
    if backend and backend not in RPM_BACKENDS:
        raise ValueError("The native RPM database backend is unsupported: " + backend[:80])
    # Older BDB-only RPM releases do not define _db_backend. Do not guess a
    # modern backend when the native tool has not identified one.
    expected = RPM_BACKENDS[backend] if backend else "Packages"
    path = os.path.realpath(path)
    validate_path(path)
    candidates = tuple(os.path.join(path, name) for name in ("rpmdb.sqlite", "Packages", "Packages.db"))
    existing = [entry for entry in candidates if os.path.isfile(entry)]
    if len(existing) != 1 or os.path.basename(existing[0]) != expected:
        raise ValueError("The configured RPM database backend is missing, ambiguous or differs from its existing files")
    return {"path": path, "backend": backend, "candidates": candidates}


def rpm_packages(database=None):
    command = ["rpm"]
    if database is not None:
        command.extend(["--dbpath", database["path"]])
        if database["backend"]:
            command.extend(["--define", "_db_backend " + database["backend"]])
    tag_code, tag_output, _ = run(command + ["--querytags"])
    tags = set(tag_output.upper().split()) if tag_code == 0 else set()
    epoch_tag = "EPOCHNUM" if "EPOCHNUM" in tags else "EPOCH"
    fields = ["NAME", epoch_tag, "VERSION", "RELEASE", "ARCH", "SOURCERPM", "VENDOR", "PACKAGER", "DISTRIBUTION"]
    modularity_queried = "MODULARITYLABEL" in tags
    fields.append("MODULARITYLABEL" if modularity_queried else None)
    query = "\t".join("%{" + field + "}" if field else "(none)" for field in fields) + "\n"
    code, output, error = run(command + ["-qa", "--qf", query])
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
        rpm_database = resolve_rpm_database() if manager == "rpm" else None
        if rpm_database is not None:
            extra["rpmDatabase"] = {"path": rpm_database["path"], "backend": rpm_database["backend"] or "legacy-bdb",
                                    "selection": "native-macros-pinned"}
        with DatabaseConsistency(manager, rpm_database["candidates"] if rpm_database else None) as consistency:
            packages, error = rpm_packages(rpm_database) if manager == "rpm" else {"dpkg": debian_packages, "apk": apk_packages}[manager]()
            if manager == "apk":
                extra["apkRepositories"] = apk_repositories(os_release)
            elif manager == "dpkg" and os_release.get("ID") == "debian":
                extra["aptRepositories"] = debian_apt_repository_observation(os_release)
                extra["debianSignedReleases"] = debian_cached_inrelease_signatures(os_release)
                extra["debianPackageIndexes"] = debian_cached_package_index_hashes(os_release, extra["debianSignedReleases"])
            same_configuration = rpm_database is None or resolve_rpm_database() == rpm_database
            if not consistency.unchanged() or not same_configuration:
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
