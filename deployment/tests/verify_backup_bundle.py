#!/usr/bin/env python3
"""Read-only offline integrity and TAR safety gate for an HCP stopped-container backup.

A self-hashed SHA256SUMS manifest can be modified with all archives: passing
does NOT prove its trusted origin or successful restore. Never print secrets,
archive member names, original paths or raw exception text.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import posixpath
import re
import stat
import sys
import tarfile

FILES = (
    "runtime.tar.gz", "settings.tar.gz", "image.tar.gz",
    "commit.txt", "image-id.txt", "architecture.txt", "active-timers.txt",
)
META = "SHA256SUMS"
SHA = re.compile(r"^[a-f0-9]{64}$")
MAX_FILE_BYTES = 64 * 1024**3
MAX_MEMBER_BYTES = 16 * 1024**3
MAX_EXPANDED_BYTES = 128 * 1024**3
MAX_ENTRIES = 1000000
CHUNK = 1024 * 1024


class VerificationFailure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def ensure(ok, code):
    if not ok:
        raise VerificationFailure(code)


def open_bundle(directory):
    info = os.lstat(directory)
    ensure(stat.S_ISDIR(info.st_mode) and (info.st_mode & 0o077) == 0,
           "bundle_directory_unsafe")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(fd)
        raise VerificationFailure("bundle_directory_changed")
    return fd


def open_member(dir_fd, name):
    ensure(name in FILES or name == META, "unexpected_manifest_name")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(name, flags, dir_fd=dir_fd)
    try:
        before = os.fstat(descriptor)
        ensure(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE_BYTES,
               "bundle_file_unsafe")
        ensure((before.st_mode & 0o077) == 0, "bundle_file_permissions")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def ensure_unchanged(fd, original):
    after = os.fstat(fd)
    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
        ensure(getattr(original, field) == getattr(after, field),
               "bundle_file_changed")


def hash_member(dir_fd, name, max_bytes=MAX_FILE_BYTES):
    fd, info = open_member(dir_fd, name)
    try:
        ensure(info.st_size <= max_bytes, "bundle_file_too_large")
        hasher = hashlib.sha256()
        size = 0
        while True:
            data = os.read(fd, CHUNK)
            if not data:
                break
            size += len(data)
            ensure(size <= max_bytes, "bundle_file_too_large")
            hasher.update(data)
        ensure(size == info.st_size, "bundle_file_changed")
        ensure_unchanged(fd, info)
        return hasher.hexdigest(), size
    finally:
        os.close(fd)


def read_small(dir_fd, name, bound=2048):
    fd, info = open_member(dir_fd, name)
    try:
        ensure(info.st_size <= bound, "bundle_metadata_oversize")
        data = bytearray()
        while len(data) <= bound:
            part = os.read(fd, min(4096, bound + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        ensure(len(data) == info.st_size and len(data) <= bound, "bundle_metadata_changed")
        ensure_unchanged(fd, info)
        return bytes(data)
    finally:
        os.close(fd)


def manifest_entries(raw):
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError:
        raise VerificationFailure("manifest_invalid")
    ensure(len(lines) == len(FILES), "manifest_incomplete")
    entries = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-zA-Z0-9_.-]+)", line)
        ensure(match is not None, "manifest_invalid")
        digest, filename = match.groups()
        ensure(filename in FILES and filename not in entries,
               "manifest_duplicate_or_unknown")
        entries[filename] = digest
    ensure(set(entries) == set(FILES), "manifest_incomplete")
    return entries


def normalized_tar_name(raw):
    ensure(isinstance(raw, str) and 0 < len(raw) <= 4096,
           "archive_path_invalid")
    ensure(not raw.startswith("/") and "\\" not in raw
           and not any(ord(char) < 32 or ord(char) == 127 for char in raw),
           "archive_path_unsafe")
    pieces = raw.split("/")
    ensure(".." not in pieces, "archive_path_traversal")
    value = posixpath.normpath(raw)
    ensure(value != ".." and not value.startswith("../"), "archive_path_traversal")
    return value


def check_tar_link(path, target, is_symlink):
    normalized_tar_name(target)
    # Symbolic link targets resolve relative to the containing directory;
    # hardlink names are root-relative in GNU tar archives.
    joined = posixpath.normpath(posixpath.join(
        posixpath.dirname(path) if is_symlink else "", target))
    ensure(joined != ".." and not joined.startswith("../")
           and not joined.startswith("/"), "archive_link_escape")


def inspect_tar(dir_fd, name):
    fd, info = open_member(dir_fd, name)
    names = set()
    regular = set()
    members = 0
    expanded = 0
    types = {"file": 0, "dir": 0, "link": 0}
    try:
        with os.fdopen(os.dup(fd), "rb") as stream:
            try:
                with tarfile.open(fileobj=stream, mode="r|gz") as archive:
                    for item in archive:
                        members += 1
                        ensure(members <= MAX_ENTRIES, "archive_too_many_entries")
                        path = normalized_tar_name(item.name)
                        ensure(path not in names, "archive_duplicate_path")
                        names.add(path)
                        ensure(0 <= item.size <= MAX_MEMBER_BYTES, "archive_member_too_large")
                        expanded += item.size
                        ensure(expanded <= MAX_EXPANDED_BYTES, "archive_expansion_budget")
                        if item.isfile():
                            types["file"] += 1
                            regular.add(path)
                        elif item.isdir():
                            types["dir"] += 1
                        elif item.issym() or item.islnk():
                            types["link"] += 1
                            check_tar_link(path, item.linkname, item.issym())
                        else:
                            raise VerificationFailure("archive_unsafe_member_type")
            except (tarfile.TarError, EOFError, OSError, ValueError):
                raise VerificationFailure("archive_invalid_or_truncated")
        ensure_unchanged(fd, info)
    finally:
        os.close(fd)
    ensure(members > 0, "archive_empty")
    if name == "settings.tar.gz":
        ensure({".env", "ansible/inventory.ini"}.issubset(regular)
               and "secrets" in names, "settings_missing_required")
    if name == "runtime.tar.gz":
        ensure({"hcp.sqlite", "inventory.ini", "known_hosts"}.issubset(regular),
               "runtime_missing_required")
    return {"members": members, "regularFiles": types["file"],
            "directories": types["dir"], "links": types["link"],
            "expandedBytesDeclared": expanded}


def inspect_identity_metadata(dir_fd):
    commit = read_small(dir_fd, "commit.txt", 256).decode("ascii", "strict").strip()
    image = read_small(dir_fd, "image-id.txt", 256).decode("ascii", "strict").strip()
    arch = read_small(dir_fd, "architecture.txt", 64).decode("ascii", "strict").strip()
    timers = read_small(dir_fd, "active-timers.txt", 256).decode("ascii", "strict")
    ensure(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit) is not None,
           "backup_commit_invalid")
    ensure(re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None,
           "backup_image_id_invalid")
    ensure(re.fullmatch(r"[A-Za-z0-9_-]{2,32}", arch) is not None,
           "backup_arch_invalid")
    listed = [v for v in timers.splitlines() if v]
    ensure(len(listed) == len(set(listed)) and set(listed).issubset(
           {"hcp-scheduled-audit.timer", "hcp-deep-audit.timer"}),
           "backup_timers_invalid")
    return {"commit": commit, "containerImageDigest": image,
            "architecture": arch, "activeTimerCount": len(listed)}


def verify(directory, independent_manifest_sha256=None):
    if independent_manifest_sha256 is not None:
        ensure(SHA.fullmatch(independent_manifest_sha256) is not None,
               "independent_manifest_digest_invalid")
    fd = open_bundle(directory)
    try:
        manifest_sha, _ = hash_member(fd, META, 2048)
        if independent_manifest_sha256:
            ensure(manifest_sha == independent_manifest_sha256,
                   "independent_manifest_digest_mismatch")
        entries = manifest_entries(read_small(fd, META))
        sizes = {}
        for name in FILES:
            digest, size = hash_member(fd, name)
            ensure(digest == entries[name], "manifest_file_digest_mismatch")
            sizes[name] = size
        metadata = inspect_identity_metadata(fd)
        structure = {key: inspect_tar(fd, key)
                     for key in ("runtime.tar.gz", "settings.tar.gz", "image.tar.gz")}
        return {
            "schemaVersion": 1,
            "status": "structurally-verified-not-restored",
            "scope": "local-archive-format-sha256-and-safe-member-paths",
            "manifestSha256": manifest_sha,
            "independentManifestPinMatched": independent_manifest_sha256 is not None,
            "archiveSha256": {name: entries[name] for name in FILES
                              if name.endswith(".tar.gz")},
            "archiveCompressedBytes": {name: sizes[name] for name in FILES
                                       if name.endswith(".tar.gz")},
            "metadata": metadata,
            "archiveStructure": structure,
            "checkedAtUtc": datetime.now(timezone.utc).isoformat(),
            "limitations": [
                "A self-consistent SHA256SUMS is not independently trusted without an external manifest digest.",
                "Archive inspection cannot certify SQLite integrity or HMAC journal consistency.",
                "No secrets were extracted, printed or compared with an external secret store.",
                "Only a real restore into a new isolated control node proves operational recoverability.",
                "Remote Astra firewall backups and Dependency-Track/Greenbone are out of scope.",
            ],
        }
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True, help="Existing private backup folder")
    parser.add_argument("--expected-manifest-sha256",
                        help="SHA-256 of SHA256SUMS recorded independently, not from the same folder")
    parser.add_argument("--output", help="Optional new JSON protocol path, not inside the backup folder")
    args = parser.parse_args(argv)
    report = verify(args.backup_dir, args.expected_manifest_sha256)
    if args.output:
        ensure(os.path.realpath(os.path.dirname(os.path.abspath(args.output)))
               != os.path.realpath(os.path.abspath(args.backup_dir)),
               "output_must_be_outside_backup")
        encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf8")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationFailure, UnicodeError, ValueError) as error:
        # Original file paths, manifest contents or secrets never leave the tool.
        code = error.code if isinstance(error, VerificationFailure) else "backup_unreadable_or_invalid"
        print(json.dumps({"schemaVersion": 1, "status": "blocked",
                          "reasonCode": code, "restorationVerified": False}),
              file=sys.stdout)
        sys.exit(1)
