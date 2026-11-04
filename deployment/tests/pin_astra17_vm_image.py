#!/usr/bin/env python3
"""Pin a locally downloaded Astra SE 1.7.6.UU2 VirtualBox OVA for native acceptance.

No network, execution, extraction, secret access, VM launch or claim of publisher
authentication. Only operator-provided expected SHA-256 and exact size prove the
local file matches a recorded reference; independently review its origin.
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

MAX_IMAGE_BYTES = 8 * 1024**3
SHA = re.compile(r"^[a-f0-9]{64}$")
IMAGE = re.compile(
    r"^alse-1\.7\.6\.uu2-(base|adv|max)-virtualbox-mg15\.3\.1-amd64\.ova$"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash_image(image_path):
    """Hash one bounded, stable, ordinary file without following a symlink."""
    image_path = Path(image_path)
    original = os.lstat(str(image_path))
    require(stat.S_ISREG(original.st_mode) and 1024 < original.st_size <= MAX_IMAGE_BYTES,
            "Image must be a bounded regular file, not a symlink")
    fd = os.open(str(image_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        require(opened.st_dev == original.st_dev and opened.st_ino == original.st_ino
                and stat.S_ISREG(opened.st_mode), "Image file identity changed")
        digest = hashlib.sha256()
        count = 0
        header = b""
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            if not header:
                header = chunk[:512]
            digest.update(chunk)
            count += len(chunk)
            require(count <= MAX_IMAGE_BYTES, "Image exceeds maximum size")
        final = os.fstat(fd)
        current = os.lstat(str(image_path))
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(count == original.st_size and all(
            getattr(original, key) == getattr(final, key) == getattr(current, key)
            for key in keys), "Image changed during validation")
    finally:
        os.close(fd)
    # The canonical VirtualBox OVA distribution is a TAR archive. This is only
    # a format sanity check; a malicious TAR can still pass it. Never extract.
    require(len(header) >= 512 and header[257:262] == b"ustar",
            "Image does not have the expected OVA/TAR container header")
    return count, digest.hexdigest()


def assess(image, expected_sha256, expected_bytes, reference, observed_size, observed_sha):
    filename = Path(image).name
    match = IMAGE.fullmatch(filename)
    require(match is not None, "Not a pinned Astra 1.7.6.UU2 VirtualBox image name")
    require(SHA.fullmatch(expected_sha256) is not None,
            "Expected SHA-256 must be lowercase hexadecimal")
    require(isinstance(expected_bytes, int) and 1024 < expected_bytes <= MAX_IMAGE_BYTES,
            "Expected size must be bounded")
    require(observed_size == expected_bytes and observed_sha == expected_sha256,
            "Image SHA-256 or byte length differs from the independently recorded pin")
    require(isinstance(reference, str) and 6 <= len(reference) <= 256
            and not any(ord(char) < 32 for char in reference),
            "State a bounded independent reference ID, not a secret or URL with credentials")
    require(not re.search(r"://[^/]+@", reference), "Never record URLs with credentials")
    return {
        "schemaVersion": 1,
        "status": "local-bytes-match-recorded-pin",
        "imageName": filename,
        "astraReleaseCandidate": "1.7.6.UU2",
        "expectedInsideGuest": "/etc/astra_version 1.7.6.15",
        "architectureCandidate": "amd64",
        "securityLevelCandidate": match.group(1),
        "fileSizeBytes": observed_size,
        "sha256": observed_sha,
        "operatorReference": reference,
        "verifiedAtUtc": datetime.now(timezone.utc).isoformat(),
        "publisherSignatureVerified": False,
        "nativeGuestVerified": False,
        "cveSourceApplicable": None,
        "limitations": [
            "Matching local bytes to a recorded digest does not authenticate the publisher.",
            "Image metadata and file name cannot prove the actual OS release or security level.",
            "Confirm OS release, kernel, machine identity, protection level and OpenSCAP through the actual guest.",
            "No vulnerability or CVE coverage has been measured.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, help="Downloaded local OVA; never uploaded")
    parser.add_argument("--expected-sha256", required=True,
                        help="Pinned digest reviewed and recorded separately")
    parser.add_argument("--expected-bytes", type=int, required=True,
                        help="Exact independently recorded source file size")
    parser.add_argument("--reference", required=True,
                        help="Nonsecret independent verification record or reference ID")
    parser.add_argument("--output", required=True, help="New private JSON evidence path")
    args = parser.parse_args()
    require(os.path.abspath(args.file) != os.path.abspath(args.output),
            "Source image and output must be distinct")
    size, digest = hash_image(args.file)
    result = assess(args.file, args.expected_sha256.lower(), args.expected_bytes,
                    args.reference, size, digest)
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(args.output)
        raise
    finally:
        os.close(fd)
    print("PASS: local image bytes match the operator pin; publisher and guest NOT attested.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        # The OS error can contain a private local path: never echo it.
        print("FAIL: " + (str(error) if isinstance(error, ValueError)
                          else "Image or output cannot be safely accessed"), file=sys.stderr)
        sys.exit(1)
