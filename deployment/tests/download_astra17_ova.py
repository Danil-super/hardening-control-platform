#!/usr/bin/env python3
"""Download one exact public Astra 1.7.6.UU2 VirtualBox OVA to a private directory.

This is a convenience transport, NOT independent authentication of the publisher,
proof of the guest's identity, or permission to test a VM. No SSH/Ansible/VM
commands are executed. A trusted operator pin is optional and explicitly marked.
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
import time
import urllib.error
import urllib.request
from uuid import uuid4

ROOT = "https://registry.astralinux.ru/artifactory/mg-generic/alse/virtualbox/"
FILENAMES = {
    level: "alse-1.7.6.uu2-{}-virtualbox-mg15.3.1-amd64.ova".format(level)
    for level in ("base", "adv", "max")
}
MAX_BYTES = 8 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024
CHECKSUM_BUDGET = 128
CHECKSUM = re.compile(r"^[a-f0-9]{64}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        raise ValueError("Vendor endpoint redirected; refusing unknown image origin")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def private_directory(directory):
    # Do not create directories implicitly, follow symlinks or use /tmp as a
    # public staging area for an executable VM image.
    d = Path(directory)
    mode = d.lstat()
    require(stat.S_ISDIR(mode.st_mode) and not (mode.st_mode & 0o077),
            "Use an existing private output directory (mode 0700), not a symlink")
    return d


def fixed_urls(level):
    require(level in FILENAMES, "Only official 1.7.6.UU2 base/adv/max names allowed")
    filename = FILENAMES[level]
    return ROOT + filename, ROOT + filename + ".sha256"


def strict_open(opener, url):
    response = opener(url, timeout=30)
    try:
        require(response.geturl() == url, "Source URL changed or redirected")
        require(response.status == 200, "Official source returned an unexpected HTTP status")
    except BaseException:
        response.close()
        raise
    return response


def vendor_checksum(level, opener):
    _, checksum_url = fixed_urls(level)
    with strict_open(opener, checksum_url) as response:
        data = response.read(CHECKSUM_BUDGET + 1)
    require(len(data) <= CHECKSUM_BUDGET, "Vendor checksum exceeds fixed size budget")
    try:
        observed = data.decode("ascii").strip().lower()
    except UnicodeDecodeError:
        raise ValueError("Vendor checksum is not ASCII")
    require(CHECKSUM.fullmatch(observed) is not None,
            "Official source did not return a single 64-hex SHA-256")
    return observed


def download(level, directory, *, opener, progress, clock=time.monotonic,
             max_seconds=3600, expected_sha256=None, expected_bytes=None):
    """Download, hash, pin and atomically publish private evidence, without clobbering.

    Dependency injection is only for offline tests. CLI always uses the
    no-redirect HTTPS opener and a fixed allowlisted filename.
    """
    target_dir = private_directory(directory)
    image_url, checksum_url = fixed_urls(level)
    name = FILENAMES[level]
    target = target_dir / name
    evidence = target_dir / (name + ".source.json")
    require(not target.exists() and not target.is_symlink()
            and not evidence.exists() and not evidence.is_symlink(),
            "Image or evidence already exists; refusing to replace existing files")
    require(0 < max_seconds <= 7200, "Time budget must be bounded")
    require((expected_sha256 is None) == (expected_bytes is None),
            "Independent SHA-256 and byte length must be supplied together")
    if expected_sha256 is not None:
        require(isinstance(expected_sha256, str)
                and CHECKSUM.fullmatch(expected_sha256) is not None,
                "Independent SHA-256 is not 64 lowercase hexadecimal characters")
        require(type(expected_bytes) is int and 0 < expected_bytes <= MAX_BYTES,
                "Independent image size is out of bounds")

    advertised = vendor_checksum(level, opener)
    if expected_sha256 is not None:
        require(advertised == expected_sha256,
                "Artifactory checksum differs from independently recorded operator pin")
    partial = target_dir / (".hcp-ova-" + uuid4().hex + ".partial")
    partial_manifest = target_dir / (".hcp-ova-" + uuid4().hex + ".json.partial")
    linked_image = False
    linked_evidence = False
    start = clock()
    try:
        # A private random temporary path is exclusively created, then linked
        # into place without replacing anything, only after full verification.
        with os.fdopen(os.open(str(partial), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as file:
            with strict_open(opener, image_url) as response:
                length = response.headers.get("Content-Length")
                if length is not None:
                    require(length.isdecimal() and 0 < int(length) <= MAX_BYTES,
                            "Remote image size header is invalid")
                    if expected_bytes is not None:
                        require(int(length) == expected_bytes,
                                "Remote image size differs from independent pin")
                total = 0
                digest = hashlib.sha256()
                preview = b""
                last_progress = start
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= MAX_BYTES, "Image exceeds the 8 GiB maximum")
                    require(clock() - start <= max_seconds, "Image download exceeded time budget")
                    if len(preview) < 512:
                        preview += chunk[:512 - len(preview)]
                    file.write(chunk)
                    digest.update(chunk)
                    now = clock()
                    if now - last_progress >= 4:
                        progress(total, int(length) if length is not None else None)
                        last_progress = now
                file.flush()
                os.fsync(file.fileno())

        if length is not None:
            require(total == int(length), "Remote image transfer is truncated")
        require(digest.hexdigest() == advertised,
                "Downloaded bytes do not match the publisher-side checksum")
        require(total > 1024 and preview[257:262] == b"ustar",
                "Downloaded bytes are not a recognizable OVA/TAR archive")
        if expected_bytes is not None:
            require(total == expected_bytes, "Downloaded file size differs from operator pin")
        require(clock() - start <= max_seconds, "Image download exceeded time budget")

        record = {
            "schemaVersion": 1,
            "status": "local-bytes-match-artifactory-sidecar",
            "candidateRelease": "1.7.6.UU2",
            "expectedNativeRelease": "1.7.6.15",
            "declaredSecurityLevel": level,
            "imageFileName": name,
            "sourceUrl": image_url,
            "checksumUrl": checksum_url,
            "sha256": advertised,
            "bytes": total,
            "downloadedAtUtc": datetime.now(timezone.utc).isoformat(),
            "operatorIndependentPinSupplied": expected_sha256 is not None,
            "operatorPinMatched": expected_sha256 is not None,
            "publisherSignatureVerified": False,
            "nativeGuestVerified": False,
            "cveSourceApplicable": None,
            "limitations": [
                "Publisher checksum and image come from the same online Artifactory origin.",
                "A matching checksum does not independently authenticate Astra or attest its security mode.",
                "Verify the actual guest OS, SSH fingerprint, package inventory and protected mode separately.",
                "No scan, rollback, CVE completeness or production readiness has been established.",
            ],
        }
        with os.fdopen(os.open(str(partial_manifest),
                              os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as file:
            file.write((json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            file.flush()
            os.fsync(file.fileno())
        # Exclusive hardlinks prevent overwriting existing operator data.
        os.link(str(partial), str(target), follow_symlinks=False)
        linked_image = True
        os.link(str(partial_manifest), str(evidence), follow_symlinks=False)
        linked_evidence = True
        progress(total, total)
        return record
    except BaseException:
        if linked_evidence:
            evidence.unlink()
        if linked_image:
            target.unlink()
        raise
    finally:
        partial.unlink(missing_ok=True)
        partial_manifest.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--level", choices=sorted(FILENAMES), required=True)
    parser.add_argument("--output-dir",
                        help="Existing private directory chmod 700; no files are overwritten")
    parser.add_argument("--expected-sha256", help="Optional independently recorded SHA-256")
    parser.add_argument("--expected-bytes", type=int, help="Optional independently recorded size")
    parser.add_argument("--inspect-only", action="store_true",
                        help="Read only Artifactory sidecar checksum; download nothing")
    args = parser.parse_args()
    url, checksum_url = fixed_urls(args.level)
    opener = urllib.request.build_opener(NoRedirect()).open
    if args.inspect_only:
        print(json.dumps({
            "candidate": FILENAMES[args.level], "sha256ClaimedByArtifactory": vendor_checksum(args.level, opener),
            "sourceUrl": url, "checksumUrl": checksum_url,
            "publisherSignatureVerified": False, "nativeGuestVerified": False,
        }, ensure_ascii=False))
        return
    require(bool(args.output_dir), "Specify an existing private --output-dir for downloads")
    def progress(downloaded, total):
        value = "{:.1f} MiB".format(downloaded / 1048576)
        whole = " / {:.1f} MiB".format(total / 1048576) if total else ""
        print("Astra {} OVA: {}{}".format(args.level, value, whole), file=sys.stderr, flush=True)
    result = download(args.level, args.output_dir, opener=opener, progress=progress,
                      expected_sha256=args.expected_sha256,
                      expected_bytes=args.expected_bytes)
    print("PASS: vendor-sidecar SHA-256 matches local OVA; publisher/guest are NOT attested.")
    print("Private image and evidence: " + result["imageFileName"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, urllib.error.URLError) as error:
        # Never echo a file path, URL with credentials or response HTML on failure.
        reason = str(error) if isinstance(error, ValueError) else "Secure source or output unavailable"
        print("FAIL: " + reason, file=sys.stderr)
        sys.exit(1)
