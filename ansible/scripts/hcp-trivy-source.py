#!/usr/bin/env python3
"""Serialize HCP Trivy access and retain evidence of the bytes actually scanned.

This is a controller helper, not an Astra target program. flock is advisory:
writers outside HCP can still change files, so hashes AND file identities are
checked before/after execution. A mismatch never produces a complete verdict.
The lock descriptor is inherited by Trivy, keeping other HCP writers out even
if the controller/helper dies while the native scanner is still running.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone


# Native JSON includes repeated advisory descriptions, references and CVSS
# records. A real 433-package Rocky inventory already produces over 22 MiB.
# Keep a finite scan budget without duplicating that output in a JSON envelope.
SCAN_STDOUT_LIMIT = 64 * 1024 * 1024
SCAN_STDERR_LIMIT = 1024 * 1024


class SourceError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint(file, maximum=None):
    fd = os.open(str(file), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SourceError("source_type", "Scanner source is not an ordinary file")
        if maximum is not None and before.st_size > maximum:
            raise SourceError("source_size", "Scanner source exceeds the allowed size")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        current = os.stat(str(file), follow_symlinks=False)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise SourceError("source_changed", "Scanner source changed while hashing")
        return {"sha256": digest.hexdigest(), "bytes": after.st_size, "identity": [str(value) for value in identity(after)]}
    finally:
        os.close(fd)


@contextlib.contextmanager
def source_lock(cache, timeout):
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Never unlink this file: all waiters must hold the same flock inode.
    fd = os.open(str(cache / ".hcp-source.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SourceError("lock_type", "Trivy source lock is not a private ordinary file")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SourceError("lock_timeout", "Another HCP process is using the Trivy source")
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        yield fd
    finally:
        # Do not explicitly LOCK_UN: an orphaned native child inherits this fd
        # and must retain the lock until it exits. Closing our copy is sufficient.
        os.close(fd)


def execute(command, environment, lock_fd, timeout, limit=16 * 1024 * 1024,
            stdout_path=None, stderr_limit=None):
    output_fd = None
    completed = False
    process = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {"stdout": 0, "stderr": 0}
    digest = hashlib.sha256()
    limits = {"stdout": limit, "stderr": limit if stderr_limit is None else stderr_limit}
    deadline = time.monotonic() + timeout
    try:
        if stdout_path is not None:
            # The caller owns a private temporary directory. Never follow or
            # replace an existing file, including a dangling symbolic link.
            output_fd = os.open(str(stdout_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(lock_fd,), start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SourceError("native_timeout", "Trivy execution timed out")
                for key, _ in selector.select(min(0.2, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    if counts[name] + len(chunk) > limits[name]:
                        raise SourceError("output_limit", "Trivy output exceeded the allowed size")
                    counts[name] += len(chunk)
                    if name == "stdout" and output_fd is not None:
                        remaining_chunk = memoryview(chunk)
                        while remaining_chunk:
                            written = os.write(output_fd, remaining_chunk)
                            if written <= 0:
                                raise SourceError("output_write", "Trivy output file write did not complete")
                            remaining_chunk = remaining_chunk[written:]
                        digest.update(chunk)
                    else:
                        output[name].extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        completed = True
    except BaseException:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise
    finally:
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        if output_fd is not None:
            os.close(output_fd)
            if not completed:
                try:
                    os.unlink(str(stdout_path))
                except FileNotFoundError:
                    pass
    if stdout_path is not None:
        return code, {"stdoutFile": {"sha256": digest.hexdigest(), "bytes": counts["stdout"]},
                      "stderr": bytes(output["stderr"]).decode("utf-8", "replace")}
    return code, {name: bytes(value).decode("utf-8", "replace") for name, value in output.items()}


def fsync_directory(directory):
    fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json_atomic(file, value):
    fd, temporary = tempfile.mkstemp(prefix=".hcp-state-", dir=str(file.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(file))
        fsync_directory(file.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def describe_files(files):
    limits = {"metadata": 1024 * 1024, "config": 1024 * 1024, "sbom": 64 * 1024 * 1024}
    return {name: fingerprint(file, limits.get(name)) for name, file in files.items()}


def source_manifest(cache, files, method):
    manifest = {"version": 1, "method": method, "registeredAt": datetime.now(timezone.utc).isoformat(),
                "files": {name: {"sha256": files[name]["sha256"], "bytes": files[name]["bytes"]} for name in ("database", "metadata")}}
    write_json_atomic(cache / ".hcp-source.json", manifest)
    return manifest


def verify_registered_source(cache, observed):
    manifest_path = cache / ".hcp-source.json"
    if not os.path.lexists(str(manifest_path)):
        return None
    before = fingerprint(manifest_path, 65536)
    manifest = json.loads(manifest_path.read_text())
    if before != fingerprint(manifest_path, 65536) or manifest.get("version") != 1:
        raise SourceError("source_manifest", "Trivy source manifest is invalid or changed")
    for name in ("database", "metadata"):
        expected = manifest.get("files", {}).get(name, {})
        if not isinstance(expected.get("sha256"), str) or not re.fullmatch("[a-f0-9]{64}", expected["sha256"]):
            raise SourceError("source_manifest", "Trivy source manifest lacks a usable digest")
        if expected["sha256"] != observed[name]["sha256"] or expected.get("bytes") != observed[name]["bytes"]:
            raise SourceError("source_changed", "Trivy source differs from the registered download/import")
    return manifest


def validate_metadata(metadata):
    if metadata.get("Version") != 2 or not isinstance(metadata.get("UpdatedAt"), str):
        raise SourceError("source_format", "Trivy source lacks a supported database/metadata pair")
    # This helper runs on the controller's Python, not the legacy Astra target.
    try:
        timestamp = datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.timestamp() <= 0 or timestamp.timestamp() > time.time() + 300:
            raise ValueError("publication time")
    except ValueError:
        raise SourceError("source_format", "Trivy metadata publication time is invalid")


def download(cache, binary, args, env, lock_fd, timeout):
    # Failed registry attempts must not damage the last usable source. Only a
    # successful complete download is published; an interrupted publication
    # leaves a marker that prevents subsequent scans until refresh succeeds.
    staging = Path(tempfile.mkdtemp(prefix=".hcp-download-", dir=str(cache)))
    try:
        args = list(args)
        if "--cache-dir" not in args:
            raise SourceError("download_arguments", "Download must select its cache directory")
        args[args.index("--cache-dir") + 1] = str(staging)
        code, output = execute([binary] + args, dict(env, TRIVY_CACHE_DIR=str(staging)), lock_fd, timeout)
        if code != 0:
            return {"ok": False, "errorCode": "native_exit", "nativeCode": code, **output}
        database = staging / "db" / "trivy.db"
        metadata = staging / "db" / "metadata.json"
        if (staging / "db").is_symlink() or not (staging / "db").is_dir():
            raise SourceError("source_type", "Downloaded database must be an ordinary directory")
        source = describe_files({"database": database, "metadata": metadata})
        details = json.loads(metadata.read_text())
        validate_metadata(details)
        if not source["database"]["bytes"]:
            raise SourceError("download_invalid", "Downloaded Trivy database is empty")
        for file in (database, metadata):
            fd = os.open(str(file), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        target = cache / "db"
        target.mkdir(exist_ok=True, mode=0o700)
        if target.is_symlink() or not target.is_dir():
            raise SourceError("source_type", "Trivy database directory must be an ordinary directory")
        pending = cache / ".hcp-refresh-pending.json"
        write_json_atomic(pending, {"version": 1, "database": source["database"]["sha256"], "metadata": source["metadata"]["sha256"]})
        os.replace(str(database), str(target / "trivy.db"))
        os.replace(str(metadata), str(target / "metadata.json"))
        fsync_directory(target)
        source_manifest(cache, source, "completed-native-download")
        pending.unlink()
        fsync_directory(cache)
        return {"ok": True, "nativeCode": code, **output}
    finally:
        shutil.rmtree(str(staging))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--action", choices=("scan", "download", "register-import"), required=True)
    parser.add_argument("--sbom")
    parser.add_argument("--config")
    parser.add_argument("--stdout-file", help="New private file for bounded scan JSON; existing files are refused")
    parser.add_argument("--lock-timeout", type=float, default=60)
    parser.add_argument("--timeout", type=float, default=315)
    parser.add_argument("--expected-db-sha256")
    parser.add_argument("--expected-metadata-sha256")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    command = options.command[1:] if options.command[:1] == ["--"] else options.command
    if (not command and options.action != "register-import") or not 0 < options.timeout <= 315 or not 0 <= options.lock_timeout <= 600:
        parser.error("A native command and bounded positive timeouts are required")
    if options.stdout_file and (options.action != "scan" or not os.path.isabs(options.stdout_file)):
        parser.error("A scan stdout file must be an absolute path")
    cache = Path(options.cache_dir).resolve()
    binary = shutil.which(command[0]) if command else None
    if binary is None and options.action != "register-import":
        print(json.dumps({"ok": False, "errorCode": "binary_missing"}))
        return
    binary = os.path.realpath(binary) if binary else None
    evidence = {"version": 1, "status": "unavailable", "coordination": "HCP advisory flock; file hashes and identities checked before/after", "checkedAt": datetime.now(timezone.utc).isoformat()}
    try:
        with source_lock(cache, options.lock_timeout) as lock_fd:
            environment = dict(os.environ, TRIVY_CACHE_DIR=str(cache))
            if options.action == "download":
                result = download(cache, binary, command[1:], environment, lock_fd, options.timeout)
            elif options.action == "register-import":
                expected = {"database": options.expected_db_sha256, "metadata": options.expected_metadata_sha256}
                if any(not value or not re.fullmatch("[a-f0-9]{64}", value) for value in expected.values()):
                    raise SourceError("import_digests", "Registration requires independently supplied database and metadata SHA-256 values")
                if (cache / "db").is_symlink():
                    raise SourceError("source_type", "Trivy database directory must not be a symbolic link")
                files = {"database": cache / "db" / "trivy.db", "metadata": cache / "db" / "metadata.json"}
                observed = describe_files(files)
                validate_metadata(json.loads(files["metadata"].read_text()))
                if not observed["database"]["bytes"] or any(observed[name]["sha256"] != digest for name, digest in expected.items()):
                    raise SourceError("source_changed", "Imported files differ from the supplied digests")
                if observed != describe_files(files):
                    raise SourceError("source_changed", "Imported source changed during registration")
                manifest = source_manifest(cache, observed, "explicit-digest-checked-import")
                pending = cache / ".hcp-refresh-pending.json"
                if pending.exists():
                    pending.unlink()
                    fsync_directory(cache)
                result = {"ok": True, "sourceManifest": manifest, "vulnerabilityAssessment": "not_run"}
            else:
                if not options.sbom or not options.config:
                    raise SourceError("scan_arguments", "Scan must identify its SBOM and configuration")
                if os.path.lexists(str(cache / ".hcp-refresh-pending.json")):
                    raise SourceError("refresh_interrupted", "A database refresh publication was interrupted; refresh the source again")
                if (cache / "db").is_symlink():
                    raise SourceError("source_type", "Trivy database directory must not be a symbolic link")
                files = {"database": cache / "db" / "trivy.db", "metadata": cache / "db" / "metadata.json", "engine": Path(binary), "sbom": Path(options.sbom), "config": Path(options.config)}
                before = describe_files(files)
                metadata = json.loads(files["metadata"].read_text())
                validate_metadata(metadata)
                if not before["database"]["bytes"]:
                    raise SourceError("source_format", "Trivy database schema or size is not supported")
                evidence.update({"before": before, "databaseUpdatedAt": metadata.get("UpdatedAt"), "databaseSchema": metadata.get("Version"), "parameters": command[1:]})
                registered = verify_registered_source(cache, before)
                evidence["registration"] = registered.get("method") if registered else "legacy-unregistered-cache"
                code, version = execute([binary, "--version"], environment, lock_fd, min(30, options.timeout), 1024 * 1024)
                if code != 0 or not re.search(r"^Version:\s+\S+", version["stdout"], re.MULTILINE):
                    raise SourceError("engine_version", "Cannot identify the native Trivy engine")
                evidence["engineVersion"] = version["stdout"].strip()[:4096]
                if options.stdout_file:
                    code, output = execute([binary] + command[1:], environment, lock_fd, options.timeout,
                                           SCAN_STDOUT_LIMIT, options.stdout_file, SCAN_STDERR_LIMIT)
                    evidence["nativeOutput"] = output["stdoutFile"]
                else:
                    # Existing CLI callers retain the inline response contract.
                    code, output = execute([binary] + command[1:], environment, lock_fd, options.timeout)
                after = describe_files(files)
                evidence["after"] = after
                evidence["status"] = "unchanged" if before == after else "changed"
                result = {"ok": code == 0 and before == after, "nativeCode": code, **output, "sourceEvidence": evidence}
                if before != after:
                    result["errorCode"] = "source_changed"
                elif code != 0:
                    result["errorCode"] = "native_exit"
                elif not registered:
                    # Preserve compatibility with already imported offline
                    # caches. First successful execution pins their observed
                    # bytes; it does not authenticate their publisher.
                    source_manifest(cache, before, "first-successful-native-use")
            print(json.dumps(result))
    except Exception as exc:
        if getattr(exc, "code", "") == "source_changed":
            evidence["status"] = "changed"
        print(json.dumps({"ok": False, "errorCode": getattr(exc, "code", "source_unavailable"), "sourceEvidence": evidence}))


if __name__ == "__main__":
    main()
