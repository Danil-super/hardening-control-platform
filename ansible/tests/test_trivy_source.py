"""Execute the controller source guard with real files/processes, not a CVE engine.

Native advisory matching is separately exercised by verify_trivy_matching.mjs.
These regressions establish serialization, input identity and failure behavior.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = Path(__file__).resolve().parents[1] / "scripts" / "hcp-trivy-source.py"
SPEC = importlib.util.spec_from_file_location("trivy_source", str(HELPER))
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)


class TrivySourceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hcp-trivy-source-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        (self.cache / "db").mkdir(parents=True)
        self.database = self.cache / "db" / "trivy.db"
        self.metadata = self.cache / "db" / "metadata.json"
        self.database.write_bytes(b"original labelled source bytes")
        self.metadata.write_text(json.dumps({"Version": 2, "UpdatedAt": "2026-10-28T07:00:00Z"}))
        self.sbom = self.root / "source.cdx.json"
        self.sbom.write_text('{"bomFormat":"CycloneDX"}')
        self.config = self.root / "config.yaml"
        self.config.write_text("{}\n")
        self.binary = self.root / "native-contract-fixture"
        self.binary.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys, time
args=sys.argv[1:]
cache=pathlib.Path(os.environ['TRIVY_CACHE_DIR'])
root=pathlib.Path(os.environ['HCP_SOURCE_TEST_ROOT'])
mode=os.environ.get('HCP_SOURCE_TEST_MODE','normal')
if '--version' in args:
    print('Version: 0.74.0-contract-fixture')
    sys.exit(0)
if '--download-db-only' in args:
    (cache/'db').mkdir(parents=True,exist_ok=True)
    (cache/'db/trivy.db').write_bytes(b'new complete labelled source')
    (cache/'db/metadata.json').write_text(json.dumps({'Version':2,'UpdatedAt':'2026-10-28T08:00:00Z'}))
    if mode=='download-malformed':
        (cache/'db/metadata.json').write_text(json.dumps({'Version':2,'UpdatedAt':'not a publication date'}))
    if mode=='download-fail':
        print('network connection reset',file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
if mode=='hold':
    (root/'native.pid').write_text(str(os.getpid()))
    until=time.monotonic()+15
    while not (root/'release').exists():
        if time.monotonic()>until: sys.exit(2)
        time.sleep(0.02)
if mode=='database-write':
    with open(str(cache/'db/trivy.db'),'ab') as handle: handle.write(b'change')
if mode=='metadata-replace':
    target=cache/'db/metadata.json'
    before=target.stat()
    replacement=cache/'db/replacement'
    replacement.write_bytes(target.read_bytes())
    os.utime(str(replacement),ns=(before.st_atime_ns,before.st_mtime_ns))
    os.replace(str(replacement),str(target))
if mode=='same-sbom-write':
    target=pathlib.Path(args[-1])
    before=target.stat()
    target.write_bytes(target.read_bytes())
    os.utime(str(target),ns=(before.st_atime_ns,before.st_mtime_ns))
print(json.dumps({'SchemaVersion':2,'Results':[]}))
""")
        self.binary.chmod(0o700)

    def environment(self, mode):
        return dict(os.environ, HCP_SOURCE_TEST_ROOT=str(self.root), HCP_SOURCE_TEST_MODE=mode)

    def command(self, action="scan", wait=1):
        command = [sys.executable, str(HELPER), "--action", action, "--cache-dir", str(self.cache),
                   "--lock-timeout", str(wait), "--timeout", "10"]
        if action == "scan":
            return command + ["--sbom", str(self.sbom), "--config", str(self.config), "--", str(self.binary),
                              "sbom", "--config", str(self.config), str(self.sbom)]
        return command + ["--", str(self.binary), "image", "--download-db-only", "--cache-dir", str(self.cache)]

    def invoke(self, mode="normal", action="scan", wait=1):
        result = subprocess.run(self.command(action, wait), env=self.environment(mode), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def wait_for_file(self, file):
        until = time.monotonic() + 5
        while not file.exists() and time.monotonic() < until:
            time.sleep(0.02)
        self.assertTrue(file.exists(), "Controlled subprocess did not start")

    def test_success_records_exact_database_engine_and_input_hashes(self):
        result = self.invoke()
        self.assertTrue(result["ok"])
        evidence = result["sourceEvidence"]
        self.assertEqual(evidence["status"], "unchanged")
        self.assertEqual(evidence["before"], evidence["after"])
        self.assertIn("0.74.0-contract-fixture", evidence["engineVersion"])
        for name, file in (("database", self.database), ("metadata", self.metadata), ("engine", self.binary), ("sbom", self.sbom), ("config", self.config)):
            self.assertEqual(evidence["before"][name]["sha256"], hashlib.sha256(file.read_bytes()).hexdigest())

    def test_byte_write_replacement_and_same_bytes_rewrite_are_not_complete(self):
        for mode in ("database-write", "metadata-replace", "same-sbom-write"):
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertFalse(result["ok"])
                self.assertEqual(result["errorCode"], "source_changed")
                self.assertEqual(result["sourceEvidence"]["status"], "changed")

    def test_failed_download_preserves_previous_database_and_metadata(self):
        before = (self.database.read_bytes(), self.metadata.read_bytes())
        result = self.invoke("download-fail", "download")
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "native_exit")
        self.assertEqual(before, (self.database.read_bytes(), self.metadata.read_bytes()))
        self.assertFalse(list(self.cache.glob(".hcp-download-*")))
        self.assertFalse((self.cache / ".hcp-refresh-pending.json").exists())

    def test_zero_exit_download_with_invalid_metadata_preserves_old_source(self):
        original = (self.database.read_bytes(), self.metadata.read_bytes())
        result = self.invoke("download-malformed", "download")
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "source_format")
        self.assertEqual(original, (self.database.read_bytes(), self.metadata.read_bytes()))

    def test_process_exit_between_database_and_metadata_publication_blocks_scan(self):
        script = """import importlib.util,os,sys
spec=importlib.util.spec_from_file_location('guard',sys.argv[1])
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original=module.os.replace
def terminate_after_database(source,destination):
    original(source,destination)
    if os.path.basename(str(destination))=='trivy.db': os._exit(91)
module.os.replace=terminate_after_database
sys.argv=sys.argv[1:]
module.main()
"""
        result = subprocess.run([sys.executable, "-c", script] + self.command("download")[1:],
                                env=self.environment("normal"), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 91, result.stderr)
        self.assertEqual(self.database.read_bytes(), b"new complete labelled source")
        self.assertTrue((self.cache / ".hcp-refresh-pending.json").exists())
        self.assertEqual(self.invoke()["errorCode"], "refresh_interrupted")
        self.assertTrue(self.invoke(action="download")["ok"])
        self.assertTrue(self.invoke()["ok"])

    def test_changed_bytes_between_scans_require_a_new_verified_source(self):
        self.assertTrue(self.invoke()["ok"])
        manifest = (self.cache / ".hcp-source.json").read_bytes()
        self.database.write_bytes(b"silently replaced after an earlier successful scan")
        result = self.invoke()
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "source_changed")
        self.assertEqual(result["sourceEvidence"]["status"], "changed")
        self.assertEqual((self.cache / ".hcp-source.json").read_bytes(), manifest)

    def test_offline_registration_requires_both_matching_independent_digests(self):
        command = [sys.executable, str(HELPER), "--action", "register-import", "--cache-dir", str(self.cache),
                   "--expected-db-sha256", "0" * 64,
                   "--expected-metadata-sha256", hashlib.sha256(self.metadata.read_bytes()).hexdigest()]
        failed = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertFalse(json.loads(failed.stdout)["ok"])
        self.assertFalse((self.cache / ".hcp-source.json").exists())
        command[command.index("--expected-db-sha256") + 1] = hashlib.sha256(self.database.read_bytes()).hexdigest()
        successful = subprocess.run(command, capture_output=True, text=True, timeout=5)
        result = json.loads(successful.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["vulnerabilityAssessment"], "not_run")
        self.assertTrue(self.invoke()["ok"])

    def test_successful_refresh_replaces_both_files_and_recovers_publication_marker(self):
        marker = self.cache / ".hcp-refresh-pending.json"
        marker.write_text("interrupted earlier publication")
        self.assertEqual(self.invoke()["errorCode"], "refresh_interrupted")
        self.assertTrue(self.invoke(action="download")["ok"])
        self.assertFalse(marker.exists())
        self.assertEqual(self.database.read_bytes(), b"new complete labelled source")
        self.assertEqual(json.loads(self.metadata.read_text())["UpdatedAt"], "2026-10-28T08:00:00Z")
        self.assertTrue(self.invoke()["ok"])

    def test_source_symlink_and_fifo_are_refused_without_following(self):
        original = self.root / "outside"
        original.write_bytes(b"must remain unchanged")
        self.database.unlink()
        self.database.symlink_to(original)
        self.assertFalse(self.invoke()["ok"])
        self.assertEqual(original.read_bytes(), b"must remain unchanged")
        self.database.unlink()
        os.mkfifo(str(self.database))
        result = self.invoke()
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "source_type")

    def test_competing_refresh_waits_for_the_real_native_scanner(self):
        process = subprocess.Popen(self.command(), env=self.environment("hold"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for_file(self.root / "native.pid")
            original = self.database.read_bytes()
            self.assertEqual(self.invoke(action="download", wait=0.15)["errorCode"], "lock_timeout")
            self.assertEqual(self.database.read_bytes(), original)
            (self.root / "release").touch()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertTrue(json.loads(stdout)["ok"])
            self.assertTrue(self.invoke(action="download")["ok"])
        finally:
            (self.root / "release").touch()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def test_killed_helper_cannot_release_lock_held_by_surviving_native_child(self):
        process = subprocess.Popen(self.command(), env=self.environment("hold"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child = None
        try:
            self.wait_for_file(self.root / "native.pid")
            child = int((self.root / "native.pid").read_text())
            process.kill()
            process.communicate(timeout=5)
            os.kill(child, 0)
            self.assertEqual(self.invoke(action="download", wait=0.15)["errorCode"], "lock_timeout")
            (self.root / "release").touch()
            # A new bounded request must wait for the inherited fd to close.
            self.assertTrue(self.invoke(action="download", wait=5)["ok"])
        finally:
            (self.root / "release").touch()
            if child:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_native_timeout_and_output_overflow_are_bounded_failures(self):
        with SOURCE.source_lock(self.cache, 0) as lock_fd:
            for args, timeout, limit, expected in ((["-c", "import time; time.sleep(10)"], 0.1, 4096, "native_timeout"),
                                                 (["-c", "print('x'*50000)"], 5, 1024, "output_limit")):
                with self.subTest(expected=expected):
                    with self.assertRaises(SOURCE.SourceError) as caught:
                        SOURCE.execute([sys.executable] + args, os.environ.copy(), lock_fd, timeout, limit)
                    self.assertEqual(caught.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
