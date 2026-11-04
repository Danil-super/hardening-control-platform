"""Synthetic archives only: proves fail-closed preflight, NOT operational restore."""
import contextlib
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify_backup_bundle.py")
SPEC = importlib.util.spec_from_file_location("verify_backup_bundle", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FILES = MODULE.FILES
FAKE_SECRET = "fake-backing-file-do-not-share-OR-LOG"


def tar_gz(path, entries, *, malicious=None):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries.items():
            if data is None:
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                item.mode = 0o700
            else:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o600
            archive.addfile(item, io.BytesIO(data) if data is not None else None)
        if malicious is not None:
            archive.addfile(malicious)


class BundleGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hcp-offline-backup-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.folder = self.root / "backup"
        self.folder.mkdir(mode=0o700)
        self.write_bundle()

    def write_bundle(self):
        tar_gz(self.folder / "runtime.tar.gz", {
            ".": None, "./hcp.sqlite": b"fake SQLite bytes: not an actual database",
            "./inventory.ini": b"[linux_hosts]\n", "./known_hosts": b"mock-pin\n",
            "./reports": None, "./reports/example.json": b'{"partial": true}',
            "./ssh-host-keys": None,
        })
        tar_gz(self.folder / "settings.tar.gz", {
            ".env": ("HCP_ADMIN_PASSWORD=" + FAKE_SECRET).encode(),
            "secrets": None, "secrets/known_hosts": b"mock-fingerprint\n",
            "ansible/inventory.ini": b"[linux_hosts]\n",
        })
        tar_gz(self.folder / "image.tar.gz", {
            "manifest.json": b'[{"Config": "fake-image.json"}]',
            "fake-image.json": b'{"architecture":"amd64"}',
        })
        values = {
            "commit.txt": ("a" * 40 + "\n").encode(),
            "image-id.txt": ("sha256:" + "b" * 64 + "\n").encode(),
            "architecture.txt": b"x86_64\n",
            # The documented backup command initially makes this file empty.
            "active-timers.txt": b"",
        }
        for name, data in values.items():
            (self.folder / name).write_bytes(data)
        self.regenerate()

    def regenerate(self):
        lines = []
        for name in FILES:
            file = self.folder / name
            file.chmod(0o600)
            lines.append(hashlib.sha256(file.read_bytes()).hexdigest() + "  " + name)
        manifest = self.folder / "SHA256SUMS"
        manifest.write_text("\n".join(lines) + "\n")
        manifest.chmod(0o600)

    def invoke(self, *extra):
        cmd = [sys.executable, str(SCRIPT), "--backup-dir", str(self.folder), *extra]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_valid_backup_is_only_structurally_verified_and_not_restored(self):
        process = self.invoke()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "structurally-verified-not-restored")
        self.assertFalse(result["independentManifestPinMatched"])
        self.assertEqual(result["metadata"]["commit"], "a" * 40)
        self.assertEqual(result["metadata"]["activeTimerCount"], 0)
        self.assertTrue(result["archiveStructure"]["runtime.tar.gz"]["members"] >= 5)
        self.assertNotIn(FAKE_SECRET, process.stdout + process.stderr)
        self.assertNotIn(str(self.folder), process.stdout + process.stderr)
        self.assertFalse((self.root / "report.json").exists())

    def test_independent_manifest_pin_and_exclusive_private_output(self):
        pinned = hashlib.sha256((self.folder / "SHA256SUMS").read_bytes()).hexdigest()
        target = self.root / "preflight.json"
        args = ["--expected-manifest-sha256", pinned, "--output", str(target)]
        process = self.invoke(*args)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(target.read_text())
        self.assertTrue(result["independentManifestPinMatched"])
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.invoke(*args).returncode, 0)
        self.assertNotIn(FAKE_SECRET, target.read_text())
        target.unlink()
        bad = self.invoke("--expected-manifest-sha256", "0" * 64)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(json.loads(bad.stdout)["reasonCode"], "independent_manifest_digest_mismatch")
        self.assertFalse(target.exists())

    def test_changed_archive_is_blocked_without_exposing_contents(self):
        with (self.folder / "runtime.tar.gz").open("ab") as stream:
            stream.write(b"tamper")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "manifest_file_digest_mismatch")
        self.assertNotIn(FAKE_SECRET, result.stdout + result.stderr)

    def test_checksum_manifest_cannot_omit_or_duplicate_files(self):
        manifest = self.folder / "SHA256SUMS"
        rows = manifest.read_text().splitlines()
        manifest.write_text("\n".join(rows[:-1]) + "\n")
        self.assertEqual(json.loads(self.invoke().stdout)["reasonCode"], "manifest_incomplete")
        manifest.write_text("\n".join(rows[:-1] + [rows[0]]) + "\n")
        self.assertEqual(json.loads(self.invoke().stdout)["reasonCode"], "manifest_duplicate_or_unknown")

    def test_world_readable_backup_symlinked_archive_and_manifest_are_blocked(self):
        self.folder.chmod(0o755)
        self.assertEqual(json.loads(self.invoke().stdout)["reasonCode"], "bundle_directory_unsafe")
        self.folder.chmod(0o700)
        image = self.folder / "image.tar.gz"
        image.chmod(0o644)
        self.assertEqual(json.loads(self.invoke().stdout)["reasonCode"], "bundle_file_permissions")
        image.chmod(0o600)
        storage = self.root / "original-runtime.tar.gz"
        runtime = self.folder / "runtime.tar.gz"
        runtime.rename(storage)
        runtime.symlink_to(storage)
        self.assertNotEqual(self.invoke().returncode, 0)
        runtime.unlink()
        storage.rename(runtime)
        manifest = self.folder / "SHA256SUMS"
        manifest.rename(self.root / "manifest")
        manifest.symlink_to(self.root / "manifest")
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_unsafe_tar_paths_even_with_correct_digest_are_rejected(self):
        bad = tarfile.TarInfo("../../escape")
        bad.size = 0
        bad.mode = 0o600
        tar_gz(self.folder / "runtime.tar.gz", {
            ".": None, "./hcp.sqlite": b"sqlite", "./inventory.ini": b"x",
            "./known_hosts": b"x",
        }, malicious=bad)
        self.regenerate()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "archive_path_traversal")
        self.assertFalse((self.root / "escape").exists())

    def test_unsafe_symlink_in_settings_is_blocked_even_with_matching_hashes(self):
        link = tarfile.TarInfo("secrets/../../etc/shadow")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        tar_gz(self.folder / "settings.tar.gz", {
            ".env": b"fake", "secrets": None,
            "ansible/inventory.ini": b"abc",
        }, malicious=link)
        self.regenerate()
        data = json.loads(self.invoke().stdout)
        self.assertEqual(data["status"], "blocked")
        self.assertIn(data["reasonCode"], ("archive_path_traversal", "archive_path_unsafe"))

    def test_runtime_must_contain_sqlite_inventory_and_known_hosts(self):
        tar_gz(self.folder / "runtime.tar.gz", {
            ".": None, "./inventory.ini": b"x", "./known_hosts": b"x",
        })
        self.regenerate()
        result = json.loads(self.invoke().stdout)
        self.assertEqual(result["reasonCode"], "runtime_missing_required")

    def test_settings_require_env_inventory_and_secret_directory(self):
        tar_gz(self.folder / "settings.tar.gz", {
            ".env": b"test-secret", "secrets": None,
        })
        self.regenerate()
        result = json.loads(self.invoke().stdout)
        self.assertEqual(result["reasonCode"], "settings_missing_required")

    def test_no_output_in_backup_folder_and_foreign_path_protection(self):
        result = self.invoke("--output", str(self.folder / "same.json"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.folder / "same.json").exists())
        self.assertNotIn(str(self.folder), result.stderr + result.stdout)

    def test_valid_activated_timers_are_counted_without_running_them(self):
        (self.folder / "active-timers.txt").write_text(
            "hcp-deep-audit.timer\nhcp-scheduled-audit.timer\n")
        self.regenerate()
        parsed = json.loads(self.invoke().stdout)
        self.assertEqual(parsed["status"], "structurally-verified-not-restored")
        self.assertEqual(parsed["metadata"]["activeTimerCount"], 2)


if __name__ == "__main__":
    unittest.main()
