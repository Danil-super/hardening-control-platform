"""Synthetic offline restored-volume tests; do NOT claim Docker/SSH restore passed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "verify_restored_runtime.py"
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("verify_restored_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SECRET = b"fake-private-key-material-NEVER-PRINT"
FILES = ("runtime.tar.gz", "settings.tar.gz", "image.tar.gz",
         "commit.txt", "image-id.txt", "architecture.txt", "active-timers.txt")


def archive(path, file_tree):
    with tarfile.open(path, mode="w:gz") as tar:
        for name, kind in file_tree:
            info = tarfile.TarInfo(name)
            if kind is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                tar.addfile(info)
            else:
                info.size = len(kind)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(kind))


class RestoredRuntimeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hcp-restored-runtime-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.backup = self.root / "backup"
        self.backup.mkdir(mode=0o700)
        self.restored = self.root / "restored"
        self.restored.mkdir(mode=0o700)
        db = self.restored / "hcp.sqlite"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, note TEXT)")
        conn.execute("INSERT INTO audit_events(note) VALUES ('synthetic integrity check')")
        conn.commit()
        conn.close()
        db.chmod(0o600)
        assets = {
            "hcp.sqlite": db.read_bytes(),
            "inventory.ini": b"[linux_hosts]\nunit-host\n",
            "known_hosts": b"hashed-ssh-host-pinned\n",
            "ssh-host-keys/one/id_ed25519": SECRET,
            "ssh-host-keys/one/id_ed25519.pub": b"ssh-ed25519 SYNTHETIC-UNIT-ONLY",
            "reports/unit-host-audit.json": b'{"mode":"openscap","partial":true}',
            "sbom/unit-host.json": b'{"bomFormat":"CycloneDX"}',
        }
        for name, data in assets.items():
            file = self.restored / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
            file.chmod(0o600)
        archive(self.backup / "runtime.tar.gz", [
            (".", None),
            ("./ssh-host-keys", None),
            ("./ssh-host-keys/one", None),
            ("./reports", None),
            ("./sbom", None),
            *[("./" + name, data) for name, data in assets.items()],
        ])
        archive(self.backup / "settings.tar.gz", [
            ("secrets", None), (".env", SECRET),
            ("secrets/known_hosts", b"pinned-host"),
            ("ansible/inventory.ini", b"[linux_hosts]\n"),
        ])
        archive(self.backup / "image.tar.gz", [
            ("manifest.json", b'[{"Config":"mock.json"}]'),
        ])
        for name, value in {
            "commit.txt": "c" * 40 + "\n",
            "image-id.txt": "sha256:" + "d" * 64 + "\n",
            "architecture.txt": "x86_64\n",
            "active-timers.txt": "",
        }.items():
            (self.backup / name).write_text(value)
        self.update_manifest()

    def update_manifest(self):
        lines = []
        for name in FILES:
            file = self.backup / name
            file.chmod(0o600)
            lines.append(hashlib.sha256(file.read_bytes()).hexdigest() + "  " + name)
        f = self.backup / "SHA256SUMS"
        f.write_text("\n".join(lines) + "\n")
        f.chmod(0o600)

    def command(self, *extra, acknowledge=True, require=True):
        cmd = [sys.executable, str(SCRIPT), "--backup-dir", str(self.backup),
               "--restored-runtime", str(self.restored)]
        if acknowledge:
            cmd.append("--acknowledge-stopped")
        if require:
            cmd.append("--require-enrolled-host")
        return subprocess.run(cmd + list(extra), capture_output=True, text=True)

    def test_genuine_matching_bytes_and_sqlite_integrity_are_scoped_only(self):
        outcome = self.command()
        self.assertEqual(outcome.returncode, 0, outcome.stdout + outcome.stderr)
        data = json.loads(outcome.stdout)
        self.assertEqual(data["status"], "critical-runtime-bytes-match-backup")
        self.assertEqual(data["sqlite"]["integrityCheck"], "ok")
        self.assertGreaterEqual(data["sqlite"]["tableCount"], 1)
        self.assertEqual(data["categories"]["sqlite"], 1)
        self.assertEqual(data["categories"]["hostKeyFiles"], 2)
        self.assertEqual(data["categories"]["reports"], 1)
        for flag in ("actualLoginVerified", "auditHmacChainVerified",
                     "sessionsRevokedVerified", "sshReconnectVerified"):
            self.assertFalse(data[flag])
        self.assertNotIn(SECRET.decode(), outcome.stdout + outcome.stderr)
        self.assertNotIn(str(self.restored), outcome.stdout)

    def test_no_acknowledgement_is_blocked_before_any_success(self):
        result = self.command(acknowledge=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"],
                         "stopped_restore_acknowledgement_required")

    def test_modified_report_or_private_key_fail_without_disclosing_data(self):
        for filename in ("reports/unit-host-audit.json",
                         "ssh-host-keys/one/id_ed25519",
                         "inventory.ini", "known_hosts"):
            with self.subTest(filename=filename):
                file = self.restored / filename
                original = file.read_bytes()
                file.write_bytes(b"changed contents" + SECRET)
                result = self.command()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)["reasonCode"],
                                 "restored_file_mismatch")
                self.assertNotIn(SECRET.decode(), result.stdout + result.stderr)
                file.write_bytes(original)
                file.chmod(0o600)

    def test_symlink_to_private_key_does_not_escape_restored_root(self):
        file = self.restored / "ssh-host-keys/one/id_ed25519"
        original = file.read_bytes()
        file.unlink()
        foreign = self.root / "not-restored-private-key"
        foreign.write_bytes(original)
        file.symlink_to(foreign)
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout).get("restorationVerified", True))

    def test_sqlite_corruption_and_wal_marker_are_separately_blocked(self):
        sqlite = self.restored / "hcp.sqlite"
        original = sqlite.read_bytes()
        sqlite.write_bytes(b"x" * len(original))
        self.assertNotEqual(self.command().returncode, 0)
        sqlite.write_bytes(original)
        sqlite.chmod(0o600)
        (self.restored / "hcp.sqlite-wal").write_bytes(b"nonempty WAL marker")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"],
                         "sqlite_wal_requires_separate_checkpoint_review")

    def test_release_gate_demands_enrolled_host_and_preserved_reports(self):
        key = self.restored / "ssh-host-keys/one/id_ed25519"
        key.unlink()
        self.assertNotEqual(self.command().returncode, 0)
        # The optional diagnostic flag does not waive byte mismatch for a
        # missing key: structural comparison still refuses the restore.
        self.assertNotEqual(self.command(require=False).returncode, 0)

    def test_private_result_is_new_and_never_written_inside_evidence(self):
        target = self.root / "post-restore.json"
        result = self.command("--output", str(target))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(target.read_text())["sqlite"]["integrityCheck"], "ok")
        self.assertNotEqual(self.command("--output", str(target)).returncode, 0)
        target.unlink()
        file = self.restored / "invalid-output.json"
        self.assertNotEqual(self.command("--output", str(file)).returncode, 0)
        self.assertFalse(file.exists())


if __name__ == "__main__":
    unittest.main()
