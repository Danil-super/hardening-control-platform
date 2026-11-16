"""Real archive/SQLite/HMAC fixture for the read-only DR readiness aggregator.

These are synthetic local bytes; they do NOT establish operational recovery of
HCP, Docker, SSH or any Astra Linux release.
"""
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
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_restored_audit_chain as hmac_gate
SCRIPT = HERE / "check_restore_readiness.py"
SPEC = importlib.util.spec_from_file_location("check_restore_readiness", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
FAKE_HMAC = "Example-HMAC-Only-For-Synthetic-DR-Tests-123456789"
SECRET = "TEST-PROTECTED-KEY-NOT-FOR-PRODUCTION"
ARCHIVES = ["runtime.tar.gz", "settings.tar.gz", "image.tar.gz"]
MANIFEST_FILES = ARCHIVES + [
    "commit.txt", "image-id.txt", "architecture.txt", "active-timers.txt",
]


def make_tar(path, items):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in items.items():
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.DIRTYPE
                member.mode = 0o700
                archive.addfile(member)
            else:
                member.size = len(data)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(data))
    path.chmod(0o600)


class OfflineReadinessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hcp-local-release-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.backup = self.root / "backup"
        self.runtime = self.root / "restored-runtime"
        self.secrets = self.root / "settings"
        for directory in (self.backup, self.runtime, self.secrets):
            directory.mkdir(mode=0o700)
        self.env = self.secrets / ".env"
        self.env.write_text("HCP_AUDIT_HMAC_KEY=" + FAKE_HMAC + "\n")
        self.env.chmod(0o600)
        self.db = self.runtime / "hcp.sqlite"
        connection = sqlite3.connect(str(self.db))
        connection.executescript("""
            CREATE TABLE audit_events (
              id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL,
              entity_id TEXT NOT NULL, payload_json TEXT NOT NULL,
              previous_hash TEXT, entry_hash TEXT NOT NULL UNIQUE,
              hash_version INTEGER NOT NULL
            );
            CREATE TABLE admin_sessions (token_hash TEXT PRIMARY KEY);
        """)
        previous = None
        for n in range(3):
            payload = {"synthetic": True, "nested": {"test": n}}
            observed = {
                "createdAt": "2026-11-04T07:0%d:00.000Z" % n,
                "eventType": "test", "entityId": "event-%d" % n,
                "payload": payload, "previousHash": previous,
            }
            checksum = hmac_gate.calculate_hash(observed, FAKE_HMAC.encode(), 2)
            connection.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,2)",
                               ("row-%d" % n, observed["createdAt"], "test",
                                observed["entityId"], json.dumps(payload), previous,
                                checksum))
            previous = checksum
        connection.commit()
        connection.close()
        self.db.chmod(0o600)
        self.anchor = previous
        self.count = 3
        self.files = {
            "hcp.sqlite": self.db.read_bytes(),
            "inventory.ini": b"[linux_hosts]\nsynthetic-host ansible_host=192.0.2.3\n",
            "known_hosts": b"fake-key-pin\n",
            "ssh-host-keys/fixture/id_ed25519": SECRET.encode(),
            "ssh-host-keys/fixture/id_ed25519.pub": b"synthetic-public-key",
            "reports/synthetic-scap.json": b'{"scanner":{"partial":true}}',
            "sbom/synthetic.json": b'{"bomFormat":"CycloneDX"}',
        }
        for name, value in self.files.items():
            f = self.runtime / name
            f.parent.mkdir(parents=True, exist_ok=True)
            if f != self.db:
                f.write_bytes(value)
            f.chmod(0o600)
        self.make_backup()

    def make_backup(self):
        self.files["hcp.sqlite"] = self.db.read_bytes()
        runtime = {
            ".": None, "./reports": None, "./ssh-host-keys": None,
            "./ssh-host-keys/fixture": None, "./sbom": None,
        }
        for name, data in self.files.items():
            runtime["./" + name] = data
        make_tar(self.backup / "runtime.tar.gz", runtime)
        make_tar(self.backup / "settings.tar.gz", {
            "secrets": None,
            ".env": self.env.read_bytes(),
            "ansible/inventory.ini": self.files["inventory.ini"],
            "secrets/known_hosts": self.files["known_hosts"],
        })
        make_tar(self.backup / "image.tar.gz", {
            "manifest.json": b'[{"Config":"fake-image-config.json"}]',
            "fake-image-config.json": b'{"architecture":"amd64"}',
        })
        for name, value in {
            "commit.txt": "a" * 40 + "\n",
            "image-id.txt": "sha256:" + "b" * 64 + "\n",
            "architecture.txt": "x86_64\n",
            "active-timers.txt": "",
        }.items():
            (self.backup / name).write_text(value, encoding="utf-8")
        lines = []
        for name in MANIFEST_FILES:
            f = self.backup / name
            f.chmod(0o600)
            lines.append(hashlib.sha256(f.read_bytes()).hexdigest() + "  " + name)
        manifest = self.backup / "SHA256SUMS"
        manifest.write_text("\n".join(lines) + "\n")
        manifest.chmod(0o600)
        self.manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

    def cli(self, *extras, include_pins=True, ack=True):
        argv = [sys.executable, str(SCRIPT),
                "--backup-dir", str(self.backup),
                "--restored-runtime", str(self.runtime),
                "--env", str(self.env)]
        if ack:
            argv.append("--acknowledge-isolated-stopped")
        if include_pins:
            argv.extend(["--expected-manifest-sha256", self.manifest_sha,
                         "--expected-head-hmac", self.anchor,
                         "--expected-entry-count", str(self.count)])
        argv.extend(extras)
        return subprocess.run(argv, capture_output=True, text=True)

    def test_all_actual_local_bytes_succeed_with_both_operator_pins(self):
        proc = self.cli()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "local-preflight-complete-live-recovery-unverified")
        self.assertEqual(result["criticalFilesCompared"], len(self.files))
        self.assertEqual(result["auditHmac"]["entries"], 3)
        self.assertEqual(result["sqliteIntegrity"], "ok")
        self.assertTrue(result["operatorSuppliedIndependentAuditHeadMatched"])
        self.assertTrue(result["operatorSuppliedIndependentManifestPinMatched"])
        self.assertEqual(result["reviewRequired"], [])
        for name in ("operatorHasVerifiedLiveService", "originalAdminCookieRevocationVerified",
                     "restoredSshReconnectVerified", "firewallRollbackVerified",
                     "completeRecoveryVerified"):
            self.assertFalse(result[name])
        self.assertNotIn(SECRET, proc.stdout + proc.stderr)
        self.assertNotIn(FAKE_HMAC, proc.stdout + proc.stderr)
        self.assertNotIn(str(self.runtime), proc.stdout + proc.stderr)

    def test_local_self_consistent_archive_without_manifest_pin_is_blocked(self):
        proc = self.cli(include_pins=False)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reasonCode"], "independent_manifest_pin_required")

    def test_missing_or_wrong_manifest_pin_stops_before_sqlite_and_secrets(self):
        for digest, reason in ((None, "independent_manifest_pin_required"),
                               ("0" * 64, "independent_manifest_digest_mismatch")):
            with self.subTest(digest=digest), \
                    patch.object(sqlite3, "connect", side_effect=AssertionError("SQLite opened")), \
                    patch.object(MOD, "read_env_file", side_effect=AssertionError("Secret read")):
                with self.assertRaises((MOD.ReadinessFailure, MOD.VerificationFailure)) as caught:
                    MOD.run_preflight(self.backup, self.runtime, self.env, manifest_sha=digest)
                self.assertEqual(caught.exception.code, reason)

    def test_trusted_archive_without_audit_anchor_remains_incomplete(self):
        proc = self.cli("--expected-manifest-sha256", self.manifest_sha, include_pins=False)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "local-preflight-incomplete-authority")
        self.assertEqual(result["reviewRequired"], ["independent_audit_head_pin_missing"])

    def test_archive_tampering_is_distinct_from_restored_file_mismatch(self):
        with (self.backup / "runtime.tar.gz").open("ab") as stream:
            stream.write(b"append without manifest change")
        proc = self.cli()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["reasonCode"], "manifest_file_digest_mismatch")
        self.make_backup()
        report = self.runtime / "reports/synthetic-scap.json"
        report.write_text("changed", encoding="utf-8")
        report.chmod(0o600)
        proc = self.cli()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["reasonCode"], "restored_file_mismatch")

    def test_valid_hmac_prefix_cannot_replace_externally_pinned_full_history(self):
        con = sqlite3.connect(str(self.db))
        con.execute("DELETE FROM audit_events WHERE id='row-2'")
        con.commit()
        con.close()
        self.db.chmod(0o600)
        # Update the backup too, so all local/archive checks still pass:
        # the externally retained audit length is the sole remaining witness.
        self.make_backup()
        out = self.cli()
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(json.loads(out.stdout)["reasonCode"],
                         "audit_anchor_entry_count_mismatch")

    def test_valid_different_hmac_tail_at_same_length_is_blocked(self):
        con = sqlite3.connect(str(self.db))
        con.execute("UPDATE audit_events SET payload_json=? WHERE id='row-2'",
                    ('{"synthetic":false}',))
        # Re-sign only the altered last event with the known fake key:
        previous = con.execute("SELECT entry_hash FROM audit_events WHERE id='row-1'").fetchone()[0]
        changed = {
            "createdAt": "2026-11-04T07:02:00.000Z",
            "eventType": "test", "entityId": "event-2",
            "payload": {"synthetic": False}, "previousHash": previous,
        }
        head = hmac_gate.calculate_hash(changed, FAKE_HMAC.encode(), 2)
        con.execute("UPDATE audit_events SET entry_hash=? WHERE id='row-2'", (head,))
        con.commit()
        con.close()
        self.db.chmod(0o600)
        self.make_backup()
        out = self.cli()
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(json.loads(out.stdout)["reasonCode"], "audit_anchor_head_mismatch")

    def test_missing_ack_and_bad_pin_are_fail_closed(self):
        self.assertEqual(json.loads(self.cli(ack=False).stdout)["reasonCode"],
                         "stopped_isolated_restore_acknowledgement_required")
        out = self.cli("--expected-manifest-sha256", "0" * 64)
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(json.loads(out.stdout)["reasonCode"],
                         "independent_manifest_digest_mismatch")
        bad = self.cli("--expected-head-hmac", "c" * 64)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(json.loads(bad.stdout)["reasonCode"],
                         "audit_anchor_head_mismatch")

    def test_receipt_is_exclusive_private_and_not_inside_any_evidence(self):
        destination = self.root / "readiness.json"
        out = self.cli("--output", str(destination))
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET, destination.read_text())
        self.assertNotEqual(self.cli("--output", str(destination)).returncode, 0)
        destination.unlink()
        for nested in (self.backup / "bad.json",
                       self.runtime / "bad.json",
                       self.secrets / "bad.json"):
            with self.subTest(nested=str(nested)):
                result = self.cli("--output", str(nested))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(nested.exists())


if __name__ == "__main__":
    unittest.main()
