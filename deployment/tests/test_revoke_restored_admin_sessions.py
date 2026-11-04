"""Synthetic SQLite restore tests; no production database or real session is touched."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("revoke_restored_admin_sessions.py")
SPEC = importlib.util.spec_from_file_location("revoke_restored_admin_sessions", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SESSION_DDL = """CREATE TABLE admin_sessions (
 token_hash TEXT PRIMARY KEY,
 credential_generation TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
)"""
SECRET = "FAKE-SESSION-TOKEN-HASH-DO-NOT-LOG"


class SessionRestoreAcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hcp-restored-session-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runtime = self.root / "isolated-restored-runtime"
        self.runtime.mkdir(mode=0o700)
        self.db = self.runtime / "hcp.sqlite"
        db = sqlite3.connect(str(self.db))
        db.execute(SESSION_DDL)
        db.execute("CREATE TABLE audit_ledger (id INTEGER PRIMARY KEY, proof TEXT)")
        db.execute("INSERT INTO audit_ledger (proof) VALUES ('source-audit-chain-unchanged')")
        db.execute("INSERT INTO admin_sessions VALUES (?, 'hmac-generation', 100, 200)",
                   (SECRET,))
        db.execute("INSERT INTO admin_sessions VALUES ('second-hash', 'g2', 110, 210)")
        db.commit()
        db.close()
        self.db.chmod(0o600)

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT),
            "--restored-runtime", str(self.runtime), *args],
            capture_output=True, text=True)

    def digest(self):
        return hashlib.sha256(self.db.read_bytes()).hexdigest()

    def apply_args(self, *, pin=None, receipt=None):
        return ["--apply", "--confirm-isolated-stopped",
                "--confirm-text", MODULE.CONFIRM,
                "--expected-db-sha256", pin or self.digest(),
                "--output", str(receipt or (self.root / "revocation.json"))]

    def count(self):
        conn = sqlite3.connect(str(self.db))
        try:
            return conn.execute("SELECT COUNT(*) FROM admin_sessions").fetchone()[0]
        finally:
            conn.close()

    def test_read_only_preview_reports_count_but_never_token_values(self):
        before = self.digest()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["storedSessionHashes"], 2)
        self.assertEqual(output["databaseSha256"], before)
        self.assertFalse(output["revocationPerformed"])
        self.assertEqual(self.digest(), before)
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_explicit_revocation_only_deletes_admin_sessions_and_preserves_ledger(self):
        receipt = self.root / "revoked.json"
        args = self.apply_args(receipt=receipt)
        result = self.invoke(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "restored-admin-session-hashes-revoked")
        self.assertEqual(data["sessionsRemoved"], 2)
        self.assertEqual(data["remainingSessionHashes"], 0)
        self.assertFalse(data["hmacChainVerified"])
        self.assertFalse(data["oldBrowserCookiesTested"])
        self.assertFalse(data["originalControllerIsolationIndependentlyVerified"])
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET, receipt.read_text() + result.stdout + result.stderr)
        self.assertEqual(self.count(), 0)
        con = sqlite3.connect(str(self.db))
        try:
            self.assertEqual(con.execute("SELECT proof FROM audit_ledger").fetchone()[0],
                             "source-audit-chain-unchanged")
        finally:
            con.close()
        self.assertNotEqual(self.invoke(*args).returncode, 0)

    def test_missing_confirmation_does_not_modify_database(self):
        before = self.digest()
        result = self.invoke("--apply", "--expected-db-sha256", before,
                             "--output", str(self.root / "result.json"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"],
                         "explicit_isolated_restore_confirmation_required")
        self.assertEqual(self.digest(), before)

    def test_mismatched_expected_hash_does_not_change_database(self):
        before = self.digest()
        result = self.invoke(*self.apply_args(pin="0" * 64))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "sqlite_digest_mismatch")
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.count(), 2)

    def test_active_wal_and_symlink_are_refused(self):
        before = self.digest()
        (self.runtime / "hcp.sqlite-wal").write_bytes(b"uncheckpointed bytes")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"],
                         "sqlite_wal_requires_offline_review")
        (self.runtime / "hcp.sqlite-wal").unlink()
        foreign = self.root / "backup.sqlite"
        self.db.rename(foreign)
        self.db.symlink_to(foreign)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(hashlib.sha256(foreign.read_bytes()).hexdigest(), before)

    def test_no_admin_session_schema_never_creates_table(self):
        con = sqlite3.connect(str(self.db))
        con.execute("DROP TABLE admin_sessions")
        con.commit()
        con.close()
        self.db.chmod(0o600)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "session_schema_unexpected")

    def test_receipt_cannot_be_stored_inside_restored_runtime(self):
        before = self.digest()
        dest = self.runtime / "cannot-write.json"
        result = self.invoke(*self.apply_args(receipt=dest))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(dest.exists())
        self.assertEqual(self.digest(), before)


if __name__ == "__main__":
    unittest.main()
