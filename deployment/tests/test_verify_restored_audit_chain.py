"""Synthetic local HCP v1/v2 audit events; no real user secrets or HCP access."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "verify_restored_audit_chain.py"
SPEC = importlib.util.spec_from_file_location("verify_restored_audit_chain", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

KEY = "Synthetic-Key-Not-For-Deployment-12345678901234567890123456789"
DDL = """CREATE TABLE audit_events (
id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
event_type TEXT NOT NULL, entity_id TEXT NOT NULL,
payload_json TEXT NOT NULL, previous_hash TEXT,
entry_hash TEXT NOT NULL UNIQUE, hash_version INTEGER NOT NULL
)"""
SECRET = "EXAMPLE-PRIVATE-PAYLOAD-NEVER-LOG"


class RestoredAuditGateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hcp-audit-chain-restore-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.runtime = self.root / "offline-runtime"
        self.runtime.mkdir(mode=0o700)
        self.db = self.runtime / "hcp.sqlite"
        self.config = self.root / "private-config"
        self.config.mkdir(mode=0o700)
        self.env = self.config / ".env"
        self.env.write_text("HCP_AUDIT_HMAC_KEY=" + KEY + "\n")
        self.env.chmod(0o600)
        conn = sqlite3.connect(str(self.db))
        conn.execute(DDL)
        conn.execute("CREATE TABLE admin_sessions (token_hash TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()
        self.db.chmod(0o600)
        self.insert_events([(2, {"nested": {"alpha": 1, "zeta": SECRET}}),
                            (2, {"approved": True, "tags": [2, 1]})])

    def insert_events(self, specs):
        conn = sqlite3.connect(str(self.db))
        conn.execute("DELETE FROM audit_events")
        previous = None
        for i, (version, payload) in enumerate(specs):
            at = "2026-11-04T05:%02d:00.000Z" % i
            evt = {"createdAt": at, "eventType": "test",
                   "entityId": "evt-%d" % i, "payload": payload,
                   "previousHash": previous}
            digest = MOD.calculate_hash(evt, KEY.encode(), version)
            conn.execute("INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         ("id-%d" % i, at, "test", "evt-%d" % i,
                          json.dumps(payload), previous, digest, version))
            previous = digest
        conn.commit()
        conn.close()
        self.db.chmod(0o600)

    def invoke(self, *params, ack=True):
        argv = [sys.executable, str(SCRIPT), "--restored-runtime",
                str(self.runtime), "--env", str(self.env)]
        if ack:
            argv.append("--acknowledge-stopped")
        return subprocess.run(argv + list(params), capture_output=True, text=True)

    def test_unchanged_v2_chain_passes_but_no_production_claims(self):
        result = self.invoke("--require-payload-protection")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["entries"], 2)
        self.assertEqual(value["legacyEntries"], 0)
        self.assertTrue(value["payloadProtectedForAllEntries"])
        self.assertFalse(value["restoredLoginVerified"])
        self.assertFalse(value["publisherOrOperatorAuthenticated"])
        self.assertNotIn(KEY, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(str(self.runtime), result.stdout + result.stderr)

    def test_modifying_a_payload_without_hmac_key_fails(self):
        conn = sqlite3.connect(str(self.db))
        conn.execute("UPDATE audit_events SET payload_json = ? WHERE id = ?",
                     ('{"nested":{"alpha":99,"zeta":"tampered"}}', "id-0"))
        conn.commit()
        conn.close()
        self.db.chmod(0o600)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "audit_entry_hmac_mismatch")
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_a_broken_previous_pointer_never_passes(self):
        conn = sqlite3.connect(str(self.db))
        conn.execute("UPDATE audit_events SET previous_hash = ? WHERE id = ?",
                     ("0" * 64, "id-1"))
        conn.commit()
        conn.close()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"],
                         "audit_chain_previous_hash_mismatch")

    def test_legacy_v1_entry_passes_only_with_explicit_weaker_scope(self):
        self.insert_events([(1, {"nested": {"secret": SECRET}}),
                            (2, {"verified": "after-legacy"})])
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["legacyEntries"], 1)
        self.assertFalse(value["payloadProtectedForAllEntries"])
        strict = self.invoke("--require-payload-protection")
        self.assertNotEqual(strict.returncode, 0)
        self.assertEqual(json.loads(strict.stdout)["reasonCode"],
                         "legacy_entries_payload_not_fully_protected")
        # Legacy JSON.stringify replacer-list excludes nested 'secret' key.
        # This is a known limitation, never report all payloads as protected.
        conn = sqlite3.connect(str(self.db))
        conn.execute("UPDATE audit_events SET payload_json=? WHERE id=?",
                     ('{"nested":{"secret":"changed-without-updating-hash"}}', "id-0"))
        conn.commit()
        conn.close()
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["payloadProtectedForAllEntries"])

    def test_wrong_hmac_key_and_missing_secret_are_never_success(self):
        self.env.write_text("HCP_AUDIT_HMAC_KEY=" + "X" * 64 + "\n")
        self.env.chmod(0o600)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "audit_entry_hmac_mismatch")
        self.env.write_text("HCP_AUDIT_HMAC_KEY=\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "audit_key_missing_or_short")

    def test_no_confirmation_or_public_env_permissions_fail(self):
        self.assertNotEqual(self.invoke(ack=False).returncode, 0)
        self.env.chmod(0o644)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_sqlite_wal_symlink_and_empty_chain_fail_closed(self):
        (self.runtime / "hcp.sqlite-wal").write_bytes(b"pending")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "sqlite_wal_needs_separate_recovery")
        (self.runtime / "hcp.sqlite-wal").unlink()
        conn = sqlite3.connect(str(self.db))
        conn.execute("DELETE FROM audit_events")
        conn.commit()
        conn.close()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reasonCode"], "audit_history_empty")
        original = self.root / "saved.sqlite"
        self.db.rename(original)
        self.db.symlink_to(original)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_private_exclusive_receipt_and_no_rewrites(self):
        old_bytes = self.db.read_bytes()
        output = self.root / "preflight.json"
        result = self.invoke("--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.db.read_bytes(), old_bytes)
        self.assertNotIn(SECRET, output.read_text())
        self.assertNotEqual(self.invoke("--output", str(output)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
