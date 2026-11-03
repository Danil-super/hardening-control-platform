import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("validate_production_env.py")
SPEC = importlib.util.spec_from_file_location("hcp_release_env_preflight", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

VALUES = {
    "HCP_ADMIN_PASSWORD": "Sample-Strong-Secret-Passphrase-01!",
    "HCP_AUTH_SECRET": "Secret-for-auth-cookie-digest-wNsA-12345!",
    "HCP_AUDIT_HMAC_KEY": "Another-independent-audit-key-Rv32vZ!",
    "HCP_SCHEDULE_API_KEY": "Third-random-looking-schedule-key-Zf7!",
}


def serialize(values):
    return "\n".join(key + "=" + value for key, value in values.items()) + "\n"


class ReleaseEnvPreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hcp-release-env-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = self.root / ".env"
        self.write(VALUES)

    def write(self, values):
        self.env.write_text(serialize(values), encoding="utf-8")
        self.env.chmod(0o600)

    def run_cli(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), "--env", str(self.env), "--json", *extra],
                              capture_output=True, text=True)

    def test_valid_independent_secrets_and_private_file_are_only_static_preflight(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["checks"]["requiredSecretFields"], 4)
        self.assertIn("does not certify", data["note"])
        for secret in VALUES.values():
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count('"status": "passed"'), 1)

    def test_unset_placeholder_too_short_and_duplicate_secrets_fail(self):
        values = dict(VALUES)
        values.pop("HCP_AUTH_SECRET")
        values["HCP_AUDIT_HMAC_KEY"] = VALUES["HCP_ADMIN_PASSWORD"]
        values["HCP_SCHEDULE_API_KEY"] = "replace-with-not-safe"
        self.write(values)
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        codes = {(item["field"], item["code"]) for item in data["blockers"]}
        self.assertIn(("HCP_AUTH_SECRET", "secret_missing"), codes)
        self.assertIn(("HCP_AUDIT_HMAC_KEY", "secret_matches_other_field"), codes)
        self.assertIn(("HCP_SCHEDULE_API_KEY", "secret_weak_or_template"), codes)
        for secret in values.values():
            self.assertNotIn(secret, result.stdout + result.stderr)

    def test_symlink_open_permissions_duplicate_names_and_oversize_fail(self):
        self.env.chmod(0o644)
        self.assertEqual(json.loads(self.run_cli().stdout)["blockers"][0]["code"], "env_permissions_too_open")
        self.env.chmod(0o600)
        with self.env.open("a", encoding="utf-8") as output:
            output.write("HCP_ADMIN_PASSWORD=SecondSecretOverrideShouldBeBlocked\n")
        self.assertEqual(json.loads(self.run_cli().stdout)["blockers"][0]["code"], "env_syntax_or_duplicate")
        self.write(VALUES)
        moved = self.root / "actual-env"
        self.env.rename(moved)
        self.env.symlink_to(moved)
        self.assertEqual(json.loads(self.run_cli().stdout)["blockers"][0]["code"], "env_not_regular")
        self.env.unlink()
        self.env.write_bytes(b"#" * (MODULE.MAX_BYTES + 1))
        self.env.chmod(0o600)
        self.assertEqual(json.loads(self.run_cli().stdout)["blockers"][0]["code"], "env_size_invalid")

    def test_dependency_track_secret_opt_in_and_remote_bind_warnings(self):
        values = dict(VALUES, HCP_BIND_ADDRESS="0.0.0.0", HCP_TRUSTED_TLS_PROXY="true")
        self.write(values)
        data = json.loads(self.run_cli().stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(len(data["warnings"]), 2)
        required = json.loads(self.run_cli("--with-dependency-track").stdout)
        self.assertEqual(required["status"], "blocked")
        self.assertEqual(required["blockers"][0]["field"], "HCP_DEPENDENCY_TRACK_DB_PASSWORD")
        values["HCP_DEPENDENCY_TRACK_DB_PASSWORD"] = "Separate-Database-password-Zk29x!"
        self.write(values)
        self.assertEqual(self.run_cli("--with-dependency-track").returncode, 0)


if __name__ == "__main__":
    unittest.main()
