"""Offline tests only; never call an actual Docker daemon or user's HCP."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import preflight_control_node as mod


class ControlNodeReadinessTests(unittest.TestCase):
    def fixture(self, home):
        root = Path(home) / "project"
        (root / "secrets").mkdir(parents=True, mode=0o700)
        (root / "ansible").mkdir()
        (root / "Dockerfile").write_text("FROM scratch\n")
        (root / "docker-compose.yml").write_text("services: {}\n")
        (root / "ansible" / "inventory.ini").write_text("[linux_hosts]\n")
        (root / "secrets" / "known_hosts").write_text("")
        os.chmod(root / "secrets", 0o700)
        os.chmod(root / "secrets" / "known_hosts", 0o600)
        data = {
            "HCP_ADMIN_PASSWORD": "ABcdEfGH0123456789+_^!password",
            "HCP_AUTH_SECRET": "mnopQRSTuvWXzy1234567890!@#$%^^&&**",
            "HCP_AUDIT_HMAC_KEY": "abcdef0123456789QRSTUVWX+=!abcdef",
            "HCP_SCHEDULE_API_KEY": "Zxyw!23456789&-=ABCDEabcdeX_YZ7890",
            "HCP_BIND_ADDRESS": "127.0.0.1",
        }
        (root / ".env").write_text("\n".join(k + "=" + v for k, v in data.items()) + "\n")
        os.chmod(root / ".env", 0o600)
        return root, data

    def runner(self, args, **kwargs):
        self.assertEqual(args[0], "docker")
        self.assertNotIn("up", args)
        self.assertNotIn("exec", args)
        self.assertNotIn("logs", args)
        self.assertTrue(kwargs["capture_output"])
        if args[1:] == ["compose", "ps", "--format", "json"]:
            return SimpleNamespace(returncode=0,
                stdout=json.dumps({"Service":"hcp","State":"running","Health":"healthy",
                                   "Secret":"should-be-discarded"}),
                stderr="PRIVATE_PASSWORD")
        return SimpleNamespace(returncode=0, stdout="PRIVATE_PASSWORD", stderr="PRIVATE_PASSWORD")

    def test_read_only_passing_preflight_has_no_production_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, secrets = self.fixture(temporary)
            result = mod.probe(root, ".env", check_running=True, runner=self.runner)
            self.assertEqual(result["status"], "static-preflight-passed-live-acceptance-not-proven")
            self.assertEqual(result["checks"]["hcpRuntime"], "healthy")
            self.assertFalse(result["operatorAcceptanceCompleted"])
            self.assertFalse(result["nativeAstra17AcceptanceCompleted"])
            dumped = json.dumps(result)
            for value in secrets.values():
                self.assertNotIn(value, dumped)
            self.assertNotIn("PRIVATE_PASSWORD", dumped)
            self.assertNotIn("should-be-discarded", dumped)

    def test_cannot_call_runtime_when_docker_disabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            status = mod.probe(root, ".env", with_docker=False, check_running=True)
            self.assertEqual(status["status"], "blocked")
            self.assertIn("runtime_requires_docker_checks",
                {x["code"] for x in status["blockers"]})

    def test_invalid_env_and_docker_error_never_expose_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, secrets = self.fixture(temporary)
            (root / ".env").write_text("SENSITIVE_PASSWORD=superprivate\n")
            os.chmod(root / ".env", 0o644)
            def rejected(args, **kwargs):
                return SimpleNamespace(returncode=1, stdout="credential=secret-key",
                                       stderr="cannot connect with superprivate")
            result = mod.probe(root, ".env", check_running=True, runner=rejected)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["checks"]["hcpRuntime"], "runtime_unavailable")
            body = json.dumps(result)
            self.assertNotIn("superprivate", body)
            self.assertNotIn("secret-key", body)

    def test_untrusted_docker_runtime_states_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            for text in ('', '{}', '{"Service":"hcp","State":"running","Health":"starting"}',
                         '{"Service":"hcp","State":"running","Health":"healthy"}\n'
                         '{"Service":"hcp","State":"running","Health":"healthy"}',
                         '{"Secret":"my-pass","Service":"hcp","State":"running","Health":"unhealthy"}'):
                with self.subTest(input=text):
                    outcome = mod.parse_hcp_runtime(text)
                    self.assertNotEqual(outcome, "healthy")

    def test_private_files_and_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            os.chmod(root / "secrets", 0o755)
            result = mod.probe(root, ".env", with_docker=False)
            self.assertIn("private_directory_missing_or_unsafe",
                          {x["code"] for x in result["blockers"]})
            os.chmod(root / "secrets", 0o700)
            (root / "secrets" / "known_hosts").unlink()
            (root / "secrets" / "known_hosts").symlink_to(root / "Dockerfile")
            result = mod.probe(root, ".env", with_docker=False)
            self.assertIn("known_hosts_missing_or_unsafe",
                          {x["code"] for x in result["blockers"]})


if __name__ == "__main__":
    unittest.main()
