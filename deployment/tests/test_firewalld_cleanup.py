"""Deterministic regression for the disposable firewalld veth cleanup race."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("hcp_firewalld_cleanup_acceptance", ROOT / "verify_firewalld.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IFACE = "hfw" + "a" * 10
NETNS = "hcp-firewalld-" + "b" * 12

class FirewalldCleanupRaceTests(unittest.TestCase):
    def fixture(self):
        folder = tempfile.TemporaryDirectory(prefix="hcp-firewalld-cleanup-")
        self.addCleanup(folder.cleanup)
        work = Path(folder.name)
        (work / "artifacts").mkdir()
        (work / "recovery.json").write_text(json.dumps({
            "namespace": NETNS, "interface": IFACE, "cleaned": False,
            "firewallTouched": False, "stoppedServices": [], "transaction": "",
        }))
        return work

    def mock_commands(self, delete_message, after_probe):
        seen = []
        checks = iter([0, after_probe])
        def command(argv, **kwargs):
            seen.append(tuple(argv))
            if argv == ["ip", "netns", "list"]:
                return subprocess.CompletedProcess(argv, 0, stdout=NETNS + "\n", stderr="")
            if argv == ["ip", "netns", "delete", NETNS]:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            if argv == ["ip", "link", "show", "dev", IFACE]:
                status = next(checks)
                return subprocess.CompletedProcess(argv, status, stdout="existing" if status == 0 else "",
                                                   stderr="" if status == 0 else 'Device "' + IFACE + '" does not exist')
            if argv == ["ip", "link", "delete", IFACE]:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr=delete_message)
            raise AssertionError("Unexpected cleanup command: " + repr(argv))
        return seen, command

    def test_peer_deletion_race_is_idempotent_only_when_interface_is_independently_absent(self):
        work = self.fixture()
        seen, command = self.mock_commands('Cannot find device "' + IFACE + '"', after_probe=1)
        with patch.object(MODULE.subprocess, "run", side_effect=command):
            MODULE.cleanup(work)
        self.assertTrue(json.loads((work / "recovery.json").read_text())["cleaned"])
        self.assertTrue(json.loads((work / "artifacts/cleanup.json").read_text())["ok"])
        self.assertEqual(seen.count(("ip", "link", "show", "dev", IFACE)), 2)
        self.assertIn(("ip", "netns", "delete", NETNS), seen)

    def test_unrelated_delete_error_cannot_be_ignored(self):
        for message, after_status in [
            ("RTNETLINK answers: Operation not permitted", 1),
            ('Cannot find device "' + IFACE + '"', 0),
        ]:
            with self.subTest(message=message, after=after_status):
                work = self.fixture()
                unused, command = self.mock_commands(message, after_probe=after_status)
                with patch.object(MODULE.subprocess, "run", side_effect=command):
                    with self.assertRaisesRegex(RuntimeError, "Cleanup ip link delete"):
                        MODULE.cleanup(work)
                self.assertFalse(json.loads((work / "artifacts/cleanup.json").read_text())["ok"])
                self.assertFalse(json.loads((work / "recovery.json").read_text())["cleaned"])

class FirewalldWorkflowBootstrapTests(unittest.TestCase):
    def test_only_builtin_ansible_core_is_installed_and_cleanup_runs_always(self):
        workflow = (ROOT.parents[1] / ".github/workflows/firewalld.yml").read_text()
        self.assertIn("firewalld openssh-server ansible-core iproute2", workflow)
        self.assertNotIn("openssh-server ansible iproute2", workflow)
        self.assertIn("Acquire::http::Timeout=35", workflow)
        self.assertIn("Acquire::https::Timeout=35", workflow)
        self.assertIn("sudo systemctl mask firewalld.service", workflow)
        self.assertIn("sudo systemctl unmask firewalld.service", workflow)
        self.assertIn("name: Restore original services and remove the isolated SSH target", workflow)
        self.assertIn("if: always()", workflow)


if __name__ == "__main__":
    unittest.main()
