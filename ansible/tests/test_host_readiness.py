"""Readiness behaviour tests: facts are never substituted for audit coverage."""

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "host_readiness", Path(__file__).parents[1] / "scripts/hcp-host-readiness.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def completed(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class HostReadinessTests(unittest.TestCase):
    def test_astra_identity_is_preserved_without_executing_os_release(self):
        errors = []
        result = probe.parse_os_release(
            'ID=astra\nID_LIKE=debian\nPRETTY_NAME="Astra Linux Special Edition"\n'
            'VERSION_ID="1.7_x86-64"\nSECRET_TOKEN="do-not-export"\n'
            'VERSION="$(touch /tmp/should-not-exist)"\n', errors
        )
        self.assertEqual(result["ID"], "astra")
        self.assertEqual(result["ID_LIKE"], "debian")
        self.assertEqual(result["VERSION"], "$(touch /tmp/should-not-exist)")
        self.assertNotIn("SECRET_TOKEN", result)
        self.assertEqual(errors, [])

    def test_unknown_and_malformed_distribution_is_not_assumed_debian(self):
        errors = []
        result = probe.parse_os_release('NAME="broken\nID_LIKE=debian\n', errors)
        self.assertNotIn("ID", result)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("distribution ID" in error for error in errors))

    def test_status_queries_are_noninteractive_locale_stable_and_bounded(self):
        with patch.object(probe.subprocess, "run", return_value=completed()) as run:
            probe.run_query(["/usr/sbin/ufw", "status"], [], "ufw")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/sbin/ufw", "status"])
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(kwargs["env"]["PATH"], probe.SAFE_PATH)
        self.assertLessEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)

    def test_ufw_uses_actual_status_and_does_not_export_rules(self):
        for state in ("active", "inactive"):
            with self.subTest(state=state):
                errors = []
                with patch.object(probe, "run_query", return_value=completed(stdout="Status: " + state + "\n22/tcp ALLOW 192.0.2.1\n")) as run:
                    self.assertEqual(probe.ufw_state("/usr/sbin/ufw", errors), state)
                self.assertEqual(run.call_args[0][0], ["/usr/sbin/ufw", "status"])
                self.assertEqual(errors, [])

    def test_ufw_errors_and_unexpected_output_are_unknown(self):
        for response in (completed(1, "Status: inactive", "permission denied"),
                         completed(0, "some unexpected output")):
            with self.subTest(response=response):
                errors = []
                with patch.object(probe, "run_query", return_value=response):
                    self.assertEqual(probe.ufw_state("/usr/sbin/ufw", errors), "unknown")
                self.assertTrue(errors)

    def test_firewalld_not_running_is_distinct_from_permission_or_dbus_failure(self):
        cases = (
            (completed(0, "running\n"), "active"),
            (completed(252, "not running\n"), "inactive"),
            (completed(252, stderr="not running\n"), "inactive"),
            (completed(1, stderr="DBusException: access denied"), "unknown"),
            (completed(252, stderr="unexpected failure"), "unknown"),
            (completed(0, ""), "unknown"),
        )
        for response, expected in cases:
            with self.subTest(expected=expected, response=response):
                errors = []
                with patch.object(probe, "run_query", return_value=response):
                    self.assertEqual(probe.firewalld_state("/usr/bin/firewall-cmd", errors), expected)
                self.assertEqual(bool(errors), expected == "unknown")

    def test_timeout_and_missing_executable_never_become_inactive(self):
        for exception in (subprocess.TimeoutExpired(["ufw", "status"], 5), OSError("unavailable")):
            with self.subTest(exception=exception):
                errors = []
                with patch.object(probe.subprocess, "run", side_effect=exception):
                    self.assertEqual(probe.ufw_state("/usr/sbin/ufw", errors), "unknown")
                self.assertTrue(errors)
        with patch.object(probe, "run_query") as run:
            self.assertEqual(probe.ufw_state(None, []), "missing")
            self.assertEqual(probe.firewalld_state(None, []), "missing")
            run.assert_not_called()

    def test_netfilter_service_load_state_distinguishes_missing_from_inactive(self):
        cases = (
            (completed(0, "LoadState=not-found\nActiveState=inactive\n"), "missing"),
            (completed(0, "LoadState=loaded\nActiveState=active\n"), "active"),
            (completed(0, "LoadState=loaded\nActiveState=inactive\n"), "inactive"),
            (completed(0, "LoadState=loaded\nActiveState=failed\n"), "unknown"),
            (completed(1, stderr="System has not been booted with systemd"), "unknown"),
        )
        for response, expected in cases:
            with self.subTest(expected=expected):
                with patch.object(probe, "run_query", return_value=response):
                    self.assertEqual(probe.netfilter_persistent_state("/usr/bin/systemctl", []), expected)

    def test_non_systemd_installed_service_is_unknown(self):
        errors = []
        with patch.object(probe.shutil, "which", return_value="/usr/sbin/netfilter-persistent"):
            self.assertEqual(probe.netfilter_persistent_state(None, errors), "unknown")
        self.assertTrue(errors)
        with patch.object(probe.shutil, "which", return_value=None), patch.object(probe.Path, "exists", return_value=False):
            self.assertEqual(probe.netfilter_persistent_state(None, []), "missing")

    def test_complete_report_contains_explicit_insufficient_privilege_error(self):
        files = {
            "/etc/os-release": "ID=astra\nID_LIKE=debian\nVERSION_ID=1.7\n",
            "/etc/astra_version": "1.7.6.15\n",
            "/proc/1/comm": "systemd\n",
        }
        with patch.object(probe, "read_text", side_effect=lambda path, *args, **kwargs: files[path]), \
                patch.object(probe.shutil, "which", return_value=None), \
                patch.object(probe.Path, "exists", return_value=False), \
                patch.object(probe.os, "geteuid", return_value=1000):
            report = probe.collect_readiness()
        self.assertEqual(report["schemaVersion"], 1)
        self.assertEqual(report["astraVersion"], "1.7.6.15")
        self.assertEqual(report["osRelease"]["ID"], "astra")
        self.assertEqual(report["effectiveUid"], 1000)
        self.assertEqual(report["initSystem"], "systemd")
        self.assertEqual(set(report["tools"]), set(probe.TOOL_NAMES))
        self.assertEqual(set(report["firewall"].values()), {"missing"})
        self.assertTrue(report["createdAt"].endswith("Z"))
        self.assertTrue(any("Root privileges" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
