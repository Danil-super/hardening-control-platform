"""Run the shipped package collector against controlled dpkg status records."""

import ast
import contextlib
import io
import json
import subprocess
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


PLAYBOOK = Path(__file__).resolve().parents[1] / "playbooks" / "package-inventory.yml"
SOURCE = textwrap.dedent(PLAYBOOK.read_text().split("python3 - <<'PY'\n", 1)[1].split("        PY\n", 1)[0])


class PackageInventoryTest(unittest.TestCase):
    def collect(self, records):
        def execute(command, **kwargs):
            self.assertEqual(command[:2], ["dpkg-query", "-W"])
            return subprocess.CompletedProcess(command, 0, records.encode(), b"")

        def read_host(path, **kwargs):
            if path == "/etc/os-release":
                return io.StringIO('ID=debian\nVERSION_ID="12"\n')
            if path == "/etc/astra_version":
                raise FileNotFoundError(path)
            raise AssertionError("Unexpected host file: " + path)

        output = io.StringIO()
        with patch("subprocess.run", side_effect=execute), patch("builtins.open", side_effect=read_host), \
                patch("shutil.which", side_effect=lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None), \
                contextlib.redirect_stdout(output):
            exec(compile(SOURCE, str(PLAYBOOK), "exec"), {})
        return json.loads(output.getvalue())

    @staticmethod
    def record(status, name="package", maintainer="Debian Team <team@debian.org>", origin=""):
        return status + "\t" + name + "\t1.0-1\tamd64\tsource-package\t1.0-1\t" + maintainer + "\t" + origin + "\n"

    def test_complete_inventory_keeps_held_and_removal_requested_code(self):
        report = self.collect(self.record("ii ", "installed") + self.record("hi ", "held")
                              + self.record("ri ", "removal-requested") + self.record("rc ", "removed")
                              + self.record("pn ", "not-installed"))
        self.assertEqual([p["name"] for p in report["packages"]], ["installed", "held", "removal-requested"])
        self.assertEqual([p["dpkgStatus"] for p in report["packages"]], ["ii ", "hi ", "ri "])
        self.assertFalse(report["partial"])
        self.assertFalse(report["packageInventory"]["partial"])
        self.assertEqual(report["packageInventory"]["partialReasons"], [])
        self.assertEqual(report["packageInventory"]["error"], "")

    def test_interrupted_install_and_pending_triggers_keep_versions_and_uncertainty(self):
        for status in ("iH ", "iU ", "iF ", "iW ", "it ", "iiR"):
            with self.subTest(status=status):
                report = self.collect(self.record(status))
                self.assertEqual(report["packageInventory"]["packageCount"], 1)
                self.assertEqual(report["packages"][0]["dpkgStatus"], status)
                self.assertEqual(report["packages"][0]["sourceVersion"], "1.0-1")
                self.assertTrue(report["partial"])
                self.assertTrue(report["packageInventory"]["partial"])
                self.assertTrue(report["packageInventory"]["partialReasons"])
                # Usable versions can still be checked; a partial inventory is
                # different from an unreadable package record.
                self.assertEqual(report["packageInventory"]["error"], "")

    def test_unknown_or_malformed_status_does_not_silently_shrink_inventory(self):
        for status in ("i? ", "ii", "iiX", "?i "):
            with self.subTest(status=status):
                report = self.collect(self.record("ii ", "known") + self.record(status, "unknown"))
                self.assertTrue(report["partial"])
                self.assertIn("status", report["packageInventory"]["error"])

    def test_installed_origin_observations_survive_empty_optional_origin(self):
        report = self.collect(self.record("ii ", "vendor", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", "Ubuntu")
                              + self.record("ii ", "external", "NodeSource <support@nodesource.com>"))
        self.assertFalse(report["partial"])
        self.assertEqual(report["packages"][0]["origin"], "Ubuntu")
        self.assertEqual(report["packages"][1]["origin"], "")
        self.assertEqual(report["packages"][1]["maintainer"], "NodeSource <support@nodesource.com>")

    def test_missing_maintainer_remains_unknown_instead_of_inventing_vendor(self):
        report = self.collect(self.record("ii ", maintainer=""))
        self.assertEqual(report["packages"][0]["maintainer"], "")
        self.assertEqual(report["packages"][0]["origin"], "")

    def test_target_program_keeps_python35_syntax(self):
        ast.parse(SOURCE, feature_version=(3, 5))


if __name__ == "__main__":
    unittest.main()
