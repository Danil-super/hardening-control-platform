#!/usr/bin/env python3
"""Run actual target code under the selected interpreter, with isolated host data.

Compatible with Python 3.5 itself. This verifies Python APIs, not Astra services.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    path = ROOT / "ansible/scripts" / name
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TargetPythonTests(unittest.TestCase):
    def test_oval_adapter_real_files_subprocess_and_incomplete_report(self):
        module = load_script("hcp-oval-audit.py")
        config = module.parse_config({"mode": "local", "releasePattern": "*"})
        module.check_scope({"id": "astra", "astraVersion": "1.6.7.15", "architecture": "x86_64"}, config)
        module.check_scope({"id": "astra", "astraVersion": "12.4-custom", "architecture": "aarch64"}, config)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "source.xml")
            module.write_bytes(path, b"<root/>")
            self.assertEqual(module.read_regular(path, 1024), b"<root/>")
            self.assertEqual(module.safe_xml(b"<root/>").tag, "root")
            code, stdout = module.run_oscap([sys.executable, "-c", "print('actual child')"], directory, 10, capture_stdout=True)
            self.assertEqual(code, 0)
            self.assertEqual(stdout.strip(), "actual child")
        args = argparse.Namespace(inventory_host="legacy-target", run_id="test")
        report = module.finish(module.empty_report(args, "No database"))
        self.assertTrue(report["scanner"]["partial"])
        self.assertIsNone(report["scanner"]["uniqueCveCount"])

    def test_oval_evidence_hashes_actual_files_and_handles_missing_package(self):
        module = load_script("hcp-host-readiness.py")
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "vendor.xml"
            candidate.write_bytes(b"<oval_definitions/>")
            result, consumed = module.fingerprint_candidate(str(candidate), 1024)
            self.assertEqual(result["sha256"], hashlib.sha256(b"<oval_definitions/>").hexdigest())
            self.assertEqual(consumed, len(b"<oval_definitions/>"))
        with patch.object(module.shutil, "which", return_value="/usr/bin/dpkg-query"), \
                patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"dpkg-query: no packages found matching oval-db")):
            report = module.collect_oval_metadata()
        self.assertEqual(report["status"], "not_installed")
        self.assertEqual(report["vulnerabilityAssessment"], "not_run")

    def test_readiness_decodes_real_child_output_without_locale_dependency(self):
        module = load_script("hcp-host-readiness.py")
        errors = []
        result = module.run_query([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xd0\\x90\\xff')"], errors, "test")
        self.assertEqual(result.stdout, "А\ufffd")
        self.assertEqual(errors, [])

    def test_firewall_real_subprocess_and_match_apis(self):
        module = load_script("hcp-firewall.py")
        self.assertEqual(module.run(sys.executable, "-c", "print('ok')").stdout.strip(), "ok")
        self.assertEqual(module.ufw_numbered_rules("[ 1] 8080/tcp DENY Anywhere")[0]["number"], 1)
        self.assertEqual(module.firewalld_configuration_blocks("public (default, active)\n  target: default"),
                         module.firewalld_configuration_blocks("public (default)\n  target: default"))

    def test_firewall_real_archive_and_exact_filesystem_rollback(self):
        module = load_script("hcp-firewall.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration = root / "etc"
            (configuration / "ufw").mkdir(parents=True)
            (configuration / "machine-id").write_text("owned-compatibility-test")
            rule = configuration / "ufw/user.rules"
            rule.write_text("original\n")
            args = argparse.Namespace(transaction="txn-compatibility-12345678")
            with patch.object(module, "CONFIG_ROOT", configuration), patch.object(module, "BACKUP_ROOT", root / "backups"), \
                    patch.object(module, "backend", return_value="ufw"), patch.object(module, "run"):
                module.backup(args)
                rule.write_text("changed\n")
                (configuration / "ufw/extra.rules").write_text("new\n")
                self.assertTrue(module.rollback(args)["ok"])
                self.assertEqual(rule.read_text(), "original\n")
                self.assertFalse((configuration / "ufw/extra.rules").exists())

    def test_all_embedded_target_programs_execute_with_unavailable_tools(self):
        for name in ("agentless-audit.yml", "package-inventory.yml", "collect-security-events.yml"):
            with self.subTest(playbook=name):
                text = (ROOT / "ansible/playbooks" / name).read_text(encoding="utf-8")
                source = textwrap.dedent(text.split("python3 - <<'PY'\n", 1)[1].split("\n        PY", 1)[0])
                output = io.StringIO()
                namespace = {}
                def unavailable(argv, **kwargs):
                    return subprocess.CompletedProcess(argv, 127, b"", b"not installed")
                with patch("subprocess.run", side_effect=unavailable), patch("shutil.which", return_value=None), \
                        patch.dict(os.environ, {"AUDIT_PROFILE": "basic_linux", "AUDIT_RULES_JSON": "{}"}), contextlib.redirect_stdout(output):
                    exec(compile(source, name, "exec"), namespace)
                report = json.loads(output.getvalue())
                self.assertEqual(report["schemaVersion"], 1)
                if "run" in namespace:
                    code, stdout, stderr = namespace["run"]([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xd0\\x90')"])
                    self.assertEqual((code, stdout, stderr), (0, "А", ""))


if __name__ == "__main__":
    print("Target interpreter: " + sys.version, flush=True)
    unittest.main(verbosity=2)
