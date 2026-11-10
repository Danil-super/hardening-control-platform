"""Native scanner originals: execute CLI fixtures without remote connections."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/scripts/hcp-controller-scan.py"
spec = importlib.util.spec_from_file_location("raw_scanner", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScannerRawEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix=".scanner-original-test-", dir=ROOT)
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)

    def invoke(self, mode, original=None, code=0, preserve=True, help_output="ssh-audit v3.3.0 --skip-rate-test", preserve_environment=False, **options):
        output = self.directory / f"report-{mode}.json"
        environment = {**os.environ, "HCP_PRESERVE_RAW_EVIDENCE": "1" if preserve_environment else "0"}
        command = ["/usr/bin/python3", str(SCRIPT), mode, "--inventory-host", "fixture", "--run-id", "fixture", "--output", str(output)]
        if preserve:
            command.append("--preserve-raw-evidence")
        if mode in ("nmap", "ssh-audit"):
            tool = self.directory / f"fixture-{mode}"
            if original is not None:
                tool.write_text("#!/usr/bin/python3\nimport sys\n"
                                f"if '--help' in sys.argv:\n print({help_output!r})\n sys.exit(0)\n"
                                f"sys.stdout.buffer.write({original!r})\nsys.exit({code})\n", encoding="utf-8")
                tool.chmod(0o700)
            environment["HCP_NMAP_BIN" if mode == "nmap" else "HCP_SSH_AUDIT_BIN"] = str(tool)
            command.extend(["--host", "192.0.2.10"])
        elif mode == "lynis-report":
            source = self.directory / "input.dat"
            if original is not None:
                source.write_bytes(original)
            command.extend(["--input", str(source), "--exit-code", str(code)])
        for key, value in options.items():
            command.extend(["--" + key.replace("_", "-"), str(value)])
        result = subprocess.run(command, env=environment, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return output, json.loads(output.read_bytes())

    def assert_original(self, output, suffix, original):
        sidecar = output.with_name(f".{output.stem}.{suffix}")
        self.assertEqual(sidecar.read_bytes(), original)
        self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)

    def test_nmap_cli_preserves_exact_xml_for_success_and_partial_runs(self):
        original = (b'<?xml version="1.0"?>\r\n<!-- native formatting -->\r\n'
                    b'<nmaprun><host><status state="up"/><ports/></host>'
                    b'<runstats><finished exit="success"/></runstats></nmaprun>\r\n')
        for code in (0, 1):
            with self.subTest(code=code):
                output, report = self.invoke("nmap", original, code=code)
                self.assertEqual(report["scanner"]["partial"], code != 0)
                self.assert_original(output, "nmap.xml", original)
                output.with_name(f".{output.stem}.nmap.xml").unlink()

    def test_ssh_cli_preserves_stdout_not_normalized_json_for_success_and_partial(self):
        payload = {"banner": {"raw": "SSH-2.0-fixture"}, "recommendations": {},
                   **{kind: [{"algorithm": "fixture", "notes": {}}] for kind in ("kex", "key", "enc", "mac")}}
        original = (json.dumps(payload, indent=3) + "\n").replace("\n", "\r\n").encode()
        for code in (0, 1, 3):
            with self.subTest(code=code):
                output, report = self.invoke("ssh-audit", original, code=code)
                self.assertEqual(report["scanner"]["partial"], code != 0)
                self.assert_original(output, "ssh-audit.json", original)
                output.with_name(f".{output.stem}.ssh-audit.json").unlink()

    def test_lynis_cli_preserves_non_utf8_crlf_and_incomplete_reports(self):
        for original, partial in ((b"# native \xff\r\nlynis_version=3.1.2\r\nfinish=true\r\n", False),
                                  (b"# incomplete\r\nlynis_version=3.1.2\r\n", True)):
            with self.subTest(partial=partial):
                output, report = self.invoke("lynis-report", original)
                self.assertEqual(report["scanner"]["partial"], partial)
                self.assert_original(output, "report.dat", original)
                output.with_name(f".{output.stem}.report.dat").unlink()

    def test_no_original_is_fabricated_for_missing_empty_or_unavailable_tools(self):
        for mode, suffix in (("nmap", "nmap.xml"), ("ssh-audit", "ssh-audit.json"), ("lynis-report", "report.dat"), ("lynis-unavailable", "report.dat")):
            for original in (None, b""):
                with self.subTest(mode=mode, original=original):
                    output, report = self.invoke(mode, original)
                    self.assertTrue(report["scanner"]["partial"])
                    self.assertFalse(output.with_name(f".{output.stem}.{suffix}").exists())

    def test_ansible_environment_can_enable_preservation_without_cli_flag(self):
        original = b"lynis_version=3.1.2\r\nfinish=true\r\n"
        output, report = self.invoke("lynis-report", original, preserve=False, preserve_environment=True)
        self.assertFalse(report["scanner"]["partial"])
        self.assert_original(output, "report.dat", original)

    def test_incompatible_ssh_help_is_not_saved_as_an_original(self):
        output, report = self.invoke("ssh-audit", b'{"error":"not executed"}', help_output="ssh-audit v2.5.0")
        self.assertFalse(report["scanner"]["available"])
        self.assertFalse(output.with_name(f".{output.stem}.ssh-audit.json").exists())

    def test_preservation_is_opt_in_and_invalid_output_is_kept_as_partial_original(self):
        for mode, suffix in (("nmap", "nmap.xml"), ("ssh-audit", "ssh-audit.json"), ("lynis-report", "report.dat")):
            for preserve in (False, True):
                output, report = self.invoke(mode, b"partial native bytes\r\n", preserve=preserve)
                self.assertTrue(report["scanner"]["partial"])
                self.assertEqual(output.with_name(f".{output.stem}.{suffix}").exists(), preserve)

    @unittest.skipUnless(shutil.which("nmap"), "optional local Nmap fixture generator unavailable")
    def test_actual_nmap_xml_fixture_without_scanning_any_hosts(self):
        native = subprocess.run(["nmap", "-n", "-sL", "-iL", "/dev/null", "-oX", "-"], capture_output=True, check=False)
        self.assertIn(b"<nmaprun", native.stdout)
        output, report = self.invoke("nmap", native.stdout, code=native.returncode)
        self.assertTrue(report["scanner"]["partial"])
        self.assert_original(output, "nmap.xml", native.stdout)

    def test_timeout_keeps_only_actual_partial_stdout(self):
        args = scanner.argparse.Namespace(output=str(self.directory / "timeout.json"), preserve_raw_evidence=True)
        with patch.object(scanner.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1, output=b"<partial>\r\n")):
            code, stdout, stderr = scanner.run_with_original(args, ["fixture"], 1, "nmap.xml")
        self.assertIsNone(code)
        self.assertEqual(stdout, "<partial>\r\n")
        self.assertIn("1", stderr)
        self.assert_original(Path(args.output), "nmap.xml", b"<partial>\r\n")

    def test_existing_native_sidecar_is_never_overwritten(self):
        args = scanner.argparse.Namespace(output=str(self.directory / "immutable.json"), preserve_raw_evidence=True)
        scanner.preserve_original(args, "nmap.xml", b"first")
        with self.assertRaises(FileExistsError):
            scanner.preserve_original(args, "nmap.xml", b"second")
        self.assert_original(Path(args.output), "nmap.xml", b"first")

    def test_lynis_same_sidecar_input_is_not_rewritten(self):
        original = b"lynis_version=3.1.2\nfinish=true\n"
        output = self.directory / "same.json"
        sidecar = output.with_name(f".{output.stem}.report.dat")
        sidecar.write_bytes(original)
        before = sidecar.stat().st_ino
        scanner.preserve_original(scanner.argparse.Namespace(output=str(output), preserve_raw_evidence=True), "report.dat", original, sidecar)
        self.assertEqual(sidecar.stat().st_ino, before)
        self.assert_original(output, "report.dat", original)


if __name__ == "__main__":
    unittest.main()
