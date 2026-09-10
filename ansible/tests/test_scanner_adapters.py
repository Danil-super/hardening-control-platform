"""Behavioral adapter regressions using synthetic data, without network scans.

Formats follow upstream ssh-audit build_struct, Nmap XML, Lynis report.dat,
XCCDF rule-result and Greenbone GMP report/results contracts.
"""

import argparse
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "hcp-controller-scan.py"
spec = importlib.util.spec_from_file_location("scanner", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def arguments(**values):
    return argparse.Namespace(**{
        "inventory_host": "lab-host", "host": "192.0.2.10", "expected_host": [],
        "port": 22, "run_id": "test-run", "input": "", "exit_code": 0,
        "profile": "test-profile", "datastream": "/content/ssg.xml", "policy_group": "lab",
        "datastream_mtime": "123", "datastream_checksum": "sha256:test", **values,
    })


def ssh_payload():
    return {
        "banner": {"raw": "SSH-2.0-OpenSSH_test", "protocol": "2.0"},
        "target": "192.0.2.10", "recommendations": {},
        **{kind: [{"algorithm": "safe-example", "notes": {}}] for kind in ("kex", "key", "enc", "mac")},
    }


def nmap_xml(ports='<extraports state="closed" count="100"/>', finished='exit="success"'):
    return f'<nmaprun scanner="nmap"><host><status state="up"/><ports>{ports}</ports></host><runstats><finished {finished}/></runstats></nmaprun>'


def greenbone_result(host="192.0.2.10", identifier="one", severity="7.5", qod="80"):
    return f'''<result id="{identifier}"><host>{host}</host><port>443/tcp</port>
      <name>Test vulnerability</name><nvt oid="{identifier}"><refs><ref type="cve" id="CVE-2026-0001"/></refs>
      <solution>Apply vendor update</solution></nvt><severity>{severity}</severity><threat>High</threat>
      <qod><value>{qod}</value></qod><description>Test evidence</description></result>'''


class ScannerAdaptersTest(unittest.TestCase):
    def parse_file(self, content, parser, **options):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_text(content, encoding="utf-8")
            return parser(arguments(input=str(input_path), **options))

    def invoke_network(self, parser, payload, code=0):
        with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", return_value=(code, payload, "")):
            return parser(arguments())

    def assert_no_pass(self, report):
        self.assertFalse(any(item["status"] == "passed" for item in report["findings"]))

    def test_ssh_empty_or_error_json_is_not_success(self):
        for payload in ({}, [], {"error": "connection refused"}, {"banner": {"raw": "SSH-test"}}):
            with self.subTest(payload=payload):
                report = self.invoke_network(scanner.ssh_audit, json.dumps(payload))
                self.assertTrue(report["scanner"]["partial"])
                self.assert_no_pass(report)

    def test_ssh_complete_clean_handshake_can_pass(self):
        report = self.invoke_network(scanner.ssh_audit, json.dumps(ssh_payload()))
        self.assertFalse(report["scanner"]["partial"])
        self.assertEqual(report["findings"][0]["status"], "passed")

    def test_ssh_change_recommendations_are_not_dropped(self):
        payload = ssh_payload()
        payload["recommendations"] = {"critical": {"chg": {"key": [{"name": "ssh-rsa", "notes": "increase modulus"}]}}}
        report = self.invoke_network(scanner.ssh_audit, json.dumps(payload), code=3)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertFalse(report["scanner"]["partial"])
        self.assertIn("increase modulus", report["findings"][0]["evidence"])

    def test_ssh_unknown_algorithm_notes_are_not_dropped(self):
        payload = ssh_payload()
        payload["kex"] = [{"algorithm": "unknown", "notes": {"fail": ["unknown algorithm"]}}]
        report = self.invoke_network(scanner.ssh_audit, json.dumps(payload), code=3)
        self.assertEqual(report["summary"]["high"], 1)
        self.assert_no_pass(report)

    def test_ssh_same_algorithm_not_counted_twice(self):
        payload = ssh_payload()
        payload["kex"] = [{"algorithm": "weak", "notes": {"fail": ["weak algorithm"]}}]
        payload["recommendations"] = {"critical": {"del": {"kex": [{"name": "weak", "notes": "weak algorithm"}]}}}
        report = self.invoke_network(scanner.ssh_audit, json.dumps(payload), code=3)
        self.assertEqual(report["summary"]["high"], 1)

    def test_ssh_execution_error_keeps_scan_partial(self):
        report = self.invoke_network(scanner.ssh_audit, json.dumps(ssh_payload()), code=1)
        self.assertTrue(report["scanner"]["partial"])
        self.assert_no_pass(report)

    def test_nmap_valid_xml_with_error_exit_never_passes(self):
        report = self.invoke_network(scanner.nmap, nmap_xml(), code=1)
        self.assertTrue(report["scanner"]["partial"])
        self.assert_no_pass(report)

    def test_nmap_missing_finished_or_ports_never_passes(self):
        for payload in ('<nmaprun><host><status state="up"/></host></nmaprun>', '<html/>'):
            report = self.invoke_network(scanner.nmap, payload)
            self.assertTrue(report["scanner"]["partial"])
            self.assert_no_pass(report)

    def test_nmap_open_port_is_not_automatically_a_vulnerability(self):
        report = self.invoke_network(scanner.nmap, nmap_xml('<port portid="5432" protocol="tcp"><state state="open"/><service name="postgresql" method="probed" conf="10"/></port>'))
        self.assertEqual(report["findings"][0]["status"], "manual")
        self.assertEqual(report["summary"]["medium"], 0)
        self.assertIn("confidence=10", report["findings"][0]["evidence"])

    def test_nmap_successful_closed_top_ports_has_limited_pass(self):
        report = self.invoke_network(scanner.nmap, nmap_xml())
        self.assertFalse(report["scanner"]["partial"])
        self.assertEqual(report["findings"][0]["status"], "passed")

    def test_lynis_arbitrary_text_is_not_success(self):
        report = self.parse_file("not a lynis report", scanner.lynis_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assert_no_pass(report)

    def test_lynis_unfinished_index_is_not_presented_as_valid_score(self):
        report = self.parse_file("lynis_version=3.1.6\nhardening_index=99\n", scanner.lynis_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assertIsNone(report["summary"]["score"])

    def test_lynis_preserves_all_warnings(self):
        content = "lynis_version=3.1.6\nhardening_index=64\nfinish=true\n" + "\n".join(f"warning[]=TEST-{i}|Evidence {i}|" for i in range(100))
        report = self.parse_file(content, scanner.lynis_report)
        self.assertEqual(report["summary"]["medium"], 100)
        self.assertEqual(report["summary"]["score"], 64)
        self.assertFalse(report["scanner"]["partial"])

    def test_openscap_uses_rule_result_severity_and_preserves_over_800(self):
        xml = '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">' + ''.join(f'<rule-result idref="rule-{i}" severity="high"><result>fail</result></rule-result>' for i in range(850)) + '</TestResult>'
        report = self.parse_file(xml, scanner.openscap_arf, exit_code=2)
        self.assertEqual(report["summary"]["high"], 850)
        self.assertFalse(report["scanner"]["partial"])

    def test_openscap_error_exit_keeps_existing_results_but_marks_partial(self):
        report = self.parse_file('<TestResult><rule-result idref="rule"><result>pass</result></rule-result></TestResult>', scanner.openscap_arf, exit_code=1)
        self.assertTrue(report["scanner"]["partial"])
        self.assertTrue(any(item["id"] == "openscap_incomplete" for item in report["findings"]))

    def test_openscap_rule_errors_are_partial(self):
        report = self.parse_file('<TestResult><rule-result idref="rule"><result>error</result></rule-result></TestResult>', scanner.openscap_arf)
        self.assertTrue(report["scanner"]["partial"])

    def test_greenbone_only_selected_host_and_rich_evidence(self):
        content = '<report><scan_run_status>Done</scan_run_status><results>' + greenbone_result() + greenbone_result(host="192.0.2.20", identifier="foreign") + '</results></report>'
        report = self.parse_file(content, scanner.greenbone_report)
        self.assertEqual(report["scanner"]["excludedOtherHostResults"], 1)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertIn("CVE-2026-0001", report["findings"][0]["evidence"])
        self.assertEqual(report["findings"][0]["recommendation"], "Apply vendor update")

    def test_greenbone_foreign_host_or_unrecognized_document_is_rejected(self):
        for content in ('<html/>', '<report><results>' + greenbone_result(host="192.0.2.20") + '</results></report>', '<broken'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.parse_file(content, scanner.greenbone_report)

    def test_greenbone_preserves_over_1000_results(self):
        content = '<report><scan_run_status>Done</scan_run_status><results>' + ''.join(greenbone_result(identifier=str(i)) for i in range(1001)) + '</results></report>'
        report = self.parse_file(content, scanner.greenbone_report)
        self.assertEqual(report["summary"]["high"], 1001)

    def test_greenbone_running_and_filtered_exports_are_partial(self):
        for metadata in ('<scan_run_status>Running</scan_run_status>', '<scan_run_status>Done</scan_run_status><result_count><full>20</full></result_count>'):
            report = self.parse_file('<report>' + metadata + '<results>' + greenbone_result() + '</results></report>', scanner.greenbone_report)
            self.assertTrue(report["scanner"]["partial"])

    def test_greenbone_unknown_or_nonfinite_severity_is_not_clean(self):
        for severity in ("NaN", "", "Infinity"):
            report = self.parse_file('<report><scan_run_status>Done</scan_run_status><results>' + greenbone_result(severity=severity) + '</results></report>', scanner.greenbone_report)
            self.assertTrue(report["scanner"]["partial"])
            self.assertEqual(report["findings"][0]["status"], "manual")

    def test_greenbone_low_qod_requires_verification(self):
        report = self.parse_file('<report><scan_run_status>Done</scan_run_status><results>' + greenbone_result(qod="30") + '</results></report>', scanner.greenbone_report)
        self.assertEqual(report["findings"][0]["status"], "manual")
        self.assertEqual(report["summary"]["high"], 0)

    def test_greenbone_cli_rejects_malformed_xml_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.xml"
            output = Path(directory) / "report.json"
            source.write_text("<broken", encoding="utf-8")
            result = subprocess.run(["python3", str(SCRIPT), "greenbone-report", "--host", "192.0.2.10", "--inventory-host", "lab-host", "--input", str(source), "--output", str(output), "--run-id", "test-run"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
