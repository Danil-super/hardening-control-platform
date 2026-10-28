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
        "datastream_mtime": "123", "datastream_checksum": "sha256:" + "a" * 64, "content_id": "", **values,
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


def greenbone_error(host="192.0.2.10", description="Authentication failed"):
    return f'''<error><host>{host}</host><port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Local checks</name></nvt>
      <description>{description}</description><severity>-3.0</severity></error>'''


def greenbone_with_errors(errors, count="1", results=None):
    count_xml = "" if count is None else f"<count>{count}</count>"
    return '<report><scan_run_status>Done</scan_run_status><scan_end>2025-01-01T01:00:00Z</scan_end><results>' + (greenbone_result() if results is None else results) + '</results><errors>' + count_xml + errors + '</errors></report>'


class ScannerAdaptersTest(unittest.TestCase):
    def parse_file(self, content, parser, **options):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            input_path.write_text(content, encoding="utf-8")
            return parser(arguments(input=str(input_path), **options))

    def invoke_network(self, parser, payload, code=0):
        def response(command, timeout):
            if command[-1] == "--help":
                return 0, "ssh-audit v3.3.0\n  --skip-rate-test", ""
            return code, payload, ""
        with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", side_effect=response):
            return parser(arguments())

    def test_ssh_25_distro_cli_is_rejected_before_any_target_connection(self):
        with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", return_value=(
            0, "# ssh-audit v2.5.0, https://github.com/jtesta/ssh-audit\n --json --batch --no-colors --verbose", ""
        )) as execute:
            report = scanner.ssh_audit(arguments())
        self.assertTrue(report["scanner"]["partial"])
        self.assertFalse(report["scanner"]["available"])
        self.assertEqual(report["scanner"]["version"], "2.5.0")
        self.assertIn("ssh-audit >=3.2.0", report["findings"][0]["evidence"])
        self.assertEqual(execute.call_count, 1)

    def test_ssh_current_cli_always_disables_connection_rate_test(self):
        with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", side_effect=[
            (0, "ssh-audit v3.3.0\n --skip-rate-test", ""), (0, json.dumps(ssh_payload()), "")
        ]) as execute:
            report = scanner.ssh_audit(arguments())
        self.assertIn("--skip-rate-test", execute.call_args_list[1].args[0])
        self.assertEqual(report["scanner"]["connectionRateTest"], "disabled")

    def test_unknown_or_new_cli_without_skip_flag_is_not_run_against_target(self):
        for help_output in ("usage: unknown scanner", "ssh-audit v3.3.0\n --json"):
            with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", return_value=(0, help_output, "")) as execute:
                report = scanner.ssh_audit(arguments())
            self.assertTrue(report["scanner"]["partial"])
            self.assertEqual(execute.call_count, 1)

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
        self.assertTrue(report["scanner"]["available"])
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
        self.assertEqual(report["scanner"]["scanScope"], "top_100")
        self.assertFalse(report["scanner"]["coverageComplete"])

    def test_nmap_full_tcp_uses_entire_range_and_records_coverage(self):
        with patch.object(scanner.shutil, "which", return_value="/test/tool"), patch.object(scanner, "run", return_value=(0, nmap_xml(), "")) as execute:
            report = scanner.nmap(arguments(scan_scope="full_tcp"))
        command = execute.call_args.args[0]
        self.assertIn("-p-", command)
        self.assertNotIn("--top-ports", command)
        self.assertEqual(report["scanner"]["scanScope"], "full_tcp")
        self.assertTrue(report["scanner"]["coverageComplete"])
        self.assertIn("1–65535", report["findings"][0]["title"])

    def test_lynis_arbitrary_text_is_not_success(self):
        report = self.parse_file("not a lynis report", scanner.lynis_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assert_no_pass(report)

    def test_lynis_unfinished_index_is_not_presented_as_valid_score(self):
        report = self.parse_file("lynis_version=3.1.6\nhardening_index=99\n", scanner.lynis_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assertFalse(report["scanner"]["available"])
        self.assertIsNone(report["summary"]["score"])

    def test_lynis_startup_diagnostics_are_bounded_and_exclude_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostics = Path(directory) / "diagnostics.json"
            diagnostics.write_text(json.dumps({
                "stdout": "Regular audit output\n" + "\n".join("Error loading test " + str(i) for i in range(20)),
                "stderr": "Unknown option: --unsupported-test\nError password=do-not-publish\nError token=do-not-publish",
            }))
            report = self.parse_file("", scanner.lynis_report, exit_code=1, diagnostics_input=str(diagnostics))
        metadata = report["scanner"]["executionDiagnostics"]
        self.assertFalse(report["scanner"]["available"])
        self.assertIn("Unknown option: --unsupported-test", metadata["startupErrors"])
        self.assertLessEqual(len(metadata["startupErrors"]), 8)
        self.assertNotIn("do-not-publish", json.dumps(report))
        self.assertNotIn("Regular audit output", json.dumps(report))
        self.assertFalse(metadata["fullOutputStored"])

    def test_lynis_invalid_diagnostics_do_not_hide_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostics = Path(directory) / "diagnostics.json"
            diagnostics.write_text("<invalid")
            report = self.parse_file("", scanner.lynis_report, exit_code=1, diagnostics_input=str(diagnostics))
        self.assertFalse(report["scanner"]["available"])
        self.assertFalse(report["scanner"]["executionDiagnostics"]["readable"])

    def test_lynis_preserves_all_warnings(self):
        content = "lynis_version=3.1.6\nhardening_index=64\nfinish=true\n" + "\n".join(f"warning[]=TEST-{i}|Evidence {i}|" for i in range(100))
        report = self.parse_file(content, scanner.lynis_report)
        self.assertEqual(len(report["findings"]), 100)
        self.assertEqual(report["summary"]["medium"], 0)
        self.assertTrue(all(item["severityUnknown"] for item in report["findings"]))
        self.assertEqual(report["summary"]["score"], 64)
        self.assertFalse(report["scanner"]["partial"])
        self.assertTrue(report["scanner"]["available"])

    def test_lynis_keeps_source_fields_and_does_not_invent_severity(self):
        content = "lynis_version=3.0.8\nfinish=true\nwarning[]=NAME-4210|Found BIND version in banner|localhost|text:Mask version|\n"
        result = self.parse_file(content, scanner.lynis_report)["findings"][0]
        self.assertTrue(result["severityUnknown"])
        self.assertEqual(result["status"], "manual")
        self.assertEqual(result["lynis"]["message"], "Found BIND version in banner")
        self.assertEqual(result["lynis"]["details"], "localhost")
        self.assertEqual(result["lynis"]["solution"], "text:Mask version")

    def test_lynis_repeated_rule_retains_distinct_parameter_identities(self):
        content = "lynis_version=3.0.8\nfinish=true\nsuggestion[]=SSH-7408|Consider hardening SSH configuration|AllowTcpForwarding (set YES to NO)|-|\nsuggestion[]=SSH-7408|Consider hardening SSH configuration|Port (set 22 to )|-|\n"
        results = self.parse_file(content, scanner.lynis_report)["findings"]
        self.assertEqual(len(set(item["id"] for item in results)), 2)
        self.assertEqual(results[1]["lynis"]["details"], "Port (set 22 to )")

    def test_openscap_uses_rule_result_severity_and_preserves_over_800(self):
        xml = '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">' + ''.join(f'<rule-result idref="rule-{i}" severity="high"><result>fail</result></rule-result>' for i in range(850)) + '</TestResult>'
        report = self.parse_file(xml, scanner.openscap_arf, exit_code=2)
        self.assertEqual(report["summary"]["high"], 850)
        self.assertFalse(report["scanner"]["partial"])

    def test_openscap_error_exit_keeps_existing_results_but_marks_partial(self):
        report = self.parse_file('<TestResult><rule-result idref="rule"><result>pass</result></rule-result></TestResult>', scanner.openscap_arf, exit_code=1)
        self.assertTrue(report["scanner"]["partial"])
        self.assertTrue(any(item["id"] == "openscap_incomplete" for item in report["findings"]))

    def test_openscap_sce_observation_is_preserved_and_all_na_is_partial(self):
        xml = '''<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><rule-result idref="rule"><result>fail</result>
          <check><check-import import-name="stdout">{"mode":"0o666","ownerUid":0}</check-import></check>
          </rule-result></TestResult>'''
        report = self.parse_file(xml, scanner.openscap_arf, exit_code=2)
        self.assertIn('{"mode":"0o666","ownerUid":0}', report['findings'][0]['evidence'])
        self.assertFalse(report['scanner']['partial'])
        report = self.parse_file(xml.replace('<result>fail</result>', '<result>notapplicable</result>'), scanner.openscap_arf)
        self.assertTrue(report['scanner']['partial'])
        self.assertEqual(report['scanner']['ruleResultCounts'], {'notapplicable': 1})
        self.assertIn("неприменим", report['scanner']['partialReasons'][0])

    def test_openscap_rule_errors_are_partial(self):
        report = self.parse_file('<TestResult><rule-result idref="rule"><result>error</result></rule-result></TestResult>', scanner.openscap_arf)
        self.assertTrue(report["scanner"]["partial"])

    def test_openscap_preserves_actual_profile_and_content_identity(self):
        xml = '<TestResult><profile idref="test-profile"/><rule-result idref="rule"><result>pass</result></rule-result></TestResult>'
        report = self.parse_file(xml, scanner.openscap_arf, content_id="bundle-sha256:" + "b" * 64)
        self.assertEqual(report["profileId"], "test-profile")
        self.assertEqual(report["scanner"]["contentIdentity"], "bundle-sha256:" + "b" * 64)
        self.assertEqual(report["scanner"]["datastreamChecksum"], "sha256:" + "a" * 64)
        self.assertFalse(report["scanner"]["partial"])
        mismatched = self.parse_file(xml, scanner.openscap_arf, profile="another-profile")
        self.assertEqual(mismatched["profileId"], "test-profile")
        self.assertEqual(mismatched["scanner"]["requestedProfile"], "another-profile")
        self.assertTrue(mismatched["scanner"]["partial"])
        short_name = self.parse_file(xml.replace('idref="test-profile"', 'idref="xccdf_example_profile_standard"'), scanner.openscap_arf, profile="standard")
        self.assertEqual(short_name["profileId"], "xccdf_example_profile_standard")
        self.assertFalse(short_name["scanner"]["partial"])

    def test_openscap_missing_configuration_explains_setup_without_claiming_a_scan(self):
        reason = "Не задан профиль OpenSCAP для группы хоста."
        report = scanner.openscap_unavailable(arguments(reason=reason, profile=None, datastream=None))
        self.assertFalse(report["scanner"]["available"])
        self.assertEqual(report["scanner"]["partialReasons"], [reason])
        self.assertIn("Astra", report["findings"][0]["recommendation"])
        self.assertIn("OpenSCAP и исключения", report["findings"][0]["recommendation"])
        self.assert_no_pass(report)

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

    def test_greenbone_anonymous_export_explains_format_even_when_host_matches(self):
        inner = '<report><scan_run_status>Done</scan_run_status><results>' + greenbone_result(host="127.0.0.1") + '</results></report>'
        for metadata in (
            '<report_format><name>Anonymous XML</name></report_format>',
            '<report_format id="5057e5cc-b825-11e4-9d0e-28d24461215b"><name>Renamed format</name></report_format>',
        ):
            for selected_host in ("192.0.2.10", "127.0.0.1"):
                with self.subTest(metadata=metadata, host=selected_host), self.assertRaisesRegex(ValueError, "Anonymous XML.*обезличенный"):
                    self.parse_file('<report>' + metadata + inner + '</report>', scanner.greenbone_report, host=selected_host)
        with self.assertRaisesRegex(ValueError, "Anonymous XML"):
            self.parse_file('<report format_id="5057e5cc-b825-11e4-9d0e-28d24461215b">' + inner + '</report>', scanner.greenbone_report)

    def test_greenbone_standard_xml_wrapper_keeps_original_host(self):
        content = '<report><report_format><name>XML</name></report_format><report><scan_run_status>Done</scan_run_status><scan_end>2025-01-01T01:00:00Z</scan_end><results>' + greenbone_result() + '</results></report></report>'
        report = self.parse_file(content, scanner.greenbone_report)
        self.assertEqual(report["scanner"]["matchedResults"], 1)
        self.assertFalse(report["scanner"]["partial"])

    def test_greenbone_observation_is_scan_end_not_import_time(self):
        xml = '<report><scan_run_status>Done</scan_run_status><scan_start>2020-01-01T00:00:00Z</scan_start><scan_end>2020-01-01T04:00:00+03:00</scan_end><results>' + greenbone_result() + '</results></report>'
        with patch.object(scanner, "now", return_value="2026-10-28T12:00:00+00:00"):
            report = self.parse_file(xml, scanner.greenbone_report)
        self.assertEqual(report["createdAt"], "2020-01-01T01:00:00+00:00")
        self.assertEqual(report["observedAt"], report["createdAt"])
        self.assertEqual(report["importedAt"], "2026-10-28T12:00:00+00:00")
        self.assertFalse(report["scanner"]["partial"])

    def test_greenbone_invalid_missing_or_future_times_are_unknown_and_partial(self):
        for start, end in [("", ""), ("", "not-a-date"), ("", "2025-02-30T00:00:00Z"),
                           ("", "2025-01-01T00:00:00"), ("", "2099-01-01T00:00:00Z"),
                           ("2025-02-01T00:00:00Z", "2025-01-01T00:00:00Z"),
                           ("invalid", "2025-01-01T00:00:00Z")]:
            with self.subTest(start=start, end=end):
                report = self.parse_file('<report><scan_run_status>Done</scan_run_status><scan_start>' + start + '</scan_start><scan_end>' + end + '</scan_end><results>' + greenbone_result() + '</results></report>', scanner.greenbone_report)
                self.assertIsNone(report["observedAt"])
                self.assertIsNone(report["createdAt"])
                self.assertTrue(report["scanner"]["partial"])
                self.assertFalse(report["scanner"]["observationTimeValid"])
                self.assertTrue(report["scanner"]["partialReasons"])

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

    def test_greenbone_done_with_target_errors_preserves_error_and_is_partial(self):
        report = self.parse_file(greenbone_with_errors(greenbone_error()), scanner.greenbone_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assertEqual(report["scanner"]["matchedErrors"], 1)
        self.assertTrue(report["scanner"]["partialReasons"])
        errors = [f for f in report["findings"] if f["id"].startswith("greenbone_error_")]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["status"], "manual")
        self.assertEqual(errors[0]["description"], "Authentication failed")
        self.assertEqual(report["summary"]["high"], 1)

    def test_greenbone_error_can_identify_target_without_successful_results(self):
        report = self.parse_file(greenbone_with_errors(greenbone_error(), results=""), scanner.greenbone_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assertEqual(report["scanner"]["matchedResults"], 0)
        self.assertEqual(report["scanner"]["matchedErrors"], 1)
        self.assert_no_pass(report)

    def test_greenbone_foreign_errors_do_not_disclose_details_or_make_target_partial(self):
        content = greenbone_with_errors(greenbone_error(host="192.0.2.20", description="private-other-host-error"))
        report = self.parse_file(content, scanner.greenbone_report)
        self.assertFalse(report["scanner"]["partial"])
        self.assertEqual(report["scanner"]["excludedOtherHostErrors"], 1)
        self.assertNotIn("192.0.2.20", json.dumps(report))
        self.assertNotIn("private-other-host-error", json.dumps(report))

    def test_greenbone_unscoped_errors_are_partial_without_exposing_unbound_details(self):
        report = self.parse_file(greenbone_with_errors(greenbone_error(host="", description="private-unbound-error")), scanner.greenbone_report)
        self.assertTrue(report["scanner"]["partial"])
        self.assertEqual(report["scanner"]["unscopedErrors"], 1)
        self.assertNotIn("private-unbound-error", json.dumps(report))

    def test_greenbone_count_only_truncated_and_inconsistent_errors_remain_partial(self):
        foreign = greenbone_error(host="192.0.2.20", description="private-other-host-error")
        for count, errors in (("1", ""), ("2", foreign), ("0", foreign), (None, ""), ("-1", ""), ("invalid", "")):
            with self.subTest(count=count, errors=bool(errors)):
                report = self.parse_file(greenbone_with_errors(errors, count), scanner.greenbone_report)
                self.assertTrue(report["scanner"]["partial"])
                self.assertTrue(report["scanner"]["partialReasons"])
                self.assertNotIn("private-other-host-error", json.dumps(report))

    def test_greenbone_explicit_zero_errors_can_be_complete(self):
        report = self.parse_file(greenbone_with_errors("", "0"), scanner.greenbone_report)
        self.assertFalse(report["scanner"]["partial"])
        self.assertEqual(report["scanner"]["errorCount"], 0)

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
