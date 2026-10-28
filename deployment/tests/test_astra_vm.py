"""Reject misleading acceptance evidence before attempting a guest launch."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from verify_astra_vm import download, installed_control_versions, record_failure, verify_baseline_report, verify_oval_report, PROFILE, RULE


class DownloadResponse(io.BytesIO):
    def geturl(self):
        return "https://publisher.invalid/pinned-image"


class AstraVmAcceptanceTests(unittest.TestCase):
    def test_failed_and_cancelled_protocol_records_stop_point_and_bounded_error(self):
        for error in (RuntimeError("fixture error " * 1000), InterruptedError("CI cancellation"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)
                protocol = {"status": "running", "checks": [{"name": "Genuine guest identity"}]}
                record_failure(path, protocol, error)
                saved = json.loads((path / "protocol.json").read_text())
                self.assertEqual(saved["status"], "failed" if isinstance(error, RuntimeError) else "cancelled")
                self.assertEqual(saved["failedAfterCheck"], "Genuine guest identity")
                self.assertLessEqual(len(saved["error"]["message"]), 4000)

    def test_download_requires_exact_pinned_bytes_and_does_not_publish_failure(self):
        content = b"publisher fixture"
        source = {"url": "https://publisher.invalid/pinned-image", "bytes": len(content),
                  "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "image"
            for unexpected in (content + b"x", content[:-1], b"x" * len(content)):
                with self.subTest(unexpected=unexpected), self.assertRaises(ValueError):
                    download(source, target, opener=lambda *_args, **_kwargs: DownloadResponse(unexpected))
                self.assertFalse(target.exists())
                self.assertEqual(list(Path(temporary).iterdir()), [])
            download(source, target, opener=lambda *_args, **_kwargs: DownloadResponse(content))
            self.assertEqual(target.read_bytes(), content)

    def report(self, expected="true"):
        source = {"sha256": "a" * 64, "definitionCount": 2, "definitionId": "oval:example:def:1", "cve": "CVE-2024-5535"}
        report = {"scanner": {"available": True, "evaluationPerformed": True, "exitCode": 0, "hostIdentity": {"id": "astra", "astraVersion": "1.8.1"},
                              "database": {"sha256": source["sha256"], "checksumVerified": True},
                              "definitionCount": 2, "evaluatedDefinitionCount": 2,
                              "definitionResults": [{"id": source["definitionId"], "result": expected, "cveIds": [source["cve"]]},
                                                    {"id": "oval:example:def:2", "result": "unknown", "cveIds": []}],
                              "partial": True, "partialReasons": ["An unrelated definition is unknown"], "resultSha256": "b" * 64},
                  "summary": {"score": None}, "findings": []}
        if expected == "true":
            report["findings"].append({"id": source["definitionId"], "status": "failed", "vulnerability": {"cveIds": [source["cve"]]}})
        return source, report

    def test_positive_and_fixed_controls_preserve_partial(self):
        for expected in ("true", "false"):
            source, report = self.report(expected)
            proof = verify_oval_report(report, source, "1.8.1", expected)
            self.assertTrue(proof["partial"])
            self.assertEqual(proof["result"], expected)

    def test_empty_unknown_or_forged_source_is_not_a_success(self):
        source, original = self.report()
        changes = [lambda r: r["scanner"].update(evaluationPerformed=False),
                   lambda r: r["scanner"].update(available=False),
                   lambda r: r["scanner"].update(exitCode=1),
                   lambda r: r["scanner"].update(exitCode=None),
                   lambda r: r["scanner"].update(evaluatedDefinitionCount=1),
                   lambda r: r["scanner"].update(resultSha256=""),
                   lambda r: r["scanner"].update(definitionResults=[]),
                   lambda r: r["scanner"]["definitionResults"][0].update(result="unknown"),
                   lambda r: r["scanner"]["database"].update(sha256="c" * 64),
                   lambda r: r["scanner"]["database"].update(checksumVerified=False),
                   lambda r: r["scanner"]["hostIdentity"].update(id="ubuntu"),
                   lambda r: r.update(findings=[])]
        for change in changes:
            report = copy.deepcopy(original)
            change(report)
            with self.assertRaises(AssertionError):
                verify_oval_report(report, source, "1.8.1", "true")

    def test_native_error_or_incomplete_result_set_cannot_pass_on_one_surviving_control(self):
        source, report = self.report()
        report["scanner"]["definitionResults"] = report["scanner"]["definitionResults"][:1]
        with self.assertRaises(AssertionError):
            verify_oval_report(report, source, "1.8.1", "true")

    def test_version_control_ignores_removed_packages_and_preserves_holds(self):
        packages = ["openssl", "libssl3", "openssl-provider-legacy"]
        before = "libssl3:amd64\t3.4.0-2-astra6\tii \nopenssl\t3.4.0-2-astra6\thi \nopenssl-provider-legacy\t3.0.0-1\trc \n"
        expected = {"libssl3:amd64": "3.4.0-2-astra6", "openssl": "3.4.0-2-astra6"}
        self.assertEqual(installed_control_versions(before, packages), expected)
        for invalid in ("", "openssl\t3.0.0-1\trc \n", "openssl\t3.0.0-1\tiF \n", "openssl\t\tii \n", "unknown\t3.0.0-1\tii \n"):
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                installed_control_versions(invalid, packages)

    def test_baseline_requires_each_native_status_observation_and_exact_content(self):
        results = {RULE: "pass", "xccdf_org.hcp_rule_aslr": "fail"}
        evidence = {RULE: ["observed_mode=0644"], "xccdf_org.hcp_rule_aslr": []}
        report = {"scanner": {"scannerExitCode": 2, "profile": PROFILE, "datastream": "/__hcp_builtin__/astra-baseline.xml",
                              "datastreamChecksum": "sha256:" + "a" * 64, "ruleResultCounts": {"pass": 1, "fail": 1}},
                  "findings": [{"id": "openscap_" + RULE, "status": "passed", "evidence": "native: observed_mode=0644"},
                               {"id": "openscap_xccdf_org.hcp_rule_aslr", "status": "failed", "evidence": ""}]}
        verify_baseline_report(report, results, evidence, "a" * 64)
        for change in (lambda r: r["findings"].pop(),
                       lambda r: r["findings"][1].update(status="passed"),
                       lambda r: r["findings"][0].update(evidence=""),
                       lambda r: r["scanner"].update(scannerExitCode=1),
                       lambda r: r["scanner"].update(datastreamChecksum="sha256:" + "b" * 64)):
            broken = copy.deepcopy(report)
            change(broken)
            with self.assertRaises(AssertionError):
                verify_baseline_report(broken, results, evidence, "a" * 64)

    def test_fixed_control_cannot_keep_positive_finding(self):
        source, report = self.report("false")
        report["findings"] = self.report("true")[1]["findings"]
        with self.assertRaises(AssertionError):
            verify_oval_report(report, source, "1.8.1", "false")


if __name__ == "__main__":
    unittest.main()
