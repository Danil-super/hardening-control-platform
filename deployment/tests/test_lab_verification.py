"""The lab's unavailable-CVE gate rejects misleading saved report evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "hcp_lab_verify", Path(__file__).resolve().parents[1] / "lab" / "verify.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class UnavailableCveAcceptanceTests(unittest.TestCase):
    def fixture(self, freshness="missing"):
        finding = {"id": "trivy_scan_unavailable", "status": "manual",
                   "evidence": "mode=offline; failure=database; database=" + freshness}
        packages = {"id": "lab-host-packages-test", "raw": {"packages": [{"name": "openssl"}]}}
        payload = {"ok": True, "partial": True, "reportId": "lab-host-vulnerabilities-test"}
        item = {"id": payload["reportId"], "score": None, "partial": True,
                "findings": [copy.deepcopy(finding)], "raw": {
                    "scanner": {"available": False, "partial": True},
                    "summary": {"score": None}, "findings": [finding],
                    "vulnerabilityScan": {
                        "providerMode": "offline", "partial": True, "checkedPackages": 0,
                        "databaseFreshness": {"status": freshness},
                        "sourcePackageReportId": packages["id"], "sourceEvidence": None,
                        "vendorAssessment": {"verified": False},
                        "coverage": {"inventoryPackages": 1, "scannedPackages": 0,
                                     "complete": False, "reasons": ["DB is unavailable"]},
                    },
                }}
        return payload, item, packages

    def test_nonfresh_database_preserves_manual_saved_report(self):
        for freshness in ("missing", "stale", "unknown"):
            with self.subTest(freshness=freshness):
                VERIFY.verify_unavailable_cve_report(*self.fixture(freshness), freshness)

    def test_missing_or_false_partial_and_unavailable_flags_fail(self):
        for target, key, value in (
            ("payload", "ok", False), ("payload", "partial", False),
            ("item", "partial", None), ("scanner", "available", True),
            ("scanner", "available", None), ("scanner", "partial", False),
            ("scan", "partial", False),
        ):
            payload, item, packages = self.fixture()
            objects = {"payload": payload, "item": item, "scanner": item["raw"]["scanner"],
                       "scan": item["raw"]["vulnerabilityScan"]}
            objects[target][key] = value
            with self.subTest(target=target, key=key, value=value), self.assertRaises(AssertionError):
                VERIFY.verify_unavailable_cve_report(payload, item, packages, "missing")

    def test_pass_empty_findings_or_missing_manual_reason_fail(self):
        for location in ("raw", "normalized"):
            for findings in ([], [{"id": "trivy_scan_unavailable", "status": "passed"}],
                             [{"id": "trivy_scan_unavailable", "status": "manual"}]):
                payload, item, packages = self.fixture()
                target = item["raw"] if location == "raw" else item
                target["findings"] = findings
                with self.subTest(location=location, findings=findings), self.assertRaises(AssertionError):
                    VERIFY.verify_unavailable_cve_report(payload, item, packages, "missing")
            payload, item, packages = self.fixture()
            target = item["raw"] if location == "raw" else item
            target["findings"].append({"id": "trivy_no_known_vulnerabilities", "status": "manual"})
            with self.assertRaises(AssertionError):
                VERIFY.verify_unavailable_cve_report(payload, item, packages, "missing")

    def test_invented_coverage_score_or_source_evidence_fail(self):
        for target, key, value in (
            ("coverage", "complete", True), ("coverage", "scannedPackages", 1),
            ("coverage", "inventoryPackages", 0), ("coverage", "reasons", []),
            ("scan", "checkedPackages", 1), ("scan", "providerMode", "online"),
            ("scan", "databaseFreshness", {"status": "fresh"}),
            ("scan", "vendorAssessment", {"verified": True}),
            ("scan", "sourceEvidence", {"status": "unchanged"}),
            ("item", "score", 100), ("summary", "score", 100),
        ):
            payload, item, packages = self.fixture()
            scan = item["raw"]["vulnerabilityScan"]
            objects = {"item": item, "scan": scan, "coverage": scan["coverage"],
                       "summary": item["raw"]["summary"]}
            objects[target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(AssertionError):
                VERIFY.verify_unavailable_cve_report(payload, item, packages, "missing")

    def test_response_and_saved_report_must_reference_same_inventory(self):
        for target in ("payload", "scan"):
            payload, item, packages = self.fixture()
            if target == "payload":
                payload["reportId"] = "another-report"
            else:
                item["raw"]["vulnerabilityScan"]["sourcePackageReportId"] = "another-inventory"
            with self.subTest(target=target), self.assertRaises(AssertionError):
                VERIFY.verify_unavailable_cve_report(payload, item, packages, "missing")


if __name__ == "__main__":
    unittest.main()
