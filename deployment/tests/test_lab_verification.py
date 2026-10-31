"""Lab acceptance rejects misleading scheduler and unavailable-CVE evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


SPEC = importlib.util.spec_from_file_location(
    "hcp_lab_verify", Path(__file__).resolve().parents[1] / "lab" / "verify.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ScheduledAcceptanceTests(unittest.TestCase):
    def response(self, partial=False, error=None, returncode=None):
        result = {"hostAlias": "lab-scheduled", "partial": partial}
        if error:
            result["error"] = error
        payload = {"ok": not partial, "partial": partial,
                   "reportRunId": "schedule-20261030T180000Z", "results": [result]}
        return subprocess.CompletedProcess(["hcp-scheduled-audit"],
                                           int(partial) if returncode is None else returncode,
                                           stdout=json.dumps(payload), stderr=""), payload

    def test_complete_and_partial_native_results_have_opposite_exit_states(self):
        for partial in (False, True):
            completed, _ = self.response(partial)
            payload, result = VERIFY.verify_scheduled_response(completed, "lab-scheduled")
            self.assertIs(payload["partial"], partial)
            self.assertEqual(result["hostAlias"], "lab-scheduled")
        completed, _ = self.response(True, error="sudo_password_required")
        VERIFY.verify_scheduled_response(completed, "lab-scheduled")

    def test_partial_or_error_cannot_be_successful_cli_exit(self):
        for error in (None, "sudo_password_required"):
            completed, _ = self.response(True, error=error, returncode=0)
            with self.subTest(error=error), self.assertRaises(AssertionError):
                VERIFY.verify_scheduled_response(completed, "lab-scheduled")
        completed, _ = self.response(False, returncode=1)
        with self.assertRaises(AssertionError):
            VERIFY.verify_scheduled_response(completed, "lab-scheduled")

    def test_misleading_result_aggregate_or_wrong_host_is_rejected(self):
        changes = [lambda p: p.update(ok=True), lambda p: p.update(partial=False),
                   lambda p: p.update(results=[]),
                   lambda p: p["results"][0].update(hostAlias="different-host"),
                   lambda p: p["results"][0].pop("partial"),
                   lambda p: p.update(reportRunId="run-unrelated")]
        for change in changes:
            completed, payload = self.response(True)
            change(payload)
            completed.stdout = json.dumps(payload)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                VERIFY.verify_scheduled_response(completed, "lab-scheduled")

    def binding_fixture(self):
        binding = {"status": "verified", "assetId": "asset-native", "alias": "lab-scheduled",
                   "generation": 1, "machineIdSha256": "a" * 64,
                   "sshHostKeyFingerprint": "SHA256:fixture", "connectionId": "b" * 64}
        return {"inventoryHost": "lab-scheduled", "assetBinding": copy.deepcopy(binding),
                "assetBindingInvalid": False, "reportTimeValid": True,
                "raw": {"inventoryHost": "lab-scheduled", "assetBinding": copy.deepcopy(binding)}}, binding

    def test_saved_report_preserves_the_independent_preflight_identity(self):
        item, binding = self.binding_fixture()
        VERIFY.verify_scheduled_binding(item, "lab-scheduled", binding)

    def test_missing_or_replaced_asset_evidence_cannot_pass(self):
        changes = [lambda p: p.pop("assetBinding"),
                   lambda p: p["raw"].pop("assetBinding"),
                   lambda p: p["assetBinding"].update(status="unverified"),
                   lambda p: p.update(assetBindingInvalid=True),
                   lambda p: p.update(reportTimeValid=False),
                   lambda p: p["raw"].update(inventoryHost="different-host")]
        for change in changes:
            item, binding = self.binding_fixture()
            change(item)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                VERIFY.verify_scheduled_binding(item, "lab-scheduled", binding)
        for key in ("assetId", "generation", "machineIdSha256", "sshHostKeyFingerprint", "connectionId"):
            item, binding = self.binding_fixture()
            item["assetBinding"][key] = item["raw"]["assetBinding"][key] = "replaced"
            with self.subTest(key=key), self.assertRaises(AssertionError):
                VERIFY.verify_scheduled_binding(item, "lab-scheduled", binding)

    def package_fixture(self):
        native = "installed\tlibssl3:amd64\t3.0.14-1~deb12u2\tamd64\ninstalled\topenssl\t3.0.14-1~deb12u2\tamd64\nconfig-files\tremoved-package\t1.0\tall\n"
        packages = [{"name": "libssl3:amd64", "version": "3.0.14-1~deb12u2", "arch": "amd64", "manager": "dpkg"},
                    {"name": "openssl", "version": "3.0.14-1~deb12u2", "arch": "amd64", "manager": "dpkg"}]
        item = {"partial": False, "raw": {"packages": packages, "packageInventory": {
            "manager": "dpkg", "packageCount": 2, "partial": False, "error": ""}}}
        return item, native

    def test_scheduled_inventory_matches_native_versions_architectures_and_count(self):
        VERIFY.verify_native_package_snapshot(*self.package_fixture())

    def test_dropped_changed_duplicate_or_incomplete_inventory_is_rejected(self):
        changes = [lambda p: p["raw"]["packages"].pop(),
                   lambda p: p["raw"]["packages"].append(copy.deepcopy(p["raw"]["packages"][0])),
                   lambda p: p["raw"]["packages"][0].update(version="3.0.14-1"),
                   lambda p: p["raw"]["packages"][0].update(arch="arm64"),
                   lambda p: p["raw"]["packages"][0].update(manager="rpm"),
                   lambda p: p["raw"]["packageInventory"].update(partial=True),
                   lambda p: p["raw"]["packageInventory"].update(error="database changed"),
                   lambda p: p["raw"]["packageInventory"].update(packageCount=3),
                   lambda p: p.update(partial=True)]
        for change in changes:
            item, native = self.package_fixture()
            change(item)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                VERIFY.verify_native_package_snapshot(item, native)


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
