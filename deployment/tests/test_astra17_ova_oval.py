"""Offline tests for full exact-source native Astra 1.7 vendor OVAL gates.

These tests use explicitly synthetic XML and scanner JSON. They do NOT claim
a real 1.7 OVAL run. Actual verdict requires the standalone native KVM CI.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import verify_astra17_ova_oval as oval


class OriginalVendorOvaSourceTests(unittest.TestCase):
    def fixture(self):
        original = {
            "inventoryHost": "hcp-real-astra",
            "mode": "astra-oval", "partial": False,
            "summary": {"score": None},
            "scanner": {
                "available": True,
                "evaluationPerformed": True,
                "exitCode": 0, "partial": False, "partialReasons": [],
                "hostIdentity": {"id": "astra", "astraVersion": "1.7.6"},
                "database": {"sha256": oval.VENDOR["sha256"],
                             "checksumVerified": True},
                "definitionCount": 2, "evaluatedDefinitionCount": 2,
                "definitionResults": [
                    {"id": "oval:astra:def:10", "result": "true"},
                    {"id": "oval:astra:def:20", "result": "unknown"},
                ],
                "resultSha256": "a" * 64,
                "evidenceProjection": "bounded",
                "fullDefinitionIdSetPreserved": True,
                "auxiliaryDetailsOmitted": True,
            },
        }
        return original, {"oval:astra:def:10", "oval:astra:def:20"}

    def test_original_official_17_full_definition_source_is_exact_pinned(self):
        self.assertEqual(oval.VENDOR["bytes"], 134668815)
        self.assertEqual(oval.VENDOR["sha256"],
                         "c9364c80d664907dc472475d2ef57689c314abecede7a58e7e9dae8250891d17")
        self.assertIn("1.7_x86-64", oval.VENDOR["url"])
        self.assertNotIn("latest", oval.VENDOR["url"])

    def test_parse_full_xml_requires_unique_real_definition_set(self):
        head = ('<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
                '<definitions>')
        end = '</definitions></oval_definitions>'
        with tempfile.TemporaryDirectory() as directory:
            xml = Path(directory) / "vendor.xml"
            xml.write_text(
                head + '<definition id="oval:astra:def:10"/>'
                + '<definition id="oval:astra:def:20"/>' + end,
                encoding="utf-8",
            )
            self.assertEqual(oval.exact_original_source_ids(xml),
                             {"oval:astra:def:10", "oval:astra:def:20"})
            for fragment in [
                '<definition id="oval:astra:def:10"/><definition id="oval:astra:def:10"/>',
                '<definition id="not-oval"/>',
                '',
            ]:
                xml.write_text(head + fragment + end, encoding="utf-8")
                with self.subTest(xml=fragment):
                    with self.assertRaises(RuntimeError):
                        oval.exact_original_source_ids(xml)

    def test_full_evaluation_preserves_unknown_as_state_not_fake_cve_absence(self):
        report, identities = self.fixture()
        result = oval.validate_original_native_oval(report, identities)
        self.assertEqual(result["definitionCountFromExactVendorXml"], 2)
        self.assertEqual(result["evaluatedDefinitions"], 2)
        self.assertEqual(result["observedResultStates"], {"true": 1, "unknown": 1})
        self.assertTrue(result["fullSelectedSourceEvaluated"])
        self.assertFalse(result["independentPublisherSignatureVerified"])
        self.assertFalse(result["generalAllCveRecallVerified"])
        self.assertTrue(result["reportCannotProveNoVulnerabilities"])

    def test_wrong_id_release_source_partial_exit_missing_or_duplicate_fails(self):
        base, definitions = self.fixture()
        corrupt = []
        a = deepcopy(base)
        a["scanner"]["database"]["sha256"] = "b" * 64
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["hostIdentity"]["astraVersion"] = "1.8.6"
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["hostIdentity"]["id"] = "debian"
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["partial"] = True
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["partialReasons"] = ["timeout"]
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["exitCode"] = 1
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["evaluationPerformed"] = False
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["definitionCount"] = 1
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["evaluatedDefinitionCount"] = 1
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["definitionResults"].pop()
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["definitionResults"][1]["id"] = "oval:astra:def:10"
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["definitionResults"][1]["id"] = "oval:foreign:def:22"
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["definitionResults"][0]["result"] = "not-supported"
        corrupt.append(a)
        for not_completed in ("error", "not evaluated"):
            a = deepcopy(base)
            a["scanner"]["definitionResults"][1]["result"] = not_completed
            corrupt.append(a)
        a = deepcopy(base)
        a["summary"]["score"] = 100
        corrupt.append(a)
        a = deepcopy(base)
        a["scanner"]["resultSha256"] = "unverified"
        corrupt.append(a)
        for index, candidate in enumerate(corrupt):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeError):
                    oval.validate_original_native_oval(candidate, definitions)

    def test_native_report_preflight_distinguishes_bounded_empty_and_oversized(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / 'normalized.json'
            state = {"nativeHcp": {}}
            with self.assertRaisesRegex(RuntimeError, 'native_oval_normalized_report_missing'):
                oval.load_scoped_normalized_report(p, state, limit=100)
            self.assertEqual(state["nativeHcp"]["normalizedOvalReportPreflight"]["result"], "missing")
            p.write_bytes(b'')
            with self.assertRaisesRegex(RuntimeError, 'native_oval_normalized_report_empty'):
                oval.load_scoped_normalized_report(p, state, limit=100)
            p.write_bytes(b'X' * 101)
            with self.assertRaisesRegex(RuntimeError, 'native_oval_normalized_report_oversized'):
                oval.load_scoped_normalized_report(p, state, limit=100)
            self.assertEqual(state["nativeHcp"]["normalizedOvalReportPreflight"]["sizeBytes"], 101)
            p.unlink()
            p.symlink_to(root / "nonexistent")
            with self.assertRaisesRegex(RuntimeError, 'native_oval_normalized_report_unsafe_type'):
                oval.load_scoped_normalized_report(p, state, limit=100)
            p.unlink()
            p.write_text('{"result":"private-but-valid"}')
            doc = oval.load_scoped_normalized_report(p, state, limit=100)
            self.assertEqual(doc["result"], "private-but-valid")
            self.assertEqual(state["nativeHcp"]["normalizedOvalReportPreflight"]["result"], "within_bound")

    def test_child_oval_experiment_preserves_parent_three_stage_truthfulness(self):
        runner = (Path(oval.__file__).with_name("verify_astra17_ova_kvm.py")
                  .read_text(encoding="utf-8"))
        self.assertIn("record_native_hcp_three_stage_success(protocol)", runner)
        self.assertIn("native_oval_full_selected_scope_not_verified", runner)
        self.assertIn("native_oval_normalized_report_oversized", runner)
        self.assertIn("native_oval_bounded_projection_not_attested", runner)
        self.assertIn('"nativeVendorOval17Evaluated": False', runner)

    def test_top_level_oval_success_only_after_original_full_scope_proof(self):
        import verify_astra17_ova_kvm as smoke
        expected = {
            "fullSelectedSourceEvaluated": True,
            "definitionCountFromExactVendorXml": 2,
            "evaluatedDefinitions": 2,
            "sourceSha256": oval.VENDOR["sha256"],
            "observedResultStates": {"true": 1, "false": 1},
            "rawOvalsResultsSha256": "a" * 64,
            "independentPublisherSignatureVerified": False,
            "generalAllCveRecallVerified": False,
            "reportCannotProveNoVulnerabilities": True,
        }
        base = {
            "realNative18RuleThreeStageObserved": True,
            "nativeVendorOval17Evaluated": False,
            "ovalEvaluationPerformed": False,
            "fullNative18RuleAcceptance": False,
            "hardenedProdReady": False,
            "publisherSignatureIndependentlyVerified": False,
            "nativeHcp": {"fullOvalEvaluated": True,
                          "sourceBoundVendorOval": deepcopy(expected)},
        }
        accepted = deepcopy(base)
        smoke.record_selected_vendor_oval_success(accepted)
        self.assertTrue(accepted["nativeVendorOval17Evaluated"])
        self.assertTrue(accepted["ovalEvaluationPerformed"])
        self.assertFalse(accepted["fullNative18RuleAcceptance"])
        self.assertFalse(accepted["hardenedProdReady"])
        self.assertFalse(accepted["publisherSignatureIndependentlyVerified"])
        for broken in ("missing_scope", "incomplete", "wrong_source", "wrong_counts",
                       "fabricated_signature", "raw_result_sha_missing",
                       "not_native_three_stage", "scanner_not_completed"):
            with self.subTest(case=broken):
                candidate = deepcopy(base)
                detail = candidate["nativeHcp"]["sourceBoundVendorOval"]
                if broken == "missing_scope":
                    del candidate["nativeHcp"]["sourceBoundVendorOval"]
                elif broken == "incomplete":
                    detail["fullSelectedSourceEvaluated"] = False
                elif broken == "wrong_source":
                    detail["sourceSha256"] = "b" * 64
                elif broken == "wrong_counts":
                    detail["observedResultStates"] = {"true": 2, "false": 1}
                elif broken == "fabricated_signature":
                    detail["independentPublisherSignatureVerified"] = True
                elif broken == "raw_result_sha_missing":
                    detail["rawOvalsResultsSha256"] = None
                elif broken == "not_native_three_stage":
                    candidate["realNative18RuleThreeStageObserved"] = False
                elif broken == "scanner_not_completed":
                    candidate["nativeHcp"]["fullOvalEvaluated"] = False
                with self.assertRaisesRegex(
                        RuntimeError, "native_oval_full_selected_scope_not_verified"):
                    smoke.record_selected_vendor_oval_success(candidate)
                self.assertFalse(candidate["nativeVendorOval17Evaluated"])
                self.assertFalse(candidate["ovalEvaluationPerformed"])

    def test_real_execution_requires_original_hcp_18_rule_completion_first(self):
        main = (oval.VENDOR["url"])
        self.assertTrue(main.startswith("https://dl.astralinux.ru/artifactory/"))
        content = (Path(oval.__file__).read_text(encoding="utf-8"))
        self.assertIn('run_playbook(work, reports, "astra-oval-audit"', content)
        self.assertIn('"sourceReviewedAt": "2026-11-04"', content)
        self.assertNotIn("shell=True", content)
        self.assertIn('protocol["nativeHcp"]["fullOvalEvaluated"] = True', content)
        runner = (Path(oval.__file__).with_name("verify_astra17_ova_kvm.py")
                  .read_text(encoding="utf-8"))
        self.assertIn('require(not args.native_vendor_oval or args.native_hcp_three_stage', runner)
        self.assertIn('"nativeVendorOval17Evaluated": False', runner)


if __name__ == "__main__":
    unittest.main()
