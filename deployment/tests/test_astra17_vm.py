"""Offline tests for native acceptance *gates*, not actual Astra 1.7 tests."""
from copy import deepcopy
import json
from pathlib import Path
import re
import tempfile
import unittest

import verify_astra17_vm as vm


class NativeAstra17GateTests(unittest.TestCase):
    def test_official_exact_release_sources_are_sha_and_size_pinned(self):
        sources = json.loads(vm.SOURCE.read_text())
        self.assertEqual(sources["schemaVersion"], 1)
        self.assertEqual(set(sources["images"]), {"base", "adv", "max"})
        self.assertEqual(sources["reviewedAt"], "2026-11-04")
        for level, image in sources["images"].items():
            filename = "alse-1.7.6.uu2-%s-cloudinit-mg15.3.1-amd64.qcow2" % level
            self.assertEqual(image["url"], "https://registry.astralinux.ru/artifactory/mg-generic/alse/cloudinit/" + filename)
            self.assertEqual(image["metadataUrl"], "https://registry.astralinux.ru/artifactory/api/storage/mg-generic/alse/cloudinit/" + filename)
            self.assertRegex(image["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(image["bytes"], 400 * 1024 * 1024 - 15 * 1024 * 1024)
            self.assertLess(image["bytes"], 500 * 1024 * 1024)
            self.assertNotIn("latest", image["url"])
        self.assertEqual(sources["images"]["base"]["sha256"],
                         "654aae66598bb4e5e38efc4fc18e2c9cb53170713a31728ff502f04dabf1838e")
        self.assertEqual(sources["images"]["adv"]["sha256"],
                         "03b72d0e058a7feabfb3e2e0b7636f7f4bd331f861f76ec8843cf9efad873c49")
        self.assertEqual(sources["images"]["max"]["sha256"],
                         "0d0e10096c9df52d7eab25bc4456ee9d4210bc912d80d73d4a7b62c01527b2a4")
        self.assertEqual(sources["oval"]["sha256"],
                         "c9364c80d664907dc472475d2ef57689c314abecede7a58e7e9dae8250891d17")
        self.assertEqual(sources["oval"]["bytes"], 134668815)
        self.assertIn("1.7_x86-64", sources["oval"]["url"])
        self.assertIn("not an independent", sources["sourceTrust"])

    def test_actual_vendor_xml_must_contain_real_definition_elements(self):
        with tempfile.TemporaryDirectory(prefix="astra17-oval-count-") as tmp:
            path = Path(tmp) / "source.xml"
            path.write_text(
                '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
                '<definitions><definition id="oval:astra:def:11"/>'
                '<definition id="oval:astra:def:12"/></definitions>'
                '</oval_definitions>', encoding="utf-8")
            self.assertEqual(vm.full_oval_definition_count(path), 2)
            path.write_text('<oval_definitions/>', encoding="utf-8")
            with self.assertRaises(AssertionError):
                vm.full_oval_definition_count(path)

    def fixture(self):
        source = json.loads(vm.SOURCE.read_text())["oval"]
        report = {
            "mode": "astra-oval", "inventoryHost": "hcp-real-astra",
            "summary": {"score": None},
            "scanner": {
                "available": True,
                "evaluationPerformed": True,
                "exitCode": 0,
                "partial": False,
                "partialReasons": [],
                "hostIdentity": {"id": "astra", "astraVersion": "1.7.6.15"},
                "database": {"sha256": source["sha256"],
                             "checksumVerified": True},
                "definitionCount": 3,
                "evaluatedDefinitionCount": 3,
                "definitionResults": [
                    {"id": "oval:astra:def:11", "result": "true"},
                    {"id": "oval:astra:def:12", "result": "false"},
                    {"id": "oval:astra:def:13", "result": "unknown"},
                ],
            },
        }
        return report, source

    def test_native_full_oval_requires_all_reported_definitions_and_no_fabricated_cve(self):
        report, source = self.fixture()
        result = vm.verify_native_oval_report(report, source, 3)
        self.assertEqual(result["definitions"], 3)
        self.assertFalse(result["fullCveRecallVerified"])
        self.assertFalse(result["sourcePublisherSignatureIndependent"])
        self.assertNotIn("unaffected", result)
        self.assertNotIn("fixedCve", result)

    def test_native_oval_rejects_wrong_release_missing_definitions_and_partial(self):
        original, source = self.fixture()
        mutants = []
        report = deepcopy(original)
        report["scanner"]["hostIdentity"]["astraVersion"] = "1.8.6"
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["database"]["sha256"] = "a" * 64
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["evaluatedDefinitionCount"] = 2
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["definitionResults"].pop()
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["partial"] = True
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["evaluationPerformed"] = False
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["definitionResults"][1]["id"] = "oval:astra:def:11"
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["exitCode"] = 1
        mutants.append(report)
        for index, candidate in enumerate(mutants):
            with self.subTest(case=index):
                with self.assertRaises(AssertionError):
                    vm.verify_native_oval_report(candidate, source, 3)

    def test_no_public_artifacts_include_generated_native_identity(self):
        workflow = (vm.ROOT / ".github/workflows/astra17-vm.yml").read_text()
        self.assertIn("workflow_dispatch", workflow)
        self.assertIn("pull_request", workflow)
        self.assertIn("source", (vm.ROOT / "deployment/tests/verify_astra17_vm.py").read_text())
        self.assertNotIn("native-identity-private.txt", workflow)
        self.assertNotIn("asset-observation.json", workflow)
        self.assertNotIn("guest-console.log", workflow)
        self.assertIn("retention-days: 14", workflow)


if __name__ == "__main__":
    unittest.main()
