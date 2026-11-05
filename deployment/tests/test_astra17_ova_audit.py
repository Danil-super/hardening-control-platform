"""Offline contract/negative checks; actual Astra 1.7 CI is separate."""
from copy import deepcopy
import json
import tempfile
from pathlib import Path
import unittest

from verify_astra_vm import RULE
import verify_astra17_ova_audit as audit


class NativeAstra17AuditTests(unittest.TestCase):
    def fixture(self):
        before = {"xccdf_org.hcp_rule_sample_" + str(i): "pass" for i in range(17)}
        before[RULE] = "pass"
        after = deepcopy(before)
        after[RULE] = "fail"
        return {"baseline": before, "violation": after,
                "restored": deepcopy(before)}

    def test_exactly_one_observed_rule_and_restoration_are_required(self):
        actual = audit.validate_native_three_stage(self.fixture())
        self.assertEqual(actual["testedRules"], 18)
        self.assertEqual(actual["counts"]["baseline"]["failed"], 0)
        self.assertEqual(actual["counts"]["violation"]["failed"], 1)
        self.assertEqual(actual["counts"]["restored"]["failed"], 0)
        self.assertTrue(actual["restoredMatchesBaseline18Rules"])
        self.assertFalse(actual["fullOsRollbackProven"])
        self.assertFalse(actual["cveCoverageProven"])

    def test_unknown_missing_duplicate_changed_and_extra_rule_rejected(self):
        original = self.fixture()
        variations = []
        case = deepcopy(original)
        case["baseline"].pop(RULE)
        variations.append(case)
        case = deepcopy(original)
        case["restored"][RULE] = "manual"
        variations.append(case)
        case = deepcopy(original)
        case["restored"][RULE] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["violation"][RULE] = "pass"
        variations.append(case)
        case = deepcopy(original)
        case["violation"]["xccdf_org.hcp_rule_sample_0"] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["restored"]["xccdf_org.hcp_rule_sample_0"] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["violation"]["foreign_rule"] = "pass"
        variations.append(case)
        case = deepcopy(original)
        case["extra"] = case["baseline"]
        variations.append(case)
        for mutant in variations:
            with self.subTest(stage=json.dumps(list(mutant))):
                with self.assertRaises(RuntimeError):
                    audit.validate_native_three_stage(mutant)

    def test_real_hcp_playbook_and_evidence_paths_are_bound_to_fixed_repository(self):
        content = Path(audit.__file__).read_text(encoding="utf-8")
        self.assertIn('run_playbook(work, reports, "collect-facts"', content)
        self.assertIn('run_playbook(work, reports, "package-inventory"', content)
        self.assertIn('run_playbook(work, reports, "openscap-audit"', content)
        self.assertIn('verify_baseline_report(', content)
        self.assertIn('"hcp_openscap_keep_arf": True', content)
        self.assertIn('finally:', content)
        self.assertNotIn("shell=True", content)
        self.assertNotIn("StrictHostKeyChecking=no", content)
        self.assertIn('"fullOvalEvaluated": False', content)

    def test_original_report_reader_rejects_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            report = folder / "report.json"
            report.write_text(json.dumps({"real": True}))
            self.assertEqual(audit.load_private_json(report), {"real": True})
            linked = folder / "linked.json"
            linked.symlink_to(report)
            with self.assertRaises(RuntimeError):
                audit.load_private_json(linked)
            with self.assertRaises(RuntimeError):
                audit.load_private_json(report, limit=2)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                audit.load_private_json(folder / "missing.json")

    def test_original_smoke_path_default_still_remains_separate(self):
        smoke = (audit.ROOT / "deployment/tests/verify_astra17_ova_kvm.py").read_text()
        self.assertIn("native_hcp_three_stage=False", smoke)
        self.assertIn('"realNative18RuleThreeStageObserved": False', smoke)
        self.assertIn('"fullNative18RuleAcceptance": False', smoke)
        self.assertIn("original_identity=second", smoke)
        self.assertIn("native_hcp_three_stage=args.native_hcp_three_stage", smoke)


if __name__ == "__main__":
    unittest.main()
