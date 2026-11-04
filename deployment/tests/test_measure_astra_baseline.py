"""Synthetic fixtures verify the *acceptance logic*, not a real Astra run."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "measure_astra_baseline.py"
SPEC = importlib.util.spec_from_file_location("measure_astra_baseline", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture(failed=("0", "1"), time="2026-11-03T10:00:00Z"):
    findings = [
        {"id": "openscap_xccdf_org.hcp_rule_test_" + str(i),
         "status": "failed" if str(i) in failed else "passed"}
        for i in range(18)
    ]
    return {
        "mode": "openscap", "partial": False, "createdAt": time, "inventoryHost": "astra-fixture",
        "assetBinding": {"version": 1, "status": "verified",
                         "assetId": "asset-" + "a" * 64, "generation": 2},
        "scanner": {"profile": MODULE.PROFILE,
                    "datastream": "/__hcp_builtin__/astra-baseline.xml",
                    "datastreamChecksum": "sha256:" + "b" * 64,
                    "contentIdentity": "bundle-sha256:" + "a" * 64,
                    "scannerExitCode": 2, "partial": False,
                    "ruleResultCounts": {
                        "pass": 18 - len(failed), "fail": len(failed),
                        "notapplicable": 0,
                    }},
        "findings": findings,
    }


class HcpAstraExperimentGateTest(unittest.TestCase):
    def test_exact_paired_observation_reports_changes_without_inventing_effectiveness(self):
        before = fixture()
        after = fixture(failed=("1",), time="2026-11-03T10:10:00Z")
        result = MODULE.measure(before, after, "c" * 64, "d" * 64)
        self.assertEqual(result["completeComparableRuleCount"], 18)
        self.assertEqual(result["beforeFailed"], 2)
        self.assertEqual(result["afterFailed"], 1)
        self.assertEqual(result["observedFailedToPassed"], 1)
        self.assertEqual(result["observedPassedToFailed"], 0)
        self.assertEqual(result["netFailedRuleChange"], -1)
        self.assertEqual(result["improvedRules"], ["openscap_xccdf_org.hcp_rule_test_0"])
        self.assertEqual(result["source"]["sourceBundleSha256"], "bundle-sha256:" + "a" * 64)
        self.assertEqual(result["source"]["executedDatastreamSha256Before"], "sha256:" + "b" * 64)
        self.assertEqual(result["source"]["executedDatastreamSha256After"], "sha256:" + "b" * 64)
        self.assertNotIn("percentageSecure", result)
        self.assertNotIn("timeSavedSeconds", result)

    def test_cross_asset_or_changed_policy_never_counts_as_improvement(self):
        baseline = fixture()
        valid_after = fixture(failed=(), time="2026-11-03T10:30:00Z")
        edits = [
            ("asset identity changed", lambda x: x["assetBinding"].update(assetId="asset-" + "b" * 64)),
            ("asset generation changed", lambda x: x["assetBinding"].update(generation=3)),
            ("different alias", lambda x: x.update(inventoryHost="other")),
            ("different source bundle", lambda x: x["scanner"].update(contentIdentity="bundle-sha256:" + "c" * 64)),
            ("same timestamp", lambda x: x.update(createdAt=baseline["createdAt"])),
            ("different rule scope", lambda x: x["findings"][0].update(id="openscap_xccdf_org.hcp_rule_other")),
            ("partial", lambda x: x.update(partial=True)),
            ("scanner partial", lambda x: x["scanner"].update(partial=True)),
            ("scanner completion unproven", lambda x: x["scanner"].pop("partial")),
            ("unverified binding", lambda x: x["assetBinding"].update(status="unknown")),
            ("removed finding", lambda x: x["findings"].pop()),
            ("duplicate rule", lambda x: x["findings"][1].update(id=x["findings"][0]["id"])),
            ("invalid scanner exit", lambda x: x["scanner"].update(scannerExitCode=1)),
            ("tampered counter", lambda x: x["scanner"]["ruleResultCounts"].update(fail=1)),
            ("unknown result", lambda x: x["findings"][0].update(status="manual")),
        ]
        for label, edit in edits:
            with self.subTest(label=label):
                after = copy.deepcopy(valid_after)
                edit(after)
                with self.assertRaises(ValueError):
                    MODULE.measure(baseline, after, "c" * 64, "d" * 64)

    def test_recompilation_timestamps_change_execution_sha_not_policy_identity(self):
        before = fixture()
        after = fixture(failed=(), time="2026-11-03T10:30:00Z")
        before["scanner"]["datastreamChecksum"] = "sha256:d01811aa52c133de51d59dfacff9581e929b37c97951c26a2d4b6ccf033fce04"
        after["scanner"]["datastreamChecksum"] = "sha256:4f9f0eb5351de1b6bb94e2425a294473cc5f6d120671dfa132610f40c9271a02"
        stable = "bundle-sha256:d5dcd96987d288da7ca92bfcfced2b1cfc3b51f787821870ed14a49c9b0416b7"
        before["scanner"]["contentIdentity"] = stable
        after["scanner"]["contentIdentity"] = stable
        # Native unpublished scanner reports omit top-level partial; the
        # scanner's own explicit partial=False remains mandatory.
        before.pop("partial")
        after.pop("partial")
        measured = MODULE.measure(before, after, "c" * 64, "d" * 64)
        self.assertEqual(measured["source"]["sourceBundleSha256"], stable)
        self.assertNotEqual(measured["source"]["executedDatastreamSha256Before"],
                            measured["source"]["executedDatastreamSha256After"])
        self.assertEqual(measured["observedFailedToPassed"], 2)

    def test_three_observations_preserve_a_real_rule_transition_and_return_to_baseline(self):
        baseline = fixture(failed=("0", "1"), time="2026-11-03T10:00:00Z")
        changed = fixture(failed=("0", "1", "2"), time="2026-11-03T10:10:00Z")
        restored = fixture(failed=("0", "1"), time="2026-11-03T10:20:00Z")
        # OpenSCAP timestamps may change compiled XML bytes between invocations.
        changed["scanner"]["datastreamChecksum"] = "sha256:" + "c" * 64
        restored["scanner"]["datastreamChecksum"] = "sha256:" + "d" * 64
        result = MODULE.measure_three_stage(baseline, changed, restored, "e" * 64,
                                            "f" * 64, "0" * 64)
        self.assertEqual(result["scope"], "astra-builtin-18-rule-three-observation-evidence-only")
        self.assertEqual(result["completeComparableRuleCount"], 18)
        self.assertEqual(result["baselineToChanged"]["observedPassedToFailed"], 1)
        self.assertEqual(result["changedToRestored"]["observedFailedToPassed"], 1)
        self.assertEqual(result["baselineToRestored"]["netFailedRuleChange"], 0)
        self.assertTrue(result["observedChangeIn18Rules"])
        self.assertTrue(result["restorationMatchesBaseline18Rules"])
        self.assertEqual(result["status"], "same-18-rule-statuses-observed")
        self.assertEqual(result["source"]["restoredSha256"], "0" * 64)
        self.assertEqual(result["source"]["executedDatastreamSha256Changed"], "sha256:" + "c" * 64)
        self.assertEqual(result["source"]["executedDatastreamSha256Restored"], "sha256:" + "d" * 64)
        self.assertNotIn("fullCveCoverage", result)
        self.assertNotIn("securityScore", result)

    def test_restoration_mismatch_is_preserved_as_failure_not_reported_as_success(self):
        baseline = fixture(failed=("0", "1"), time="2026-11-03T10:00:00Z")
        changed = fixture(failed=("0", "1", "2"), time="2026-11-03T10:10:00Z")
        restored = fixture(failed=("0", "1", "3"), time="2026-11-03T10:20:00Z")
        data = MODULE.measure_three_stage(baseline, changed, restored, "a" * 64,
                                          "b" * 64, "c" * 64)
        self.assertFalse(data["restorationMatchesBaseline18Rules"])
        self.assertEqual(data["status"], "rules-not-restored")
        self.assertEqual(data["baselineToRestored"]["regressedRules"],
                         ["openscap_xccdf_org.hcp_rule_test_3"])

    def test_no_observed_intervention_is_not_claimed_as_effective_hardening(self):
        baseline = fixture(failed=("0", "1"), time="2026-11-03T10:00:00Z")
        changed = fixture(failed=("0", "1"), time="2026-11-03T10:10:00Z")
        restored = fixture(failed=("0", "1"), time="2026-11-03T10:20:00Z")
        result = MODULE.measure_three_stage(baseline, changed, restored, "1" * 64,
                                            "2" * 64, "3" * 64)
        self.assertFalse(result["observedChangeIn18Rules"])
        self.assertTrue(result["restorationMatchesBaseline18Rules"])
        self.assertEqual(result["baselineToChanged"]["netFailedRuleChange"], 0)
        self.assertNotIn("effectiveHardening", result)

    def test_three_stage_rejects_different_assets_scopes_and_chronology(self):
        base = fixture(time="2026-11-03T10:00:00Z")
        changed = fixture(failed=(), time="2026-11-03T10:10:00Z")
        restored = fixture(time="2026-11-03T10:20:00Z")
        edits = [
            lambda x: x["assetBinding"].update(assetId="asset-" + "b" * 64),
            lambda x: x["assetBinding"].update(generation=3),
            lambda x: x["scanner"].update(contentIdentity="bundle-sha256:" + "c" * 64),
            lambda x: x.update(createdAt=changed["createdAt"]),
            lambda x: x["findings"][0].update(status="manual"),
        ]
        for edit in edits:
            with self.subTest(edit=edit):
                candidate = copy.deepcopy(restored)
                edit(candidate)
                with self.assertRaises(ValueError):
                    MODULE.measure_three_stage(base, changed, candidate, "1" * 64,
                                               "2" * 64, "3" * 64)

    def test_three_stage_cli_outputs_reviewable_failure_and_protects_originals(self):
        with tempfile.TemporaryDirectory(prefix="hcp-astra-three-state-") as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            changed = root / "changed.json"
            restored = root / "restored.json"
            output = root / "result.json"
            baseline.write_text(json.dumps(fixture()), encoding="utf-8")
            changed.write_text(json.dumps(fixture(failed=("0", "1", "2"),
                time="2026-11-03T10:10:00Z")), encoding="utf-8")
            restored.write_text(json.dumps(fixture(failed=("0", "1", "3"),
                time="2026-11-03T10:20:00Z")), encoding="utf-8")
            original = [p.read_bytes() for p in [baseline, changed, restored]]
            cmd = [sys.executable, str(SCRIPT), "--before", str(baseline),
                   "--after", str(changed), "--restored", str(restored),
                   "--output", str(output)]
            run = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "rules-not-restored")
            self.assertFalse(result["restorationMatchesBaseline18Rules"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(original, [p.read_bytes() for p in [baseline, changed, restored]])
            output.unlink()
            restored.write_text(json.dumps(fixture(failed=("0", "1"),
                time="2026-11-03T10:20:00Z")), encoding="utf-8")
            run = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))
                            ["restorationMatchesBaseline18Rules"])
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            output.unlink()
            duplicate = cmd.copy()
            duplicate[duplicate.index(str(restored))] = str(baseline)
            self.assertNotEqual(subprocess.run(duplicate, capture_output=True).returncode, 0)
            self.assertFalse(output.exists())

    def test_real_cli_rejects_symlinks_and_does_not_overwrite_inputs(self):
        with tempfile.TemporaryDirectory(prefix="hcp-experiment-fixture-") as temporary:
            root = Path(temporary)
            pre = root / "before.json"
            post = root / "after.json"
            output = root / "metrics.json"
            pre.write_text(json.dumps(fixture()), encoding="utf-8")
            post.write_text(json.dumps(fixture(failed=("1",), time="2026-11-03T11:00:00Z")),
                            encoding="utf-8")
            command = [sys.executable, str(SCRIPT), "--before", str(pre),
                       "--after", str(post), "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["source"]["beforeSha256"],
                             hashlib.sha256(pre.read_bytes()).hexdigest())
            self.assertEqual(saved["source"]["afterSha256"],
                             hashlib.sha256(post.read_bytes()).hexdigest())
            self.assertEqual(saved["observedFailedToPassed"], 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            output.unlink()
            redirect = root / "shortcut.json"
            redirect.symlink_to(pre)
            command[command.index(str(pre))] = str(redirect)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
