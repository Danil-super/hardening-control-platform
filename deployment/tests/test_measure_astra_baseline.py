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
