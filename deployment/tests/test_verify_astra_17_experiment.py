"""Synthetic policy/identity gate tests. NOT native Astra 1.7 measurements."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import verify_astra_17_experiment as gate
from test_measure_astra_baseline import fixture

MACHINE = "0123456789abcdef0123456789abcdef"
FINGERPRINT = "SHA256:" + "A" * 43
KERNEL = "6.1.90-1-generic"
IDENTITY = ("NAME=Astra Linux\nID=astra\nRELEASE=1.7.6.15\n"
            "KERNEL=" + KERNEL + "\nMACHINE_ID=" + MACHINE + "\n")
MACHINE_HASH = hmac.new(gate.ASSET_KEY, MACHINE.encode("ascii"),
                        hashlib.sha256).hexdigest()
ASSET_ID = "asset-" + hashlib.sha256(json.dumps(
    [MACHINE_HASH, FINGERPRINT], separators=(",", ":")).encode()).hexdigest()


def observations():
    binding = {
        "version": 1, "status": "verified", "assetId": ASSET_ID,
        "alias": "astra-fixture", "generation": 2,
        "machineIdSha256": MACHINE_HASH,
        "sshHostKeyFingerprint": FINGERPRINT,
        "connectionId": "f" * 64,
        "verifiedAt": "2026-11-03T09:59:00Z",
    }
    reports = []
    for failed, time in (
        (("0", "1"), "2026-11-03T10:00:00Z"),
        (("0", "1", "2"), "2026-11-03T10:10:00Z"),
        (("0", "1"), "2026-11-03T10:20:00Z"),
    ):
        report = fixture(failed=failed, time=time)
        report["assetBinding"] = copy.deepcopy(binding)
        reports.append(report)
    facts = {
        "mode": "facts", "inventoryHost": "astra-fixture",
        "os": "Astra Linux 1.7_x86-64", "architecture": "x86_64",
        "kernel": KERNEL, "createdAt": "2026-11-03T09:59:00Z",
    }
    return reports, facts


def hashes():
    return {key: ("d" * 64) for key in
            ("before", "changed", "restored", "facts", "identity")}


class Astra17IdentityGateTests(unittest.TestCase):
    def test_consistent_exact_native_identity_and_source_bound_reports(self):
        reports, facts = observations()
        result = gate.verify_experiment(*reports, facts, IDENTITY,
                                        FINGERPRINT, hashes())
        self.assertEqual(result["completeComparableRuleCount"], 18)
        self.assertEqual(result["baselineToChanged"]["observedPassedToFailed"], 1)
        self.assertTrue(result["restorationMatchesBaseline18Rules"])
        self.assertEqual(result["nativeReleaseCrosscheck"]["declaredRelease"],
                         "1.7.6.15")
        self.assertTrue(result["nativeReleaseCrosscheck"]["machineIdMatchedBinding"])
        self.assertFalse(result["nativeReleaseCrosscheck"]["vendorImageAttested"])
        for secret in (MACHINE,):
            self.assertNotIn(secret, json.dumps(result))

    def test_wrong_os_claims_and_cross_machine_sources_fail_closed(self):
        baseline, facts = observations()
        edits = [
            ("Astra 1.8 forged as 1.7", None, {"os": "Astra Linux 1.8_x86-64"},
             IDENTITY, FINGERPRINT),
            ("non-Astra native OS", None, None, IDENTITY.replace("ID=astra", "ID=debian"),
             FINGERPRINT),
            ("wrong native release", None, None, IDENTITY.replace("1.7.6.15", "1.7.6.14"),
             FINGERPRINT),
            ("different SSH host key", None, None, IDENTITY, "SHA256:" + "B" * 43),
            ("wrong kernel", None, {"kernel": "different-generic"}, IDENTITY,
             FINGERPRINT),
            ("wrong architecture", None, {"architecture": "aarch64"}, IDENTITY,
             FINGERPRINT),
            ("late facts", None, {"createdAt": "2026-11-03T10:45:00Z"},
             IDENTITY, FINGERPRINT),
            ("cross-machine asset binding", (0, "assetId", "asset-" + "b" * 64),
             None, IDENTITY, FINGERPRINT),
            ("different session key", (2, "sshHostKeyFingerprint", "SHA256:" + "B" * 43),
             None, IDENTITY, FINGERPRINT),
            ("nonmatching source bundle", (2, "contentIdentity", "bundle-sha256:" + "b" * 64),
             None, IDENTITY, FINGERPRINT),
            ("partial source", (2, "partial", True), None, IDENTITY, FINGERPRINT),
        ]
        for name, edit, facts_edit, identity, fingerprint in edits:
            with self.subTest(name=name):
                records = copy.deepcopy(baseline)
                observed_facts = copy.deepcopy(facts)
                if facts_edit:
                    observed_facts.update(facts_edit)
                if edit:
                    index, key, value = edit
                    if key == "contentIdentity":
                        records[index]["scanner"][key] = value
                    elif key == "partial":
                        records[index]["scanner"][key] = value
                    else:
                        records[index]["assetBinding"][key] = value
                with self.assertRaises(ValueError):
                    gate.verify_experiment(*records, observed_facts, identity,
                                           fingerprint, hashes())

    def test_no_actual_control_transition_cannot_be_sold_as_an_experiment(self):
        records, facts = observations()
        records[1]["findings"] = copy.deepcopy(records[0]["findings"])
        records[1]["scanner"]["ruleResultCounts"] = copy.deepcopy(
            records[0]["scanner"]["ruleResultCounts"])
        with self.assertRaisesRegex(ValueError, "No observed rule transition"):
            gate.verify_experiment(*records, facts, IDENTITY, FINGERPRINT, hashes())

    def test_exact_source_binding_rejects_fingerprint_mismatch_even_if_asset_matches(self):
        reports, facts = observations()
        reports[0]["assetBinding"]["sshHostKeyFingerprint"] = "SHA256:" + "B" * 43
        with self.assertRaises(ValueError):
            gate.verify_experiment(*reports, facts, IDENTITY, FINGERPRINT, hashes())

    def test_bound_facts_must_match_the_same_asset_generation_and_ssh_connection(self):
        reports, facts = observations()
        facts["assetBinding"] = copy.deepcopy(reports[0]["assetBinding"])
        self.assertTrue(gate.verify_experiment(*reports, facts, IDENTITY,
                                               FINGERPRINT, hashes())
                        ["nativeReleaseCrosscheck"]["machineIdMatchedBinding"])
        for field, invalid in (
            ("generation", 3),
            ("connectionId", "e" * 64),
            ("machineIdSha256", "0" * 64),
        ):
            with self.subTest(field=field):
                wrong = copy.deepcopy(facts)
                wrong["assetBinding"][field] = invalid
                with self.assertRaises(ValueError):
                    gate.verify_experiment(*reports, wrong, IDENTITY,
                                           FINGERPRINT, hashes())

    def test_identity_file_symlink_public_permissions_and_overlong_text_refused(self):
        with tempfile.TemporaryDirectory(prefix="hcp-astra17-private-") as directory:
            root = Path(directory)
            original = root / "private.txt"
            original.write_text(IDENTITY, encoding="utf-8")
            original.chmod(0o600)
            parsed, digest = gate.read_identity(original)
            self.assertEqual(parsed, IDENTITY)
            self.assertEqual(digest, hashlib.sha256(IDENTITY.encode()).hexdigest())
            original.chmod(0o644)
            with self.assertRaises(ValueError):
                gate.read_identity(original)
            original.chmod(0o600)
            shortcut = root / "link.txt"
            shortcut.symlink_to(original)
            with self.assertRaises(ValueError):
                gate.read_identity(shortcut)
            original.write_bytes(b"x" * (gate.MAX_IDENTITY_BYTES + 1))
            with self.assertRaises(ValueError):
                gate.read_identity(original)

    def test_cli_only_creates_private_digest_bound_result_and_refuses_overwrite(self):
        reports, facts = observations()
        with tempfile.TemporaryDirectory(prefix="hcp-astra17-gate-") as directory:
            root = Path(directory)
            paths = [root / name for name in
                     ("before.json", "changed.json", "restored.json")]
            for path, report in zip(paths, reports):
                path.write_text(json.dumps(report), encoding="utf-8")
            facts_path = root / "facts.json"
            facts_path.write_text(json.dumps(facts), encoding="utf-8")
            identity_path = root / "guest-identity.txt"
            identity_path.write_text(IDENTITY, encoding="utf-8")
            identity_path.chmod(0o600)
            output = root / "experiment.json"
            script = Path(gate.__file__)
            argv = [sys.executable, str(script),
                    "--before", str(paths[0]), "--changed", str(paths[1]),
                    "--restored", str(paths[2]), "--facts", str(facts_path),
                    "--native-identity", str(identity_path),
                    "--ssh-fingerprint", FINGERPRINT,
                    "--output", str(output)]
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["nativeReleaseCrosscheck"]["identityObservationSha256"],
                             hashlib.sha256(IDENTITY.encode()).hexdigest())
            self.assertEqual(parsed["baselineToRestored"]["netFailedRuleChange"], 0)
            self.assertNotIn(MACHINE, output.read_text() + result.stdout + result.stderr)
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            output.unlink()

            # A failed rollback must preserve exact observed states, not return PASS.
            reports[2]["findings"][3]["status"] = "failed"
            reports[2]["scanner"]["ruleResultCounts"].update({"pass": 15, "fail": 3})
            paths[2].write_text(json.dumps(reports[2]), encoding="utf-8")
            result = subprocess.run(argv, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(output.read_text())["status"], "rules-not-restored")


if __name__ == "__main__":
    unittest.main()
