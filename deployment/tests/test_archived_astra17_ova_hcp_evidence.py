"""Immutable, original, sanitized real Astra SE 1.7.6.15 HCP CI evidence.

This verifies only the exact artifact from run 42085774318, not guest
re-execution, publisher signature, full OVAL, host enrollment or production.
"""
import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "docs/evidence/astra17-ova-hcp-18-rule-run-42085774318.zip"
ARCHIVE_SIZE = 2683
ARCHIVE_SHA256 = "046acf81c31ca0ba6f81d774fe3a2b32b421fd0ad81ca6e60e4c73b5c3eea593"
ENTRY_NAME = "hcp-real-astra17-hcp-public.json"
ENTRY_SIZE = 6623
ENTRY_SHA256 = "9a5716b94fd81fdbf10d357e21e0e32efddcfdee28ebbd086914f0106a176412"
IMAGE_SHA256 = "72ccb335f4c46b5b6d1410cfe0c08f648f95a5e6fd1026f6e0b2d65d8b7ebf6e"
BUNDLE = "bundle-sha256:d5dcd96987d288da7ca92bfcfced2b1cfc3b51f787821870ed14a49c9b0416b7"


class GenuineHcpAstra17ThreeStageArchiveTests(unittest.TestCase):
    @staticmethod
    def original():
        with zipfile.ZipFile(ARCHIVE) as z:
            return json.loads(z.read(ENTRY_NAME))

    def test_exact_original_zip_and_only_one_original_json(self):
        self.assertFalse(ARCHIVE.is_symlink())
        payload = ARCHIVE.read_bytes()
        self.assertEqual(len(payload), ARCHIVE_SIZE)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), ARCHIVE_SHA256)
        with zipfile.ZipFile(ARCHIVE) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.namelist(), [ENTRY_NAME])
            entry = z.getinfo(ENTRY_NAME)
            self.assertEqual(entry.file_size, ENTRY_SIZE)
            self.assertLess(entry.compress_size, ENTRY_SIZE)
            raw = z.read(entry)
        self.assertEqual(len(raw), ENTRY_SIZE)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ENTRY_SHA256)

    def test_corrected_top_level_labels_and_native_18_rule_measurements(self):
        o = self.original()
        self.assertEqual(o["schemaVersion"], 1)
        self.assertEqual(o["status"], "native-astra17-ova-hcp-three-stage-only")
        self.assertEqual(o["experiment"], "exact-native-Astra17-OVA-HCP-18-rule-three-stage-only")
        self.assertTrue(o["realNative18RuleThreeStageObserved"])
        guest = o["nativeGuest"]
        self.assertEqual([guest[x] for x in ("osId", "pointRelease", "fullBuild", "architecture")],
                         ["astra", "1.7.6", "1.7.6.15", "x86_64"])
        self.assertEqual(o["originalImage"]["bytes"], 427995648)
        self.assertEqual(o["originalImage"]["sha256"], IMAGE_SHA256)
        native = o["nativeHcp"]
        self.assertTrue(native["realFactsCollected"])
        self.assertTrue(native["realPackageInventoryCollected"])
        self.assertEqual(native["installedPackageCount"], 398)
        self.assertTrue(native["originalModeRestoredVerified"])
        self.assertTrue(native["freshSshSameGuestAfterRestore"])
        self.assertEqual(native["sourceBundleIdentity"], BUNDLE)
        measurements = native["ruleMeasurements"]
        self.assertEqual(measurements["testedRules"], 18)
        self.assertTrue(measurements["oneControlledPassedToFailed"])
        self.assertTrue(measurements["restoredMatchesBaseline18Rules"])
        self.assertEqual(measurements["counts"], {
            "baseline": {"passed": 14, "failed": 4},
            "violation": {"passed": 13, "failed": 5},
            "restored": {"passed": 14, "failed": 4},
        })
        phases = native["phaseEvidenceSha256"]
        self.assertEqual(set(phases), {"baseline", "violation", "restored"})
        for phase in ("baseline", "violation", "restored"):
            self.assertEqual(phases[phase]["sourceBundleIdentity"], BUNDLE)
            for key in ("rawArfSha256", "evaluatedOriginalXccdfSha256",
                        "normalizedJsonSha256"):
                self.assertRegex(phases[phase][key], r"\A[a-f0-9]{64}\Z")
        self.assertEqual(len({phases[k]["rawArfSha256"] for k in phases}), 3)

    def test_no_full_cve_production_or_publisher_claims_or_private_payload(self):
        o = self.original()
        for key in ("fullNative18RuleAcceptance", "ovalEvaluationPerformed",
                    "hardenedProdReady", "publisherSignatureIndependentlyVerified"):
            self.assertIs(o[key], False)
        native = o["nativeHcp"]
        for key in ("fullOvalEvaluated", "productionHcpEnrollmentPerformed",
                    "entireOsRollbackProven", "rawArfPublished"):
            self.assertIs(native[key], False)
        self.assertIs(o["originalImage"]["publisherSignatureVerified"], False)
        self.assertIs(o["nativeGuest"]["hcpEnrollmentVerified"], False)
        self.assertNotIn("machineId", o["nativeGuest"])
        self.assertNotIn("privateKey", o)
        self.assertNotIn("password", o)


if __name__ == "__main__":
    unittest.main()
