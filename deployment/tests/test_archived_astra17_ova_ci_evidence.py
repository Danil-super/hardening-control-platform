"""Verify retained original *sanitized* Astra native CI evidence bytes.

No VM, network, SSH or secret access. The SHA is of the byte-exact original
GitHub Actions artifact entry from successful run 42027952736.
"""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/evidence/astra17-ova-ssh-run-42027952736.json"
EXPECTED_SHA256 = "ba0cbce8203fd2c23b531c1f9cb3aad85bddb21d8ebd5eb3189a69d2650de2fb"
EXPECTED_SIZE = 1794


class GenuineAstra17ArchivedProofTests(unittest.TestCase):
    def test_exact_original_sanitized_github_ci_payload(self):
        raw = EVIDENCE.read_bytes()
        self.assertEqual(len(raw), EXPECTED_SIZE)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)
        evidence = json.loads(raw)
        self.assertEqual(evidence["status"], "genuine-astra17-ova-ssh-preflight-only")
        self.assertEqual(evidence["nativeGuest"]["osId"], "astra")
        self.assertEqual(evidence["nativeGuest"]["pointRelease"], "1.7.6")
        self.assertEqual(evidence["nativeGuest"]["fullBuild"], "1.7.6.15")
        self.assertEqual(evidence["nativeGuest"]["architecture"], "x86_64")
        self.assertEqual(evidence["acceleration"], "kvm")
        self.assertEqual(evidence["originalImage"]["bytes"], 427995648)
        self.assertEqual(evidence["originalImage"]["sha256"],
                         "72ccb335f4c46b5b6d1410cfe0c08f648f95a5e6fd1026f6e0b2d65d8b7ebf6e")
        self.assertEqual(evidence["checks"][-1], "fresh_pinned_ssh_identity_stable")

    def test_no_full_scanner_or_vendor_attestation_claim(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertFalse(evidence["fullNative18RuleAcceptance"])
        self.assertFalse(evidence["ovalEvaluationPerformed"])
        self.assertFalse(evidence["hardenedProdReady"])
        self.assertFalse(evidence["publisherSignatureIndependentlyVerified"])
        self.assertFalse(evidence["nativeGuest"]["hcpEnrollmentVerified"])
        self.assertFalse(evidence["originalImage"]["publisherSignatureVerified"])
        self.assertTrue(evidence["nativeGuest"]["machineIdObserved"])
        # Only a one-way digest of the disposable guest observation is allowed;
        # raw OS identity, guest credentials or logs are never retained here.
        self.assertNotIn("machineId", evidence["nativeGuest"])
        self.assertNotIn("privateKey", evidence)
        self.assertNotIn("password", evidence)


if __name__ == "__main__":
    unittest.main()
