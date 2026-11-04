"""Synthetic negative acceptance logic only; not a native Astra 1.7 run."""
import base64
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import unittest

import accept_astra17_native_experiment as gate
from test_verify_astra_17_experiment import observations, IDENTITY, FINGERPRINT


class Astra17NativeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hcp-astra17-acceptance-fixture-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.image = self.root / "alse-1.7.6.uu2-base-virtualbox-mg15.3.1-amd64.ova"
        with tarfile.open(self.image, "w", format=tarfile.USTAR_FORMAT) as archive:
            data = b"SYNTHETIC OVA TEST NOT AN ACTUAL ASTRA VIRTUAL MACHINE" * 50
            entry = tarfile.TarInfo("synthetic.ovf")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        self.image_sha = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.image_evidence = self.root / "image.json"
        self.image_evidence.write_text(json.dumps({
            "schemaVersion": 1, "status": "local-bytes-match-recorded-pin",
            "imageName": self.image.name, "fileSizeBytes": self.image.stat().st_size,
            "sha256": self.image_sha,
            "securityLevelCandidate": "base",
            "publisherSignatureVerified": False,
            "nativeGuestVerified": False,
        }))
        self.reports, self.facts = observations()
        self.paths = [self.root / name for name in
                      ("before.json", "changed.json", "restored.json", "facts.json", "oval.json")]
        self.oval_sha = "a" * 64
        self.oval = {
            "mode": "astra-oval", "inventoryHost": "astra-fixture",
            "assetBinding": dict(self.reports[0]["assetBinding"]),
            "partial": False,
            "scanner": {
                "hostIdentity": {"id": "astra", "astraVersion": "1.7.6"},
                "database": {"sha256": self.oval_sha, "checksumVerified": True},
                "definitionCount": 2, "evaluatedDefinitionCount": 2,
                "definitionResults": [{"id": "oval:astra:def:1", "result": "true"},
                                      {"id": "oval:astra:def:2", "result": "false"}],
                "evaluationPerformed": True, "available": True,
                "exitCode": 2, "partial": False,
            },
        }
        self.save()

    def save(self):
        for path, content in zip(self.paths, [*self.reports, self.facts, self.oval]):
            path.write_text(json.dumps(content))

    def accept(self, after=IDENTITY):
        return gate.verify_all(
            str(self.image), str(self.image_evidence),
            *(str(path) for path in self.paths[:4]),
            IDENTITY, after, FINGERPRINT, str(self.paths[4]), self.oval_sha,
        )

    def test_exact_image_real_report_shapes_and_post_identity_are_scoped(self):
        proof = self.accept()
        self.assertEqual(proof["status"], "astra-17-native-evidence-bounded-acceptance")
        self.assertEqual(proof["experiment"]["completeComparableRuleCount"], 18)
        self.assertEqual(proof["experiment"]["baselineToChanged"]["observedPassedToFailed"], 1)
        self.assertEqual(proof["experiment"]["changedToRestored"]["observedFailedToPassed"], 1)
        self.assertTrue(proof["experiment"]["restorationMatchesBaseline18Rules"])
        self.assertEqual(proof["oval"]["defined"], 2)
        self.assertTrue(proof["postRestoreSsh"]["freshPinnedSshConnectionObserved"])
        for key in ("independentVendorSignatureVerified", "generalCveCoverageVerified",
                    "fullSystemRollbackVerified", "operatorSignoffReceived"):
            self.assertFalse(proof[key])
        self.assertNotIn("0123456789abcdef0123456789abcdef", json.dumps(proof))

    def test_image_bytes_or_preflight_can_not_be_attested_by_filename(self):
        self.image_evidence.write_text(json.dumps({
            "schemaVersion": 1, "status": "local-bytes-match-recorded-pin",
            "imageName": self.image.name, "fileSizeBytes": self.image.stat().st_size,
            "sha256": "b" * 64, "publisherSignatureVerified": False,
            "nativeGuestVerified": False,
        }))
        with self.assertRaises(gate.AcceptanceError):
            self.accept()
        self.assertFalse((self.root / "output.json").exists())

    def test_cross_host_identity_and_post_restore_kernel_change_fail(self):
        with self.assertRaises(ValueError):
            self.accept(IDENTITY.replace("6.1.90-1-generic", "different-kernel"))
        with self.assertRaises(ValueError):
            self.accept(IDENTITY.replace("0123456789abcdef0123456789abcdef",
                                         "fedcba9876543210fedcba9876543210"))
        with self.assertRaises(ValueError):
            self.accept(IDENTITY.replace("RELEASE=1.7.6", "RELEASE=1.8.6"))
        with self.assertRaises(ValueError):
            self.accept(IDENTITY.replace("BUILD_VERSION=1.7.6.15",
                                         "BUILD_VERSION=1.7.6.14"))
        with self.assertRaises(ValueError):
            self.accept(IDENTITY.replace("BUILD_VERSION=1.7.6.15\n", ""))

    def test_actual_full_oval_size_above_generic_32_mib_is_supported_safely(self):
        # A real full vendor OVAL HCP JSON can be 70+ MiB. This synthetic
        # payload tests only file-size handling, never CVE correctness.
        large = self.root / "large-oval.json"
        with large.open("wb") as stream:
            stream.write(b'{"mode":"astra-oval","filler":"')
            segment = b"x" * (1024 * 1024)
            for _ in range(33):
                stream.write(segment)
            stream.write(b'"}')
        parsed, digest = gate.read_large_oval(str(large))
        self.assertEqual(parsed["mode"], "astra-oval")
        self.assertEqual(len(parsed["filler"]), 33 * 1024 * 1024)
        self.assertEqual(digest, hashlib.sha256(large.read_bytes()).hexdigest())
        with self.assertRaises(ValueError):
            gate.read_report(str(large))
        shortcut = self.root / "large-oval-symlink.json"
        shortcut.symlink_to(large)
        with self.assertRaises(ValueError):
            gate.read_large_oval(str(shortcut))

    def test_oval_size_budget_is_strict_and_exclusive_of_special_files(self):
        oversized = self.root / "oversize-oval.json"
        oversized.write_text('{"mode":"astra-oval","extra":"abcdef"}')
        old_budget = gate.MAX_OVAL_REPORT
        try:
            gate.MAX_OVAL_REPORT = 16
            with self.assertRaisesRegex(ValueError, "oval_report_not_bounded_regular_file"):
                gate.read_large_oval(str(oversized))
        finally:
            gate.MAX_OVAL_REPORT = old_budget

    def test_oval_database_or_definition_coverage_mismatch_is_not_pass(self):
        self.oval["scanner"]["database"]["sha256"] = "b" * 64
        self.save()
        with self.assertRaises(gate.AcceptanceError):
            self.accept()
        self.oval["scanner"]["database"]["sha256"] = self.oval_sha
        self.oval["scanner"]["evaluatedDefinitionCount"] = 1
        self.save()
        with self.assertRaises(gate.AcceptanceError):
            self.accept()
        self.oval["scanner"]["evaluatedDefinitionCount"] = 2
        self.oval["scanner"]["partial"] = True
        self.save()
        with self.assertRaises(gate.AcceptanceError):
            self.accept()

    def test_oval_must_belong_to_the_same_verified_asset_and_connection(self):
        for field, invalid in (
            ("assetId", "asset-" + "e" * 64),
            ("generation", 7),
            ("sshHostKeyFingerprint", "SHA256:" + "Z" * 43),
            ("connectionId", "9" * 64),
        ):
            with self.subTest(field=field):
                original = self.oval["assetBinding"][field]
                self.oval["assetBinding"][field] = invalid
                self.save()
                with self.assertRaisesRegex(ValueError, "oval_different_or_unverified_asset_binding"):
                    self.accept()
                self.oval["assetBinding"][field] = original
        self.oval["assetBinding"]["status"] = "unknown"
        self.save()
        with self.assertRaisesRegex(ValueError, "oval_different_or_unverified_asset_binding"):
            self.accept()

    def test_declared_image_protection_mode_cannot_differ_from_filename(self):
        original = json.loads(self.image_evidence.read_text())
        original["securityLevelCandidate"] = "max"
        self.image_evidence.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, "image_bytes_not_bound_to_local_pin"):
            self.accept()

    def test_restored_rule_regression_fails_instead_of_claiming_rollback(self):
        self.reports[2]["findings"][3]["status"] = "failed"
        counts = self.reports[2]["scanner"]["ruleResultCounts"]
        counts["fail"] += 1
        counts["pass"] -= 1
        self.save()
        with self.assertRaises(gate.AcceptanceError):
            self.accept()

    def test_pinned_ssh_rechecks_actual_key_without_user_controlled_ssh_options(self):
        binary_key = b"synthetic-host-key-encoded-body"
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(binary_key).digest()).decode().rstrip("=")
        known = self.root / "known_hosts"
        known.write_text("[test-host]:2222 ssh-ed25519 " +
                         base64.b64encode(binary_key).decode() + "\n")
        known.chmod(0o600)
        private = self.root / "private_ssh"
        private.write_text("fake private key for isolated test")
        private.chmod(0o600)
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            if args[0] == "ssh-keygen":
                return SimpleNamespace(returncode=0, stdout=known.read_bytes())
            return SimpleNamespace(returncode=0, stdout=IDENTITY.encode("utf-8"))
        returned = gate.post_restore_ssh(
            "test-host", 2222, "testuser", private, known,
            fingerprint, runner=runner)
        self.assertEqual(returned, IDENTITY)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", calls[1])
        self.assertIn("PasswordAuthentication=no", calls[1])
        self.assertIn("GlobalKnownHostsFile=/dev/null", calls[1])
        self.assertEqual(calls[1][-1], gate.REMOTE_OBSERVATION)
        with self.assertRaisesRegex(ValueError, "ssh_pinned_host_key_not_exactly_expected"):
            gate.post_restore_ssh(
                "test-host", 2222, "testuser", private, known, FINGERPRINT, runner=runner)
        self.assertEqual(len(calls), 3)

    def test_no_ssh_timeouts_or_server_error_can_create_a_positive_result(self):
        blob = b"synthetic-other-ssh-key"
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        known = self.root / "known_hosts"
        known.write_text("node ssh-ed25519 " + base64.b64encode(blob).decode())
        known.chmod(0o600)
        private = self.root / "client"
        private.write_text("synthetic-key")
        private.chmod(0o600)
        def timed_out(args, **kwargs):
            if args[0] == "ssh-keygen":
                return SimpleNamespace(returncode=0, stdout=known.read_bytes())
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        with self.assertRaisesRegex(gate.AcceptanceError, "post_restore_ssh_timeout"):
            gate.post_restore_ssh("node", 22, "tester", private, known,
                                  fingerprint, runner=timed_out)
        with self.assertRaisesRegex(ValueError, "invalid_ssh_endpoint"):
            gate.post_restore_ssh("-ProxyCommand=sh", 22, "tester",
                                  private, known, fingerprint, runner=timed_out)


if __name__ == "__main__":
    unittest.main()
