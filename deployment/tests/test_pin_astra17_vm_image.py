"""Only synthetic OVA containers; no claim of real Astra 1.7 installation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("pin_astra17_vm_image.py")
SPEC = importlib.util.spec_from_file_location("pin_astra17_vm_image", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
IMAGE = "alse-1.7.6.uu2-base-virtualbox-mg15.3.1-amd64.ova"


class ImagePinTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hcp-astra17-image-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / IMAGE
        with tarfile.open(self.file, "w") as archive:
            data = b"synthetic OVF only, not an Astra guest" * 64
            from io import BytesIO
            info = tarfile.TarInfo(name="test.ovf")
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
        self.original = self.file.read_bytes()
        self.expected = hashlib.sha256(self.original).hexdigest()

    def cli(self, *more):
        cmd = [sys.executable, str(SCRIPT), "--file", str(self.file),
               "--expected-sha256", self.expected,
               "--expected-bytes", str(len(self.original)),
               "--reference", "OPERATOR-RECORD-0001",
               "--output", str(self.root / "evidence.json"), *more]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_local_pin_is_not_a_publisher_or_native_vm_attestation(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.root / "evidence.json").read_text())
        self.assertEqual(record["status"], "local-bytes-match-recorded-pin")
        self.assertEqual(record["sha256"], self.expected)
        self.assertEqual(record["fileSizeBytes"], len(self.original))
        self.assertEqual(record["expectedInsideGuest"], "/etc/astra_version 1.7.6.15")
        self.assertIs(record["publisherSignatureVerified"], False)
        self.assertIs(record["nativeGuestVerified"], False)
        self.assertIsNone(record["cveSourceApplicable"])
        self.assertEqual((self.root / "evidence.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.file.read_bytes(), self.original)
        self.assertNotEqual(self.cli().returncode, 0, "Evidence cannot be overwritten")

    def test_bad_digest_size_and_nonarchive_are_rejected(self):
        self.assertNotEqual(self.cli("--expected-sha256", "a" * 64).returncode, 0)
        self.assertNotEqual(self.cli("--expected-bytes", str(len(self.original) + 1)).returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.file.write_bytes(b"x" * len(self.original))
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())

    def test_symlink_and_unsupported_release_names_are_rejected(self):
        original = self.root / "original.ova"
        self.file.rename(original)
        self.file.symlink_to(original)
        self.assertNotEqual(self.cli().returncode, 0)
        self.file.unlink()
        original.rename(self.file)
        renamed = self.root / "alse-1.8.6-base-virtualbox-mg15.3.1-amd64.ova"
        self.file.rename(renamed)
        self.file = renamed
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())

    def test_three_declared_security_levels_match_only_pinned_name(self):
        for level in ("base", "adv", "max"):
            record = MOD.assess(
                IMAGE.replace("-base-", "-" + level + "-"),
                self.expected, len(self.original), "INDEPENDENT-REVIEW-01",
                len(self.original), self.expected)
            self.assertEqual(record["securityLevelCandidate"], level)
            self.assertFalse(record["publisherSignatureVerified"])

    def test_source_output_collision_and_secret_reference_rejected(self):
        self.assertNotEqual(self.cli("--output", str(self.file)).returncode, 0)
        self.assertNotEqual(self.cli("--reference", "https://user:pass@host/file").returncode, 0)
        self.assertEqual(self.file.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
