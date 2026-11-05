"""Offline negative tests for pinned official Astra 1.7 OVA KVM smoke gate."""
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

import verify_astra17_ova_kvm as smoke


def synthetic_tar(items):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, payload in items:
            entry = tarfile.TarInfo(name)
            if kind == "file":
                entry.size = len(payload)
                archive.addfile(entry, io.BytesIO(payload))
            elif kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = "../private"
                archive.addfile(entry)
            else:
                raise AssertionError("unexpected synthetic tar fixture type")
    return buffer.getvalue()


class OvaNativePreflightTests(unittest.TestCase):
    def test_ci_caches_only_exact_vendor_public_ova_even_when_scan_fails(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/astra17-ova-hcp.yml").read_text()
        self.assertIn("actions/cache/restore@v4", workflow)
        self.assertIn("actions/cache/save@v4", workflow)
        self.assertIn("id: verified-public-ova", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("sha256sum --check --strict --status", workflow)
        self.assertIn("test ! -L", workflow)
        self.assertIn("test -f", workflow)
        self.assertIn('test "$(stat -c %s "$image")" -eq 427995648', workflow)
        self.assertIn("steps.verified-public-ova.outputs.verified == 'true'", workflow)
        self.assertIn("steps.public-ova-cache.outputs.cache-hit != 'true'", workflow)
        self.assertNotIn("hcp-real-astra17-ova-hcp-private\n          key:", workflow)



    def test_original_ova_cache_rehashes_before_and_after_copy(self):
        import hashlib
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "public-cache"
            cache.mkdir(mode=0o700)
            original = b"FAKE OVA synthetic bytes, not Astra!" * 85
            cache_image = cache / smoke.FILENAMES["base"]
            cache_image.write_bytes(original)
            cache_image.chmod(0o600)
            work = root / "isolated-work"
            work.mkdir(mode=0o700)
            env = {"HCP_ASTRA17_PUBLIC_OVA_CACHE_DIR": str(cache),
                   "RUNNER_TEMP": str(root), "GITHUB_ACTIONS": "true",
                   "RUNNER_ENVIRONMENT": "github-hosted"}
            with patch.dict(os.environ, env), \
                 patch.object(smoke, "EXPECTED_BYTES", len(original)), \
                 patch.object(smoke, "EXPECTED_SHA256", hashlib.sha256(original).hexdigest()):
                result = smoke.exact_pinned_original_ova(
                    work, opener=None, progress=lambda *_: None)
                self.assertTrue(result["cacheReused"])
                target = work / smoke.FILENAMES["base"]
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                target.unlink()
                cache_image.write_bytes(original + b"CORRUPT")
                with self.assertRaises((RuntimeError, ValueError)):
                    smoke.exact_pinned_original_ova(
                        work, opener=None, progress=lambda *_: None)
            with patch.dict(os.environ, {**env,
                     "HCP_ASTRA17_PUBLIC_OVA_CACHE_DIR": str(root.parent)}):
                with self.assertRaises(RuntimeError):
                    smoke.exact_pinned_original_ova(
                        work, opener=None, progress=lambda *_: None)


    def test_source_pins_and_security_claims_are_fixed(self):
        self.assertEqual(smoke.EXPECTED_BYTES, 427995648)
        self.assertEqual(smoke.EXPECTED_SHA256,
                         "72ccb335f4c46b5b6d1410cfe0c08f648f95a5e6fd1026f6e0b2d65d8b7ebf6e")
        self.assertEqual(smoke.FILENAMES["base"],
                         "alse-1.7.6.uu2-base-virtualbox-mg15.3.1-amd64.ova")
        text = Path(smoke.__file__).read_text()
        self.assertIn('"fullNative18RuleAcceptance": False', text)
        self.assertIn('"ovalEvaluationPerformed": False', text)
        self.assertIn('"hardenedProdReady": False', text)
        self.assertNotIn("tar.extractall(", text)

    def test_safe_tar_one_vmdk_and_ovf(self):
        fixture = synthetic_tar([
            ("one.ovf", "file", b"synthetic ovf"),
            ("one-disk001.vmdk", "file", b"fake disk bytes"),
            ("one.mf", "file", b"manifest"),
        ])
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            image = root / "test.ova"
            image.write_bytes(fixture)
            out = root / "only.vmdk"
            size = smoke.extract_vmdk(image, out)
            self.assertEqual(size, len(b"fake disk bytes"))
            self.assertEqual(out.read_bytes(), b"fake disk bytes")
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_special_files_unsafe_paths_extra_disks_and_unexpected_files_rejected(self):
        regular = [("one.ovf", "file", b"a"), ("one.vmdk", "file", b"abc")]
        negative = [
            regular + [("../secret", "file", b"evil")],
            regular + [("secret", "symlink", b"")],
            regular + [("two.vmdk", "file", b"second")],
            regular + [("settings.json", "file", b"unexpected")],
            [("one.vmdk", "file", b"disk")],
            [("one.ovf", "file", b"ovf")],
        ]
        for files in negative:
            with self.subTest(names=[z[0] for z in files]):
                with tempfile.TemporaryDirectory() as d:
                    image = Path(d) / "test.ova"
                    image.write_bytes(synthetic_tar(files))
                    with self.assertRaises(RuntimeError):
                        smoke.extract_vmdk(image, Path(d) / "out.vmdk")

    def test_genuine_ssh_guest_identity_strict_version_and_machine_id(self):
        identity = (
            "NAME=Astra Linux\nID=astra\n"
            "HCP_RELEASE=1.7.6\nHCP_BUILD=1.7.6.15\n"
            "HCP_ARCH=x86_64\nHCP_KERNEL=5.10.99-astra\n"
            "HCP_MACHINE_ID=0123456789abcdef0123456789abcdef\n"
        )
        result = smoke.observed_native_identity(identity)
        self.assertEqual(result["pointRelease"], "1.7.6")
        self.assertEqual(result["fullBuild"], "1.7.6.15")
        self.assertNotIn("0123456789abcdef", json.dumps(result))
        for modified in (
            identity.replace("HCP_RELEASE=1.7.6", "HCP_RELEASE=1.7.7"),
            identity.replace("HCP_BUILD=1.7.6.15", "HCP_BUILD=1.7.6.14"),
            identity.replace("ID=astra", "ID=debian"),
            identity.replace("HCP_ARCH=x86_64", "HCP_ARCH=arm64"),
            identity.replace("0123456789abcdef0123456789abcdef", "0" * 32),
            identity + "HCP_BUILD=1.7.6.15\n",
        ):
            with self.subTest(sha=hash(modified)):
                with self.assertRaises(RuntimeError):
                    smoke.observed_native_identity(modified)

    def test_host_key_exact_local_port_and_only_one_ed25519(self):
        port = 43211
        valid = f"[127.0.0.1]:{port} ssh-ed25519 " + "A" * 75 + "\n"
        self.assertEqual(smoke.trusted_local_scan(valid, port), valid)
        for malicious in (
            valid + valid,
            valid.replace("127.0.0.1", "192.0.2.1"),
            valid.replace("ssh-ed25519", "ssh-rsa"),
            valid.replace(str(port), str(port + 1)),
        ):
            with self.assertRaises(RuntimeError):
                smoke.trusted_local_scan(malicious, port)


if __name__ == "__main__":
    unittest.main()
