"""Network-free tests: only synthetic TAR data, never a real Astra image."""
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("download_astra17_ova.py")
SPEC = importlib.util.spec_from_file_location("download_astra17_ova", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sample_ova():
    data = io.BytesIO()
    with tarfile.open(mode="w", fileobj=data, format=tarfile.USTAR_FORMAT) as archive:
        content = b"synthetic ordinary OVF, definitely NOT Astra Linux" * 150
        info = tarfile.TarInfo("synthetic.ovf")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return data.getvalue()


class FakeResponse:
    def __init__(self, data, url, status=200, advertised_length=None):
        self.data = io.BytesIO(data)
        self.url = url
        self.status = status
        self.headers = {"Content-Length": str(len(data)) if advertised_length is None
                        else advertised_length}
        self.closed = False

    def read(self, size):
        return self.data.read(size)

    def geturl(self):
        return self.url

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class DownloadAstra17Test(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hcp-ova-remote-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.data = sample_ova()
        self.sha = hashlib.sha256(self.data).hexdigest()
        self.image_url, self.sha_url = MODULE.fixed_urls("base")
        self.calls = []
        self.progresses = []
        self.now = 0

    def opener(self, url, timeout=30):
        self.calls.append(url)
        self.assertEqual(timeout, 30)
        if url == self.sha_url:
            return FakeResponse(self.sha.encode(), url)
        if url == self.image_url:
            return FakeResponse(self.data, url)
        self.fail("Unexpected network URL: " + url)

    def clock(self):
        self.now += 0.1
        return self.now

    def run_download(self, **kwargs):
        return MODULE.download("base", self.root, opener=self.opener,
                               progress=lambda size, total: self.progresses.append((size, total)),
                               clock=self.clock, **kwargs)

    def test_exact_vendor_source_is_pinned_but_never_attested(self):
        record = self.run_download()
        image = self.root / MODULE.FILENAMES["base"]
        meta = self.root / (image.name + ".source.json")
        self.assertEqual(image.read_bytes(), self.data)
        self.assertEqual(json.loads(meta.read_text()), record)
        self.assertEqual(self.calls, [self.sha_url, self.image_url])
        self.assertEqual(record["sha256"], self.sha)
        self.assertFalse(record["publisherSignatureVerified"])
        self.assertFalse(record["nativeGuestVerified"])
        self.assertFalse(record["operatorIndependentPinSupplied"])
        self.assertIsNone(record["cveSourceApplicable"])
        self.assertEqual(record["bytes"], len(self.data))
        self.assertEqual(image.stat().st_mode & 0o777, 0o600)
        self.assertEqual(meta.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.progresses[-1], (len(self.data), len(self.data)))
        self.assertEqual(list(self.root.glob("*.partial")), [])
        with self.assertRaises(ValueError):
            self.run_download()
        self.assertEqual(image.read_bytes(), self.data)

    def test_optional_independent_pin_must_match_both_metadata_and_download(self):
        record = self.run_download(expected_sha256=self.sha, expected_bytes=len(self.data))
        self.assertTrue(record["operatorIndependentPinSupplied"])
        self.assertTrue(record["operatorPinMatched"])
        self.assertFalse(record["publisherSignatureVerified"])

    def test_stale_independent_digest_rejects_before_image_download(self):
        with self.assertRaisesRegex(ValueError, "differs from independently"):
            self.run_download(expected_sha256="c" * 64, expected_bytes=len(self.data))
        self.assertEqual(self.calls, [self.sha_url])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unexpected_sidecar_digest_or_remote_redirect_fails_closed(self):
        def broken_sidecar(url, timeout=30):
            return FakeResponse(b"not-a-checksum", url)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            MODULE.download("base", self.root, opener=broken_sidecar,
                            progress=lambda *_: None)
        def redirect(url, timeout=30):
            return FakeResponse(self.sha.encode(), "https://foreign.invalid/takeover")
        with self.assertRaisesRegex(ValueError, "redirected"):
            MODULE.download("base", self.root, opener=redirect,
                            progress=lambda *_: None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_ova_and_short_stream_do_not_publish_partials(self):
        bad = bytes(b"Z" * len(self.data))
        def swapped(url, timeout=30):
            return FakeResponse(self.sha.encode() if url.endswith(".sha256") else bad, url)
        with self.assertRaisesRegex(ValueError, "checksum"):
            MODULE.download("base", self.root, opener=swapped, progress=lambda *_: None)
        def truncated(url, timeout=30):
            if url.endswith(".sha256"):
                return FakeResponse(self.sha.encode(), url)
            return FakeResponse(self.data[:-5], url, advertised_length=str(len(self.data)))
        with self.assertRaisesRegex(ValueError, "truncated"):
            MODULE.download("base", self.root, opener=truncated, progress=lambda *_: None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_refuses_world_readable_destination_and_symlinked_destination(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.run_download()
        self.root.chmod(0o700)
        other = self.root.parent / (self.root.name + "-real")
        other.mkdir(mode=0o700)
        self.addCleanup(lambda: other.rmdir())
        alias = self.root / "alias"
        alias.symlink_to(other, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            MODULE.download("base", alias, opener=self.opener, progress=lambda *_: None)

    def test_mismatched_http_content_length_is_not_a_success(self):
        def invalid_header(url, timeout=30):
            if url.endswith(".sha256"):
                return FakeResponse(self.sha.encode(), url)
            return FakeResponse(self.data, url, advertised_length=str(len(self.data) + 1))
        with self.assertRaisesRegex(ValueError, "truncated"):
            MODULE.download("base", self.root, opener=invalid_header, progress=lambda *_: None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_bounded_transfer_duration_cleans_up_temp_files(self):
        def advanced_clock():
            self.now += 10
            return self.now
        with self.assertRaisesRegex(ValueError, "time budget"):
            MODULE.download("base", self.root, opener=self.opener,
                            progress=lambda *_: None, clock=advanced_clock, max_seconds=1)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_only_three_fixed_ova_names_and_no_user_controlled_url(self):
        for level in ("base", "adv", "max"):
            source, checksum = MODULE.fixed_urls(level)
            self.assertTrue(source.startswith(MODULE.ROOT))
            self.assertEqual(checksum, source + ".sha256")
            self.assertNotIn("?", source)
        for level in ("../", "2027", "latest", "base?param=1"):
            with self.assertRaises(ValueError):
                MODULE.fixed_urls(level)


if __name__ == "__main__":
    unittest.main()
