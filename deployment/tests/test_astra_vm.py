"""Reject misleading acceptance evidence before attempting a guest launch."""
import copy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest

from verify_astra_vm import download, verify_oval_report


class DownloadResponse(io.BytesIO):
    def geturl(self):
        return "https://publisher.invalid/pinned-image"


class AstraVmAcceptanceTests(unittest.TestCase):
    def test_download_requires_exact_pinned_bytes_and_does_not_publish_failure(self):
        content = b"publisher fixture"
        source = {"url": "https://publisher.invalid/pinned-image", "bytes": len(content),
                  "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "image"
            for unexpected in (content + b"x", content[:-1], b"x" * len(content)):
                with self.subTest(unexpected=unexpected), self.assertRaises(ValueError):
                    download(source, target, opener=lambda *_args, **_kwargs: DownloadResponse(unexpected))
                self.assertFalse(target.exists())
                self.assertEqual(list(Path(temporary).iterdir()), [])
            download(source, target, opener=lambda *_args, **_kwargs: DownloadResponse(content))
            self.assertEqual(target.read_bytes(), content)

    def report(self, expected="true"):
        source = {"sha256": "a" * 64, "definitionCount": 2, "definitionId": "oval:example:def:1", "cve": "CVE-2024-5535"}
        report = {"scanner": {"evaluationPerformed": True, "hostIdentity": {"id": "astra", "astraVersion": "1.8.1"},
                              "database": {"sha256": source["sha256"], "checksumVerified": True},
                              "definitionCount": 2, "definitionResults": [{"id": source["definitionId"], "result": expected, "cveIds": [source["cve"]]}],
                              "partial": True, "partialReasons": ["An unrelated definition is unknown"], "resultSha256": "b" * 64},
                  "summary": {"score": None}, "findings": []}
        if expected == "true":
            report["findings"].append({"id": source["definitionId"], "status": "failed", "vulnerability": {"cveIds": [source["cve"]]}})
        return source, report

    def test_positive_and_fixed_controls_preserve_partial(self):
        for expected in ("true", "false"):
            source, report = self.report(expected)
            proof = verify_oval_report(report, source, "1.8.1", expected)
            self.assertTrue(proof["partial"])
            self.assertEqual(proof["result"], expected)

    def test_empty_unknown_or_forged_source_is_not_a_success(self):
        source, original = self.report()
        changes = [lambda r: r["scanner"].update(evaluationPerformed=False),
                   lambda r: r["scanner"].update(definitionResults=[]),
                   lambda r: r["scanner"]["definitionResults"][0].update(result="unknown"),
                   lambda r: r["scanner"]["database"].update(sha256="c" * 64),
                   lambda r: r["scanner"]["database"].update(checksumVerified=False),
                   lambda r: r["scanner"]["hostIdentity"].update(id="ubuntu"),
                   lambda r: r.update(findings=[])]
        for change in changes:
            report = copy.deepcopy(original)
            change(report)
            with self.assertRaises(AssertionError):
                verify_oval_report(report, source, "1.8.1", "true")

    def test_fixed_control_cannot_keep_positive_finding(self):
        source, report = self.report("false")
        report["findings"] = self.report("true")[1]["findings"]
        with self.assertRaises(AssertionError):
            verify_oval_report(report, source, "1.8.1", "false")


if __name__ == "__main__":
    unittest.main()
