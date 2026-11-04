"""Pure guardrails for a real-Docker CI restore drill (no Docker in unit tests)."""
import importlib.util
import json
import os
from pathlib import Path
from unittest import mock
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "lab/verify-restored-controller.py"
SPEC = importlib.util.spec_from_file_location("hcp_lab_restored_controller", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RestoreDrillContractTests(unittest.TestCase):
    def test_host_comparison_is_order_invariant_and_only_public_structural_metadata(self):
        hosts = [
            {"alias": "lab-insecure", "reportCount": 5, "credentialReady": True,
             "credentialId": "a" * 64, "credentialFingerprint": "SHA256:test",
             "riskSummary": {"critical": 1}, "address": "secret-address"},
            {"alias": "lab-scheduled", "reportCount": 2, "credentialReady": False,
             "credentialId": None, "credentialFingerprint": None,
             "lastReport": {"createdAt": "any"}},
        ]
        first = MODULE.safe_host_summary(hosts)
        self.assertEqual(first, MODULE.safe_host_summary(list(reversed(hosts))))
        self.assertEqual([h["alias"] for h in first], ["lab-insecure", "lab-scheduled"])
        self.assertEqual(first[0]["reportCount"], 5)
        self.assertEqual(first[0]["credentialId"], "a" * 64)
        self.assertNotIn("riskSummary", first[0])
        self.assertNotIn("address", first[0])
        self.assertNotIn("lastReport", first[1])

    def test_source_volume_must_be_hcp_lab_named_volume_only(self):
        values = [
            ({"Destination": "/var/lib/hcp", "Type": "volume",
              "Name": "hcp-lab_hcp-lab-state"}, True),
            ({"Destination": "/var/lib/hcp", "Type": "volume",
              "Name": "my-production-hcp"}, False),
            ({"Destination": "/var/lib/hcp", "Type": "bind",
              "Name": "hcp-lab_state"}, False),
            ({"Destination": "/var/lib/other", "Type": "volume",
              "Name": "hcp-lab_state"}, False),
        ]
        for item, allowed in values:
            with self.subTest(item=item):
                with mock.patch.object(MODULE, "docker", return_value=json.dumps([item])):
                    if allowed:
                        self.assertEqual(MODULE.find_source_volume("fixture"), item["Name"])
                    else:
                        with self.assertRaises(AssertionError):
                            MODULE.find_source_volume("fixture")

    def test_network_must_be_unique_lab_only(self):
        for networks, allowed in [
            ({"hcp-lab_lab": {}, "bridge": {}}, True),
            ({"production": {}}, False),
            ({"hcp-lab_lab": {}, "hcp-lab-other": {}}, False),
        ]:
            with mock.patch.object(MODULE, "docker", return_value=json.dumps(networks)):
                if allowed:
                    self.assertEqual(MODULE.find_network("fixture"), "hcp-lab_lab")
                else:
                    with self.assertRaises(AssertionError):
                        MODULE.find_network("fixture")

    def test_restore_drill_refuses_execution_outside_hosted_ci_before_docker_access(self):
        scenarios = [
            {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"},
            {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
            {"GITHUB_ACTIONS": "", "RUNNER_ENVIRONMENT": ""},
        ]
        for env in scenarios:
            with self.subTest(env=env):
                with mock.patch.dict(os.environ, env), mock.patch.object(
                    MODULE, "docker", side_effect=AssertionError("Docker must not be called")
                ):
                    with self.assertRaisesRegex(AssertionError, "Only disposable"):
                        MODULE.main()

    def test_image_identity_requires_immutable_digest(self):
        with mock.patch.object(MODULE, "docker",
                               return_value="sha256:" + "a" * 64 + "\n"):
            self.assertEqual(MODULE.full_image("fixture"), "sha256:" + "a" * 64)
        for value in ("debian:latest", "sha256:abc", "my-image"):
            with mock.patch.object(MODULE, "docker", return_value=value):
                with self.assertRaises(AssertionError):
                    MODULE.full_image("fixture")

    def test_sanitized_protocol_labels_are_bounded_to_disposable_lab(self):
        self.assertEqual(MODULE.RESTORED_URL, "http://127.0.0.1:3002")
        self.assertEqual(MODULE.SOURCE_URL, "http://127.0.0.1:3001")
        self.assertIn("hcp-lab_", MODULE.find_source_volume.__code__.co_consts)


if __name__ == "__main__":
    unittest.main()
