"""Offline contract/negative checks; actual Astra 1.7 CI is separate."""
from copy import deepcopy
import json
import os
import tempfile
from pathlib import Path
import unittest

from verify_astra_vm import RULE
import verify_astra17_ova_audit as audit


class NativeAstra17AuditTests(unittest.TestCase):
    def fixture(self):
        before = {"xccdf_org.hcp_rule_sample_" + str(i): "pass" for i in range(17)}
        before[RULE] = "pass"
        after = deepcopy(before)
        after[RULE] = "fail"
        return {"baseline": before, "violation": after,
                "restored": deepcopy(before)}

    def test_exactly_one_observed_rule_and_restoration_are_required(self):
        actual = audit.validate_native_three_stage(self.fixture())
        self.assertEqual(actual["testedRules"], 18)
        self.assertEqual(actual["counts"]["baseline"]["failed"], 0)
        self.assertEqual(actual["counts"]["violation"]["failed"], 1)
        self.assertEqual(actual["counts"]["restored"]["failed"], 0)
        self.assertTrue(actual["restoredMatchesBaseline18Rules"])
        self.assertFalse(actual["fullOsRollbackProven"])
        self.assertFalse(actual["cveCoverageProven"])

    def test_unknown_missing_duplicate_changed_and_extra_rule_rejected(self):
        original = self.fixture()
        variations = []
        case = deepcopy(original)
        case["baseline"].pop(RULE)
        variations.append(case)
        case = deepcopy(original)
        case["restored"][RULE] = "manual"
        variations.append(case)
        case = deepcopy(original)
        case["restored"][RULE] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["violation"][RULE] = "pass"
        variations.append(case)
        case = deepcopy(original)
        case["violation"]["xccdf_org.hcp_rule_sample_0"] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["restored"]["xccdf_org.hcp_rule_sample_0"] = "fail"
        variations.append(case)
        case = deepcopy(original)
        case["violation"]["foreign_rule"] = "pass"
        variations.append(case)
        case = deepcopy(original)
        case["extra"] = case["baseline"]
        variations.append(case)
        for mutant in variations:
            with self.subTest(stage=json.dumps(list(mutant))):
                with self.assertRaises(RuntimeError):
                    audit.validate_native_three_stage(mutant)

    def test_native_ansible_ssh_options_precede_repository_known_hosts_config(self):
        with tempfile.TemporaryDirectory() as d:
            known = Path(d) / "known_hosts"
            known.write_text("[127.0.0.1]:2222 ssh-ed25519 " + "A" * 70 + "\n")
            os.chmod(known, 0o600)
            args = audit.safe_ansible_ssh_args(known)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("UserKnownHostsFile=", args)
            self.assertIn(str(known), args)
            self.assertIn("GlobalKnownHostsFile=/dev/null", args)
            self.assertIn("HostKeyAlgorithms=ssh-ed25519", args)
            self.assertNotIn("StrictHostKeyChecking=no", args)
            self.assertNotIn("~/.ssh/known_hosts", args)
            os.chmod(known, 0o644)
            with self.assertRaises(RuntimeError):
                audit.safe_ansible_ssh_args(known)
            known.unlink()
            known.symlink_to(Path(d) / "elsewhere")
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                audit.safe_ansible_ssh_args(known)

    def test_private_ansible_failure_diagnostics_allow_only_known_categories(self):
        with tempfile.TemporaryDirectory() as d:
            private_log = Path(d) / "ansible-private.log"
            private_log.write_text(
                "UNREACHABLE! Host key verification failed:\\n"
                "SENSITIVE_MACHINE_ID=abc-private-host\\n")
            result = audit.classify_ansible_failure(private_log)
            self.assertEqual(result,
                             ["ssh_host_key_verification", "ssh_unreachable"])
            self.assertNotIn("abc-private-host", json.dumps(result))
            self.assertNotIn("SENSITIVE_MACHINE_ID", json.dumps(result))

    def test_upstream_python_ansible_support_bounds_do_not_claim_compatibility(self):
        self.assertEqual(audit.upstream_ansible_target_range(15), (5, 11))
        self.assertEqual(audit.upstream_ansible_target_range(16), (6, 12))
        self.assertEqual(audit.upstream_ansible_target_range(17), (7, 12))
        self.assertEqual(audit.upstream_ansible_target_range(19), (8, 13))
        self.assertEqual(audit.upstream_ansible_target_range(21), (9, 14))
        self.assertIsNone(audit.upstream_ansible_target_range(99))

    def test_runtime_preflight_checks_actual_guest_python_and_controller_ansible(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        probe = {"nativeHcp": {}}
        def ssh(command, timeout=30):
            self.assertIn("python3 -c", command)
            return "3.7\\n".replace("\\n", "\n")
        fake = SimpleNamespace(returncode=0,
                               stdout="ansible-playbook [core 2.16.3]\\n".replace("\\n", "\n"))
        # This test verifies support-matrix parsing independent of the CI
        # pin; it intentionally mocks 2.16 while the real CI requires 2.17.
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(audit.subprocess, "run", return_value=fake):
            supported = audit.check_ansible_runtime_support(ssh, probe)
        self.assertTrue(supported["targetWithinUpstreamSupportedRange"])
        self.assertEqual(supported["targetPython"], "3.7")
        self.assertEqual(supported["ansibleCore"], "2.16")
        self.assertNotIn("private", json.dumps(supported))
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(audit.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "target_python_outside"):
                audit.check_ansible_runtime_support(
                    lambda *_a, **_k: "3.5\\n".replace("\\n", "\n"),
                    {"nativeHcp": {}})

    def test_lab_only_pinned_controller_bypasses_no_python_or_identity_gate(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        fake = SimpleNamespace(returncode=0,
                               stdout="ansible-playbook [core 2.17.14]\n")
        pin_env = {"HCP_ASTRA17_CI_ANSIBLE_PIN": "2.17.14",
                   "GITHUB_ACTIONS": "true",
                   "RUNNER_ENVIRONMENT": "github-hosted",
                   "RUNNER_TEMP": "/runner-owned"}
        with patch.dict(os.environ, pin_env), \
             patch.object(audit.subprocess, "run", return_value=fake), \
             patch.object(audit.shutil, "which", return_value="/runner-owned/hcp-astra17-ansible217/bin/ansible-playbook"):
            target = {"nativeHcp": {}}
            result = audit.check_ansible_runtime_support(
                lambda *_a, **_k: "3.7\n", target)
            self.assertTrue(result["targetWithinUpstreamSupportedRange"])
            self.assertTrue(result["isolatedLabAnsibleVersionPinVerified"])
            self.assertTrue(result["labOnlyUnsupportedAnsibleEol"])
            self.assertEqual(result["ansibleCoreExactVersion"], "2.17.14")
            with self.assertRaisesRegex(RuntimeError, "target_python_outside"):
                audit.check_ansible_runtime_support(
                    lambda *_a, **_k: "3.5\n", {"nativeHcp": {}})
        with patch.dict(os.environ, {**pin_env, "RUNNER_ENVIRONMENT": "self-hosted"}), \
             patch.object(audit.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "lab_only_ansible_pin_context_invalid"):
                audit.check_ansible_runtime_support(
                    lambda *_a, **_k: "3.7\n", {"nativeHcp": {}})

    def test_native_workflows_only_isolate_legacy_ansible_on_ephemeral_runner(self):
        workflow = (audit.ROOT / ".github/workflows/astra17-ova-hcp.yml").read_text()
        self.assertIn("ansible-core==2.17.14", workflow)
        self.assertIn("test \"$RUNNER_ENVIRONMENT\" = github-hosted", workflow)
        self.assertIn("HCP_ASTRA17_CI_ANSIBLE_PIN=2.17.14", workflow)
        self.assertIn("RUNNER_TEMP/hcp-astra17-ansible217", workflow)
        self.assertNotIn("sudo pip install", workflow)

    def test_nonzero_raw_probe_cannot_skip_to_native_scanner(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            known = root / "known_hosts"
            known.write_text("pinned-key\\n")
            os.chmod(known, 0o600)
            def failed(args, **kwargs):
                self.assertEqual(args[0], "ansible")
                self.assertIn("ANSIBLE_SSH_ARGS", kwargs["env"])
                kwargs["stdout"].write(b"fatal host: private-key omitted")
                return SimpleNamespace(returncode=2)
            protocol = {"nativeHcp": {}}
            with patch.object(audit.subprocess, "run", side_effect=failed):
                with self.assertRaisesRegex(RuntimeError, "ansible_transport_probe_failed"):
                    audit.native_ansible_transport_preflight(root, protocol)
            self.assertEqual(protocol["nativeHcp"]["ansibleTransportFailedAt"], "ssh_raw")
            self.assertEqual(protocol["nativeHcp"]["ansibleTransportStages"], [])
            self.assertEqual(protocol["nativeHcp"]["ansibleFailureReturnCode"], 2)
            self.assertNotIn("private-key", json.dumps(protocol))


    def test_target_sds_probe_codes_and_component_hints_never_expose_private_text(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            report = folder / "normalized-private.json"
            secret = "SENSITIVE_PRIVATE_GUEST_NAME_DO_NOT_SHARE"
            report.write_text(json.dumps({
                "mode": "openscap",
                "scanner": {
                    "available": True,
                    "partial": True,
                    "scannerExitCode": 1,
                    "reason": ("No such file or directory astra-platform-oval.xml; "
                               "target_info_rc=1; target_schema_rc=0; "
                               "check.py " + secret),
                },
                "findings": [],
            }))
            observed = audit.native_openscap_failure_observation(
                folder / "absent-arf", folder / "missing-datastream", report)
            self.assertEqual(
                observed["targetReadOnlySdsProbeExitCodes"],
                {"oscap_info": 1, "oscap_schema": 0},
            )
            self.assertEqual(
                observed["componentReferenceCategories"],
                ["oval_component_referenced_in_error",
                 "sce_script_referenced_in_error"],
            )
            self.assertIn("openscap_missing_file", observed["reasonCategories"])
            self.assertNotIn(secret, json.dumps(observed))
            self.assertNotIn(str(folder), json.dumps(observed))
            self.assertNotIn("astra-platform-oval.xml", json.dumps(observed))
            self.assertEqual(
                observed["status"], "native-openscap-original-evidence-incomplete")

    def test_target_sds_inspection_is_read_only_and_additional_to_schema_gate(self):
        playbook = (
            audit.ROOT / "ansible/playbooks/openscap-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Inspect controller-validated SDS on target using read-only oscap info",
            playbook)
        self.assertIn(
            "Check controller-validated SDS schema with the target OpenSCAP engine",
            playbook)
        self.assertIn("openscap_target_sds_info.rc", playbook)
        self.assertIn("openscap_target_sds_validate.rc", playbook)
        self.assertIn("oscap, info", playbook)
        self.assertIn("oscap, ds, sds-validate", playbook)
        self.assertIn(
            "openscap_evaluated_content.stat.checksum == "
            "openscap_controller_built_file.stat.checksum", playbook)
        self.assertNotIn("--skip-validation", playbook)

    def test_failed_scap_report_is_diagnosed_only_as_allowlisted_aggregate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw = root / ".native.arf.xml"
            stream = root / ".native.arf.xml.datastream.xml"
            report = root / "native-openscap.json"
            private_secret = "REDACT_THIS_RANDOM_PRIVATE_USER_VALUE"
            report.write_text(json.dumps({
                "mode": "openscap", "partial": True,
                "scanner": {
                    "available": False, "partial": True,
                    "reason": "Не удалось подготовить встроенный профиль Astra: "
                              "compose=1, dictionary=1, validation=1; "
                              "SCE plugin not available " + private_secret,
                    "partialReasons": ["Invalid option; /hidden/path " + private_secret],
                    "scannerExitCode": 2,
                },
                "findings": [{"description": "Profile not found " + private_secret}],
            }))
            result = audit.native_openscap_failure_observation(raw, stream, report)
            self.assertFalse(result["rawArfPresent"])
            self.assertFalse(result["executedDatastreamPresent"])
            self.assertTrue(result["normalizedReportPresent"])
            self.assertFalse(result["reportedScannerAvailable"])
            self.assertTrue(result["reportedPartial"])
            self.assertEqual(result["reportedScannerExitCode"], 2)
            self.assertEqual(result["normalizedFindingCount"], 1)
            self.assertEqual(result["preparationExitCodes"],
                             {"compose": 1, "dictionary": 1, "validation": 1})
            self.assertIn("sce_plugin_unavailable", result["reasonCategories"])
            self.assertIn("openscap_unsupported_command", result["reasonCategories"])
            self.assertIn("openscap_profile_missing", result["reasonCategories"])
            self.assertNotIn(private_secret, json.dumps(result))
            self.assertNotIn("/hidden/path", json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))
            # Missing source file never becomes PASS even with normalized JSON.
            self.assertEqual(result["status"],
                             "native-openscap-original-evidence-incomplete")

    def test_native_openscap_complete_artifacts_still_require_full_validation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw, datastream, normalized = (
                root / "raw.arf", root / "bundle.xml", root / "normalized.json")
            raw.write_text("fake ARF fixture -- not evidence")
            datastream.write_text("fake datastream fixture")
            normalized.write_text(json.dumps({
                "mode": "openscap",
                "scanner": {"available": True, "partial": False,
                            "scannerExitCode": 0},
                "findings": [],
            }))
            result = audit.native_openscap_failure_observation(
                raw, datastream, normalized)
            self.assertTrue(result["rawArfPresent"])
            self.assertTrue(result["executedDatastreamPresent"])
            self.assertTrue(result["normalizedReportPresent"])
            self.assertEqual(result["status"],
                             "native-openscap-original-evidence-incomplete")
            self.assertFalse(result["reportedPartial"])
            # This is only diagnostic. Real acceptance requires raw_results()
            # and verify_baseline_report() checks in production-derived runner.

    def test_opt_in_controller_composition_never_bypasses_schema_validation(self):
        source = (audit.ROOT / "ansible/playbooks/openscap-audit.yml").read_text()
        self.assertIn("openscap_compose_on_controller", source)
        self.assertIn("controller source checksum differs", source.lower())
        self.assertIn("sds-validate", source)
        self.assertIn("openscap_controller_built_file.stat.checksum", source)
        self.assertIn("openscap_evaluated_content.stat.checksum", source)
        self.assertIn("- not (openscap_compose_on_controller | bool)", source)
        self.assertIn("controllerSideSdsSchemaValidationRequested", Path(audit.__file__).read_text())

    def test_real_hcp_playbook_and_evidence_paths_are_bound_to_fixed_repository(self):
        content = Path(audit.__file__).read_text(encoding="utf-8")
        self.assertIn('run_playbook(work, reports, "collect-facts"', content)
        self.assertIn('run_playbook(work, reports, "package-inventory"', content)
        self.assertIn('run_playbook(work, reports, "openscap-audit"', content)
        self.assertIn('verify_baseline_report(', content)
        self.assertIn('"hcp_openscap_keep_arf": True', content)
        self.assertIn('finally:', content)
        self.assertNotIn("shell=True", content)
        self.assertNotIn("StrictHostKeyChecking=no", content)
        self.assertIn('"fullOvalEvaluated": False', content)

    def test_original_report_reader_rejects_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            report = folder / "report.json"
            report.write_text(json.dumps({"real": True}))
            self.assertEqual(audit.load_private_json(report), {"real": True})
            linked = folder / "linked.json"
            linked.symlink_to(report)
            with self.assertRaises(RuntimeError):
                audit.load_private_json(linked)
            with self.assertRaises(RuntimeError):
                audit.load_private_json(report, limit=2)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                audit.load_private_json(folder / "missing.json")

    def test_original_smoke_path_default_still_remains_separate(self):
        smoke = (audit.ROOT / "deployment/tests/verify_astra17_ova_kvm.py").read_text()
        self.assertIn("native_hcp_three_stage=False", smoke)
        self.assertIn('"realNative18RuleThreeStageObserved": False', smoke)
        self.assertIn('"fullNative18RuleAcceptance": False', smoke)
        self.assertIn("original_identity=second", smoke)
        self.assertIn("native_hcp_three_stage=args.native_hcp_three_stage", smoke)


if __name__ == "__main__":
    unittest.main()
