"""Offline tests for native acceptance *gates*, not actual Astra 1.7 tests."""
from copy import deepcopy
import json
from pathlib import Path
import re
import tempfile
import unittest

import verify_astra17_vm as vm
from astra17_cloud_init_forensics import validated_evidence, collect_guest_evidence, GUEST_PROBE


class NativeAstra17GateTests(unittest.TestCase):
    def test_official_exact_release_sources_are_sha_and_size_pinned(self):
        sources = json.loads(vm.SOURCE.read_text())
        self.assertEqual(sources["schemaVersion"], 1)
        self.assertEqual(set(sources["images"]), {"base", "adv", "max"})
        self.assertEqual(sources["reviewedAt"], "2026-11-04")
        for level, image in sources["images"].items():
            filename = "alse-1.7.6.uu2-%s-cloudinit-mg15.3.1-amd64.qcow2" % level
            self.assertEqual(image["url"], "https://registry.astralinux.ru/artifactory/mg-generic/alse/cloudinit/" + filename)
            self.assertEqual(image["metadataUrl"], "https://registry.astralinux.ru/artifactory/api/storage/mg-generic/alse/cloudinit/" + filename)
            self.assertRegex(image["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(image["bytes"], 400 * 1024 * 1024 - 15 * 1024 * 1024)
            self.assertLess(image["bytes"], 500 * 1024 * 1024)
            self.assertNotIn("latest", image["url"])
        self.assertEqual(sources["images"]["base"]["sha256"],
                         "654aae66598bb4e5e38efc4fc18e2c9cb53170713a31728ff502f04dabf1838e")
        self.assertEqual(sources["images"]["adv"]["sha256"],
                         "03b72d0e058a7feabfb3e2e0b7636f7f4bd331f861f76ec8843cf9efad873c49")
        self.assertEqual(sources["images"]["max"]["sha256"],
                         "0d0e10096c9df52d7eab25bc4456ee9d4210bc912d80d73d4a7b62c01527b2a4")
        self.assertEqual(sources["oval"]["sha256"],
                         "c9364c80d664907dc472475d2ef57689c314abecede7a58e7e9dae8250891d17")
        self.assertEqual(sources["oval"]["bytes"], 134668815)
        self.assertIn("1.7_x86-64", sources["oval"]["url"])
        self.assertIn("not an independent", sources["sourceTrust"])

    def test_actual_vendor_xml_must_contain_real_definition_elements(self):
        with tempfile.TemporaryDirectory(prefix="astra17-oval-count-") as tmp:
            path = Path(tmp) / "source.xml"
            path.write_text(
                '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
                '<definitions><definition id="oval:astra:def:11"/>'
                '<definition id="oval:astra:def:12"/></definitions>'
                '</oval_definitions>', encoding="utf-8")
            self.assertEqual(vm.full_oval_definition_count(path), 2)
            path.write_text('<oval_definitions/>', encoding="utf-8")
            with self.assertRaises(AssertionError):
                vm.full_oval_definition_count(path)

    def fixture(self):
        source = json.loads(vm.SOURCE.read_text())["oval"]
        report = {
            "mode": "astra-oval", "inventoryHost": "hcp-real-astra",
            "summary": {"score": None},
            "scanner": {
                "available": True,
                "evaluationPerformed": True,
                "exitCode": 0,
                "partial": False,
                "partialReasons": [],
                "hostIdentity": {"id": "astra", "astraVersion": "1.7.6"},
                "database": {"sha256": source["sha256"],
                             "checksumVerified": True},
                "definitionCount": 3,
                "evaluatedDefinitionCount": 3,
                "definitionResults": [
                    {"id": "oval:astra:def:11", "result": "true"},
                    {"id": "oval:astra:def:12", "result": "false"},
                    {"id": "oval:astra:def:13", "result": "unknown"},
                ],
            },
        }
        return report, source

    def test_native_full_oval_requires_all_reported_definitions_and_no_fabricated_cve(self):
        report, source = self.fixture()
        result = vm.verify_native_oval_report(report, source, 3)
        self.assertEqual(result["definitions"], 3)
        self.assertFalse(result["fullCveRecallVerified"])
        self.assertFalse(result["sourcePublisherSignatureIndependent"])
        self.assertNotIn("unaffected", result)
        self.assertNotIn("fixedCve", result)

    def test_native_oval_rejects_wrong_release_missing_definitions_and_partial(self):
        original, source = self.fixture()
        mutants = []
        report = deepcopy(original)
        report["scanner"]["hostIdentity"]["astraVersion"] = "1.8.6"
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["database"]["sha256"] = "a" * 64
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["evaluatedDefinitionCount"] = 2
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["definitionResults"].pop()
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["partial"] = True
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["evaluationPerformed"] = False
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["definitionResults"][1]["id"] = "oval:astra:def:11"
        mutants.append(report)
        report = deepcopy(original)
        report["scanner"]["exitCode"] = 1
        mutants.append(report)
        for index, candidate in enumerate(mutants):
            with self.subTest(case=index):
                with self.assertRaises(AssertionError):
                    vm.verify_native_oval_report(candidate, source, 3)

    def test_true_guest_release_is_observed_without_leaking_machine_identity(self):
        machine = "0123456789abcdef0123456789abcdef"
        raw = ("NAME=Astra Linux\nID=astra\nPRETTY_NAME=Astra Linux SE\n"
               "RELEASE=1.7.6\nBUILD_VERSION=1.7.6.15\n"
               "KERNEL=5.10.99-1-astra-amd64\nMACHINE_ID=" + machine + "\n")
        proof = vm.parse_native_guest_release_summary(raw)
        self.assertTrue(proof["guestOsIdIsAstra"])
        self.assertTrue(proof["exactRequiredReleaseObserved"])
        self.assertTrue(proof["pointReleaseMatchesExpected"])
        self.assertTrue(proof["buildVersionMatchesExpected"])
        self.assertTrue(proof["independentGuestKernelObserved"])
        self.assertTrue(proof["machineIdPresent"])
        self.assertEqual(proof["observedReleaseToken"], "1.7.6")
        self.assertEqual(proof["observedBuildVersionToken"], "1.7.6.15")
        self.assertNotIn(machine, json.dumps(proof))

        wrong_point = vm.parse_native_guest_release_summary(
            raw.replace("RELEASE=1.7.6\n", "RELEASE=1.7.7\n"))
        self.assertTrue(wrong_point["guestOsIdIsAstra"])
        self.assertFalse(wrong_point["exactRequiredReleaseObserved"])
        self.assertFalse(wrong_point["pointReleaseMatchesExpected"])
        self.assertTrue(wrong_point["buildVersionMatchesExpected"])
        self.assertEqual(wrong_point["observedReleaseToken"], "1.7.7")

        wrong_build = vm.parse_native_guest_release_summary(
            raw.replace("BUILD_VERSION=1.7.6.15", "BUILD_VERSION=1.7.6.14"))
        self.assertFalse(wrong_build["exactRequiredReleaseObserved"])
        self.assertTrue(wrong_build["pointReleaseMatchesExpected"])
        self.assertFalse(wrong_build["buildVersionMatchesExpected"])
        self.assertEqual(wrong_build["observedBuildVersionToken"], "1.7.6.14")

        missing_build = vm.parse_native_guest_release_summary(
            raw.replace("BUILD_VERSION=1.7.6.15\n", ""))
        self.assertFalse(missing_build["exactRequiredReleaseObserved"])
        self.assertEqual(missing_build["observedBuildVersionToken"], "unavailable")

        duplicated = vm.parse_native_guest_release_summary(
            raw + "BUILD_VERSION=1.7.6.15\n")
        self.assertFalse(duplicated["exactRequiredReleaseObserved"])
        self.assertEqual(duplicated["observedBuildVersionToken"], "unavailable")

        unsafe = vm.parse_native_guest_release_summary(
            raw.replace("BUILD_VERSION=1.7.6.15",
                        "BUILD_VERSION=1.7.6.15 secret-hostname-and-user"))
        self.assertFalse(unsafe["exactRequiredReleaseObserved"])
        self.assertEqual(unsafe["observedBuildVersionToken"], "unavailable")

    def test_full_build_release_crosscheck_survives_init_and_rollback(self):
        machine = "0123456789abcdef0123456789abcdef"
        original = chr(10).join((
            "NAME=Astra Linux", "ID=astra", "RELEASE=1.7.6",
            "BUILD_VERSION=1.7.6.15", "KERNEL=5.10.99-1-astra-amd64",
            "MACHINE_ID=" + machine,
        )) + chr(10)
        result = vm.require_stable_native_guest_identity(original, original)
        self.assertTrue(result["exactRequiredReleaseObserved"])
        source = (vm.ROOT / "deployment/tests/verify_astra17_vm.py").read_text()
        self.assertNotIn('assert "RELEASE=1.7.6.15" in identity', source)
        for damaged in (
            original.replace("RELEASE=1.7.6" + chr(10),
                             "RELEASE=1.7.6.15" + chr(10)),
            original.replace("BUILD_VERSION=1.7.6.15", "BUILD_VERSION=1.7.6.14"),
            original.replace("BUILD_VERSION=1.7.6.15" + chr(10), ""),
            original.replace("ID=astra", "ID=debian"),
            original.replace(machine, "f" * 32),
            original + "BUILD_VERSION=1.7.6.15" + chr(10),
        ):
            with self.subTest(variant=hash(damaged)):
                with self.assertRaises(AssertionError):
                    vm.require_stable_native_guest_identity(original, damaged)

    def test_native_release_failure_summary_keeps_only_version_numbers(self):
        from summarize_astra17_ci_failure import summary
        base = {
            "status": "failed",
            "checks": [
                {"name": "Native guest release preflight recorded", "detail": {
                    "observedReleaseToken": "1.7.6",
                    "observedBuildVersionToken": "1.7.6.14",
                    "pointReleaseMatchesExpected": True,
                    "buildVersionMatchesExpected": False,
                    "guestOsIdIsAstra": True,
                    "exactRequiredReleaseObserved": False,
                    "rawMachineId": "0123456789abcdef0123456789abcdef",
                }},
            ],
            "error": {"type": "AssertionError", "message": "private path /etc"},
        }
        result = summary(base)
        self.assertEqual(result["observedGuestRelease"], "1.7.6")
        self.assertEqual(result["observedGuestBuildVersion"], "1.7.6.14")
        self.assertTrue(result["pointReleaseMatchesExpected"])
        self.assertFalse(result["buildVersionMatchesExpected"])
        self.assertTrue(result["guestOsIdIsAstra"])
        self.assertFalse(result["exactRelease117615Observed"])
        self.assertFalse(result["nativeAcceptancePassed"])
        self.assertNotIn("0123456789abcdef", json.dumps(result))
        self.assertNotIn("private path", json.dumps(result))
        base["checks"][0]["detail"]["observedBuildVersionToken"] = (
            "secret-hostname.example.org")
        self.assertIsNone(summary(base)["observedGuestBuildVersion"])

    def test_cloud_init_diagnostics_only_expose_allowlisted_module_names(self):
        raw = ("status: error\\nerrors:\\n - ('users_groups', "
               "RuntimeError('secret-client-key SENSITIVE'))\\n"
               " - ('ssh', RuntimeError('/etc/machine-id confidential'))\\n"
               " - ('my_private_host_ssh_key', 'arbitrary data')\\n")
        selected = vm.classify_private_cloud_init_errors(raw)
        self.assertEqual(selected, ["ssh", "users_groups"])
        self.assertNotIn("SENSITIVE", json.dumps(selected))
        self.assertNotIn("machine-id", json.dumps(selected))
        extra = ("2026-11-04 10:01:22 [DEBUG] finish: "
                 "init-network/config-users-groups: FAIL: private error\\n"
                 "finish: modules-final/config-phone-home: FAIL: secret URL\\n")
        self.assertEqual(vm.classify_private_cloud_init_errors(extra),
                         ["phone_home", "users_groups"])
        error_text = ("Traceback (most recent call last)\\n"
                      "ScriptFailure: run-parts: exit status 1\\n"
                      "FileNotFoundError: /private/credentials/missing\\n"
                      "Permission denied: ssh key")
        selected_classes = vm.classify_cloud_init_failure_classes(error_text)
        self.assertEqual(selected_classes, [
            "missing_file", "permission_denied", "python_exception",
            "script_process_failed",
        ])
        self.assertNotIn("credentials", json.dumps(selected_classes))
        opaque = ("Runparts: failure in /private/key; "
                  "Temporary failure resolving private.example; "
                  "syntax error near unexpected token SECRET")
        reasons = vm.classify_cloud_init_failure_classes(opaque)
        self.assertEqual(reasons, [
            "network_unavailable", "script_process_failed", "shell_syntax_error",
        ])
        self.assertNotIn("private.example", json.dumps(reasons))
        self.assertNotIn("/private/", json.dumps(reasons))


    def test_native_guest_log_probe_requires_strict_safe_schema(self):
        import json
        from types import SimpleNamespace
        safe = {
            "schemaVersion": 1,
            "status": "sanitized-guest-log-observation",
            "cloudLogReadable": True,
            "outputLogReadable": True,
            "cloudLogClasses": ["script_process_failed"],
            "outputLogClasses": ["name_resolution_failure"],
            "observedNonzeroExitCodes": [1],
            "perOnceFailureMarkerSeen": True,
            "defaultRoutePresent": False,
            "resolverConfigured": True,
            "rootFreeMiB": 3872,
        }
        self.assertEqual(validated_evidence(json.dumps(safe)), safe)
        commands = []
        def remote(command, **kwargs):
            commands.append(command)
            return SimpleNamespace(stdout=json.dumps(safe))
        self.assertEqual(collect_guest_evidence(remote), safe)
        self.assertEqual(len(commands), 1)
        self.assertIn("sudo python3 -c ", commands[0])
        self.assertNotIn("cloud-init single", commands[0])
        self.assertNotIn("cloud-init clean", commands[0])
        self.assertIn("cloud-init-output.log", GUEST_PROBE)
        # The in-guest classifier must not call every PARSEC mention a denial.
        clean_definitions = GUEST_PROBE.split('cloud_log = log_tail(', 1)[0]
        probe_scope = {}
        exec(compile(clean_definitions, "<read-only-probe-fixture>", "exec"),
             probe_scope)
        categories = probe_scope["categories"]
        self.assertEqual(categories("PARSEC controls configured"),
                         ["security_policy_referenced"])
        self.assertEqual(categories("PARSEC: access denied"),
                         ["security_policy_denied", "security_policy_referenced"])
        self.assertEqual(categories("No route to host"),
                         ["network_unavailable"])
        self.assertNotIn("print(cloud_log)", GUEST_PROBE)
        self.assertNotIn("print(output_log)", GUEST_PROBE)
        for altered in [
            {**safe, "rawGuest": "my-secret-key"},
            {**safe, "cloudLogClasses": ["my private path"]},
            {**safe, "outputLogClasses": ["name_resolution_failure", "name_resolution_failure"]},
            {**safe, "observedNonzeroExitCodes": [1, 0]},
            {**safe, "observedNonzeroExitCodes": [True]},
            {**safe, "rootFreeMiB": "secret"},
            {**safe, "defaultRoutePresent": "false"},
            {**safe, "status": "failed"},
        ]:
            with self.subTest(case=repr(list(altered.keys()))):
                with self.assertRaises(ValueError):
                    validated_evidence(json.dumps(altered))
        for unsafe in ["secret-data", "{", "", "x" * 4100]:
            with self.assertRaises(ValueError):
                validated_evidence(unsafe)

    def test_guest_script_metadata_probe_returns_only_bounded_sanitized_types(self):
        from types import SimpleNamespace
        recorded = []
        def remote(command, **kwargs):
            recorded.append((command, kwargs))
            return SimpleNamespace(stdout=json.dumps({
                "directoryExists": True,
                "scriptCount": 1,
                "scripts": [{
                    "regular": True, "executable": False,
                    "sizeBytes": 643,
                    "sha256": "a" * 64, "shebangCategory": "shell",
                    "interpreterPresent": True,
                    "shellSyntaxValid": True,
                }],
            }))
        metadata = vm.inspect_guest_per_once_scripts(remote)
        self.assertEqual(metadata["scriptCount"], 1)
        self.assertEqual(metadata["scripts"][0]["executable"], False)
        self.assertIs(metadata["scripts"][0]["shellSyntaxValid"], True)
        self.assertEqual(len(recorded), 1)
        self.assertTrue(recorded[0][0].startswith("sudo python3 -c "))
        self.assertNotIn("secret:", json.dumps(metadata))

    def test_public_failure_summary_discards_raw_guest_values_and_commands(self):
        from summarize_astra17_ci_failure import summary
        private = {
            "status": "failed",
            "checks": [
                {"name": "Official fixed Astra 1.7.6.UU2 image bytes match source catalog",
                 "detail": {"rawMachineId": "confidential-identity"}},
                {"name": "Native guest release preflight recorded",
                 "detail": {"observedReleaseToken": "1.7.6",
                            "observedBuildVersionToken": "1.7.6.15",
                            "pointReleaseMatchesExpected": True,
                            "buildVersionMatchesExpected": True,
                            "guestOsIdIsAstra": True,
                            "exactRequiredReleaseObserved": True,
                            "rawMachineId": "never-publish"}},
                {"name": "Native Astra 1.7.6.15 identity observed before final cloud-init",
                 "detail": {"rawMachineId": "never-publish", "releaseObserved": True}},
                {"name": "Native guest cloud-init failure; no audit claimed",
                 "detail": {"reportedModuleNames": ["users_groups", "secret-custom-stage"],
                            "perOnceDirectoryPresent": True,
                            "perOnceScriptCount": 3,
                            "perOnceExecutableCount": 1,
                            "perOnceInterpreterCategories": ["shell", "other", "private-sh"],
                            "failureClasses": ["permission_denied", "secret_reason"],
                            "perOnceShellSyntaxValid": False,
                            "guestLogEvidence": {
                                "schemaVersion": 1,
                                "status": "sanitized-guest-log-observation",
                                "cloudLogReadable": True,
                                "outputLogReadable": True,
                                "cloudLogClasses": ["script_process_failed"],
                                "outputLogClasses": ["name_resolution_failure"],
                                "observedNonzeroExitCodes": [1],
                                "perOnceFailureMarkerSeen": True,
                                "defaultRoutePresent": False,
                                "resolverConfigured": True,
                                "rootFreeMiB": 3872,
                                "rawGuestSecret": "never-include",
                            },
                            "privateKey": "SENSITIVE"}},
            ],
            "error": {"type": "RuntimeError",
                      "message": "ssh -i /secret/privatekey machine-id abc123"},
        }
        public = summary(private)
        self.assertFalse(public["nativeAcceptancePassed"])
        self.assertEqual(public["cloudInitFailingModuleNames"], ["users_groups"])
        self.assertEqual(public["failureClass"], "RuntimeError")
        self.assertEqual(public["observedGuestRelease"], "1.7.6")
        self.assertEqual(public["observedGuestBuildVersion"], "1.7.6.15")
        self.assertTrue(public["pointReleaseMatchesExpected"])
        self.assertTrue(public["buildVersionMatchesExpected"])
        self.assertTrue(public["guestOsIdIsAstra"])
        self.assertTrue(public["exactRelease117615Observed"])
        self.assertEqual(public["cloudInitPerOnceScriptCount"], 3)
        self.assertEqual(public["cloudInitPerOnceDirectoryPresent"], True)
        self.assertEqual(public["cloudInitPerOnceExecutableCount"], 1)
        self.assertEqual(public["cloudInitPerOnceInterpreterCategories"], ["other", "shell"])
        self.assertEqual(public["cloudInitFailureCategories"], ["permission_denied"])
        self.assertIs(public["cloudInitPerOnceShellSyntaxValid"], False)
        self.assertIsNone(public["guestLogDiagnostics"])
        private["checks"][-1]["detail"]["guestLogEvidence"].pop("rawGuestSecret")
        validated = summary(private)
        self.assertEqual(validated["guestLogDiagnostics"]["outputLogClasses"],
                         ["name_resolution_failure"])
        self.assertNotIn("rawGuestSecret", json.dumps(validated))
        self.assertNotIn("secret_reason", json.dumps(public))
        self.assertEqual(public["completedSafeStageNames"],
                         ["image_sha256_verified",
                          "native_release_observed_but_not_yet_accepted",
                          "native_release_17_observed", "cloud_init_failed"])
        self.assertNotIn("SENSITIVE", json.dumps(public))
        self.assertNotIn("privatekey", json.dumps(public))
        self.assertNotIn("confidential-identity", json.dumps(public))

    def test_no_public_artifacts_include_generated_native_identity(self):
        workflow = (vm.ROOT / ".github/workflows/astra17-vm.yml").read_text()
        self.assertIn("workflow_dispatch", workflow)
        self.assertIn("pull_request", workflow)
        self.assertIn("source", (vm.ROOT / "deployment/tests/verify_astra17_vm.py").read_text())
        self.assertNotIn("native-identity-private.txt", workflow)
        self.assertNotIn("asset-observation.json", workflow)
        self.assertNotIn("guest-console.log", workflow)
        self.assertIn("retention-days: 14", workflow)


if __name__ == "__main__":
    unittest.main()
