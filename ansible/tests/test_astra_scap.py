"""HCP baseline semantics: missing observation never creates a passing result."""
import errno
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


CONTENT = Path(__file__).parents[1] / "scap/astra"
SPEC = importlib.util.spec_from_file_location("astra_scap_check", CONTENT / "check.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)
X = "{http://checklists.nist.gov/xccdf/1.2}"


class AstraBaselineTests(unittest.TestCase):
    def test_every_selected_rule_has_readonly_check_and_stdout_evidence(self):
        root = ET.parse(CONTENT / "astra-baseline.xml").getroot()
        rules = root.findall(X + "Rule")
        selects = root.findall(X + "Profile/" + X + "select")
        self.assertEqual(len(rules), 18)
        self.assertEqual({r.get("id") for r in rules}, {s.get("idref") for s in selects})
        self.assertTrue(all(s.get("selected") == "true" for s in selects))
        values = {v.get("id"): v.findtext(X + "value") for v in root.findall(X + "Value")}
        # Although optional in XCCDF schema, missing operator makes OpenSCAP
        # 1.3.9 abort inside sce_engine_eval_rule before running the script.
        self.assertTrue(all(value.get("operator") == "equals" for value in root.findall(X + "Value")))
        ids = set()
        for rule in rules:
            evaluation = rule.find(X + "check")
            if rule.get("id") == "xccdf_org.hcp_rule_aslr":
                self.assertEqual(evaluation.get("system"), "http://oval.mitre.org/XMLSchema/oval-definitions-5")
                reference = evaluation.find(X + "check-content-ref")
                self.assertEqual(reference.get("href"), "astra-platform-oval.xml")
                self.assertEqual(reference.get("name"), "oval:org.hcp.astra:def:2")
                continue
            ids.add(values[evaluation.find(X + "check-export").get("value-id")])
            self.assertEqual(evaluation.find(X + "check-content-ref").get("href"), "check.py")
            self.assertEqual(evaluation.find(X + "check-import").get("import-name"), "stdout")
            self.assertIsNone(rule.find(X + "fix"))
        self.assertEqual(ids, check.CHECK_IDS)

    def test_astra_family_support_has_no_release_whitelist_and_no_shell_execution(self):
        for release in ("1.6", "1.7.6", "1.8", "future-release"):
            with patch.object(check, "read_text", return_value='ID=astra\nVERSION_ID="' + release + '"\n'):
                self.assertTrue(check.astra_identity())
        for release in ('ID=debian\nID_LIKE=debian\n', 'ID=ubuntu\nID_LIKE=debian\n'):
            with patch.object(check, "read_text", return_value=release):
                self.assertFalse(check.astra_identity())
                self.assertEqual(check.evaluate("protected_hardlinks")[0], check.NOT_APPLICABLE)
        with patch.object(check, "read_text", return_value="ID=astra\nID=debian\n"):
            self.assertEqual(check.evaluate("protected_hardlinks")[0], check.UNKNOWN)

    def test_unreadable_or_missing_observations_are_not_success(self):
        with patch.object(check, "astra_identity", return_value=True), patch.object(check.os, "geteuid", return_value=0):
            for error, expected in ((PermissionError(errno.EACCES, "denied"), check.UNKNOWN),
                                    (FileNotFoundError(errno.ENOENT, "missing"), check.NOT_APPLICABLE)):
                with patch.object(check, "read_text", side_effect=error):
                    self.assertEqual(check.evaluate("protected_hardlinks")[0], expected)
            with patch.object(check, "read_text", return_value="unsupported"):
                self.assertEqual(check.evaluate("protected_hardlinks")[0], check.UNKNOWN)
        with patch.object(check, "astra_identity", return_value=True), patch.object(check.os, "geteuid", return_value=1000):
            self.assertEqual(check.evaluate("passwd_permissions")[0], check.UNKNOWN)

    def test_real_file_permissions_change_result_and_symlink_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "passwd"
            path.write_text("root:x:0:0:root:/root:/bin/sh\n")
            link = Path(directory) / "link"
            link.symlink_to(path)
            with patch.dict(check.FILE_CHECKS, {"fixture": (str(path), 0o644, False)}):
                path.chmod(0o644)
                # Owners are real filesystem identities, not mocked stat data.
                expected = check.PASS if os.getuid() == 0 and os.getgid() == 0 else check.FAIL
                self.assertEqual(check.file_permissions("fixture")[0], expected)
                path.chmod(0o666)
                self.assertEqual(check.file_permissions("fixture")[0], check.FAIL)
                path.chmod(0o4644)
                self.assertEqual(check.file_permissions("fixture")[0], check.FAIL)
            with patch.dict(check.FILE_CHECKS, {"fixture": (str(link), 0o644, False)}):
                self.assertEqual(check.file_permissions("fixture")[0], check.UNKNOWN)

    def test_local_accounts_detect_duplicates_uid_zero_and_empty_password_without_hash_output(self):
        with patch.object(check, "read_text", return_value="root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/:/bin/sh\n"):
            self.assertEqual(check.local_accounts("unique_uid_zero")[0], check.FAIL)
        with patch.object(check, "read_text", return_value="root:x:0:0::/:/bin/sh\nroot:x:0:0::/:/bin/sh\n"):
            self.assertEqual(check.local_accounts("root_account")[0], check.UNKNOWN)
        with patch.object(check, "read_text", return_value="root:!locked-hash:1:0:99999:7:::\nalice::1:0:99999:7:::\n"):
            code, details = check.local_accounts("empty_local_passwords")
            self.assertEqual(code, check.FAIL)
            self.assertEqual(details["emptyPasswordAccounts"], ["alice"])
            self.assertNotIn("locked-hash", str(details))
        with patch.object(check, "read_text", return_value="+::::::\n"):
            self.assertEqual(check.local_accounts("unique_uid_zero")[0], check.UNKNOWN)

    def test_ssh_uses_effective_global_configuration_and_reports_errors(self):
        with patch.object(check.shutil, "which", return_value="/usr/sbin/sshd"), \
                patch.object(check, "command", return_value=subprocess.CompletedProcess([], 0, "permitrootlogin no\n", "")) as run:
            code, details = check.ssh_configuration("ssh_root_login")
            self.assertEqual(code, check.PASS)
            self.assertEqual(details["scope"], "global_sshd_T_without_Match_contexts")
            run.assert_called_once_with(["/usr/sbin/sshd", "-T"])
        for output, code, expected in (("permitrootlogin yes\n", 0, check.FAIL),
                                       ("", 1, check.UNKNOWN), ("", 0, check.UNKNOWN),
                                       ("permitrootlogin no\npermitrootlogin yes\n", 0, check.UNKNOWN)):
            with patch.object(check.shutil, "which", return_value="/usr/sbin/sshd"), \
                    patch.object(check, "command", return_value=subprocess.CompletedProcess([], code, output, "")):
                self.assertEqual(check.ssh_configuration("ssh_root_login")[0], expected)

    def test_service_absence_is_a_finding_but_unavailable_query_is_unknown(self):
        for state, rc, expected in (("LoadState=not-found\nActiveState=inactive\n", 0, check.FAIL),
                                    ("LoadState=loaded\nActiveState=active\n", 0, check.PASS),
                                    ("LoadState=loaded\nActiveState=failed\n", 0, check.FAIL),
                                    ("", 1, check.UNKNOWN)):
            with patch.object(check.shutil, "which", return_value="/bin/systemctl"), \
                    patch.object(check.os.path, "isdir", return_value=True), \
                    patch.object(check, "command", return_value=subprocess.CompletedProcess([], rc, state, "")):
                self.assertEqual(check.audit_service()[0], expected)


if __name__ == "__main__":
    unittest.main()
