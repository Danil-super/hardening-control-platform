"""Execute the actual embedded audit program against controlled host responses."""

import contextlib
import io
import json
import os
import subprocess
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


PLAYBOOK = Path(__file__).resolve().parents[1] / "playbooks" / "agentless-audit.yml"
SOURCE = textwrap.dedent(PLAYBOOK.read_text().split("python3 - <<'PY'\n", 1)[1].split("        PY\n", 1)[0])
RULES = {
    "dangerous_ports": [{"port": 23, "risk": "high", "title": "Telnet", "recommendation": "Disable telnet"}],
    "ssh_rules": {}, "service_rules": [{"service": "auditd", "title": "Audit logging", "recommendation": "Enable auditd"}],
    "package_rules": {"unattended_upgrades": {"packages": ["unattended-upgrades"]}},
    "filesystem_rules": {"world_writable_paths": {"paths": ["/tmp", "/var/tmp"]}},
}


class AgentlessAuditTest(unittest.TestCase):
    def execute_audit(self, overrides=None, profile="basic_linux"):
        overrides = overrides or {}
        def execute(command, **kwargs):
            command = tuple(command)
            if command in overrides:
                code, stdout, stderr = overrides[command]
            elif command[0] == "ss":
                code, stdout, stderr = 0, "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port", ""
            elif command[0] == "sshd":
                code, stdout, stderr = 0, "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3", ""
            elif command[0] == "systemctl":
                code, stdout, stderr = 0, "active", ""
            elif command[0] == "ufw":
                code, stdout, stderr = 0, "Status: active", ""
            elif command[0] == "firewall-cmd":
                code, stdout, stderr = 252, "not running", ""
            elif command[0] == "dpkg-query":
                code, stdout, stderr = 0, "install ok installed", ""
            elif command[0] == "apt":
                code, stdout, stderr = 0, "Listing... Done", ""
            elif command[0] == "grep":
                code, stdout, stderr = 1, "", ""
            elif command[0] in ("find", "awk"):
                code, stdout, stderr = 0, "", ""
            elif command == ("bash", "-lc", "docker info 2>&1"):
                code, stdout, stderr = 0, "Server: Docker", ""
            elif command[:2] == ("docker", "info"):
                code, stdout, stderr = 0, '["name=seccomp,profile=builtin"]', ""
            elif command == ("docker", "ps", "-q"):
                code, stdout, stderr = 0, "", ""
            elif command[0] == "bash" and command[2].startswith("stat -c"):
                code, stdout, stderr = 0, "660 root:docker", ""
            elif command[0] == "getent" or command[0] == "bash" and "getent" in command[2]:
                code, stdout, stderr = 0, "root:x:0:0:root:/root:/bin/bash", ""
            else:
                code, stdout, stderr = 127, "", "command unavailable in test"
            return subprocess.CompletedProcess(command, code, stdout, stderr)

        output = io.StringIO()
        def open_file(*args, **kwargs):
            if str(args[0]) == "/etc/os-release":
                return io.StringIO('PRETTY_NAME="Test Linux"\n')
            raise OSError("file unavailable in test")
        with patch("subprocess.run", side_effect=execute), patch("shutil.which", side_effect=lambda name: "/test/" + name if name in {"apt", "dpkg-query"} else None), patch("builtins.open", side_effect=open_file), patch("os.path.exists", return_value=True), patch.dict(os.environ, {"AUDIT_PROFILE": profile, "AUDIT_RULES_JSON": json.dumps(RULES)}), contextlib.redirect_stdout(output):
            exec(compile(SOURCE, str(PLAYBOOK), "exec"), {})
        report = json.loads(output.getvalue())
        return report, {item["id"]: item for item in report["findings"]}

    def test_ss_error_does_not_report_dangerous_ports_absent(self):
        report, findings = self.execute_audit({("ss", "-tuln"): (1, "", "permission denied")})
        self.assertNotIn("dangerous_ports_absent", findings)
        self.assertTrue(report["scanner"]["partial"])
        self.assertIsNone(report["summary"]["score"])

    def test_sshd_error_does_not_fall_back_to_unreliable_file_parsing(self):
        report, findings = self.execute_audit({("sshd", "-T"): (1, "", "invalid configuration")})
        self.assertNotIn("ssh_root_login", findings)
        self.assertEqual(findings["sshd_config_unavailable"]["status"], "manual")
        self.assertTrue(report["scanner"]["partial"])

    def test_systemd_error_is_unknown_not_inactive(self):
        report, findings = self.execute_audit({("systemctl", "is-active", "auditd"): (1, "", "Failed to connect to bus")})
        self.assertEqual(findings["service_auditd_active"]["status"], "manual")
        self.assertTrue(report["scanner"]["partial"])

    def test_confirmed_inactive_required_service_is_a_failure(self):
        _, findings = self.execute_audit({("systemctl", "is-active", "auditd"): (3, "inactive", "")})
        self.assertEqual(findings["service_auditd_active"]["status"], "failed")

    def test_shadow_read_error_does_not_produce_a_clean_account_check(self):
        _, findings = self.execute_audit({("awk", "-F:", '($2 == "") {print $1}', "/etc/shadow"): (2, "", "permission denied")})
        self.assertEqual(findings["empty_password_accounts"]["status"], "manual")

    def test_find_error_does_not_produce_a_clean_filesystem_check(self):
        command = ("find", "/tmp", "/var/tmp", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print")
        _, findings = self.execute_audit({command: (1, "", "permission denied")})
        self.assertEqual(findings["world_writable_dirs"]["status"], "manual")

    def test_package_query_residual_config_is_not_an_installed_package(self):
        _, findings = self.execute_audit({("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"): (0, "deinstall ok config-files", "")})
        self.assertEqual(findings["security_auto_updates"]["status"], "failed")

    def test_stale_or_failed_package_cache_cannot_confirm_current_updates(self):
        for overrides in ({}, {("apt", "list", "--upgradable"): (100, "", "repository error")}):
            _, findings = self.execute_audit(overrides)
            self.assertEqual(findings["package_updates_available"]["status"], "manual")

    def test_docker_privileged_container_is_detected_from_inspect_boolean(self):
        _, findings = self.execute_audit({
            ("docker", "ps", "-q"): (0, "abc123", ""),
            ("docker", "inspect", "abc123"): (0, '[{"Id":"abc123","HostConfig":{"Privileged":true}}]', ""),
        }, profile="docker_host")
        self.assertEqual(findings["docker_privileged_containers"]["status"], "failed")
        self.assertIn("abc123", findings["docker_privileged_containers"]["evidence"])

    def test_failed_docker_inspect_does_not_pass(self):
        report, findings = self.execute_audit({
            ("docker", "ps", "-q"): (0, "abc123", ""),
            ("docker", "inspect", "abc123"): (1, "", "daemon failed"),
        }, profile="docker_host")
        self.assertEqual(findings["docker_privileged_containers"]["status"], "manual")
        self.assertTrue(report["scanner"]["partial"])

    def test_nginx_comment_cannot_confirm_disabled_server_tokens(self):
        _, findings = self.execute_audit({("bash", "-lc", "nginx -T 2>&1"): (0, "# server_tokens off;", "")}, profile="web_server")
        self.assertEqual(findings["nginx_server_tokens"]["status"], "manual")
        self.assertEqual(findings["nginx_server_tokens"]["evidence"], "server_tokens=not found")


if __name__ == "__main__":
    unittest.main()
