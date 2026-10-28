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
    "dangerous_ports": [{"port": 23, "protocol": "tcp", "risk": "high", "title": "Telnet", "recommendation": "Disable telnet"}],
    "ssh_rules": {}, "service_rules": [{"service": "auditd", "title": "Audit logging", "recommendation": "Enable auditd"}],
    "package_rules": {"unattended_upgrades": {"packages": ["unattended-upgrades"]}},
    "filesystem_rules": {"world_writable_paths": {"paths": ["/tmp", "/var/tmp"]}},
}

def nft_input(policy="drop", expressions=(), output_policy="accept"):
    return json.dumps({"nftables": [
        {"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": policy}},
        {"chain": {"family": "inet", "table": "filter", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": output_policy}},
        *[{"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": expression}} for expression in expressions],
    ]})


class AgentlessAuditTest(unittest.TestCase):
    def execute_audit(self, overrides=None, profile="basic_linux", rules=None):
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
            elif command == ("iptables", "-S"):
                code, stdout, stderr = 0, "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT", ""
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
        with patch("subprocess.run", side_effect=execute), patch("shutil.which", side_effect=lambda name: "/test/" + name if name in {"apt", "dpkg-query"} else None), patch("builtins.open", side_effect=open_file), patch("os.path.exists", return_value=True), patch.dict(os.environ, {"AUDIT_PROFILE": profile, "AUDIT_RULES_JSON": json.dumps(RULES if rules is None else rules)}), contextlib.redirect_stdout(output):
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

    def test_nftables_fallback_handles_an_unreadable_ufw_lock(self):
        report, findings = self.execute_audit({
            ("ufw", "status"): (1, "", "PermissionError: [Errno 13] Permission denied: '/run/ufw.lock'"),
            ("firewall-cmd", "--state"): (252, "not running", ""),
            ("nft", "-j", "list", "ruleset"): (0, nft_input(), ""),
            ("iptables", "-S"): (127, "", "command unavailable"),
        })
        self.assertEqual(findings["firewall_active"]["status"], "passed")
        self.assertIn("backend=nftables", findings["firewall_active"]["evidence"])
        self.assertNotIn("firewall_active", report["scanner"]["incompleteChecks"])

    def test_output_deny_cannot_make_unrestricted_input_pass(self):
        report, findings = self.execute_audit({
            ("nft", "-j", "list", "ruleset"): (0, nft_input(policy="accept", output_policy="drop"), ""),
            ("iptables", "-S"): (0, "-P INPUT ACCEPT\n-P OUTPUT DROP", ""),
        })
        self.assertEqual(findings["firewall_active"]["status"], "failed")
        self.assertNotEqual(report["summary"]["score"], 100)

    def test_dormant_nft_table_cannot_prove_input_filtering(self):
        for flags, expected in [([], "passed"), (["owner", "persist"], "passed"), (["dormant"], "failed"), (["unsupported"], "manual")]:
            with self.subTest(flags=flags):
                rules = json.loads(nft_input())
                rules["nftables"].insert(0, {"table": {"family": "inet", "name": "filter", "flags": flags}})
                _, findings = self.execute_audit({
                    ("ufw", "status"): (0, "Status: inactive", ""),
                    ("firewall-cmd", "--state"): (252, "not running", ""),
                    ("nft", "-j", "list", "ruleset"): (0, json.dumps(rules), ""),
                    ("iptables", "-S"): (0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT", ""),
                })
                self.assertEqual(findings["firewall_active"]["status"], expected)

    def test_unconditional_accept_hides_later_deny_in_both_formats(self):
        _, findings = self.execute_audit({
            ("nft", "-j", "list", "ruleset"): (0, nft_input(expressions=[[{"accept": None}], [{"drop": None}]]), ""),
            ("iptables", "-S"): (0, "-P INPUT DROP\n-A INPUT -j ACCEPT\n-A INPUT -j DROP", ""),
        })
        self.assertEqual(findings["firewall_active"]["status"], "failed")

    def test_nft_input_deny_and_conditional_allow_keep_a_real_restrictive_path(self):
        for expected in ("tcp", 6):
            with self.subTest(protocol=expected):
                _, findings = self.execute_audit({
                    ("nft", "-j", "list", "ruleset"): (0, nft_input(expressions=[[{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": expected}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": None}]]), ""),
                    ("iptables", "-S"): (127, "", "missing"),
                })
                self.assertEqual(findings["firewall_active"]["status"], "passed")
                self.assertIn("scope=local_input", findings["firewall_active"]["evidence"])

    def test_iptables_follows_input_jumps_and_does_not_count_an_unreferenced_chain(self):
        rules = "-P INPUT ACCEPT\n-N restrict\n-A INPUT -p tcp --dport 23 -j restrict\n-A restrict -j REJECT"
        _, findings = self.execute_audit({("iptables", "-S"): (0, rules, "")})
        self.assertEqual(findings["firewall_active"]["status"], "passed")
        _, findings = self.execute_audit({("iptables", "-S"): (0, rules.replace("-A INPUT -p tcp --dport 23 -j restrict\n", ""), "")})
        self.assertEqual(findings["firewall_active"]["status"], "failed")

    def test_running_manager_or_unsupported_semantics_are_not_filtering_proof(self):
        for rules in ("-P INPUT DROP\n-N trusted\n-A INPUT -g trusted\n-A trusted -j ACCEPT", "-P INPUT DROP\n-A INPUT -j QUEUE"):
            report, findings = self.execute_audit({("iptables", "-S"): (0, rules, "")})
            self.assertEqual(findings["firewall_active"]["status"], "manual")
            self.assertIn("firewall_active", report["scanner"]["incompleteChecks"])
        report, findings = self.execute_audit({("iptables", "-S"): (127, "", "missing")})
        self.assertEqual(findings["firewall_active"]["status"], "manual")
        self.assertTrue(report["scanner"]["partial"])

    def test_supported_ufw_style_input_chains_keep_the_manager_identity(self):
        rules = "\n".join([
            "-P INPUT DROP", "-N ufw-before-input", "-N ufw-user-input", "-A INPUT -j ufw-before-input",
            "-A ufw-before-input -i lo -j ACCEPT", "-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A ufw-before-input -j ufw-user-input", "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
        ])
        report, findings = self.execute_audit({("iptables", "-S"): (0, rules, "")})
        self.assertEqual(findings["firewall_active"]["status"], "passed")
        self.assertTrue(findings["firewall_active"]["evidence"].startswith("backend=ufw;"))
        self.assertNotIn("firewall_active", report["scanner"]["incompleteChecks"])

    def test_supported_firewalld_style_nft_jump_keeps_the_manager_identity(self):
        data = json.loads(nft_input(policy="accept", expressions=[[{"jump": {"target": "public"}}]]))
        data["nftables"].extend([
            {"chain": {"family": "inet", "table": "filter", "name": "public"}},
            {"rule": {"family": "inet", "table": "filter", "chain": "public", "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 22}}, {"accept": None}]}},
            {"rule": {"family": "inet", "table": "filter", "chain": "public", "expr": [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]}},
        ])
        _, findings = self.execute_audit({
            ("ufw", "status"): (0, "Status: inactive", ""),
            ("firewall-cmd", "--state"): (0, "running", ""),
            ("nft", "-j", "list", "ruleset"): (0, json.dumps(data), ""),
            ("iptables", "-S"): (0, "-P INPUT ACCEPT", ""),
        })
        self.assertEqual(findings["firewall_active"]["status"], "passed")
        self.assertTrue(findings["firewall_active"]["evidence"].startswith("backend=firewalld;"))

    def test_nft_verdict_map_and_invalid_json_require_manual_review(self):
        for output in (nft_input(expressions=[[{"vmap": {"key": {}, "data": "@policy"}}]]), "table inet filter { hook input; drop; }"):
            report, findings = self.execute_audit({
                ("nft", "-j", "list", "ruleset"): (0, output, ""),
                ("iptables", "-S"): (127, "", "missing"),
            })
            self.assertEqual(findings["firewall_active"]["status"], "manual")
            self.assertIsNone(report["summary"]["score"])

    def test_tcp_policy_does_not_report_a_udp_listener_as_telnet(self):
        report, findings = self.execute_audit({("ss", "-tuln"): (0, "udp UNCONN 0 0 0.0.0.0:23 0.0.0.0:*", "")})
        self.assertNotIn("dangerous_port_tcp_23", findings)
        self.assertNotIn("dangerous_port_udp_23", findings)
        self.assertEqual(findings["dangerous_ports_absent"]["status"], "passed")
        self.assertEqual(findings["dangerous_ports_absent"]["evidence"], "checked_ports=tcp/23")
        self.assertEqual(report["agentless"]["openSockets"][0]["protocol"], "udp")

    def test_matching_protocol_preserves_binding_and_does_not_infer_service_identity(self):
        _, findings = self.execute_audit({("ss", "-tuln"): (0, "tcp LISTEN 0 128 192.0.2.10:23 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:23 0.0.0.0:*", "")})
        result = findings["dangerous_port_tcp_23"]
        self.assertEqual(result["status"], "failed")
        self.assertIn("port=tcp/23", result["evidence"])
        self.assertIn("bindings=192.0.2.10:23", result["evidence"])
        self.assertNotIn("0.0.0.0:23", result["evidence"])
        self.assertIn("service=unverified", result["evidence"])
        self.assertIn("externalReachability=unverified", result["evidence"])
        self.assertNotIn("Telnet", result["title"])

    def test_tcp_and_udp_rules_on_the_same_port_remain_distinct(self):
        rules = {**RULES, "dangerous_ports": [RULES["dangerous_ports"][0], {**RULES["dangerous_ports"][0], "protocol": "udp"}]}
        _, findings = self.execute_audit({("ss", "-tuln"): (0, "tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*\nudp UNCONN 0 0 [::]:23 [::]:*", "")}, rules=rules)
        self.assertEqual(findings["dangerous_port_tcp_23"]["status"], "failed")
        self.assertEqual(findings["dangerous_port_udp_23"]["status"], "failed")
        self.assertIn("port=udp/23; bindings=[::]:23", findings["dangerous_port_udp_23"]["evidence"])

    def test_loopback_only_listener_is_reviewable_not_a_claim_of_network_exposure(self):
        _, findings = self.execute_audit({("ss", "-tuln"): (0, "tcp LISTEN 0 128 127.0.0.1:23 0.0.0.0:*\ntcp LISTEN 0 128 [::1]:23 [::]:*", "")})
        result = findings["dangerous_port_tcp_23"]
        self.assertEqual(result["status"], "manual")
        self.assertFalse(result["remediationAvailable"])
        self.assertIn("bindingScopes=loopback", result["evidence"])
        self.assertNotIn("dangerous_ports_absent", findings)

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
