"""Execute the actual embedded audit program against controlled host responses."""

import contextlib
import ast
import io
import json
import os
import subprocess
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


PLAYBOOK = Path(__file__).resolve().parents[1] / "playbooks" / "agentless-audit.yml"
SOURCE = textwrap.dedent(PLAYBOOK.read_text().split("<<'PY'\n", 1)[1].split("        PY\n", 1)[0])
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


def nft_graph(input_policies, rules, family="inet"):
    """Build a real nft JSON chain graph, including empty regular chains."""
    names = list(input_policies) + [name for name in rules if name not in input_policies]
    entries = []
    for priority, name in enumerate(names):
        chain = {"family": family, "table": "filter", "name": name}
        if name in input_policies:
            chain.update({"type": "filter", "hook": "input", "prio": priority, "policy": input_policies[name]})
        entries.append({"chain": chain})
    for name, expressions in rules.items():
        entries.extend({"rule": {"family": family, "table": "filter", "chain": name, "expr": expression}} for expression in expressions)
    return json.dumps({"nftables": entries})


def nft_match(left, right, operation="=="):
    return {"match": {"left": left, "op": operation, "right": right}}


def firewalld_input_graph(allow_all=False):
    """Relevant INPUT clauses from the native Alma firewalld ruleset.

    Keep DNAT, both zone goto branches, ICMPv6 header dependencies and the
    early runtime rich-rule chain, which a shallow jump-only fixture misses.
    """
    jump = lambda target: [{"jump": {"target": target}}]
    rules = {
        "filter_INPUT": [
            [nft_match({"ct": {"key": "state"}}, {"set": ["established", "related"]}), {"accept": None}],
            [nft_match({"ct": {"key": "status"}}, "dnat", "in"), {"accept": None}],
            [nft_match({"meta": {"key": "iifname"}}, "lo"), {"accept": None}],
            [nft_match({"ct": {"key": "state"}}, "invalid", "in"), {"drop": None}],
            jump("filter_INPUT_ZONES"),
            [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}],
        ],
        "filter_INPUT_ZONES": [
            [nft_match({"meta": {"key": "iifname"}}, "eth0"), {"goto": {"target": "filter_IN_public"}}],
            [{"goto": {"target": "filter_IN_public"}}],
        ],
        "filter_IN_public": [jump(name) for name in [
            "filter_INPUT_POLICIES_pre", "filter_IN_public_pre", "filter_IN_public_log",
            "filter_IN_public_deny", "filter_IN_public_allow", "filter_IN_public_post", "filter_INPUT_POLICIES_post",
        ]] + [
            [nft_match({"meta": {"key": "l4proto"}}, {"set": ["icmp", "ipv6-icmp"]}), {"accept": None}],
            [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}],
        ],
        "filter_INPUT_POLICIES_pre": [jump("filter_IN_policy_allow-host-ipv6")],
        "filter_IN_policy_allow-host-ipv6": [jump("filter_IN_policy_allow-host-ipv6_" + part) for part in ("pre", "log", "deny", "allow", "post")],
        "filter_IN_policy_allow-host-ipv6_allow": [
            [nft_match({"payload": {"protocol": "icmpv6", "field": "type"}}, kind), {"accept": None}]
            for kind in ("nd-neighbor-advert", "nd-neighbor-solicit", "nd-router-advert", "nd-redirect",
                         "mld-listener-done", "mld-listener-query", "mld-listener-report", "mld2-listener-report")
        ],
        "filter_IN_public_pre": [[{"accept": None}]] if allow_all else [],
        "filter_IN_public_allow": [
            [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, 22), {"accept": None}],
            [nft_match({"payload": {"protocol": "ip6", "field": "daddr"}}, {"prefix": {"addr": "fe80::", "len": 64}}),
             nft_match({"payload": {"protocol": "udp", "field": "dport"}}, 546), {"accept": None}],
            [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, 9090), {"accept": None}],
            [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, 8088), {"accept": None}],
        ],
    }
    for name in ("filter_IN_public_log", "filter_IN_public_deny", "filter_IN_public_post", "filter_INPUT_POLICIES_post"):
        rules[name] = []
    for part in ("pre", "log", "deny", "post"):
        rules["filter_IN_policy_allow-host-ipv6_" + part] = []
    data = json.loads(nft_graph({"filter_INPUT": "accept"}, rules))
    data["nftables"].insert(0, {"table": {"family": "inet", "name": "filter", "flags": ["owner", "persist"]}})
    return json.dumps(data)


def systemd_show(service):
    return ("systemctl", "show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--", service + ".service")


class AgentlessAuditTest(unittest.TestCase):
    def execute_audit(self, overrides=None, profile="basic_linux", rules=None, init="systemd", tools=None, files=None, absent_paths=()):
        overrides = overrides or {}
        commands = []
        host_files = {"/etc/os-release": 'PRETTY_NAME="Test Linux"\n', "/proc/1/comm": ("init" if init == "openrc" else "sysvinit" if init == "sysv" else init) + "\n"}
        if init == "openrc":
            host_files["/run/openrc/softlevel"] = "default\n"
        host_files.update(files or {})
        available_tools = set(tools) if tools is not None else {"apt", "dpkg-query", "systemctl"}
        if init == "openrc":
            available_tools.add("rc-service")
        original_stat = os.stat
        def execute(command, **kwargs):
            command = tuple(command)
            commands.append(command)
            if command in overrides:
                if isinstance(overrides[command], BaseException):
                    raise overrides[command]
                code, stdout, stderr = overrides[command]
            elif command[0] == "ss":
                code, stdout, stderr = 0, "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port", ""
            elif command[0] == "sshd":
                code, stdout, stderr = 0, "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3", ""
            elif command[0] == "systemctl":
                code, stdout, stderr = 0, "LoadState=loaded\nActiveState=active", ""
            elif command[:2] == ("rc-service", "--exists"):
                code, stdout, stderr = 1, "", ""
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
            elif command[0] == "tail":
                code, stdout, stderr = 0, "", ""
            elif command[0] in ("find", "awk"):
                code, stdout, stderr = 0, "", ""
            elif command == ("docker", "info"):
                code, stdout, stderr = 0, "Server: Docker", ""
            elif command[:2] == ("docker", "info"):
                code, stdout, stderr = 0, '["name=seccomp,profile=builtin"]', ""
            elif command == ("docker", "ps", "-q"):
                code, stdout, stderr = 0, "", ""
            elif command == ("stat", "-c", "%a %U:%G", "/var/run/docker.sock"):
                code, stdout, stderr = 0, "660 root:docker", ""
            elif command[0] == "getent":
                code, stdout, stderr = 0, "root:x:0:0:root:/root:/bin/bash", ""
            else:
                code, stdout, stderr = 127, "", "command unavailable in test"
            return subprocess.CompletedProcess(command, code, stdout, stderr)

        output = io.StringIO()
        def open_file(*args, **kwargs):
            content = host_files.get(str(args[0]))
            if content is not None:
                return io.StringIO(content)
            raise OSError("file unavailable in test")
        def stat_file(path, *args, **kwargs):
            if str(path).startswith("/etc/init.d/"):
                if str(path) not in host_files:
                    raise FileNotFoundError(str(path))
                return os.stat_result((0o100755, 0, 0, 1, 0, 0, len(host_files[str(path)] or ""), 0, 0, 0))
            return original_stat(path, *args, **kwargs)
        with patch("subprocess.run", side_effect=execute), patch("shutil.which", side_effect=lambda name: "/test/" + name if name in available_tools else None), \
                patch("builtins.open", side_effect=open_file), patch("os.path.exists", side_effect=lambda name: name not in absent_paths), \
                patch("os.path.isdir", side_effect=lambda name: name == "/etc/init.d" and init in {"sysv", "init"}), patch("os.stat", side_effect=stat_file), \
                patch.dict(os.environ, {"AUDIT_PROFILE": profile, "AUDIT_RULES_JSON": json.dumps(RULES if rules is None else rules)}), contextlib.redirect_stdout(output):
            exec(compile(SOURCE, str(PLAYBOOK), "exec"), {})
        self.last_commands = commands
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
        report, findings = self.execute_audit({systemd_show("auditd"): (1, "", "Failed to connect to bus")})
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

    def check_nft_input(self, data, expected, iptables=(0, "-P INPUT ACCEPT", ""), overrides=None):
        commands = {
            ("ufw", "status"): (0, "Status: inactive", ""),
            ("firewall-cmd", "--state"): (0, "running", ""),
            ("nft", "-j", "list", "ruleset"): (0, data, ""),
            ("iptables", "-S"): iptables,
        }
        commands.update(overrides or {})
        report, findings = self.execute_audit(commands)
        result = findings["firewall_active"]
        self.assertEqual(result["status"], expected, result["evidence"])
        self.assertEqual("firewall_active" in report["scanner"]["incompleteChecks"], expected == "manual")
        for marker in ("scope=local_input", "packet_model=new_non_loopback_non_dnat_tcp_udp",
                       "evaluation=conditional_ruleset_path", "external_reachability=unverified", "filter_coverage="):
            self.assertIn(marker, result["evidence"])
        self.assertIn("nftables=" + data, result["evidence"])
        return report, result

    def test_native_firewalld_input_clauses_and_runtime_allow_all_restore(self):
        for phase, allow_all, expected in (("baseline", False, "passed"), ("allow_all", True, "failed"), ("restored", False, "passed")):
            with self.subTest(phase=phase):
                _, result = self.check_nft_input(firewalld_input_graph(allow_all), expected)
                if expected == "passed":
                    self.assertTrue(result["evidence"].startswith("backend=firewalld;"))
                self.assertIn("без DNAT", result["title"])
                self.assertIn("условный путь", result["description"])

    def test_exact_captured_alma_ruleset_baseline_single_accept_and_restored(self):
        snapshot = (Path(__file__).parent / "fixtures" / "firewalld-almalinux9-main-2026-11-01.nft.json").read_text()
        changed = json.loads(snapshot)
        self.assertTrue(any(entry.get("chain", {}).get("name") == "filter_IN_public_pre" for entry in changed["nftables"]))
        self.assertFalse(any(entry.get("rule", {}).get("chain") == "filter_IN_public_pre" for entry in changed["nftables"]))
        changed["nftables"].append({"rule": {"family": "inet", "table": "firewalld", "chain": "filter_IN_public_pre", "expr": [{"accept": None}]}})
        for phase, data, expected in (("baseline", snapshot, "passed"), ("single_accept", json.dumps(changed), "failed"), ("restored", snapshot, "passed")):
            with self.subTest(phase=phase):
                _, result = self.check_nft_input(data, expected)
                proofs = json.loads(result["evidence"].split("filter_proofs=", 1)[1].split("; ", 1)[0])
                if expected == "passed":
                    self.assertEqual(proofs["nftables"], {"kind": "deny_witness", "family": "ip", "protocol": "tcp", "destination_port": 1,
                                                          "deny_chains": ["inet/firewalld/filter_INPUT"], "evaluated_input_chains": ["inet/firewalld/filter_INPUT"]})
                    self.assertIn("filter_coverage=nftables:active,iptables:inactive", result["evidence"])
                else:
                    self.assertEqual(proofs["nftables"], {})
                    self.assertIn("filter_coverage=nftables:inactive,iptables:inactive", result["evidence"])

    def test_deny_witness_records_the_actual_ip_family_protocol_port_and_chains(self):
        for family in ("ip", "ip6", "inet"):
            with self.subTest(family=family):
                _, result = self.check_nft_input(nft_graph({"input": "drop"}, {}, family), "passed")
                proof = json.loads(result["evidence"].split("filter_proofs=", 1)[1].split("; ", 1)[0])["nftables"]
                self.assertEqual(proof, {"kind": "deny_witness", "family": "ip" if family == "inet" else family,
                                         "protocol": "tcp", "destination_port": 1,
                                         "deny_chains": [family + "/filter/input"], "evaluated_input_chains": [family + "/filter/input"]})
        entries = json.loads(nft_graph({"input": "accept"}, {}, "ip"))["nftables"]
        entries.extend(json.loads(nft_graph({"input": "drop"}, {}, "ip6"))["nftables"])
        _, result = self.check_nft_input(json.dumps({"nftables": entries}), "passed")
        proof = json.loads(result["evidence"].split("filter_proofs=", 1)[1].split("; ", 1)[0])["nftables"]
        self.assertEqual(proof["family"], "ip6")
        self.assertEqual(proof["evaluated_input_chains"], ["ip6/filter/input"])
        _, findings = self.execute_audit()
        proof = json.loads(findings["firewall_active"]["evidence"].split("filter_proofs=", 1)[1].split("; ", 1)[0])["iptables"]
        self.assertEqual(proof["family"], "ip")
        self.assertEqual(proof["deny_chains"], ["INPUT"])

    def test_nft_goto_does_not_push_a_jump_return_position(self):
        examples = [
            ("goto_skips_later_drop", "accept", {"input": [[{"goto": {"target": "empty"}}], [{"drop": None}]], "empty": []}, "failed"),
            ("goto_resumes_last_jump", "drop", {"input": [[{"jump": {"target": "a"}}], [{"accept": None}]],
                                               "a": [[{"goto": {"target": "empty"}}], [{"drop": None}]], "empty": []}, "failed"),
            ("goto_uses_original_base_policy", "drop", {"input": [[{"goto": {"target": "empty"}}], [{"accept": None}]], "empty": []}, "passed"),
            ("base_return_uses_policy", "drop", {"input": [[{"return": None}]]}, "passed"),
            ("jump_resumes_after_empty_chain", "accept", {"input": [[{"jump": {"target": "empty"}}], [{"drop": None}]], "empty": []}, "passed"),
            ("explicit_return_skips_goto_caller", "drop", {"input": [[{"jump": {"target": "a"}}], [{"accept": None}]],
                                                         "a": [[{"goto": {"target": "b"}}], [{"drop": None}]], "b": [[{"return": None}]]}, "failed"),
        ]
        for name, policy, rules, expected in examples:
            with self.subTest(name=name):
                self.check_nft_input(nft_graph({"input": policy}, rules), expected)

    def test_nft_ct_status_model_knows_only_absence_of_literal_dnat(self):
        for right, operation, expected in [
            ("dnat", "in", "passed"), ("dnat", "==", "passed"), ("dnat", "!=", "failed"),
            ("confirmed", "in", "manual"), ("assured", "in", "manual"), ("snat", "in", "manual"),
            ({"set": ["dnat", "confirmed"]}, "in", "manual"), (32, "in", "manual"),
        ]:
            with self.subTest(right=right, operation=operation):
                rules = [[nft_match({"ct": {"key": "status"}}, right, operation), {"accept": None}]]
                self.check_nft_input(nft_input(expressions=rules), expected)
        bitwise = nft_match({"&": [{"ct": {"key": "status"}}, 32]}, 0, "==")
        self.check_nft_input(nft_input(expressions=[[bitwise, {"accept": None}]]), "manual")

    def test_unmodelled_bitmask_operands_are_not_scalar_no_match(self):
        # libnftables-json defines "in" as LHS & RHS != 0. Do not assume
        # scalar equality or a native lookup form that has not been evaluated.
        for left, right in (({"meta": {"key": "l4proto"}}, 6),
                            ({"ct": {"key": "state"}}, 8),
                            ({"ct": {"key": "state"}}, {"set": [8, "established"]}),
                            ({"ct": {"key": "state"}}, "future-state")):
            with self.subTest(left=left, right=right):
                self.check_nft_input(nft_input(expressions=[[nft_match(left, right, "in"), {"accept": None}]]), "manual")
        for right in (65535, {"set": [1, 22]}, {"range": [1, 65535]}):
            with self.subTest(dport=right):
                rules = [
                    [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, right, "in"), {"accept": None}],
                    [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, 0), {"accept": None}],
                    [nft_match({"meta": {"key": "l4proto"}}, "udp"), {"accept": None}],
                ]
                self.check_nft_input(nft_input(expressions=rules), "manual")

    def test_nft_typed_icmp_conditions_are_unreachable_but_ip_address_is_not_l4(self):
        rules = [[nft_match({"payload": {"protocol": protocol, "field": "type"}}, kind), {"accept": None}]
                 for protocol, kind in (("icmp", "echo-request"), ("icmpv6", "nd-neighbor-solicit"))]
        self.check_nft_input(nft_input(expressions=rules), "passed")
        for protocol in ("ip", "ip6"):
            with self.subTest(protocol=protocol):
                condition = nft_match({"payload": {"protocol": protocol, "field": "daddr"}}, "192.0.2.1" if protocol == "ip" else "2001:db8::1")
                self.check_nft_input(nft_input(expressions=[[condition, {"accept": None}]]), "manual")

    def test_unknown_pure_predicate_branches_and_unreachable_action_does_not_poison(self):
        condition = nft_match({"fib": {"result": "type", "flags": ["daddr", "iif"]}}, "local")
        self.check_nft_input(nft_input(expressions=[[condition, {"accept": None}]]), "manual")
        self.check_nft_input(nft_input(expressions=[[condition, {"reject": None}]]), "passed")
        # An unknown match is not an unknown mutation: both branches deny.
        self.check_nft_input(nft_input(expressions=[[condition, {"drop": None}], [{"drop": None}]]), "passed")
        self.check_nft_input(nft_input(expressions=[[{"accept": None}], [{"vmap": {"key": {}, "data": "@opaque"}}], [{"drop": None}]]), "failed")
        unreachable = [nft_match({"payload": {"protocol": "icmpv6", "field": "type"}}, "nd-neighbor-solicit"), {"vmap": {"key": {}, "data": "@opaque"}}]
        self.check_nft_input(nft_input(expressions=[unreachable]), "passed")

    def test_symbolic_port_pass_cannot_infer_allow_all_from_finite_probes(self):
        clauses = [nft_match({"payload": {"protocol": protocol, "field": "dport"}}, {"set": [1, 22, 23, 80, 443, 65535]})
                   for protocol in ("tcp", "udp")]
        self.check_nft_input(nft_input(expressions=[[condition, {"accept": None}] for condition in clauses]), "manual")
        self.check_nft_input(nft_input(policy="accept", expressions=[[condition, {"accept": None}] for condition in clauses]), "failed")

    def test_opaque_packet_mutation_in_another_input_chain_blocks_a_deny_witness(self):
        rewrite = [nft_match({"meta": {"key": "l4proto"}}, "tcp"),
                   {"mangle": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "value": 80}}]
        deny = [nft_match({"payload": {"protocol": "tcp", "field": "dport"}}, 1), {"drop": None}]
        data = nft_graph({"rewrite": "accept", "later": "accept"}, {"rewrite": [rewrite], "later": [deny, [{"accept": None}]]})
        self.check_nft_input(data, "manual")
        # A mutation after a terminal accept is unreachable and cannot alter a
        # witness evaluated by another base chain.
        data = nft_graph({"rewrite": "accept", "later": "accept"}, {"rewrite": [[{"accept": None}], rewrite], "later": [deny, [{"accept": None}]]})
        self.check_nft_input(data, "passed")

    def test_unknown_packet_filter_cannot_be_overridden_by_another_backend(self):
        restrictive_iptables = (0, "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 1 -j DROP", "")
        opaque = nft_input(policy="accept", expressions=[[nft_match({"meta": {"key": "l4proto"}}, "tcp"),
            {"mangle": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "value": 80}}]])
        self.check_nft_input(opaque, "manual", restrictive_iptables)
        for code, output, error in ((1, "", "Operation not permitted"), (0, "{\"nftables\":[", "")):
            with self.subTest(nft_error=error or "truncated"):
                report, findings = self.execute_audit({("nft", "-j", "list", "ruleset"): (code, output, error), ("iptables", "-S"): restrictive_iptables})
                self.assertEqual(findings["firewall_active"]["status"], "manual")
                self.assertIn("nftables:unknown", findings["firewall_active"]["evidence"])
                self.assertIn("incomplete_reason=", findings["firewall_active"]["evidence"])
                self.assertIn("firewall_active", report["scanner"]["incompleteChecks"])
        for iptables in ((1, "", "Permission denied"), (0, "-P INPUT DROP\n-A INPUT -j QUEUE", "")):
            with self.subTest(iptables=iptables):
                _, result = self.check_nft_input(nft_input(), "manual", iptables)
                self.assertIn("iptables:unknown", result["evidence"])

    def test_safe_probe_in_each_backend_cannot_hide_mutation_of_the_other_witness(self):
        rewrite = [nft_match({"meta": {"key": "l4proto"}}, "tcp"),
                   {"mangle": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "value": 80}}]
        deny_udp = [nft_match({"payload": {"protocol": "udp", "field": "dport"}}, 1), {"drop": None}]
        data = json.loads(nft_graph({"early": "accept", "late": "accept"}, {"early": [rewrite], "late": [deny_udp]}))
        for entry in data["nftables"]:
            if "chain" in entry:
                entry["chain"]["prio"] = -10 if entry["chain"]["name"] == "early" else 10
        # The queue consumer may change UDP before the later nft chain. The
        # earlier nft mutation already bypassed the iptables TCP deny. Neither
        # frontend's otherwise safe probe can stand in for the combined path.
        iptables = (0, "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 1 -j DROP\n-A INPUT -p udp -j NFQUEUE", "")
        _, result = self.check_nft_input(json.dumps(data), "manual", iptables)
        self.assertIn("filter_coverage=nftables:unknown,iptables:unknown", result["evidence"])
        proofs = json.loads(result["evidence"].split("filter_proofs=", 1)[1].split("; ", 1)[0])
        self.assertEqual(proofs["nftables"]["incomplete_reason"], "unresolved_input_path")
        self.assertEqual(proofs["iptables"]["incomplete_reason"], "unresolved_input_path")

    def test_packet_filter_cycle_missing_target_and_work_bounds_stay_unknown(self):
        fixtures = {
            "cycle": nft_graph({"input": "drop"}, {"input": [[{"jump": {"target": "loop"}}]], "loop": [[{"goto": {"target": "loop"}}]]}),
            "missing_target": nft_graph({"input": "drop"}, {"input": [[{"goto": {"target": "absent"}}]]}),
            "depth_bound": nft_input(expressions=[[{"counter": {"packets": 0, "bytes": 0}}] for _ in range(140)]),
        }
        unknown = nft_match({"meta": {"key": "mark"}}, 123)
        # Short chains with a branching graph exhaust the total work budget,
        # independently of the depth limit, and must not produce a deny proof.
        branching = {"input": [[{"jump": {"target": "level0"}}]]}
        for level in range(14):
            target = "level" + str(level + 1)
            branching["level" + str(level)] = [[unknown, {"jump": {"target": target}}], [{"jump": {"target": target}}]]
        branching["level14"] = [[{"drop": None}]]
        fixtures["work_bound"] = nft_graph({"input": "drop"}, branching)
        for name, data in fixtures.items():
            with self.subTest(name=name):
                self.check_nft_input(data, "manual")

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
        _, findings = self.execute_audit({systemd_show("auditd"): (0, "LoadState=loaded\nActiveState=inactive", "")})
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
        _, findings = self.execute_audit({("nginx", "-T"): (0, "# server_tokens off;", "")}, profile="web_server")
        self.assertEqual(findings["nginx_server_tokens"]["status"], "manual")
        self.assertEqual(findings["nginx_server_tokens"]["evidence"], "server_tokens=not found")

    def test_systemd_transient_malformed_and_failed_queries_remain_unknown(self):
        for response in (
            (0, "LoadState=loaded\nActiveState=activating", ""),
            (0, "LoadState=loaded\nActiveState=deactivating", ""),
            (0, "LoadState=loaded\nActiveState=reloading", ""),
            (0, "LoadState=error\nActiveState=inactive", ""),
            (0, "LoadState=not-found\nActiveState=active", ""),
            (0, "active", ""),
            (0, "LoadState=loaded\nActiveState=active\nActiveState=inactive", ""),
            (1, "LoadState=loaded\nActiveState=active", "permission denied"),
            subprocess.TimeoutExpired("systemctl", 8),
        ):
            with self.subTest(response=response):
                report, findings = self.execute_audit({systemd_show("auditd"): response})
                self.assertEqual(findings["service_auditd_active"]["status"], "manual")
                self.assertIn("service_auditd", report["scanner"]["incompleteChecks"])

    def test_systemd_semantic_aliases_use_the_actual_service_without_duplicate_queries(self):
        rules = dict(RULES, service_rules=[{"service": name, "title": name, "recommendation": "Review"} for name in ("ssh", "cron", "apache2")])
        overrides = {systemd_show(name): (0, "LoadState=not-found\nActiveState=inactive", "") for name in ("ssh", "cron", "apache2")}
        report, findings = self.execute_audit(overrides, rules=rules)
        for requested, actual in (("ssh", "sshd"), ("cron", "crond"), ("apache2", "httpd")):
            self.assertEqual(findings["service_" + requested + "_active"]["status"], "passed")
            self.assertIn("service=" + actual, findings["service_" + requested + "_active"]["evidence"])
            self.assertEqual(self.last_commands.count(systemd_show(actual)), 1)
        self.assertEqual(report["agentless"]["serviceManager"], "systemd")

    def test_an_unknown_alias_is_not_hidden_by_a_known_inactive_alias(self):
        rules = dict(RULES, service_rules=[{"service": "ssh", "title": "SSH", "recommendation": "Review"}])
        report, findings = self.execute_audit({
            systemd_show("ssh"): (0, "LoadState=not-found\nActiveState=inactive", ""),
            systemd_show("sshd"): (1, "", "Failed to connect to bus"),
        }, rules=rules)
        self.assertEqual(findings["service_ssh_active"]["status"], "manual")
        self.assertIn("service_ssh", report["scanner"]["incompleteChecks"])

    def test_openrc_states_follow_native_status_contract_and_ignore_installed_systemctl(self):
        for code, state, expected in ((0, "started", "passed"), (3, "stopped", "failed"), (16, "inactive", "failed"),
                                      (32, "crashed", "failed"), (4, "stopping", "manual"), (8, "starting", "manual"),
                                      (1, "permission denied", "manual"), (0, "stopped", "manual"), (3, "started", "manual")):
            with self.subTest(code=code, state=state):
                report, findings = self.execute_audit({
                    ("rc-service", "--exists", "auditd"): (0, "", ""),
                    ("rc-service", "--nocolor", "auditd", "status"): (code, " * status: " + state, ""),
                }, init="openrc")
                self.assertEqual(findings["service_auditd_active"]["status"], expected)
                self.assertEqual(report["agentless"]["serviceManager"], "openrc")
                self.assertFalse(any(command[0] == "systemctl" for command in self.last_commands))
                self.assertFalse(any(word in {"start", "stop", "restart", "reload"} for command in self.last_commands for word in command))

    def test_openrc_missing_service_differs_from_failed_existence_query(self):
        for response, expected in (((1, "", ""), "failed"), ((1, "", "permission denied"), "manual"), ((127, "", "missing command"), "manual")):
            with self.subTest(response=response):
                _, findings = self.execute_audit({("rc-service", "--exists", "auditd"): response}, init="openrc")
                self.assertEqual(findings["service_auditd_active"]["status"], expected)

    def test_sysv_uses_only_lsb_status_and_keeps_unknown_codes_explicit(self):
        script = "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: auditd\n### END INIT INFO\n"
        for code, expected in ((0, "passed"), (1, "failed"), (2, "failed"), (3, "failed"), (4, "manual"), (5, "manual"), (127, "manual")):
            with self.subTest(code=code):
                report, findings = self.execute_audit({("/etc/init.d/auditd", "status"): (code, "native status", "")},
                    init="sysv", files={"/etc/init.d/auditd": script})
                self.assertEqual(report["agentless"]["serviceManager"], "sysv")
                self.assertEqual(findings["service_auditd_active"]["status"], expected)
                self.assertEqual([command for command in self.last_commands if command[0].startswith("/etc/init.d/")], [("/etc/init.d/auditd", "status")])

    def test_sysv_missing_unreadable_non_lsb_and_oversize_scripts_remain_distinct(self):
        for files, expected in (({}, "failed"), ({"/etc/init.d/auditd": None}, "manual"),
                                ({"/etc/init.d/auditd": "#!/bin/sh\nexit 0\n"}, "manual"),
                                ({"/etc/init.d/auditd": "#" * 65537}, "manual")):
            with self.subTest(expected=expected, size=len(str(files))):
                _, findings = self.execute_audit(init="sysv", files=files)
                self.assertEqual(findings["service_auditd_active"]["status"], expected)
                self.assertFalse(any(command[0].startswith("/etc/init.d/") for command in self.last_commands))

    def test_generic_init_does_not_prove_sysv_or_absence_of_a_running_service(self):
        report, findings = self.execute_audit(init="init")
        self.assertEqual(report["agentless"]["serviceManager"], "unknown")
        self.assertIn("init_identity=unverified", report["agentless"]["serviceManagerEvidence"])
        self.assertEqual(findings["service_auditd_active"]["status"], "manual")
        self.assertIn("init_script_missing; service_manager_unverified", findings["service_auditd_active"]["evidence"])
        self.assertIn("service_auditd", report["scanner"]["incompleteChecks"])
        self.assertFalse(any(command[0].startswith("/etc/init.d/") for command in self.last_commands))
        script = "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: auditd\n### END INIT INFO\n"
        for code, expected in ((0, "passed"), (3, "failed"), (4, "manual")):
            with self.subTest(code=code):
                report, findings = self.execute_audit({("/etc/init.d/auditd", "status"): (code, "LSB observed status", "")},
                    init="init", files={"/etc/init.d/auditd": script})
                self.assertEqual(report["agentless"]["serviceManager"], "unknown")
                self.assertEqual(findings["service_auditd_active"]["status"], expected)
                self.assertEqual([command for command in self.last_commands if command[0].startswith("/etc/init.d/")], [("/etc/init.d/auditd", "status")])

    def test_unverified_init_does_not_guess_from_installed_service_binaries(self):
        for init, files in (("tini", {}), ("unknown", {"/proc/1/comm": None}), ("openrc", {"/run/openrc/softlevel": None})):
            with self.subTest(init=init):
                report, findings = self.execute_audit(init=init, files=files)
                self.assertEqual(report["agentless"]["serviceManager"], "unknown")
                self.assertEqual(findings["service_auditd_active"]["status"], "manual")
                self.assertFalse(any(command[0] in {"systemctl", "rc-service"} for command in self.last_commands))

    def test_web_profile_resolves_httpd_and_preserves_configuration_errors(self):
        report, findings = self.execute_audit({
            systemd_show("apache2"): (0, "LoadState=not-found\nActiveState=inactive", ""),
            systemd_show("nginx"): (0, "LoadState=not-found\nActiveState=inactive", ""),
            ("httpd", "-t", "-D", "DUMP_RUN_CFG"): (1, "", "Syntax error"),
        }, profile="web_server", tools={"systemctl", "httpd", "dpkg-query", "apt"})
        self.assertEqual(findings["web_service_apache2"]["status"], "passed")
        self.assertNotIn("web_profile_not_applicable", findings)
        self.assertEqual(findings["apache_config_unavailable"]["status"], "manual")
        self.assertIn("apache_configuration", report["scanner"]["incompleteChecks"])
        self.assertFalse(any(command[0] in {"bash", "sh"} for command in self.last_commands))

    def test_direct_nginx_query_retains_configuration_written_to_stderr(self):
        _, findings = self.execute_audit({("nginx", "-T"): (0, "", "# configuration file /etc/nginx/nginx.conf:\nserver_tokens off;")}, profile="web_server")
        self.assertEqual(findings["nginx_server_tokens"]["evidence"], "server_tokens=off")

    def test_authentication_files_have_an_explicit_bounded_scope(self):
        _, findings = self.execute_audit({("tail", "-n", "1000", "/var/log/auth.log"): (0, "\n".join(["Failed password old"] * 2 + ["Accepted publickey"] * 999 + ["Invalid user recent"]), "")})
        evidence = findings["failed_logins"]["evidence"]
        self.assertIn("scope=last_1000_lines_per_file", evidence)
        self.assertIn("Invalid user recent", evidence)
        self.assertNotIn("Failed password old", evidence)
        self.assertEqual(findings["failed_logins"]["status"], "manual")
        self.assertFalse(any(command[-1] in {"/var/log/messages", "/var/log/syslog"} for command in self.last_commands))

    def test_mixed_syslog_fallback_keeps_bounded_events_without_proving_auth_routing(self):
        primary = ("/var/log/auth.log", "/var/log/secure", "/var/log/authlog")
        for logfile in ("/var/log/messages", "/var/log/syslog"):
            with self.subTest(logfile=logfile):
                other = "/var/log/syslog" if logfile.endswith("messages") else "/var/log/messages"
                lines = ["Failed password old"] * 2 + ["unrelated service event"] * 999 + ["Invalid user alpine-fixture"]
                report, findings = self.execute_audit({("tail", "-n", "1000", logfile): (0, "\n".join(lines), "")},
                    init="openrc", absent_paths=primary + (other,))
                evidence = findings["failed_logins"]["evidence"]
                self.assertIn("log_class=mixed_syslog", evidence)
                self.assertIn("scope=last_1000_lines_per_file", evidence)
                self.assertIn("authentication_routing=unverified", evidence)
                self.assertIn("Invalid user alpine-fixture", evidence)
                self.assertNotIn("Failed password old", evidence)
                self.assertIn("failed_logins", report["scanner"]["incompleteChecks"])
                self.assertIsNone(report["summary"]["score"])
        report, findings = self.execute_audit(absent_paths=primary)
        self.assertEqual(findings["failed_logins"]["title"], "Журналы аутентификации не проверены")
        self.assertIn("failed_logins", report["scanner"]["incompleteChecks"])

    def test_journald_fallback_requires_readable_probe_and_preserves_detection(self):
        probe = ("journalctl", "--no-pager", "--output=json", "--lines=1")
        query = ("journalctl", "--no-pager", "--output=json", "--since=-24h", "--lines=1000", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")
        entry = json.dumps({"__REALTIME_TIMESTAMP": "1793350000000000", "MESSAGE": "Failed password for invalid user fixture"})
        paths = ("/var/log/auth.log", "/var/log/secure", "/var/log/authlog", "/var/log/messages", "/var/log/syslog")
        report, findings = self.execute_audit({probe: (0, entry, ""), query: (0, entry, "")}, tools={"systemctl", "journalctl", "apt", "dpkg-query"}, absent_paths=paths)
        self.assertIn("Failed password for invalid user fixture", findings["failed_logins"]["evidence"])
        self.assertIn("source=journald", findings["failed_logins"]["evidence"])
        self.assertIn("last_24h_max_1000_entries", findings["failed_logins"]["evidence"])
        self.assertNotIn("failed_logins", report["scanner"]["incompleteChecks"])
        for response in ((0, "", ""), (0, entry, "Hint: not seeing messages from other users"), (1, "", "permission denied")):
            with self.subTest(response=response):
                report, findings = self.execute_audit({probe: response}, tools={"systemctl", "journalctl", "apt", "dpkg-query"}, absent_paths=paths)
                self.assertIn("failed_logins", report["scanner"]["incompleteChecks"])
                self.assertNotIn(query, self.last_commands)

    def test_malformed_journal_retains_observed_failures_and_marks_collection_incomplete(self):
        probe = ("journalctl", "--no-pager", "--output=json", "--lines=1")
        query = ("journalctl", "--no-pager", "--output=json", "--since=-24h", "--lines=1000", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")
        entry = json.dumps({"__REALTIME_TIMESTAMP": "1793350000000000", "MESSAGE": "Authentication failure fixture"})
        report, findings = self.execute_audit({probe: (0, entry, ""), query: (0, entry + "\ninvalid JSON", "")},
            tools={"systemctl", "journalctl", "apt", "dpkg-query"}, absent_paths=("/var/log/auth.log", "/var/log/secure", "/var/log/authlog", "/var/log/messages", "/var/log/syslog"))
        self.assertIn("Authentication failure fixture", findings["failed_logins"]["evidence"])
        self.assertIn("failed_logins", report["scanner"]["incompleteChecks"])
        self.assertIsNone(report["summary"]["score"])

    def test_target_program_preserves_python35_syntax(self):
        ast.parse(SOURCE, feature_version=(3, 5))

    def test_evaluator_version_is_independent_of_profile_rules_provenance(self):
        for version in ("1.1.0", "custom-policy-42"):
            with self.subTest(rules_version=version):
                report, findings = self.execute_audit(rules=dict(RULES, audit_rules_version=version, evaluatorVersion="custom-override"))
                self.assertEqual(report["schemaVersion"], 1)
                self.assertEqual(report["agentless"]["version"], version)
                self.assertEqual(report["agentless"]["evaluatorVersion"], "1.2.0")
                self.assertIn("filter_proofs=", findings["firewall_active"]["evidence"])


if __name__ == "__main__":
    unittest.main()
