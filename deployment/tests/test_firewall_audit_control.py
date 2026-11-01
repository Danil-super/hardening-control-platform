"""Controller regressions only: synthetic snapshots, no host firewall commands."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "hcp_rpm_vm_acceptance", Path(__file__).with_name("linux_rpm_vm_integration.py"))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


def fixture():
    return {"nftables": [
        {"metainfo": {"version": "fixture", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "firewalld", "handle": 1, "flags": ["owner", "persist"]}},
        {"chain": {"family": "inet", "table": "firewalld", "name": "filter_INPUT", "handle": 2,
                   "type": "filter", "hook": "input", "prio": 10, "policy": "accept"}},
        {"chain": {"family": "inet", "table": "firewalld", "name": "filter_IN_public_pre", "handle": 3}},
        {"rule": {"family": "inet", "table": "firewalld", "chain": "filter_INPUT", "handle": 4,
                  "expr": [{"jump": {"target": "filter_IN_public_pre"}}]}},
        {"rule": {"family": "inet", "table": "firewalld", "chain": "filter_INPUT", "handle": 5,
                  "expr": [{"counter": {"packets": 17, "bytes": 1234}}, {"reject": None}]}},
    ]}


def with_allow_rule(ruleset):
    result = copy.deepcopy(ruleset)
    result["nftables"].append({"rule": {"family": "inet", "table": "firewalld", "chain": "filter_IN_public_pre",
                                         "handle": 6, "expr": [{"accept": None}]}})
    return result


class RulesetGuardTests(unittest.TestCase):
    def test_exact_owned_delta_and_complete_input_inventory(self):
        ruleset = fixture()
        inputs = NATIVE.inspect_firewall_audit_ruleset(ruleset)
        self.assertEqual([item["chain"] for item in inputs], ["filter_INPUT"])
        self.assertEqual(inputs[0]["tableFlags"], ["owner", "persist"])
        NATIVE.verify_firewall_control_delta(ruleset, with_allow_rule(ruleset))
        ruleset["nftables"].extend([
            {"table": {"family": "ip6", "name": "filter"}},
            {"chain": {"family": "ip6", "table": "filter", "name": "INPUT", "type": "filter",
                       "hook": "input", "prio": 0, "policy": "accept"}},
        ])
        self.assertEqual(len(NATIVE.inspect_firewall_audit_ruleset(ruleset)), 2)
        ruleset["nftables"][-1]["chain"]["policy"] = "drop"
        with self.assertRaisesRegex(RuntimeError, "Another active INPUT"):
            NATIVE.inspect_firewall_audit_ruleset(ruleset)

    def test_unknown_flags_policy_type_and_unaccounted_rules_fail_closed(self):
        mutations = [
            lambda r: r["nftables"][1]["table"]["flags"].append("new-owner-mode"),
            lambda r: r["nftables"][1]["table"].update(flags=["persist"]),
            lambda r: r["nftables"][2]["chain"].update(policy="unknown"),
            lambda r: r["nftables"][2]["chain"].update(type="nat"),
            lambda r: r["nftables"][2]["chain"].update(prio="filter"),
            lambda r: r["nftables"][2]["chain"].update(flags=["offload"]),
            lambda r: r["nftables"][4]["rule"].update(chain="unobserved"),
            lambda r: r["nftables"].append(copy.deepcopy(r["nftables"][2])),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                ruleset = fixture()
                mutation(ruleset)
                with self.assertRaises(RuntimeError):
                    NATIVE.inspect_firewall_audit_ruleset(ruleset)

    def test_semantics_ignore_only_handles_and_counter_values(self):
        before, after = fixture(), fixture()
        for entry in after["nftables"]:
            for kind in ("table", "chain", "rule"):
                if kind in entry:
                    entry[kind]["handle"] += 100
        after["nftables"][-1]["rule"]["expr"][0]["counter"].update(packets=99, bytes=12000)
        self.assertEqual(NATIVE.semantic_nftables(before), NATIVE.semantic_nftables(after))
        for mutate in (
            lambda r: r["nftables"][-1]["rule"]["expr"].pop(0),
            lambda r: r["nftables"][-1]["rule"]["expr"][-1].update(reject={"type": "tcp reset"}),
            lambda r: r["nftables"][2]["chain"].update(policy="drop"),
            lambda r: r["nftables"][1]["table"].update(flags=["persist"]),
            lambda r: r["nftables"].reverse(),
        ):
            changed = copy.deepcopy(after)
            mutate(changed)
            self.assertNotEqual(NATIVE.semantic_nftables(before), NATIVE.semantic_nftables(changed))

    def test_extra_kernel_changes_or_conditional_accept_are_rejected(self):
        for change in (
            lambda r: r["nftables"][2]["chain"].update(policy="drop"),
            lambda r: r["nftables"][-1]["rule"]["expr"].insert(0, {"match": {"left": "dport", "right": 22, "op": "=="}}),
            lambda r: r["nftables"].append(copy.deepcopy(r["nftables"][-1])),
        ):
            allowed = with_allow_rule(fixture())
            change(allowed)
            with self.assertRaises(RuntimeError):
                NATIVE.verify_firewall_control_delta(fixture(), allowed)


class ControlFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hcp-firewall-audit-test-")
        self.addCleanup(self.temporary.cleanup)
        self.artifacts = Path(self.temporary.name)
        (self.artifacts / "reports").mkdir()
        self.active = False
        self.actions, self.audits, self.checkpoints = [], [], []
        self.fail_add_reply = False
        self.failed_audit = False
        self.changed_restore = False
        self.bad_proof = False

    def remote_python(self, code, arguments=(), **kwargs):
        if code == NATIVE.FIREWALL_AUDIT_CONTROL:
            action, marker, rule = arguments
            self.assertRegex(marker, r"^/run/hcp-rpm-firewall-audit-[a-f0-9]{32}$")
            self.assertEqual(rule, NATIVE.FIREWALL_RICH_RULE)
            self.actions.append(action)
            self.active = action == "add"
            if action == "add" and self.fail_add_reply:
                raise RuntimeError("fixture: add succeeded but SSH reply was lost")
            result = {"owned": True, "present": self.active}
        elif code == NATIVE.FIREWALL_AUDIT_SNAPSHOT:
            nft = with_allow_rule(fixture()) if self.active else fixture()
            state = {"selinux": "Enforcing", "pid1": "systemd", "firewalld": "running",
                     "labels": {".": "fixture-selinux-label"}, "manifest": "fixture-config-digest",
                     "runtime": {"zones": NATIVE.FIREWALL_RICH_RULE if self.active else "fixture-baseline"}}
            if "remove" in self.actions and self.changed_restore:
                state["manifest"] = "fixture-unrelated-change"
            result = {"nftables": json.dumps(nft), "state": state}
        else:
            raise AssertionError("Unrecognized remote fixture program")
        return SimpleNamespace(stdout=json.dumps(result), returncode=0)

    def playbook(self, name, phase, extra):
        self.assertEqual(name, "agentless-audit")
        self.audits.append(phase)
        status = "failed" if self.active else "passed"
        if self.active and self.failed_audit:
            status = "manual"
        nft = with_allow_rule(fixture()) if self.active else fixture()
        proof = {} if self.active else {"kind": "deny_witness", "family": "ip", "protocol": "tcp", "destination_port": 1,
                                       "deny_chains": ["inet/firewalld/filter_INPUT"],
                                       "evaluated_input_chains": ["inet/firewalld/filter_INPUT"]}
        if self.bad_proof and not self.active:
            proof["evaluated_input_chains"].append("inet/unobserved/INPUT")
        report = {"scanner": {"partial": False, "incompleteChecks": []}, "summary": {"score": 75},
                  "findings": [{"id": "firewall_active", "status": status,
                                "evidence": "packet_model=" + NATIVE.FIREWALL_PACKET_MODEL
                                + "; evaluation=conditional_ruleset_path; external_reachability=unverified; filter_proofs="
                                + json.dumps({"nftables": proof, "iptables": {}}) + "; nftables="
                                + json.dumps(nft)}]}
        path = self.artifacts / "reports" / (NATIVE.HOST + "-basic_linux-" + phase + ".json")
        path.write_text(json.dumps(report))

    def normalization(self, argv, **kwargs):
        self.assertEqual(argv[0], "node")
        destination = self.artifacts / "firewall-audit-normalized"
        destination.mkdir()
        (destination / "protocol.json").write_text(json.dumps({"status": "passed", "syntheticUnitTest": True}))
        return subprocess.CompletedProcess(argv, 0, stdout="")

    def verify(self):
        with patch.object(NATIVE, "run", self.normalization):
            NATIVE.verify_firewall_audit(self.remote_python, self.playbook,
                                        lambda *args: self.checkpoints.append(args), self.artifacts, "fixture-helper.py")

    def test_all_three_reports_and_exact_restore_are_required(self):
        self.verify()
        self.assertEqual(self.actions, ["add", "remove"])
        self.assertEqual(self.audits, ["firewall-audit-baseline", "firewall-audit-allow-all", "firewall-audit-restored"])
        proof = json.loads((self.artifacts / "firewall-audit-protocol.json").read_text())
        self.assertTrue(proof["exactRestoration"])
        self.assertEqual(proof["status"], "passed")
        self.assertEqual(proof["snapshots"][0]["nftSemanticSha256"], proof["snapshots"][2]["nftSemanticSha256"])
        self.assertNotEqual(proof["snapshots"][0]["nftSemanticSha256"], proof["snapshots"][1]["nftSemanticSha256"])

    def test_wrong_negative_audit_still_removes_owned_control_and_cannot_pass(self):
        self.failed_audit = True
        with self.assertRaisesRegex(RuntimeError, "did not produce failed"):
            self.verify()
        self.assertEqual(self.actions, ["add", "remove"])
        self.assertFalse(self.active)
        self.assertTrue((self.artifacts / "firewall-audit-restored.nft.json").is_file())
        proof = json.loads((self.artifacts / "firewall-audit-protocol.json").read_text())
        self.assertEqual(proof["status"], "failed")
        self.assertTrue(proof["exactRestoration"])
        self.assertFalse(self.checkpoints)

    def test_lost_add_reply_still_attempts_owned_cleanup(self):
        self.fail_add_reply = True
        with self.assertRaisesRegex(RuntimeError, "SSH reply was lost"):
            self.verify()
        self.assertEqual(self.actions, ["add", "remove"])
        self.assertFalse(self.active)

    def test_configuration_restore_mismatch_is_a_failure(self):
        self.changed_restore = True
        with self.assertRaisesRegex(RuntimeError, "did not restore exact"):
            self.verify()
        self.assertEqual(self.actions, ["add", "remove"])
        self.assertFalse(self.checkpoints)

    def test_unobserved_positive_proof_chain_blocks_mutation(self):
        self.bad_proof = True
        with self.assertRaisesRegex(RuntimeError, "account for every observed INPUT chain"):
            self.verify()
        self.assertFalse(self.actions)
        self.assertFalse(self.checkpoints)


if __name__ == "__main__":
    unittest.main()
