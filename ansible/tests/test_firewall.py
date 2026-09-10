"""Behavioural firewall tests. All commands and /etc paths are isolated."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("firewall", Path(__file__).parents[1] / "scripts/hcp-firewall.py")
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


def args(**values):
    return argparse.Namespace(**{**dict(operation="closePort", port=8080, protocol="tcp", ssh_port=2222,
                                       ip="198.51.100.42", ssh_client="192.0.2.10", protected_ip=["192.0.2.20"],
                                       check=False, transaction="txn-test-backup-12345678"), **values})


class FirewallTests(unittest.TestCase):
    def test_ufw_deny_moves_before_allow_and_is_idempotent(self):
        rows = ["8080/tcp ALLOW IN Anywhere", "8080/tcp DENY IN Anywhere"]
        calls = []
        def command(*argv, **kwargs):
            calls.append(argv)
            if argv == ("ufw", "status", "numbered"):
                return subprocess.CompletedProcess(argv, 0, "\n".join(f"[ {i+1}] {row}" for i, row in enumerate(rows)), "")
            if argv[:3] == ("ufw", "--force", "delete"):
                rows.remove("8080/tcp DENY IN Anywhere")
            if argv[:3] == ("ufw", "insert", "1"):
                rows.insert(0, "8080/tcp DENY IN Anywhere")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(fw, "backend", return_value="ufw"), patch.object(fw, "run", side_effect=command):
            self.assertTrue(fw.close_or_block(args())["changed"])
            self.assertEqual(rows[0], "8080/tcp DENY IN Anywhere")
            before = len(calls)
            self.assertFalse(fw.close_or_block(args())["changed"])
            self.assertTrue(all(call[:2] == ("ufw", "status") for call in calls[before:]))

    def test_preview_never_executes_mutating_commands(self):
        calls = []
        def command(*argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "[ 1] 8080/tcp ALLOW IN Anywhere\n", "")
        with patch.object(fw, "backend", return_value="ufw"), patch.object(fw, "run", side_effect=command):
            self.assertTrue(fw.close_or_block(args(check=True))["changed"])
        self.assertEqual(calls, [("ufw", "status", "numbered")])

    def test_firewalld_rich_rule_is_one_argument_and_covers_runtime_and_permanent(self):
        rules = set()
        calls = []
        def command(*argv, **kwargs):
            calls.append(argv)
            if argv[-1] == "--get-active-zones":
                return subprocess.CompletedProcess(argv, 0, "public\n  interfaces: eth0\n", "")
            if argv[-1] == "--get-default-zone":
                return subprocess.CompletedProcess(argv, 0, "public\n", "")
            permanent = "--permanent" in argv
            if argv[-1].startswith("--query-rich-rule="):
                return subprocess.CompletedProcess(argv, 0 if (permanent, argv[-1].split("=", 1)[1]) in rules else 1, "", "")
            if argv[-1].startswith("--add-rich-rule="):
                rules.add((permanent, argv[-1].split("=", 1)[1]))
                return subprocess.CompletedProcess(argv, 0, "success", "")
            self.fail(f"Unexpected command: {argv}")
        with patch.object(fw, "backend", return_value="firewalld"), patch.object(fw, "run", side_effect=command):
            self.assertTrue(fw.close_or_block(args())["changed"])
            self.assertFalse(fw.close_or_block(args())["changed"])
        self.assertEqual(len(rules), 4)
        self.assertTrue(all('priority="-32768"' in rule for _, rule in rules))
        self.assertTrue(all(not any(arg == "drop" for arg in call) for call in calls))

    def test_management_endpoints_and_nondefault_ssh_port_are_rejected(self):
        with patch.object(fw, "backend", return_value="ufw"), patch.object(fw, "run") as command:
            for request in (args(port=2222), args(port=22), args(operation="blockIp", ip="192.0.2.10"),
                            args(operation="blockIp", ip="192.0.2.20"), args(operation="blockIp", ssh_client="")):
                with self.assertRaises(fw.FirewallError):
                    fw.close_or_block(request)
            command.assert_not_called()

    def test_inactive_or_conflicting_firewall_is_rejected(self):
        with patch.object(fw.shutil, "which", return_value=None):
            with self.assertRaises(fw.FirewallError): fw.backend()
        with patch.object(fw.shutil, "which", return_value="/fake"), patch.object(fw, "run", side_effect=[subprocess.CompletedProcess([], 0, "Status: active", ""), subprocess.CompletedProcess([], 0, "running", "")]):
            with self.assertRaises(fw.FirewallError): fw.backend()

    def test_process_errors_are_never_suppressed(self):
        with patch.object(fw.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "", "bad rule")):
            with self.assertRaisesRegex(fw.FirewallError, "bad rule"):
                fw.run("firewall-cmd", '--add-rich-rule=rule drop')

    def test_divergent_runtime_configuration_blocks_unsafe_backup(self):
        with patch.object(fw, "run", side_effect=[subprocess.CompletedProcess([], 0, "public runtime-rule", ""), subprocess.CompletedProcess([], 0, "public", "")]):
            with self.assertRaisesRegex(fw.FirewallError, "runtime and permanent"):
                fw.persistent_firewalld()

    def test_transaction_traversal_and_archive_links_are_rejected(self):
        for transaction in ("../etc", "........", "txn-../../etc", "txn-ok/../bad"):
            with self.assertRaises(fw.FirewallError): fw.transaction_dir(args(transaction=transaction))
        for name, kind in (("etc/ufw/../../passwd", tarfile.REGTYPE), ("etc/ufw/link", tarfile.SYMTYPE), ("etc/passwd", tarfile.REGTYPE)):
            member = tarfile.TarInfo(name)
            member.type = kind
            with patch.object(tarfile.TarFile, "getmembers", return_value=[member]):
                with self.assertRaises(fw.FirewallError): fw.validate_members(tarfile.TarFile.__new__(tarfile.TarFile), "ufw")

    def test_real_archive_round_trip_removes_new_files_and_detects_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = root / "etc"
            (configuration / "ufw").mkdir(parents=True)
            (configuration / "machine-id").write_text("test-machine-id")
            rules = configuration / "ufw/user.rules"
            rules.write_text("original rules")
            with patch.object(fw, "CONFIG_ROOT", configuration), patch.object(fw, "BACKUP_ROOT", root / "backups"), patch.object(fw, "backend", return_value="ufw"), patch.object(fw, "run") as command:
                result = fw.backup(args())
                rules.write_text("modified rules")
                (configuration / "ufw/extra.rules").write_text("added rules")
                fw.rollback(args())
                self.assertEqual(rules.read_text(), "original rules")
                self.assertFalse((configuration / "ufw/extra.rules").exists())
                command.assert_called_once_with("ufw", "reload")
                Path(result["backupRef"]).write_bytes(b"corrupted")
                with self.assertRaisesRegex(fw.FirewallError, "checksum"):
                    fw.rollback(args())
                self.assertEqual(rules.read_text(), "original rules")


if __name__ == "__main__":
    unittest.main()
