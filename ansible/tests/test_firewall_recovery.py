"""Real process/FS interruption tests; only temporary files and fake firewall I/O."""
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "scripts/hcp-firewall.py"
spec = importlib.util.spec_from_file_location("firewall_recovery", SCRIPT)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
TRANSACTION = "txn-recovery-native-12345678"

# The child loads the production helper. A real SIGKILL aborts the interpreter
# around durable checkpoints/rename; no finally block can repair its state.
CHILD = r'''
import argparse, importlib.util, json, os, signal, subprocess, sys
from pathlib import Path
source, temporary, operation, failpoint, recovered, transaction = sys.argv[1:]
spec = importlib.util.spec_from_file_location("owned_firewall", source)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
root = Path(temporary)
fw.CONFIG_ROOT, fw.BACKUP_ROOT = root / "etc", root / "backups"
fw.backend = lambda: "ufw"
fw.ufw_ipv6_enabled = lambda: False
args = argparse.Namespace(operation=operation, transaction=transaction, check=False,
    recovery_verified=recovered == "yes", port=8080, protocol="tcp", ssh_port=2222,
    ip="198.51.100.40", ssh_client="192.0.2.10", protected_ip=[])
def stop(name):
    if failpoint == name:
        os.kill(os.getpid(), signal.SIGKILL)
original_checkpoint = fw.rollback_checkpoint
def checkpoint(directory, state, phase):
    stop("before_" + phase)
    original_checkpoint(directory, state, phase)
    stop("after_cleanup_intent" if state.get("cleanupStarted") else "after_" + phase)
fw.rollback_checkpoint = checkpoint
original_sync_directory = fw.sync_directory
def sync_directory(path):
    # The marker replacement has already happened. The following fsync fails,
    # so a completed backup lease exists despite the command's error response.
    if failpoint == "backup_marker_fsync" and path == fw.BACKUP_ROOT and (path / fw.STATE_NAME).exists():
        raise OSError("injected backup marker directory fsync failure")
    return original_sync_directory(path)
fw.sync_directory = sync_directory
original_rename = Path.rename
def rename(path, destination):
    stage = "move_old" if path == fw.CONFIG_ROOT / "ufw" else "install"
    stop("before_rename_" + stage)
    result = original_rename(path, destination)
    stop("after_rename_" + stage)
    return result
Path.rename = rename
original_rmtree = fw.shutil.rmtree
def rmtree(path, *argv, **kwargs):
    owner = Path(path) / "owner.json"
    if failpoint == "during_cleanup" and owner.exists():
        owner.unlink()
        stop("during_cleanup")
    return original_rmtree(path, *argv, **kwargs)
fw.shutil.rmtree = rmtree
def run(*argv, **kwargs):
    rule = fw.CONFIG_ROOT / "ufw/user.rules"
    if argv == ("ufw", "status", "numbered"):
        value = "DENY" if rule.read_text().startswith("current") else "ALLOW"
        return subprocess.CompletedProcess(argv, 0, "[ 1] 8080/tcp " + value + " Anywhere\n", "")
    if argv[:3] == ("ufw", "--force", "delete"):
        return subprocess.CompletedProcess(argv, 0, "", "")
    if argv[:2] == ("ufw", "prepend"):
        rule.write_text("current rules\n")
        stop("after_apply_native")
        if failpoint == "apply_timeout":
            raise fw.FirewallError("fixture timeout", outcome_unknown=True)
        if failpoint == "apply_failure":
            raise fw.FirewallError("fixture completed failure")
        return subprocess.CompletedProcess(argv, 0, "", "")
    if argv == ("ufw", "reload"):
        with (root / "reloads").open("a") as stream:
            stream.write("reload\n")
            stream.flush()
            os.fsync(stream.fileno())
        stop("after_native_reload")
        if failpoint == "reload_timeout":
            raise fw.FirewallError("fixture reload timeout", outcome_unknown=True)
        if failpoint == "reload_failure":
            raise fw.FirewallError("fixture completed reload failure")
        return subprocess.CompletedProcess(argv, 0, "", "")
    raise AssertionError("Unexpected command: " + repr(argv))
fw.run = run
if operation == "hold":
    with fw.target_lock():
        print("locked", flush=True)
        sys.stdin.readline()
else:
    try:
        print(json.dumps(fw.execute_operation(args)))
    except (fw.FirewallError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error), "outcomeUnknown": fw.outcome_is_unknown(args, error)}))
        sys.exit(1)
'''


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.configuration = self.root / "etc"
        (self.configuration / "ufw").mkdir(parents=True)
        (self.configuration / "machine-id").write_text("owned-recovery-target")
        (self.configuration / "ufw/user.rules").write_text("original rules\n")
        (self.configuration / "ufw").chmod(0o700)
        (self.configuration / "ufw/user.rules").chmod(0o660)

    def child(self, operation, failpoint="", recovered=False, transaction=TRANSACTION):
        return subprocess.run([sys.executable, "-c", CHILD, str(SCRIPT), str(self.root), operation,
                               failpoint, "yes" if recovered else "no", transaction],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["ok"])
        return value

    def prepare(self):
        self.success(self.child("backup"))
        self.success(self.child("closePort"))
        self.assertEqual((self.configuration / "ufw/user.rules").read_text(), "current rules\n")

    def restored(self):
        self.assertEqual((self.configuration / "ufw/user.rules").read_text(), "original rules\n")
        self.assertEqual((self.configuration / "ufw").stat().st_mode & 0o7777, 0o700)
        self.assertEqual((self.configuration / "ufw/user.rules").stat().st_mode & 0o7777, 0o660)
        self.assertFalse((self.root / "backups" / fw.STATE_NAME).exists())
        self.assertEqual(list(self.configuration.glob(".hcp-rollback-*")), [])

    def journal(self):
        return self.root / "backups" / TRANSACTION / "rollback-state.json"

    def test_kill_and_restart_before_and_after_every_durable_filesystem_stage(self):
        points = ["before_preparing", "after_preparing", "before_prepared", "after_prepared",
                  "before_move_old_intent", "after_move_old_intent", "before_rename_move_old",
                  "after_rename_move_old", "before_old_saved", "after_old_saved", "before_install_intent",
                  "after_install_intent", "before_rename_install", "after_rename_install", "before_installed",
                  "after_installed", "before_reload_intent"]
        for failpoint in points:
            with self.subTest(failpoint=failpoint):
                self.prepare()
                killed = self.child("rollback", failpoint)
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stdout + killed.stderr)
                if failpoint == "after_rename_move_old":
                    self.assertFalse((self.configuration / "ufw").exists())
                result = self.success(self.child("rollback"))
                self.assertFalse(result["replayed"])
                self.restored()
                self.assertEqual((self.root / "reloads").read_text().splitlines(), ["reload"])
                fw.shutil.rmtree(str(self.root / "backups"))
                (self.root / "reloads").unlink()

    def test_unknown_reload_requires_new_independent_attestation(self):
        for failpoint in ("after_reload_intent", "after_native_reload", "before_reload_completed", "reload_timeout"):
            with self.subTest(failpoint=failpoint):
                self.prepare()
                interrupted = self.child("rollback", failpoint)
                self.assertIn(interrupted.returncode, (-signal.SIGKILL, 1))
                if interrupted.returncode == 1:
                    self.assertTrue(json.loads(interrupted.stdout)["outcomeUnknown"])
                before = (self.root / "reloads").read_text() if (self.root / "reloads").exists() else ""
                rejected = self.child("rollback")
                self.assertEqual(rejected.returncode, 1)
                self.assertTrue(json.loads(rejected.stdout)["outcomeUnknown"])
                self.assertEqual((self.root / "reloads").read_text() if (self.root / "reloads").exists() else "", before)
                other = self.child("backup", transaction="txn-other-alias-87654321")
                self.assertEqual(other.returncode, 1)
                self.success(self.child("rollback", recovered=True))
                self.restored()
                fw.shutil.rmtree(str(self.root / "backups"))
                (self.root / "reloads").unlink()

    def test_completed_reload_failure_preserves_previous_and_allows_known_retry(self):
        self.prepare()
        result = self.child("rollback", "reload_failure")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["outcomeUnknown"])
        self.assertEqual(len(list(self.configuration.glob(".hcp-rollback-*/previous/user.rules"))), 1)
        self.success(self.child("rollback"))
        self.restored()

    def test_verified_completion_and_partial_cleanup_replay_without_reloading(self):
        for failpoint in ("after_reload_completed", "before_completed", "after_completed", "after_cleanup_intent", "during_cleanup"):
            with self.subTest(failpoint=failpoint):
                self.prepare()
                killed = self.child("rollback", failpoint)
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stdout + killed.stderr)
                self.success(self.child("rollback"))
                replay = self.success(self.child("rollback"))
                self.assertTrue(replay["replayed"])
                self.assertFalse(replay["changed"])
                self.assertEqual((self.root / "reloads").read_text().splitlines(), ["reload"])
                self.restored()
                fw.shutil.rmtree(str(self.root / "backups"))
                (self.root / "reloads").unlink()

    def test_unknown_apply_locks_target_across_aliases_until_verified_rollback(self):
        for failpoint in ("after_apply_native", "apply_timeout"):
            with self.subTest(failpoint=failpoint):
                self.success(self.child("backup"))
                result = self.child("closePort", failpoint)
                self.assertIn(result.returncode, (1, -signal.SIGKILL))
                self.assertEqual(self.child("backup", transaction="txn-other-alias-87654321").returncode, 1)
                blocked = self.child("rollback")
                self.assertEqual(blocked.returncode, 1)
                self.assertTrue(json.loads(blocked.stdout)["outcomeUnknown"])
                self.success(self.child("rollback", recovered=True))
                self.restored()
                fw.shutil.rmtree(str(self.root / "backups"))
                (self.root / "reloads").unlink()

    def test_completed_apply_failure_can_use_normal_rollback(self):
        self.success(self.child("backup"))
        result = self.child("closePort", "apply_failure")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["outcomeUnknown"])
        self.success(self.child("rollback"))
        self.restored()

    def test_prepared_backup_blocks_other_transaction_and_can_replay(self):
        result = self.success(self.child("backup"))
        replay = self.success(self.child("backup"))
        self.assertEqual(result["backupRef"], replay["backupRef"])
        self.assertFalse(replay["changed"])
        self.assertEqual(self.child("backup", transaction="txn-other-alias-87654321").returncode, 1)
        self.success(self.child("closePort"))
        self.success(self.child("closePort"))
        self.assertFalse((self.root / "backups" / fw.STATE_NAME).exists())

    def test_backup_marker_fsync_failure_requires_controller_reconciliation(self):
        result = self.child("backup", "backup_marker_fsync")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(json.loads(result.stdout)["outcomeUnknown"])
        self.assertEqual((self.configuration / "ufw/user.rules").read_text(), "original rules\n")
        marker = json.loads((self.root / "backups" / fw.STATE_NAME).read_text())
        self.assertEqual(marker["phase"], "backed_up")
        self.assertEqual(self.child("backup", transaction="txn-other-alias-87654321").returncode, 1)
        # A verified retry can discover the completed backup and rollback can
        # release it. The controller must not discard this state as not-started.
        self.assertFalse(self.success(self.child("backup"))["changed"])
        self.success(self.child("rollback", recovered=True))
        self.restored()

    def test_real_target_lock_rejects_second_process_and_is_released_by_kernel(self):
        command = [sys.executable, "-c", CHILD, str(SCRIPT), str(self.root), "hold", "", "no", TRANSACTION]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            rejected = self.child("backup")
            self.assertEqual(rejected.returncode, 1)
            self.assertIn("still running", json.loads(rejected.stdout)["error"])
        finally:
            process.kill()
            process.communicate(timeout=10)
        self.success(self.child("backup"))

    def test_changed_live_configuration_cannot_be_overwritten_on_resume(self):
        self.prepare()
        self.assertEqual(self.child("rollback", "after_prepared").returncode, -signal.SIGKILL)
        rule = self.configuration / "ufw/user.rules"
        rule.write_text("outside administrator change\n")
        rejected = self.child("rollback")
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("manifest", json.loads(rejected.stdout)["error"])
        self.assertEqual(rule.read_text(), "outside administrator change\n")
        self.assertFalse((self.root / "reloads").exists())

    def test_tampered_staging_journal_and_symlink_are_rejected(self):
        for attack in ("journal_path", "owner", "prepared", "previous", "symlink"):
            with self.subTest(attack=attack):
                self.prepare()
                point = "after_rename_move_old" if attack == "previous" else "after_prepared"
                self.assertEqual(self.child("rollback", point).returncode, -signal.SIGKILL)
                state = json.loads(self.journal().read_text())
                staging = self.configuration / state["stagingName"]
                if attack == "journal_path":
                    state["stagingName"] = "../../outside"
                    self.journal().write_text(json.dumps(state))
                elif attack == "owner":
                    (staging / "owner.json").write_text("{}")
                elif attack == "prepared":
                    (staging / "etc/ufw/user.rules").write_text("tampered\n")
                elif attack == "previous":
                    (staging / "previous/user.rules").write_text("tampered\n")
                else:
                    rule = staging / "etc/ufw/user.rules"
                    rule.unlink()
                    rule.symlink_to(self.configuration / "machine-id")
                rejected = self.child("rollback", recovered=True)
                self.assertEqual(rejected.returncode, 1, rejected.stdout)
                self.assertFalse((self.root / "reloads").exists())
                self.assertEqual((self.configuration / "machine-id").read_text(), "owned-recovery-target")
                fw.shutil.rmtree(str(self.root / "backups"))
                for item in self.configuration.glob(".hcp-rollback-*"):
                    fw.shutil.rmtree(str(item))
                if not (self.configuration / "ufw").exists():
                    (self.configuration / "ufw").mkdir(mode=0o700)
                (self.configuration / "ufw/user.rules").write_text("original rules\n")
                (self.configuration / "ufw/user.rules").chmod(0o660)

    def test_unsupported_xattr_is_rejected_before_backup_or_replacement(self):
        rule = self.configuration / "ufw/user.rules"
        os.setxattr(str(rule), "user.hcp-test", b"must not lose")
        rejected = self.child("backup")
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("Unsupported ACL or extended attribute", json.loads(rejected.stdout)["error"])
        self.assertFalse((self.root / "backups" / TRANSACTION).exists())
        os.removexattr(str(rule), "user.hcp-test")
        self.prepare()
        os.setxattr(str(rule), "user.hcp-test", b"must not lose")
        rejected = self.child("rollback")
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(rule.read_text(), "current rules\n")
        self.assertEqual(os.getxattr(str(rule), "user.hcp-test"), b"must not lose")
        self.assertFalse((self.root / "reloads").exists())

    def test_failed_journal_write_does_not_rename_live_configuration(self):
        self.prepare()
        args = argparse.Namespace(transaction=TRANSACTION, recovery_verified=False)
        with patch.object(fw, "CONFIG_ROOT", self.configuration), patch.object(fw, "BACKUP_ROOT", self.root / "backups"), \
                patch.object(fw, "backend", return_value="ufw"), patch.object(fw, "run") as native, \
                patch.object(fw.os, "fsync", side_effect=OSError("injected disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                fw.rollback(args)
            native.assert_not_called()
        self.assertEqual((self.configuration / "ufw/user.rules").read_text(), "current rules\n")


if __name__ == "__main__":
    unittest.main()
