"""SELinux backup protocol tests using real temp files and translated xattrs."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from firewall_xattr_fixture import translated_xattrs

SCRIPT = Path(__file__).parents[1] / "scripts/hcp-firewall.py"
spec = importlib.util.spec_from_file_location("firewall_selinux", SCRIPT)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
TRANSACTION = "txn-selinux-labels-12345678"
DIRECTORY_CONTEXT = b"system_u:object_r:firewalld_etc_rw_t:s0\x00"
FILE_CONTEXT = b"system_u:object_r:etc_t:s0:c0.c3,c7\x00"
CHANGED_CONTEXT = b"unconfined_u:object_r:tmp_t:s0\x00"


class SELinuxTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, labels=True):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary)
            configuration = root / "etc"
            (configuration / "ufw/nested").mkdir(parents=True)
            (configuration / "machine-id").write_text("selinux-temp-fixture")
            (configuration / "ufw/nested/user.rules").write_text("original rules\n")
            stack.enter_context(patch.object(fw, "CONFIG_ROOT", configuration))
            stack.enter_context(patch.object(fw, "BACKUP_ROOT", root / "backups"))
            stack.enter_context(patch.object(fw, "backend", return_value="ufw"))
            command = stack.enter_context(patch.object(fw, "run"))
            stack.enter_context(translated_xattrs(fw))
            if labels:
                for path in [configuration] + list(configuration.rglob("*")):
                    os.setxattr(str(path), fw.SELINUX_LABEL, DIRECTORY_CONTEXT if path.is_dir() else FILE_CONTEXT)
            yield root, configuration / "ufw", command

    def args(self):
        return argparse.Namespace(transaction=TRANSACTION, recovery_verified=False)

    def metadata(self, root):
        return fw.read_control_json(root / "backups" / TRANSACTION / "metadata.json")

    def rewrite_archive(self, root, change, legacy=False):
        directory = root / "backups" / TRANSACTION
        path = directory / "firewall-state.tar.gz"
        with tarfile.open(str(path)) as archive:
            items = []
            for member in archive.getmembers():
                content = archive.extractfile(member).read() if member.isfile() else None
                member = copy.copy(member)
                member.pax_headers = dict(member.pax_headers)
                change(member)
                items.append((member, content))
        with tarfile.open(str(path), "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for member, content in items:
                archive.addfile(member, io.BytesIO(content) if content is not None else None)
        metadata = self.metadata(root)
        metadata["sha256"] = fw.hashlib.sha256(path.read_bytes()).hexdigest()
        if legacy:
            metadata["securityLabels"] = "pax-v1"
            metadata["filesystemMetadata"] = fw.LEGACY_FILESYSTEM_METADATA
            metadata["configurationSha256"] = fw.tree_digest(root / "etc/ufw", metadata_version=fw.LEGACY_FILESYSTEM_METADATA)
        fw.write_control_json(directory / "metadata.json", metadata)

    def test_both_raw_labels_round_trip_for_files_and_directories(self):
        with self.fixture() as (root, tree, command):
            rules = tree / "nested/user.rules"
            os.setxattr(str(rules), fw.SECURITY_LABEL, b"opaque-pdpl\x00\xff")
            expected = fw.tree_digest(tree)
            fw.backup(self.args())
            metadata = self.metadata(root)
            self.assertEqual(metadata["filesystemMetadata"], "posix-security-v2")
            self.assertEqual(metadata["securityLabels"], "pax-v2")
            with tarfile.open(str(root / "backups" / TRANSACTION / "firewall-state.tar.gz")) as archive:
                self.assertEqual(fw.archive_digest(archive, "ufw"), expected)
                for member in archive.getmembers():
                    self.assertIn(fw.LABEL_HEADER, member.pax_headers)
                    self.assertIn(fw.SELINUX_HEADER, member.pax_headers)
                    self.assertEqual(bytes.fromhex(member.pax_headers[fw.SELINUX_HEADER]), FILE_CONTEXT if member.isfile() else DIRECTORY_CONTEXT)
            rules.write_text("changed rules\n")
            os.setxattr(str(tree), fw.SELINUX_LABEL, CHANGED_CONTEXT)
            os.setxattr(str(rules), fw.SELINUX_LABEL, CHANGED_CONTEXT)
            (tree / "new.rules").write_text("new\n")
            self.assertTrue(fw.rollback(self.args())["ok"])
            self.assertEqual(fw.tree_digest(tree), expected)
            self.assertEqual(os.getxattr(str(rules), fw.SECURITY_LABEL), b"opaque-pdpl\x00\xff")
            self.assertFalse((tree / "new.rules").exists())
            command.assert_called_once_with("ufw", "reload")
            self.assertFalse(fw.rollback(self.args())["changed"])
            self.assertEqual(command.call_count, 1)

    def test_raw_context_validation_preserves_optional_nul_and_mls(self):
        for value in (b"user_u:role_r:type_t", b"user_u:role_r:type_t\x00", FILE_CONTEXT,
                      b"user_u:role_r:type_t:s0-s15:c0.c1023\x00"):
            fw.validate_security_label(value, fw.SELINUX_LABEL)
        for value in (b"", b"plain", b"u:r:t\x00extra", b"u:r:t\x00\x00", b"u:r:t\n", b"u:r:t s0", b"u:r:\xff", b"a" * 4097):
            with self.subTest(value=value[:60]), self.assertRaises(fw.FirewallError):
                fw.validate_security_label(value, fw.SELINUX_LABEL)

    def test_astra_parent_integrity_prerequisite_survives_selinux_round_trip(self):
        with self.fixture() as (root, tree, command):
            for path in (root / "etc", tree, tree / "nested", tree / "nested/user.rules"):
                os.setxattr(str(path), fw.SECURITY_LABEL, b"high-integrity")
            expected = fw.tree_digest(tree)
            fw.backup(self.args())
            (tree / "nested/user.rules").write_text("changed rules\n")
            original = os.setxattr

            def mandatory_parent(path, name, value, **kwargs):
                if name == fw.SECURITY_LABEL and ".hcp-rollback-" in str(path):
                    if fw.security_label(Path(path).parent) != value:
                        raise PermissionError("fixture parent mandatory integrity must be prepared first")
                return original(path, name, value, **kwargs)

            with patch.object(fw.os, "setxattr", side_effect=mandatory_parent):
                self.assertTrue(fw.rollback(self.args())["ok"])
            self.assertEqual(fw.tree_digest(tree), expected)
            command.assert_called_once_with("ufw", "reload")

    def test_malformed_missing_unsupported_and_tampered_labels_reject_before_replacement(self):
        changes = {
            "missing": lambda member: member.pax_headers.pop(fw.SELINUX_HEADER),
            "nonhex": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: "zz"}),
            "oddhex": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: "0"}),
            "embedded-nul": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: b"u:r:t\x00more".hex()}),
            "oversized": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: (b"u:r:" + b"t" * 4093).hex()}),
            "valid-different": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: CHANGED_CONTEXT.hex()}),
            "absent": lambda member: member.pax_headers.update({fw.SELINUX_HEADER: ""}),
            "unknown-xattr": lambda member: member.pax_headers.update({"SCHILY.xattr.user.other": "opaque"}),
            "unknown-acl": lambda member: member.pax_headers.update({"SCHILY.acl.access": "user::rw-"}),
            "unknown-hcp": lambda member: member.pax_headers.update({"HCP.security.unknown": "00"}),
        }
        for case, change in changes.items():
            with self.subTest(case=case), self.fixture() as (root, tree, command):
                fw.backup(self.args())
                self.rewrite_archive(root, lambda member: change(member) if member.isfile() else None)
                (tree / "nested/user.rules").write_text("current rules\n")
                expected = fw.tree_digest(tree)
                identity = tree.stat().st_ino
                with self.assertRaises(fw.FirewallError):
                    fw.rollback(self.args())
                self.assertEqual(fw.tree_digest(tree), expected)
                self.assertEqual(tree.stat().st_ino, identity)
                command.assert_not_called()

    def test_partially_restored_or_denied_label_never_installs_or_reloads(self):
        for silent in (False, True):
            with self.subTest(silent=silent), self.fixture() as (root, tree, command):
                fw.backup(self.args())
                (tree / "nested/user.rules").write_text("current rules\n")
                expected = fw.tree_digest(tree)
                original = os.setxattr

                def interrupted(path, name, value, **kwargs):
                    if ".hcp-rollback-" in str(path) and str(path).endswith("/user.rules") and name == fw.SELINUX_LABEL:
                        if not silent:
                            raise PermissionError("fixture SELinux setxattr denied")
                        return None
                    return original(path, name, value, **kwargs)

                with patch.object(fw.os, "setxattr", side_effect=interrupted):
                    with self.assertRaises((fw.FirewallError, PermissionError)):
                        fw.rollback(self.args())
                self.assertEqual(fw.tree_digest(tree), expected)
                command.assert_not_called()
                self.assertTrue(fw.rollback(self.args())["ok"])
                self.assertEqual(os.getxattr(str(tree / "nested/user.rules"), fw.SELINUX_LABEL), FILE_CONTEXT)
                command.assert_called_once_with("ufw", "reload")

    def test_label_drift_after_backup_blocks_apply_intent(self):
        with self.fixture() as (root, tree, command):
            fw.backup(self.args())
            os.setxattr(str(tree / "nested/user.rules"), fw.SELINUX_LABEL, CHANGED_CONTEXT)
            arguments = self.args()
            arguments._target_managed = True
            with self.assertRaisesRegex(fw.FirewallError, "no longer matches"):
                fw.mark_apply_intent(arguments, "ufw")
            command.assert_not_called()

    def test_unknown_live_attribute_stays_unsupported(self):
        with self.fixture() as (root, tree, command):
            os.setxattr(str(tree / "nested/user.rules"), "user.unknown", b"unsupported")
            with self.assertRaisesRegex(fw.FirewallError, "Unsupported ACL"):
                fw.backup(self.args())
            self.assertFalse((root / "backups" / TRANSACTION).exists())
            command.assert_not_called()

    def test_legacy_pdpl_archive_and_in_progress_journal_remain_readable(self):
        with self.fixture(labels=False) as (root, tree, command):
            rules = tree / "nested/user.rules"
            os.setxattr(str(rules), fw.SECURITY_LABEL, b"legacy-pdpl\x00\xff")
            expected = fw.tree_digest(tree, metadata_version=fw.LEGACY_FILESYSTEM_METADATA)
            fw.backup(self.args())
            self.rewrite_archive(root, lambda member: member.pax_headers.pop(fw.SELINUX_HEADER), legacy=True)
            rules.write_text("current rules\n")
            original_checkpoint = fw.rollback_checkpoint

            def old_checkpoint(directory, state, phase):
                state.pop("filesystemMetadata", None)
                original_checkpoint(directory, state, phase)
                if phase == "prepared":
                    raise RuntimeError("fixture old process interrupted")

            with patch.object(fw, "rollback_checkpoint", side_effect=old_checkpoint), self.assertRaisesRegex(RuntimeError, "interrupted"):
                fw.rollback(self.args())
            self.assertTrue(fw.rollback(self.args())["ok"])
            self.assertEqual(fw.tree_digest(tree, metadata_version=fw.LEGACY_FILESYSTEM_METADATA), expected)
            self.assertEqual(os.getxattr(str(rules), fw.SECURITY_LABEL), b"legacy-pdpl\x00\xff")
            command.assert_called_once_with("ufw", "reload")

    def test_legacy_archive_does_not_guess_a_selinux_context(self):
        with self.fixture(labels=False) as (root, tree, command):
            fw.backup(self.args())
            self.rewrite_archive(root, lambda member: member.pax_headers.pop(fw.SELINUX_HEADER), legacy=True)
            os.setxattr(str(tree), fw.SELINUX_LABEL, DIRECTORY_CONTEXT)
            before = fw.tree_digest(tree)
            with self.assertRaisesRegex(fw.FirewallError, "Legacy.*SELinux"):
                fw.rollback(self.args())
            self.assertEqual(fw.tree_digest(tree), before)
            self.assertFalse((root / "backups" / TRANSACTION / "rollback-state.json").exists())
            command.assert_not_called()

    def test_metadata_and_journal_cannot_drop_label_manifest_version(self):
        for field, value in (("filesystemMetadata", "posix-pdpl-v1"), ("securityLabels", "pax-v1"),
                             ("configurationSha256", None)):
            with self.subTest(field=field), self.fixture() as (root, tree, command):
                fw.backup(self.args())
                metadata = self.metadata(root)
                metadata[field] = value
                fw.write_control_json(root / "backups" / TRANSACTION / "metadata.json", metadata)
                with self.assertRaises(fw.FirewallError):
                    fw.rollback(self.args())
                command.assert_not_called()
        with self.fixture() as (root, tree, command):
            fw.backup(self.args())
            original = fw.rollback_checkpoint

            def interrupted(directory, state, phase):
                original(directory, state, phase)
                if phase == "prepared":
                    raise RuntimeError("fixture interrupted")

            with patch.object(fw, "rollback_checkpoint", side_effect=interrupted), self.assertRaises(RuntimeError):
                fw.rollback(self.args())
            journal = root / "backups" / TRANSACTION / "rollback-state.json"
            state = fw.read_control_json(journal)
            state.pop("filesystemMetadata")
            fw.write_control_json(journal, state)
            with self.assertRaisesRegex(fw.FirewallError, "manifest version"):
                fw.rollback(self.args())
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
