"""Exercise native package metadata and honest inventory failure boundaries."""

import ast
import importlib.util
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


COLLECTOR = Path(__file__).resolve().parents[1] / "scripts" / "hcp-package-inventory.py"
SPEC = importlib.util.spec_from_file_location("hcp_package_inventory", COLLECTOR)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class PackageInventoryTest(unittest.TestCase):
    def collect(self, records, snapshots=None):
        def execute(command):
            self.assertEqual(command[:2], ["dpkg-query", "-W"])
            return 0, records.rstrip("\n"), ""

        def read_host(path, limit=None):
            if path == "/etc/os-release":
                return 'ID=debian\nVERSION_ID="12"\n'
            if path == "/etc/astra_version":
                raise FileNotFoundError(path)
            raise AssertionError("Unexpected host file: " + path)

        with patch.object(collector, "run", side_effect=execute), patch.object(collector, "read_text", side_effect=read_host), \
                patch.object(collector.shutil, "which", side_effect=lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None), \
                patch.object(collector, "database_snapshot", side_effect=snapshots or [[("status", 1)], [("status", 1)]]):
            return collector.collect()

    @staticmethod
    def record(status, name="package", maintainer="Debian Team <team@debian.org>", origin=""):
        return status + "\t" + name + "\t1.0-1\tamd64\tsource-package\t1.0-1\t" + maintainer + "\t" + origin + "\n"

    def test_complete_inventory_keeps_held_and_removal_requested_code(self):
        report = self.collect(self.record("ii ", "installed") + self.record("hi ", "held")
                              + self.record("ri ", "removal-requested") + self.record("rc ", "removed")
                              + self.record("pn ", "not-installed"))
        self.assertEqual([p["name"] for p in report["packages"]], ["installed", "held", "removal-requested"])
        self.assertEqual([p["dpkgStatus"] for p in report["packages"]], ["ii ", "hi ", "ri "])
        self.assertFalse(report["partial"])
        self.assertFalse(report["packageInventory"]["partial"])
        self.assertEqual(report["packageInventory"]["partialReasons"], [])
        self.assertEqual(report["packageInventory"]["error"], "")
        self.assertEqual(report["packageInventory"]["managerSelection"], "os-id")

    def test_interrupted_install_and_pending_triggers_keep_versions_and_uncertainty(self):
        for status in ("iH ", "iU ", "iF ", "iW ", "it ", "iiR"):
            with self.subTest(status=status):
                report = self.collect(self.record(status))
                self.assertEqual(report["packageInventory"]["packageCount"], 1)
                self.assertEqual(report["packages"][0]["dpkgStatus"], status)
                self.assertEqual(report["packages"][0]["sourceVersion"], "1.0-1")
                self.assertTrue(report["partial"])
                self.assertTrue(report["packageInventory"]["partial"])
                self.assertTrue(report["packageInventory"]["partialReasons"])
                # Usable versions can still be checked; a partial inventory is
                # different from an unreadable package record.
                self.assertEqual(report["packageInventory"]["error"], "")

    def test_unknown_or_malformed_status_does_not_silently_shrink_inventory(self):
        for status in ("i? ", "ii", "iiX", "?i "):
            with self.subTest(status=status):
                report = self.collect(self.record("ii ", "known") + self.record(status, "unknown"))
                self.assertTrue(report["partial"])
                self.assertIn("status", report["packageInventory"]["error"])

    def test_installed_origin_observations_survive_empty_optional_origin(self):
        report = self.collect(self.record("ii ", "vendor", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", "Ubuntu")
                              + self.record("ii ", "external", "NodeSource <support@nodesource.com>"))
        self.assertFalse(report["partial"])
        self.assertEqual(report["packages"][0]["origin"], "Ubuntu")
        self.assertEqual(report["packages"][1]["origin"], "")
        self.assertEqual(report["packages"][1]["maintainer"], "NodeSource <support@nodesource.com>")

    def test_missing_maintainer_remains_unknown_instead_of_inventing_vendor(self):
        report = self.collect(self.record("ii ", maintainer=""))
        self.assertEqual(report["packages"][0]["maintainer"], "")
        self.assertEqual(report["packages"][0]["origin"], "")

    def test_database_mutation_or_empty_output_cannot_be_complete(self):
        report = self.collect(self.record("ii "), snapshots=[[("status", 1)], [("status", 2)]])
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])
        self.assertEqual(report["packageInventory"]["packageCount"], 1)
        empty = self.collect("")
        self.assertTrue(empty["partial"])
        self.assertIn("empty", empty["packageInventory"]["error"])

    def test_exact_os_selects_native_manager_even_with_other_databases(self):
        with patch.object(collector, "database_paths", return_value=["present"]):
            self.assertEqual(collector.select_manager({"ID": "alpine", "ID_LIKE": "debian"}), ("apk", "os-id"))
            self.assertEqual(collector.select_manager({"ID": "rocky"}), ("rpm", "os-id"))
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                collector.select_manager({"ID": "unknown"})

    def test_unknown_distribution_may_select_collection_only_by_family_or_database(self):
        self.assertEqual(collector.select_manager({"ID": "private-os", "ID_LIKE": "rhel fedora"}), ("rpm", "id-like-collection-only"))
        with patch.object(collector, "database_paths", side_effect=lambda manager: ["installed"] if manager == "apk" else []):
            self.assertEqual(collector.select_manager({"ID": "private-os"}), ("apk", "native-database"))
        with patch.object(collector, "database_paths", return_value=[]):
            with self.assertRaisesRegex(ValueError, "No supported"):
                collector.select_manager({"ID": "unknown"})

    def test_os_release_fallback_is_non_executable_and_does_not_merge(self):
        literal = 'ID=alpine\nNAME="literal $(touch /never-execute)"\nVERSION_ID=\'3.22.2\'\n'
        with patch.object(collector.os.path, "lexists", return_value=False), patch.object(collector, "read_text", return_value=literal) as read:
            values = collector.read_os_release()
            self.assertEqual(values["NAME"], "literal $(touch /never-execute)")
            self.assertEqual(values["VERSION_ID"], "3.22.2")
            self.assertEqual([call.args[0] for call in read.call_args_list], ["/usr/lib/os-release"])
        with patch.object(collector, "read_text", return_value="ID=debian\n") as read:
            self.assertEqual(collector.read_os_release(), {"ID": "debian"})
            read.assert_called_once()
        with patch.object(collector, "read_text", side_effect=PermissionError("denied")) as read:
            with self.assertRaises(PermissionError):
                collector.read_os_release()
            read.assert_called_once()
        with patch.object(collector.os.path, "lexists", return_value=True), patch.object(collector, "read_text", side_effect=FileNotFoundError("dangling primary symlink")) as read:
            with self.assertRaises(FileNotFoundError):
                collector.read_os_release()
            read.assert_called_once_with("/etc/os-release", 65536)

    def test_rpm_preserves_binary_epoch_and_module_without_inventing_source_epoch(self):
        native = "libfoo-tools\t2\t1.7\t3.module_el9+17\tx86_64\tfoo-source-1.7-3.module_el9+17.src.rpm\tAlmaLinux\tAlmaLinux Packaging Team\tAlmaLinux\tfoo:1.7:90001:context\n"
        with patch.object(collector, "run", side_effect=[(0, "EPOCH EPOCHNUM MODULARITYLABEL", ""), (0, native, "")]) as run:
            packages, error = collector.rpm_packages()
        self.assertEqual(error, "")
        self.assertEqual(len(packages), 1)
        package = packages[0]
        self.assertEqual(package["version"], "2:1.7-3.module_el9+17")
        self.assertEqual(package["sourceName"], "foo-source")
        self.assertEqual(package["sourceVersion"], "1.7-3.module_el9+17")
        self.assertFalse(package["sourceEpochKnown"])
        self.assertEqual(package["modularityLabel"], "foo:1.7:90001:context")
        self.assertTrue(package["rpmModularityQueried"])
        self.assertEqual(package["vendor"], "AlmaLinux")
        self.assertEqual(package["distribution"], "AlmaLinux")
        self.assertEqual(package["packager"], "AlmaLinux Packaging Team")
        self.assertEqual(package["rpmRepositoryEvidence"], "not-recorded-in-rpmdb")
        self.assertIn("%{EPOCHNUM}", run.call_args_list[1].args[0][-1])

    def test_old_rpm_tags_and_public_keys_remain_observed_without_invalid_query(self):
        native = "gpg-pubkey\t(none)\tabcdef01\t12345678\t(none)\t(none)\t(none)\t(none)\t(none)\t(none)\n"
        with patch.object(collector, "run", side_effect=[(0, "EPOCH", ""), (0, native, "")]) as run:
            packages, error = collector.rpm_packages()
        self.assertEqual(error, "")
        self.assertEqual(packages[0]["arch"], "None")
        self.assertEqual(packages[0]["vendor"], "")
        self.assertEqual(packages[0]["sourceVersion"], "")
        self.assertFalse(packages[0]["rpmModularityQueried"])
        self.assertIn("%{EPOCH}", run.call_args_list[1].args[0][-1])
        self.assertNotIn("%{MODULARITYLABEL}", run.call_args_list[1].args[0][-1])

    def test_apk_preserves_source_origin_and_entire_native_revision(self):
        text = "P:libcrypto3\nV:3.3.3-r0\nA:x86_64\no:openssl\nm:Alpine Team <team@alpinelinux.org>\nc:abc123\nF:usr/lib\nR:libcrypto.so.3\n\nP:busybox\nV:1.37.0-r12\nA:aarch64\no:busybox"
        with patch.object(collector, "database_paths", return_value=["installed"]), patch.object(collector, "read_text", return_value=text):
            packages, error = collector.apk_packages()
        self.assertEqual(error, "")
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0]["name"], "libcrypto3")
        self.assertEqual(packages[0]["sourceName"], "openssl")
        self.assertEqual(packages[0]["apkOrigin"], "openssl")
        self.assertEqual(packages[0]["sourceVersion"], "3.3.3-r0")
        self.assertEqual(packages[0]["version"], "3.3.3-r0")
        self.assertEqual(packages[0]["apkCommit"], "abc123")
        self.assertEqual(packages[1]["arch"], "aarch64")

    def test_apk_malformed_records_are_explicit_errors_not_silent_omissions(self):
        valid = "P:libcrypto3\nV:3.3.3-r0\nA:x86_64\no:openssl\n\n"
        for invalid in ("P:broken\nV:1.0-r0\nA:x86_64", "P:broken\nP:duplicate\nV:1.0-r0\nA:x86_64\no:broken", "P:broken\nV:garbage\nA:x86_64\no:broken"):
            with self.subTest(invalid=invalid), patch.object(collector, "database_paths", return_value=["installed"]), \
                    patch.object(collector, "read_text", return_value=valid + invalid):
                packages, error = collector.apk_packages()
            self.assertEqual(len(packages), 1)
            self.assertTrue(error)

    def test_apk_repository_hints_preserve_mixed_branch_uncertainty_without_credentials(self):
        text = "https://username:private-password@mirror.example/v3.22/main\n@edge https://mirror.example/edge/testing\n/local/packages\n"
        with patch.object(collector, "read_text", return_value=text):
            result = collector.apk_repositories({"ID": "alpine"})
        self.assertEqual(result["branches"], ["edge", "v3.22"])
        self.assertEqual(result["unknownEntries"], 1)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertNotIn("private-password", str(result))
        self.assertIn("installed-origin-not-attested", result["scope"])

    def test_target_program_keeps_python35_syntax(self):
        ast.parse(COLLECTOR.read_text(), feature_version=(3, 5))


class SQLiteRpmConsistencyTest(unittest.TestCase):
    def setUp(self):
        # URI-reserved characters also exercise safe mode=ro path handling.
        self.temporary = tempfile.TemporaryDirectory(prefix="hcp-rpm # ? ")
        self.addCleanup(self.temporary.cleanup)
        self.path = str(Path(self.temporary.name) / "rpmdb.sqlite")
        self.writer = sqlite3.connect(self.path)
        self.addCleanup(self.writer.close)
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.execute("CREATE TABLE Packages (name TEXT, version TEXT)")
        self.writer.execute("INSERT INTO Packages VALUES ('example', '1.0-1')")
        self.writer.commit()
        self.writer.execute("PRAGMA wal_checkpoint(FULL)").fetchall()
        patcher = patch.dict(collector.DATABASES, {"rpm": (self.path,)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def collect(self, action=None):
        def query():
            if action:
                action()
            return [{"manager": "rpm", "name": "example", "version": "1.0-1", "arch": "x86_64"}], ""
        with patch.object(collector, "read_os_release", return_value={"ID": "rocky", "VERSION_ID": "9.8"}), \
                patch.object(collector.shutil, "which", return_value="/usr/bin/rpm"), \
                patch.object(collector, "rpm_packages", side_effect=query), \
                patch.object(collector, "read_text", side_effect=FileNotFoundError()):
            return collector.collect()

    def test_read_only_wal_metadata_changes_are_not_package_commits(self):
        snapshots = []
        def read_and_touch_metadata():
            connection = sqlite3.connect("file:" + collector.quote(self.path, safe="/") + "?mode=ro", uri=True)
            try:
                self.assertEqual(connection.execute("SELECT * FROM Packages").fetchall(), [("example", "1.0-1")])
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("DELETE FROM Packages")
            finally:
                connection.close()
            snapshots.append(collector.database_snapshot("rpm"))
            # RPM/SQLite readers can change WAL permissions/ctime while no
            # package changes. Reproduce that real filesystem metadata event.
            wal = self.path + "-wal"
            os.chmod(wal, os.stat(wal).st_mode & 0o777)
            os.utime(wal, ns=(os.stat(wal).st_atime_ns, os.stat(wal).st_mtime_ns + 1000000000))
            snapshots.append(collector.database_snapshot("rpm"))
        report = self.collect(read_and_touch_metadata)
        self.assertNotEqual(snapshots[0], snapshots[1])
        self.assertFalse(report["partial"], report["packageInventory"])

    def test_real_commit_is_partial_even_with_identical_parsed_output(self):
        def commit():
            self.writer.execute("UPDATE Packages SET version='2.0-1'")
            self.writer.commit()
        report = self.collect(commit)
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])
        self.assertEqual(report["packageInventory"]["packageCount"], 1)

    def test_write_and_revert_cannot_be_mistaken_for_stability(self):
        def change_and_revert():
            self.writer.execute("UPDATE Packages SET version='2.0-1'")
            self.writer.commit()
            self.writer.execute("UPDATE Packages SET version='1.0-1'")
            self.writer.commit()
            self.assertEqual(self.writer.execute("SELECT * FROM Packages").fetchall(), [("example", "1.0-1")])
        report = self.collect(change_and_revert)
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_uncommitted_rollback_does_not_invent_an_installed_change(self):
        def rollback():
            self.writer.execute("UPDATE Packages SET version='2.0-1'")
            self.writer.rollback()
        report = self.collect(rollback)
        self.assertFalse(report["partial"], report["packageInventory"])

    def test_database_replacement_is_partial_even_if_rows_are_identical(self):
        replacement = self.path + ".replacement"
        shutil.copyfile(self.path, replacement)
        report = self.collect(lambda: os.replace(replacement, self.path))
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_database_alias_uses_one_observer_and_cannot_switch_targets(self):
        alias = Path(self.temporary.name) / "alias" / "rpmdb.sqlite"
        alias.parent.mkdir()
        alias.symlink_to(self.path)
        with patch.dict(collector.DATABASES, {"rpm": (self.path, str(alias))}):
            with collector.DatabaseConsistency("rpm") as guard:
                self.assertEqual(len(guard.connections), 1)
                self.assertTrue(guard.unchanged())
                alias.unlink()
                self.assertFalse(guard.unchanged())
        self.assertEqual(guard.connections, [])

    def test_other_rpm_database_backends_keep_physical_change_guard(self):
        path = Path(self.temporary.name) / "Packages"
        path.write_bytes(b"opaque BDB fixture")
        with patch.dict(collector.DATABASES, {"rpm": (str(path),)}):
            report = self.collect(lambda: path.write_bytes(b"changed BDB fixture"))
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_sqlite_dependency_failure_is_reported_as_partial_json(self):
        with patch.dict("sys.modules", {"sqlite3": None}):
            report = self.collect()
        self.assertTrue(report["partial"])
        self.assertIn("SQLite support", report["packageInventory"]["error"])

    def test_corrupt_sqlite_database_is_not_complete(self):
        self.writer.close()
        Path(self.path).write_bytes(b"not a SQLite database")
        report = self.collect()
        self.assertTrue(report["partial"])
        self.assertIn("SQLite", report["packageInventory"]["error"])

    def test_missing_data_version_fails_closed_and_closes_observer(self):
        class UnsupportedConnection:
            closed = False
            def execute(self, query):
                return self
            def fetchone(self):
                return None
            def close(self):
                self.closed = True
        connection = UnsupportedConnection()
        with patch.object(sqlite3, "connect", return_value=connection):
            report = self.collect()
        self.assertTrue(report["partial"])
        self.assertIn("cannot observe", report["packageInventory"]["error"])
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main()
