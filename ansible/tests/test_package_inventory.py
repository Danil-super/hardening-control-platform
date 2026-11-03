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

    def test_debian_apt_policy_observes_release_hints_without_pretending_signatures(self):
        raw = ("Package files:\n"
               " 100 /var/lib/dpkg/status\n"
               "     release a=now\n"
               " 500 https://secret:password@repo.example/debian bookworm/main amd64 Packages\n"
               "     release v=12.12,o=Debian,a=oldstable,n=bookworm,l=Debian,c=main,b=amd64\n"
               "     origin repo.example\n"
               " 500 https://repo.example/debian-security bookworm-security/main amd64 Packages\n"
               "     release o=Debian,a=oldstable-security,n=bookworm-security,l=Debian-Security,c=main,b=amd64\n"
               "Pinned packages:\n")
        with patch.object(collector.shutil, "which", return_value="/usr/bin/apt-cache"), \
                patch.object(collector, "run", return_value=(0, raw.rstrip("\n"), "")) as native:
            evidence = collector.debian_apt_repository_observation({
                "ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"})
        native.assert_called_once_with(["env", "LC_ALL=C", "apt-cache",
                                        "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "policy"])
        self.assertEqual(evidence["status"], "observed")
        self.assertEqual(evidence["indexEntries"], 2)
        self.assertEqual(evidence["debianLabelEntries"], 2)
        self.assertEqual(evidence["suites"], ["bookworm", "bookworm-security"])
        self.assertTrue(evidence["suiteConsistent"])
        self.assertFalse(evidence["publisherAuthenticated"])
        self.assertFalse(evidence["repositorySignatureVerified"])
        self.assertFalse(evidence["installedPackageOriginVerified"])
        self.assertEqual(len(evidence["policySha256"]), 64)
        self.assertNotIn("secret", str(evidence))
        self.assertNotIn("repo.example", str(evidence))
        self.assertIn("installed-origin-or-signature-attestation", evidence["scope"])

    def test_apt_policy_foreign_label_and_suite_remain_uncertain(self):
        raw = ("Package files:\n"
               " 500 https://mirror.invalid stable/main amd64 Packages\n"
               "     release o=Some Corporate Mirror,a=stable,n=trixie,c=main,b=amd64\n"
               "Pinned packages:\n")
        with patch.object(collector.shutil, "which", return_value="/usr/bin/apt-cache"), \
                patch.object(collector, "run", return_value=(0, raw.rstrip("\n"), "")):
            result = collector.debian_apt_repository_observation({
                "ID": "debian", "VERSION_CODENAME": "bookworm"})
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["otherLabelEntries"], 1)
        self.assertEqual(result["releaseLabels"], ["other-label-observed"])
        self.assertFalse(result["suiteConsistent"])
        self.assertFalse(result["repositorySignatureVerified"])

    def test_malformed_or_missing_apt_policy_is_not_debian_signing_evidence(self):
        inputs = [
            "Package files:\n 500 file:/packages\n release o=Debian,n=bookworm,n=trixie\nPinned packages:",
            "Package files:\n 500 file:/packages\n release o=Debian,n=https://tokens.example\nPinned packages:",
            "Package files:\n 100 /var/lib/dpkg/status\n release a=now\nPinned packages:",
            "Package files:\nPinned packages:",
        ]
        for raw in inputs:
            with self.subTest(raw=raw[:28]), patch.object(collector.shutil, "which", return_value="/usr/bin/apt-cache"), \
                    patch.object(collector, "run", return_value=(0, raw, "")):
                evidence = collector.debian_apt_repository_observation({
                    "ID": "debian", "VERSION_CODENAME": "bookworm"})
                self.assertEqual(evidence["status"], "ambiguous")
                self.assertIsNotNone(evidence["policySha256"])
                self.assertFalse(evidence["suiteConsistent"])
                self.assertFalse(evidence["installedPackageOriginVerified"])
        with patch.object(collector.shutil, "which", return_value=None), \
                patch.object(collector, "run") as run:
            missing = collector.debian_apt_repository_observation({
                "ID": "debian", "VERSION_CODENAME": "bookworm"})
            self.assertEqual(missing["status"], "unavailable")
            run.assert_not_called()
        with patch.object(collector.shutil, "which", return_value="/usr/bin/apt-cache"), \
                patch.object(collector, "run", return_value=(2, "", "hidden local error")):
            failure = collector.debian_apt_repository_observation({
                "ID": "debian", "VERSION_CODENAME": "bookworm"})
            self.assertEqual(failure["status"], "unavailable")
            self.assertNotIn("hidden", str(failure))

    def test_apt_evidence_cannot_inherit_debian_identity_from_astra_or_ubuntu(self):
        for osid in ("astra", "ubuntu", "custom"):
            with self.subTest(os=osid), patch.object(collector, "run") as run:
                result = collector.debian_apt_repository_observation({
                    "ID": osid, "VERSION_CODENAME": "bookworm"})
                self.assertEqual(result["status"], "unavailable")
                run.assert_not_called()

    def test_signed_release_backports_requires_exact_origin_and_codename_pair(self):
        def release(origin, codename):
            return ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                    "Origin: " + origin + "\nCodename: " + codename + "\n"
                    "Date: Mon, 02 Nov 2026 10:00:00 UTC\n"
                    "-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n").encode()
        self.assertEqual(collector._debian_inrelease_headers(
            release("Debian Backports", "bookworm-backports"), "bookworm"), "bookworm-backports")
        self.assertEqual(collector._debian_inrelease_headers(
            release("Debian", "bookworm-security"), "bookworm"), "bookworm-security")
        for origin, codename in [
            ("Debian Backports", "bookworm"),
            ("Debian", "bookworm-backports"),
            ("Unrelated Builder", "bookworm"),
            ("Debian Backports", "trixie-backports"),
        ]:
            with self.subTest(origin=origin, codename=codename):
                with self.assertRaises(ValueError):
                    collector._debian_inrelease_headers(release(origin, codename), "bookworm")

    def test_cached_signed_debian_release_is_only_locally_verified(self):
        import hashlib
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory(prefix="hcp-debian-inrelease-") as temp:
            root = Path(temp)
            lists = root / "lists"
            lists.mkdir()
            keyring = root / "debian-archive-keyring.gpg"
            keyring.write_bytes(b"synthetic-keyring-NOT-A-TRUST-ANCHOR")
            release = lists / "deb.debian.org_debian_dists_bookworm_InRelease"
            release.write_bytes((
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Origin: Debian\nLabel: Debian\nCodename: bookworm\n"
                "Suite: oldstable\nDate: Mon, 02 Nov 2026 10:00:00 UTC\n"
                "-----BEGIN PGP SIGNATURE-----\nnot-a-real-signature\n"
                "-----END PGP SIGNATURE-----\n").encode("utf-8"))
            fingerprint = "A" * 40
            gpgv_output = ("[GNUPG:] GOODSIG 01234567890ABCDEF Example\n"
                           "[GNUPG:] VALIDSIG " + fingerprint + " 2026-11-02 0 4 0 1 8 00 " +
                           fingerprint + "\n").encode("ascii")
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(lists)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(keyring)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"), \
                    patch.object(collector.subprocess, "run", return_value=Mock(returncode=0, stdout=gpgv_output, stderr=b"")) as run:
                result = collector.debian_cached_inrelease_signatures(
                    {"ID": "debian", "VERSION_CODENAME": "bookworm"})
            self.assertEqual(result["status"], "verified_with_local_keyring")
            self.assertTrue(result["localSignatureVerified"])
            self.assertEqual(result["validLocalSignatures"], 1)
            self.assertEqual(result["signedReleases"], ["bookworm"])
            self.assertEqual(result["signerFingerprints"], [fingerprint.lower()])
            self.assertEqual(result["localKeyringSha256"], hashlib.sha256(keyring.read_bytes()).hexdigest())
            self.assertEqual(result["inReleaseSha256"], [hashlib.sha256(release.read_bytes()).hexdigest()])
            for field in ("publisherAuthenticated", "publisherFreshnessVerified",
                          "packageIndexHashesVerified", "installedPackageOriginVerified", "remediationAuthorized"):
                self.assertIs(result[field], False)
            self.assertNotIn(str(lists), str(result))
            self.assertNotIn("not-a-real-signature", str(result))
            self.assertEqual(run.call_args.args[0][0], "gpgv")
            self.assertNotIn("sh", run.call_args.args[0][0])

    def test_only_fixed_same_directory_debian_gpg_pgp_alias_is_allowed(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory(prefix="hcp-inrelease-alias-") as temp:
            directory = Path(temp)
            apt = directory / "lists"
            apt.mkdir()
            key = directory / "debian-archive-keyring.pgp"
            key.write_bytes(b"synthetic-local-only-keyring")
            alias = directory / "debian-archive-keyring.gpg"
            alias.symlink_to("debian-archive-keyring.pgp")
            release = apt / "mirror_debian_dists_bookworm_InRelease"
            release.write_bytes((
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Origin: Debian\nCodename: bookworm\nDate: Mon, 02 Nov 2026 10:00:00 UTC\n"
                "-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n").encode())
            stdout = ("[GNUPG:] GOODSIG 1234567890 Example\n[GNUPG:] VALIDSIG " +
                      "A" * 40 + " extra\n").encode()
            def verify(command, **kwargs):
                self.assertEqual(command[4], str(key))
                return Mock(returncode=0, stdout=stdout, stderr=b"")
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(apt)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(alias)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"), \
                    patch.object(collector.subprocess, "run", side_effect=verify):
                good = collector.debian_cached_inrelease_signatures({
                    "ID": "debian", "VERSION_CODENAME": "bookworm"})
            self.assertEqual(good["status"], "verified_with_local_keyring")
            self.assertTrue(good["localSignatureVerified"])
            alias.unlink()
            alias.symlink_to("../untrusted-location")
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(apt)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(alias)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"):
                bad = collector.debian_cached_inrelease_signatures({
                    "ID": "debian", "VERSION_CODENAME": "bookworm"})
            self.assertEqual(bad["status"], "unavailable")
            self.assertFalse(bad["publisherAuthenticated"])

    def test_cached_release_rejects_invalid_local_signature_and_distro_spoof(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory(prefix="hcp-debian-inrelease-") as temp:
            root = Path(temp)
            lists = root / "lists"
            lists.mkdir()
            keyring = root / "debian-archive-keyring.gpg"
            keyring.write_bytes(b"synthetic-keyring")
            release = lists / "mirror_debian_dists_bookworm_InRelease"
            release.write_bytes((
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Origin: Debian\nCodename: bookworm\nDate: Mon, 02 Nov 2026 10:00:00 UTC\n"
                "-----BEGIN PGP SIGNATURE-----\nnot-signed\n-----END PGP SIGNATURE-----\n").encode())
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(lists)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(keyring)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"), \
                    patch.object(collector.subprocess, "run", return_value=Mock(
                        returncode=1, stdout=b"[GNUPG:] BADSIG AAAAAAAAAAAAA Bad\n", stderr=b"bad")):
                invalid = collector.debian_cached_inrelease_signatures(
                    {"ID": "debian", "VERSION_CODENAME": "bookworm"})
                self.assertEqual(invalid["status"], "partial")
                self.assertEqual(invalid["validLocalSignatures"], 0)
                self.assertEqual(invalid["invalidOrUnverifiable"], 1)
                self.assertFalse(invalid["localSignatureVerified"])
                self.assertFalse(invalid["publisherAuthenticated"])
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(lists)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(keyring)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"), \
                    patch.object(collector.subprocess, "run") as run:
                self.assertEqual(collector.debian_cached_inrelease_signatures(
                    {"ID": "astra", "VERSION_CODENAME": "bookworm"})["status"], "unavailable")
                self.assertEqual(collector.debian_cached_inrelease_signatures(
                    {"ID": "ubuntu", "VERSION_CODENAME": "bookworm"})["status"], "unavailable")
                run.assert_not_called()
            release.unlink()
            release.symlink_to(keyring)
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(lists)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(keyring)), \
                    patch.object(collector.shutil, "which", return_value="/usr/bin/gpgv"):
                bad = collector.debian_cached_inrelease_signatures(
                    {"ID": "debian", "VERSION_CODENAME": "bookworm"})
                self.assertEqual(bad["status"], "unavailable")
                self.assertFalse(bad["localSignatureVerified"])


    def test_debian_release_signed_sha256_parses_exact_uncompressed_packages_without_urls(self):
        import hashlib
        raw_pkg = b"Package: libssl3\nVersion: 3.0.14-1~deb12u2\n\n"
        sha = hashlib.sha256(raw_pkg).hexdigest()
        contents = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                    "Origin: Debian\nCodename: bookworm\nDate: Tue, 03 Nov 2026 10:00:00 UTC\n"
                    "SHA256:\n " + sha + " " + str(len(raw_pkg)) + " main/binary-amd64/Packages\n"
                    " " + "a" * 64 + " 2 main/binary-amd64/Packages.xz\n"
                    "-----BEGIN PGP SIGNATURE-----\nsynthetic-test-only\n"
                    "-----END PGP SIGNATURE-----\n").encode()
        release, entries = collector._debian_signed_package_hashes(contents, "bookworm")
        self.assertEqual(release, "bookworm")
        self.assertEqual(entries, {"main/binary-amd64/Packages": (sha, len(raw_pkg))})
        altered = contents.replace(b" main/binary-amd64/Packages\n",
                                   b" ../private/Packages\n")
        self.assertEqual(collector._debian_signed_package_hashes(altered, "bookworm")[1], {})
        repeated = contents.replace(b"-----BEGIN PGP SIGNATURE-----",
                                    (" " + sha + " " + str(len(raw_pkg)) + " main/binary-amd64/Packages\n"
                                     "-----BEGIN PGP SIGNATURE-----").encode())
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            collector._debian_signed_package_hashes(repeated, "bookworm")

    def test_debian_cached_packages_match_only_actual_signed_release_sha256(self):
        import hashlib
        from unittest.mock import Mock
        package = b"Package: libssl3\nVersion: 3.0.14-1~deb12u2\nArchitecture: amd64\n\n"
        sha = hashlib.sha256(package).hexdigest()
        with tempfile.TemporaryDirectory(prefix="hcp-signed-packages-") as directory:
            root = Path(directory)
            lists = root / "lists"
            lists.mkdir()
            key = root / "debian-archive-keyring.gpg"
            key.write_bytes(b"synthetic-keyring")
            inrelease = lists / "mirror_debian_dists_bookworm_InRelease"
            inrelease.write_bytes((
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Origin: Debian\nCodename: bookworm\nDate: Tue, 03 Nov 2026 10:00:00 UTC\n"
                "SHA256:\n " + sha + " " + str(len(package)) + " main/binary-amd64/Packages\n"
                "-----BEGIN PGP SIGNATURE-----\nsynthetic-only\n-----END PGP SIGNATURE-----\n").encode())
            index = lists / "mirror_debian_dists_bookworm_main_binary-amd64_Packages.lz4"
            index.write_bytes(b"synthetic-compressed-bytes")
            signature = {"status": "verified_with_local_keyring", "localSignatureVerified": True,
                         "publisherAuthenticated": False, "installedPackageOriginVerified": False,
                         "localKeyringSha256": hashlib.sha256(key.read_bytes()).hexdigest(),
                         "inReleaseSha256": [hashlib.sha256(inrelease.read_bytes()).hexdigest()]}
            verification = Mock(returncode=0,
                                stdout=("[GNUPG:] GOODSIG ABC Example\n[GNUPG:] VALIDSIG " +
                                        "A" * 40 + " extra\n").encode())
            with patch.object(collector, "DEBIAN_INRELEASE_DIR", str(lists)), \
                    patch.object(collector, "DEBIAN_ARCHIVE_KEYRING", str(key)), \
                    patch.object(collector.subprocess, "run", return_value=verification), \
                    patch.object(collector, "_debian_apt_helper_sha256", return_value=(sha, len(package))) as decode:
                observed = collector.debian_cached_package_index_hashes(
                    {"ID": "debian", "VERSION_CODENAME": "bookworm"}, signature)
                self.assertEqual(observed["status"], "locally_hash_matched")
                self.assertTrue(observed["verifiedAgainstLocallySignedRelease"])
                self.assertEqual(observed["candidateIndexes"], 1)
                self.assertEqual(observed["matchedIndexes"], 1)
                self.assertEqual(observed["indexRecords"][0]["packagesSha256"], sha)
                self.assertEqual(observed["indexRecords"][0]["releaseSha256"],
                                 hashlib.sha256(inrelease.read_bytes()).hexdigest())
                self.assertEqual(observed["indexRecords"][0]["component"], "main")
                self.assertEqual(observed["indexRecords"][0]["architecture"], "amd64")
                self.assertEqual(decode.call_count, 1)
                for flag in ("publisherAuthenticated", "keyringIndependentlyAuthenticated",
                             "publisherFreshnessVerified", "installedPackageOriginVerified",
                             "remediationAuthorized"):
                    self.assertIs(observed[flag], False)
                with patch.object(collector, "_debian_apt_helper_sha256", return_value=("f" * 64, len(package))):
                    bad = collector.debian_cached_package_index_hashes(
                        {"ID": "debian", "VERSION_CODENAME": "bookworm"}, signature)
                    self.assertEqual(bad["status"], "partial")
                    self.assertEqual(bad["matchedIndexes"], 0)
                    self.assertEqual(bad["mismatchedIndexes"], 1)
                    self.assertFalse(bad["verifiedAgainstLocallySignedRelease"])
                with patch.object(collector, "_debian_apt_helper_sha256", return_value=(sha, len(package) - 1)):
                    bad_length = collector.debian_cached_package_index_hashes(
                        {"ID": "debian", "VERSION_CODENAME": "bookworm"}, signature)
                    self.assertEqual(bad_length["status"], "partial")
                index.unlink()
                index.symlink_to(str(key))
                with patch.object(collector, "_debian_apt_helper_sha256", return_value=(sha, len(package))):
                    symlink = collector.debian_cached_package_index_hashes(
                        {"ID": "debian", "VERSION_CODENAME": "bookworm"}, signature)
                    self.assertEqual(symlink["status"], "unavailable")
                    self.assertFalse(symlink["verifiedAgainstLocallySignedRelease"])
                    self.assertEqual(symlink["indexRecords"], [])

    def test_debian_package_index_hashes_never_inherit_astra_or_suggest_installed_origin(self):
        with patch.object(collector, "_debian_apt_helper_sha256") as decompress:
            for distro in ("astra", "ubuntu", "derivative"):
                evidence = collector.debian_cached_package_index_hashes(
                    {"ID": distro, "VERSION_CODENAME": "bookworm"}, {})
                self.assertEqual(evidence["status"], "unavailable")
                self.assertFalse(evidence["installedPackageOriginVerified"])
            decompress.assert_not_called()

    def test_apt_helper_streams_actual_gzip_without_network_or_unbounded_output(self):
        import gzip
        import hashlib
        apt_helper = Path("/usr/lib/apt/apt-helper")
        if not apt_helper.is_file():
            self.skipTest("APT helper is not installed on this runner")
        raw = b"Package: libssl3\nVersion: 1\n\n" * 1024
        with tempfile.TemporaryDirectory(prefix="hcp-apt-helper-") as directory:
            filename = Path(directory) / "test_Packages.gz"
            filename.write_bytes(gzip.compress(raw))
            sha, size = collector._debian_apt_helper_sha256(str(filename))
            self.assertEqual(size, len(raw))
            self.assertEqual(sha, hashlib.sha256(raw).hexdigest())

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
        def query(database=None):
            if action:
                action()
            return [{"manager": "rpm", "name": "example", "version": "1.0-1", "arch": "x86_64"}], ""
        database = {"path": os.path.dirname(collector.DATABASES["rpm"][0]), "backend": "sqlite",
                    "candidates": collector.DATABASES["rpm"]}
        with patch.object(collector, "read_os_release", return_value={"ID": "rocky", "VERSION_ID": "9.8"}), \
                patch.object(collector.shutil, "which", return_value="/usr/bin/rpm"), \
                patch.object(collector, "resolve_rpm_database", return_value=database), \
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


class RpmDatabaseSelectionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hcp-rpm-path # ? ")
        self.addCleanup(self.temporary.cleanup)
        self.standard = Path(self.temporary.name) / "stale-standard"
        self.custom = Path(self.temporary.name) / "custom"
        for path, version in ((self.standard, "1.0"), (self.custom, "2.0")):
            path.mkdir()
            connection = sqlite3.connect(str(path / "rpmdb.sqlite"))
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE Packages (version TEXT)")
            connection.execute("INSERT INTO Packages VALUES (?)", (version,))
            connection.commit()
            connection.close()
        self.configuration = {"path": str(self.custom), "backend": "sqlite"}
        self.queries = []

    def collect(self, before_query=None, after_query=None, macro_response=None, during_recheck=None):
        macro_reads = [0]
        def native(command):
            if command == ["rpm", "--eval", collector.RPM_DATABASE_QUERY]:
                macro_reads[0] += 1
                if macro_reads[0] == 2 and during_recheck:
                    during_recheck()
                return 0, macro_response if macro_response is not None else (
                    self.configuration["path"] + "\n" + self.configuration["backend"] + "\nHCP-RPM-DATABASE-END"), ""
            self.assertEqual(command[:2], ["rpm", "--dbpath"])
            self.assertEqual(command[3:5], ["--define", "_db_backend sqlite"])
            if command[-1] == "--querytags":
                return 0, "EPOCHNUM MODULARITYLABEL", ""
            self.assertIn("-qa", command)
            self.queries.append(command)
            if before_query:
                before_query()
            connection = sqlite3.connect("file:" + collector.quote(str(Path(command[2]) / "rpmdb.sqlite"), safe="/") + "?mode=ro", uri=True)
            try:
                version = connection.execute("SELECT version FROM Packages").fetchone()[0]
            finally:
                connection.close()
            if after_query:
                after_query()
            return 0, "example\t0\t" + version + "\t1.el9\tx86_64\texample-" + version + "-1.el9.src.rpm\tRocky Enterprise Software Foundation\tRocky\tRocky\t(none)\n", ""

        with patch.dict(collector.DATABASES, {"rpm": (str(self.standard / "rpmdb.sqlite"),)}), \
                patch.object(collector, "read_os_release", return_value={"ID": "rocky", "VERSION_ID": "9.8"}), \
                patch.object(collector.shutil, "which", return_value="/usr/bin/rpm"), \
                patch.object(collector, "run", side_effect=native), \
                patch.object(collector, "read_text", side_effect=FileNotFoundError()):
            return collector.collect()

    def test_custom_db_is_selected_and_pinned_despite_stale_standard_db(self):
        report = self.collect()
        self.assertFalse(report["partial"], report["packageInventory"])
        self.assertEqual(report["packages"][0]["version"], "2.0-1.el9")
        self.assertEqual(report["packageInventory"]["rpmDatabase"], {
            "path": str(self.custom), "backend": "sqlite", "selection": "native-macros-pinned"})
        self.assertEqual(self.queries[0][2], str(self.custom))

    def test_commit_in_custom_db_is_detected_while_stale_db_is_unchanged(self):
        before = (self.standard / "rpmdb.sqlite").read_bytes()
        def update():
            connection = sqlite3.connect(str(self.custom / "rpmdb.sqlite"))
            connection.execute("UPDATE Packages SET version='3.0'")
            connection.commit()
            connection.close()
        report = self.collect(after_query=update)
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])
        self.assertEqual((self.standard / "rpmdb.sqlite").read_bytes(), before)

    def test_macro_path_migration_cannot_be_reported_complete(self):
        def migrate():
            self.configuration["path"] = str(self.standard)
        report = self.collect(after_query=migrate)
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_commit_during_final_configuration_query_is_still_observed(self):
        def update():
            connection = sqlite3.connect(str(self.custom / "rpmdb.sqlite"))
            connection.execute("UPDATE Packages SET version='3.0'")
            connection.commit()
            connection.close()
        report = self.collect(during_recheck=update)
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_symlink_retarget_does_not_redirect_pinned_query(self):
        alias = Path(self.temporary.name) / "current"
        alias.symlink_to(self.custom, target_is_directory=True)
        self.configuration["path"] = str(alias)
        def retarget():
            alias.unlink()
            alias.symlink_to(self.standard, target_is_directory=True)
        report = self.collect(before_query=retarget)
        self.assertEqual(report["packages"][0]["version"], "2.0-1.el9")
        self.assertTrue(report["partial"])
        self.assertIn("changed", report["packageInventory"]["error"])

    def test_new_backend_file_during_query_is_ambiguous(self):
        report = self.collect(after_query=lambda: (self.custom / "Packages").write_bytes(b"new backend"))
        self.assertTrue(report["partial"])
        self.assertIn("ambiguous", report["packageInventory"]["error"])

    def test_unknown_missing_or_mismatched_backend_never_runs_query(self):
        for backend in ("unknown", "dummy", "bdb", "ndb", ""):
            with self.subTest(backend=backend):
                self.configuration["backend"] = backend
                report = self.collect()
                self.assertTrue(report["partial"])
                self.assertEqual(self.queries, [])
                self.assertEqual(report["packages"], [])
        self.configuration["backend"] = "sqlite"
        self.configuration["path"] = str(self.custom / "missing")
        report = self.collect()
        self.assertTrue(report["partial"])
        self.assertFalse((self.custom / "missing").exists())

    def test_invalid_macro_path_and_output_are_rejected_without_query(self):
        for path in ("relative", "%{_dbpath}", "/tmp/%[1+1]", "/tmp/%bare_macro", "/tmp/%%literal",
                     "/tmp/path\nsecond", "/tmp/path\x00", "/tmp/path\ufffd", "/" + "x" * 4096):
            with self.subTest(path=path[:60]):
                report = self.collect(macro_response=path + "\nsqlite\nHCP-RPM-DATABASE-END")
                self.assertTrue(report["partial"])
                self.assertEqual(self.queries, [])
        report = self.collect(macro_response="unexpected output")
        self.assertTrue(report["partial"])
        self.assertEqual(self.queries, [])

    def test_macro_syntax_hidden_in_canonical_symlink_target_is_rejected(self):
        target = Path(self.temporary.name) / "literal-%[1+1]"
        target.mkdir()
        shutil.copyfile(str(self.custom / "rpmdb.sqlite"), str(target / "rpmdb.sqlite"))
        alias = Path(self.temporary.name) / "alias-without-macros"
        alias.symlink_to(target, target_is_directory=True)
        self.configuration["path"] = str(alias)
        report = self.collect()
        self.assertTrue(report["partial"])
        self.assertIn("unsupported", report["packageInventory"]["error"])
        self.assertEqual(self.queries, [])

    def test_legacy_bdb_without_backend_macro_is_explicitly_bounded(self):
        legacy = Path(self.temporary.name) / "legacy"
        legacy.mkdir()
        (legacy / "Packages").write_bytes(b"BDB fixture")
        with patch.object(collector, "run", return_value=(0, str(legacy) + "\n\nHCP-RPM-DATABASE-END", "")):
            database = collector.resolve_rpm_database()
        self.assertEqual(database["path"], str(legacy))
        self.assertEqual(database["backend"], "")
        self.assertEqual(len(database["candidates"]), 3)


if __name__ == "__main__":
    unittest.main()
