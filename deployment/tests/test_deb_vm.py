"""Controller regressions with synthetic data and owned temporary processes.

These tests never run a VM, query a host package database or change host firewall
rules. The native workflow supplies the separate runtime evidence.
"""
import builtins
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
try:
    SPEC = importlib.util.spec_from_file_location("hcp_deb_vm_acceptance", TESTS / "linux_deb_vm_integration.py")
    NATIVE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(NATIVE)
finally:
    sys.path.pop(0)


def image_bytes_source(data):
    return {
        "url": "https://cloud.debian.org/owned-test.qcow2",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "publisherChecksum": {"algorithm": "sha512", "value": hashlib.sha512(data).hexdigest()},
    }


class Response(io.BytesIO):
    def __init__(self, data, url="https://cloud.debian.org/owned-test.qcow2", on_read=None):
        super().__init__(data)
        self.url, self.on_read = url, on_read

    def geturl(self):
        return self.url

    def read1(self, size=-1):
        if self.on_read:
            callback, self.on_read = self.on_read, None
            callback()
        return super().read(min(size, 7))


class ImageGuardTests(unittest.TestCase):
    def test_actual_pins_are_dated_and_bound_to_native_identity(self):
        for distribution, version in (("debian", "12"), ("ubuntu", "24.04")):
            with self.subTest(distribution=distribution):
                source = NATIVE.image_source(distribution)
                self.assertEqual((source["expectedOsId"], source["expectedVersionId"]), (distribution, version))
                self.assertIn(source["build"], source["url"])
                self.assertEqual(source["architecture"], "x86_64")
                self.assertGreater(source["bytes"], 100 * 1024 * 1024)

    def test_moving_aliases_foreign_urls_and_conflicting_metadata_cannot_be_pins(self):
        manifest = json.loads(NATIVE.MANIFEST.read_text())
        invalid = []
        for distribution, changes in (
            ("debian", {"url": manifest["images"]["debian"]["url"].replace("20261026-2643/", "latest/")}),
            ("ubuntu", {"url": manifest["images"]["ubuntu"]["url"].replace("release-20261017/", "release/")}),
            ("ubuntu", {"url": manifest["images"]["ubuntu"]["url"].replace("release-20261017/", "current/")}),
            ("debian", {"url": manifest["images"]["debian"]["url"].replace("https://", "http://")}),
            ("ubuntu", {"url": manifest["images"]["ubuntu"]["url"].replace("https://", "https://user@")}),
            ("debian", {"url": manifest["images"]["debian"]["url"] + "?mutable=1"}),
            ("debian", {"expectedVersionId": "13"}),
            ("ubuntu", {"architecture": "aarch64"}),
            ("debian", {"bytes": True}),
            ("ubuntu", {"build": "20261018"}),
            ("debian", {"checksumUrl": "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"}),
            ("ubuntu", {"publisherChecksum": {"algorithm": "sha256", "value": "0" * 64}}),
        ):
            candidate = copy.deepcopy(manifest)
            candidate["images"][distribution].update(changes)
            invalid.append((distribution, changes, candidate))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            for distribution, changes, candidate in invalid:
                with self.subTest(distribution=distribution, fields=tuple(changes)):
                    path.write_text(json.dumps(candidate))
                    with self.assertRaises(ValueError):
                        NATIVE.image_source(distribution, path)

    def test_full_download_preserves_exact_bytes_and_both_digests(self):
        data = b"qcow2-synthetic-byte-fixture\x00\xff" * 13
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "source.qcow2"
            NATIVE.download_image(image_bytes_source(data), target, opener=lambda *a, **k: Response(data))
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertFalse(target.with_suffix(".download").exists())

    def test_truncated_oversized_corrupt_and_publisher_mismatch_downloads_are_withheld(self):
        data = b"pinned image data"
        cases = [
            (image_bytes_source(data), data[:-1]),
            (image_bytes_source(data), data + b"!"),
            (image_bytes_source(data), b"X" + data[1:]),
        ]
        publisher_conflict = image_bytes_source(data)
        publisher_conflict["publisherChecksum"]["value"] = "0" * 128
        cases.append((publisher_conflict, data))
        for source, observed in cases:
            with self.subTest(length=len(observed), publisher=source["publisherChecksum"]["value"][:8]):
                with tempfile.TemporaryDirectory() as temporary:
                    target = Path(temporary) / "source.qcow2"
                    with self.assertRaises(ValueError):
                        NATIVE.download_image(source, target, opener=lambda *a, **k: Response(observed))
                    self.assertFalse(target.exists())
                    self.assertFalse(target.with_suffix(".download").exists())

    def test_http_redirect_is_rejected_before_publication(self):
        data = b"pinned"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "source.qcow2"
            with self.assertRaisesRegex(ValueError, "outside HTTPS"):
                NATIVE.download_image(image_bytes_source(data), target,
                                      opener=lambda *a, **k: Response(data, "http://example.test/source"))
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".download").exists())

    def test_preexisting_target_temporary_and_symlink_are_never_removed(self):
        for kind in ("target", "temporary", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "source.qcow2"
                occupied = target if kind == "target" else target.with_suffix(".download")
                owner = Path(temporary) / "other-owner"
                owner.write_bytes(b"other-owner-data")
                if kind == "symlink":
                    occupied.symlink_to(owner)
                else:
                    occupied.write_bytes(b"existing-data")
                with self.assertRaises(ValueError):
                    NATIVE.download_image(image_bytes_source(b"new"), target,
                                          opener=lambda *a, **k: self.fail("Preexisting paths must fail before networking"))
                self.assertTrue(os.path.lexists(occupied))
                self.assertEqual(owner.read_bytes(), b"other-owner-data")
                self.assertEqual(occupied.read_bytes(), b"other-owner-data" if kind == "symlink" else b"existing-data")

    def test_concurrent_target_creation_is_preserved_by_no_clobber_publication(self):
        data = b"pinned-image"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "source.qcow2"
            def race():
                target.write_bytes(b"belongs-to-another-operation")
            with self.assertRaises(FileExistsError):
                NATIVE.download_image(image_bytes_source(data), target,
                                      opener=lambda *a, **k: Response(data, on_read=race))
            self.assertEqual(target.read_bytes(), b"belongs-to-another-operation")
            self.assertFalse(target.with_suffix(".download").exists())

    def test_absolute_deadline_interrupts_blocked_reads_and_restores_signal_handler(self):
        data = b"pinned-image"
        old_handler = signal.getsignal(signal.SIGALRM)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "source.qcow2"
            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, "absolute time limit"):
                NATIVE.download_image(image_bytes_source(data), target, timeout=0.05,
                                      opener=lambda *a, **k: Response(data, on_read=lambda: time.sleep(5)))
            self.assertLess(time.monotonic() - started, 2)
            self.assertIs(signal.getsignal(signal.SIGALRM), old_handler)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".download").exists())


def dpkg_fixture():
    rows = [
        ("ii ", "libexample:amd64", "1:2.3-4+b1", "amd64", "example", "1:2.3-4", "Debian Example Team <team@debian.org>", ""),
        ("hi ", "libexample:i386", "1:2.3-4+b1", "i386", "example", "1:2.3-4", "Debian Example Team <team@debian.org>", ""),
        ("ii ", "independent", "0.1", "all", "independent-source", "0.1", "Local Builder", "Third Party"),
    ]
    fields = ("dpkgStatus", "name", "version", "arch", "sourceName", "sourceVersion", "maintainer", "origin")
    packages = [dict(zip(fields, row), manager="dpkg", sourceEpochKnown=True) for row in rows]
    report = {"packages": packages, "packageInventory": {
        "manager": "dpkg", "partial": False, "collectorVersion": 2, "managerSelection": "os-id",
        "packageCount": len(packages), "osRelease": {"ID": "debian", "VERSION_ID": "12"}}}
    rows.append(("rc ", "removed", "1.0", "amd64", "removed", "1.0", "Debian", ""))
    return report, "\n".join("\t".join(row) for row in rows) + "\n"


class DpkgConservationTests(unittest.TestCase):
    def test_native_multiset_preserves_multiarch_epoch_source_and_hold(self):
        report, native = dpkg_fixture()
        report["packages"].reverse()
        result = NATIVE.verify_dpkg_inventory(report, native, "debian")
        self.assertEqual(result["records"], 3)
        self.assertTrue(result["allEightNativeFieldsEqual"])
        self.assertTrue(result["sourceEpochPreserved"])

    def test_missing_multiarch_record_or_changed_source_cannot_be_hidden_by_counts(self):
        report, native = dpkg_fixture()
        changes = [
            ("sourceVersion", "1:2.3-4+b1"), ("sourceName", "libexample"),
            ("arch", "i386"), ("dpkgStatus", "iiR"), ("maintainer", "Different Maintainer"),
            ("origin", "Vendor"), ("sourceEpochKnown", False), ("manager", "rpm"),
        ]
        for key, value in changes:
            with self.subTest(key=key):
                candidate = copy.deepcopy(report)
                candidate["packages"][0][key] = value
                with self.assertRaises(ValueError):
                    NATIVE.verify_dpkg_inventory(candidate, native, "debian")
        for operation in ("omit", "duplicate"):
            candidate = copy.deepcopy(report)
            if operation == "omit":
                candidate["packages"].pop(1)
            else:
                candidate["packages"][1] = copy.deepcopy(candidate["packages"][0])
            candidate["packageInventory"]["packageCount"] = len(candidate["packages"])
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                NATIVE.verify_dpkg_inventory(candidate, native, "debian")

    def test_native_partial_or_wrong_release_and_duplicate_native_rows_fail(self):
        report, native = dpkg_fixture()
        for key, value in (("partial", True), ("managerSelection", "id-like"), ("error", "query failed")):
            candidate = copy.deepcopy(report)
            candidate["packageInventory"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                NATIVE.verify_dpkg_inventory(candidate, native, "debian")
        with self.assertRaises(ValueError):
            NATIVE.verify_dpkg_inventory(report, native, "ubuntu")
        with self.assertRaises(ValueError):
            NATIVE.verify_dpkg_inventory(report, native + native.splitlines()[0] + "\n", "debian")


def ufw_fixture():
    entries = [{"metainfo": {"version": "synthetic", "json_schema_version": 1}}]
    for family in ("ip", "ip6"):
        entries.extend([
            {"table": {"family": family, "name": "filter", "handle": 1}},
            {"chain": {"family": family, "table": "filter", "name": "INPUT", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"rule": {"family": family, "table": "filter", "chain": "INPUT", "handle": 3,
                      "expr": [{"counter": {"packets": 12, "bytes": 400}}, {"drop": None}]}},
        ])
    return {"nftables": entries}


TOKEN = "hcp-deb-input-" + "a" * 32


def with_owned_accepts(baseline):
    result = copy.deepcopy(baseline)
    for family in ("ip", "ip6"):
        position = next(i for i, entry in enumerate(result["nftables"])
                        if entry.get("rule", {}).get("family") == family)
        result["nftables"].insert(position, {"rule": {
            "family": family, "table": "filter", "chain": "INPUT", "handle": 10, "comment": TOKEN,
            "expr": [{"counter": {"packets": 10, "bytes": 300}}, {"accept": None}]}})
    return result


class UfwRulesetGuardTests(unittest.TestCase):
    def test_two_observed_input_chains_and_only_owned_first_accepts_are_accepted(self):
        baseline = ufw_fixture()
        self.assertEqual(NATIVE.validate_ufw_ruleset(baseline), ["ip/filter/INPUT", "ip6/filter/INPUT"])
        allowed = with_owned_accepts(baseline)
        # Handles and live counters vary without changing rule semantics.
        for entry in allowed["nftables"]:
            value = next(iter(entry.values()))
            if "handle" in value:
                value["handle"] += 100
            for expression in value.get("expr", []):
                if "counter" in expression:
                    expression["counter"] = {"packets": 99, "bytes": 9999}
        NATIVE.verify_allow_delta(baseline, allowed, TOKEN)
        self.assertEqual(baseline, ufw_fixture())

    def test_unobserved_input_chain_dormant_table_or_dangling_rule_blocks_mutation(self):
        cases = []
        extra = ufw_fixture()
        extra["nftables"].append({"chain": {"family": "ip", "table": "filter", "name": "other",
                                             "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}})
        cases.append(extra)
        flagged = ufw_fixture(); flagged["nftables"][1]["table"]["flags"] = ["dormant"]; cases.append(flagged)
        policy = ufw_fixture(); policy["nftables"][2]["chain"]["policy"] = "accept"; cases.append(policy)
        missing = ufw_fixture(); missing["nftables"] = missing["nftables"][:4]; cases.append(missing)
        dangling = ufw_fixture(); dangling["nftables"][3]["rule"]["chain"] = "unobserved"; cases.append(dangling)
        named_set = ufw_fixture(); named_set["nftables"].append({"set": {"family": "ip", "table": "filter", "name": "unknown"}}); cases.append(named_set)
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                NATIVE.validate_ufw_ruleset(candidate)

    def test_owned_comment_does_not_authorize_conditions_extra_actions_or_unrelated_changes(self):
        baseline = ufw_fixture()
        for mutation in ("condition", "action", "unrelated", "one-family", "last", "wrong-comment"):
            allowed = with_owned_accepts(baseline)
            owned_index = next(i for i, e in enumerate(allowed["nftables"]) if e.get("rule", {}).get("comment") == TOKEN)
            owned = allowed["nftables"][owned_index]["rule"]
            if mutation == "condition":
                owned["expr"].insert(0, {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}})
            elif mutation == "action":
                owned["expr"].insert(0, {"mangle": {"key": "mark", "value": 1}})
            elif mutation == "unrelated":
                allowed["nftables"][owned_index + 1]["rule"]["expr"][-1] = {"accept": None}
            elif mutation == "one-family":
                allowed["nftables"].pop(owned_index)
            elif mutation == "last":
                allowed["nftables"].append(allowed["nftables"].pop(owned_index))
            else:
                owned["comment"] = "another-owner"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                NATIVE.verify_allow_delta(baseline, allowed, TOKEN)
        with self.assertRaises(ValueError):
            NATIVE.verify_allow_delta(with_owned_accepts(baseline), with_owned_accepts(baseline), TOKEN)


class ProcessAndPrivacyTests(unittest.TestCase):
    def test_command_output_limit_retains_only_bounded_owned_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output.log"
            with self.assertRaisesRegex(RuntimeError, "output limit"):
                NATIVE.run([sys.executable, "-c", "import os; os.write(1, b'x' * 10000)"],
                           output=output, max_bytes=128, timeout=5)
            self.assertEqual(output.read_bytes(), b"x" * 128)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_timeout_kills_owned_grandchild_even_after_group_leader_exits(self):
        # The child deliberately inherits stdout and ignores SIGTERM. The
        # leader exits, reproducing the case where poll() alone misses a leak.
        code = """import os, signal, sys, time
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open(sys.argv[1], 'w') as stream:
        stream.write(str(os.getpid()) + ' ' + str(os.getpgrp()))
        stream.flush()
        os.fsync(stream.fileno())
    while True:
        time.sleep(1)
while not os.path.exists(sys.argv[1]):
    time.sleep(0.005)
os._exit(0)
"""
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "owned-process.json"
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(RuntimeError, "time limit"):
                    NATIVE.run([sys.executable, "-c", code, str(record)], timeout=0.4)
                self.assertLess(time.monotonic() - started, 8)
                pid, group = map(int, record.read_text().split())
                status = Path("/proc/{}/stat".format(pid))
                deadline = time.monotonic() + 2
                while status.exists() and status.read_text().split()[2] != "Z" and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z", "Owned grandchild escaped teardown")
            finally:
                if record.exists():
                    unused_pid, group = map(int, record.read_text().split())
                    self.assertNotEqual(group, os.getpgrp())
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_all_leaking_outputs_are_withheld_while_safe_outputs_remain(self):
        machine_id = "123456789abcdef0123456789abcdef0"
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            first, second, safe = (artifacts / name for name in ("first.json", "second.log", "safe.json"))
            first.write_text(json.dumps({"unexpected": machine_id}))
            second.write_bytes(b"x" * (1024 * 1024 - 8) + machine_id.upper().encode() + b"tail")
            safe.write_text('{"status":"failed","rawMachineIdPublished":false}')
            original = safe.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "Withheld 2"):
                NATIVE.check_public_artifacts(artifacts, machine_id)
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())
            self.assertEqual(safe.read_bytes(), original)

    def test_public_artifact_gate_removes_links_without_reading_external_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "private"; outside.write_text("private-owner-file")
            artifacts = root / "artifacts"; artifacts.mkdir()
            link = artifacts / "linked"; link.symlink_to(outside)
            key = artifacts / "key.log"; key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nowned-test-material\n")
            with self.assertRaisesRegex(RuntimeError, "Withheld 2"):
                NATIVE.check_public_artifacts(artifacts, None)
            self.assertFalse(os.path.lexists(link))
            self.assertFalse(key.exists())
            self.assertEqual(outside.read_text(), "private-owner-file")

    def test_unreadable_subtree_prevents_privacy_success_instead_of_being_skipped(self):
        machine_id = "123456789abcdef0123456789abcdef0"
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            restricted = artifacts / "unreadable"; restricted.mkdir()
            private = restricted / "uninspected.log"; private.write_text(machine_id)
            (artifacts / "safe.json").write_text('{"status":"failed"}')
            original_scandir = os.scandir
            def unreadable(path):
                if Path(path) == restricted:
                    raise PermissionError("synthetic denied subtree")
                return original_scandir(path)
            with patch.object(NATIVE.os, "scandir", side_effect=unreadable):
                with self.assertRaisesRegex(PermissionError, "denied subtree"):
                    NATIVE.check_public_artifacts(artifacts, machine_id)
            self.assertTrue(private.exists(), "A failed scan must report its gap, not claim to have inspected the subtree")

    def test_fifo_is_withheld_without_opening_or_blocking_and_safe_file_survives(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            fifo = artifacts / "unsafe.pipe"; os.mkfifo(fifo)
            safe = artifacts / "safe.json"; safe.write_text('{"status":"failed"}')
            original_open = os.open
            def guarded_open(path, flags, *args, **kwargs):
                if Path(path) == fifo:
                    self.assertTrue(flags & os.O_NONBLOCK, "The privacy gate must never block on a special file")
                return original_open(path, flags, *args, **kwargs)
            with patch.object(NATIVE.os, "open", side_effect=guarded_open):
                with self.assertRaisesRegex(RuntimeError, "Withheld 1"):
                    NATIVE.check_public_artifacts(artifacts, None)
            self.assertFalse(os.path.lexists(fifo))
            self.assertEqual(safe.read_text(), '{"status":"failed"}')

    def test_known_private_identity_and_key_are_removed_from_public_error(self):
        machine_id = "123456789abcdef0123456789abcdef0"
        error = RuntimeError("Assertion failed at " + machine_id.upper() +
                             '\n{"machineId":"' + machine_id + '"}\n' +
                             "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----")
        value = NATIVE.sanitize_public_error(error, machine_id)
        serialized = json.dumps(value)
        self.assertNotIn(machine_id, serialized.lower())
        self.assertNotIn("secret", serialized)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", serialized)
        self.assertEqual(value["type"], "RuntimeError")

    def test_final_failure_protocol_and_stderr_are_sanitized_before_publication_gate(self):
        machine_id = "123456789abcdef0123456789abcdef0"
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "owned-run"
            def failed_boot(distribution, owned_work, artifacts, protocol, private_context):
                private_context["machineId"] = machine_id
                (artifacts / "leak-one").write_text(machine_id)
                (artifacts / "leak-two").write_text(machine_id.upper())
                (artifacts / "safe").write_text("diagnostic preserved")
                (owned_work / "asset-observation.json").write_text(machine_id)
                raise RuntimeError("Unlabelled unexpected identity: " + machine_id)
            stderr = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": temporary}), \
                    patch.object(sys, "argv", ["acceptance", "--distribution", "debian", "--work-dir", str(work)]), \
                    patch.object(NATIVE.os, "access", return_value=True), \
                    patch.object(NATIVE.signal, "signal"), \
                    patch.object(NATIVE, "boot_and_verify", side_effect=failed_boot), redirect_stderr(stderr):
                self.assertEqual(NATIVE.main(), 1)
            protocol_text = (work / "artifacts/protocol.json").read_text()
            protocol = json.loads(protocol_text)
            self.assertEqual(protocol["status"], "failed")
            self.assertFalse(protocol["publicationPrivacyVerified"])
            self.assertTrue(protocol["privateGuestFilesRemoved"])
            self.assertNotIn(machine_id, protocol_text.lower())
            self.assertNotIn(machine_id, stderr.getvalue().lower())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse((work / "asset-observation.json").exists())
            self.assertFalse((work / "artifacts/leak-one").exists())
            self.assertFalse((work / "artifacts/leak-two").exists())
            self.assertEqual((work / "artifacts/safe").read_text(), "diagnostic preserved")

    def test_workflow_upload_requires_a_regular_bounded_privacy_verified_protocol(self):
        workflow = (NATIVE.ROOT / ".github/workflows/linux-deb-vm-integration.yml").read_text()
        gate = workflow.split("id: public-evidence", 1)[1].split("- name: Save public native evidence", 1)[0]
        snippet = gate.split("python - <<'PY'", 1)[1].split("\n", 1)[1].rsplit("          PY", 1)[0]
        script = "\n".join(line[10:] for line in snippet.splitlines())
        self.assertIn("if: always() && steps.public-evidence.outputs.safe == 'true'", workflow)
        cases = [("missing", None, False), ("malformed", "{", False), ("false", '{"publicationPrivacyVerified":false}', False),
                 ("string", '{"publicationPrivacyVerified":"true"}', False), ("true", '{"publicationPrivacyVerified":true}', True),
                 ("symlink", None, False), ("fifo", None, False)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            safe = root / "actual-safe.json"; safe.write_text('{"publicationPrivacyVerified":true}')
            for kind, text, expected in cases:
                protocol = root / (kind + ".json")
                if text is not None:
                    protocol.write_text(text)
                elif kind == "symlink":
                    protocol.symlink_to(safe)
                elif kind == "fifo":
                    os.mkfifo(protocol)
                with self.subTest(kind=kind):
                    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=3,
                                            env={**os.environ, "HCP_NATIVE_PROTOCOL": str(protocol)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "safe=" + ("true" if expected else "false"))


class OwnedGuestControl:
    """Execute the unchanged guest program against an isolated fake kernel.

    Every Path is mapped into the test directory; every subprocess is a strict
    fake. Any new command or attempted path outside /run and /proc fails.
    """
    def __init__(self, directory):
        self.root = Path(directory)
        (self.root / "run").mkdir()
        (self.root / "proc/1").mkdir(parents=True)
        (self.root / "proc/1/comm").write_text("systemd\n")
        self.unrelated = ("-p", "tcp", "--dport", "22", "-j", "ACCEPT")
        self.rules = {binary: [self.unrelated] for binary in ("iptables", "ip6tables")}
        self.commands = []
        self.fail_insert = None
        self.owned = ("-m", "comment", "--comment", TOKEN, "-j", "ACCEPT")
        self.marker = self.root / "run" / TOKEN

    def path(self, value):
        value = str(value)
        if not (value == "/run" or value.startswith("/run/") or value == "/proc/1/comm"):
            raise AssertionError("Guest attempted an unsupported filesystem path")
        return self.root / value.lstrip("/")

    def run_command(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        binary = argv[0]
        if binary not in self.rules or argv[1:5] != ["-w", "5", "-t", "filter"]:
            raise AssertionError("Guest attempted an unsupported subprocess")
        args = argv[5:]
        if args == ["-S", "INPUT"]:
            return SimpleNamespace(returncode=0, stdout="\n".join("-A INPUT " + " ".join(rule) for rule in self.rules[binary]), stderr="")
        operation, chain = args[:2]
        if chain != "INPUT" or operation not in ("-C", "-I", "-D"):
            raise AssertionError("Guest attempted an unsupported kernel mutation")
        rule = tuple(args[3:] if operation == "-I" else args[2:])
        if rule != self.owned or (operation == "-I" and args[2] != "1"):
            raise AssertionError("Guest attempted to mutate an unowned rule")
        if operation == "-C":
            return SimpleNamespace(returncode=0 if rule in self.rules[binary] else 1, stdout="", stderr="")
        if operation == "-I":
            # Durable intent must precede every actual insertion.
            if json.loads((self.marker / "plan.json").read_text())["state"] != "installing":
                raise AssertionError("Insert preceded durable ownership intent")
            if self.fail_insert == binary:
                return SimpleNamespace(returncode=2, stdout="", stderr="synthetic second-family failure")
            self.rules[binary].insert(0, rule)
        elif rule in self.rules[binary]:
            self.rules[binary].remove(rule)
        else:
            return SimpleNamespace(returncode=1, stdout="", stderr="absent")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def check_output(self, argv, **kwargs):
        if argv not in (["iptables", "--version"], ["ip6tables", "--version"]):
            raise AssertionError("Guest attempted an unsupported version query")
        return argv[0] + " v1.8.10 (nf_tables)\n"

    def execute(self, action):
        original_import, original_lstat = builtins.__import__, Path.lstat
        modules = {
            "pathlib": SimpleNamespace(Path=self.path),
            "os": SimpleNamespace(geteuid=lambda: 0, open=os.open, close=os.close, fsync=os.fsync, fchmod=os.fchmod,
                                  O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY),
            "sys": SimpleNamespace(argv=["owned-control", action, "/run/" + TOKEN, TOKEN]),
            "subprocess": SimpleNamespace(run=self.run_command, check_output=self.check_output, PIPE=subprocess.PIPE),
        }
        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in modules:
                return modules[name]
            if name not in {"fcntl", "json", "re", "stat", "time"}:
                raise AssertionError("Guest attempted an unsupported import")
            return original_import(name, globals, locals, fromlist, level)
        def root_owned_stat(path, *args, **kwargs):
            observed = original_lstat(path, *args, **kwargs)
            if path.is_relative_to(self.root):
                fields = list(observed); fields[4] = 0
                return os.stat_result(fields)
            return observed
        namespace = {"__builtins__": {**vars(builtins), "__import__": guarded_import}}
        output = io.StringIO()
        with patch.object(Path, "lstat", root_owned_stat), redirect_stdout(output):
            exec(compile(NATIVE.UFW_INPUT_CONTROL, "owned-guest-control", "exec"), namespace)
        return json.loads(output.getvalue())


class GuestOwnershipTests(unittest.TestCase):
    def test_successful_dual_family_control_restores_only_owned_rules_and_blocks_late_add(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = OwnedGuestControl(temporary)
            self.assertTrue(guest.execute("prepare")["prepared"])
            self.assertEqual(guest.execute("add")["installedRules"], 2)
            self.assertTrue(all(rules == [guest.owned, guest.unrelated] for rules in guest.rules.values()))
            self.assertEqual(guest.execute("remove")["removedRules"], 2)
            self.assertTrue(all(rules == [guest.unrelated] for rules in guest.rules.values()))
            self.assertEqual(json.loads((guest.marker / "plan.json").read_text())["state"], "closed")
            with self.assertRaisesRegex(RuntimeError, "Late/repeated add"):
                guest.execute("add")
            self.assertEqual(guest.execute("remove")["removedRules"], 0)

    def test_partial_add_and_lost_reply_can_be_cleaned_using_durable_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = OwnedGuestControl(temporary)
            guest.execute("prepare")
            guest.fail_insert = "ip6tables"
            with self.assertRaisesRegex(RuntimeError, "synthetic second-family failure"):
                guest.execute("add")
            self.assertEqual(json.loads((guest.marker / "plan.json").read_text())["state"], "installing")
            self.assertEqual(guest.execute("remove")["removedRules"], 1)
            self.assertTrue(all(rules == [guest.unrelated] for rules in guest.rules.values()))

    def test_missing_or_unused_marker_never_authorizes_removing_a_preexisting_exact_rule(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = OwnedGuestControl(temporary)
            guest.rules["iptables"].insert(0, guest.owned)
            self.assertFalse(guest.execute("remove")["owned"])
            guest.execute("prepare")
            with self.assertRaisesRegex(RuntimeError, "preexisting control rule"):
                guest.execute("add")
            with self.assertRaisesRegex(RuntimeError, "not owned and was preserved"):
                guest.execute("remove")
            self.assertEqual(guest.rules["iptables"], [guest.owned, guest.unrelated])
            self.assertFalse(any(command[5] == "-D" for command in guest.commands))
            self.assertEqual(json.loads((guest.marker / "plan.json").read_text())["state"], "unused")

    def test_cleanup_first_tombstone_prevents_delayed_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = OwnedGuestControl(temporary)
            guest.execute("prepare")
            self.assertEqual(guest.execute("remove")["removedRules"], 0)
            with self.assertRaisesRegex(RuntimeError, "Late/repeated add"):
                guest.execute("add")
            self.assertTrue(all(rules == [guest.unrelated] for rules in guest.rules.values()))

    def test_unverifiable_ownership_refuses_kernel_changes(self):
        for tampering in ("permissions", "plan"):
            with self.subTest(tampering=tampering), tempfile.TemporaryDirectory() as temporary:
                guest = OwnedGuestControl(temporary)
                guest.execute("prepare")
                plan = guest.marker / "plan.json"
                if tampering == "permissions":
                    plan.chmod(0o644)
                else:
                    value = json.loads(plan.read_text()); value["token"] = "another-owner"
                    plan.write_text(json.dumps(value))
                with self.assertRaises(RuntimeError):
                    guest.execute("remove")
                self.assertEqual(guest.commands, [])

    def test_duplicate_owned_shape_is_not_silently_deleted_as_arbitrary_kernel_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = OwnedGuestControl(temporary)
            guest.execute("prepare"); guest.execute("add")
            guest.rules["iptables"].insert(0, guest.owned)
            with self.assertRaisesRegex(RuntimeError, "unexpected duplicate"):
                guest.execute("remove")
            self.assertEqual(guest.rules["iptables"], [guest.owned, guest.unrelated])
            self.assertEqual(sum(command[5] == "-D" for command in guest.commands), 1)


if __name__ == "__main__":
    unittest.main()
