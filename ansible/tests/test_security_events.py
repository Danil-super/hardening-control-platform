import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / "scripts/hcp-security-events.py"
spec = importlib.util.spec_from_file_location("security_events", SOURCE)
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)


class SecurityEventsTests(unittest.TestCase):
    def test_read_real_bounded_file_and_refuse_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "auth.log"
            log.write_text("earlier line\n" + "x" * 100 + "\nFailed password for test\n")
            with patch.object(events, "MAX_BYTES", 50):
                evidence, lines = events.tail_file(str(log))
            self.assertEqual(evidence["state"], "observed")
            self.assertTrue(evidence["windowTruncated"])
            self.assertEqual(lines, ["Failed password for test"])
            os.mkfifo(str(root / "fifo"))
            self.assertEqual(events.tail_file(str(root / "fifo"))[0]["error"], "not_a_regular_file")
            self.assertEqual(events.tail_file(str(root / "missing"))[0]["error"], "missing")

    def test_missing_logs_and_permission_denial_are_not_clean_evidence(self):
        with patch.object(events, "tail_file", return_value=({"state": "unavailable", "error": "missing"}, [])), \
                patch.object(events.shutil, "which", return_value=None), \
                patch.object(events, "command_sample", return_value=({"state": "unavailable", "exitCode": 1}, [])):
            result = events.collect_events()
        self.assertTrue(result["scanner"]["partial"])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["scanner"]["incompleteChecks"], ["authentication_logs_unavailable", "kernel_logs_unavailable"])
        self.assertIsNone(result["summary"]["score"])

    def test_journald_fallback_and_recorded_query_scope(self):
        probe = json.dumps({"__REALTIME_TIMESTAMP": "1793368800000000", "MESSAGE": "A readable journal entry"})
        entries = [json.dumps({"__REALTIME_TIMESTAMP": "1793368800000000", "SYSLOG_FACILITY": "10", "MESSAGE": message})
                   for message in ("Invalid user test", "unrelated message")]
        with patch.object(events, "tail_file", return_value=({"state": "unavailable", "error": "missing"}, [])), \
                patch.object(events.shutil, "which", return_value="/usr/bin/journalctl"), \
                patch.object(events, "command_sample", side_effect=[({"state": "observed"}, [probe]), ({"state": "observed"}, entries), ({"state": "observed"}, [])]) as query:
            result = events.collect_events()
        self.assertFalse(result["scanner"]["partial"])
        self.assertEqual(result["events"], [{"source": "auth_failed", "message": "Invalid user test"}])
        self.assertIn("--lines=1", query.call_args_list[0][0][0])
        self.assertIn("--since=-24h", query.call_args_list[1][0][0])
        self.assertIn("SYSLOG_FACILITY=10", query.call_args_list[1][0][0])
        self.assertTrue(any(row.get("path") == "journald:auth,authpriv;last24h" for row in result["scanner"]["sourceCoverage"]))

    def test_empty_success_without_a_readable_journal_does_not_claim_coverage(self):
        with patch.object(events, "tail_file", return_value=({"state": "unavailable", "error": "missing"}, [])), \
                patch.object(events.shutil, "which", return_value="/usr/bin/journalctl"), \
                patch.object(events, "command_sample", return_value=({"state": "observed"}, [])) as query:
            result = events.collect_events()
        self.assertTrue(result["scanner"]["partial"])
        self.assertIn("authentication_logs_unavailable", result["scanner"]["incompleteChecks"])
        journal = next(row for row in result["scanner"]["sourceCoverage"] if row.get("path", "").startswith("journald:"))
        self.assertEqual(journal["error"], "readable_journal_unverified")
        self.assertFalse(journal["journalReadable"])
        self.assertEqual(len(query.call_args_list), 2, "Only the probe and kernel sample should run")

    def test_empty_auth_window_is_accepted_only_after_a_valid_journal_probe(self):
        probe = json.dumps({"__REALTIME_TIMESTAMP": "1793368800000000", "MESSAGE": "Readable boot entry"})
        with patch.object(events, "command_sample", side_effect=[({"state": "observed"}, [probe]), ({"state": "observed"}, [])]):
            evidence, lines = events.auth_journal_sample("journalctl")
        self.assertEqual(evidence["state"], "observed")
        self.assertTrue(evidence["journalReadable"])
        self.assertEqual(lines, [])

    def test_malformed_auth_journal_preserves_observed_matches_and_uncertainty(self):
        probe = json.dumps({"__REALTIME_TIMESTAMP": "1793368800000000"})
        valid = json.dumps({"__REALTIME_TIMESTAMP": "1793368800000000000", "SYSLOG_FACILITY": "4", "MESSAGE": "Failed password for test"})
        with patch.object(events, "command_sample", side_effect=[({"state": "observed"}, [probe]), ({"state": "observed"}, [valid, "malformed"])]):
            evidence, lines = events.auth_journal_sample("journalctl")
        self.assertEqual(evidence["state"], "unavailable")
        self.assertEqual(evidence["error"], "invalid_journal_records")
        self.assertEqual(lines, ["Failed password for test"])

    def test_generic_syslog_fallback_finds_events_but_never_assumes_auth_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "messages"
            log.write_text("sshd: Failed password for test\nnormal boot message\n")
            with patch.object(events, "AUTH_FILES", ()), patch.object(events, "GENERIC_AUTH_FILES", (str(log),)), \
                    patch.object(events, "OPTIONAL_FILES", {}), patch.object(events.shutil, "which", return_value=None), \
                    patch.object(events, "command_sample", return_value=({"state": "observed"}, [])):
                result = events.collect_events()
                log.write_text("")
                empty = events.collect_events()
        self.assertEqual(result["events"], [{"source": "auth_failed", "message": "sshd: Failed password for test"}])
        for report in (result, empty):
            self.assertTrue(report["scanner"]["partial"])
            self.assertIn("authentication_log_routing_unverified", report["scanner"]["incompleteChecks"])
            row = report["scanner"]["sourceCoverage"][0]
            self.assertFalse(row["authRoutingVerified"])
            self.assertEqual(row["scope"], "generic_syslog_pattern_sample")
        self.assertEqual(empty["summary"]["total"], 0)

    def test_generic_source_read_error_remains_partial_even_with_other_auth_evidence(self):
        def read(path):
            if path == events.GENERIC_AUTH_FILES[0]:
                return {"state": "observed"}, ["Invalid user test"]
            return {"state": "unavailable", "error": "unreadable" if path == events.GENERIC_AUTH_FILES[1] else "missing"}, []
        with patch.object(events, "tail_file", side_effect=read), patch.object(events.shutil, "which", return_value=None), \
                patch.object(events, "command_sample", return_value=({"state": "observed"}, [])):
            result = events.collect_events()
        self.assertTrue(result["scanner"]["partial"])
        self.assertIn("log_source_unreadable", result["scanner"]["incompleteChecks"])
        self.assertEqual(result["events"], [{"source": "auth_failed", "message": "Invalid user test"}])

    def test_readable_empty_auth_log_does_not_require_journald(self):
        def read(path):
            return ({"state": "observed"}, []) if path == events.AUTH_FILES[0] else ({"state": "unavailable", "error": "missing"}, [])
        with patch.object(events, "tail_file", side_effect=read), patch.object(events.shutil, "which") as which, \
                patch.object(events, "command_sample", return_value=({"state": "observed"}, [])):
            result = events.collect_events()
        which.assert_not_called()
        self.assertFalse(result["scanner"]["partial"])
        self.assertEqual(result["summary"]["total"], 0)
        self.assertIn("No all-history", result["scanner"]["scope"])

    def test_per_source_match_limit_is_reported_even_inside_the_read_window(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            log.write_text("".join("Failed password for user{}\n".format(index) for index in range(100)))
            with patch.object(events, "AUTH_FILES", (str(log),)), patch.object(events, "OPTIONAL_FILES", {}), \
                    patch.object(events, "command_sample", return_value=({"state": "observed"}, [])):
                result = events.collect_events()
        self.assertEqual(result["summary"]["total"], 30)
        self.assertEqual(result["summary"]["sampledMatches"], 100)
        self.assertTrue(result["scanner"]["eventsTruncated"])
        source = result["scanner"]["sourceCoverage"][0]
        self.assertFalse(source["windowTruncated"])
        self.assertEqual(source["matchedLines"], 100)
        self.assertTrue(source["eventsTruncated"])

    def test_real_command_capture_timeout_and_error_are_explicit(self):
        evidence, lines = events.command_sample(["/bin/sh", "-c", "printf 'denied\\n'"])
        self.assertEqual((evidence["state"], lines), ("observed", ["denied"]))
        self.assertEqual(events.command_sample(["/bin/sh", "-c", "exit 2"])[0]["exitCode"], 2)
        evidence, lines = events.command_sample([sys.executable, "-c", "import sys; sys.stdout.write('denied\\n'); sys.stderr.write('source incomplete\\n')"])
        self.assertEqual(evidence["state"], "unavailable")
        self.assertEqual(evidence["error"], "command_stderr")
        self.assertEqual(lines, ["denied"])
        with patch.object(events.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 12)):
            self.assertEqual(events.command_sample(["dmesg"])[0]["error"], "timeout")

    def test_python35_syntax(self):
        ast.parse(SOURCE.read_text(), feature_version=(3, 5))


if __name__ == "__main__":
    unittest.main()
