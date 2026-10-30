#!/usr/bin/env python3
"""Bounded read-only event samples, with explicit source coverage (Python 3.5+)."""
from datetime import datetime, timezone
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile

MAX_BYTES = 256 * 1024
MAX_LINES = 1000
MAX_EVENTS_PER_SOURCE = 30
AUTH_FILES = ("/var/log/auth.log", "/var/log/secure", "/var/log/authlog")
GENERIC_AUTH_FILES = ("/var/log/messages", "/var/log/syslog")
OPTIONAL_FILES = {
    "ufw_denied": (("/var/log/ufw.log", "/var/log/syslog", "/var/log/messages"), r"UFW (?:BLOCK|DENY)"),
    "suricata_fast": (("/var/log/suricata/fast.log",), None),
    "suricata_eve": (("/var/log/suricata/eve.json",), r'"event_type"\s*:\s*"(?:alert|drop)"'),
}
AUTH_PATTERN = r"failed password|authentication failure|invalid user"
KERNEL_PATTERN = r"denied|blocked|martian|syn flood"


def tail_file(path):
    result = {"path": path, "state": "unavailable", "windowTruncated": False}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                result["error"] = "not_a_regular_file"
                return result, []
            offset = max(0, metadata.st_size - MAX_BYTES)
            source.seek(offset)
            data = source.read(MAX_BYTES)
            if offset:
                data = data.split(b"\n", 1)[1] if b"\n" in data else b""
            lines = data.decode("utf-8", "replace").splitlines()
            result.update(state="observed", windowTruncated=offset > 0 or len(lines) > MAX_LINES)
            return result, lines[-MAX_LINES:]
    except FileNotFoundError:
        result["error"] = "missing"
    except OSError:
        result["error"] = "unreadable"
    return result, []


def command_sample(argv):
    # File-backed capture bounds memory; journalctl itself is limited by count
    # and time, and dmesg reads the finite kernel ring buffer.
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            completed = subprocess.run(argv, stdout=output, stderr=errors, timeout=12,
                                       env=dict(os.environ, LC_ALL="C"))
            length = output.tell()
            output.seek(max(0, length - MAX_BYTES))
            data = output.read(MAX_BYTES).decode("utf-8", "replace")
            reported_error = errors.tell() > 0
        if completed.returncode != 0:
            return {"state": "unavailable", "exitCode": completed.returncode, "error": "command_failed"}, []
        lines = data.splitlines()
        if reported_error:
            # Keep usable observations, but a successful exit with diagnostics
            # does not establish complete access to a log source.
            return {"state": "unavailable", "error": "command_stderr", "windowTruncated": length > MAX_BYTES or len(lines) > MAX_LINES}, lines[-MAX_LINES:]
        return {"state": "observed", "windowTruncated": length > MAX_BYTES or len(lines) > MAX_LINES}, lines[-MAX_LINES:]
    except subprocess.TimeoutExpired:
        return {"state": "unavailable", "error": "timeout"}, []
    except OSError:
        return {"state": "unavailable", "error": "command_unavailable"}, []


def auth_journal_sample(journal):
    # journalctl exits 0 with no output when no journal files exist. Establish
    # a readable journal with an actual record before accepting an empty query.
    probe, records = command_sample([journal, "--no-pager", "--output=json", "--lines=1"])
    try:
        entry = json.loads(records[0]) if len(records) == 1 else None
        readable = (probe["state"] == "observed" and isinstance(entry, dict)
                    and str(entry.get("__REALTIME_TIMESTAMP", "")).isdigit())
    except (ValueError, TypeError):
        readable = False
    if not readable:
        return {"state": "unavailable", "error": "readable_journal_unverified", "journalReadable": False}, []
    evidence, records = command_sample([journal, "--no-pager", "--output=json", "--since=-24h", "--lines=" + str(MAX_LINES),
                                        "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"])
    evidence["journalReadable"] = True
    messages = []
    for raw in records:
        try:
            entry = json.loads(raw)
            if (not isinstance(entry, dict) or not isinstance(entry.get("MESSAGE"), str)
                    or not str(entry.get("__REALTIME_TIMESTAMP", "")).isdigit()
                    or str(entry.get("SYSLOG_FACILITY", "")) not in ("4", "10")):
                raise ValueError("unrecognised auth journal record")
            messages.append(entry["MESSAGE"])
        except (ValueError, TypeError):
            evidence.update(state="unavailable", error="invalid_journal_records")
    return evidence, messages


def collect_events():
    events, sources = [], []
    sampled_matches = 0

    def add(name, lines, pattern):
        nonlocal sampled_matches
        selected = [line for line in lines if line.strip() and (pattern is None or re.search(pattern, line, re.I))]
        sampled_matches += len(selected)
        sources[-1].update(matchedLines=len(selected), emittedMatches=min(len(selected), MAX_EVENTS_PER_SOURCE),
                           eventsTruncated=len(selected) > MAX_EVENTS_PER_SOURCE)
        events.extend({"source": name, "message": line[:500]} for line in selected[-MAX_EVENTS_PER_SOURCE:])

    auth_available = False
    for path in AUTH_FILES:
        evidence, lines = tail_file(path)
        sources.append(dict(evidence, source="auth_failed"))
        auth_available = auth_available or evidence["state"] == "observed"
        add("auth_failed", lines, AUTH_PATTERN)
    generic_auth_observed = False
    if not auth_available:
        # Common on BusyBox/OpenRC hosts. Message patterns remain useful, but a
        # generic syslog file (including an empty one) does not prove where all
        # authentication messages are routed.
        for path in GENERIC_AUTH_FILES:
            evidence, lines = tail_file(path)
            sources.append(dict(evidence, source="auth_failed", authRoutingVerified=False,
                                scope="generic_syslog_pattern_sample", limitation="authentication_routing_unverified"))
            generic_auth_observed = generic_auth_observed or evidence["state"] == "observed"
            add("auth_failed", lines, AUTH_PATTERN)
        journal = shutil.which("journalctl")
        evidence, lines = auth_journal_sample(journal) if journal else ({"state": "unavailable", "error": "command_unavailable"}, [])
        sources.append(dict(evidence, source="auth_failed", path="journald:auth,authpriv;last24h"))
        auth_available = evidence["state"] == "observed"
        add("auth_failed", lines, AUTH_PATTERN)
    for name, (paths, pattern) in OPTIONAL_FILES.items():
        for path in paths:
            evidence, lines = tail_file(path)
            sources.append(dict(evidence, source=name, optional=True))
            add(name, lines, pattern)
    kernel, lines = command_sample(["dmesg"])
    sources.append(dict(kernel, source="kernel_network", path="kernel-ring-buffer"))
    add("kernel_network", lines, KERNEL_PATTERN)
    # Missing optional IDS/firewall logs describe absent evidence. An I/O
    # failure of an existing log still makes the result incomplete.
    incomplete = [] if auth_available else ["authentication_log_routing_unverified" if generic_auth_observed else "authentication_logs_unavailable"]
    if kernel["state"] != "observed":
        incomplete.append("kernel_logs_unavailable")
    if any(row.get("error") in ("unreadable", "not_a_regular_file") for row in sources):
        incomplete.append("log_source_unreadable")
    # Preserve ordering, remove duplicate lines from overlapping file sources.
    unique, seen = [], set()
    for event in events:
        key = (event["source"], event["message"])
        if key not in seen:
            unique.append(event)
            seen.add(key)
    limited = unique[:120]
    return {
        "schemaVersion": 1, "action": "collectEvents", "runId": os.environ.get("REPORT_RUN_ID"),
        "inventoryHost": os.environ.get("INVENTORY_HOST"), "createdAt": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(), "mode": "events",
        "scanner": {"source": "host-events", "partial": bool(incomplete), "incompleteChecks": incomplete,
                    "sourceCoverage": sources, "scope": "Last 256 KiB / 1000 lines per file; generic messages/syslog fallback is pattern-only with unverified authentication routing; auth/authpriv journald fallback last 24h / 1000 entries after a readable-journal probe; kernel ring buffer; at most 30 matching lines per source and 120 deduplicated events. No all-history or incident-absence claim.",
                    "eventsTruncated": len(unique) > len(limited) or any(row.get("eventsTruncated") for row in sources)},
        "summary": {"total": len(limited), "sampledMatches": sampled_matches, "sampledMatchesScope": "Matching lines before per-source caps and cross-source deduplication", "score": None,
                    "severity": "high" if any(event["source"].startswith("suricata") for event in limited) else "medium" if limited else "info",
                    "sources": sorted(set(event["source"] for event in limited))},
        "events": limited,
    }


if __name__ == "__main__":
    print(json.dumps(collect_events(), ensure_ascii=True))
