#!/usr/bin/env python3
"""Owned Debian/Ubuntu KVM guests: native collectors, honest reports and UFW.

Only disposable guests receive firewall/service changes. Image bytes, launch
ownership, SSH identity, command output and execution time are bounded. This
proves the pinned images and declared controls, not universal Linux support.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid

# Deliberately reuse only this pure, already tested canonicalization routine.
# The RPM launcher/commands are never invoked; UFW has its own strict preflight.
from linux_rpm_vm_integration import semantic_nftables

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-deb-ci"
PORT = 8088
MODEL = "new_non_loopback_non_dnat_tcp_udp"
VERSIONS = {"debian": "12", "ubuntu": "24.04"}
MANIFEST = ROOT / "deployment/tests/fixtures/linux-deb-images.json"
DPKG_FORMAT = "${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Maintainer}\t${Origin}\n"
INPUTS = {("ip", "filter", "INPUT"), ("ip6", "filter", "INPUT")}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")
    path.chmod(0o600)


def stop_owned_process(process):
    """Stop only a process group created by this controller."""
    # The group may still contain children after its leader exits. In
    # particular a child retaining stdout must not escape a command timeout.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def run(argv, output=None, timeout=120, accepted=(0,), env=None, max_bytes=16 * 1024 * 1024):
    """Drain bounded output while the command runs; timeouts kill owned children."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, start_new_session=True, cwd=str(ROOT), env=env)
    captured, deadline = bytearray(), time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Command exceeded its time limit: " + Path(argv[0]).name)
            for key, unused in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(captured) + len(chunk) > max_bytes:
                    captured.extend(chunk[:max_bytes - len(captured)])
                    raise RuntimeError("Command exceeded its output limit: " + Path(argv[0]).name)
                captured.extend(chunk)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        selector.close()
        stop_owned_process(process)
        process.stdout.close()
        if output:
            output.write_text(captured.decode("utf-8", "replace"))
            output.chmod(0o600)
    result = subprocess.CompletedProcess(argv, process.returncode, captured.decode("utf-8", "replace"))
    if result.returncode not in accepted:
        detail = result.stdout if len(result.stdout) <= 6000 else result.stdout[:2000] + "\n[bounded excerpt]\n" + result.stdout[-4000:]
        raise RuntimeError("Command failed (exit {}): {}\n{}".format(result.returncode, Path(argv[0]).name, detail))
    return result


def image_source(distribution, manifest_path=MANIFEST):
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schemaVersion") != 1 or distribution not in VERSIONS:
        raise ValueError("Unsupported native image manifest/distribution")
    source = manifest.get("images", {}).get(distribution, {})
    url = urllib.parse.urlsplit(source.get("url", ""))
    expected_host = "cloud.debian.org" if distribution == "debian" else "cloud-images.ubuntu.com"
    publisher = source.get("publisherChecksum", {})
    algorithm, checksum = publisher.get("algorithm"), publisher.get("value", "")
    dated = (r"/images/cloud/bookworm/(\d{8}-\d+)/debian-12-genericcloud-amd64-\1\.qcow2"
             if distribution == "debian" else r"/releases/noble/release-(\d{8}(?:\.\d+)?)/ubuntu-24\.04-server-cloudimg-amd64\.img")
    build = re.fullmatch(dated, url.path)
    checksum_url = urllib.parse.urlsplit(source.get("checksumUrl", ""))
    if (url.scheme != "https" or url.hostname != expected_host or url.username or url.password or url.query or url.fragment
            or not build or build.group(1) != source.get("build")
            or checksum_url.scheme != "https" or checksum_url.netloc != url.netloc or checksum_url.query or checksum_url.fragment
            or checksum_url.path.rsplit("/", 1)[0] != url.path.rsplit("/", 1)[0]
            or checksum_url.path.rsplit("/", 1)[-1] != ("SHA512SUMS" if distribution == "debian" else "SHA256SUMS")
            or source.get("expectedOsId") != distribution or source.get("expectedVersionId") != VERSIONS[distribution]
            or source.get("architecture") != "x86_64" or source.get("format") != "qcow2"
            or type(source.get("bytes")) is not int or not 1 <= source["bytes"] <= 2 * 1024**3
            or not re.fullmatch(r"[a-f0-9]{64}", source.get("sha256", ""))
            or algorithm not in ("sha256", "sha512")
            or not re.fullmatch(r"[a-f0-9]{%d}" % (64 if algorithm == "sha256" else 128), checksum)):
        raise ValueError("Image pin, immutable publisher URL or native identity is invalid")
    if algorithm == "sha256" and checksum != source["sha256"]:
        raise ValueError("Conflicting publisher and controller SHA-256 pins")
    return source


def download_image(source, target, opener=urllib.request.urlopen, timeout=600):
    """Bound the complete HTTPS operation, including a slow-drip response.

    SIGALRM is deliberately local to the Linux controller main thread and
    interrupts socket reads even while a peer sends bytes within its idle
    timeout. Exclusive creation plus link publication never remove or replace
    a path that this download did not create.
    """
    temporary = target.with_suffix(".download")
    if os.path.lexists(target) or os.path.lexists(temporary):
        raise ValueError("Image download requires absent target and temporary paths")
    digests = {name: hashlib.new(name) for name in {"sha256", source["publisherChecksum"]["algorithm"]}}
    start, size, owned = time.monotonic(), 0, False
    def expired(_signum, _frame):
        raise TimeoutError("Image download exceeded its absolute time limit")
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        with temporary.open("xb") as stream:
            owned = True
            os.fchmod(stream.fileno(), 0o600)
            with opener(source["url"], timeout=min(30, timeout)) as response:
                if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                    raise ValueError("Image download redirected outside HTTPS")
                read = getattr(response, "read1", response.read)
                while True:
                    chunk = read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > source["bytes"] or time.monotonic() - start > timeout:
                        raise ValueError("Image download exceeded its pinned byte/time limit")
                    for digest in digests.values():
                        digest.update(chunk)
                    stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        publisher = source["publisherChecksum"]
        if (size != source["bytes"] or digests["sha256"].hexdigest() != source["sha256"]
                or digests[publisher["algorithm"]].hexdigest() != publisher["value"]):
            raise ValueError("Image bytes do not match the recorded publisher/controller pin")
        os.link(str(temporary), str(target))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, previous_timer[0] - (time.monotonic() - start)), previous_timer[1])
        if owned:
            temporary.unlink(missing_ok=True)


def verify_dpkg_inventory(report, native_output, distribution):
    coverage = report.get("packageInventory", {})
    packages = report.get("packages", [])
    if (not packages or coverage.get("manager") != "dpkg" or coverage.get("partial") is not False
            or coverage.get("error") or coverage.get("collectorVersion") != 2 or coverage.get("managerSelection") != "os-id"
            or coverage.get("packageCount") != len(packages)
            or coverage.get("osRelease", {}).get("ID") != distribution
            or coverage.get("osRelease", {}).get("VERSION_ID") != VERSIONS[distribution]):
        raise ValueError("Native dpkg inventory is missing, partial or identifies another OS release")
    expected = []
    for line in native_output.splitlines():
        fields = line.split("\t")
        if len(fields) != 8 or not re.fullmatch(r"[uihrp][ncHUFWti][ R]", fields[0]):
            raise ValueError("Malformed independent dpkg-query observation")
        # Not-installed/config-only records are not installed software. Keep
        # holds and every other observed package state exactly as collected.
        if fields[0][1] in "nc" and fields[0][2] == " ":
            continue
        if not all(fields[1:6]):
            raise ValueError("Independent dpkg metadata lacks binary/source identity")
        expected.append(tuple(fields))
    observed = []
    for item in packages:
        if item.get("manager") != "dpkg" or item.get("sourceEpochKnown") is not True:
            raise ValueError("Native DEB source epoch/manager was not preserved")
        observed.append(tuple(item.get(key, "") for key in
                              ("dpkgStatus", "name", "version", "arch", "sourceName", "sourceVersion", "maintainer", "origin")))
    if Counter(observed) != Counter(expected) or len(set(expected)) != len(expected):
        raise ValueError("Production dpkg inventory differs from independent native status/binary/source/supplier records")
    return {"records": len(packages), "manager": "dpkg", "allEightNativeFieldsEqual": True,
            "partial": coverage["partial"], "sourceEpochPreserved": True}


def validate_ufw_ruleset(ruleset):
    """Account for every INPUT base chain before any temporary kernel mutation."""
    if not isinstance(ruleset, dict) or set(ruleset) != {"nftables"} or not isinstance(ruleset["nftables"], list):
        raise ValueError("Invalid native nft envelope")
    tables, chains, rules = {}, {}, []
    for entry in ruleset["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError("Unknown native nft object")
        kind, value = next(iter(entry.items()))
        if kind not in ("metainfo", "table", "chain", "rule") or not isinstance(value, dict):
            raise ValueError("Unsupported native UFW nft layout: " + kind)
        if kind == "table":
            key = (value.get("family"), value.get("name"))
            if key in tables or value.get("flags", []) != []:
                raise ValueError("UFW table ownership/flags are outside the controlled fixture")
            tables[key] = value
        elif kind == "chain":
            key = (value.get("family"), value.get("table"), value.get("name"))
            if key in chains or value.get("flags"):
                raise ValueError("Duplicate or flagged native nft chain")
            chains[key] = value
        elif kind == "rule":
            if not isinstance(value.get("expr"), list) or not all(isinstance(item, dict) for item in value["expr"]):
                raise ValueError("Invalid native rule expressions")
            rules.append(value)
    inputs = []
    for key, chain in chains.items():
        if not all(isinstance(part, str) and part for part in key) or key[:2] not in tables:
            raise ValueError("Native chain has no known table identity")
        if chain.get("hook") == "input":
            if (key not in INPUTS or chain.get("type") != "filter" or chain.get("policy") != "drop"
                    or type(chain.get("prio")) is not int):
                raise ValueError("Unexpected INPUT chain, policy, type or priority")
            inputs.append(key)
    if set(inputs) != INPUTS or len(inputs) != 2:
        raise ValueError("Both native IPv4/IPv6 UFW INPUT filter chains are required")
    for rule in rules:
        if (rule.get("family"), rule.get("table"), rule.get("chain")) not in chains:
            raise ValueError("Native rule belongs to an unobserved chain")
    return ["/".join(value) for value in sorted(inputs)]


def verify_allow_delta(baseline, allowed, token, baseline_runtime, allowed_runtime):
    """Bind the hidden xt_comment text through an exact native -S delta.

    iptables-nft can store the comment in an opaque xt match instead of nft
    rule metadata. Require both representations to identify the same two first
    INPUT rules; neither a comment-shaped expression nor a token alone owns it.
    """
    if not isinstance(token, str) or not re.fullmatch(r"hcp-deb-input-[a-f0-9]{32}", token):
        raise ValueError("Invalid owned INPUT control token")
    expected = ["-A", "INPUT", "-m", "comment", "--comment", token, "-j", "ACCEPT"]
    for key in ("ipv4", "ipv6"):
        before_output, after_output = baseline_runtime.get(key), allowed_runtime.get(key)
        if (not isinstance(before_output, str) or not isinstance(after_output, str)
                or not before_output or not after_output or token in before_output):
            raise ValueError("Missing decoded INPUT evidence or pre-existing control token")
        before_lines, after_lines = before_output.splitlines(keepends=True), after_output.splitlines(keepends=True)
        parsed = [shlex.split(line) for line in after_lines]
        if any(not words or words[0] not in ("-P", "-N", "-A") for words in parsed):
            raise ValueError("Unexpected native -S output in owned INPUT evidence")
        tagged = [index for index, line in enumerate(after_lines) if token in line]
        first = next((index for index, words in enumerate(parsed) if words[:2] == ["-A", "INPUT"]), None)
        if len(tagged) != 1 or tagged[0] != first or parsed[tagged[0]] != expected:
            raise ValueError("Expected one exact, uniquely tagged first INPUT accept per family")
        if before_lines != after_lines[:first] + after_lines[first + 1:]:
            raise ValueError("Temporary control changed unrelated decoded kernel rules")

    before, after = semantic_nftables(baseline), semantic_nftables(allowed)
    if any(entry.get("rule", {}).get("comment") == token for entry in before["nftables"]):
        raise ValueError("Control token already belongs to native rule metadata")
    owned = set()
    counter, accept = {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}
    for family, table, chain in sorted(INPUTS):
        index = next((index for index, entry in enumerate(after["nftables"])
                      if (entry.get("rule", {}).get("family"), entry.get("rule", {}).get("table"),
                          entry.get("rule", {}).get("chain")) == (family, table, chain)), None)
        if index is None:
            raise ValueError("Owned rules do not cover both observed INPUT chains")
        rule = after["nftables"][index]["rule"]
        metadata = "comment" in rule
        fields = {"family", "table", "chain", "expr"} | ({"comment"} if metadata else set())
        expressions = [counter, accept] if metadata else [{"xt": {"type": "match", "name": "comment"}}, counter, accept]
        if set(rule) != fields or (metadata and rule["comment"] != token) or rule["expr"] != expressions:
            raise ValueError("First owned INPUT rule contains unexpected metadata, conditions or actions")
        owned.add(index)
    if len(owned) != 2:
        raise ValueError("Expected exactly two correlated owned kernel rules")
    after["nftables"] = [entry for index, entry in enumerate(after["nftables"]) if index not in owned]
    if before != after:
        raise ValueError("Temporary control changed unrelated kernel semantics")


def redact_public_log(value):
    value = re.sub(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
                   "[private key redacted]", value, flags=re.S)
    return re.sub(r'''(?i)(machine[ _-]?id["']?\s*[:=]\s*["']?)[a-f0-9]{32}''', r"\1[redacted]", value)


def sanitize_public_error(error, private_machine_id=None):
    value = redact_public_log(str(error))
    if private_machine_id:
        value = re.sub(re.escape(private_machine_id), "[private machine identity]", value, flags=re.I)
    return {"type": type(error).__name__, "message": value[-6000:]}


UFW_SNAPSHOT = r'''
import hashlib, importlib.util, json, os, stat, subprocess, sys
from pathlib import Path
def query(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                            universal_newlines=True, env=dict(os.environ, LC_ALL="C"))
    if result.returncode or len(result.stdout.encode()) > 4 * 1024 * 1024:
        raise RuntimeError("Native snapshot command failed/oversized: " + repr(argv) + result.stderr[-1500:])
    return result.stdout
def optional(path):
    try: return Path(path).read_text().strip()
    except FileNotFoundError: return None
spec = importlib.util.spec_from_file_location("owned_ufw_snapshot", sys.argv[1])
fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)
default = Path("/etc/default/ufw"); details = default.lstat()
if not stat.S_ISREG(details.st_mode): raise RuntimeError("Unexpected default UFW file")
status = query(["ufw", "status", "numbered"])
if status.splitlines()[0].strip() != "Status: active": raise RuntimeError("UFW is not active")
versions = {name: query([name, "--version"]).strip() for name in ("iptables", "ip6tables", "ufw", "nft")}
if not all("(nf_tables)" in versions[name] for name in ("iptables", "ip6tables")): raise RuntimeError("Native nf_tables frontends are required")
print(json.dumps({"nftables": query(["nft", "--json", "list", "ruleset"]), "state": {
    "manifest": fw.tree_digest(Path("/etc/ufw")),
    "defaultUfw": {"sha256": hashlib.sha256(default.read_bytes()).hexdigest(), "mode": stat.S_IMODE(details.st_mode),
       "uid": details.st_uid, "gid": details.st_gid,
       "xattrs": {name: os.getxattr(str(default), name, follow_symlinks=False).hex() for name in os.listxattr(str(default), follow_symlinks=False)}},
    "runtime": {"ufw": status, "ipv4": query(["iptables", "-S"]), "ipv6": query(["ip6tables", "-S"])},
    "versions": versions, "pid1": Path("/proc/1/comm").read_text().strip(),
    "securityModules": {"selinuxEnforce": optional("/sys/fs/selinux/enforce"),
                        "apparmorEnabled": optional("/sys/module/apparmor/parameters/enabled")}}}))
'''

UFW_INPUT_CONTROL = r'''
import fcntl, json, os, re, stat, subprocess, sys, time
from pathlib import Path
action, marker_path, token = sys.argv[1:]
if (action not in ("prepare", "add", "remove") or os.geteuid() != 0
        or not re.fullmatch(r"hcp-deb-input-[a-f0-9]{32}", token) or marker_path != "/run/" + token):
    raise RuntimeError("Invalid owned UFW control identity")
marker = Path(marker_path)
identity = {"schemaVersion": 1, "token": token, "binaries": ["iptables", "ip6tables"], "table": "filter", "chain": "INPUT"}
rule = ["-m", "comment", "--comment", token, "-j", "ACCEPT"]
def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
def store(state, first=False):
    plan = dict(identity, state=state)
    target = marker / ("plan.json" if first else "next.json")
    with target.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600); json.dump(plan, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    if not first: target.replace(marker / "plan.json")
    fsync_dir(marker)
def validated_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise RuntimeError("Unsafe owned UFW control file")
def read_plan():
    info = marker.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("Unsafe owned UFW control directory")
    validated_file(marker / "plan.json"); validated_file(marker / "lock")
    plan = json.loads((marker / "plan.json").read_text())
    state = plan.pop("state", None)
    if plan != identity or state not in ("prepared", "installing", "active", "closed", "unused"):
        raise RuntimeError("Owned UFW control plan could not be verified")
    return state
def command(binary, args, accepted=(0,)):
    result = subprocess.run([binary, "-w", "5", "-t", "filter"] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
    if result.returncode not in accepted: raise RuntimeError("Owned kernel control failed: " + result.stderr[-2000:])
    return result
def present(binary): return command(binary, ["-C", "INPUT"] + rule, (0, 1)).returncode == 0
if action == "prepare":
    # Preparation is acknowledged separately before the caller can start an
    # add. A lost prepare reply therefore cannot race a future mutation.
    marker.mkdir(mode=0o700)
    with (marker / "lock").open("x") as stream:
        os.fchmod(stream.fileno(), 0o600); os.fsync(stream.fileno())
    store("prepared", first=True); fsync_dir(marker.parent)
    print(json.dumps({"owned": True, "prepared": True, "installedRules": 0}))
elif action == "remove" and not marker.exists():
    print(json.dumps({"owned": False, "removedRules": 0, "reason": "add-not-started"}))
else:
    read_plan()
    with (marker / "lock").open("r+") as lock:
        deadline = time.monotonic() + 210
        while True:
            try: fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic() >= deadline: raise RuntimeError("Owned UFW operation did not become quiescent")
                time.sleep(0.1)
        state = read_plan()
        if action == "add":
            if state != "prepared": raise RuntimeError("Late/repeated add after mutation or cleanup is forbidden")
            if Path("/proc/1/comm").read_text().strip() != "systemd": raise RuntimeError("Expected native systemd guest")
            for binary in identity["binaries"]:
                version = subprocess.check_output([binary, "--version"], universal_newlines=True, timeout=10)
                if "(nf_tables)" not in version or present(binary): raise RuntimeError("Unexpected backend or preexisting control rule")
                if token in command(binary, ["-S", "INPUT"]).stdout: raise RuntimeError("Control comment is already in use")
            store("installing")
            for binary in identity["binaries"]:
                command(binary, ["-I", "INPUT", "1"] + rule)
                if not present(binary): raise RuntimeError("Owned accept was not observed after insert")
            store("active")
            print(json.dumps({"owned": True, "installedRules": 2, "permanent": False}))
        else:
            # Keep a closed tombstone until the owned VM is destroyed. Any add
            # delayed by a lost SSH reply must fail after this lock is released.
            removed = 0
            if state in ("prepared", "unused"):
                store("unused")
                # A failed absence precondition does not authorize deletion of
                # a pre-existing rule, even one with this unlikely token.
                if any(present(binary) for binary in identity["binaries"]):
                    raise RuntimeError("Pre-existing control-shaped rule is not owned and was preserved")
            else:
                store("closed")
                for binary in identity["binaries"]:
                    if present(binary): command(binary, ["-D", "INPUT"] + rule); removed += 1
                    if present(binary): raise RuntimeError("An unexpected duplicate owned accept remains")
            print(json.dumps({"owned": True, "removedRules": removed, "present": False, "markerClosed": True}))
'''


def semantic_digest(ruleset):
    return hashlib.sha256(json.dumps(semantic_nftables(ruleset), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def snapshot_ufw(remote_python, guest_source, artifacts, label):
    observed = json.loads(remote_python(UFW_SNAPSHOT, (guest_source,)).stdout)
    raw, state = observed["nftables"], observed["state"]
    nft_file = artifacts / (label + ".nft.json")
    nft_file.write_text(raw); nft_file.chmod(0o600)
    write_json(artifacts / (label + ".state.json"), state)
    # Persist the actual observation before interpreting its supported shape.
    ruleset = json.loads(raw)
    inputs = validate_ufw_ruleset(ruleset)
    if state.get("pid1") != "systemd":
        raise RuntimeError("UFW snapshot no longer observes native systemd")
    return ruleset, state, {"nftFile": nft_file.name, "nftSha256": hashlib.sha256(raw.encode()).hexdigest(),
                            "semanticSha256": semantic_digest(ruleset), "inputChains": inputs}


def read_audit(artifacts, phase, finding_id, expected):
    path = artifacts / "reports" / (HOST + "-basic_linux-" + phase + ".json")
    raw = path.read_bytes(); report = json.loads(raw)
    findings = [item for item in report["findings"] if item.get("id") == finding_id]
    if len(findings) != 1 or findings[0].get("status") != expected:
        actual = findings[0].get("status") if len(findings) == 1 else "missing/duplicate"
        raise RuntimeError("{}: native {} must be {}, observed {} (raw report retained)".format(phase, finding_id, expected, actual))
    scanner, agentless = report.get("scanner", {}), report.get("agentless", {})
    if (type(scanner.get("partial")) is not bool or not isinstance(scanner.get("incompleteChecks"), list)
            or finding_id in scanner["incompleteChecks"] or (scanner["incompleteChecks"] and not scanner["partial"])
            or (scanner["partial"] and report.get("summary", {}).get("score") is not None)):
        raise RuntimeError("Native audit coverage/score contradicts the controlled observation")
    if agentless.get("serviceManager") != "systemd" or not agentless.get("serviceManagerEvidence"):
        raise RuntimeError("Native audit omitted observed systemd evidence")
    if not any(item.get("service") in ("ssh", "sshd") and item.get("state") == "active"
               for item in agentless.get("serviceObservations", [])):
        raise RuntimeError("Native audit did not observe the active SSH service")
    detail = {"phase": phase, "file": str(path.relative_to(artifacts)), "sha256": hashlib.sha256(raw).hexdigest(),
              "findingId": finding_id, "status": expected, "findingCount": len(report["findings"]),
              "partial": scanner["partial"], "incompleteChecks": scanner["incompleteChecks"],
              "score": report.get("summary", {}).get("score")}
    return report, findings[0], detail


def verify_system_controls(remote, playbook, checkpoint, artifacts):
    control = "/var/tmp/hcp-deb-sticky-" + uuid.uuid4().hex
    remote("sudo -n mkdir -m 1777 " + shlex.quote(control))
    proof = {"status": "running", "service": "cron", "phases": [], "restored": False}
    try:
        for phase, mode, service in (("baseline", "1777", "active"), ("violated", "0777", "inactive"), ("restored", "1777", "active")):
            operation = "start" if service == "active" else "stop"
            remote("sudo -n chmod " + mode + " " + shlex.quote(control) + " && sudo -n systemctl " + operation + " cron.service")
            observed = remote("systemctl is-active cron.service", accepted=(0, 3)).stdout.strip()
            if observed != service:
                raise RuntimeError("Native cron state did not follow the controlled transition")
            playbook("agentless-audit", phase, {"audit_profile": "basic_linux"})
            report, finding, detail = read_audit(artifacts, phase, "world_writable_dirs", "failed" if mode == "0777" else "passed")
            if mode == "0777" and control not in finding.get("evidence", ""):
                raise RuntimeError("Sticky-bit finding omitted its actual controlled directory")
            observations = [item for item in report["agentless"].get("serviceObservations", []) if item.get("service") == "cron"]
            review = [item for item in report["findings"] if item.get("id") == "critical_services_review"]
            if (len(observations) != 1 or observations[0].get("state") != service or not observations[0].get("evidence")
                    or len(review) != 1 or not re.search(r"(?:^|; )cron=" + service + r";", review[0].get("evidence", ""))):
                raise RuntimeError("Native service observation/evidence did not follow active/inactive/restored cron")
            detail["cronState"] = service; proof["phases"].append(detail)
            write_json(artifacts / "system-control-protocol.json", proof)
    finally:
        remote("sudo -n chmod 1777 " + shlex.quote(control) + " && sudo -n systemctl start cron.service && sudo -n rmdir " + shlex.quote(control))
        if remote("systemctl is-active cron.service").stdout.strip() != "active":
            raise RuntimeError("Native cron cleanup did not restore the active service")
        proof["restored"] = True
        write_json(artifacts / "system-control-protocol.json", proof)
    proof["status"] = "passed"; write_json(artifacts / "system-control-protocol.json", proof)
    checkpoint("Native sticky-bit and actual cron active/inactive/restored controls", proof)


def verify_ufw_audit(remote_python, playbook, checkpoint, artifacts, guest_source):
    token = "hcp-deb-input-" + uuid.uuid4().hex
    marker = "/run/" + token
    proof = {"status": "running", "packetModel": MODEL, "evaluation": "conditional_ruleset_path",
             "externalReachability": "unverified", "runtimeOnly": True, "managerRemainsActive": True,
             "control": "Two uniquely commented unconditional INPUT accepts through native nf_tables frontends",
             "semanticComparisonIgnores": ["nft table/chain/rule handles", "counter packet/byte values"],
             "snapshots": [], "reports": [], "exactRestoration": False}
    def save(): write_json(artifacts / "firewall-audit-protocol.json", proof)
    def snapshot(phase):
        ruleset, state, detail = snapshot_ufw(remote_python, guest_source, artifacts, "firewall-audit-" + phase)
        proof["snapshots"].append(dict(detail, phase=phase)); save()
        return ruleset, state
    def audit(phase, expected, ruleset):
        phase = "firewall-" + phase
        playbook("agentless-audit", phase, {"audit_profile": "basic_linux"})
        report, finding, detail = read_audit(artifacts, phase, "firewall_active", expected)
        evidence = finding.get("evidence", "")
        for value in ("packet_model=" + MODEL, "evaluation=conditional_ruleset_path", "external_reachability=unverified"):
            if value not in evidence: raise RuntimeError("Native firewall decision omitted its conditional scope")
        if evidence.count("filter_proofs=") != 1 or evidence.count("nftables=") != 1:
            raise RuntimeError("Native firewall evidence omitted/duplicated its proof or kernel JSON")
        proofs, unused = json.JSONDecoder().raw_decode(evidence.split("filter_proofs=", 1)[1].lstrip())
        observed, unused = json.JSONDecoder().raw_decode(evidence.split("nftables=", 1)[1].lstrip())
        if semantic_nftables(observed) != semantic_nftables(ruleset):
            raise RuntimeError("Native report changed or truncated its contemporaneous nft evidence")
        if not isinstance(proofs, dict) or not isinstance(proofs.get("nftables"), dict):
            raise RuntimeError("Native nft decision proof is malformed")
        if expected == "passed":
            witness = proofs["nftables"]
            observed_inputs = ["/".join(key) for key in sorted(INPUTS) if key[0] == witness.get("family")]
            if (witness.get("kind") != "deny_witness" or witness.get("family") not in ("ip", "ip6")
                    or witness.get("protocol") not in ("tcp", "udp") or type(witness.get("destination_port")) is not int
                    or not 1 <= witness["destination_port"] <= 65535
                    or witness.get("evaluated_input_chains") != observed_inputs
                    or not isinstance(witness.get("deny_chains"), list) or not witness["deny_chains"]
                    or any(value not in observed_inputs for value in witness["deny_chains"])):
                raise RuntimeError("Native UFW pass omitted a complete, bounded INPUT deny witness")
        detail["filterProofs"] = proofs; proof["reports"].append(detail); save()
    save()
    try:
        baseline, baseline_state = snapshot("baseline")
        audit("baseline", "passed", baseline)
        try:
            # The intention is durable before either insert. Always attempt
            # exact owned removal even if the add reply or second insert fails.
            remote_python(UFW_INPUT_CONTROL, ("prepare", marker, token), output=artifacts / "firewall-audit-prepare.json")
            remote_python(UFW_INPUT_CONTROL, ("add", marker, token), output=artifacts / "firewall-audit-add.json", timeout=450)
            allowed, allowed_state = snapshot("allow-all")
            verify_allow_delta(baseline, allowed, token, baseline_state["runtime"], allowed_state["runtime"])
            for key in ("manifest", "defaultUfw", "versions", "securityModules", "pid1"):
                if baseline_state.get(key) != allowed_state.get(key):
                    raise RuntimeError("Temporary INPUT control changed permanent configuration or security modules")
            if baseline_state["runtime"]["ufw"] != allowed_state["runtime"]["ufw"]:
                raise RuntimeError("Temporary INPUT control changed UFW manager state")
            audit("allow-all", "failed", allowed)
        finally:
            remote_python(UFW_INPUT_CONTROL, ("remove", marker, token), output=artifacts / "firewall-audit-remove.json", timeout=450)
            restored, restored_state = snapshot("restored")
            if semantic_nftables(baseline) != semantic_nftables(restored) or baseline_state != restored_state:
                raise RuntimeError("Temporary INPUT control failed exact kernel/config/runtime restoration")
            proof["exactRestoration"] = True; save()
        audit("restored", "passed", restored)
        proof["status"] = "passed"; save()
        checkpoint("Native UFW firewall_active passed/failed/passed with full kernel evidence", proof)
    except BaseException as error:
        proof["status"] = "failed"
        proof["error"] = {"type": type(error).__name__, "message": redact_public_log(str(error))[-4000:]}
        save(); raise


UFW_CRASH_ROLLBACK = r'''
import json, re, signal, subprocess, sys
from pathlib import Path
code = """
import argparse, importlib.util, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('owned_ufw_crash', sys.argv[1])
fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)
original = Path.rename
def interrupted(source, target):
    result = original(source, target)
    if source == Path('/etc/ufw'): os.kill(os.getpid(), signal.SIGKILL)
    return result
Path.rename = interrupted
fw.execute_operation(argparse.Namespace(operation='rollback', transaction=sys.argv[2], check=False, recovery_verified=False))
"""
result = subprocess.run([sys.executable, "-c", code, sys.argv[1], sys.argv[2]],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75)
if result.returncode != -signal.SIGKILL or Path("/etc/ufw").exists():
    raise RuntimeError("Owned UFW rollback did not reach the killed/missing-directory boundary")
journal = json.loads((Path("/var/lib/hcp-backups") / sys.argv[2] / "rollback-state.json").read_text())
if (journal.get("phase") != "move_old_intent" or journal.get("transactionId") != sys.argv[2]
        or not re.fullmatch(r"\.hcp-rollback-[a-f0-9]{32}", journal.get("stagingName", ""))
        or not (Path("/etc") / journal["stagingName"] / "previous").is_dir()):
    raise RuntimeError("Owned UFW rollback lost durable intent or its previous tree")
# The production journal contains raw machine identity. Publish only the
# independently checked recovery conditions, never the journal or backup.
print(json.dumps({"phase": journal["phase"], "killedBy": "SIGKILL", "exitSignal": 9,
                  "liveTreeAbsent": True, "durableIntent": True, "previousTreePresent": True,
                  "transactionMatched": True, "rawJournalPublished": False}))
'''


def verify_ufw_remediation(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port):
    token = "hcp-deb-http-" + uuid.uuid4().hex
    directory, unit = "/home/hcp-ci/" + token, token + ".service"
    proof = {"status": "running", "port": PORT, "networkProbe": "IPv4 through QEMU localhost forwarding",
             "ipv6TrafficEvaluated": False, "snapshots": [], "checks": [], "exactRestoration": False}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def save(): write_json(artifacts / "firewall-remediation-protocol.json", proof)
    def snapshot(phase):
        ruleset, state, detail = snapshot_ufw(remote_python, guest_source, artifacts, "ufw-remediation-" + phase)
        proof["snapshots"].append(dict(detail, phase=phase)); save()
        return semantic_nftables(ruleset), state
    def probe(expected):
        try:
            with opener.open("http://127.0.0.1:{}/health".format(http_port), timeout=4) as response:
                if response.status != 200 or response.read(4096).decode() != token:
                    raise RuntimeError("Native HTTP probe reached an unexpected service")
                reachable = True
        except urllib.error.HTTPError as error:
            raise RuntimeError("Native HTTP probe returned an unexpected HTTP status") from error
        except OSError:
            reachable = False
        # A blocked connection is meaningful only while the actual service
        # continues to answer locally and fresh authenticated SSH still works.
        remote("test \"$(curl --noproxy '*' --silent --fail --max-time 4 http://127.0.0.1:8088/health)\" = " + shlex.quote(token)
               + " && test \"$(cat /proc/1/comm)\" = systemd", timeout=15)
        if reachable != expected:
            raise RuntimeError("Native incoming IPv4 HTTP reachability differs from expectation: " + str(reachable))
    save()
    remote("mkdir -m 700 " + shlex.quote(directory) + " && printf %s " + shlex.quote(token) + " > " + shlex.quote(directory + "/health"))
    try:
        remote("sudo -n systemd-run --quiet --collect --unit=" + shlex.quote(unit)
               + " --uid=hcp-ci --property=Type=exec --property=NoNewPrivileges=yes --property=WorkingDirectory=" + shlex.quote(directory)
               + " /usr/bin/python3 -m http.server 8088 --bind 0.0.0.0 --directory " + shlex.quote(directory))
        for attempt in range(30):
            try: probe(True); break
            except RuntimeError:
                if attempt == 29: raise
                time.sleep(0.2)
        baseline = snapshot("baseline")
        backup_created = False
        try:
            playbook("backup-remediation", "ufw-backup")
            backup_created = True
            playbook("close-port", "ufw-reject-ssh", {"target_port": 22}, expected_error="management SSH port cannot be closed")
            playbook("close-port", "ufw-preview", check=True)
            if snapshot("after-preview") != baseline:
                raise RuntimeError("Preview or rejected SSH management request changed the firewall")
            probe(True)
            proof["checks"].extend(["verified-backup", "management-ssh-protected", "preview-unchanged"]); save()
            playbook("close-port", "ufw-apply")
            probe(False)
            applied = snapshot("applied")
            repeated = playbook("close-port", "ufw-repeat-apply")
            if not re.search(HOST + r"\s+:.*changed=0\b", repeated) or snapshot("repeated") != applied:
                raise RuntimeError("Native UFW repeated apply is not idempotent")
            remote("sudo -n ufw reload")
            probe(False)
            if snapshot("reloaded") != applied:
                raise RuntimeError("Native UFW reload did not preserve applied configuration/kernel decisions")
            proof["checks"].extend(["incoming-http-denied-local-service-live", "apply-idempotent", "deny-persists-after-reload"]); save()
            interrupted = json.loads(remote_python(UFW_CRASH_ROLLBACK, (guest_source, transaction),
                                                   output=artifacts / "ufw-interrupted-recovery.json", timeout=100).stdout)
            if interrupted.get("phase") != "move_old_intent" or interrupted.get("rawJournalPublished") is not False:
                raise RuntimeError("Native UFW crash proof is incomplete")
            probe(False)
            playbook("rollback-remediation", "ufw-rollback")
            probe(True)
            if snapshot("restored") != baseline:
                raise RuntimeError("Native UFW recovery did not restore exact kernel/config/runtime metadata")
            replay = playbook("rollback-remediation", "ufw-replay-rollback")
            if not re.search(HOST + r"\s+:.*changed=0\b", replay) or snapshot("replayed") != baseline:
                raise RuntimeError("Native UFW rollback replay changed restored state")
            proof["exactRestoration"] = True
            proof["checks"].extend(["sigkill-durable-boundary", "rollback-resumed", "incoming-http-restored", "rollback-idempotent"])
        finally:
            if backup_created and not proof["exactRestoration"]:
                # Attempt the same production recovery on every failure after
                # backup. Cleanup cannot convert a failed gate into success.
                try:
                    playbook("rollback-remediation", "ufw-failure-cleanup")
                    probe(True)
                    proof["failureCleanupRestored"] = snapshot("failure-cleanup") == baseline
                    if not proof["failureCleanupRestored"]: raise RuntimeError("UFW failure cleanup differed from baseline")
                finally: save()
        proof["status"] = "passed"; save()
        checkpoint("Native UFW preview/apply/reload/SIGKILL rollback and exact restoration", proof)
    except BaseException as error:
        proof["status"] = "failed"
        proof["error"] = {"type": type(error).__name__, "message": redact_public_log(str(error))[-4000:]}
        save(); raise
    finally:
        remote("sudo -n systemctl stop " + shlex.quote(unit) + " && rm -- " + shlex.quote(directory + "/health")
               + " && rmdir -- " + shlex.quote(directory), accepted=(0, 5), timeout=30)


GUEST_IDENTITY = r'''
import hashlib, json, platform, shlex, subprocess
from pathlib import Path
release = {}
for line in Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        release[key] = shlex.split(value)[0] if value else ""
print(json.dumps({"osRelease": release, "kernel": platform.release(), "architecture": platform.machine(),
    "pid1": Path("/proc/1/comm").read_text().strip(), "machineId": Path("/etc/machine-id").read_text().strip(),
    "bootIdSha256": hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest(),
    "virtualization": subprocess.check_output(["systemd-detect-virt", "--vm"], universal_newlines=True, timeout=10).strip(),
    "sshHostKeyFingerprint": subprocess.check_output(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"],
                                                      universal_newlines=True, timeout=10).split()[1]}))
'''


def capture_initial_kernel(remote_python, artifacts):
    observation = json.loads(remote_python(r'''
import json, os, subprocess
commands = {"nft": ["nft", "--json", "list", "ruleset"], "iptables": ["iptables", "-S"],
            "ip6tables": ["ip6tables", "-S"], "ufw": ["ufw", "status", "verbose"]}
result = {}
for name, argv in commands.items():
    value = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                           universal_newlines=True, env=dict(os.environ, LC_ALL="C"))
    if len(value.stdout.encode()) + len(value.stderr.encode()) > 8 * 1024 * 1024:
        raise RuntimeError("Initial kernel command exceeded its observation limit")
    result[name] = {"exitCode": value.returncode, "stdout": value.stdout, "stderr": value.stderr}
print(json.dumps(result))
''', timeout=150, max_bytes=40 * 1024 * 1024).stdout)
    write_json(artifacts / "initial-kernel-commands.json", observation)
    for name, result in observation.items():
        path = artifacts / ("initial-" + name + (".json" if name == "nft" else ".txt"))
        path.write_text(result["stdout"]); path.chmod(0o600)
    if any(result["exitCode"] != 0 for result in observation.values()):
        raise RuntimeError("Initial native kernel/UFW observation failed (command output retained)")


def validate_work_directory(path, runner_temp):
    work, base = path.absolute(), runner_temp.resolve()
    # An exact fresh child avoids traversing an attacker-replaced intermediate
    # directory. Commas/newlines are also unsafe in QEMU key=value arguments.
    if (work != work.resolve() or work.parent != base or os.path.lexists(work)
            or any(character in str(work) for character in (",", "\n", "\r", "\x00"))):
        raise ValueError("Require one new non-symlink private child of RUNNER_TEMP")
    return work


def check_public_artifacts(artifacts, private_machine_id):
    """A final publication gate, not a modification of native report content."""
    needle = private_machine_id.encode() if private_machine_id else None
    withheld, pending = [], [artifacts]
    while pending:
        # Path.rglob may suppress filesystem errors on Python 3.13. A subtree
        # that could not be enumerated must keep the upload gate closed.
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path, mode = Path(entry.path), entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(mode):
                    path.unlink(); withheld.append(path)
                    continue
                overlap = b""
                descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise OSError("Public artifact changed to a non-regular file")
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk: break
                        value = overlap + chunk
                        if (needle and needle in value.lower()) or re.search(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----", value):
                            # These paths are owned outputs. Withhold every
                            # leak before failing, without rewriting reports.
                            path.unlink(); withheld.append(path)
                            break
                        overlap = value[-128:]
    if withheld:
        raise RuntimeError("Withheld {} public artifacts containing private identity/key material, links or special files".format(len(withheld)))


def boot_and_verify(distribution, work, artifacts, protocol, private_context):
    source = image_source(distribution)
    reports = artifacts / "reports"; reports.mkdir(mode=0o700)
    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)
        print("PASS: " + name, flush=True)
    download_image(source, work / "source.qcow2")
    info = json.loads(run(["qemu-img", "info", "--output=json", str(work / "source.qcow2")]).stdout)
    specific = info.get("format-specific", {}).get("data", {})
    if (info.get("format") != "qcow2" or info.get("backing-filename") or info.get("full-backing-filename")
            or info.get("encrypted") or specific.get("data-file") or specific.get("encrypt")
            or type(info.get("virtual-size")) is not int or not 1 <= info["virtual-size"] <= 64 * 1024**3):
        raise RuntimeError("Unexpected guest image format, external file, encryption or virtual size")
    checkpoint("Official dated QCOW2 image bytes match pinned publisher digests", {
        "url": source["url"], "sha256": source["sha256"], "bytes": source["bytes"],
        "publisherChecksum": source["publisherChecksum"], "independentSignatureVerified": False})
    for name in ("client", "server"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
    expected_fingerprint = run(["ssh-keygen", "-lf", str(work / "server.pub"), "-E", "sha256"]).stdout.split()[1]
    config = {"hostname": HOST, "ssh_pwauth": False, "disable_root": True, "ssh_deletekeys": True,
              "users": [{"name": "hcp-ci", "groups": ["sudo"], "shell": "/bin/bash",
                 "sudo": "ALL=(ALL) NOPASSWD:ALL", "lock_passwd": True,
                 "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
              "ssh_keys": {"ed25519_private": (work / "server").read_text(), "ed25519_public": (work / "server.pub").read_text()},
              "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True}
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config)); (work / "user-data").chmod(0o600)
    write_json(work / "meta-data", {"instance-id": "hcp-deb-" + uuid.uuid4().hex, "local-hostname": HOST})
    run(["cloud-localds", str(work / "seed.iso"), str(work / "user-data"), str(work / "meta-data")])
    (work / "seed.iso").chmod(0o600)
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
    run(["qemu-img", "resize", str(work / "guest.qcow2"), str(16 * 1024**3)])
    (work / "guest.qcow2").chmod(0o600)
    with socket.socket() as ssh_listener, socket.socket() as http_listener:
        ssh_listener.bind(("127.0.0.1", 0)); http_listener.bind(("127.0.0.1", 0))
        ssh_port, http_port = ssh_listener.getsockname()[1], http_listener.getsockname()[1]
    public = " ".join((work / "server.pub").read_text().split()[:2])
    (work / "known_hosts").write_text("[127.0.0.1]:{} {}\n".format(ssh_port, public)); (work / "known_hosts").chmod(0o600)
    ssh_options = ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=8", "-o", "PasswordAuthentication=no",
                   "-o", "KbdInteractiveAuthentication=no", "-o", "UserKnownHostsFile=" + str(work / "known_hosts"),
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]
    ssh = ["ssh", "-i", str(work / "client"), "-p", str(ssh_port)] + ssh_options + ["hcp-ci@127.0.0.1"]
    def remote(command, **kwargs): return run(ssh + [command], **kwargs)
    def remote_python(code, arguments=(), **kwargs):
        return remote("sudo -n /usr/bin/python3 - " + " ".join(map(shlex.quote, arguments))
                      + " <<'HCP_NATIVE_PY'\n" + code + "\nHCP_NATIVE_PY", **kwargs)
    qemu_args = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "4096", "-smp", "2",
                 "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
                 "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2",
                 "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on",
                 "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:{}".format(ssh_port, http_port, PORT),
                 "-device", "virtio-net-pci,netdev=net0"]
    private_machine_id = None
    process = subprocess.Popen(qemu_args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    console, console_total = bytearray(), [0]
    def drain_console():
        while True:
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk: break
            console_total[0] += len(chunk); console.extend(chunk)
            if len(console) > 4 * 1024 * 1024: del console[:-4 * 1024 * 1024]
    reader = threading.Thread(target=drain_console, daemon=True); reader.start()
    try:
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            if process.poll() is not None: raise RuntimeError("Owned KVM guest exited before pinned SSH was ready")
            if remote("true", accepted=(0, 255), timeout=12).returncode == 0: break
            time.sleep(3)
        else: raise RuntimeError("Owned KVM guest pinned SSH readiness timed out")
        remote("sudo -n cloud-init status --wait", output=artifacts / "cloud-init-status.txt", timeout=300)
        identity = json.loads(remote_python(GUEST_IDENTITY).stdout)
        private_machine_id = identity.pop("machineId")
        private_context["machineId"] = private_machine_id
        boot_hash = identity.pop("bootIdSha256")
        controller_boot = hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest()
        if (identity["osRelease"].get("ID") != distribution or identity["osRelease"].get("VERSION_ID") != VERSIONS[distribution]
                or identity.get("pid1") != "systemd" or identity.get("architecture") != "x86_64" or identity.get("virtualization") != "kvm"
                or not re.fullmatch(r"[a-f0-9]{64}", boot_hash) or boot_hash == controller_boot
                or not re.fullmatch(r"[a-f0-9]{32}", private_machine_id) or private_machine_id == "0" * 32
                or identity.get("sshHostKeyFingerprint") != expected_fingerprint):
            raise RuntimeError("Guest OS/PID1/KVM/private boot identity or fresh pinned host key does not match the native contract")
        write_json(work / "asset-observation.json", {"alias": HOST, "machineId": private_machine_id,
            "sshHostKeyFingerprint": expected_fingerprint, "observedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "connection": {"address": "127.0.0.1", "port": ssh_port, "user": "hcp-ci"}})
        identity.update({"bootIdentityDiffersFromController": True, "machineIdFormatVerified": True,
                         "kernelReleaseDiffersFromController": identity["kernel"] != os.uname().release,
                         "freshSeedHostKeyVerified": True})
        write_json(artifacts / "guest-identity.json", identity)
        checkpoint("Genuine independent KVM/systemd guest with authenticated pre-scan identity", identity)
        remote("sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30"
               " -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=120 update",
               output=artifacts / "guest-apt-update.log", timeout=480)
        remote("sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends -o Acquire::Retries=2"
               " -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=120"
               " install python3 sudo ufw nftables iptables iproute2 curl cron ca-certificates",
               output=artifacts / "guest-provision.log", timeout=600)
        with tarfile.open(str(work / "helpers.tar"), "w") as archive:
            for name in ("hcp-firewall.py", "hcp-host-readiness.py"):
                archive.add(str(ROOT / "ansible/scripts" / name), arcname=name)
        run(["scp", "-i", str(work / "client"), "-P", str(ssh_port)] + ssh_options
            + [str(work / "helpers.tar"), "hcp-ci@127.0.0.1:/home/hcp-ci/helpers.tar"])
        remote("mkdir -m 700 /home/hcp-ci/hcp-source && tar -xf /home/hcp-ci/helpers.tar -C /home/hcp-ci/hcp-source")
        guest_source = "/home/hcp-ci/hcp-source/hcp-firewall.py"
        remote(r'''set -e
test "$(cat /proc/1/comm)" = systemd
test "$(sudo -n env LC_ALL=C ufw status | head -n 1)" = 'Status: inactive'
test "$(sed -n 's/^IPV6=//p' /etc/default/ufw)" = yes
sudo -n systemctl start cron.service
sudo -n ufw default deny incoming
sudo -n ufw default allow outgoing
sudo -n ufw allow 22/tcp
sudo -n ufw allow 8088/tcp
sudo -n ufw --force enable
''', output=artifacts / "ufw-baseline-setup.log", timeout=180)
        # These files precede every audit/preflight assertion. A production
        # manual verdict must retain the actual native unsupported predicates.
        capture_initial_kernel(remote_python, artifacts)
        initial_rules, initial_state, initial_detail = snapshot_ufw(remote_python, guest_source, artifacts, "ufw-initial")
        checkpoint("Unmodified default UFW logging/before rules observed in both native INPUT families", initial_detail)
        inventory = {"linux_hosts": {"hosts": {HOST: {"ansible_host": "127.0.0.1", "ansible_port": ssh_port,
            "ansible_user": "hcp-ci", "ansible_become": True, "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": str(work / "client"), "ansible_ssh_common_args": shlex.join(ssh_options)}}}}
        write_json(work / "inventory.json", inventory)
        transaction = "txn-ci-ufw-" + uuid.uuid4().hex
        def playbook(name, phase, extra=None, check=False, expected_error=None):
            variables = {"hcp_reports_dir": str(reports), "report_run_id": phase, "transaction_id": transaction,
                         "remediation_action": "closePort", "target_port": PORT, "target_protocol": "tcp", **(extra or {})}
            var_file = work / ("vars-" + phase + ".json"); write_json(var_file, variables)
            argv = ["ansible-playbook", "-i", str(work / "inventory.json"), str(ROOT / "ansible/playbooks" / (name + ".yml")),
                    "--limit", HOST, "-e", "@" + str(var_file)]
            if check: argv.append("--check")
            result = run(argv, output=artifacts / (phase + ".log"), timeout=360, accepted=(2,) if expected_error else (0,),
                         env={**os.environ, "ANSIBLE_SSH_ARGS": shlex.join(ssh_options), "ANSIBLE_FORCE_COLOR": "false"})
            if expected_error and expected_error not in result.stdout:
                raise RuntimeError("Operation failed for a different reason than the expected SSH protection")
            return result.stdout
        playbook("collect-facts", "facts")
        facts = json.loads((reports / (HOST + "-facts-facts.json")).read_text())
        if (facts.get("kernel") != identity["kernel"] or facts.get("architecture") != "x86_64"
                or facts.get("virtualizationType") != "kvm" or facts.get("virtualizationRole") != "guest"):
            raise RuntimeError("Production SSH facts do not describe the owned native KVM guest")
        playbook("package-inventory", "packages")
        package_path = reports / (HOST + "-packages-packages.json")
        package_report = json.loads(package_path.read_text())
        native = remote("env LC_ALL=C dpkg-query -W -f " + shlex.quote(DPKG_FORMAT),
                        output=artifacts / "native-dpkg-records.txt").stdout
        checkpoint("Production dpkg collector equals all eight independent native fields",
                   verify_dpkg_inventory(package_report, native, distribution))
        if distribution == "debian":
            apt = package_report.get("packageInventory", {}).get("aptRepositories")
            # No repository URL, credential or raw APT output is retained in
            # public CI evidence. Independently compare two read-only views.
            native_apt = remote("env LC_ALL=C apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy", timeout=60).stdout.rstrip("\n")
            expected_policy_sha = hashlib.sha256(native_apt.encode("utf-8")).hexdigest()
            if (not isinstance(apt, dict) or apt.get("schemaVersion") != 1
                    or apt.get("status") != "observed" or apt.get("indexEntries", 0) <= 0
                    or apt.get("policySha256") != expected_policy_sha
                    or apt.get("releaseCodename") != "bookworm"
                    or apt.get("publisherAuthenticated") is not False
                    or apt.get("repositorySignatureVerified") is not False
                    or apt.get("installedPackageOriginVerified") is not False):
                raise RuntimeError("APT index metadata observation was incomplete, changed or claimed unverified signing authority")
            checkpoint("Debian APT index metadata SHA equals independent native apt-cache policy",
                       {"sha256": expected_policy_sha, "indexEntries": apt["indexEntries"],
                        "suites": apt.get("suites", []), "suiteConsistent": apt.get("suiteConsistent") is True,
                        "releaseLabels": apt.get("releaseLabels", []),
                        "publisherAuthenticated": False, "repositorySignatureVerified": False,
                        "installedPackageOriginVerified": False})
            signed = package_report.get("packageInventory", {}).get("debianSignedReleases")
            if (not isinstance(signed, dict) or signed.get("schemaVersion") != 1
                    or signed.get("status") != "verified_with_local_keyring"
                    or signed.get("candidateFiles", 0) <= 0
                    or signed.get("candidateFiles") != signed.get("validLocalSignatures")
                    or signed.get("invalidOrUnverifiable") != 0
                    or signed.get("localSignatureVerified") is not True
                    or not re.fullmatch(r"[a-f0-9]{64}", signed.get("localKeyringSha256", ""))
                    or not signed.get("signerFingerprints") or not signed.get("inReleaseSha256")
                    or signed.get("publisherAuthenticated") is not False
                    or signed.get("publisherFreshnessVerified") is not False
                    or signed.get("packageIndexHashesVerified") is not False
                    or signed.get("installedPackageOriginVerified") is not False
                    or signed.get("remediationAuthorized") is not False):
                # Only safe predefined status and integer counters enter CI
                # logs. No local path, repository URL, GPG data or VM secrets.
                safe_status = signed.get("status") if isinstance(signed, dict) else "missing"
                if safe_status not in ("verified_with_local_keyring", "partial", "unavailable", "missing"):
                    safe_status = "unknown"
                counters = []
                for field in ("candidateFiles", "validLocalSignatures", "invalidOrUnverifiable"):
                    value = signed.get(field) if isinstance(signed, dict) else None
                    counters.append(str(value) if type(value) is int and 0 <= value <= 100 else "unknown")
                raise RuntimeError("Native cached Debian InRelease verification unavailable: "
                                   "state={}, candidate={}, valid={}, invalid={}".format(
                                       safe_status, counters[0], counters[1], counters[2]))
            checkpoint("Cached Debian InRelease signatures verified by native gpgv with local keyring only",
                       {"candidateFiles": signed["candidateFiles"],
                        "validLocalSignatures": signed["validLocalSignatures"],
                        "signedReleases": signed["signedReleases"],
                        "localKeyringSha256": signed["localKeyringSha256"],
                        "inReleaseSha256": signed["inReleaseSha256"],
                        "publisherAuthenticated": False,
                        "packageIndexHashesVerified": False,
                        "installedPackageOriginVerified": False})
            package_indexes = package_report.get("packageInventory", {}).get("debianPackageIndexes")
            if (not isinstance(package_indexes, dict) or package_indexes.get("schemaVersion") != 1
                    or package_indexes.get("status") != "locally_hash_matched"
                    or package_indexes.get("verifiedAgainstLocallySignedRelease") is not True
                    or package_indexes.get("candidateIndexes", 0) < 1
                    or package_indexes.get("candidateIndexes") != package_indexes.get("matchedIndexes")
                    or package_indexes.get("mismatchedIndexes") != 0
                    or package_indexes.get("missingSignedHashes") != 0
                    or package_indexes.get("publisherAuthenticated") is not False
                    or package_indexes.get("keyringIndependentlyAuthenticated") is not False
                    or package_indexes.get("publisherFreshnessVerified") is not False
                    or package_indexes.get("installedPackageOriginVerified") is not False
                    or package_indexes.get("remediationAuthorized") is not False):
                safe_status = package_indexes.get("status") if isinstance(package_indexes, dict) else "missing"
                if safe_status not in ("locally_hash_matched", "partial", "unavailable",
                                       "budget_exceeded", "missing"):
                    safe_status = "unknown"
                raise RuntimeError("Native Debian Packages hash-chain verification incomplete: state=" + safe_status)
            verified_indexes = package_indexes.get("indexRecords", [])
            if (not isinstance(verified_indexes, list)
                    or len(verified_indexes) != package_indexes.get("matchedIndexes")
                    or any(not isinstance(item, dict) or
                           not re.fullmatch(r"[a-f0-9]{64}", item.get("packagesSha256", "")) or
                           item.get("releaseSha256") not in signed.get("inReleaseSha256", [])
                           for item in verified_indexes)):
                raise RuntimeError("Native Debian Packages hash chain could not be linked to signed InRelease")
            checkpoint("Native Debian cached Packages SHA256 matches locally signed InRelease records",
                       {"matchedIndexes": package_indexes["matchedIndexes"],
                        "candidateIndexes": package_indexes["candidateIndexes"],
                        "verifiedIndexes": verified_indexes,
                        "publisherAuthenticated": False,
                        "installedPackageOriginVerified": False,
                        "remediationAuthorized": False})
        readiness = json.loads(remote("sudo -n python3 /home/hcp-ci/hcp-source/hcp-host-readiness.py",
                                      output=artifacts / "host-readiness.json").stdout)
        if (readiness.get("osRelease", {}).get("ID") != distribution
                or readiness.get("osRelease", {}).get("VERSION_ID") != VERSIONS[distribution]
                or readiness.get("serviceManager") != "systemd" or readiness.get("effectiveUid") != 0
                or not readiness.get("tools", {}).get("dpkg-query") or readiness.get("firewall", {}).get("ufw") != "active"
                or readiness.get("errors")):
            raise RuntimeError("Production readiness did not observe complete native dpkg/systemd/UFW prerequisites")
        checkpoint("Production root readiness identifies native systemd/dpkg/UFW", {"serviceManager": readiness["serviceManager"],
            "firewall": readiness["firewall"], "securityModules": readiness["securityModules"], "errors": readiness["errors"]})
        verify_system_controls(remote, playbook, checkpoint, artifacts)
        verify_ufw_audit(remote_python, playbook, checkpoint, artifacts, guest_source)
        run(["node", str(ROOT / "deployment/tests/verify_deb_vm_normalization.mjs"), str(artifacts),
             str(work / "asset-observation.json"), str(artifacts / "report-publication")],
            output=artifacts / "report-publication.log", timeout=180)
        publication = json.loads((artifacts / "report-publication/protocol.json").read_text())
        if publication.get("status") != "passed" or len(publication.get("checks", [])) != 6:
            raise RuntimeError("Production asset-bound publication/normalization did not verify all six native reports")
        checkpoint("Six native reports conserve identity, findings, risk, evidence and incomplete coverage", publication)
        verify_ufw_remediation(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port)
        run(["node", str(ROOT / "deployment/tests/verify_linux_packages.mjs"), str(package_path), str(artifacts / "package-matching")],
            output=artifacts / "package-matching.log", timeout=1000,
            env={**os.environ, "HCP_TRIVY_CACHE_DIR": str(work / "trivy-cache")})
        matching = json.loads((artifacts / "package-matching/protocol.json").read_text())
        if matching.get("status") != "passed":
            raise RuntimeError("Production native SBOM/Trivy/normalization did not establish verified success")
        checkpoint("Native DEB packages and labelled vendor CVE boundaries through production matching", matching)
        final_rules, final_state, final_detail = snapshot_ufw(remote_python, guest_source, artifacts, "ufw-final")
        if semantic_nftables(final_rules) != semantic_nftables(initial_rules) or final_state != initial_state:
            raise RuntimeError("Final guest UFW/config/security-module state differs from the established native baseline")
        if remote("systemctl is-active cron.service").stdout.strip() != "active":
            raise RuntimeError("Final native cron service was not restored")
        checkpoint("Final native firewall/config/security-module state and cron restored", final_detail)
    except BaseException:
        try:
            remote("sudo -n journalctl -u ufw -u ssh -u cron --no-pager -n 60 && sudo -n env LC_ALL=C ufw status verbose",
                   output=artifacts / "failure-guest-diagnostics.log", timeout=25, accepted=(0, 1, 255))
        except Exception: pass
        raise
    finally:
        stop_owned_process(process)
        reader.join(timeout=5); process.stdout.close()
        public_console = redact_public_log(console.decode("utf-8", "replace"))
        if private_machine_id: public_console = public_console.replace(private_machine_id, "[private machine identity]")
        (artifacts / "guest-console.log").write_text(public_console); (artifacts / "guest-console.log").chmod(0o600)
        protocol["ownedGuestStopped"] = process.poll() is not None
        protocol["consoleCapture"] = {"totalBytes": console_total[0], "retainedBytes": len(console),
                                       "limitBytes": 4 * 1024 * 1024, "truncated": console_total[0] > len(console)}
        write_json(artifacts / "protocol.json", protocol)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", choices=tuple(VERSIONS), required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Only an owned disposable GitHub-hosted runner is supported")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("Real KVM is required; no software-emulation or container fallback can pass native acceptance")
    work = validate_work_directory(args.work_dir, Path(os.environ["RUNNER_TEMP"]))
    work.mkdir(mode=0o700)
    artifacts = work / "artifacts"; artifacts.mkdir(mode=0o700)
    protocol = {"schemaVersion": 1, "status": "running", "distribution": args.distribution,
        "image": image_source(args.distribution), "sourceCommit": os.environ.get("GITHUB_SHA"),
        "acceleration": "kvm", "syntheticOsIdentity": False, "publicationPrivacyVerified": False,
        "limitations": ["Pinned Debian 12/bookworm or Ubuntu 24.04/noble x86_64 images only",
            "Publisher HTTPS checksums and complete image bytes verified; no independent OpenPGP signature verification",
            "Real traffic probe covers IPv4 through QEMU localhost forwarding; external IPv6 is not evaluated",
            "firewall_active covers conditional NEW/non-loopback/non-DNAT TCP/UDP paths, not all packet classes or external reachability",
            "Observed LSM module flags are preserved; this gate does not validate every AppArmor or SELinux policy",
            "Authenticated CLI publication is covered; browser onboarding is not evaluated",
            "Labelled vendor boundaries demonstrate named cases, not complete vulnerability recall"], "checks": []}
    write_json(artifacts / "protocol.json", protocol)
    def interrupted(_signum, _frame): raise InterruptedError("CI cancellation")
    signal.signal(signal.SIGTERM, interrupted)
    private_context, exit_code = {}, 0
    try:
        boot_and_verify(args.distribution, work, artifacts, protocol, private_context)
        protocol["status"] = "passed"
    except BaseException as error:
        protocol["status"] = "cancelled" if isinstance(error, (InterruptedError, KeyboardInterrupt)) else "failed"
        protocol["error"] = sanitize_public_error(error, private_context.get("machineId"))
        exit_code = 1
    finally:
        # Every listed path belongs to this exclusively created work directory.
        # Private inputs and disks are neither retained nor uploaded.
        cleanup_errors = []
        private_paths = [work / name for name in ("client", "client.pub", "server", "server.pub", "user-data", "meta-data", "seed.iso",
                     "guest.qcow2", "source.qcow2", "source.download", "known_hosts", "inventory.json",
                     "helpers.tar", "asset-observation.json")]
        for path in private_paths + list(work.glob("vars-*.json")):
            try: path.unlink(missing_ok=True)
            except OSError: cleanup_errors.append(path.name)
        protocol["privateGuestFilesRemoved"] = not cleanup_errors
        if cleanup_errors:
            protocol["status"], exit_code = "failed", 1
            protocol["cleanupError"] = "Could not remove {} owned private files".format(len(cleanup_errors))
        protocol["finishedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        write_json(artifacts / "protocol.json", protocol)
        try:
            check_public_artifacts(artifacts, private_context.get("machineId"))
            protocol["publicationPrivacyVerified"] = True
            protocol["rawMachineIdPublished"] = False
        except BaseException as error:
            protocol["status"], exit_code = "failed", 1
            protocol["privacyError"] = sanitize_public_error(error, private_context.get("machineId"))
        # Protocol values are curated; sanitize its final serialization as a
        # defense against known identity appearing in an unexpected error.
        safe = redact_public_log(json.dumps(protocol, ensure_ascii=True))
        if private_context.get("machineId"):
            safe = re.sub(re.escape(private_context["machineId"]), "[private machine identity]", safe, flags=re.I)
        write_json(artifacts / "protocol.json", json.loads(safe))
    if exit_code:
        # Never re-raise the original exception into public CI stderr.
        summary = protocol.get("privacyError") or protocol.get("error") or {"type": "RuntimeError", "message": protocol.get("cleanupError", "Native acceptance failed")}
        print(summary["type"] + ": " + summary["message"], file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
