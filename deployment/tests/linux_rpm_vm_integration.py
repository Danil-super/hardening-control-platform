#!/usr/bin/env python3
"""Real RPM VM acceptance: native collectors, firewalld and enforcing SELinux.

Only an owned, checksum-pinned QEMU guest receives configuration changes.
Controller artifacts exclude guest disks, cloud-init seeds and SSH private keys.
The labelled system rule and CVE pairs establish specific controls, not overall
scanner recall or compatibility with all RPM distributions and releases.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-rpm-ci"
PORT = 8088
# Official publisher CHECKSUM files and image sizes reviewed 2026-10-30.
# Keep immutable filenames and reviewed SHA-256 values; never resolve "latest".
SOURCES = {
    "almalinux": {
        "url": "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-9.8-20261005.x86_64.qcow2",
        "sha256": "25942b554efaac077e2f60d6bb27bd3332c171454cc21bbd33e5f79244d7570f",
        "bytes": 572850176,
        "checksumUrl": "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM",
    },
    "rocky": {
        "url": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
        "sha256": "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
        "bytes": 645988352,
        "checksumUrl": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2.CHECKSUM",
    },
}

FIREWALL_PACKET_MODEL = "new_non_loopback_non_dnat_tcp_udp"
FIREWALL_RICH_RULE = 'rule priority="-32768" accept'
FIREWALL_CONTROL_CHAIN = ("inet", "firewalld", "filter_IN_public_pre")

# These programs are sent only through remote_python to the owned QEMU guest.
# No controller subprocess receives a firewall-changing command.
FIREWALL_AUDIT_SNAPSHOT = r'''
import importlib.util, json, os, subprocess, sys
from pathlib import Path
def observed(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=30)
    if result.returncode or len(result.stdout.encode("utf-8")) > 4 * 1024 * 1024:
        raise RuntimeError("Snapshot command failed or exceeded its output limit: " + repr(argv) + ": " + result.stderr[-2000:])
    return result.stdout
spec = importlib.util.spec_from_file_location("native_firewall_audit_snapshot", sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
tree = Path("/etc/firewalld")
labels = {str(path.relative_to(tree)): os.getxattr(str(path), "security.selinux", follow_symlinks=False).hex()
          for path in [tree] + sorted(tree.rglob("*"))}
runtime = {name: observed(["firewall-cmd"] + args)
           for name, args in (("zones", ["--list-all-zones"]), ("policies", ["--list-all-policies"]),
                              ("direct", ["--direct", "--get-all-rules"]))}
print(json.dumps({"nftables": observed(["nft", "--json", "list", "ruleset"]),
    "state": {"manifest": fw.tree_digest(tree), "labels": labels, "runtime": runtime,
              "selinux": observed(["getenforce"]).strip(),
              "firewalld": observed(["firewall-cmd", "--state"]).strip(),
              "pid1": Path("/proc/1/comm").read_text().strip()}}))
'''

FIREWALL_AUDIT_CONTROL = r'''
import json, os, re, stat, subprocess, sys
from pathlib import Path
action, marker_path, rule = sys.argv[1:]
if action not in ("add", "remove") or not re.fullmatch(r"/run/hcp-rpm-firewall-audit-[a-f0-9]{32}", marker_path):
    raise RuntimeError("Unexpected native control action or ownership path")
if os.geteuid() != 0 or rule != 'rule priority="-32768" accept':
    raise RuntimeError("Unexpected native control identity or rule")
marker, plan = Path(marker_path), {"zone": "public", "rule": rule}
def command(args, accepted=(0,)):
    result = subprocess.run(["firewall-cmd", "--zone=public"] + args,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=30)
    if result.returncode not in accepted:
        raise RuntimeError("firewall-cmd failed: " + result.stderr[-2000:] + result.stdout[-2000:])
    return result
def present():
    return command(["--query-rich-rule=" + rule], accepted=(0, 1)).returncode == 0
if action == "add":
    if (subprocess.check_output(["getenforce"], universal_newlines=True).strip() != "Enforcing"
            or subprocess.check_output(["firewall-cmd", "--state"], universal_newlines=True).strip() != "running"
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise RuntimeError("Native control requires enforcing SELinux and running systemd/firewalld")
    # Validate with this guest's actual firewalld parser, not a local grammar.
    from firewall.core.rich import Rich_Rule
    Rich_Rule(rule_str=rule).check()
    if present():
        raise RuntimeError("Exact runtime control rule already exists; refusing to claim or remove it")
    if command(["--permanent", "--query-rich-rule=" + rule], accepted=(0, 1)).returncode == 0:
        raise RuntimeError("Exact control rule already exists in permanent configuration")
    marker.mkdir(mode=0o700)
    # Durable ownership intent covers a successful add with a lost SSH reply.
    with (marker / "plan.json").open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(plan, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    command(["--add-rich-rule=" + rule])
    if not present():
        raise RuntimeError("Runtime control rule was not observed after add")
    print(json.dumps({"owned": True, "present": True, "rule": rule, "permanent": False}))
else:
    if not marker.exists():
        print(json.dumps({"owned": False, "removed": False, "reason": "add-not-started"}))
    else:
        info, plan_info = marker.lstat(), (marker / "plan.json").lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or not stat.S_ISREG(plan_info.st_mode) or plan_info.st_uid != 0
                or stat.S_IMODE(plan_info.st_mode) != 0o600
                or json.loads((marker / "plan.json").read_text()) != plan):
            raise RuntimeError("Runtime control ownership could not be verified")
        was_present = present()
        if was_present:
            command(["--remove-rich-rule=" + rule])
        if present():
            raise RuntimeError("Owned runtime control rule remains after removal")
        (marker / "plan.json").unlink()
        marker.rmdir()
        print(json.dumps({"owned": True, "removed": was_present, "present": False, "rule": rule}))
'''


def semantic_nftables(ruleset):
    """Keep all rule order/expressions/flags; ignore only kernel IDs and counters.

    Managed insertion/deletion changes handles, and observing live guest traffic
    advances counters. Neither changes a rule's decision. Counter statements are
    retained, as are every policy, predicate, table flag and metainfo field.
    """
    result = json.loads(json.dumps(ruleset))
    for entry in result["nftables"]:
        for kind, value in entry.items():
            if kind in ("table", "chain", "rule"):
                value.pop("handle", None)
            if kind == "rule":
                for expression in value["expr"]:
                    counter = expression.get("counter")
                    if isinstance(counter, dict):
                        for field in ("packets", "bytes"):
                            if field in counter:
                                if type(counter[field]) is not int or counter[field] < 0:
                                    raise RuntimeError("Unexpected nft counter value")
                                counter[field] = 0
    return result


def inspect_firewall_audit_ruleset(ruleset):
    """Fail closed on layouts outside this pinned firewalld acceptance fixture."""
    if not isinstance(ruleset, dict) or set(ruleset) != {"nftables"} or not isinstance(ruleset["nftables"], list):
        raise RuntimeError("Invalid native nft ruleset envelope")
    tables, chains, rules = {}, {}, []
    for entry in ruleset["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise RuntimeError("Unexpected native nft object")
        kind, value = next(iter(entry.items()))
        if kind not in ("metainfo", "table", "chain", "rule") or not isinstance(value, dict):
            raise RuntimeError("Unaccounted native nft object: " + kind)
        if kind == "table":
            flags = value.get("flags", [])
            key = (value.get("family"), value.get("name"))
            if (key in tables or not all(isinstance(part, str) and part for part in key)
                    or not isinstance(flags, list) or any(flag not in ("dormant", "owner", "persist") for flag in flags)
                    or len(flags) != len(set(flags))):
                raise RuntimeError("Unknown or duplicate native nft table/flags")
            tables[key] = value
        elif kind == "chain":
            key = (value.get("family"), value.get("table"), value.get("name"))
            if key in chains or not all(isinstance(part, str) and part for part in key) or value.get("flags"):
                raise RuntimeError("Unknown or duplicate native nft chain/flags")
            chains[key] = value
        elif kind == "rule":
            if not isinstance(value.get("expr"), list) or not all(isinstance(item, dict) for item in value["expr"]):
                raise RuntimeError("Invalid native nft rule expressions")
            rules.append(value)
    for rule in rules:
        if (rule.get("family"), rule.get("table"), rule.get("chain")) not in chains:
            raise RuntimeError("Native nft rule has no observed chain")
    inputs = []
    for key, chain in chains.items():
        table = tables.get(key[:2])
        if table is None:
            raise RuntimeError("Native nft chain has no observed table")
        if chain.get("hook") != "input":
            continue
        if (key[0] not in ("ip", "ip6", "inet") or chain.get("type") != "filter"
                or chain.get("policy") not in ("accept", "drop") or type(chain.get("prio")) is not int):
            raise RuntimeError("Unknown native INPUT hook/type/priority/policy")
        if "dormant" in table.get("flags", []):
            continue
        own_rules = [item for item in rules if (item["family"], item["table"], item["chain"]) == key]
        if key != ("inet", "firewalld", "filter_INPUT") and (own_rules or chain["policy"] != "accept"):
            raise RuntimeError("Another active INPUT chain could invalidate the owned allow-all control")
        inputs.append({"family": key[0], "table": key[1], "chain": key[2], "type": chain["type"],
                       "priority": chain["prio"], "policy": chain["policy"], "tableFlags": table.get("flags", [])})
    target = chains.get(("inet", "firewalld", "filter_INPUT"))
    table = tables.get(("inet", "firewalld"), {})
    if (not target or target.get("hook") != "input" or target.get("policy") != "accept"
            or set(table.get("flags", [])) != {"owner", "persist"} or FIREWALL_CONTROL_CHAIN not in chains):
        raise RuntimeError("Pinned native firewalld INPUT/public_pre ownership or policy was not established")
    if any(key[:2] == ("inet", "firewalld") and chain.get("hook") == "input"
           and key != ("inet", "firewalld", "filter_INPUT") for key, chain in chains.items()):
        raise RuntimeError("Unexpected additional native firewalld INPUT base chain")
    return inputs


def verify_firewall_control_delta(baseline, allowed):
    """The owned rich rule must add exactly one unconditional public_pre accept."""
    before, after = semantic_nftables(baseline), semantic_nftables(allowed)

    def controlled(entry):
        rule = entry.get("rule", {})
        return (rule.get("family"), rule.get("table"), rule.get("chain")) == FIREWALL_CONTROL_CHAIN

    if any(controlled(entry) for entry in before["nftables"]):
        raise RuntimeError("Native public_pre is not empty before the owned runtime control")
    inserted = [entry["rule"] for entry in after["nftables"] if controlled(entry)]
    expected = {"family": "inet", "table": "firewalld", "chain": "filter_IN_public_pre", "expr": [{"accept": None}]}
    if inserted != [expected]:
        raise RuntimeError("Runtime rich rule did not create exactly the expected unconditional public_pre accept")
    after["nftables"] = [entry for entry in after["nftables"] if not controlled(entry)]
    if before != after:
        raise RuntimeError("Runtime rich rule changed additional native kernel semantics")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")
    path.chmod(0o600)


def run(argv, output=None, timeout=120, accepted=(0,), env=None):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, env=env)
    if output:
        output.write_text(result.stdout)
    if result.returncode not in accepted:
        raise RuntimeError("Command failed (exit {}): {}\n{}".format(result.returncode, argv[0], result.stdout[-8000:]))
    return result


def download_image(source, target):
    start, size, digest = time.monotonic(), 0, hashlib.sha256()
    temporary = target.with_suffix(".download")
    try:
        with urllib.request.urlopen(source["url"], timeout=60) as response, temporary.open("xb") as stream:
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise RuntimeError("Refusing an image redirect outside HTTPS.")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > source["bytes"] or time.monotonic() - start > 600:
                    raise RuntimeError("Image download exceeded its pinned byte/time limit.")
                digest.update(chunk)
                stream.write(chunk)
        if size != source["bytes"] or digest.hexdigest() != source["sha256"]:
            raise RuntimeError("Image differs from its pinned publisher SHA-256 or byte count.")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def boot_and_verify(distribution, work, artifacts, protocol):
    source = SOURCES[distribution]
    reports = artifacts / "reports"
    reports.mkdir()

    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)
        print("PASS: " + name, flush=True)

    download_image(source, work / "source.qcow2")
    info = json.loads(run(["qemu-img", "info", "--output=json", str(work / "source.qcow2")]).stdout)
    if info["format"] != "qcow2" or info.get("backing-filename") or info["virtual-size"] > 64 * 1024**3:
        raise RuntimeError("Unexpected image format, backing file or virtual size.")
    checkpoint("Pinned official guest image verified", source)
    for name in ("client", "server"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
    config = {"hostname": HOST, "ssh_pwauth": False, "disable_root": True,
              "users": ["default", {"name": "hcp-ci", "groups": ["wheel"], "sudo": "ALL=(ALL) NOPASSWD:ALL",
                                     "lock_passwd": True, "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
              "ssh_keys": {"ed25519_private": (work / "server").read_text(), "ed25519_public": (work / "server.pub").read_text()},
              "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True}
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "user-data").chmod(0o600)
    write_json(work / "meta-data", {"instance-id": "hcp-rpm-" + distribution, "local-hostname": HOST})
    run(["cloud-localds", str(work / "seed.iso"), str(work / "user-data"), str(work / "meta-data")])
    (work / "seed.iso").chmod(0o600)
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
    run(["qemu-img", "resize", str(work / "guest.qcow2"), str(max(info["virtual-size"], 16 * 1024**3))])
    with socket.socket() as ssh_listener, socket.socket() as http_listener:
        ssh_listener.bind(("127.0.0.1", 0))
        http_listener.bind(("127.0.0.1", 0))
        ssh_port, http_port = ssh_listener.getsockname()[1], http_listener.getsockname()[1]
    public = " ".join((work / "server.pub").read_text().split()[:2])
    (work / "known_hosts").write_text("[127.0.0.1]:{} {}\n".format(ssh_port, public))
    ssh_options = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=8",
                   "-o", "UserKnownHostsFile=" + str(work / "known_hosts"),
                   "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]
    ssh = ["ssh", "-i", str(work / "client"), "-p", str(ssh_port)] + ssh_options + ["hcp-ci@127.0.0.1"]

    def remote(command, **kwargs):
        return run(ssh + [command], **kwargs)

    def remote_python(code, arguments=(), **kwargs):
        return remote("sudo python3 - " + " ".join(map(shlex.quote, arguments)) + " <<'HCP_NATIVE_PY'\n" + code + "\nHCP_NATIVE_PY", **kwargs)

    qemu_args = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "4096", "-smp", "2",
                 "-display", "none", "-monitor", "none", "-serial", "file:" + str(artifacts / "guest-console.log"), "-no-reboot",
                 "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2",
                 "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on",
                 "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22,hostfwd=tcp:127.0.0.1:{}-:{}".format(ssh_port, http_port, PORT),
                 "-device", "virtio-net-pci,netdev=net0"]
    with (artifacts / "qemu.log").open("w") as log:
        process = subprocess.Popen(qemu_args, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Guest exited before SSH readiness; inspect QEMU and console logs.")
                if remote("true", accepted=(0, 255), timeout=12).returncode == 0:
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Guest SSH readiness timed out.")
            remote("sudo cloud-init status --wait", output=artifacts / "cloud-init-status.txt", timeout=300)
            identity = json.loads(remote_python(r'''
import json, os, platform, shlex, subprocess
from pathlib import Path
release = {}
for line in Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        release[key] = shlex.split(value)[0] if value else ""
print(json.dumps({"osRelease": release, "kernel": platform.release(), "architecture": platform.machine(),
    "pid1": Path("/proc/1/comm").read_text().strip(), "machineId": Path("/etc/machine-id").read_text().strip(),
    "selinux": subprocess.check_output(["getenforce"], universal_newlines=True).strip()}))
''').stdout)
            if (identity["osRelease"].get("ID") != distribution or not identity["osRelease"].get("VERSION_ID", "").startswith("9.")
                    or identity["pid1"] != "systemd" or identity["architecture"] != "x86_64"
                    or identity["kernel"] == os.uname().release or identity["selinux"] != "Enforcing"
                    or not re.fullmatch(r"[a-f0-9]{32}", identity["machineId"])):
                raise RuntimeError("Guest identity, independent kernel, PID1 or enforcing SELinux does not match the native test.")
            identity.pop("machineId")
            identity["machineIdFormatVerified"] = True
            write_json(artifacts / "guest-identity.json", identity)
            checkpoint("Genuine RPM guest with independent kernel and enforcing SELinux", identity)
            remote("sudo dnf -y --setopt=retries=2 --setopt=timeout=30 install python3 firewalld iproute nftables curl policycoreutils",
                   output=artifacts / "guest-provision.log", timeout=600)
            remote("test \"$(getenforce)\" = Enforcing && test \"$(cat /proc/1/comm)\" = systemd")
            # A separate private source copy lets native metadata/crash tests
            # import the same production helper. No user secrets are copied.
            with tarfile.open(str(work / "helpers.tar"), "w") as archive:
                archive.add(str(ROOT / "ansible/scripts"), arcname="ansible/scripts", filter=lambda member: None if "__pycache__" in member.name else member)
                archive.add(str(ROOT / "ansible/tests/native_selinux_firewall_acceptance.py"), arcname="ansible/tests/native_selinux_firewall_acceptance.py")
                archive.add(str(ROOT / "ansible/tests/native_rpm_inventory_diagnostics.py"), arcname="ansible/tests/native_rpm_inventory_diagnostics.py")
            run(["scp", "-i", str(work / "client"), "-P", str(ssh_port)] + ssh_options + [str(work / "helpers.tar"), "hcp-ci@127.0.0.1:/home/hcp-ci/helpers.tar"])
            remote("mkdir -m 700 /home/hcp-ci/hcp-source && tar -xf /home/hcp-ci/helpers.tar -C /home/hcp-ci/hcp-source")
            guest_source = "/home/hcp-ci/hcp-source/ansible/scripts/hcp-firewall.py"
            remote(r'''set -e
sudo systemctl enable --now firewalld.service
sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --permanent --zone=public --add-service=ssh
sudo firewall-cmd --permanent --zone=public --add-port=8088/tcp
interface=$(ip -4 route show default | awk 'NR == 1 { for (i=1;i<=NF;i++) if ($i == "dev") { print $(i+1); exit } }')
test -n "$interface"
sudo firewall-cmd --permanent --zone=public --change-interface="$interface"
sudo firewall-cmd --zone=public --change-interface="$interface"
sudo firewall-cmd --reload
test "$(sudo firewall-cmd --get-zone-of-interface="$interface")" = public
test "$(getenforce)" = Enforcing
''', output=artifacts / "firewall-baseline-setup.log")
            inventory = {"linux_hosts": {"hosts": {HOST: {"ansible_host": "127.0.0.1", "ansible_port": ssh_port,
                "ansible_user": "hcp-ci", "ansible_become": True, "ansible_python_interpreter": "/usr/bin/python3",
                "ansible_ssh_private_key_file": str(work / "client"), "ansible_ssh_common_args": shlex.join(ssh_options)}}}}
            write_json(work / "inventory.json", inventory)
            transaction = "txn-ci-firewalld-" + uuid.uuid4().hex

            def playbook(name, phase, extra=None, check=False, expected_error=None):
                variables = {"hcp_reports_dir": str(reports), "report_run_id": phase,
                             "transaction_id": transaction, "remediation_action": "closePort", "target_port": PORT,
                             "target_protocol": "tcp", **(extra or {})}
                var_file = work / ("vars-" + phase + ".json")
                write_json(var_file, variables)
                argv = ["ansible-playbook", "-i", str(work / "inventory.json"), str(ROOT / "ansible/playbooks" / (name + ".yml")),
                        "--limit", HOST, "-e", "@" + str(var_file)]
                if check:
                    argv.append("--check")
                result = run(argv, output=artifacts / (phase + ".log"), timeout=360, accepted=(2,) if expected_error else (0,),
                             env={**os.environ, "ANSIBLE_SSH_ARGS": shlex.join(ssh_options), "ANSIBLE_FORCE_COLOR": "false"})
                if expected_error and expected_error not in result.stdout:
                    raise RuntimeError("Request failed for a different reason than the expected protection: " + phase)
                return result.stdout

            playbook("collect-facts", "facts")
            facts = json.loads((reports / (HOST + "-facts-facts.json")).read_text())
            if facts["kernel"] != identity["kernel"] or facts["architecture"] != "x86_64":
                raise RuntimeError("Production Ansible facts do not describe the native guest.")
            playbook("package-inventory", "packages")
            package_path = reports / (HOST + "-packages-packages.json")
            packages = json.loads(package_path.read_text())
            coverage = packages["packageInventory"]
            if (coverage.get("manager") != "rpm" or coverage.get("error") or coverage.get("partial") is not False
                    or coverage.get("osRelease", {}).get("ID") != distribution or not packages.get("packages")
                    or coverage.get("collectorVersion") != 2 or coverage.get("managerSelection") != "os-id"
                    or coverage.get("packageCount") != len(packages["packages"])):
                # Preserve the failing production report. Additional read-only
                # queries explain SQLite/WAL changes; they cannot make this
                # inventory complete or bypass the original acceptance gate.
                remote("sudo python3 /home/hcp-ci/hcp-source/ansible/tests/native_rpm_inventory_diagnostics.py",
                       output=artifacts / "native-rpm-inventory-diagnostics.json", timeout=300)
                raise RuntimeError("Native RPM package inventory is missing, partial or identifies a different distribution: "
                                   + json.dumps(coverage, sort_keys=True))
            if not all(item.get("manager") == "rpm" and item.get("name") and item.get("version") and item.get("arch") for item in packages["packages"]):
                raise RuntimeError("RPM inventory omitted package identity fields.")
            query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
            native_records = remote("rpm -qa --qf " + shlex.quote(query), output=artifacts / "native-rpm-records.txt").stdout
            expected_records = []
            for line in native_records.splitlines():
                name, epoch, version, arch, source_rpm = line.split("\t")
                expected_records.append((name, (epoch + ":" if epoch not in ("0", "(none)", "") else "") + version,
                                         "None" if arch == "(none)" else arch, "" if source_rpm == "(none)" else source_rpm))
            observed_records = [(item["name"], item["version"], item["arch"], item.get("sourceRpm", "")) for item in packages["packages"]]
            if Counter(observed_records) != Counter(expected_records):
                raise RuntimeError("Collected binary RPM EVR/architecture/source records differ from the native RPM database.")
            checkpoint("Production SSH facts and complete native RPM collection", {"count": len(packages["packages"]), "manager": coverage["manager"]})
            readiness = json.loads(remote("sudo python3 /home/hcp-ci/hcp-source/ansible/scripts/hcp-host-readiness.py",
                                         output=artifacts / "host-readiness.json").stdout)
            if (readiness["osRelease"].get("ID") != distribution or readiness.get("serviceManager") != "systemd"
                    or readiness.get("securityModules", {}).get("selinux") != "enforcing"
                    or not readiness.get("tools", {}).get("rpm") or readiness.get("firewall", {}).get("firewalld") != "active"):
                raise RuntimeError("Readiness did not retain the native service manager and SELinux state.")
            # A native pass/fail/restored control uses an owned temporary child
            # of /var/tmp, one of the production profile's inspected roots.
            control = "/var/tmp/hcp-world-writable-" + uuid.uuid4().hex
            remote("sudo mkdir -m 1777 " + shlex.quote(control))
            states = []
            try:
                for phase, mode in (("system-baseline", "1777"), ("system-violation", "0777"), ("system-restored", "1777")):
                    remote("sudo chmod " + mode + " " + shlex.quote(control))
                    playbook("agentless-audit", phase, {"audit_profile": "basic_linux"})
                    report = json.loads((reports / (HOST + "-basic_linux-" + phase + ".json")).read_text())
                    agentless = report["agentless"]
                    if agentless.get("serviceManager") != "systemd" or not agentless.get("serviceManagerEvidence"):
                        raise RuntimeError("Agentless report omitted observed systemd evidence.")
                    observations = agentless.get("serviceObservations", [])
                    if not any(item.get("service") in ("ssh", "sshd") and item.get("state") == "active" for item in observations):
                        raise RuntimeError("Native sshd service was not detected through its distro alias.")
                    if report["scanner"].get("partial") and report["summary"].get("score") is not None:
                        raise RuntimeError("Incomplete native checks produced an unqualified score.")
                    finding = [item for item in report["findings"] if item["id"] == "world_writable_dirs"]
                    if len(finding) != 1 or finding[0]["status"] != ("failed" if mode == "0777" else "passed"):
                        raise RuntimeError("Native sticky-bit control produced the wrong agentless finding.")
                    if mode == "0777" and control not in finding[0].get("evidence", ""):
                        raise RuntimeError("Native violation report omitted the actual affected directory.")
                    states.append(finding[0]["status"])
            finally:
                remote("sudo chmod 1777 " + shlex.quote(control) + " && sudo rmdir " + shlex.quote(control))
            checkpoint("Native agentless pass/fail/restored rule and honest coverage", states)
            verify_firewall_audit(remote_python, playbook, checkpoint, artifacts, guest_source)
            native_labels = json.loads(remote("sudo python3 /home/hcp-ci/hcp-source/ansible/tests/native_selinux_firewall_acceptance.py",
                                              output=artifacts / "native-selinux-metadata.json", timeout=240).stdout)
            if not native_labels.get("ok") or native_labels.get("selinux") != "Enforcing" or not native_labels.get("realSecuritySelinuxXattrs"):
                raise RuntimeError("Native SELinux metadata acceptance did not establish success.")
            checkpoint("Native enforcing SELinux metadata and crash recovery", native_labels)
            verify_firewall(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port)
            run(["node", str(ROOT / "deployment/tests/verify_linux_packages.mjs"), str(package_path), str(artifacts / "package-matching")],
                output=artifacts / "package-matching.log", timeout=900,
                env={**os.environ, "HCP_TRIVY_CACHE_DIR": str(work / "trivy-cache")})
            matching = json.loads((artifacts / "package-matching/protocol.json").read_text())
            if matching.get("status") != "passed" and matching.get("ok") is not True:
                raise RuntimeError("Native SBOM and vendor CVE controls did not report verified success.")
            checkpoint("Native inventory through production SBOM and Trivy vendor controls", matching)
            remote("test \"$(getenforce)\" = Enforcing && sudo firewall-cmd --state && test \"$(cat /proc/1/comm)\" = systemd",
                   output=artifacts / "final-native-state.txt")
            protocol["status"] = "passed"
            write_json(artifacts / "protocol.json", protocol)
        except BaseException:
            try:
                remote("sudo journalctl -u firewalld --no-pager -n 80; sudo ausearch -m AVC,USER_AVC -ts boot | tail -n 80; getenforce",
                       output=artifacts / "failure-guest-diagnostics.log", timeout=20, accepted=(0, 1, 127, 255))
            except Exception:
                pass
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def verify_firewall_audit(remote_python, playbook, checkpoint, artifacts, guest_source):
    """Prove conditional kernel decisions and report fidelity in the owned guest.

    This is separate from the real HTTP apply/rollback test below. A ruleset
    proof for NEW/non-loopback/non-DNAT TCP/UDP does not attest external IPv6
    reachability, every connection state, or filtering of ICMP/INVALID packets.
    """
    reports = artifacts / "reports"
    proof = {"status": "running", "packetModel": FIREWALL_PACKET_MODEL,
             "evaluation": "conditional_ruleset_path", "externalReachability": "unverified",
             "runtimeRule": FIREWALL_RICH_RULE, "zone": "public", "permanent": False,
             "semanticComparisonIgnores": ["nft table/chain/rule handles", "counter packet/byte values"],
             "snapshots": [], "reports": []}
    marker = "/run/hcp-rpm-firewall-audit-" + uuid.uuid4().hex

    def save():
        write_json(artifacts / "firewall-audit-protocol.json", proof)

    def snapshot(phase):
        observed = json.loads(remote_python(FIREWALL_AUDIT_SNAPSHOT, (guest_source,)).stdout)
        raw = observed["nftables"]
        ruleset, state = json.loads(raw), observed["state"]
        nft_path = artifacts / ("firewall-audit-" + phase + ".nft.json")
        nft_path.write_text(raw)
        nft_path.chmod(0o600)
        write_json(artifacts / ("firewall-audit-" + phase + ".state.json"), state)
        # Save raw command observations even if the subsequent layout or state
        # gate fails; unknown evidence must never disappear into a PASS.
        inputs = inspect_firewall_audit_ruleset(ruleset)
        if state.get("selinux") != "Enforcing" or state.get("firewalld") != "running" or state.get("pid1") != "systemd":
            raise RuntimeError("Native audit control lost enforcing SELinux or running firewalld/systemd")
        proof["snapshots"].append({"phase": phase, "nftFile": nft_path.name,
            "nftSha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "nftSemanticSha256": hashlib.sha256(json.dumps(semantic_nftables(ruleset), sort_keys=True,
                                                           separators=(",", ":")).encode("utf-8")).hexdigest(),
            "activeInputChains": inputs, "selinux": state["selinux"], "firewalld": state["firewalld"]})
        save()
        return ruleset, state

    def audit(phase, expected, ruleset):
        report_phase = "firewall-audit-" + phase
        playbook("agentless-audit", report_phase, {"audit_profile": "basic_linux"})
        report_path = reports / (HOST + "-basic_linux-" + report_phase + ".json")
        raw = report_path.read_bytes()
        report = json.loads(raw)
        findings = [item for item in report["findings"] if item.get("id") == "firewall_active"]
        if len(findings) != 1 or findings[0].get("status") != expected:
            raise RuntimeError("Native firewall_active audit did not produce {} in {}".format(expected, phase))
        scanner = report.get("scanner", {})
        if (type(scanner.get("partial")) is not bool or not isinstance(scanner.get("incompleteChecks"), list)
                or "firewall_active" in scanner["incompleteChecks"]
                or (scanner["incompleteChecks"] and not scanner["partial"])):
            raise RuntimeError("Proven firewall decision retained incomplete or inconsistent native coverage")
        if scanner["partial"] and report.get("summary", {}).get("score") is not None:
            raise RuntimeError("Partial native firewall audit produced an unqualified score")
        evidence = findings[0].get("evidence", "")
        for marker_value in ("packet_model=" + FIREWALL_PACKET_MODEL, "evaluation=conditional_ruleset_path",
                             "external_reachability=unverified"):
            if marker_value not in evidence:
                raise RuntimeError("Native firewall evidence omitted its conditional packet scope: " + marker_value)
        if evidence.count("filter_proofs=") != 1:
            raise RuntimeError("Native firewall evidence omitted or duplicated its decision proof")
        filter_proofs, _ = json.JSONDecoder().raw_decode(evidence.split("filter_proofs=", 1)[1].lstrip())
        if not isinstance(filter_proofs, dict) or not isinstance(filter_proofs.get("nftables"), dict):
            raise RuntimeError("Invalid native nft decision proof")
        if expected == "passed":
            witness = filter_proofs["nftables"]
            if (witness.get("kind") != "deny_witness" or witness.get("family") not in ("ip", "ip6")
                    or witness.get("protocol") not in ("tcp", "udp")
                    or type(witness.get("destination_port")) is not int or not 1 <= witness["destination_port"] <= 65535
                    or not isinstance(witness.get("deny_chains"), list) or not witness["deny_chains"]
                    or not isinstance(witness.get("evaluated_input_chains"), list) or not witness["evaluated_input_chains"]
                    or not all(isinstance(chain, str) for chain in witness["deny_chains"] + witness["evaluated_input_chains"])
                    or any(chain not in witness["evaluated_input_chains"] for chain in witness["deny_chains"])):
                raise RuntimeError("Native passed decision omitted its bounded family/protocol/port/chain witness")
            observed_inputs = ["/".join((item["family"], item["table"], item["chain"]))
                               for item in inspect_firewall_audit_ruleset(ruleset)
                               if item["family"] in ("inet", witness["family"])]
            if sorted(witness["evaluated_input_chains"]) != sorted(observed_inputs):
                raise RuntimeError("Native deny witness did not account for every observed INPUT chain in its family")
        if evidence.count("nftables=") != 1:
            raise RuntimeError("Native firewall evidence omitted or duplicated the observed nft ruleset")
        observed, _ = json.JSONDecoder().raw_decode(evidence.split("nftables=", 1)[1].lstrip())
        if semantic_nftables(observed) != semantic_nftables(ruleset):
            raise RuntimeError("Native audit evidence differs from its contemporaneous kernel snapshot")
        proof["reports"].append({"phase": phase, "file": str(report_path.relative_to(artifacts)),
                                 "sha256": hashlib.sha256(raw).hexdigest(), "firewallStatus": findings[0]["status"],
                                 "findingCount": len(report["findings"]), "partial": scanner["partial"],
                                 "incompleteChecks": scanner["incompleteChecks"], "filterProofs": filter_proofs})
        save()

    save()
    try:
        baseline, baseline_state = snapshot("baseline")
        audit("baseline", "passed", baseline)
        try:
            # The guest records exclusive ownership after checking exact rule
            # absence and before adding it. Cleanup also handles a lost reply.
            remote_python(FIREWALL_AUDIT_CONTROL, ("add", marker, FIREWALL_RICH_RULE),
                          output=artifacts / "firewall-audit-control-add.json")
            allowed, allowed_state = snapshot("allow-all")
            verify_firewall_control_delta(baseline, allowed)
            if any(allowed_state.get(key) != baseline_state.get(key) for key in ("manifest", "labels")):
                raise RuntimeError("Runtime control changed permanent firewall configuration or SELinux labels")
            audit("allow-all", "failed", allowed)
        finally:
            remote_python(FIREWALL_AUDIT_CONTROL, ("remove", marker, FIREWALL_RICH_RULE),
                          output=artifacts / "firewall-audit-control-remove.json")
            restored, restored_state = snapshot("restored")
            if semantic_nftables(restored) != semantic_nftables(baseline) or restored_state != baseline_state:
                raise RuntimeError("Owned runtime control did not restore exact kernel semantics, runtime, config and labels")
            proof["exactRestoration"] = True
            save()
        audit("restored", "passed", restored)
        run(["node", str(ROOT / "deployment/tests/verify_firewall_audit_normalization.mjs"), str(artifacts)],
            output=artifacts / "firewall-audit-normalization.log", timeout=120)
        normalization = json.loads((artifacts / "firewall-audit-normalized/protocol.json").read_text())
        if normalization.get("status") != "passed":
            raise RuntimeError("Native firewall report normalization did not establish success")
        proof["normalization"] = normalization
        proof["status"] = "passed"
        save()
        checkpoint("Native firewall_active passed/failed/restored with kernel evidence and production normalization", proof)
    except BaseException as error:
        proof["status"] = "failed"
        proof["error"] = {"type": type(error).__name__, "message": str(error)[-4000:]}
        save()
        raise


def verify_firewall(remote, remote_python, playbook, checkpoint, artifacts, guest_source, transaction, http_port):
    token = "hcp-native-rpm-" + uuid.uuid4().hex
    remote("mkdir -m 700 /home/hcp-ci/hcp-http && printf %s " + shlex.quote(token) + " > /home/hcp-ci/hcp-http/health")
    remote("nohup python3 -m http.server 8088 --bind 0.0.0.0 --directory /home/hcp-ci/hcp-http > /home/hcp-ci/http.log 2>&1 < /dev/null &")
    url = "http://127.0.0.1:{}/health".format(http_port)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def probe(expected):
        try:
            with opener.open(url, timeout=4) as response:
                if response.status != 200 or response.read(4096).decode() != token:
                    raise RuntimeError("Native HTTP probe reached an unexpected service or response.")
                reachable = True
        except urllib.error.HTTPError as error:
            raise RuntimeError("Native HTTP probe received an unexpected HTTP error: " + str(error)) from error
        except OSError:
            reachable = False
        if reachable != expected:
            raise RuntimeError("Native forwarded HTTP probe had unexpected reachability: {}".format(reachable))
        remote("test \"$(getenforce)\" = Enforcing && printenv SSH_CONNECTION")

    for attempt in range(30):
        try:
            probe(True)
            break
        except RuntimeError:
            if attempt == 29:
                raise
            time.sleep(0.2)

    snapshot_code = r'''
import importlib.util, json, os, subprocess, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("native_firewall_snapshot", sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
tree = Path("/etc/firewalld")
labels = {str(path.relative_to(tree)): os.getxattr(str(path), "security.selinux", follow_symlinks=False).hex()
          for path in [tree] + list(tree.rglob("*"))}
runtime = {name: subprocess.check_output(["firewall-cmd"] + args, universal_newlines=True)
           for name, args in (("zones", ["--list-all-zones"]), ("policies", ["--list-all-policies"]),
                              ("direct", ["--direct", "--get-all-rules"]))}
print(json.dumps({"manifest": fw.tree_digest(tree), "labels": labels, "runtime": runtime}, sort_keys=True))
'''

    def snapshot(label):
        return json.loads(remote_python(snapshot_code, (guest_source,), output=artifacts / (label + ".json")).stdout)

    baseline = snapshot("firewall-baseline")
    playbook("backup-remediation", "firewall-backup")
    playbook("close-port", "firewall-reject-ssh", {"target_port": 22}, expected_error="management SSH port cannot be closed")
    playbook("close-port", "firewall-preview", check=True)
    if snapshot("firewall-after-preview") != baseline:
        raise RuntimeError("Rejected management request or preview modified native firewall state or labels.")
    probe(True)
    playbook("close-port", "firewall-apply")
    probe(False)
    remote("test \"$(curl --silent --fail --max-time 3 http://127.0.0.1:8088/health)\" = " + shlex.quote(token))
    applied = snapshot("firewall-applied")
    repeated = playbook("close-port", "firewall-repeat-apply")
    if not re.search(HOST + r"\s+:.*changed=0\b", repeated) or snapshot("firewall-repeated") != applied:
        raise RuntimeError("Native firewall repeated apply was not idempotent.")
    remote("sudo firewall-cmd --reload")
    probe(False)
    checkpoint("Native firewalld preview, management guard, incoming deny and persistent idempotence", {"port": PORT})
    interrupted = json.loads(remote_python(r'''
import json, signal, subprocess, sys
from pathlib import Path
code = """
import argparse, importlib.util, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('native_firewall_crash', sys.argv[1])
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
original = Path.rename
def interrupted(source, target):
    result = original(source, target)
    if source == Path('/etc/firewalld'):
        os.kill(os.getpid(), signal.SIGKILL)
    return result
Path.rename = interrupted
fw.execute_operation(argparse.Namespace(operation='rollback', transaction=sys.argv[2], check=False, recovery_verified=False))
"""
result = subprocess.run([sys.executable, "-c", code, sys.argv[1], sys.argv[2]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
if result.returncode != -signal.SIGKILL or Path("/etc/firewalld").exists():
    raise RuntimeError("Native rollback did not reach its expected killed/missing-directory boundary: " + repr(result.stderr))
journal = json.loads((Path("/var/lib/hcp-backups") / sys.argv[2] / "rollback-state.json").read_text())
if journal.get("phase") != "move_old_intent" or journal.get("transactionId") != sys.argv[2]:
    raise RuntimeError("Native rollback lost its durable intent.")
staging = Path("/etc") / journal["stagingName"]
if not (staging / "previous").is_dir():
    raise RuntimeError("Native rollback lost the previous tree.")
print(json.dumps(journal, sort_keys=True))
''', (guest_source, transaction), output=artifacts / "firewall-interrupted-journal.json").stdout)
    probe(False)
    playbook("rollback-remediation", "firewall-rollback")
    probe(True)
    if snapshot("firewall-restored") != baseline:
        raise RuntimeError("Native rollback did not restore exact configuration, SELinux labels and runtime state.")
    replay = playbook("rollback-remediation", "firewall-replayed-rollback")
    if not re.search(HOST + r"\s+:.*changed=0\b", replay) or snapshot("firewall-replayed") != baseline:
        raise RuntimeError("Native rollback replay changed the restored state.")
    checkpoint("Native SIGKILL rollback resumes with exact SELinux labels and restored traffic", {"phase": interrupted["phase"], "replayed": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", choices=tuple(SOURCES), required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Only an owned disposable GitHub-hosted runner is supported.")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("KVM is required; unavailable native virtualization cannot produce a passing result.")
    work, runner_temp = args.work_dir.resolve(), Path(os.environ["RUNNER_TEMP"]).resolve()
    if work == runner_temp or runner_temp not in work.parents or work.exists():
        raise RuntimeError("Require a new private work directory below RUNNER_TEMP.")
    work.mkdir(mode=0o700)
    artifacts = work / "artifacts"
    artifacts.mkdir(mode=0o755)
    protocol = {"status": "running", "distribution": args.distribution, "image": SOURCES[args.distribution],
                "acceleration": "kvm", "syntheticOsIdentity": False,
                "limitations": ["Pinned x86_64 RPM base images only; other releases require native acceptance",
                                "Incoming traffic control is IPv4 over QEMU forwarding; no IPv6 coverage claim",
                                "firewall_active proves conditional NEW/non-loopback/non-DNAT TCP/UDP kernel paths, not external reachability or all packet classes",
                                "Native SELinux validation uses the image's policy; no claim about every custom MLS/MCS policy",
                                "Labelled controls establish specific behavior, not overall vulnerability recall"], "checks": []}
    write_json(artifacts / "protocol.json", protocol)

    def interrupted(_signum, _frame):
        raise InterruptedError("CI cancellation")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        boot_and_verify(args.distribution, work, artifacts, protocol)
    except BaseException as error:
        protocol["status"] = "cancelled" if isinstance(error, (InterruptedError, KeyboardInterrupt)) else "failed"
        protocol["error"] = {"type": type(error).__name__, "message": str(error)[-4000:]}
        write_json(artifacts / "protocol.json", protocol)
        raise


if __name__ == "__main__":
    main()
